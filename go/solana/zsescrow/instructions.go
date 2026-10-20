/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"errors"

	"github.com/TxnLab/zerosignal/go/solana"
)

// One builder per program instruction. Each lists the accounts in the
// program's order (the IDL's), so a builder's Accounts are the instruction's
// metas as the program reads them. An optional account the caller leaves out
// is the program id, read-only, which is how Anchor reads None.

func writable(k solana.PublicKey) solana.AccountMeta {
	return solana.AccountMeta{PublicKey: k, IsWritable: true}
}
func readonly(k solana.PublicKey) solana.AccountMeta { return solana.AccountMeta{PublicKey: k} }
func signer(k solana.PublicKey) solana.AccountMeta {
	return solana.AccountMeta{PublicKey: k, IsSigner: true}
}
func payer(k solana.PublicKey) solana.AccountMeta {
	return solana.AccountMeta{PublicKey: k, IsSigner: true, IsWritable: true}
}

func (d Deployment) ix(name string, data []byte, accounts ...solana.AccountMeta) solana.Instruction {
	disc := discriminator("global", name)
	return solana.Instruction{ProgramID: d.Program, Accounts: accounts, Data: append(disc[:], data...)}
}

// optional is k when it is set, else the program id.
func (d Deployment) optional(k solana.PublicKey, w bool) solana.AccountMeta {
	if k.IsZero() {
		return readonly(d.Program)
	}
	return solana.AccountMeta{PublicKey: k, IsWritable: w}
}

func (d Deployment) eventCPI() []solana.AccountMeta {
	return []solana.AccountMeta{readonly(d.EventAuthority()), readonly(d.Program)}
}

func (d Deployment) programData() solana.PublicKey {
	k, _, err := solana.FindProgramAddress([][]byte{d.Program[:]}, solana.BPFLoaderUpgradeableProgramID)
	if err != nil {
		panic("zsescrow: " + err.Error())
	}
	return k
}

// InitializeArgs are the terms initialize sets. Arbiter must not be the
// default key, and only the arbiter can name its successor.
type InitializeArgs struct {
	GenesisHash       solana.Hash      `json:"genesis_hash"`
	Arbiter           solana.PublicKey `json:"arbiter"`
	FeeBps            uint16           `json:"fee_bps"`
	MaxGrace          uint32           `json:"max_grace"`
	DefaultGrace      uint32           `json:"default_grace"`
	MinGrace          uint32           `json:"min_grace"`
	MaxTicketLifetime int64            `json:"max_ticket_lifetime"`
	OperatorStake     uint64           `json:"operator_stake"`
	NodeStake         uint64           `json:"node_stake"`
}

// Initialize must be signed by the program's upgrade authority, which becomes
// the admin.
func (d Deployment) Initialize(admin, treasury solana.PublicKey, a InitializeArgs) solana.Instruction {
	w := writer{}
	w.bytes(a.GenesisHash[:])
	w.key(a.Arbiter)
	w.u16(a.FeeBps)
	w.u32(a.MaxGrace)
	w.u32(a.DefaultGrace)
	w.u32(a.MinGrace)
	w.i64(a.MaxTicketLifetime)
	w.u64(a.OperatorStake)
	w.u64(a.NodeStake)
	return d.ix("initialize", w.b,
		payer(admin),
		readonly(d.programData()),
		writable(d.Config()),
		writable(d.StakeVault()),
		writable(d.OwedVault()),
		readonly(d.Mint),
		readonly(treasury),
		readonly(solana.TokenProgramID),
		readonly(solana.SystemProgramID),
	)
}

// SetConfigArgs changes the fields that are set and leaves the rest.
type SetConfigArgs struct {
	PauseOpen         *bool             `json:"pause_open"`
	PauseRegistry     *bool             `json:"pause_registry"`
	FeeBps            *uint16           `json:"fee_bps"`
	MaxGrace          *uint32           `json:"max_grace"`
	DefaultGrace      *uint32           `json:"default_grace"`
	MinGrace          *uint32           `json:"min_grace"`
	MaxTicketLifetime *int64            `json:"max_ticket_lifetime"`
	OperatorStake     *uint64           `json:"operator_stake"`
	NodeStake         *uint64           `json:"node_stake"`
	Treasury          *solana.PublicKey `json:"treasury"`
}

// ErrZeroTreasury refuses a treasury of the default key: the program accepts
// it, and nobody can sign for its token accounts, so every later fee and
// slash would be lost.
var ErrZeroTreasury = errors.New("zsescrow: the treasury is the default key")

// SetConfig passes the new treasury as an account too: the program checks
// it is not one of its own.
func (d Deployment) SetConfig(admin solana.PublicKey, a SetConfigArgs) (solana.Instruction, error) {
	if a.Treasury != nil && a.Treasury.IsZero() {
		return solana.Instruction{}, ErrZeroTreasury
	}
	w := writer{}
	option(&w, a.PauseOpen, w.bool)
	option(&w, a.PauseRegistry, w.bool)
	option(&w, a.FeeBps, w.u16)
	option(&w, a.MaxGrace, w.u32)
	option(&w, a.DefaultGrace, w.u32)
	option(&w, a.MinGrace, w.u32)
	option(&w, a.MaxTicketLifetime, w.i64)
	option(&w, a.OperatorStake, w.u64)
	option(&w, a.NodeStake, w.u64)
	option(&w, a.Treasury, w.key)
	var treasury solana.PublicKey
	if a.Treasury != nil {
		treasury = *a.Treasury
	}
	return d.ix("set_config", w.b, signer(admin), writable(d.Config()), d.optional(treasury, false)), nil
}

func (d Deployment) ProposeAdmin(admin, next solana.PublicKey) solana.Instruction {
	w := writer{}
	w.key(next)
	return d.ix("propose_admin", w.b, signer(admin), writable(d.Config()))
}

func (d Deployment) AcceptAdmin(next solana.PublicKey) solana.Instruction {
	return d.ix("accept_admin", nil, signer(next), writable(d.Config()))
}

func (d Deployment) ProposeArbiter(arbiter, next solana.PublicKey) solana.Instruction {
	w := writer{}
	w.key(next)
	return d.ix("propose_arbiter", w.b, signer(arbiter), writable(d.Config()))
}

func (d Deployment) AcceptArbiter(next solana.PublicKey) solana.Instruction {
	return d.ix("accept_arbiter", nil, signer(next), writable(d.Config()))
}

// The program takes any USDC account the owner (or the treasury) holds where
// it pays a stake in or out, so a frozen or closed associated account can't
// block a registration, an unregister or an eviction. Those builders take
// the account; d.TokenAccount(owner) is the usual one. Payouts, fee sweeps
// and RefundOwed claims go only to the associated account, which their
// builders derive.

// CreateOperator registers the owner as operator nextOperatorID, the
// Config's next_operator_id, and escrows the operator stake from ownerUSDC.
func (d Deployment) CreateOperator(owner, ownerUSDC solana.PublicKey, nextOperatorID uint64) solana.Instruction {
	return d.ix("create_operator", nil,
		payer(owner),
		writable(d.Config()),
		writable(d.Operator(nextOperatorID)),
		writable(ownerUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
		readonly(solana.SystemProgramID),
	)
}

// CreateNode adds node nextNodeID, the operator's next_node_id. The signing
// key signs too, proving the owner holds it. A node after the first escrows
// the node stake from ownerUSDC.
func (d Deployment) CreateNode(owner, ownerUSDC solana.PublicKey, operatorID, nextNodeID uint64, signing solana.PublicKey, baseURL string) solana.Instruction {
	w := writer{}
	w.vec([]byte(baseURL))
	node := d.Node(operatorID, nextNodeID)
	return d.ix("create_node", w.b,
		payer(owner),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(node),
		writable(d.Vault(node)),
		signer(signing),
		writable(d.SignerIndex(signing)),
		writable(ownerUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
		readonly(solana.SystemProgramID),
	)
}

// UpdateNode rotates the node's signing key, and sets its URL.
func (d Deployment) UpdateNode(owner solana.PublicKey, operatorID, nodeID uint64, oldSigning, newSigning solana.PublicKey, baseURL string) solana.Instruction {
	w := writer{}
	w.vec([]byte(baseURL))
	return d.ix("update_node", w.b,
		payer(owner),
		readonly(d.Operator(operatorID)),
		writable(d.Node(operatorID, nodeID)),
		writable(d.SignerIndex(oldSigning)),
		signer(newSigning),
		writable(d.SignerIndex(newSigning)),
		readonly(solana.SystemProgramID),
	)
}

// UpdateNodeURL is signed by the owner or by the node's signing key.
func (d Deployment) UpdateNodeURL(authority solana.PublicKey, operatorID, nodeID uint64, baseURL string) solana.Instruction {
	w := writer{}
	w.vec([]byte(baseURL))
	return d.ix("update_node_url", w.b, d.nodeField(authority, operatorID, nodeID)...)
}

// SetNodeStaging is signed by the owner or by the node's signing key.
func (d Deployment) SetNodeStaging(authority solana.PublicKey, operatorID, nodeID uint64, staging bool) solana.Instruction {
	w := writer{}
	w.bool(staging)
	return d.ix("set_node_staging", w.b, d.nodeField(authority, operatorID, nodeID)...)
}

func (d Deployment) nodeField(authority solana.PublicKey, operatorID, nodeID uint64) []solana.AccountMeta {
	return []solana.AccountMeta{
		signer(authority),
		readonly(d.Config()),
		readonly(d.Operator(operatorID)),
		writable(d.Node(operatorID, nodeID)),
	}
}

// UpdateOperator hands the operator to newOwner (or keeps it, passing the
// owner) and sets its name record; a zero nameRef clears it.
func (d Deployment) UpdateOperator(owner solana.PublicKey, operatorID uint64, newOwner, nameRef solana.PublicKey) solana.Instruction {
	w := writer{}
	w.key(newOwner)
	w.key(nameRef)
	return d.ix("update_operator", w.b,
		signer(owner),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		d.optional(nameRef, false),
	)
}

// UnregisterNode removes a node with no live tickets, refunds its stake to
// ownerUSDC and its unswept fee to treasuryUSDC.
func (d Deployment) UnregisterNode(owner, ownerUSDC solana.PublicKey, operatorID, nodeID uint64, signing, treasuryUSDC solana.PublicKey) solana.Instruction {
	node := d.Node(operatorID, nodeID)
	return d.ix("unregister_node", nil,
		payer(owner),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(node),
		writable(d.Vault(node)),
		writable(d.SignerIndex(signing)),
		writable(ownerUSDC),
		writable(treasuryUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	)
}

// UnregisterOperator closes an operator with no nodes and returns its stake
// to ownerUSDC.
func (d Deployment) UnregisterOperator(owner, ownerUSDC solana.PublicKey, operatorID uint64) solana.Instruction {
	return d.ix("unregister_operator", nil,
		payer(owner),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(ownerUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	)
}

// AdminUnregisterOperator is UnregisterOperator by the admin, the stake going
// to ownerUSDC, an account the owner holds.
func (d Deployment) AdminUnregisterOperator(admin solana.PublicKey, operatorID uint64, owner, ownerUSDC solana.PublicKey) solana.Instruction {
	return d.ix("admin_unregister_operator", nil,
		signer(admin),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(owner),
		writable(ownerUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	)
}

// Evict tombstones an operator and slashes slashBps of its stake to
// treasuryUSDC, an account the treasury holds.
func (d Deployment) Evict(admin solana.PublicKey, operatorID uint64, treasuryUSDC solana.PublicKey, slashBps uint16, reason string) solana.Instruction {
	w := writer{}
	w.u16(slashBps)
	w.vec([]byte(reason))
	return d.ix("evict", w.b, append([]solana.AccountMeta{
		signer(admin),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(treasuryUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	}, d.eventCPI()...)...)
}

func (d Deployment) Reinstate(admin solana.PublicKey, operatorID uint64) solana.Instruction {
	return d.ix("reinstate", nil, signer(admin), readonly(d.Config()), writable(d.Operator(operatorID)))
}

// OpenArgs are what the node's open instruction commits to. Grace 0 takes the
// Config's default, the only grace a payer's verifier accepts.
type OpenArgs struct {
	TicketID  [16]byte
	Payer     solana.PublicKey
	MaxPrice  uint64
	ExpiresAt int64
	Grace     uint32
}

// Open is the node's half of the open offer: the node signs and pays for the
// ticket; the payer's TransferChecked into the vault rides beside it.
func (d Deployment) Open(nodeSigner solana.PublicKey, operatorID, nodeID uint64, a OpenArgs) solana.Instruction {
	w := writer{}
	w.bytes(a.TicketID[:])
	w.key(a.Payer)
	w.u64(a.MaxPrice)
	w.i64(a.ExpiresAt)
	w.u32(a.Grace)
	node := d.Node(operatorID, nodeID)
	return d.ix("open", w.b,
		payer(nodeSigner),
		readonly(d.Config()),
		readonly(d.Operator(operatorID)),
		writable(node),
		writable(d.Ticket(node, a.TicketID)),
		readonly(solana.SysvarInstructionsID),
		readonly(solana.SystemProgramID),
	)
}

// ClaimFields are what a node claims for a ticket; the payer's ack signs
// their hash.
type ClaimFields struct {
	Amount          uint64   `json:"amount"`
	ReceiptDigest   [32]byte `json:"receipt_digest"`
	TTFTMs          uint32   `json:"ttft_ms"`
	DecodeMs        uint32   `json:"decode_ms"`
	InputUnits      uint64   `json:"input_units"`
	OutputUnits     uint64   `json:"output_units"`
	OutputUsageType uint8    `json:"output_usage_type"`
	AuxUsageType    uint8    `json:"aux_usage_type"`
	AuxCount        uint32   `json:"aux_count"`
}

func (f ClaimFields) put(w *writer) {
	w.u64(f.Amount)
	w.bytes(f.ReceiptDigest[:])
	w.u32(f.TTFTMs)
	w.u32(f.DecodeMs)
	w.u64(f.InputUnits)
	w.u64(f.OutputUnits)
	w.u8(f.OutputUsageType)
	w.u8(f.AuxUsageType)
	w.u32(f.AuxCount)
}

// Claim records the node's claim on a ticket the payer has not acked; it
// lapses to the node at the deadline unless the payer answers.
func (d Deployment) Claim(nodeSigner solana.PublicKey, operatorID, nodeID uint64, ticketID [16]byte, f ClaimFields) solana.Instruction {
	w := writer{}
	f.put(&w)
	node := d.Node(operatorID, nodeID)
	return d.ix("claim", w.b, append([]solana.AccountMeta{
		signer(nodeSigner),
		readonly(node),
		writable(d.Ticket(node, ticketID)),
	}, d.eventCPI()...)...)
}

// RefundFallback is how a settle passes the payer's RefundOwed and the owed
// vault, which it needs only when the payer's token account can't take the
// refund.
type RefundFallback uint8

const (
	// NoFallback leaves them out: the common settle.
	NoFallback RefundFallback = iota
	// FallbackReadonly passes them read-only, which a settle may always do;
	// the program refuses with RefundOwedNotWritable if it needs them.
	FallbackReadonly
	// FallbackWritable passes them writable, for a payer whose token account
	// is closed or frozen.
	FallbackWritable
)

// Ending names the ticket a settle ends and who submits it.
type Ending struct {
	Submitter  solana.PublicKey
	OperatorID uint64
	NodeID     uint64
	TicketID   [16]byte
	// RentPayer funded the ticket and gets its rent back: the ticket's
	// rent_payer.
	RentPayer solana.PublicKey
	// Payer is the ticket's payer, whose token account takes the refund.
	Payer    solana.PublicKey
	Fallback RefundFallback
}

func (d Deployment) ending(name string, e Ending, args func(w *writer)) solana.Instruction {
	w := writer{}
	args(&w)
	b := d.RefundBumps(e.Payer)
	w.u8(b.PayerATA)
	w.u8(b.RefundOwed)
	node := d.Node(e.OperatorID, e.NodeID)
	accounts := []solana.AccountMeta{
		payer(e.Submitter),
		readonly(d.Config()),
		writable(node),
		writable(d.Vault(node)),
		writable(d.Ticket(node, e.TicketID)),
		writable(e.RentPayer),
		writable(d.TokenAccount(e.Payer)),
		readonly(d.Mint),
		readonly(solana.SysvarInstructionsID),
		readonly(solana.TokenProgramID),
	}
	if e.Fallback == NoFallback {
		accounts = append(accounts, readonly(d.Program), readonly(d.Program), readonly(d.Program))
	} else {
		owedWritable := e.Fallback == FallbackWritable
		accounts = append(accounts,
			solana.AccountMeta{PublicKey: d.RefundOwed(e.Payer), IsWritable: owedWritable},
			solana.AccountMeta{PublicKey: d.OwedVault(), IsWritable: owedWritable},
			readonly(solana.SystemProgramID))
	}
	return d.ix(name, w.b, append(accounts, d.eventCPI()...)...)
}

// SettleCooperative settles on the payer's ack: an Ed25519 precompile
// instruction over the ack digest, or the payer's own signature on the
// transaction, which the program checks by introspection.
func (d Deployment) SettleCooperative(e Ending, f ClaimFields) solana.Instruction {
	return d.ending("settle_cooperative", e, f.put)
}

// Ack is the payer's answer to a claim: the payer signs the transaction.
func (d Deployment) Ack(e Ending, f ClaimFields) solana.Instruction {
	return d.ending("ack", e, f.put)
}

// SettleLapsed pays a claim the payer did not answer by the deadline; the
// claim fields are resupplied and checked against the stored hash.
func (d Deployment) SettleLapsed(e Ending, f ClaimFields) solana.Instruction {
	return d.ending("settle_lapsed", e, f.put)
}

// RefundInactive refunds an open ticket nobody claimed by the deadline.
func (d Deployment) RefundInactive(e Ending) solana.Instruction {
	return d.ending("refund_inactive", e, func(*writer) {})
}

// ResolveFrozen is the arbiter's split of a protested ticket: nodeAmount to
// the node, the rest back to the payer.
func (d Deployment) ResolveFrozen(e Ending, nodeAmount uint64) solana.Instruction {
	return d.ending("resolve_frozen", e, func(w *writer) { w.u64(nodeAmount) })
}

// Protest freezes a ticket on the node's receipt, which the payer proves the
// node signed with an Ed25519 precompile instruction beside it.
func (d Deployment) Protest(payerKey solana.PublicKey, operatorID, nodeID uint64, ticketID [16]byte, receipt []byte, reason uint8) solana.Instruction {
	w := writer{}
	w.bytes(ticketID[:])
	w.vec(receipt)
	w.u8(reason)
	node := d.Node(operatorID, nodeID)
	return d.ix("protest", w.b, append([]solana.AccountMeta{
		signer(payerKey),
		readonly(d.Config()),
		writable(node),
		writable(d.Ticket(node, ticketID)),
		readonly(solana.SysvarInstructionsID),
	}, d.eventCPI()...)...)
}

// ClaimRefundOwed pays the payer what settles could not, once its token
// account can take it, and returns the record's rent to whoever funded it.
func (d Deployment) ClaimRefundOwed(payerKey, rentPayer solana.PublicKey) solana.Instruction {
	return d.ix("claim_refund_owed", nil,
		signer(payerKey),
		readonly(d.Config()),
		writable(d.RefundOwed(payerKey)),
		writable(rentPayer),
		writable(d.OwedVault()),
		writable(d.TokenAccount(payerKey)),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	)
}

// CloseRefundOwed closes a RefundOwed with nothing owed, for its rent.
func (d Deployment) CloseRefundOwed(rentPayer, payerKey solana.PublicKey) solana.Instruction {
	return d.ix("close_refund_owed", nil, payer(rentPayer), writable(d.RefundOwed(payerKey)))
}

// WithdrawPayout sends the node's accrued payout to the operator owner's USDC
// account. Anyone may submit it.
func (d Deployment) WithdrawPayout(operatorID, nodeID uint64, owner solana.PublicKey) solana.Instruction {
	node := d.Node(operatorID, nodeID)
	return d.ix("withdraw_payout", nil,
		readonly(d.Config()),
		readonly(d.Operator(operatorID)),
		writable(node),
		writable(d.Vault(node)),
		writable(d.TokenAccount(owner)),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	)
}

// SweepFees sends the node's accrued protocol fee to the treasury's USDC
// account. Anyone may submit it.
func (d Deployment) SweepFees(operatorID, nodeID uint64, treasury solana.PublicKey) solana.Instruction {
	node := d.Node(operatorID, nodeID)
	return d.ix("sweep_fees", nil,
		readonly(d.Config()),
		writable(node),
		writable(d.Vault(node)),
		writable(d.TokenAccount(treasury)),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
	)
}
