/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"crypto/sha256"
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

// InitializeArgs are the terms initialize sets.
type InitializeArgs struct {
	GenesisHash   solana.Hash `json:"genesis_hash"`
	FeeBps        uint16      `json:"fee_bps"`
	DefaultGrace  uint32      `json:"default_grace"`
	OperatorStake uint64      `json:"operator_stake"`
	NodeStake     uint64      `json:"node_stake"`
}

// Initialize must be signed by the program's upgrade authority, which becomes
// the admin. The treasury's USDC account must already exist, unfrozen: the
// program refuses a treasury that couldn't take a fee (TreasuryCannotReceive).
func (d Deployment) Initialize(admin, treasury solana.PublicKey, a InitializeArgs) solana.Instruction {
	w := writer{}
	w.bytes(a.GenesisHash[:])
	w.u16(a.FeeBps)
	w.u32(a.DefaultGrace)
	w.u64(a.OperatorStake)
	w.u64(a.NodeStake)
	return d.ix("initialize", w.b,
		payer(admin),
		readonly(d.programData()),
		writable(d.Config()),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(treasury),
		readonly(d.TokenAccount(treasury)),
		readonly(solana.TokenProgramID),
		readonly(solana.SystemProgramID),
	)
}

// SetConfigArgs changes the fields that are set and leaves the rest. Paused
// stops open and every registry write, as Algorand's paused does; settles,
// unregisters and the admin's levers run through a pause.
type SetConfigArgs struct {
	Paused        *bool             `json:"paused"`
	FeeBps        *uint16           `json:"fee_bps"`
	DefaultGrace  *uint32           `json:"default_grace"`
	OperatorStake *uint64           `json:"operator_stake"`
	NodeStake     *uint64           `json:"node_stake"`
	Treasury      *solana.PublicKey `json:"treasury"`
}

// ErrZeroTreasury refuses a treasury of the default key: the program accepts
// it, and nobody can sign for its token accounts, so every later fee and
// slash would be lost.
var ErrZeroTreasury = errors.New("zsescrow: the treasury is the default key")

// SetConfig passes the new treasury as an account too, so the program can
// check it is not one of its own, and the treasury's USDC account, which the
// program requires to exist unfrozen, as Algorand's setTreasury does.
func (d Deployment) SetConfig(admin solana.PublicKey, a SetConfigArgs) (solana.Instruction, error) {
	if a.Treasury != nil && a.Treasury.IsZero() {
		return solana.Instruction{}, ErrZeroTreasury
	}
	w := writer{}
	option(&w, a.Paused, w.bool)
	option(&w, a.FeeBps, w.u16)
	option(&w, a.DefaultGrace, w.u32)
	option(&w, a.OperatorStake, w.u64)
	option(&w, a.NodeStake, w.u64)
	option(&w, a.Treasury, w.key)
	var treasury, treasuryUSDC solana.PublicKey
	if a.Treasury != nil {
		treasury = *a.Treasury
		treasuryUSDC = d.TokenAccount(treasury)
	}
	return d.ix("set_config", w.b,
		signer(admin),
		writable(d.Config()),
		d.optional(treasury, false),
		d.optional(treasuryUSDC, false),
	), nil
}

func (d Deployment) ProposeAdmin(admin, next solana.PublicKey) solana.Instruction {
	w := writer{}
	w.key(next)
	return d.ix("propose_admin", w.b, signer(admin), writable(d.Config()))
}

func (d Deployment) AcceptAdmin(next solana.PublicKey) solana.Instruction {
	return d.ix("accept_admin", nil, signer(next), writable(d.Config()))
}

// The program takes any USDC account the owner (or the treasury) holds where
// it pays a stake in or out, so a frozen or closed associated account can't
// block a registration, an unregister or an eviction. Those builders take
// the account; d.TokenAccount(owner) is the usual one. Payouts, fee sweeps,
// refunds and forfeited refunds go only to the associated account, which
// their builders derive.

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

// CreateNode adds node nextNodeID, the operator's next_node_id, with signing
// as its key. The owner alone signs, as on Algorand: the node holds the key.
// It escrows the node stake from ownerUSDC unless the operator has no live
// node, whose stake the operator stake covers.
func (d Deployment) CreateNode(owner, ownerUSDC solana.PublicKey, operatorID, nextNodeID uint64, signing solana.PublicKey, baseURL string) solana.Instruction {
	w := writer{}
	w.key(signing)
	w.vec([]byte(baseURL))
	node := d.Node(operatorID, nextNodeID)
	return d.ix("create_node", w.b,
		payer(owner),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(node),
		writable(d.Vault(node)),
		writable(ownerUSDC),
		writable(d.StakeVault()),
		readonly(d.Mint),
		readonly(solana.TokenProgramID),
		readonly(solana.SystemProgramID),
	)
}

// UpdateNode moves the node to signing as its key, and sets its URL. The
// owner alone signs. It is pause-gated, as Algorand's updateNode is, so a
// key can't be rotated while the protocol is paused.
func (d Deployment) UpdateNode(owner solana.PublicKey, operatorID, nodeID uint64, signing solana.PublicKey, baseURL string) solana.Instruction {
	w := writer{}
	w.key(signing)
	w.vec([]byte(baseURL))
	return d.ix("update_node", w.b,
		signer(owner),
		readonly(d.Config()),
		readonly(d.Operator(operatorID)),
		writable(d.Node(operatorID, nodeID)),
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
func (d Deployment) UnregisterNode(owner, ownerUSDC solana.PublicKey, operatorID, nodeID uint64, treasuryUSDC solana.PublicKey) solana.Instruction {
	node := d.Node(operatorID, nodeID)
	return d.ix("unregister_node", nil,
		payer(owner),
		readonly(d.Config()),
		writable(d.Operator(operatorID)),
		writable(node),
		writable(d.Vault(node)),
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

// Open is the node's half of the open offer: the node signs and pays the
// fees, the ticket's rent comes from the payer's rent pool, and the payer's
// TransferChecked into the vault rides beside it.
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
		writable(d.RentPool(a.Payer)),
		readonly(solana.SysvarInstructionsID),
		readonly(solana.SystemProgramID),
	)
}

// DepositRent funds the payer's rent pool, creating it on the first deposit,
// as Algorand's depositMbr. The amount must be positive.
func (d Deployment) DepositRent(payerKey solana.PublicKey, amount uint64) solana.Instruction {
	w := writer{}
	w.u64(amount)
	return d.ix("deposit_rent", w.b, payer(payerKey), writable(d.RentPool(payerKey)), readonly(solana.SystemProgramID))
}

// WithdrawRent takes back what the pool holds above its own rent exemption,
// as Algorand's withdrawMbr.
func (d Deployment) WithdrawRent(payerKey solana.PublicKey, amount uint64) solana.Instruction {
	w := writer{}
	w.u64(amount)
	return d.ix("withdraw_rent", w.b, payer(payerKey), writable(d.RentPool(payerKey)))
}

// CloseRentPool closes the pool and returns all of it, its own rent included,
// as Algorand's closeDeposit. Refused while a ticket it funded is live.
func (d Deployment) CloseRentPool(payerKey solana.PublicKey) solana.Instruction {
	return d.ix("close_rent_pool", nil, payer(payerKey), writable(d.RentPool(payerKey)))
}

// ClaimFields are what a node claims for a ticket; the payer's ack signs
// their hash.
type ClaimFields struct {
	Amount          uint64   `json:"amount"`
	ReceiptDigest   [32]byte `json:"receipt_digest"`
	TTFTMs          uint64   `json:"ttft_ms"`
	DecodeMs        uint64   `json:"decode_ms"`
	InputUnits      uint64   `json:"input_units"`
	OutputUnits     uint64   `json:"output_units"`
	OutputUsageType uint8    `json:"output_usage_type"`
	AuxUsageType    uint8    `json:"aux_usage_type"`
	AuxCount        uint64   `json:"aux_count"`
}

func (f ClaimFields) put(w *writer) {
	w.u64(f.Amount)
	w.bytes(f.ReceiptDigest[:])
	w.u64(f.TTFTMs)
	w.u64(f.DecodeMs)
	w.u64(f.InputUnits)
	w.u64(f.OutputUnits)
	w.u8(f.OutputUsageType)
	w.u8(f.AuxUsageType)
	w.u64(f.AuxCount)
}

// The domain tags of the claim hash and the payer's ack digest, the
// program's CLAIM_TAG and ACK_TAG.
const (
	claimTag = "zs-claim-v3\x00"
	ackTag   = "zs-settle-ack-v3\x00"
)

// ClaimHash is the hash of a claim's fields that the payer's ack digest binds.
func ClaimHash(f ClaimFields) [32]byte {
	w := writer{b: []byte(claimTag)}
	f.put(&w)
	return sha256.Sum256(w.b)
}

// AckDigest is what the payer signs off chain to accept a claim, for the
// Ed25519 precompile instruction before a settle_cooperative. It binds the
// cluster, the program, the ticket and its open_seq: a closed ticket's
// address can be opened again with the same id, and only open_seq tells the
// two apart, so an ack never replays against the reopened ticket.
func (d Deployment) AckDigest(genesis solana.Hash, ticket solana.PublicKey, openSeq uint64, claimHash [32]byte) [32]byte {
	w := writer{b: []byte(ackTag)}
	w.bytes(genesis[:])
	w.key(d.Program)
	w.key(ticket)
	w.u64(openSeq)
	w.bytes(claimHash[:])
	return sha256.Sum256(w.b)
}

// RefundFallback is how a settle passes the treasury's USDC account, which
// takes the refund only when the payer's token account can't (closed, never
// created, or frozen): the refund is forfeited there, as Algorand's
// payOrForfeit forfeits it.
type RefundFallback uint8

const (
	// NoFallback leaves it out: the common settle.
	NoFallback RefundFallback = iota
	// FallbackReadonly passes it read-only, which a settle may always do; the
	// program refuses with TreasuryAccountNotWritable if it needs it.
	FallbackReadonly
	// FallbackWritable passes it writable, for a payer whose token account
	// can't take the refund. Only then: the account is one for the whole
	// protocol, so a write lock on it in every settle would serialize them all.
	FallbackWritable
)

// Ending names the ticket a settle ends and who submits it.
type Ending struct {
	// Submitter signs: the node's current signing key for Claim (and for a
	// SettleCooperative of an open ticket), the payer for Ack, the admin for
	// ResolveFrozen, anyone for SettleLapsed and RefundInactive.
	Submitter  solana.PublicKey
	OperatorID uint64
	NodeID     uint64
	TicketID   [16]byte
	// RentPayer funded the ticket and gets its rent back: the ticket's
	// rent_payer, read from the ticket. That is the payer's rent pool, or the
	// node's signer for a ticket opened before pools existed, so deriving it
	// from the payer fails to end those.
	RentPayer solana.PublicKey
	// Payer is the ticket's payer, whose token account takes the refund.
	Payer solana.PublicKey
	// Treasury is the Config's treasury, read only when Fallback passes its
	// USDC account; set_config can move it, so it comes from the Config, not
	// a constant. Left zero there, it names the default key's account, which
	// the program refuses as the forfeit's destination.
	Treasury solana.PublicKey
	Fallback RefundFallback
}

func (d Deployment) ending(name string, e Ending, args func(w *writer)) solana.Instruction {
	w := writer{}
	args(&w)
	w.u8(d.RefundBumps(e.Payer).PayerATA)
	node := d.Node(e.OperatorID, e.NodeID)
	treasuryUSDC := readonly(d.Program)
	if e.Fallback != NoFallback {
		treasuryUSDC = solana.AccountMeta{PublicKey: d.TokenAccount(e.Treasury), IsWritable: e.Fallback == FallbackWritable}
	}
	return d.ix(name, w.b, append([]solana.AccountMeta{
		signer(e.Submitter),
		readonly(d.Config()),
		writable(node),
		writable(d.Vault(node)),
		writable(d.Ticket(node, e.TicketID)),
		writable(e.RentPayer),
		writable(d.TokenAccount(e.Payer)),
		readonly(d.Mint),
		readonly(solana.SysvarInstructionsID),
		readonly(solana.TokenProgramID),
		treasuryUSDC,
	}, d.eventCPI()...)...)
}

// Claim is the node's half of a settle, signed by its current signing key.
// On an open ticket it is the first half, which lapses to the node at the
// deadline unless the payer answers; on the payer's first half it is the
// second, which settles if the fields match and freezes the ticket if not.
// Reposting the same fields is a no-op; other fields are refused.
func (d Deployment) Claim(e Ending, f ClaimFields) solana.Instruction {
	return d.ending("claim", e, f.put)
}

// SettleCooperative settles on the payer's ack: an Ed25519 precompile
// instruction over the ack digest, or the payer's own signature on the
// transaction, which the program checks by introspection.
func (d Deployment) SettleCooperative(e Ending, f ClaimFields) solana.Instruction {
	return d.ending("settle_cooperative", e, f.put)
}

// Ack is the payer's half of a settle, signed by the payer, with the same
// rules as Claim from the other side: on an open ticket the first half,
// which refund_inactive refunds in full at the deadline unless the node
// answers.
func (d Deployment) Ack(e Ending, f ClaimFields) solana.Instruction {
	return d.ending("ack", e, f.put)
}

// SettleLapsed pays a node's claim the payer did not answer by the deadline,
// the claim the ticket holds.
func (d Deployment) SettleLapsed(e Ending) solana.Instruction {
	return d.ending("settle_lapsed", e, func(*writer) {})
}

// RefundInactive refunds the whole escrow of a ticket the node never claimed,
// or whose payer-posted first half the node never answered, after the
// deadline.
func (d Deployment) RefundInactive(e Ending) solana.Instruction {
	return d.ending("refund_inactive", e, func(*writer) {})
}

// ResolveFrozen is the admin's split of a frozen ticket: the node is awarded
// operatorShareBps of the pre-fee ceiling, the protocol its fee on that, and
// the rest returns to the payer. reason is the admin's stated basis, at most
// 1024 bytes, kept in the TicketResolved event.
func (d Deployment) ResolveFrozen(e Ending, operatorShareBps uint16, reason string) solana.Instruction {
	return d.ending("resolve_frozen", e, func(w *writer) {
		w.u16(operatorShareBps)
		w.vec([]byte(reason))
	})
}

// Protest freezes a ticket on the node's receipt, which the payer proves the
// node signed with an Ed25519 precompile instruction beside it. On a ticket
// with a pending half, the receipt must be the one whose digest that half
// carries, as Algorand requires the protested digest to equal the pending
// one.
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
