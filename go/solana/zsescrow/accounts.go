/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zsescrow

import (
	"errors"
	"fmt"
	"strconv"
	"unicode/utf8"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The decoders read an account's data. None checks the account's owner, which
// is not in the data: a caller must check the owner is the program (the token
// program for a TokenAccount) before it trusts anything decoded here.

var (
	ErrDiscriminator = errors.New("zsescrow: not this account type")
	// ErrVersion is an account a later program wrote: its reserve bytes may
	// hold fields this decoder can't see, so it refuses rather than guesses.
	ErrVersion = errors.New("zsescrow: unknown account version")
)

func accountReader(name string, data []byte, size int) (*reader, error) {
	disc := discriminator("account", name)
	if len(data) < 8 || [8]byte(data[:8]) != disc {
		return nil, fmt.Errorf("%w: want %s", ErrDiscriminator, name)
	}
	if len(data) < size {
		return nil, fmt.Errorf("%w: %s of %d bytes, want %d", ErrDecode, name, len(data), size)
	}
	if v := data[8]; v != AccountVersion {
		return nil, fmt.Errorf("%w: %s version %d", ErrVersion, name, v)
	}
	return &reader{b: data, off: 8}, nil
}

const (
	ConfigSize   = 349
	OperatorSize = 171
	NodeSize     = 880
	TicketSize   = 275
	RentPoolSize = 82
)

// Config's Retired fields are the program's: retired with the owed vault,
// the separate registry pause and the arbiter seat, but kept in the layout so
// every later offset stays put on the clusters that already hold a Config.
// A Config initialized before their retirement holds values there until the
// admin's next set_config, which zeroes them; nothing reads them.
type Config struct {
	Version               uint8            `json:"version"`
	Bump                  uint8            `json:"bump"`
	StakeVaultBump        uint8            `json:"stake_vault_bump"`
	RetiredOwedVaultBump  uint8            `json:"_retired_owed_vault_bump"`
	USDCDecimals          uint8            `json:"usdc_decimals"`
	Paused                bool             `json:"paused"`
	RetiredPauseRegistry  bool             `json:"_retired_pause_registry"`
	FeeBps                uint16           `json:"fee_bps"`
	MaxGrace              uint32           `json:"max_grace"`
	DefaultGrace          uint32           `json:"default_grace"`
	MaxTicketLifetime     int64            `json:"max_ticket_lifetime"`
	OperatorStake         uint64           `json:"operator_stake"`
	NodeStake             uint64           `json:"node_stake"`
	NextOperatorID        uint64           `json:"next_operator_id"`
	Admin                 solana.PublicKey `json:"admin"`
	RetiredArbiter        solana.PublicKey `json:"_retired_arbiter"`
	USDCMint              solana.PublicKey `json:"usdc_mint"`
	Treasury              solana.PublicKey `json:"treasury"`
	GenesisHash           solana.Hash      `json:"genesis_hash"`
	PendingAdmin          solana.PublicKey `json:"pending_admin"`
	MinGrace              uint32           `json:"min_grace"`
	RetiredPendingArbiter solana.PublicKey `json:"_retired_pending_arbiter"`
	Reserve               [64]byte         `json:"_reserve"`
}

func DecodeConfig(data []byte) (*Config, error) {
	r, err := accountReader("Config", data, ConfigSize)
	if err != nil {
		return nil, err
	}
	c := &Config{
		Version: r.u8(), Bump: r.u8(), StakeVaultBump: r.u8(), RetiredOwedVaultBump: r.u8(), USDCDecimals: r.u8(),
		Paused: r.bool(), RetiredPauseRegistry: r.bool(),
		FeeBps: r.u16(), MaxGrace: r.u32(), DefaultGrace: r.u32(), MaxTicketLifetime: r.i64(),
		OperatorStake: r.u64(), NodeStake: r.u64(), NextOperatorID: r.u64(),
		Admin: r.key(), RetiredArbiter: r.key(), USDCMint: r.key(), Treasury: r.key(),
	}
	r.array(c.GenesisHash[:])
	c.PendingAdmin = r.key()
	c.MinGrace = r.u32()
	c.RetiredPendingArbiter = r.key()
	r.array(c.Reserve[:])
	return c, r.err
}

// OperatorStatus keeps an unknown variant's byte rather than failing, so a
// status a later program adds reads as unknown, never as Active.
type OperatorStatus uint8

const (
	OperatorStatusActive OperatorStatus = iota
	OperatorStatusEvicted
)

func (s OperatorStatus) String() string {
	switch s {
	case OperatorStatusActive:
		return "Active"
	case OperatorStatusEvicted:
		return "Evicted"
	}
	return "OperatorStatus(" + strconv.Itoa(int(s)) + ")"
}

type Operator struct {
	Version       uint8            `json:"version"`
	Status        OperatorStatus   `json:"status"`
	Bump          uint8            `json:"bump"`
	ID            uint64           `json:"id"`
	NextNodeID    uint64           `json:"next_node_id"`
	LiveNodeCount uint64           `json:"live_node_count"`
	Stake         uint64           `json:"stake"`
	Owner         solana.PublicKey `json:"owner"`
	NameRef       solana.PublicKey `json:"name_ref"`
	Reserve       [64]byte         `json:"_reserve"`
}

func DecodeOperator(data []byte) (*Operator, error) {
	r, err := accountReader("Operator", data, OperatorSize)
	if err != nil {
		return nil, err
	}
	o := &Operator{
		Version: r.u8(), Status: OperatorStatus(r.u8()), Bump: r.u8(),
		ID: r.u64(), NextNodeID: r.u64(), LiveNodeCount: r.u64(), Stake: r.u64(),
		Owner: r.key(), NameRef: r.key(),
	}
	r.array(o.Reserve[:])
	return o, r.err
}

// NodeActive is the only status a node is created with.
const NodeActive = 1

// OutputUnitsLen and RingDays size the node's metric arrays.
const (
	OutputUnitsLen = 8
	RingDays       = 30
)

// Node is zero-copy on chain: its fields sit at fixed offsets with no
// padding, the same bytes a sequential read gives.
type Node struct {
	Version     uint8            `json:"version"`
	Status      uint8            `json:"status"`
	Staging     uint8            `json:"staging"`
	Bump        uint8            `json:"bump"`
	VaultBump   uint8            `json:"vault_bump"`
	BaseURLLen  uint8            `json:"base_url_len"`
	Pad0        [2]byte          `json:"_pad0"`
	Signing     solana.PublicKey `json:"signing"`
	Vault       solana.PublicKey `json:"vault"`
	Operator    solana.PublicKey `json:"operator"`
	BaseURL     string           `json:"base_url"`
	OperatorID  uint64           `json:"operator_id"`
	NodeID      uint64           `json:"node_id"`
	Stake       uint64           `json:"stake"`
	AccruedPay  uint64           `json:"accrued_payout"`
	AccruedFee  uint64           `json:"accrued_fee"`
	LiveTickets uint64           `json:"live_tickets"`
	OpensTotal  uint64           `json:"opens_total"`
	// The metrics are the Algorand NodeRecord's, folded by the same rules.
	LastActivityAt  int64                  `json:"last_activity_at"`
	SettledCount    uint64                 `json:"settled_count"`
	LapsedCount     uint64                 `json:"lapsed_count"`
	RefundedCount   uint64                 `json:"refunded_count"`
	RefundedTotal   uint64                 `json:"refunded_total"`
	LatencyTotalMs  uint64                 `json:"latency_total_ms"`
	LatencySamples  uint64                 `json:"latency_samples"`
	TTFTEwmaMs      uint64                 `json:"ttft_ewma_ms"`
	DecodeTPSEwma   uint64                 `json:"decode_tps_ewma"`
	RevenueTotal    uint64                 `json:"revenue_total"`
	InputUnitsTotal uint64                 `json:"input_units_total"`
	OutputUnits     [OutputUnitsLen]uint64 `json:"output_units"`
	RingDay         int64                  `json:"ring_day"`
	RingRevenue     [RingDays]uint64       `json:"ring_revenue"`
	ProtestedCount  uint64                 `json:"protested_count"`
	ProtestedTotal  uint64                 `json:"protested_total"`
	// FrozenDisputeCount and FrozenDisputeTotal are Algorand's
	// ticketsFrozenDispute and totalFrozenDisputeUsdc: the tickets whose two
	// settle halves differed, and Σ what each first half charged.
	FrozenDisputeCount uint64 `json:"frozen_dispute_count"`
	FrozenDisputeTotal uint64 `json:"frozen_dispute_total"`
	// ResolvedCount and ResolvedTotal are Algorand's ticketsResolvedAdmin and
	// totalResolvedUsdc: the frozen tickets the admin resolved, and Σ the
	// node's award before its fee.
	ResolvedCount uint64   `json:"resolved_count"`
	ResolvedTotal uint64   `json:"resolved_total"`
	Reserve       [16]byte `json:"_reserve"`
}

func DecodeNode(data []byte) (*Node, error) {
	r, err := accountReader("Node", data, NodeSize)
	if err != nil {
		return nil, err
	}
	n := &Node{Version: r.u8(), Status: r.u8(), Staging: r.u8(), Bump: r.u8(), VaultBump: r.u8(), BaseURLLen: r.u8()}
	r.array(n.Pad0[:])
	n.Signing, n.Vault, n.Operator = r.key(), r.key(), r.key()
	url := r.take(BaseURLMax)
	if int(n.BaseURLLen) > BaseURLMax {
		return nil, fmt.Errorf("%w: base_url_len %d", ErrDecode, n.BaseURLLen)
	}
	// The program stores a Rust String, so anything but UTF-8 is a corrupt
	// account; refusing it keeps Go and TS from reading two different URLs.
	if !utf8.Valid(url[:n.BaseURLLen]) {
		return nil, fmt.Errorf("%w: base_url is not UTF-8", ErrDecode)
	}
	n.BaseURL = string(url[:n.BaseURLLen])
	n.OperatorID, n.NodeID, n.Stake = r.u64(), r.u64(), r.u64()
	n.AccruedPay, n.AccruedFee, n.LiveTickets, n.OpensTotal = r.u64(), r.u64(), r.u64(), r.u64()
	n.LastActivityAt = r.i64()
	n.SettledCount, n.LapsedCount, n.RefundedCount, n.RefundedTotal = r.u64(), r.u64(), r.u64(), r.u64()
	n.LatencyTotalMs, n.LatencySamples, n.TTFTEwmaMs, n.DecodeTPSEwma = r.u64(), r.u64(), r.u64(), r.u64()
	n.RevenueTotal, n.InputUnitsTotal = r.u64(), r.u64()
	for i := range n.OutputUnits {
		n.OutputUnits[i] = r.u64()
	}
	n.RingDay = r.i64()
	for i := range n.RingRevenue {
		n.RingRevenue[i] = r.u64()
	}
	n.ProtestedCount, n.ProtestedTotal = r.u64(), r.u64()
	n.FrozenDisputeCount, n.FrozenDisputeTotal = r.u64(), r.u64()
	n.ResolvedCount, n.ResolvedTotal = r.u64(), r.u64()
	r.array(n.Reserve[:])
	return n, r.err
}

// TicketStatus keeps an unknown variant's byte rather than failing, as
// OperatorStatus does. The program appends variants and never reorders them,
// so a value's meaning never changes under a reader.
type TicketStatus uint8

const (
	TicketOpen TicketStatus = iota
	// TicketPendingByOperator: the node posted the first half; it lapses to
	// the node at the deadline unless the payer answers.
	TicketPendingByOperator
	// TicketFrozen: the two halves differed, or the payer protested; only
	// the admin's resolve_frozen ends it.
	TicketFrozen
	// TicketPendingByPayer: the payer posted the first half; refund_inactive
	// refunds it in full at the deadline unless the node answers.
	TicketPendingByPayer
)

func (s TicketStatus) String() string {
	switch s {
	case TicketOpen:
		return "Open"
	case TicketPendingByOperator:
		return "PendingByOperator"
	case TicketFrozen:
		return "Frozen"
	case TicketPendingByPayer:
		return "PendingByPayer"
	}
	return "TicketStatus(" + strconv.Itoa(int(s)) + ")"
}

// Which path froze a ticket, as Algorand's freezeOrigin. Zero unless the
// ticket is Frozen.
const (
	FreezeOriginSettleMismatch uint8 = 1
	FreezeOriginProtest        uint8 = 2
)

type Ticket struct {
	Version  uint8        `json:"version"`
	Status   TicketStatus `json:"status"`
	Bump     uint8        `json:"bump"`
	FeeBps   uint16       `json:"fee_bps"`
	Grace    uint32       `json:"grace"`
	OpenSeq  uint64       `json:"open_seq"`
	MaxPrice uint64       `json:"max_price"`
	// Pending is the first half's claim, all zero on an open ticket, as
	// Algorand's box keeps its pending fields: the other side's half must
	// equal it, settle_lapsed pays it, and a protest's receipt must carry its
	// digest.
	Pending   ClaimFields      `json:"pending"`
	OpenedAt  int64            `json:"opened_at"`
	ExpiresAt int64            `json:"expires_at"`
	Payer     solana.PublicKey `json:"payer"`
	Node      solana.PublicKey `json:"node"`
	// NodeSigning is the node's key at open, which signs this ticket's
	// receipt; a protest checks the receipt against it, not the current key.
	NodeSigning solana.PublicKey `json:"node_signing"`
	RentPayer   solana.PublicKey `json:"rent_payer"`
	// FrozenAt and FreezeOrigin (FreezeOrigin*) are Algorand's frozenAt and
	// freezeOrigin, for whoever resolves the ticket.
	FrozenAt     int64   `json:"frozen_at"`
	FreezeOrigin uint8   `json:"freeze_origin"`
	Reserve      [7]byte `json:"_reserve"`
}

// Deadline is the last moment either half, a cooperative settle or a protest
// is accepted; settle_lapsed and refund_inactive open after it.
func (t *Ticket) Deadline() int64 {
	d := t.ExpiresAt + int64(t.Grace)
	if d < t.ExpiresAt {
		return 1<<63 - 1
	}
	return d
}

func DecodeTicket(data []byte) (*Ticket, error) {
	r, err := accountReader("Ticket", data, TicketSize)
	if err != nil {
		return nil, err
	}
	t := &Ticket{
		Version: r.u8(), Status: TicketStatus(r.u8()), Bump: r.u8(), FeeBps: r.u16(), Grace: r.u32(),
		OpenSeq: r.u64(), MaxPrice: r.u64(), Pending: r.claim(), OpenedAt: r.i64(), ExpiresAt: r.i64(),
		Payer: r.key(), Node: r.key(), NodeSigning: r.key(), RentPayer: r.key(),
	}
	t.FrozenAt, t.FreezeOrigin = r.i64(), r.u8()
	r.array(t.Reserve[:])
	return t, r.err
}

// RentPool holds the lamports a payer prepaid for its tickets' rent. What an
// open can draw, and a withdraw take, is the pool's lamports above its own
// rent exemption, which is not in the data: the rent of a live ticket sits in
// the ticket.
type RentPool struct {
	Version     uint8            `json:"version"`
	Bump        uint8            `json:"bump"`
	OpenTickets uint64           `json:"open_tickets"`
	Payer       solana.PublicKey `json:"payer"`
	Reserve     [32]byte         `json:"_reserve"`
}

func DecodeRentPool(data []byte) (*RentPool, error) {
	r, err := accountReader("RentPool", data, RentPoolSize)
	if err != nil {
		return nil, err
	}
	p := &RentPool{Version: r.u8(), Bump: r.u8(), OpenTickets: r.u64(), Payer: r.key()}
	r.array(p.Reserve[:])
	return p, r.err
}

// TokenAccountSize is an SPL token account's length.
const TokenAccountSize = 165

type TokenAccountState uint8

const (
	TokenUninitialized TokenAccountState = iota
	TokenInitialized
	TokenFrozen
)

func (s TokenAccountState) String() string {
	switch s {
	case TokenUninitialized:
		return "Uninitialized"
	case TokenInitialized:
		return "Initialized"
	case TokenFrozen:
		return "Frozen"
	}
	return "TokenAccountState(" + strconv.Itoa(int(s)) + ")"
}

// TokenAccount is an SPL token account: a vault, or an owner's USDC account.
type TokenAccount struct {
	Mint            solana.PublicKey  `json:"mint"`
	Owner           solana.PublicKey  `json:"owner"`
	Amount          uint64            `json:"amount"`
	Delegate        *solana.PublicKey `json:"delegate"`
	State           TokenAccountState `json:"state"`
	IsNative        *uint64           `json:"is_native"`
	DelegatedAmount uint64            `json:"delegated_amount"`
	CloseAuthority  *solana.PublicKey `json:"close_authority"`
}

func DecodeTokenAccount(data []byte) (*TokenAccount, error) {
	if len(data) != TokenAccountSize {
		return nil, fmt.Errorf("%w: token account of %d bytes", ErrDecode, len(data))
	}
	r := &reader{b: data}
	t := &TokenAccount{Mint: r.key(), Owner: r.key(), Amount: r.u64()}
	t.Delegate = cOption(r, r.key)
	t.State = TokenAccountState(r.u8())
	t.IsNative = cOption(r, r.u64)
	t.DelegatedAmount = r.u64()
	t.CloseAuthority = cOption(r, r.key)
	return t, r.err
}

// cOption is the token program's COption: a u32 tag, then the value, which
// is present (zeroed) even when the tag is 0.
func cOption[T any](r *reader, get func() T) *T {
	tag := r.u32()
	v := get()
	switch {
	case tag == 1:
		return &v
	case tag != 0 && r.err == nil:
		r.err = fmt.Errorf("%w: COption tag %d", ErrDecode, tag)
	}
	return nil
}
