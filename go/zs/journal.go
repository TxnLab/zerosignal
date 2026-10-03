/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// TicketStatus is a journaled ticket's local state. Terminal tickets are
// deleted, not marked.
type TicketStatus string

const (
	// TicketOpen: escrow is open and no verified receipt has been seen. Once
	// the box's deadline passes the reconciler refunds it, or calls
	// settleLapsed when the operator has a pending claim, since
	// refundInactive reverts on such a box.
	TicketOpen TicketStatus = "open"
	// TicketSettlePending: a verified receipt was seen and Settle holds the
	// arguments to re-fire the payer's settle if the first submit was lost.
	TicketSettlePending TicketStatus = "settle_pending"
)

// TicketRecord is what the reconciler needs to finish a ticket after a
// restart. Every field is public on chain; no prompt or response content
// belongs here. That rules out a body_hash protest, which needs a content
// excerpt: a restart between the violation and the protest loses it, and
// the ticket falls back to the deadline path.
type TicketRecord struct {
	TicketID string
	OpenTxID string
	// EscrowAppID scopes the record to one deployment: the same payer
	// address is valid on every network, so a journal shared across them
	// must never re-fire a testnet ticket against mainnet.
	EscrowAppID uint64
	Target      NodeRef
	Payer       string
	MaxPrice    uint64
	// ExpiresAt is the ticket's expiry. The contract refuses an open after
	// it, so a box still missing then never appears. Once the box exists its
	// own deadline is authoritative.
	ExpiresAt time.Time
	Status    TicketStatus
	CreatedAt time.Time
	UpdatedAt time.Time
	// Settle is set with TicketSettlePending.
	Settle *SettleArgs
}

// SettleArgs are the receipt values the payer co-signs on settle(). The
// contract freezes the ticket if they disagree with the node's half, so a
// re-fire must send them verbatim.
type SettleArgs struct {
	AmountCharged      uint64
	ReceiptDigest      [32]byte
	TtftMs             uint64
	DecodeMs           uint64
	InputTokens        uint64
	OutputTokens       uint64
	OutputUsageType    ticket.UsageType
	AuxOutputUsageType ticket.UsageType
	AuxOutputCount     uint64
}

// TicketJournal persists open tickets so a restarted process can still
// settle or refund them. Without one, a restart strands every open ticket
// until someone calls RefundInactive by hand. Implementations must be safe
// for concurrent use.
type TicketJournal interface {
	// Put inserts or replaces the record for rec.TicketID.
	Put(ctx context.Context, rec TicketRecord) error
	// Delete removes a ticket that reached a terminal state. Deleting an
	// unknown id is not an error.
	Delete(ctx context.Context, ticketID string) error
	// List returns the records for payer under escrowAppID only.
	List(ctx context.Context, payer string, escrowAppID uint64) ([]TicketRecord, error)
}
