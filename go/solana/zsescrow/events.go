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

// The program emits events by invoking itself (Anchor's emit_cpi), signed by
// the event authority, so they sit in a transaction's inner instructions,
// where a log truncation can't drop them. The data is EventIxTag, the event's
// discriminator, then its Borsh fields.

// EventIxTag is Anchor's EVENT_IX_TAG, little-endian.
var EventIxTag = [8]byte{0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d}

var ErrNotEvent = errors.New("zsescrow: not an event")

// SettleOutcome is how a ticket ended.
type SettleOutcome uint8

const (
	OutcomeCooperative SettleOutcome = iota
	OutcomeAcked
	OutcomeLapsed
	OutcomeRefundedInactive
	OutcomeResolved
)

func (o SettleOutcome) String() string {
	switch o {
	case OutcomeCooperative:
		return "Cooperative"
	case OutcomeAcked:
		return "Acked"
	case OutcomeLapsed:
		return "Lapsed"
	case OutcomeRefundedInactive:
		return "RefundedInactive"
	case OutcomeResolved:
		return "Resolved"
	}
	return "SettleOutcome(" + strconv.Itoa(int(o)) + ")"
}

type TicketSettled struct {
	Ticket  solana.PublicKey `json:"ticket"`
	Node    solana.PublicKey `json:"node"`
	Outcome SettleOutcome    `json:"outcome"`
	Amount  uint64           `json:"amount"`
	Fee     uint64           `json:"fee"`
	Refund  uint64           `json:"refund"`
	// RefundForfeited: the payer's token account couldn't take the refund,
	// so it went to the treasury, as Algorand's payOrForfeit sends it.
	RefundForfeited bool `json:"refund_forfeited"`
}

// TicketClaimed is a first half of a settle: the node's claim, or the
// payer's (ByPayer).
type TicketClaimed struct {
	Ticket  solana.PublicKey `json:"ticket"`
	Node    solana.PublicKey `json:"node"`
	Amount  uint64           `json:"amount"`
	ByPayer bool             `json:"by_payer"`
}

type TicketProtested struct {
	Ticket solana.PublicKey `json:"ticket"`
	Node   solana.PublicKey `json:"node"`
	Reason uint8            `json:"reason"`
	// Amount is what the protested receipt charged, read from the bytes the
	// node signed.
	Amount uint64 `json:"amount"`
}

// TicketDisputed is a second half that differed from the first, which froze
// the ticket.
type TicketDisputed struct {
	Ticket solana.PublicKey `json:"ticket"`
	Node   solana.PublicKey `json:"node"`
	// Claimed is what the first half charged; Amount is what the second
	// half charged.
	Claimed uint64 `json:"claimed"`
	Amount  uint64 `json:"amount"`
}

// TicketResolved is the admin's split of a frozen ticket, beside the
// TicketSettled that pays it, with the admin's stated reason.
type TicketResolved struct {
	Ticket           solana.PublicKey `json:"ticket"`
	Node             solana.PublicKey `json:"node"`
	OperatorShareBps uint16           `json:"operator_share_bps"`
	Reason           string           `json:"reason"`
}

type OperatorEvicted struct {
	OperatorID uint64 `json:"operator_id"`
	Slashed    uint64 `json:"slashed"`
	Reason     string `json:"reason"`
}

// IsEventInstruction reports whether an inner instruction is one of d's
// event self-invocations: to the program, with its event authority as the
// one account. Only the program can sign for that authority, and the
// program's event handler refuses an unsigned call, so in a transaction that
// succeeded such an instruction is the program's own; data of that shape
// anywhere else is a forgery. A caller must read events only from the inner
// instructions of a transaction whose meta.err is null: a failed
// transaction's metadata can still list inner instructions, events of state
// that never landed.
func (d Deployment) IsEventInstruction(programID solana.PublicKey, accounts []solana.PublicKey) bool {
	return programID == d.Program && len(accounts) == 1 && accounts[0] == d.EventAuthority()
}

// ParseEvent decodes an event self-invocation's data. It returns
// ErrNotEvent for the data of an instruction that is not an event, and
// otherwise one of TicketSettled, TicketClaimed, TicketProtested,
// TicketDisputed, TicketResolved or OperatorEvicted. Check
// IsEventInstruction first.
func ParseEvent(data []byte) (any, error) {
	if len(data) < 16 || [8]byte(data[:8]) != EventIxTag {
		return nil, ErrNotEvent
	}
	r := &reader{b: data, off: 16}
	var ev any
	switch [8]byte(data[8:16]) {
	case discriminator("event", "TicketSettled"):
		ev = TicketSettled{Ticket: r.key(), Node: r.key(), Outcome: SettleOutcome(r.u8()), Amount: r.u64(), Fee: r.u64(), Refund: r.u64(), RefundForfeited: r.bool()}
	case discriminator("event", "TicketClaimed"):
		ev = TicketClaimed{Ticket: r.key(), Node: r.key(), Amount: r.u64(), ByPayer: r.bool()}
	case discriminator("event", "TicketProtested"):
		ev = TicketProtested{Ticket: r.key(), Node: r.key(), Reason: r.u8(), Amount: r.u64()}
	case discriminator("event", "TicketDisputed"):
		ev = TicketDisputed{Ticket: r.key(), Node: r.key(), Claimed: r.u64(), Amount: r.u64()}
	case discriminator("event", "TicketResolved"):
		e := TicketResolved{Ticket: r.key(), Node: r.key(), OperatorShareBps: r.u16()}
		reason, err := utf8String(r)
		if err != nil {
			return nil, err
		}
		e.Reason = reason
		ev = e
	case discriminator("event", "OperatorEvicted"):
		e := OperatorEvicted{OperatorID: r.u64(), Slashed: r.u64()}
		reason, err := utf8String(r)
		if err != nil {
			return nil, err
		}
		e.Reason = reason
		ev = e
	default:
		return nil, fmt.Errorf("%w: discriminator %x", ErrNotEvent, data[8:16])
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.off != len(data) {
		return nil, fmt.Errorf("%w: %d trailing bytes", ErrDecode, len(data)-r.off)
	}
	return ev, nil
}

// utf8String reads a Borsh String. The program writes Rust Strings, so
// anything but UTF-8 is not its event; refusing it keeps Go and TS from
// reading two different reasons.
func utf8String(r *reader) (string, error) {
	b := r.vec()
	if r.err == nil && !utf8.Valid(b) {
		return "", fmt.Errorf("%w: reason is not UTF-8", ErrDecode)
	}
	return string(b), nil
}
