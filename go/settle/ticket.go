/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package settle holds the settlement rules every payment rail shares: what a
// live ticket allows right now, and the protocol fee on a settled charge. Each
// rail decodes its own ticket record (escrow for Algorand) into a Ticket, so
// the payer's refund watchdog and reconciler and the node's sweep ask one
// question with one answer whichever chain the ticket lives on.
//
// proto/ts/src/settle is its TypeScript mirror, pinned to this one by
// testdata/settle_vectors.json — change both and regenerate the vectors.
package settle

import "time"

// Status is a live ticket's state, in the terms the settlement rules use
// rather than any one chain's encoding.
type Status uint8

const (
	// StatusUnrecognized is a state the rail's decoder does not know: a record
	// newer than the bindings, or one the contract never writes. The zero value,
	// so a view a decoder forgot to fill classifies as Unknown, never as Wait.
	StatusUnrecognized Status = iota
	// StatusOpen: funded, with no claim recorded.
	StatusOpen
	// StatusPendingPayer: the payer has recorded its half of a cooperative
	// settle and the operator has not matched it.
	StatusPendingPayer
	// StatusPendingOperator: the operator has recorded a claim the payer has
	// not matched.
	StatusPendingOperator
	// StatusFrozen: the two sides disagreed, or the payer protested. Terminal:
	// no contract call accepts it, and there is no on-chain resolution path.
	StatusFrozen
)

// Ticket is the rail-neutral view of a live ticket that the settlement rules
// read.
type Ticket struct {
	Status Status
	// Deadline is D = expires_at + the settlement grace, in unix seconds, read
	// off the ticket itself. It is authoritative over any deadline recomputed
	// from a cached grace setting, which the admin can rotate.
	Deadline uint64
}

// DeadlineTime is Deadline as a time.Time.
func (t Ticket) DeadlineTime() time.Time { return time.Unix(int64(t.Deadline), 0) }

// Verdict is what can legally happen to a live ticket right now.
//
// The two deadline calls are disjoint by construction — refundInactive
// requires no operator claim, settleLapsed requires one — so the two are never
// both legal for the same ticket (and for Wait/Arbitrate, neither is).
type Verdict uint8

const (
	// VerdictWait: a recognized state whose settlement window is still open
	// (now <= D). Either side may settle, and the payer may protest. Neither
	// deadline call is legal yet, but waiting until D makes one of them legal.
	VerdictWait Verdict = iota + 1
	// VerdictRefund: past D with no operator claim (open, or carrying the
	// payer's own unmatched half). refundInactive is legal and returns the full
	// max_price to the payer. Callable by anyone, but the payer is normally the
	// only party that knows the ticket was orphaned.
	VerdictRefund
	// VerdictLapse: past D carrying an operator claim. settleLapsed is legal: it
	// pays the claimed amount and refunds the rest of max_price. Callable by
	// anyone; the operator's driver normally does it.
	VerdictLapse
	// VerdictArbitrate: frozen. No settle, protest or deadline call accepts it
	// at any time, and there is no unfreeze or admin close, so the escrowed
	// funds stay locked; any resolution is off-chain. Report it; don't imply it
	// resolves itself.
	VerdictArbitrate
	// VerdictUnknown: a state the rules don't recognize. Deliberately NOT
	// folded into VerdictWait: no call is known to be legal here, and unlike
	// Wait, waiting never changes that. Callers that collapse the two end up
	// telling the user "too early, try again after the deadline" about a ticket
	// that will never be refundable.
	VerdictUnknown
)

// String renders the verdict as the name of the call it authorizes, for logs
// and CLI output.
func (v Verdict) String() string {
	switch v {
	case VerdictWait:
		return "wait"
	case VerdictRefund:
		return "refundInactive"
	case VerdictLapse:
		return "settleLapsed"
	case VerdictArbitrate:
		return "arbitrate"
	case VerdictUnknown:
		return "unknown"
	}
	return "invalid"
}

// Classify reports what can legally happen to t at now.
//
// Callers that pad now for clock skew should do it themselves — the skew
// between a local clock and the chain's clock is the caller's problem, not a
// property of the ticket.
func Classify(t Ticket, now time.Time) Verdict {
	// Recognize the state BEFORE consulting the clock. Both deadline calls
	// require the chain's clock past D, so the clock decides between Wait and
	// the call — but only for a state that has a call to wait for. Checking the
	// deadline first would answer "wait" for a state no call accepts, which
	// reads as "this becomes legal at D". It never does. Frozen outranks the
	// clock for the same reason.
	switch t.Status {
	case StatusFrozen:
		return VerdictArbitrate
	case StatusOpen, StatusPendingPayer:
		if !now.After(t.DeadlineTime()) {
			return VerdictWait
		}
		return VerdictRefund
	case StatusPendingOperator:
		if !now.After(t.DeadlineTime()) {
			return VerdictWait
		}
		return VerdictLapse
	}
	return VerdictUnknown
}
