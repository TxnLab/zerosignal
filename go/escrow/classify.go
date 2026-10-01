/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import "time"

// Verdict is what can legally happen to a live ticket box right now, derived
// from the contract's settlement rules (ZeroSignalEscrow.algo.ts). It is the
// home for those rules on the Go side: the payer's refund watchdog, the
// operator's settlement sweep, and any tool reporting on a stuck ticket all ask
// the same question and must not answer it differently.
//
// Not the only implementation in the tree, though: client/'s ticket-reconciler
// (TypeScript) encodes the same table for the browser payer. escrow has no
// proto/ts mirror and no golden vectors, so nothing enforces their agreement —
// a change here should be checked against it by hand.
//
// The two deadline calls are disjoint by construction — refundInactive asserts
// 'ticket not refundable' against an operator-side claim, settleLapsed asserts
// 'ticket not pending settle' against everything else — so the two are never
// both legal for the same box (and for Wait/Arbitrate, neither is).
type Verdict uint8

const (
	// VerdictWait: a state the contract recognizes, whose settlement window is
	// still open (now <= D). Either side may settle(), and the payer may
	// protest(). Neither deadline call is legal yet — both assert
	// Global.latestTimestamp > D — but waiting until D makes one of them legal.
	VerdictWait Verdict = iota + 1
	// VerdictRefund: past D with no operator claim (STATUS_OPEN, or
	// STATUS_PENDING_SETTLE carrying the payer's own unmatched claim).
	// refundInactive is legal and returns the full max_price to the payer.
	// Callable by anyone, but the payer is normally the only party that knows
	// the ticket was orphaned.
	VerdictRefund
	// VerdictLapse: past D carrying an operator-side claim. settleLapsed is
	// legal — it disburses the claimed amount and refunds the remainder of
	// max_price. Callable by anyone; the operator's driver normally does it.
	VerdictLapse
	// VerdictArbitrate: STATUS_FROZEN. No contract method accepts a frozen
	// ticket — not settle, not protest, not refundInactive, not settleLapsed —
	// and there is no unfreeze or admin close. Both the escrowed USDC and the
	// payer's MBR slot (openTickets, which gates closeDeposit) stay locked
	// until the contract grows a resolution path. Report it; don't imply it
	// resolves itself.
	VerdictArbitrate
	// VerdictUnknown: a status this contract never writes — StatusSettled /
	// StatusRefunded correspond to box deletion, and a pending settle always
	// records a side. Reachable only via bindings that disagree with the
	// deployed app, or a future contract that adds a state.
	//
	// Deliberately NOT folded into VerdictWait: no call is known to be legal
	// here, and unlike Wait, waiting never changes that. Callers that collapse
	// the two end up telling the user "too early, try again after the deadline"
	// about a box that will never be refundable.
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

// SettlementDeadline is D = expires_at + settlement_grace_seconds, the only
// clock a ticket has. Both refundInactive and settleLapsed gate on it, and it
// is carried on the box itself — authoritative over any deadline recomputed
// from the cached `grace` global, which the admin can rotate.
func (t *TicketRecord) SettlementDeadline() time.Time {
	return time.Unix(int64(t.ExpiresAt+t.SettlementGraceSeconds), 0)
}

// Classify reports what can legally happen to t at now. t must be non-nil; an
// absent box stays the caller's concern, since ReadTicketBox returns (nil, nil)
// for one and each caller reads a different meaning into it (the watchdog: a
// benign settle it lost sight of; a sweep: nothing to do).
//
// Callers that pad now for clock skew should do it themselves — the skew
// between a local clock and Global.latestTimestamp is the caller's problem,
// not a property of the ticket.
func Classify(t *TicketRecord, now time.Time) Verdict {
	// FROZEN outranks the clock: no method accepts a frozen ticket at any
	// time, so the deadline is irrelevant to it.
	if t.Status == StatusFrozen {
		return VerdictArbitrate
	}
	// Recognize the state BEFORE consulting the clock. Both deadline calls
	// assert Global.latestTimestamp > D, so the clock decides between Wait and
	// the call — but only for a state that has a call to wait for. Checking the
	// deadline first would answer "wait" for a status no method accepts, which
	// reads as "this becomes legal at D". It never does.
	switch {
	case t.Status == StatusOpen,
		t.Status == StatusPendingSettle && t.PendingBy == PendingByPayer:
		if !now.After(t.SettlementDeadline()) {
			return VerdictWait
		}
		return VerdictRefund
	case t.Status == StatusPendingSettle && t.PendingBy == PendingByOperator:
		if !now.After(t.SettlementDeadline()) {
			return VerdictWait
		}
		return VerdictLapse
	}
	return VerdictUnknown
}
