/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"time"

	"github.com/TxnLab/zerosignal/go/settle"
)

// Verdict is what can legally happen to a live ticket box right now. The
// rules are the rail-neutral ones in package settle; escrow's part is mapping
// ZeroSignalEscrow's box encoding onto them (View). The payer's refund
// watchdog, the operator's settlement sweep, and any tool reporting on a stuck
// ticket all ask the same question and must not answer it differently.
//
// The verdicts and their names are settle's (TS ts/src/settle, pinned by
// testdata/settle_vectors.json). The box mapping is this package's, mirrored
// by ticketView in proto/ts/src/escrow/classify.ts and pinned by
// testdata/escrow_vectors.json.
//
// On this contract a frozen ticket also keeps the payer's MBR slot
// (openTickets, which gates closeDeposit), so that payer's closeDeposit
// reverts until the admin's resolveFrozen deletes the box. The box records
// when and by which path it froze (FrozenAt, FreezeOrigin), which is what an
// arbiter reads; the verdict doesn't depend on either.
type Verdict = settle.Verdict

const (
	VerdictWait      = settle.VerdictWait
	VerdictRefund    = settle.VerdictRefund
	VerdictLapse     = settle.VerdictLapse
	VerdictArbitrate = settle.VerdictArbitrate
	VerdictUnknown   = settle.VerdictUnknown
)

// SettlementDeadline is D = expires_at + settlement_grace_seconds, the only
// clock a ticket has. Both refundInactive and settleLapsed gate on it, and it
// is carried on the box itself — authoritative over any deadline recomputed
// from the cached `grace` global, which the admin can rotate.
func (t *TicketRecord) SettlementDeadline() time.Time {
	return t.View().DeadlineTime()
}

// View maps the box onto the rail-neutral ticket the settlement rules read.
// Only StatusOpen, StatusFrozen, and StatusPendingSettle with a side are ever
// written; StatusSettled / StatusRefunded correspond to box deletion, and a
// pending settle with no side is not a state the contract writes, so each of
// those reads as unrecognized.
func (t *TicketRecord) View() settle.Ticket {
	v := settle.Ticket{Deadline: t.ExpiresAt + t.SettlementGraceSeconds}
	switch {
	case t.Status == StatusOpen:
		v.Status = settle.StatusOpen
	case t.Status == StatusFrozen:
		v.Status = settle.StatusFrozen
	case t.Status == StatusPendingSettle && t.PendingBy == PendingByPayer:
		v.Status = settle.StatusPendingPayer
	case t.Status == StatusPendingSettle && t.PendingBy == PendingByOperator:
		v.Status = settle.StatusPendingOperator
	}
	return v
}

// Classify reports what can legally happen to t at now. t must be non-nil; an
// absent box stays the caller's concern, since ReadTicketBox returns (nil, nil)
// for one and each caller reads a different meaning into it (the watchdog: a
// benign settle it lost sight of; a sweep: nothing to do).
func Classify(t *TicketRecord, now time.Time) Verdict {
	return settle.Classify(t.View(), now)
}
