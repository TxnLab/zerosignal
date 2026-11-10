/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"errors"
	"log/slog"
)

// recordSpend runs a SpendGuard Settle or Release. The outcome is already
// decided by then, and what follows, the receipt journal and the settle a
// restart re-fires, must still run, so a host guard that panics is logged
// and the caller carries on. The TS twin is guardRecords.
func recordSpend(log *slog.Logger, method, ticketID string, call func()) {
	defer func() {
		if p := recover(); p != nil {
			log.Warn("spend guard "+method+" failed", slog.String("ticket_id", ticketID), slog.Any("panic", p))
		}
	}()
	call()
}

// SpendGuard is the caller's spending policy, consulted at two checkpoints.
// All amounts are microUSDC. Implementations must be safe for concurrent use.
//
// After a successful Reserve the request resolves the ticket with Settle or
// Release at most once, except a free Solana turn (MaxPrice 0, nothing
// opened): it is Released at once, and its receipt check may resolve it
// again, Settle at 0 or Release. When it cannot (no verified receipt arrived), the
// refund watchdog and the ticket reconciler may resolve it once the ticket
// ends on chain. Both Release on a refund they submitted. The reconciler also
// Settles a lapse it submitted, at the operator's claim, Releases whatever is
// left of a ticket whose receipt the request already settled, and Releases a
// ticket whose $0 operator claim it accepted. A guard that already counted a
// receipt above 0 for that ticket keeps the charge, overstating the spend. A
// ticket none of them sees end is never resolved here, because until the box
// closes the operator can still claim up to MaxPrice; the guard keeps that
// exposure until its own window ends. Neither resolves a lapse the node sends
// itself, which is the usual one.
//
// So Settle and Release can arrive more than once for a ticket, and for one
// already resolved; a guard keyed by ticket id, counting only the first,
// counts each charge once.
//
// An Admit refusal ends the request with KindSpendCap. A Reserve refusal moves
// on to the next candidate, and the request ends with KindSpendCap only when
// no candidate fits and none was merely busy. A Reserve refusal that wraps
// ErrDuplicateTicket ends the request at once with KindOperatorFault.
type SpendGuard interface {
	// Admit runs before any reserve with the lowest max_price any candidate is
	// expected to sign, priced from advertised rates. It is advisory and errs
	// both ways: a node can sign above it, so a cap must also be enforced at
	// Reserve, or below it (a lower rate, or a tighter context window), so a
	// guard refusing near its limit can turn away a request that would have
	// fit. Refusing here spares the nodes a reservation. It records nothing,
	// and is skipped when a candidate cannot be priced.
	Admit(estimate uint64) error

	// Reserve runs after a node signs a ticket and before escrow opens,
	// with the ticket's MaxPrice: the most the operator can claim. A nil
	// return records that exposure against ticketID.
	Reserve(ticketID string, maxPrice uint64) error

	// Settle reports the verified charge for a reserved ticket.
	Settle(ticketID string, charged uint64)

	// Release drops a reservation that never became a charge: the open
	// failed, the receipt failed verification, or a refund ended the ticket.
	Release(ticketID string)

	// The watchdog and the reconciler call Settle and Release from their own
	// goroutines, for tickets the request already resolved and, after a
	// restart, for tickets this process never reserved. Both must be a no-op
	// for a ticket with no open reservation; a guard that persists its
	// reservations is what gives the second kind something to free.
}

// ErrDuplicateTicket marks a Reserve refusal caused by a ticket id that
// already has an open reservation. Ticket ids are minted by the node, so a
// repeat is the node's misbehaviour, not the payer's cap. An implementation
// must wrap this variable itself; an error that merely reads the same is
// reported as KindSpendCap.
var ErrDuplicateTicket = errors.New("ticket id already has an open reservation")
