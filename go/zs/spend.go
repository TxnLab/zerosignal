/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import "errors"

// SpendGuard is the caller's spending policy, consulted at two checkpoints.
// All amounts are microUSDC. Implementations must be safe for concurrent use.
//
// After a successful Reserve the SDK calls Settle or Release at most once for
// that ticket, and possibly neither: a ticket that ends in a refund, a lapse
// or an interruption without a verified receipt is never resolved here,
// because until the box closes the operator can still claim up to MaxPrice.
// The guard keeps that exposure until its own window ends.
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
	// failed, or the receipt failed verification.
	Release(ticketID string)
}

// ErrDuplicateTicket marks a Reserve refusal caused by a ticket id that
// already has an open reservation. Ticket ids are minted by the node, so a
// repeat is the node's misbehaviour, not the payer's cap. An implementation
// must wrap this variable itself; an error that merely reads the same is
// reported as KindSpendCap.
var ErrDuplicateTicket = errors.New("ticket id already has an open reservation")
