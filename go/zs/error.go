/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"fmt"
	"time"
)

// Kind tells the caller what to do about an Error. It is the stable contract:
// wire codes may be added under a kind without breaking callers, so branch on
// Kind and treat Code as diagnostic.
type Kind string

const (
	// KindInvalidRequest: fix the request, or the Config (code
	// invalid_config). Unpaid, except model_mismatch, which is caught after
	// payment and settles at zero.
	KindInvalidRequest Kind = "invalid_request"
	// KindContextExceeded: shorten the input or pick a larger-window model.
	KindContextExceeded Kind = "context_exceeded"
	// KindNoRoute: no operator can serve this model under the request's
	// preferences, TEE or tool requirements.
	KindNoRoute Kind = "no_route"
	// KindBusy: every candidate refused for capacity; retry after RetryAfter.
	KindBusy Kind = "busy"
	// KindUnreachable: transport failures exhausted the sweep before payment.
	KindUnreachable Kind = "unreachable"
	// KindPriceRejected: nothing is priced within the caller's ceiling.
	KindPriceRejected Kind = "price_rejected"
	// KindFunds: deposit USDC or ALGO, or wait out the free quota.
	KindFunds Kind = "funds"
	// KindSpendCap: the Config.SpendGuard refused the charge.
	KindSpendCap Kind = "spend_cap"
	// KindOperatorFault: the operator broke the protocol (a ticket priced
	// past the caller's limits, a reused ticket, a reply that is unsealed or
	// unreadable) and the SDK ended the turn. Paid or not depending on when it
	// was caught: before the open nothing was paid.
	KindOperatorFault Kind = "operator_fault"
	// KindUpstream: the provider behind the node failed after payment; the
	// charge follows the node's receipt, often zero. Err is a *ProviderError
	// when the node said why.
	KindUpstream Kind = "upstream"
	// KindInterrupted: the turn stopped (caller cancel, transport loss, the
	// node refusing admission). After payment the SDK settles or refunds
	// Ticket on its own and nothing is resent; Paid says which. A caller
	// cancel before payment is code canceled, with the context's error as Err.
	KindInterrupted Kind = "interrupted"
	// KindInternal: the SDK failed on bytes it authored. Report a bug.
	KindInternal Kind = "internal"
)

// Error is the one error type every SDK call returns. Match it with
// errors.As and switch on Kind.
type Error struct {
	Kind    Kind
	Code    string // wire or SDK code that produced it, e.g. "no_capacity"
	Message string

	// Retryable reports whether the same request, sent again as a new turn,
	// could plausibly succeed: the failure was capacity, transport or the
	// provider's, not something the caller must change first. It is false
	// when the caller's own context ended the turn. A new turn is a new
	// payment, so a caller weighing a retry reads Paid too; the SDK itself
	// never resends after Paid. RetryAfter, when set, is the wait to honor
	// first.
	Retryable  bool
	RetryAfter time.Duration

	// Paid reports whether escrow was opened for this turn: the SDK submitted
	// the open. A node saying the open never confirmed doesn't clear it, since
	// that is the node's unverified claim. When it is set, Ticket is the handle
	// that can still move that money, and the SDK keeps driving it to settle,
	// protest or refund.
	Paid   bool
	Ticket *Ticket

	// Err is the underlying cause, if any.
	Err error
}

func (e *Error) Error() string {
	msg := fmt.Sprintf("zs: %s", e.Kind)
	if e.Code != "" {
		msg += " (" + e.Code + ")"
	}
	if e.Message != "" {
		msg += ": " + e.Message
	}
	if e.Err != nil {
		msg += ": " + e.Err.Error()
	}
	return msg
}

func (e *Error) Unwrap() error { return e.Err }

// ProviderError is the cause of a KindUpstream Error: the failure the node
// reported inside its response, for the provider behind it. Code is the
// node's and is not one of the SDK's codes; like Message, it is the node's
// claim, for display and logs.
type ProviderError struct {
	Code    string
	Message string
	// Status is the HTTP status of the single-body reply that carried the
	// error, or 0 when it came in a stream frame.
	Status int
}

func (e *ProviderError) Error() string {
	if e.Code == "" {
		return "provider error"
	}
	return "provider code " + e.Code
}
