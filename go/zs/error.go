/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"fmt"
	"time"

	"github.com/TxnLab/zerosignal/go/transient"
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
	// KindOperatorFault: the operator misbehaved; the SDK protested or
	// excluded the node. Paid or not depending on when it was caught.
	KindOperatorFault Kind = "operator_fault"
	// KindUpstream: the provider behind the node failed after payment; the
	// charge follows the node's receipt, often zero.
	KindUpstream Kind = "upstream"
	// KindInterrupted: the turn stopped after payment (caller cancel,
	// transport loss, the node refusing admission). The SDK settles or
	// refunds Ticket on its own; nothing is resent.
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

	// Retryable and Attribution come from the shared transient package's
	// predicates, never from a status code alone. Retryable is advice to the
	// caller about a fresh request; the SDK itself never resends after Paid.
	Retryable   bool
	RetryAfter  time.Duration
	Attribution transient.Attribution

	// Paid reports whether escrow was opened for this turn. When it was,
	// Ticket is the handle that can still move that money, and the SDK keeps
	// driving it to settle, protest or refund; Stream.Wait reports when it is
	// final.
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
