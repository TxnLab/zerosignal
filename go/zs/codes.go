/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/json"
	"errors"
	"strings"

	"github.com/TxnLab/zerosignal/go/escrow"
)

// errorKinds is the Kind of every code dispatch reports. The code decides it,
// so a site names only the code and its message: two sites that report the
// same condition can't disagree on its Kind. An adapter keys its own rendering
// (an HTTP status, say) off the code too, falling back to the Kind for a code
// it doesn't list.
var errorKinds = map[string]Kind{
	"missing_model":                   KindInvalidRequest,
	"bad_image_request":               KindInvalidRequest,
	"bad_image_edit_request":          KindInvalidRequest,
	"max_output_required":             KindInvalidRequest,
	"pin_conflicts_with_continuation": KindInvalidRequest,
	"unsupported_tool":                KindInvalidRequest,
	"context_length_exceeded":         KindContextExceeded,
	"price_ceiling_exceeded":          KindPriceRejected,

	"no_operator":            KindNoRoute,
	"no_compatible_operator": KindNoRoute,
	"no_production_operator": KindNoRoute,
	"no_pinned_operator":     KindNoRoute,
	"no_funded_operator":     KindNoRoute,
	"no_tee_capacity":        KindNoRoute,
	"no_tool_capacity":       KindNoRoute,
	"no_ephemeral_capacity":  KindNoRoute,
	"no_relay_available":     KindNoRoute,
	"operators_busy":         KindBusy,
	"operators_unreachable":  KindUnreachable,
	"mbr_pool_exhausted":     KindBusy,
	// The caller's context ended during the reserve sweep, before any open.
	"canceled": KindInterrupted,

	"free_quota_exhausted":  KindFunds,
	"payer_not_opted_in":    KindFunds,
	"wallet_unfunded":       KindFunds,
	"mbr_pool_underfunded":  KindFunds,
	"spend_cap_exceeded":    KindSpendCap,
	"ticket_price_rejected": KindOperatorFault,
	"operator_ticket_reuse": KindOperatorFault,

	"registry":     KindInternal,
	"tokenize":     KindInternal,
	"wrap_request": KindInternal,
	// Not Unreachable: the code also covers an operator's bad presigned group
	// and a submit that timed out after algod may have accepted it, and a
	// caller reads Unreachable as nothing paid, safe to retry.
	"wallet_open": KindInternal,

	// After the open: escrow holds the payer's money from here on.
	// build_request fails on the operator- or relay-published base URL.
	"build_request":                  KindOperatorFault,
	"upstream_unreachable":           KindInterrupted,
	"read_upstream":                  KindInterrupted,
	"response_handler":               KindOperatorFault,
	"stream_setup":                   KindOperatorFault,
	"operator_unsealed_response":     KindOperatorFault,
	"operator_inconsistent_response": KindOperatorFault,
	// The stream broke after its first frame: the caller has part of a turn.
	"stream_interrupted": KindInterrupted,
	// The provider failed inside the node's response. The node's own code, if
	// any, rides on the cause as a ProviderError, never here: it is the node's
	// choice and could name one of these.
	"upstream_error": KindUpstream,
}

// newError builds the Error for a code in errorKinds. An unlisted code is
// KindInternal, which TestErrorCodesAreListed keeps from happening by accident.
func newError(code, message string) *Error {
	kind, ok := errorKinds[code]
	if !ok {
		kind = KindInternal
	}
	return &Error{Kind: kind, Code: code, Message: message}
}

// openAIErrorBody is an OpenAI-shaped error body, newline included, for a
// node reply the SDK replaces because it could not parse it.
func openAIErrorBody(errType, code, message string) []byte {
	type body struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    string `json:"code,omitempty"`
	}
	b, _ := json.Marshal(struct {
		Error body `json:"error"`
	}{body{Message: message, Type: errType, Code: code}})
	return append(b, '\n')
}

// underfundedOpenSignatures are the algod ledger-eval substrings that mean the
// escrow open failed because the payer can't cover it: too little ALGO for fees
// / min-balance ("overspend", "below min"), too little USDC to lock ("underflow"
// on the asset subtract), or no USDC opt-in ("missing from"). Kept tight so an
// unrelated submit failure stays a 502 rather than a misleading "fund me" 402.
var underfundedOpenSignatures = []string{"overspend", "below min", "underflow", "missing from"}

// isUnderfundedOpenError reports whether a Wallet.Open failure was caused by the
// payer being unable to pay (vs a protocol/transport fault), so dispatch can
// surface an actionable 402 wallet_unfunded instead of a generic 502.
func isUnderfundedOpenError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sig := range underfundedOpenSignatures {
		if strings.Contains(msg, sig) {
			return true
		}
	}
	return false
}

// poolExhaustedAsserts are the three open() guards on the payer's prepaid
// ticket-MBR pool: not enough headroom for another ticket slot, not enough for
// the one-time free-quota box, or no deposit at all (the pool was closed or
// drained out from under an in-flight open). None of them is a balance
// shortfall, so without this branch the operator gets a misleading generic 502.
// A revert Wallet.Open could not clear by topping the pool up carries that
// top-up's failure too, which dispatch answers first.
var poolExhaustedAsserts = map[string]bool{
	escrow.AssertInsufficientMbrDeposit:          true,
	escrow.AssertInsufficientMbrDepositFreeQuota: true,
	escrow.AssertPayerHasNoMbrDeposit:            true,
}

// escrowOpenMethod is the ABI method name enrichSubmitError stamps onto an
// open() revert. The message alone is NOT enough to classify: Wallet.Open also
// runs the prepaid-pool top-up, so a depositMbr revert reaches this classifier
// through the same return value, and the contract can grow a guard sharing one
// of these messages on a different entry point at any time. Advising
// "raise zs.concurrent_slots, retry in 2s" about a call that is not an open
// is confident, actionable, and wrong. Checked against the real ABI by
// TestPoolExhaustedMethodNameIsARealABIMethod; the identity is pinned by the
// classifier's own fixtures and its method sweep.
const escrowOpenMethod = "open"

// isPoolExhaustedOpenError reports whether a Wallet.Open failure was an
// MBR-pool-headroom revert (vs a balance shortfall or a protocol fault), so
// dispatch can point the operator at zs.concurrent_slots with a 429 rather
// than a bare 502. Distinct from isUnderfundedOpenError: the wallet HOLDS the
// ALGO, it's just all reserved by in-flight tickets.
//
// Matches the typed revert, never the error text. algod reports only
// "assert failed pc=NNN" — the assert message exists solely because the escrow
// client resolves that PC through the embedded ARC-56 source map — so a
// text-matching version of this check is testable but inert against a real
// node, which is exactly what it was.
func isPoolExhaustedOpenError(err error) bool {
	revert, ok := errors.AsType[*escrow.ApprovalError](err)
	return ok && revert.Method == escrowOpenMethod && poolExhaustedAsserts[revert.Message]
}
