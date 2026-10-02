/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/zs"
)

type openAIErrorEnvelope struct {
	Error openAIError `json:"error"`
}

type openAIError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    string `json:"code,omitempty"`
}

// writeOpenAIError writes an OpenAI-shaped error JSON body with the given
// HTTP status. Safe to call before any other response headers are written.
func writeOpenAIError(w http.ResponseWriter, status int, errType, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(openAIErrorBody(errType, code, message))
}

// openAIErrorBody is the JSON body writeOpenAIError sends, newline included.
func openAIErrorBody(errType, code, message string) []byte {
	b, _ := json.Marshal(openAIErrorEnvelope{
		Error: openAIError{
			Message: message,
			Type:    errType,
			Code:    code,
		},
	})
	return append(b, '\n')
}

// errorShape is one dispatch error code's Kind and how the OpenAI-compatible
// surface renders it. The code decides both, so a site names only the code and
// its message: Kind and status can't drift apart between two sites that
// report the same condition.
type errorShape struct {
	kind    zs.Kind
	status  int
	errType string
}

var errorShapes = map[string]errorShape{
	"missing_model":                   {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	"bad_image_request":               {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	"bad_image_edit_request":          {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	"max_output_required":             {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	"pin_conflicts_with_continuation": {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	"unsupported_tool":                {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	"context_length_exceeded":         {zs.KindContextExceeded, http.StatusBadRequest, "invalid_request_error"},
	"price_ceiling_exceeded":          {zs.KindPriceRejected, http.StatusBadRequest, "invalid_request_error"},

	"no_operator":            {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_compatible_operator": {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_production_operator": {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_pinned_operator":     {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_funded_operator":     {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_tee_capacity":        {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_tool_capacity":       {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_ephemeral_capacity":  {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"no_relay_available":     {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	"operators_busy":         {zs.KindBusy, http.StatusServiceUnavailable, "service_unavailable"},
	"operators_unreachable":  {zs.KindUnreachable, http.StatusServiceUnavailable, "service_unavailable"},
	"mbr_pool_exhausted":     {zs.KindBusy, http.StatusTooManyRequests, "rate_limit_exceeded"},

	"free_quota_exhausted":  {zs.KindFunds, http.StatusForbidden, "invalid_request_error"},
	"wallet_unfunded":       {zs.KindFunds, http.StatusPaymentRequired, "insufficient_quota"},
	"mbr_pool_underfunded":  {zs.KindFunds, http.StatusPaymentRequired, "insufficient_quota"},
	"spend_cap_exceeded":    {zs.KindSpendCap, http.StatusPaymentRequired, "insufficient_quota"},
	"ticket_price_rejected": {zs.KindOperatorFault, http.StatusBadGateway, "bad_gateway"},
	"operator_ticket_reuse": {zs.KindOperatorFault, http.StatusBadGateway, "bad_gateway"},

	"registry":     {zs.KindInternal, http.StatusBadGateway, "proxy_error"},
	"tokenize":     {zs.KindInternal, http.StatusBadGateway, "proxy_error"},
	"wrap_request": {zs.KindInternal, http.StatusBadGateway, "proxy_error"},
	// Not Unreachable: the code also covers an operator's bad presigned group
	// and a submit that timed out after algod may have accepted it, and a
	// caller reads Unreachable as nothing paid, safe to retry.
	"wallet_open": {zs.KindInternal, http.StatusBadGateway, "proxy_error"},

	// After the open: escrow holds the payer's money from here on.
	// build_request fails on the operator- or relay-published base URL.
	"build_request":                  {zs.KindOperatorFault, http.StatusBadGateway, "proxy_error"},
	"upstream_unreachable":           {zs.KindInterrupted, http.StatusBadGateway, "proxy_error"},
	"read_upstream":                  {zs.KindInterrupted, http.StatusBadGateway, "proxy_error"},
	"response_handler":               {zs.KindOperatorFault, http.StatusBadGateway, "proxy_error"},
	"stream_setup":                   {zs.KindOperatorFault, http.StatusBadGateway, "proxy_error"},
	"operator_unsealed_response":     {zs.KindOperatorFault, http.StatusBadGateway, "proxy_error"},
	"operator_inconsistent_response": {zs.KindOperatorFault, http.StatusBadGateway, "proxy_error"},
	"no_flusher":                     {zs.KindInternal, http.StatusInternalServerError, "proxy_error"},
}

// kindShapes renders a code errorShapes doesn't list. The one site that can
// reach it is the payer refusal, whose code comes from payerRefusalCodes, so
// KindFunds renders as that site's 403 rather than the table's 402.
var kindShapes = map[zs.Kind]errorShape{
	zs.KindInvalidRequest:  {zs.KindInvalidRequest, http.StatusBadRequest, "invalid_request_error"},
	zs.KindContextExceeded: {zs.KindContextExceeded, http.StatusBadRequest, "invalid_request_error"},
	zs.KindPriceRejected:   {zs.KindPriceRejected, http.StatusBadRequest, "invalid_request_error"},
	zs.KindNoRoute:         {zs.KindNoRoute, http.StatusServiceUnavailable, "service_unavailable"},
	zs.KindBusy:            {zs.KindBusy, http.StatusServiceUnavailable, "service_unavailable"},
	zs.KindUnreachable:     {zs.KindUnreachable, http.StatusServiceUnavailable, "service_unavailable"},
	zs.KindFunds:           {zs.KindFunds, http.StatusForbidden, "invalid_request_error"},
	zs.KindSpendCap:        {zs.KindSpendCap, http.StatusPaymentRequired, "insufficient_quota"},
	zs.KindOperatorFault:   {zs.KindOperatorFault, http.StatusBadGateway, "bad_gateway"},
	zs.KindUpstream:        {zs.KindUpstream, http.StatusBadGateway, "bad_gateway"},
	zs.KindInterrupted:     {zs.KindInterrupted, http.StatusBadGateway, "bad_gateway"},
	zs.KindInternal:        {zs.KindInternal, http.StatusInternalServerError, "proxy_error"},
}

// newError builds the Error for a code in errorShapes. An unlisted code is
// KindInternal, which TestErrorCodesAreListed keeps from happening by accident.
func newError(code, message string) *zs.Error {
	kind := zs.KindInternal
	if sh, ok := errorShapes[code]; ok {
		kind = sh.kind
	}
	return &zs.Error{Kind: kind, Code: code, Message: message}
}

// writeError renders e as an OpenAI-shaped error response.
func writeError(w http.ResponseWriter, e *zs.Error) {
	sh, ok := errorShapes[e.Code]
	if !ok {
		sh = kindShapes[e.Kind]
	}
	if e.RetryAfter > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(int(e.RetryAfter.Seconds())))
	}
	writeOpenAIError(w, sh.status, sh.errType, e.Code, e.Message)
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
// drained out from under an in-flight open). All three mean the same thing to
// the payer — fund the pool — and none of them is a balance shortfall, so
// without this branch the operator gets a misleading generic 502 instead of
// "raise zs.concurrent_slots".
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
