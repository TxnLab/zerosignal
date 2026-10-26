/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

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
// An error no caller judged retryable says so, since an OpenAI SDK would
// otherwise resend a 5xx on its own.
func writeOpenAIError(w http.ResponseWriter, status int, errType, code, message string) {
	if w.Header().Get(shouldRetryHeader) == "" {
		setShouldRetry(w.Header(), false)
	}
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

// errorShape is how the OpenAI-compatible surface renders an error.
type errorShape struct {
	status  int
	errType string
}

// errorShapes renders each code dispatch reports. The code decides the shape,
// as it decides the Kind on the zs side.
var errorShapes = map[string]errorShape{
	"missing_model":                   {http.StatusBadRequest, "invalid_request_error"},
	"bad_image_request":               {http.StatusBadRequest, "invalid_request_error"},
	"bad_image_edit_request":          {http.StatusBadRequest, "invalid_request_error"},
	"max_output_required":             {http.StatusBadRequest, "invalid_request_error"},
	"pin_conflicts_with_continuation": {http.StatusBadRequest, "invalid_request_error"},
	"unsupported_tool":                {http.StatusBadRequest, "invalid_request_error"},
	"context_length_exceeded":         {http.StatusBadRequest, "invalid_request_error"},
	"price_ceiling_exceeded":          {http.StatusBadRequest, "invalid_request_error"},

	// A model nobody serves is OpenAI's 404. The next three can't be served as
	// sent, or as the proxy is configured, until someone changes something;
	// a 5xx would invite a client that ignores X-Should-Retry to resend.
	"no_operator":            {http.StatusNotFound, "invalid_request_error"},
	"no_compatible_operator": {http.StatusBadRequest, "invalid_request_error"},
	"no_production_operator": {http.StatusBadRequest, "invalid_request_error"},
	"no_pinned_operator":     {http.StatusBadRequest, "invalid_request_error"},
	"no_funded_operator":     {http.StatusServiceUnavailable, "service_unavailable"},
	"no_tee_capacity":        {http.StatusServiceUnavailable, "service_unavailable"},
	"no_tool_capacity":       {http.StatusServiceUnavailable, "service_unavailable"},
	"no_ephemeral_capacity":  {http.StatusServiceUnavailable, "service_unavailable"},
	"no_relay_available":     {http.StatusServiceUnavailable, "service_unavailable"},
	"operators_busy":         {http.StatusServiceUnavailable, "service_unavailable"},
	"operators_unreachable":  {http.StatusServiceUnavailable, "service_unavailable"},
	"mbr_pool_exhausted":     {http.StatusTooManyRequests, "rate_limit_exceeded"},
	// The client closed the request; nobody reads this. 499 is the de facto
	// "client closed request" status, and keeps it out of the server-error
	// counts a 5xx would land in.
	"canceled": {499, "proxy_error"},

	"free_quota_exhausted":        {http.StatusForbidden, "invalid_request_error"},
	"free_budget_exhausted":       {http.StatusForbidden, "invalid_request_error"},
	"payer_not_opted_in":          {http.StatusForbidden, "invalid_request_error"},
	"payer_usdc_account_unusable": {http.StatusForbidden, "invalid_request_error"},
	"wallet_unfunded":             {http.StatusPaymentRequired, "insufficient_quota"},
	"mbr_pool_underfunded":        {http.StatusPaymentRequired, "insufficient_quota"},
	"spend_cap_exceeded":          {http.StatusPaymentRequired, "insufficient_quota"},
	"ticket_price_rejected":       {http.StatusBadGateway, "bad_gateway"},
	"operator_ticket_reuse":       {http.StatusBadGateway, "bad_gateway"},

	"registry":     {http.StatusBadGateway, "proxy_error"},
	"tokenize":     {http.StatusBadGateway, "proxy_error"},
	"wrap_request": {http.StatusBadGateway, "proxy_error"},
	"wallet_open":  {http.StatusBadGateway, "proxy_error"},

	"build_request":                  {http.StatusBadGateway, "proxy_error"},
	"upstream_unreachable":           {http.StatusBadGateway, "proxy_error"},
	"read_upstream":                  {http.StatusBadGateway, "proxy_error"},
	"response_handler":               {http.StatusBadGateway, "proxy_error"},
	"stream_setup":                   {http.StatusBadGateway, "proxy_error"},
	"operator_unsealed_response":     {http.StatusBadGateway, "proxy_error"},
	"operator_inconsistent_response": {http.StatusBadGateway, "proxy_error"},
	// Only ever rendered as the SSE error frame (writeSSEError): the stream's
	// status line is already on the wire by the time it can happen.
	"stream_interrupted": {http.StatusBadGateway, "proxy_error"},
	"no_flusher":         {http.StatusInternalServerError, "proxy_error"},
	// Unreachable here: the handler sets FramesOnly, so the node's own error
	// frame is what its caller sees.
	"upstream_error": {http.StatusBadGateway, "bad_gateway"},
}

// kindShapes renders a code errorShapes doesn't list. The one site that can
// reach it is the payer refusal, whose code comes from payerRefusalCodes, so
// KindFunds renders as that site's 403 rather than the table's 402.
var kindShapes = map[zs.Kind]errorShape{
	zs.KindInvalidRequest:  {http.StatusBadRequest, "invalid_request_error"},
	zs.KindContextExceeded: {http.StatusBadRequest, "invalid_request_error"},
	zs.KindPriceRejected:   {http.StatusBadRequest, "invalid_request_error"},
	zs.KindNoRoute:         {http.StatusServiceUnavailable, "service_unavailable"},
	zs.KindBusy:            {http.StatusServiceUnavailable, "service_unavailable"},
	zs.KindUnreachable:     {http.StatusServiceUnavailable, "service_unavailable"},
	zs.KindFunds:           {http.StatusForbidden, "invalid_request_error"},
	zs.KindSpendCap:        {http.StatusPaymentRequired, "insufficient_quota"},
	zs.KindOperatorFault:   {http.StatusBadGateway, "bad_gateway"},
	zs.KindUpstream:        {http.StatusBadGateway, "bad_gateway"},
	zs.KindInterrupted:     {http.StatusBadGateway, "bad_gateway"},
	zs.KindInternal:        {http.StatusInternalServerError, "proxy_error"},
}

// writeError renders e as an OpenAI-shaped error response.
func writeError(w http.ResponseWriter, e *zs.Error) {
	sh, ok := errorShapes[e.Code]
	if !ok {
		sh = kindShapes[e.Kind]
	}
	setShouldRetry(w.Header(), shouldRetry(e))
	setRetryAfter(w.Header(), e.RetryAfter)
	writeOpenAIError(w, sh.status, sh.errType, e.Code, e.Message)
}

// setRetryAfter writes d in whole seconds, and removes any Retry-After when
// there is no wait to advise.
func setRetryAfter(h http.Header, d time.Duration) {
	if d <= 0 {
		h.Del("Retry-After")
		return
	}
	h.Set("Retry-After", strconv.Itoa(int(d.Seconds())))
}

// shouldRetryHeader overrides the status for OpenAI's SDKs (Python, Node,
// Go), which otherwise resend any 408, 409, 429 or 5xx on their own.
const shouldRetryHeader = "X-Should-Retry"

// shouldRetry is whether a client may resend on its own. Never after Paid: an
// automatic resend is a second payment the payer did not choose, so that
// choice is left to code that reads Error.Paid.
func shouldRetry(e *zs.Error) bool { return e.Retryable && !e.Paid }

func setShouldRetry(h http.Header, retry bool) {
	h.Set(shouldRetryHeader, strconv.FormatBool(retry))
}
