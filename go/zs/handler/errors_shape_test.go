/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/zs"
)

// The status and type a client sees for each code are the contract the move to
// zs.Error must not change, so they are spelled out here rather than read back
// from errorShapes.
func TestErrorShapes(t *testing.T) {
	want := map[string]errorShape{
		"missing_model":                   {zs.KindInvalidRequest, 400, "invalid_request_error"},
		"bad_image_request":               {zs.KindInvalidRequest, 400, "invalid_request_error"},
		"bad_image_edit_request":          {zs.KindInvalidRequest, 400, "invalid_request_error"},
		"max_output_required":             {zs.KindInvalidRequest, 400, "invalid_request_error"},
		"pin_conflicts_with_continuation": {zs.KindInvalidRequest, 400, "invalid_request_error"},
		"unsupported_tool":                {zs.KindInvalidRequest, 400, "invalid_request_error"},
		"context_length_exceeded":         {zs.KindContextExceeded, 400, "invalid_request_error"},
		"price_ceiling_exceeded":          {zs.KindPriceRejected, 400, "invalid_request_error"},
		"no_operator":                     {zs.KindNoRoute, 503, "service_unavailable"},
		"no_compatible_operator":          {zs.KindNoRoute, 503, "service_unavailable"},
		"no_production_operator":          {zs.KindNoRoute, 503, "service_unavailable"},
		"no_pinned_operator":              {zs.KindNoRoute, 503, "service_unavailable"},
		"no_funded_operator":              {zs.KindNoRoute, 503, "service_unavailable"},
		"no_tee_capacity":                 {zs.KindNoRoute, 503, "service_unavailable"},
		"no_tool_capacity":                {zs.KindNoRoute, 503, "service_unavailable"},
		"no_ephemeral_capacity":           {zs.KindNoRoute, 503, "service_unavailable"},
		"no_relay_available":              {zs.KindNoRoute, 503, "service_unavailable"},
		"operators_busy":                  {zs.KindBusy, 503, "service_unavailable"},
		"operators_unreachable":           {zs.KindUnreachable, 503, "service_unavailable"},
		"mbr_pool_exhausted":              {zs.KindBusy, 429, "rate_limit_exceeded"},
		"free_quota_exhausted":            {zs.KindFunds, 403, "invalid_request_error"},
		"wallet_unfunded":                 {zs.KindFunds, 402, "insufficient_quota"},
		"mbr_pool_underfunded":            {zs.KindFunds, 402, "insufficient_quota"},
		"spend_cap_exceeded":              {zs.KindSpendCap, 402, "insufficient_quota"},
		"ticket_price_rejected":           {zs.KindOperatorFault, 502, "bad_gateway"},
		"operator_ticket_reuse":           {zs.KindOperatorFault, 502, "bad_gateway"},
		"registry":                        {zs.KindInternal, 502, "proxy_error"},
		"tokenize":                        {zs.KindInternal, 502, "proxy_error"},
		"wrap_request":                    {zs.KindInternal, 502, "proxy_error"},
		"wallet_open":                     {zs.KindInternal, 502, "proxy_error"},
		"build_request":                   {zs.KindOperatorFault, 502, "proxy_error"},
		"upstream_unreachable":            {zs.KindInterrupted, 502, "proxy_error"},
		"read_upstream":                   {zs.KindInterrupted, 502, "proxy_error"},
		"response_handler":                {zs.KindOperatorFault, 502, "proxy_error"},
		"stream_setup":                    {zs.KindOperatorFault, 502, "proxy_error"},
		"operator_unsealed_response":      {zs.KindOperatorFault, 502, "proxy_error"},
		"operator_inconsistent_response":  {zs.KindOperatorFault, 502, "proxy_error"},
		"no_flusher":                      {zs.KindInternal, 500, "proxy_error"},
	}
	if len(errorShapes) != len(want) {
		t.Errorf("errorShapes has %d codes, this test pins %d", len(errorShapes), len(want))
	}
	for code, w := range want {
		if got, ok := errorShapes[code]; !ok || got != w {
			t.Errorf("%s: got %+v (listed %v), want %+v", code, got, ok, w)
		}
	}
}

// An unlisted code would build a KindInternal error and render by kind, so a
// typo or a new site that skips the table changes what the client sees.
func TestErrorCodesAreListed(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	seen := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", f, err)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if id, ok := call.Fun.(*ast.Ident); !ok || id.Name != "newError" || len(call.Args) == 0 {
				return true
			}
			lit, ok := call.Args[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				t.Errorf("%s: newError with a non-literal code; list it in errorShapes and pass the literal", fset.Position(call.Pos()))
				return true
			}
			code, _ := strconv.Unquote(lit.Value)
			if _, ok := errorShapes[code]; !ok {
				t.Errorf("%s: code %q is not in errorShapes", fset.Position(call.Pos()), code)
			}
			seen++
			return true
		})
	}
	if seen < 30 {
		t.Fatalf("found %d newError calls; the scan is looking in the wrong place", seen)
	}
}

func TestWriteError(t *testing.T) {
	render := func(e *zs.Error) (*httptest.ResponseRecorder, openAIErrorEnvelope) {
		t.Helper()
		w := httptest.NewRecorder()
		writeError(w, e)
		var env openAIErrorEnvelope
		if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
			t.Fatalf("body %q: %v", w.Body.String(), err)
		}
		return w, env
	}

	w, env := render(newError("operators_busy", "msg"))
	if w.Code != http.StatusServiceUnavailable || env.Error.Type != "service_unavailable" || env.Error.Code != "operators_busy" || env.Error.Message != "msg" {
		t.Errorf("listed code: status %d, body %+v", w.Code, env)
	}
	if h := w.Header().Get("Retry-After"); h != "" {
		t.Errorf("Retry-After %q with no RetryAfter set", h)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q", ct)
	}
	if got, want := w.Body.String(), `{"error":{"message":"msg","type":"service_unavailable","code":"operators_busy"}}`+"\n"; got != want {
		t.Errorf("body %q, want %q", got, want)
	}

	e := newError("operators_busy", "msg")
	e.RetryAfter = 7 * time.Second
	if w, _ := render(e); w.Header().Get("Retry-After") != "7" {
		t.Errorf("Retry-After = %q, want 7", w.Header().Get("Retry-After"))
	}

	// A code added to payerRefusalCodes without an errorShapes entry: rendered
	// by its Kind, as the 403 every payer refusal is today.
	w, env = render(&zs.Error{Kind: zs.KindFunds, Code: "new_payer_refusal", Message: "m"})
	if w.Code != http.StatusForbidden || env.Error.Type != "invalid_request_error" || env.Error.Code != "new_payer_refusal" {
		t.Errorf("unlisted code: status %d, body %+v", w.Code, env)
	}

	if e := newError("not_a_code", "m"); e.Kind != zs.KindInternal {
		t.Errorf("unlisted code got Kind %q, want internal", e.Kind)
	}
}

// A payer refusal is built at its site rather than through newError, so the
// table test doesn't reach it. Its Retry-After is when the quota resets, and it
// ends the sweep: every other operator would refuse the same payer.
//
// The unlisted code is one added to payerRefusalCodes without an errorShapes
// entry: the Kind set at the site is all that keeps it a 403 payer refusal.
func TestDispatch_PayerRefusalRendersNodeCodeAndRetryAfter(t *testing.T) {
	for _, code := range []string{"free_quota_exhausted", "unlisted_payer_refusal"} {
		t.Run(code, func(t *testing.T) {
			refusal := &zs.PayerRefusalError{Code: code, Message: "daily free tickets used", RetryAfter: time.Hour}
			rc := &scriptedReserveClient{script: []error{refusal, refusal}}
			s := retryServer(t, false, rc, []zs.Operator{retryOp(1, "OWNER_A"), retryOp(2, "OWNER_B")})
			s.cfg = &Config{Privacy: zs.PrivacyDirect, Affinity: zs.AffinityNone}
			s.tokenizer = testTokenizer()
			s.wallet = &fakeWallet{}

			body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`)
			w := httptest.NewRecorder()
			s.dispatchHayai(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body))), endpointChatCompletions, body, formatChat)

			var env openAIErrorEnvelope
			if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
				t.Fatalf("body %q: %v", w.Body.String(), err)
			}
			if w.Code != http.StatusForbidden || env.Error.Type != "invalid_request_error" || env.Error.Code != code || env.Error.Message != "daily free tickets used" {
				t.Errorf("status %d, body %+v", w.Code, env)
			}
			if got := w.Header().Get("Retry-After"); got != "3600" {
				t.Errorf("Retry-After = %q, want 3600", got)
			}
			if n := rc.calls(); n != 1 {
				t.Errorf("%d reserves, want 1: a payer refusal must end the sweep", n)
			}
		})
	}
}

func TestKindShapesCoverEveryKind(t *testing.T) {
	for _, k := range []zs.Kind{
		zs.KindInvalidRequest, zs.KindContextExceeded, zs.KindNoRoute, zs.KindBusy,
		zs.KindUnreachable, zs.KindPriceRejected, zs.KindFunds, zs.KindSpendCap,
		zs.KindOperatorFault, zs.KindUpstream, zs.KindInterrupted, zs.KindInternal,
	} {
		if sh, ok := kindShapes[k]; !ok || sh.status == 0 || sh.errType == "" || sh.kind != k {
			t.Errorf("kindShapes[%s] = %+v, %v", k, sh, ok)
		}
	}
}
