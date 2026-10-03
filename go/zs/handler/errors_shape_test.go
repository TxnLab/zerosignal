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
	"strconv"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/zs"
)

// The status and type a client sees for each code are the contract, so they
// are spelled out here rather than read back from errorShapes.
func TestErrorShapes(t *testing.T) {
	want := map[string]errorShape{
		"missing_model":                   {400, "invalid_request_error"},
		"bad_image_request":               {400, "invalid_request_error"},
		"bad_image_edit_request":          {400, "invalid_request_error"},
		"max_output_required":             {400, "invalid_request_error"},
		"pin_conflicts_with_continuation": {400, "invalid_request_error"},
		"unsupported_tool":                {400, "invalid_request_error"},
		"context_length_exceeded":         {400, "invalid_request_error"},
		"price_ceiling_exceeded":          {400, "invalid_request_error"},
		"no_operator":                     {404, "invalid_request_error"},
		"no_compatible_operator":          {400, "invalid_request_error"},
		"no_production_operator":          {400, "invalid_request_error"},
		"no_pinned_operator":              {400, "invalid_request_error"},
		"no_funded_operator":              {503, "service_unavailable"},
		"no_tee_capacity":                 {503, "service_unavailable"},
		"no_tool_capacity":                {503, "service_unavailable"},
		"no_ephemeral_capacity":           {503, "service_unavailable"},
		"no_relay_available":              {503, "service_unavailable"},
		"operators_busy":                  {503, "service_unavailable"},
		"operators_unreachable":           {503, "service_unavailable"},
		"mbr_pool_exhausted":              {429, "rate_limit_exceeded"},
		"free_quota_exhausted":            {403, "invalid_request_error"},
		"wallet_unfunded":                 {402, "insufficient_quota"},
		"mbr_pool_underfunded":            {402, "insufficient_quota"},
		"spend_cap_exceeded":              {402, "insufficient_quota"},
		"ticket_price_rejected":           {502, "bad_gateway"},
		"operator_ticket_reuse":           {502, "bad_gateway"},
		"registry":                        {502, "proxy_error"},
		"tokenize":                        {502, "proxy_error"},
		"wrap_request":                    {502, "proxy_error"},
		"wallet_open":                     {502, "proxy_error"},
		"build_request":                   {502, "proxy_error"},
		"upstream_unreachable":            {502, "proxy_error"},
		"read_upstream":                   {502, "proxy_error"},
		"response_handler":                {502, "proxy_error"},
		"stream_setup":                    {502, "proxy_error"},
		"operator_unsealed_response":      {502, "proxy_error"},
		"operator_inconsistent_response":  {502, "proxy_error"},
		"stream_interrupted":              {502, "proxy_error"},
		"upstream_error":                  {502, "bad_gateway"},
		"no_flusher":                      {500, "proxy_error"},
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

// Every code the Client reports must have a shape here: an unlisted one falls
// back to its Kind's, which for several kinds is a different status than the
// code has always had. The Client's table is unexported, so it is read from
// source.
func TestErrorShapesCoverEveryClientCode(t *testing.T) {
	file, err := parser.ParseFile(token.NewFileSet(), "../codes.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	ast.Inspect(file, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "errorKinds" || len(vs.Values) != 1 {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatal("errorKinds is not a composite literal")
		}
		for _, elt := range lit.Elts {
			kv := elt.(*ast.KeyValueExpr)
			code, err := strconv.Unquote(kv.Key.(*ast.BasicLit).Value)
			if err != nil {
				t.Fatal(err)
			}
			if _, ok := errorShapes[code]; !ok {
				t.Errorf("Client code %q has no entry in errorShapes", code)
			}
			seen++
		}
		return false
	})
	if seen < 30 {
		t.Fatalf("read %d codes from errorKinds; the scan is looking in the wrong place", seen)
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

	busy := func() *zs.Error { return &zs.Error{Kind: zs.KindBusy, Code: "operators_busy", Message: "msg"} }
	w, env := render(busy())
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

	e := busy()
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
}

// A payer refusal is built at its site rather than from the Client's code
// table, so the table tests don't reach it. Its Retry-After is when the quota
// resets, and it ends the sweep: every other operator would refuse the same
// payer.
//
// The unlisted code is one added to payerRefusalCodes without an errorShapes
// entry: the Kind set at the site is all that keeps it a 403 payer refusal.
func TestDispatch_PayerRefusalRendersNodeCodeAndRetryAfter(t *testing.T) {
	for _, code := range []string{"free_quota_exhausted", "unlisted_payer_refusal"} {
		t.Run(code, func(t *testing.T) {
			rc := &refusingReserveClient{err: &zs.PayerRefusalError{Code: code, Message: "daily free tickets used", RetryAfter: time.Hour}}
			s := gatesServer(t, &Config{Privacy: zs.PrivacyDirect, Affinity: zs.AffinityNone}, rc,
				gatesOp(1, "OWNER_A"), gatesOp(2, "OWNER_B"))

			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
				`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`))

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
			if n := len(rc.ops); n != 1 {
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
		if sh, ok := kindShapes[k]; !ok || sh.status == 0 || sh.errType == "" {
			t.Errorf("kindShapes[%s] = %+v, %v", k, sh, ok)
		}
	}
}
