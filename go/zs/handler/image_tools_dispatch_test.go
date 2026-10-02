/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// TestDispatchHayai_ToolBudgets_SizesReserve confirms the proxy
// sizing: a /v1/responses request carrying tool_budgets adds
// the OUTER chat model's image-tool budget (max_n) to the reserve's
// the image-tool budget on the reserve request (MaxPrice, not MaxOutputTokens).
func TestDispatchHayai_ToolBudgets_SizesReserve(t *testing.T) {
	const factor uint64 = 100_000

	var reserves []ticket.ReserveRequest
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"status":"completed","output":[]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
	})
	node.operator.Models = []string{"gpt-test"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		// ImageToolRateMicroUSDC (the tool-path rate) — NOT ImageRateMicroUSDC,
		// which would falsely mark gpt-test as a dedicated image-route model.
		"gpt-test": {ImageToolRateMicroUSDC: factor, OutputUSDPer1M: 10},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	// Control run: no tool_budgets.
	base := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", base))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("control status = %d, body=%s", w.Result().StatusCode, w.Body.String())
	}

	// Budgeted run.
	budgeted := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":3}}}`
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", budgeted))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("budgeted status = %d, body=%s", w.Result().StatusCode, w.Body.String())
	}

	if len(reserves) != 2 {
		t.Fatalf("captured %d reserves, want 2", len(reserves))
	}
	control, withBudget := reserves[0], reserves[1]
	if withBudget.ImageToolBudget != 3 {
		t.Errorf("ImageToolBudget = %d, want 3", withBudget.ImageToolBudget)
	}
	if control.ImageToolBudget != 0 {
		t.Errorf("control ImageToolBudget = %d, want 0", control.ImageToolBudget)
	}
}

// TestDispatchHayai_ToolBudgets_UnsupportedTool confirms the 400 path: a
// budget for a chat model whose capacity entry lacks the synthetic-token
// factor can't be sized, so the request is refused as unsupported_tool and
// no reserve is attempted.
func TestDispatchHayai_ToolBudgets_UnsupportedTool(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	node.operator.Models = []string{"gpt-test"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"gpt-test": {OutputUSDPer1M: 10}, // ImageToolRateMicroUSDC intentionally 0 (tool not priced)
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	body := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":2}}}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", body))

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Result().StatusCode, w.Body.String())
	}
	if got := w.Body.String(); !strings.Contains(got, "unsupported_tool") {
		t.Errorf("body = %s, want unsupported_tool", got)
	}
	if node.callCount != 0 {
		t.Errorf("node.callCount = %d, want 0 — reserve must not be attempted", node.callCount)
	}
}

// TestDispatchHayai_ImageGen_SkipsChatToolModel is the regression guard for
// the overload bug: a model that advertises only the tool-path factor
// (ImageToolRateMicroUSDC) — i.e. a chat model offering zs_image_generation
// — must NOT be routed to the dedicated /v1/images/generations route. The
// proxy has no image-tool rate to size that reserve, so the request must
// fail without ever POSTing a (zero-input_tokens) reserve the node rejects.
func TestDispatchHayai_ImageGen_SkipsChatToolModel(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	node.operator.Models = []string{"gpt-test"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		// Tool-path factor only — a chat model that OFFERS the image tool,
		// not a dedicated image-route model.
		"gpt-test": {ImageToolRateMicroUSDC: 80_000, OutputUSDPer1M: 10},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/images/generations",
		`{"model":"gpt-test","prompt":"a cat","n":1}`))

	if w.Result().StatusCode == http.StatusOK {
		t.Errorf("status = 200, want 4xx/5xx — a chat-tool model must not serve the dedicated image route")
	}
	if node.callCount > 0 {
		t.Errorf("node.callCount = %d, want 0 — no image-gen reserve should be attempted", node.callCount)
	}
}

// TestDispatchHayai_ToolBudgets_BusyBeatsUnsupportedTool is the precedence
// guard: when one candidate CAN serve the budgeted image tool (it publishes
// the factor) but is busy, and another lacks the factor, the client must get
// the retryable 503 operators_busy — NOT the terminal 400 unsupported_tool.
// A busy operator only reaches the reserve after passing the factor gate, so
// it proves the tool is serviceable; masking that as "model can't do this"
// would wrongly tell the client to stop retrying. Order-independent: both
// candidates are visited, so busyHint and toolFactorMissing are both set and
// the guard (busyHint == 0 && !relayUnavailable) is what picks the 503.
func TestDispatchHayai_ToolBudgets_BusyBeatsUnsupportedTool(t *testing.T) {
	opBusy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 7})
	opFactorless := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})

	// opBusy publishes the tool-path factor, so it passes the factor gate
	// and reaches the reserve (where it returns 429).
	opBusy.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"gpt-test": {ImageToolRateMicroUSDC: 100_000, OutputUSDPer1M: 10},
	}
	// opFactorless serves the model but has no image-tool factor → skipped
	// with toolFactorMissing.
	opFactorless.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"gpt-test": {OutputUSDPer1M: 10},
	}

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, opBusy, opFactorless))

	body := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":2}}}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", body))

	if w.Result().StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Result().StatusCode, w.Body.String())
	}
	got := w.Body.String()
	if !strings.Contains(got, "operators_busy") {
		t.Errorf("body = %s, want operators_busy (not unsupported_tool)", got)
	}
	if strings.Contains(got, "unsupported_tool") {
		t.Errorf("body = %s, must not surface unsupported_tool when an operator was merely busy", got)
	}
	if ra := w.Header().Get("Retry-After"); ra != "7" {
		t.Errorf("Retry-After = %q, want 7 (propagated from the busy operator)", ra)
	}
}

// TestDispatchHayai_ToolBudgets_EditSizesReserve mirrors the generation test
// for the edit tool: a zs_image_edit budget sizes the reserve via the
// model's ImageEditToolRateMicroUSDC and forwards ImageEditToolBudget, leaving
// the generation budget at zero.
func TestDispatchHayai_ToolBudgets_EditSizesReserve(t *testing.T) {
	const factor uint64 = 120_000

	var reserves []ticket.ReserveRequest
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"status":"completed","output":[]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
	})
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"gpt-test": {ImageEditToolRateMicroUSDC: factor, OutputUSDPer1M: 10},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	base := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", base))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("control status = %d, body=%s", w.Result().StatusCode, w.Body.String())
	}

	budgeted := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_edit":{"max_n":2}}}`
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", budgeted))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("budgeted status = %d, body=%s", w.Result().StatusCode, w.Body.String())
	}

	if len(reserves) != 2 {
		t.Fatalf("captured %d reserves, want 2", len(reserves))
	}
	_, withBudget := reserves[0], reserves[1]
	if withBudget.ImageEditToolBudget != 2 {
		t.Errorf("ImageEditToolBudget = %d, want 2", withBudget.ImageEditToolBudget)
	}
	if withBudget.ImageToolBudget != 0 {
		t.Errorf("ImageToolBudget = %d, want 0 (generation not budgeted)", withBudget.ImageToolBudget)
	}
}

// TestDispatchHayai_ToolBudgets_ClampsMaxN confirms the proxy caps an
// oversized client max_n at maxImageToolBudgetPerRequest before it sizes the
// reserve. The node trusts the proxy for this clamp (it honors the raw budget
// in its tool loop), so an unbounded max_n would otherwise overflow the
// synthetic-token multiply and under-size the escrow. Because the reserve's
// asserting the forwarded ImageToolBudget == ceiling proves the budget is bounded.
func TestDispatchHayai_ToolBudgets_ClampsMaxN(t *testing.T) {
	const factor uint64 = 100_000
	// The SDK's per-request image-tool ceiling, pinned as a literal so a
	// change to it is a deliberate edit here too.
	const maxImageToolBudgetPerRequest uint64 = 64

	var reserves []ticket.ReserveRequest
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: []byte(`{"status":"completed","output":[]}`),
		onReserve:      func(req ticket.ReserveRequest) { reserves = append(reserves, req) },
	})
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"gpt-test": {ImageToolRateMicroUSDC: factor, OutputUSDPer1M: 10},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	over := maxImageToolBudgetPerRequest + 50
	body := fmt.Sprintf(`{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":%d}}}`, over)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", body))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body=%s", w.Result().StatusCode, w.Body.String())
	}
	if len(reserves) != 1 {
		t.Fatalf("captured %d reserves, want 1", len(reserves))
	}
	if reserves[0].ImageToolBudget != maxImageToolBudgetPerRequest {
		t.Errorf("ImageToolBudget = %d, want %d (clamped from %d)",
			reserves[0].ImageToolBudget, maxImageToolBudgetPerRequest, over)
	}
}
