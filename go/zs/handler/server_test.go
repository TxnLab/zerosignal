/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// The catalog routes and the funding hint read the Client's own settings, so
// the two can never disagree about which nodes exist or which chain is paid on.
func TestNew_WiresFields(t *testing.T) {
	cfg := testConfig()
	cfg.Network = "mainnet"
	cfg.AllowStaging = true
	cfg.FundingURL = "https://app.example"
	reg := errRegistry{}
	s := testServer(cfg, deps{RegistryProvider: reg})
	if s.registryProvider != hayai.RegistryProvider(reg) {
		t.Error("registry is not the Client's")
	}
	if !s.allowStaging || s.network != "mainnet" || s.cfg.FundingURL != "https://app.example" {
		t.Errorf("allowStaging %v, network %q, FundingURL %q", s.allowStaging, s.network, s.cfg.FundingURL)
	}
	if s.log == nil {
		t.Error("logger nil")
	}
	if s.mux == nil {
		t.Error("mux nil")
	}
	if _, ok := s.reqTx.(transform.Passthrough); !ok {
		t.Error("reqTx not passthrough")
	}
	if _, ok := s.respTx.(transform.Passthrough); !ok {
		t.Error("respTx not passthrough")
	}
}

func TestHTTPServer_TimeoutsFromConfig(t *testing.T) {
	lc := ListenConfig{
		Addr:         "127.0.0.1:0",
		ReadTimeout:  11 * time.Second,
		WriteTimeout: 22 * time.Second,
		IdleTimeout:  33 * time.Second,
	}

	hs := testServer(testConfig(), deps{}).HTTPServer(lc)
	if hs.ReadTimeout != 11*time.Second {
		t.Errorf("ReadTimeout = %v", hs.ReadTimeout)
	}
	if hs.WriteTimeout != 22*time.Second {
		t.Errorf("WriteTimeout = %v", hs.WriteTimeout)
	}
	if hs.IdleTimeout != 33*time.Second {
		t.Errorf("IdleTimeout = %v", hs.IdleTimeout)
	}
	if hs.Addr != lc.Addr {
		t.Errorf("Addr = %q", hs.Addr)
	}
	if hs.Handler == nil {
		t.Error("Handler nil")
	}
}

func TestMiddleware_LogsRequest(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cfg := testConfig()
	s := newServer(&cfg.policy, logger, transform.Passthrough{}, transform.Passthrough{}, deps{})

	// Hit the health endpoint through the middleware.
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.middleware(s.mux).ServeHTTP(w, req)

	line := buf.String()
	if !strings.Contains(line, `"msg":"request"`) {
		t.Errorf("missing request log line: %s", line)
	}
	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &rec); err != nil {
		t.Fatalf("log line not JSON: %v", err)
	}
	if rec["method"] != "GET" {
		t.Errorf("method = %v", rec["method"])
	}
	if rec["path"] != "/healthz" {
		t.Errorf("path = %v", rec["path"])
	}
	if rec["status"].(float64) != 200 {
		t.Errorf("status = %v", rec["status"])
	}
}

func TestMiddleware_LogsErrorReason(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	s := newServer(&testConfig().policy, logger, transform.Passthrough{}, transform.Passthrough{}, deps{})

	// A handler that fails the way dispatchHayai does: an OpenAI-shaped 503.
	failing := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeOpenAIError(w, http.StatusServiceUnavailable, "service_unavailable", "no_operator",
			"no operator is currently advertising this model")
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	w := httptest.NewRecorder()
	s.middleware(failing).ServeHTTP(w, req)

	var rec map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &rec); err != nil {
		t.Fatalf("log line not JSON: %v (%s)", err, buf.String())
	}
	if rec["status"].(float64) != 503 {
		t.Errorf("status = %v, want 503", rec["status"])
	}
	if rec["level"] != "WARN" {
		t.Errorf("level = %v, want WARN", rec["level"])
	}
	if rec["err_code"] != "no_operator" {
		t.Errorf("err_code = %v, want no_operator", rec["err_code"])
	}
	if rec["err_type"] != "service_unavailable" {
		t.Errorf("err_type = %v", rec["err_type"])
	}
	if msg, _ := rec["err_message"].(string); !strings.Contains(msg, "advertising this model") {
		t.Errorf("err_message = %v", rec["err_message"])
	}
}

func TestErrorReasonAttrs(t *testing.T) {
	// Non-OpenAI / non-JSON body falls back to the raw prefix.
	attrs := errorReasonAttrs([]byte("plain text boom"))
	if len(attrs) != 1 || attrs[0].Key != "err_body" || attrs[0].Value.String() != "plain text boom" {
		t.Errorf("raw fallback attrs = %+v", attrs)
	}
	// Empty body yields no attrs.
	if got := errorReasonAttrs([]byte("  \n ")); got != nil {
		t.Errorf("empty body attrs = %+v, want nil", got)
	}
}

func TestStatusRecorder_DoesNotCaptureSuccessBody(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}
	rec.WriteHeader(http.StatusOK)
	_, _ = rec.Write([]byte("a successful streaming chunk"))
	if len(rec.errBody) != 0 {
		t.Errorf("captured a 2xx body: %q", rec.errBody)
	}
	if underlying.Body.String() != "a successful streaming chunk" {
		t.Errorf("body not passed through: %q", underlying.Body.String())
	}
}

func TestStatusRecorder_CapturesErrorBodyCapped(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}
	rec.WriteHeader(http.StatusServiceUnavailable)
	big := bytes.Repeat([]byte("x"), maxCapturedErrBody+1024)
	_, _ = rec.Write(big)
	if len(rec.errBody) != maxCapturedErrBody {
		t.Errorf("captured %d bytes, want cap %d", len(rec.errBody), maxCapturedErrBody)
	}
	if underlying.Body.Len() != len(big) {
		t.Errorf("full body not passed through: got %d, want %d", underlying.Body.Len(), len(big))
	}
}

func TestMiddleware_PanicRecovery(t *testing.T) {
	cfg := testConfig()
	s := testServer(cfg, deps{})

	panicking := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom")
	})

	req := httptest.NewRequest(http.MethodGet, "/anything", nil)
	w := httptest.NewRecorder()

	// Must not panic.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic escaped middleware: %v", r)
		}
	}()
	s.middleware(panicking).ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", w.Result().StatusCode)
	}
	var env openAIErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Type != "proxy_error" || env.Error.Code != "panic" {
		t.Errorf("error shape = %+v", env.Error)
	}
}

func TestStatusRecorder_WriteHeaderOnce(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}

	rec.WriteHeader(200)
	rec.WriteHeader(500) // should be ignored by the recorder's own tracking

	if rec.status != 200 {
		t.Errorf("status = %d, want 200", rec.status)
	}
}

func TestStatusRecorder_FlushDelegates(t *testing.T) {
	underlying := httptest.NewRecorder()
	rec := &statusRecorder{ResponseWriter: underlying, status: http.StatusOK}
	// httptest.ResponseRecorder implements Flusher via Flushed counter.
	rec.Flush()
	if !underlying.Flushed {
		t.Error("Flush did not delegate to underlying flusher")
	}
}

type notAFlusher struct{ http.ResponseWriter }

func TestStatusRecorder_FlushNoFlusher(t *testing.T) {
	// Wrapped writer doesn't implement Flusher; Flush should not panic.
	rec := &statusRecorder{ResponseWriter: notAFlusher{ResponseWriter: httptest.NewRecorder()}}
	rec.Flush() // no panic is the assertion
}

func TestRoutes_HealthRegistered(t *testing.T) {
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d", w.Result().StatusCode)
	}
	if body := strings.TrimSpace(w.Body.String()); body != `{"status":"ok"}` {
		t.Errorf("body = %q", body)
	}
}

func TestRoutes_EmbeddingsDisabledReturns404(t *testing.T) {
	// /v1/embeddings stays intentionally disabled (no chat equivalent to
	// emulate it with). The mux should return 404 for it.
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", bytes.NewReader([]byte(`{}`)))
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("/v1/embeddings status = %d, want 404", w.Result().StatusCode)
	}
}

func TestRoutes_CompletionsRegistered(t *testing.T) {
	// /v1/completions is emulated on top of chat completions (handleCompletions).
	// The route is wired, so a body with no prompt must surface the translation
	// error (400 missing_prompt) rather than a 404 — proving the shim handles it
	// before any operator is contacted.
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/completions", bytes.NewReader([]byte(`{"model":"gpt-4"}`)))
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("/v1/completions (no prompt) status = %d, want 400", w.Result().StatusCode)
	}
	var env openAIErrorEnvelope
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("decode error envelope: %v", err)
	}
	if env.Error.Code != "missing_prompt" {
		t.Errorf("error code = %q, want missing_prompt", env.Error.Code)
	}
}

func TestRoutes_ModelsRegistered(t *testing.T) {
	// Verify the GET /v1/models and GET /v1/models/{id} patterns are wired.
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"gpt-4", "google/gemma-5.2"},
		Reachable:    true,
		ProtoVersion: wire.ProtoVersion,
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("/v1/models status = %d", w.Result().StatusCode)
	}

	req = httptest.NewRequest(http.MethodGet, "/v1/models/gpt-4", nil)
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("/v1/models/{id} status = %d", w.Result().StatusCode)
	}

	// Model ids carry an embedded slash (e.g. "google/gemma-5.2"). The route
	// uses the trailing wildcard {id...} so the multi-segment id reaches the
	// handler; a single-segment {id} would 404 at the mux. Must route to the
	// handler and find the model (200), not the mux's bare-text 404.
	req = httptest.NewRequest(http.MethodGet, "/v1/models/google/gemma-5.2", nil)
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("/v1/models/google/gemma-5.2 status = %d, want 200", w.Result().StatusCode)
	}

	// /v1/models/ (trailing slash, empty id) routes to the handler via the
	// {id...} wildcard and hits the empty-id guard (400). Just assert no 5xx.
	req = httptest.NewRequest(http.MethodGet, "/v1/models/", nil)
	w = httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)
	if w.Result().StatusCode >= 500 {
		t.Errorf("/v1/models/ got 5xx = %d", w.Result().StatusCode)
	}
}
