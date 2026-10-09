/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// An operator's CDN answering the inference forward with an HTML error page must
// not reach the client verbatim. A strict SSE client (Ktor's plugin, which is
// what GoLand uses) reports only "expected 200, got 504" and a JSON-decoding one
// chokes on the leading "<", so the actionable status is all that survives
// either way — but the body has to be parseable to get there.
func TestForwardStream_NonOpenAIErrorBody_ReplacedWithStructuredError(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeInferenceGatewayHTMLError})
	cfg := testConfig()
	s := testServer(cfg, setup(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","stream":true}`))

	// The status is the real signal and must be preserved.
	if w.Result().StatusCode != http.StatusGatewayTimeout {
		t.Fatalf("status = %d, want 504 preserved from the gateway", w.Result().StatusCode)
	}
	body := w.Body.String()
	if strings.Contains(body, "<!DOCTYPE") || strings.Contains(body, "<html") {
		t.Errorf("the gateway's HTML page reached the client: %s", body)
	}
	// Must be a parseable OpenAI error envelope.
	var env struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &env); err != nil {
		t.Fatalf("body is not parseable JSON (%v): %s", err, body)
	}
	if env.Error.Message == "" || env.Error.Type != "server_error" {
		t.Errorf("error envelope wants a message and type server_error: %s", body)
	}
	// No error.code, deliberately: a code-less 5xx is how transient.Classify
	// recognizes out-of-tree infrastructure as retryable. Inventing one here would
	// turn a recoverable gateway blip into a terminal refusal.
	if env.Error.Code != "" {
		t.Errorf("synthesized body carries error.code = %q; it must stay code-less so the "+
			"transient classifier still reads it as retryable infrastructure", env.Error.Code)
	}
	// The proxy cannot tell an operator's CDN from the node's own mux — Go's
	// ServeMux answers an unregistered route with a text/plain "404 page not
	// found" — so the message must not assert which layer replied.
	for _, claim := range []string{"front door", "not its node", "gateway returned"} {
		if strings.Contains(env.Error.Message, claim) {
			t.Errorf("message asserts which layer answered (%q); the proxy cannot know: %s",
				claim, env.Error.Message)
		}
	}
}

// An edge rate limiter answering 429/503 with an HTML page lands on the
// body-replacement path. Its Retry-After is the only actionable thing in that
// response, so replacing the body must not drop it.
func TestForwardStream_NonOpenAIErrorBody_PreservesRetryAfter(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeInferenceGatewayHTMLError, gatewayRetryAfter: "7"})
	cfg := testConfig()
	s := testServer(cfg, setup(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","stream":true}`))

	if got := w.Header().Get("Retry-After"); got != "7" {
		t.Errorf("Retry-After = %q, want \"7\" preserved from the gateway", got)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q; the synthesized JSON body's type must win", ct)
	}
}

// Kept, but one node's day is capped like any other node hint.
func TestForwardStream_NonOpenAIErrorBody_CapsRetryAfter(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeInferenceGatewayHTMLError, gatewayRetryAfter: "86400"})
	cfg := testConfig()
	s := testServer(cfg, setup(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","stream":true}`))

	if got := w.Header().Get("Retry-After"); got != "300" {
		t.Errorf("Retry-After = %q, want 300", got)
	}
}

// A hostile operator must not be able to write an unbounded Content-Type into the
// payer's log or the client-visible error.
func TestForwardStream_NonOpenAIErrorBody_TruncatesContentType(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:            modeInferenceGatewayHTMLError,
		gatewayCTSuffix: strings.Repeat("A", 4096),
	})
	cfg := testConfig()
	s := testServer(cfg, setup(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","stream":true}`))

	if n := len(w.Body.String()); n > 512 {
		t.Errorf("error body is %d bytes; an unbounded upstream Content-Type reached the client", n)
	}
}
