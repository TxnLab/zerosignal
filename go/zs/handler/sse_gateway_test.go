/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// An operator's CDN answering the inference forward with an HTML error page must
// not reach the client verbatim. A strict SSE client (Ktor's plugin, which is
// what GoLand uses) reports only "expected 200, got 504" and a JSON-decoding one
// chokes on the leading "<", so the actionable status is all that survives
// either way — but the body has to be parseable to get there.
func TestForwardStream_NonOpenAIErrorBody_ReplacedWithStructuredError(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeInferenceGatewayHTMLError})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

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
	if env.Error.Message == "" || env.Error.Type == "" {
		t.Errorf("error envelope missing message/type: %s", body)
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
	s := testServer(cfg, setupHayai(t, cfg, node))

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

// A hostile operator must not be able to write an unbounded Content-Type into the
// payer's log or the client-visible error.
func TestForwardStream_NonOpenAIErrorBody_TruncatesContentType(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{
		mode:            modeInferenceGatewayHTMLError,
		gatewayCTSuffix: strings.Repeat("A", 4096),
	})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
		`{"model":"gpt-test","stream":true}`))

	if n := len(w.Body.String()); n > 512 {
		t.Errorf("error body is %d bytes; an unbounded upstream Content-Type reached the client", n)
	}
}

// The tally is the disconnect diagnostic's whole value, so it has to measure the
// two things that distinguish a client's total-elapsed deadline from an idle
// timeout: how much actually got delivered, and the longest silence between
// frames. A wrong maxGap sends the next investigation at the wrong fix.
func TestStreamTally_RecordsVolumeAndLargestGap(t *testing.T) {
	var tally streamTally
	start := time.Now()

	// No frames yet: ttfb must read as zero rather than "the whole elapsed time",
	// which would make a stream that never produced anything look slow-but-alive.
	if tally.frames != 0 || tally.maxGap != 0 {
		t.Fatalf("fresh tally = %+v, want zero", tally)
	}

	tally.record(10)
	tally.record(20)
	// A deliberate pause, then another frame: this gap must be the recorded max.
	time.Sleep(40 * time.Millisecond)
	tally.record(30)
	tally.record(40)

	if tally.frames != 4 {
		t.Errorf("frames = %d, want 4", tally.frames)
	}
	if tally.bytes != 100 {
		t.Errorf("bytes = %d, want 100", tally.bytes)
	}
	if tally.maxGap < 30*time.Millisecond {
		t.Errorf("maxGap = %s, want >= 30ms (the deliberate pause)", tally.maxGap)
	}
	// The gap must be an INTER-frame measure, not total elapsed: the two fast
	// frames after the pause must not have widened it.
	if tally.maxGap > 5*time.Second {
		t.Errorf("maxGap = %s; looks like total elapsed rather than an inter-frame gap", tally.maxGap)
	}

	// attrs must report a non-zero ttfb once a frame has landed, measured from the
	// forward start so it includes the reserve + escrow-open preamble the client
	// also waited through.
	var ttfb time.Duration
	for _, a := range tally.attrs(start) {
		if sa, ok := a.(slog.Attr); ok && sa.Key == "ttfb" {
			ttfb = sa.Value.Duration()
		}
	}
	if ttfb <= 0 {
		t.Errorf("ttfb attr = %s, want > 0 once a frame has been delivered", ttfb)
	}
}

// A stream that delivered nothing must report ttfb=0, not the elapsed time —
// otherwise "we waited 25s and got nothing" reads as "first byte took 25s".
func TestStreamTally_NoFramesReportsZeroTTFB(t *testing.T) {
	var tally streamTally
	start := time.Now().Add(-2 * time.Second)
	for _, a := range tally.attrs(start) {
		sa, ok := a.(slog.Attr)
		if !ok {
			continue
		}
		switch sa.Key {
		case "ttfb":
			if sa.Value.Duration() != 0 {
				t.Errorf("ttfb = %s, want 0 when no frame was delivered", sa.Value.Duration())
			}
		case "elapsed":
			if sa.Value.Duration() < time.Second {
				t.Errorf("elapsed = %s, want the real wall clock (>=1s)", sa.Value.Duration())
			}
		}
	}
}
