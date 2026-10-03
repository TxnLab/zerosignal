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

	"github.com/TxnLab/zerosignal/go/zs"
)

// OpenAI's SDKs resend a 5xx on their own unless told not to, so every error
// says whether to, and never yes once the turn is paid: that resend is a
// second payment nobody chose.
func TestWriteError_ShouldRetry(t *testing.T) {
	for code, sh := range errorShapes {
		for _, retryable := range []bool{false, true} {
			for _, paid := range []bool{false, true} {
				w := httptest.NewRecorder()
				writeError(w, &zs.Error{Code: code, Retryable: retryable, Paid: paid})
				want := "false"
				if retryable && !paid {
					want = "true"
				}
				if got := w.Header().Get("X-Should-Retry"); got != want {
					t.Errorf("%s (status %d) retryable=%v paid=%v: X-Should-Retry %q, want %q", code, sh.status, retryable, paid, got, want)
				}
			}
		}
	}
}

// An error written outside a turn (a bad body, an unknown model id, a panic)
// is never advised as a resend.
func TestWriteOpenAIError_DefaultsToNoRetry(t *testing.T) {
	w := httptest.NewRecorder()
	writeOpenAIError(w, http.StatusInternalServerError, "proxy_error", "panic", "x")
	if got := w.Header().Get("X-Should-Retry"); got != "false" {
		t.Errorf("X-Should-Retry %q, want false", got)
	}
}

// End to end, the advice follows the turn, and the node's own advice never
// reaches the client.
func TestDispatch_ShouldRetry(t *testing.T) {
	nodeSays := map[string]string{"X-Should-Retry": "true"}
	for _, tc := range []struct {
		name       string
		node       *nodeConfig
		model      string
		wantStatus int
		want       string
	}{
		{"busy, unpaid", &nodeConfig{mode: modeReserveBusy}, "gpt-test", http.StatusServiceUnavailable, "true"},
		{"no operator serves the model", &nodeConfig{mode: modeNonStreamEncrypted}, "no-such-model", http.StatusNotFound, "false"},
		{"paid, refused before the envelope", &nodeConfig{mode: modeNonStreamPreEnvelopeError, extraRespHeaders: nodeSays}, "gpt-test", http.StatusPaymentRequired, "false"},
		{"paid, a sealed provider failure", &nodeConfig{mode: modeNonStreamEncrypted, replyStatus: http.StatusServiceUnavailable, extraRespHeaders: nodeSays,
			replyPlaintext: []byte(`{"error":{"message":"busy","code":"provider_overloaded"}}`)}, "gpt-test", http.StatusServiceUnavailable, "false"},
		{"paid, a sealed rate limit", &nodeConfig{mode: modeNonStreamEncrypted, replyStatus: http.StatusTooManyRequests, extraRespHeaders: nodeSays,
			replyPlaintext: []byte(`{"error":{"message":"slow down","code":"rate_limit_exceeded"}}`)}, "gpt-test", http.StatusTooManyRequests, "false"},
		{"paid, a stream opened under a failed status", &nodeConfig{mode: modeStreamEncrypted, replyStatus: http.StatusServiceUnavailable, extraRespHeaders: nodeSays,
			streamFrames: [][]byte{[]byte(`{"choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":"stop"}]}`)}}, "gpt-test", http.StatusServiceUnavailable, "false"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := newFakeNode(t, tc.node)
			cfg := testConfig()
			opts := setupHayai(t, cfg, node)
			opts.SweepDelay = noSweepDelay
			s := testServer(cfg, opts)

			stream := tc.node.mode == modeStreamEncrypted
			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions",
				fmt.Sprintf(`{"model":%q,"max_tokens":16,"stream":%v}`, tc.model, stream)))
			if w.Code != tc.wantStatus {
				t.Fatalf("status %d body %s, want %d", w.Code, w.Body.String(), tc.wantStatus)
			}
			if got := w.Header().Get("X-Should-Retry"); got != tc.want {
				t.Errorf("X-Should-Retry %q, want %q", got, tc.want)
			}
		})
	}
}

// A browser client reads the header only if CORS exposes it; otherwise it
// falls back to the status rule and resends a paid 5xx.
func TestShouldRetry_ReadableCrossOrigin(t *testing.T) {
	w := httptest.NewRecorder()
	writeCORSHeaders(w, httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil))
	if exp := w.Header().Get("Access-Control-Expose-Headers"); !strings.Contains(exp, "X-Should-Retry") {
		t.Errorf("Access-Control-Expose-Headers %q omits X-Should-Retry", exp)
	}
}
