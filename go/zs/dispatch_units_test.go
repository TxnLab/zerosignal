/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/wire"
)

// TestProtestReasonForViolation pins the wire mapping between the
// proxy's local violation enum and the on-chain reason code carried on
// protest(). Today only BodyHash actually reaches Protest at the call
// site, but the mapper has cases for the others so future protest
// triggers slot in without a wire-format break.
// A configured SweepDelay still waits no longer than the busy budget has left,
// and not at all once it is spent.
func TestBusyRetryWait_SweepDelayBoundedByBudget(t *testing.T) {
	c := &Client{sweepDelayFn: func(int) time.Duration { return time.Hour }}
	if d, ok := c.busyRetryWait(1, 0, 50*time.Millisecond); !ok || d != 50*time.Millisecond {
		t.Errorf("wait = %v, %v; want 50ms, true", d, ok)
	}
	if _, ok := c.busyRetryWait(1, 0, -time.Millisecond); ok {
		t.Error("waited with the budget spent")
	}
}

func TestProtestReasonForViolation(t *testing.T) {
	cases := []struct {
		violation ReceiptViolation
		want      escrow.ProtestReasonCode
	}{
		{ReceiptViolationBodyHash, escrow.ProtestReasonBodyHash},
		{ReceiptViolationSig, escrow.ProtestReasonReceiptSig},
		{ReceiptViolationAmount, escrow.ProtestReasonAmount},
		{ReceiptOK, escrow.ProtestReasonUnspecified},
	}
	for _, tc := range cases {
		if got := protestReasonForViolation(tc.violation); got != tc.want {
			t.Errorf("protestReasonForViolation(%s) = %d, want %d",
				tc.violation, got, tc.want)
		}
	}
}

// The exhaustive frame-shape table now lives in proto/testdata/stream_vectors.json
// (wire.ClassifyStreamFrame), shared with the reference client so the two can't
// drift on which frames end a stream. What stays local — and is what this
// asserts — is the route-to-vocabulary mapping feeding it: get that wrong and
// every frame classifies against the other endpoint's needles, so the drain
// never arms and every ticket loses its in-band settle.
func TestStreamAPIForEndpoint(t *testing.T) {
	cases := []struct {
		endpoint string
		want     wire.StreamAPI
	}{
		{endpointResponses, wire.StreamAPIResponses},
		{endpointChatCompletions, wire.StreamAPIChat},
		// /v1/completions is emulated by re-dispatching as chat, so it never
		// reaches here as its own endpoint — anything unrecognized must still
		// fall back to chat, not silently classify against the Responses
		// needles.
		{endpointImages, wire.StreamAPIChat},
		{"", wire.StreamAPIChat},
	}
	for _, tc := range cases {
		if got := streamAPIFor(tc.endpoint); got != tc.want {
			t.Errorf("streamAPIFor(%q) = %q, want %q", tc.endpoint, got, tc.want)
		}
	}
	// The two properties the drain depends on, asserted through the SDK's own
	// mapping rather than proto's: a terminal chat chunk and an error frame both
	// arm it, a mid-stream delta does not.
	armed := func(frame, endpoint string) bool {
		return wire.ClassifyStreamFrame([]byte(frame), streamAPIFor(endpoint)).Terminal
	}
	if !armed(`{"choices":[{"finish_reason":"stop"}]}`, endpointChatCompletions) {
		t.Error("chat stop chunk did not arm the tail drain")
	}
	if !armed(`{"error":{"message":"invalid temperature: only 1 is allowed for this model"}}`, endpointChatCompletions) {
		t.Error("chat error frame did not arm the tail drain — the ticket would lapse unverified")
	}
	if !armed(`{"type":"error","message":"boom"}`, endpointResponses) {
		t.Error("responses error event did not arm the tail drain — the ticket would lapse unverified")
	}
	if armed(`{"choices":[{"delta":{"content":"hi"}}]}`, endpointChatCompletions) {
		t.Error("mid-stream delta armed the tail drain; disconnects would stop cancelling promptly")
	}
}

// responseErrorMessage surfaces operator/upstream error envelopes (logged at
// WARN, default-on) while NOT mistaking normal chunks — including the empty-
// choices usage chunk or a delta that merely mentions "error" — for errors.
func TestResponseErrorMessage(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantOK  bool
		wantMsg string
	}{
		{"error envelope", `{"error":{"message":"tools must not be empty","type":"server_error"}}`, true, "tools must not be empty"},
		{"error without message", `{"error":{"code":"x"}}`, true, `{"code":"x"}`},
		{"content chunk", `{"id":"c","object":"chat.completion.chunk","choices":[{"delta":{"content":"hi"}}]}`, false, ""},
		{"usage chunk empty choices", `{"choices":[],"usage":{"prompt_tokens":3}}`, false, ""},
		{"delta mentioning error", `{"choices":[{"delta":{"content":"the error was X"}}]}`, false, ""},
		{"error null", `{"error":null,"choices":[]}`, false, ""},
		{"no error key", `{"id":"c","choices":[{"delta":{}}]}`, false, ""},
		{"not json", `nope`, false, ""},
		// Responses-API error event: no top-level "error" object at all, so the
		// chat-shape branch alone reported false and the frame went both
		// unlogged and (via the shared predicate) undrained.
		{"responses error event", `{"type":"error","code":"context_length_exceeded","message":"too long"}`, true, "too long"},
		{"responses error event without message", `{"type":"error","code":"x"}`, true, "error"},
		// response.failed nests its error under "response" — already terminal
		// via the lifecycle needles, and must not match the type discriminator.
		{"responses failed event", `{"type":"response.failed","response":{"error":{"message":"nope"}}}`, false, ""},
		{"responses delta mentioning error", `{"type":"response.output_text.delta","delta":"error"}`, false, ""},
	}
	for _, tc := range cases {
		msg, ok := responseErrorMessage([]byte(tc.in))
		if ok != tc.wantOK {
			t.Errorf("%s: ok = %v, want %v", tc.name, ok, tc.wantOK)
		}
		if ok && msg != tc.wantMsg {
			t.Errorf("%s: msg = %q, want %q", tc.name, msg, tc.wantMsg)
		}
	}
}
