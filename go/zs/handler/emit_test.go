/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
)

// script is a turn's events as a fixed sequence, ended by err when non-nil.
// stoppedAt records how many events were taken before the range stopped (-1:
// it ran to the end).
type script struct {
	events    []zs.Event
	err       error
	stoppedAt int
}

func (s *script) seq() iter.Seq2[zs.Event, error] {
	s.stoppedAt = -1
	return func(yield func(zs.Event, error) bool) {
		for i, ev := range s.events {
			if !yield(ev, nil) {
				s.stoppedAt = i + 1
				return
			}
		}
		if s.err != nil {
			yield(nil, s.err)
		}
	}
}

func emitterFor(w http.ResponseWriter, path string, format clientFormat) *httpEmitter {
	return newHTTPEmitter(w, httptest.NewRequest(http.MethodPost, path, nil), format, "run `zs-proxy fund`.")
}

func testReceipt() zs.ReceiptVerified {
	return zs.ReceiptVerified{Receipt: ticket.UsageReceipt{TicketID: "tid"}}
}

// An operator's own error passes through with its status and body, and the
// proxy's X-Zs-* headers survive the strip while the node's do not.
func TestHTTPEmitter_PassThrough(t *testing.T) {
	w := httptest.NewRecorder()
	em := emitterFor(w, "/v1/chat/completions", formatChat)

	body := []byte(`{"error":{"message":"m","type":"invalid_request_error","code":"ticket_invalid"}}`)
	node := http.Header{}
	node.Set("Content-Type", "application/json; charset=utf-8")
	node.Set("Content-Length", "5")
	node.Set("Retry-After", "3")
	node.Set("X-Zs-Max-Output-Clamped", "999")
	node.Set("X-Zs-Future-Field", "leak-me")
	em.serve((&script{
		events: []zs.Event{zs.MaxOutputClamped{Ceiling: 100}},
		err:    &zs.Error{Kind: zs.KindInterrupted, Code: "ticket_invalid", Err: &zs.NodeReply{Status: 402, Header: node, Body: body}},
	}).seq())

	if w.Code != 402 || w.Body.String() != string(body) {
		t.Errorf("status %d body %q, want the node's", w.Code, w.Body.String())
	}
	h := w.Header()
	if got := h.Get("X-Zs-Max-Output-Clamped"); got != "100" {
		t.Errorf("clamp marker %q, want the proxy's 100", got)
	}
	if got := h.Get("X-Zs-Future-Field"); got != "" {
		t.Errorf("node-set X-Zs-Future-Field leaked: %q", got)
	}
	if got := h.Get("Retry-After"); got != "3" {
		t.Errorf("Retry-After %q, want the node's 3", got)
	}
	if got := h.Get("Content-Length"); got != "" {
		t.Errorf("Content-Length %q passed through", got)
	}
	if got := h.Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("Content-Type %q, want the node's", got)
	}

	// A body the SDK wrote in place of one it could not parse is JSON
	// whatever the operator labelled its page.
	w = httptest.NewRecorder()
	html := http.Header{}
	html.Set("Content-Type", "text/html")
	emitterFor(w, "/", formatChat).fail(&zs.Error{Kind: zs.KindInterrupted,
		Err: &zs.NodeReply{Status: 504, Header: html, Body: []byte("{}\n"), ContentType: "application/json"}})
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type %q, want application/json", got)
	}
}

// An SDK error is shaped by its code, and wallet_unfunded is completed with
// what the payer can do about it.
func TestHTTPEmitter_FailShapesAndHintsFunding(t *testing.T) {
	w := httptest.NewRecorder()
	emitterFor(w, "/", formatChat).fail(&zs.Error{Kind: zs.KindFunds, Code: "wallet_unfunded", Message: "payer has no USDC"})
	if w.Code != http.StatusPaymentRequired {
		t.Errorf("status %d, want 402", w.Code)
	}
	if !strings.Contains(w.Body.String(), "payer has no USDC — run `zs-proxy fund`.") {
		t.Errorf("body %s, want the funding hint appended", w.Body.String())
	}

	w = httptest.NewRecorder()
	emitterFor(w, "/", formatChat).fail(errors.New("boom"))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("non-SDK error: status %d, want 500", w.Code)
	}
}

// A stream starts with the node's status, as SSE.
func TestHTTPEmitter_OpenUsesUpstreamStatus(t *testing.T) {
	w := httptest.NewRecorder()
	if err := emitterFor(w, "/", formatChat).open(http.StatusAccepted); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusAccepted || w.Header().Get("Content-Type") != "text/event-stream" {
		t.Errorf("status %d Content-Type %q", w.Code, w.Header().Get("Content-Type"))
	}
}

// noFlushWriter is a ResponseWriter that can't stream.
type noFlushWriter struct{ rec *httptest.ResponseRecorder }

func (n noFlushWriter) Header() http.Header         { return n.rec.Header() }
func (n noFlushWriter) Write(p []byte) (int, error) { return n.rec.Write(p) }
func (n noFlushWriter) WriteHeader(code int)        { n.rec.WriteHeader(code) }

// A writer that can't flush gets an error, not a stream that never arrives,
// and the turn is stopped rather than run for nobody.
func TestHTTPEmitter_OpenWithoutFlusherFails(t *testing.T) {
	rec := httptest.NewRecorder()
	sc := &script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Streaming: true},
		zs.Frame{Data: []byte("{}"), Sealed: true},
	}}
	emitterFor(noFlushWriter{rec}, "/", formatChat).serve(sc.seq())
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"no_flusher"`) {
		t.Errorf("status %d body %s, want 500 no_flusher", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want the error's application/json", ct)
	}
	if sc.stoppedAt != 1 {
		t.Errorf("stopped after %d events, want 1", sc.stoppedAt)
	}
}

// A /v1/completions caller gets its content in text-completion shape, but a
// frame the node did not seal (a `data:` passed through as sent) reaches it
// unchanged, and a chat caller's content is never reshaped.
func TestHTTPEmitter_LegacyCompletionsReshapesContentOnly(t *testing.T) {
	chunk := []byte(`{"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}`)
	r := httptest.NewRequest(http.MethodPost, "/v1/completions", nil)
	r.Header.Set(usageFrameHeader, "1")
	w := httptest.NewRecorder()
	newHTTPEmitter(w, r, formatLegacyCompletions, "").serve((&script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Streaming: true},
		zs.Frame{Data: chunk, Sealed: true},
		zs.Frame{Data: chunk},
		testReceipt(),
	}}).seq())
	got := strings.Split(strings.TrimSpace(w.Body.String()), "\n\n")
	if len(got) != 3 {
		t.Fatalf("got %d frames, want 3: %q", len(got), w.Body.String())
	}
	if !strings.Contains(got[0], `"text_completion"`) || !strings.Contains(got[0], `"Hi"`) {
		t.Errorf("content frame not reshaped: %s", got[0])
	}
	if got[1] != "data: "+string(chunk) {
		t.Errorf("pass-through frame changed: %s", got[1])
	}
	if !strings.HasPrefix(got[2], "event: "+usageFrameEvent) {
		t.Errorf("usage frame: %s", got[2])
	}

	w = httptest.NewRecorder()
	emitterFor(w, "/v1/chat/completions", formatChat).serve((&script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Streaming: true},
		zs.Frame{Data: chunk, Sealed: true},
	}}).seq())
	if got := strings.TrimSpace(w.Body.String()); got != "data: "+string(chunk) {
		t.Errorf("chat content frame changed: %s", got)
	}

	w = httptest.NewRecorder()
	newHTTPEmitter(w, r, formatLegacyCompletions, "").serve((&script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Header: http.Header{}},
		zs.Frame{Data: []byte(`{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}`), Sealed: true},
		zs.Done{},
	}}).seq())
	if !strings.Contains(w.Body.String(), `"text_completion"`) {
		t.Errorf("reply not reshaped: %s", w.Body.String())
	}
}

// The usage frame is the caller's opt-in; without it the report is dropped.
func TestHTTPEmitter_UsageFrameNeedsOptIn(t *testing.T) {
	w := httptest.NewRecorder()
	emitterFor(w, "/v1/chat/completions", formatChat).serve((&script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Streaming: true},
		testReceipt(),
	}}).seq())
	if w.Body.Len() != 0 {
		t.Errorf("body %q, want nothing written", w.Body.String())
	}
}

// A non-streaming reply is held until done, so its usage headers precede the
// body, and the node's own X-Zs-* headers are dropped.
func TestHTTPEmitter_NonStreamUsageHeadersBeforeBody(t *testing.T) {
	w := httptest.NewRecorder()
	node := http.Header{}
	node.Set("X-Zs-Future-Field", "leak-me")
	node.Set("X-Request-Id", "r1")
	emitterFor(w, "/v1/chat/completions", formatChat).serve((&script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Header: node},
		zs.Frame{Data: []byte(`{"ok":true}`), Sealed: true},
		testReceipt(),
		zs.Done{},
	}}).seq())
	if w.Code != http.StatusOK || w.Body.String() != `{"ok":true}` {
		t.Fatalf("status %d body %q", w.Code, w.Body.String())
	}
	if w.Header().Get("X-Zs-Ticket-Id") != "tid" {
		t.Errorf("usage headers missing: %v", w.Header())
	}
	if w.Header().Get("X-Zs-Future-Field") != "" || w.Header().Get("X-Request-Id") != "r1" {
		t.Errorf("headers %v, want the node's X-Zs-* dropped and the rest kept", w.Header())
	}
}

// A turn that breaks after the stream opened ends in an SSE error frame, not
// a status the client can no longer receive.
func TestHTTPEmitter_ErrorAfterOpenInterrupts(t *testing.T) {
	w := httptest.NewRecorder()
	emitterFor(w, "/v1/chat/completions", formatChat).serve((&script{
		events: []zs.Event{zs.ResponseStarted{Status: http.StatusOK, Streaming: true}},
		err:    &zs.Error{Kind: zs.KindInterrupted, Code: "stream_interrupted"},
	}).seq())
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "stream interrupted") || !strings.Contains(w.Body.String(), "[DONE]") {
		t.Errorf("status %d body %q, want an SSE error frame then [DONE]", w.Code, w.Body.String())
	}
}

// failingWriter fails every write, as a broken connection does while the
// client's context is still live.
type failingWriter struct{ *httptest.ResponseRecorder }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write: connection reset") }

// A write that fails while the client is still connected stops the turn,
// which the Client treats as the client leaving.
func TestHTTPEmitter_WriteErrorStopsTheTurn(t *testing.T) {
	sc := &script{events: []zs.Event{
		zs.ResponseStarted{Status: http.StatusOK, Streaming: true},
		zs.Frame{Data: []byte("one"), Sealed: true},
		zs.Frame{Data: []byte("two"), Sealed: true},
	}}
	emitterFor(failingWriter{httptest.NewRecorder()}, "/v1/chat/completions", formatChat).serve(sc.seq())
	if sc.stoppedAt != 2 {
		t.Errorf("stopped after %d events, want 2 (the first frame's write failed)", sc.stoppedAt)
	}
}
