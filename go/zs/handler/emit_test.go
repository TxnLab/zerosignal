/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// recordingEmitter keeps what a dispatch emitted, for asserting the zs.Error a
// caller other than HTTP would receive.
type recordingEmitter struct {
	failed  *zs.Error
	replied bool
}

func (r *recordingEmitter) clamped(uint64)                               {}
func (r *recordingEmitter) fail(e *zs.Error)                             { r.failed = e }
func (r *recordingEmitter) reply(int, http.Header, []byte, *usageReport) { r.replied = true }
func (r *recordingEmitter) open(int) error                               { return nil }
func (r *recordingEmitter) frame(f transform.SSEFrame) (int, error)      { return len(f.Data), nil }
func (r *recordingEmitter) interrupt()                                   {}

// An operator's own error passes through with its status and body, and the
// proxy's X-Zs-* headers survive the strip while the node's do not.
func TestHTTPEmitter_PassThrough(t *testing.T) {
	w := httptest.NewRecorder()
	em := newHTTPEmitter(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil))
	em.clamped(100)

	body := []byte(`{"error":{"message":"m","type":"invalid_request_error","code":"ticket_invalid"}}`)
	node := http.Header{}
	node.Set("Content-Type", "application/json; charset=utf-8")
	node.Set("Content-Length", "5")
	node.Set("Retry-After", "3")
	node.Set("X-Zs-Max-Output-Clamped", "999")
	node.Set("X-Zs-Future-Field", "leak-me")
	em.fail(&zs.Error{Kind: zs.KindInterrupted, Code: "ticket_invalid", Err: &upstreamReply{status: 402, header: node, body: body}})

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

	// A body the proxy wrote in place of one it could not parse is JSON
	// whatever the operator labelled its page.
	w = httptest.NewRecorder()
	em = newHTTPEmitter(w, httptest.NewRequest(http.MethodPost, "/", nil))
	html := http.Header{}
	html.Set("Content-Type", "text/html")
	em.fail(&zs.Error{Kind: zs.KindInterrupted, Err: &upstreamReply{status: 504, header: html, body: []byte("{}\n"), contentType: "application/json"}})
	if got := w.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type %q, want application/json", got)
	}
}

// A stream starts with the node's status, as SSE.
func TestHTTPEmitter_OpenUsesUpstreamStatus(t *testing.T) {
	w := httptest.NewRecorder()
	if err := newHTTPEmitter(w, httptest.NewRequest(http.MethodPost, "/", nil)).open(http.StatusAccepted); err != nil {
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

// A writer that can't flush gets an error, not a stream that never arrives.
func TestHTTPEmitter_OpenWithoutFlusherFails(t *testing.T) {
	rec := httptest.NewRecorder()
	em := newHTTPEmitter(noFlushWriter{rec}, httptest.NewRequest(http.MethodPost, "/", nil))
	if em.open(http.StatusOK) == nil {
		t.Fatal("open succeeded without a Flusher")
	}
	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"no_flusher"`) {
		t.Errorf("status %d body %s, want 500 no_flusher", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type %q, want the error's application/json", ct)
	}
}

// failingWriter fails every write, as a broken connection does while the
// client's context is still live.
type failingWriter struct{ *httptest.ResponseRecorder }

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("write: connection reset") }

// A write that fails while the client is still connected ends the pump, which
// is what cancels the upstream instead of reading on for nobody.
func TestPumpSSE_StopsOnWriteErrorWhileConnected(t *testing.T) {
	em := &httpEmitter{w: failingWriter{httptest.NewRecorder()}, clientCtx: context.Background(), flusher: &fakeFlusher{}}
	err := pumpSSE(context.Background(), em.frame, strings.NewReader("data: one\n\ndata: two\n\n"), identityFrame, &streamTally{})
	if err == nil || !strings.Contains(err.Error(), "connection reset") {
		t.Errorf("pumpSSE = %v, want the write error", err)
	}
}

// deadSocketWriter fails every write once its client has gone, as a real
// connection does.
type deadSocketWriter struct {
	*httptest.ResponseRecorder
	clientCtx context.Context
}

func (d deadSocketWriter) Write(p []byte) (int, error) {
	if d.clientCtx.Err() != nil {
		return 0, errors.New("write: broken pipe")
	}
	return d.ResponseRecorder.Write(p)
}

// A client that leaves after generation completes must not stop the stream
// before the receipt tail: the receipt is where the operator gets paid. The
// write to the dead socket is what would end the pump, so the HTTP emitter
// built from the request has to swallow it.
func TestForwardRawStream_DisconnectAfterGenerationStillReachesTail(t *testing.T) {
	cut := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: done\n\n")
		fl.Flush()
		<-cut
		_, _ = io.WriteString(w, "data: after\n\ndata: tail\n\n")
		fl.Flush()
	}))
	defer upstream.Close()

	s := &Server{log: slog.New(slog.NewTextHandler(io.Discard, nil)), httpClient: &http.Client{}}
	clientCtx, leave := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}")).WithContext(clientCtx)
	w := deadSocketWriter{httptest.NewRecorder(), clientCtx}

	var genComplete, sawTail atomic.Bool
	factory := func(*http.Response) (frameTransform, error) {
		return func(f transform.SSEFrame) (transform.SSEFrame, error) {
			switch string(f.Data) {
			case "done":
				genComplete.Store(true)
				leave()
				close(cut)
			case "tail":
				sawTail.Store(true)
			}
			return f, nil
		}, nil
	}
	s.forwardRawStream(clientCtx, newHTTPEmitter(w, r), r, upstream.URL, "", []byte("{}"), "application/json", nil, nil,
		factory, func(emitter, *http.Response, []byte) error { return nil }, &genComplete)

	if !sawTail.Load() {
		t.Error("the stream ended before the tail frame after the client left")
	}
}

// After the open, a node refusing admission is a paid turn interrupted, and
// its code is what a caller branches on.
func TestNonStreamResponder_PreEnvelopeErrorIsInterrupted(t *testing.T) {
	s := &Server{cfg: &Config{}, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	responder := s.buildHayaiNonStreamResponder(context.Background(), nil, "", nil, zs.Operator{}, nil,
		nil, endpointChatCompletions, "m", 0, 0, nil, formatChat)

	for _, tc := range []struct {
		name, body, wantCode string
	}{
		{"node error", `{"error":{"message":"bad ticket","type":"invalid_request_error","code":"ticket_invalid"}}`, "ticket_invalid"},
		{"unparseable page", `<html>504</html>`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := &recordingEmitter{}
			resp := &http.Response{StatusCode: 402, Header: http.Header{}}
			if err := responder(em, resp, []byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if em.failed == nil || em.replied {
				t.Fatalf("failed %v replied %v, want a failure", em.failed, em.replied)
			}
			if em.failed.Kind != zs.KindInterrupted || em.failed.Code != tc.wantCode {
				t.Errorf("Kind %q Code %q, want interrupted %q", em.failed.Kind, em.failed.Code, tc.wantCode)
			}
		})
	}
}
