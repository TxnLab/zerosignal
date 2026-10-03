/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

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
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// A caller that stops ranging has left: the emitter cancels the turn, so the
// forwarder treats it as a disconnect, and nothing more is handed to yield.
func TestStreamEmitter_StopCancelsAndDrops(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var got []Event
	em := &streamEmitter{
		yield: func(ev Event, _ error) bool {
			got = append(got, ev)
			return false
		},
		cancel: cancel,
	}
	if _, err := em.frame(outFrame{frame: Frame{Data: []byte("one"), Sealed: true}}); err != nil {
		t.Fatal(err)
	}
	if ctx.Err() == nil {
		t.Error("stopping the range did not cancel the turn")
	}
	em.frame(outFrame{frame: Frame{Data: []byte("two"), Sealed: true}})
	em.fail(newError("no_operator", "x"))
	if len(got) != 1 {
		t.Errorf("yield called %d times, want once: %v", len(got), got)
	}
}

// Every terminal error is judged Retryable as it is delivered, except one the
// caller's own context ended, by cancel or deadline. Paid or not is a separate
// answer: a paid failure can still be worth a new turn.
func TestStreamEmitter_EndDecidesRetryable(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	expired, cancelExpired := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancelExpired()
	for _, tc := range []struct {
		name string
		ctx  context.Context
		code string
		paid bool
		want bool
	}{
		{"transport loss", context.Background(), "read_upstream", false, true},
		{"transport loss after payment", context.Background(), "read_upstream", true, true},
		{"caller cancelled", cancelled, "read_upstream", false, false},
		{"caller's deadline passed", expired, "read_upstream", false, false},
		{"caller must fix it", context.Background(), "missing_model", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotErr error
			em := &streamEmitter{
				yield:     func(_ Event, err error) bool { gotErr = err; return true },
				cancel:    func() {},
				callerCtx: tc.ctx,
			}
			if tc.paid {
				em.committed("tid", "txid", 1000)
			}
			em.fail(newError(tc.code, "x"))
			ze, ok := gotErr.(*Error)
			if !ok || ze.Retryable != tc.want || ze.Paid != tc.paid {
				t.Errorf("ended in %+v, want Retryable %v Paid %v", gotErr, tc.want, tc.paid)
			}
		})
	}
}

// After the escrow open, a failure is paid and names the ticket, because
// nothing is resent after the open.
func TestStreamEmitter_FailAfterCommitIsPaid(t *testing.T) {
	var gotErr error
	em := &streamEmitter{
		yield:  func(_ Event, err error) bool { gotErr = err; return true },
		cancel: func() {},
	}
	em.reserved(&ReservedTicket{Ticket: &ticket.Ticket{TicketID: "tid", MaxPrice: 7}}, Operator{ID: 3, NodeID: 4})
	em.committed("tid", "txid", 1000)
	em.interrupt()

	ze, ok := gotErr.(*Error)
	if !ok {
		t.Fatalf("terminal error = %v, want *Error", gotErr)
	}
	if !ze.Paid || ze.Ticket == nil || ze.Ticket.ID != "tid" || ze.Ticket.Target != (NodeRef{Op: 3, Node: 4}) {
		t.Errorf("error = %+v ticket %+v, want paid with ticket tid on node 3/4", ze, ze.Ticket)
	}
	if ze.Code != "stream_interrupted" || ze.Kind != KindInterrupted {
		t.Errorf("error = %s/%s, want interrupted/stream_interrupted", ze.Kind, ze.Code)
	}
}

// doneSentinel is the plaintext line that follows a node's stream.
var doneSentinel = []byte("[DONE]")

var (
	answerFrame   = Frame{Data: []byte(`{"choices":[{"index":0,"delta":{"content":"hi"}}]}`), Sealed: true}
	finishedFrame = Frame{Data: []byte(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`), Sealed: true}
	errorFrame    = Frame{Data: []byte(`{"error":{"message":"rate limited","code":"rate_limit_exceeded"}}`), Sealed: true}
	sentinelFrame = Frame{Data: doneSentinel}
)

// endedEmitter runs frames through a chat emitter, then ends the stream as
// Stream.Events does once the forwarder returns, and reports every event and
// the terminal error.
func endedEmitter(t *testing.T, frames ...Frame) ([]Event, error) {
	t.Helper()
	var evs []Event
	var gotErr error
	em := &streamEmitter{
		yield: func(ev Event, err error) bool {
			if err != nil {
				if gotErr != nil {
					t.Errorf("a second terminal error: %v after %v", err, gotErr)
				}
				gotErr = err
				return true
			}
			if gotErr != nil {
				t.Errorf("event %s after the terminal error", ev.EventType())
			}
			evs = append(evs, ev)
			return true
		},
		cancel: func() {},
		dec:    newDecoder(endpointChatCompletions),
	}
	for _, f := range frames {
		em.frame(outFrame{frame: f})
	}
	em.finish()
	em.finish()
	em.interrupt()
	if gotErr != nil && em.err != gotErr {
		t.Errorf("Err() = %v, the loop got %v", em.err, gotErr)
	}
	return evs, gotErr
}

func dones(evs []Event) []Done {
	var out []Done
	for _, ev := range evs {
		if d, ok := ev.(Done); ok {
			out = append(out, d)
		}
	}
	return out
}

// The turn's one ending is decided from the node's sealed frames once the
// stream is over. The plaintext [DONE] decides nothing: a relay can add one
// early or drop it, and neither may pass for a finished answer.
func TestStreamEmitter_EndsOnSealedEvidence(t *testing.T) {
	for _, tc := range []struct {
		name      string
		frames    []Frame
		wantErr   string // terminal error code, or "" for Done
		wantEmpty bool
	}{
		{"finished", []Frame{answerFrame, finishedFrame, sentinelFrame}, "", false},
		{"finished without the sentinel", []Frame{answerFrame, finishedFrame}, "", false},
		{"sentinel added early", []Frame{answerFrame, sentinelFrame, finishedFrame, sentinelFrame}, "", false},
		{"cut before the finish", []Frame{answerFrame, sentinelFrame}, "stream_interrupted", false},
		{"nothing", []Frame{sentinelFrame}, "stream_interrupted", false},
		{"finished with no answer", []Frame{finishedFrame, sentinelFrame}, "", true},
		{"node error", []Frame{answerFrame, errorFrame, sentinelFrame, finishedFrame}, "upstream_error", false},
		{"sealed [DONE] is content", []Frame{{Data: doneSentinel, Sealed: true}, answerFrame}, "stream_interrupted", false},
		{"plaintext finish is not evidence", []Frame{answerFrame, {Data: finishedFrame.Data}}, "stream_interrupted", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			evs, err := endedEmitter(t, tc.frames...)
			ds := dones(evs)
			if tc.wantErr != "" {
				ze, ok := err.(*Error)
				if !ok || ze.Code != tc.wantErr {
					t.Fatalf("ended in %v, want %s", err, tc.wantErr)
				}
				if len(ds) != 0 {
					t.Errorf("an errored turn also yielded Done: %+v", ds)
				}
				return
			}
			if err != nil {
				t.Fatalf("ended in %v, want Done", err)
			}
			if len(ds) != 1 {
				t.Fatalf("Done fired %d times, want once", len(ds))
			}
			if ds[0].Empty != tc.wantEmpty || ds[0].FinishReason != "stop" {
				t.Errorf("done = %+v, want stop, Empty=%v", ds[0], tc.wantEmpty)
			}
			if evs[len(evs)-1] != Event(ds[0]) {
				t.Errorf("Done is not last: %v", evs)
			}
		})
	}
}

// A plaintext frame is passed on but never decoded: a relay can write one.
func TestStreamEmitter_PlaintextFrameIsNotDecoded(t *testing.T) {
	evs, _ := endedEmitter(t, Frame{Data: answerFrame.Data})
	for _, ev := range evs {
		if _, ok := ev.(TextDelta); ok {
			t.Fatalf("a plaintext frame decoded into %+v", ev)
		}
	}
	if len(evs) != 1 {
		t.Errorf("events = %v, want the Frame alone", evs)
	}
}

// A stream that broke keeps the node's own account of why, when it gave one.
func TestStreamEmitter_InterruptPrefersTheNodesFailure(t *testing.T) {
	var gotErr error
	em := &streamEmitter{
		yield:  func(_ Event, err error) bool { gotErr = err; return true },
		cancel: func() {},
		dec:    newDecoder(endpointChatCompletions),
	}
	em.frame(outFrame{frame: errorFrame})
	em.interrupt()
	if ze, ok := gotErr.(*Error); !ok || ze.Code != "upstream_error" {
		t.Errorf("ended in %v, want the node's upstream error", gotErr)
	}
}

// A single-body reply ends in Done too, and one with no answer says so.
func TestStreamEmitter_ReplyDone(t *testing.T) {
	for _, tc := range []struct {
		body      []byte
		wantEmpty bool
	}{
		{nil, true},
		{[]byte(`{"choices":[{"index":0,"message":{"content":"hi"},"finish_reason":"stop"}]}`), false},
		{[]byte(`{"choices":[{"index":0,"message":{"content":"","reasoning":"hmm"},"finish_reason":"stop"}]}`), true},
	} {
		var last Event
		em := &streamEmitter{
			yield:  func(ev Event, _ error) bool { last = ev; return true },
			cancel: func() {},
			dec:    newDecoder(endpointChatCompletions),
		}
		em.reply(200, http.Header{}, tc.body, nil)
		d, ok := last.(Done)
		if !ok || d.Empty != tc.wantEmpty {
			t.Errorf("body %q: last event %+v, want Done{Empty: %v}", tc.body, last, tc.wantEmpty)
		}
	}
}

// A sealed reply the node marked failed is not an answer, whether or not its
// body says why, and its Retry-After is kept. Its status is what judges a
// retry when the body names no code.
func TestStreamEmitter_ReplyFailedStatus(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantMsg string
		status              int
		wantNodeReply       bool
		wantRetryable       bool
	}{
		{"unexplained", `{"detail":"x"}`, "the node answered HTTP 503", 503, true, true},
		{"not json", `<html>503</html>`, "the node answered HTTP 503", 503, true, true},
		{"explained", `{"error":{"message":"overloaded","code":"provider_overloaded"}}`, "overloaded", 503, false, true},
		{"explained without a code", `{"error":{"message":"overloaded"}}`, "overloaded", 503, false, true},
		{"the lowest failed status", `{"detail":"x"}`, "the node answered HTTP 400", 400, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotErr error
			em := &streamEmitter{
				yield: func(ev Event, err error) bool {
					if _, ok := ev.(Done); ok {
						t.Error("a failed reply yielded Done")
					}
					gotErr = err
					return true
				},
				cancel: func() {},
				dec:    newDecoder(endpointChatCompletions),
			}
			h := http.Header{}
			h.Set("Retry-After", "7")
			em.reply(tc.status, h, []byte(tc.body), nil)
			ze, ok := gotErr.(*Error)
			if !ok || ze.Kind != KindUpstream || ze.Message != tc.wantMsg {
				t.Fatalf("ended in %v, want upstream %q", gotErr, tc.wantMsg)
			}
			if ze.RetryAfter != 7*time.Second {
				t.Errorf("RetryAfter = %v, want 7s", ze.RetryAfter)
			}
			if _, isReply := ze.Err.(*NodeReply); isReply != tc.wantNodeReply {
				t.Errorf("cause = %T, want NodeReply %v", ze.Err, tc.wantNodeReply)
			}
			if ze.Retryable != tc.wantRetryable {
				t.Errorf("Retryable = %v, want %v", ze.Retryable, tc.wantRetryable)
			}
		})
	}
}

// FramesOnly yields the node's frames and nothing decoded from them, an error
// frame included, and a Done with no fields once the stream is over.
func TestStreamEmitter_FramesOnly(t *testing.T) {
	var evs []Event
	var gotErr error
	em := &streamEmitter{
		yield:  func(ev Event, err error) bool { evs = append(evs, ev); gotErr = err; return true },
		cancel: func() {},
	}
	em.frame(outFrame{frame: answerFrame})
	em.frame(outFrame{frame: errorFrame})
	em.frame(outFrame{frame: sentinelFrame})
	em.finish()

	if gotErr != nil {
		t.Fatalf("FramesOnly ended in %v, want Done", gotErr)
	}
	want := []string{"frame", "frame", "frame", "done"}
	if len(evs) != len(want) {
		t.Fatalf("events %v, want %v", evs, want)
	}
	for i, ev := range evs {
		if ev.EventType() != want[i] {
			t.Errorf("event %d = %s, want %s", i, ev.EventType(), want[i])
		}
	}
	if d := evs[3].(Done); d != (Done{}) {
		t.Errorf("Done = %+v, want zero", d)
	}
}

// An error the node reports inside its response ends the turn as paid and
// upstream, after the receipt, in place of Done.
func TestStreamEmitter_ErrorFrameEndsInUpstreamError(t *testing.T) {
	var evs []Event
	var gotErr error
	em := &streamEmitter{
		yield:  func(ev Event, err error) bool { evs = append(evs, ev); gotErr = err; return true },
		cancel: func() {},
		dec:    newDecoder(endpointChatCompletions),
	}
	em.reserved(&ReservedTicket{Ticket: &ticket.Ticket{TicketID: "tid"}}, Operator{ID: 3, NodeID: 4})
	em.committed("tid", "txid", 1000)
	em.frame(outFrame{frame: errorFrame})
	em.frame(outFrame{usage: &usageReport{receipt: &ticket.UsageReceipt{}, ticket: &ticket.Ticket{}}})
	em.frame(outFrame{frame: sentinelFrame})
	em.finish()

	ze, ok := gotErr.(*Error)
	if !ok {
		t.Fatalf("ended in %v, want *Error", gotErr)
	}
	// The node's code is its claim, kept apart from the SDK's own codes.
	if ze.Kind != KindUpstream || ze.Code != "upstream_error" || ze.Message != "rate limited" {
		t.Errorf("error = %s/%s %q, want upstream/upstream_error", ze.Kind, ze.Code, ze.Message)
	}
	pe, ok := errors.AsType[*ProviderError](gotErr)
	if !ok || pe.Code != "rate_limit_exceeded" || pe.Message != "rate limited" {
		t.Errorf("cause = %v, want the node's rate_limit_exceeded", ze.Err)
	}
	if !ze.Paid || ze.Ticket == nil || ze.Ticket.ID != "tid" {
		t.Errorf("error paid=%v ticket=%+v, want paid on tid", ze.Paid, ze.Ticket)
	}
	for _, ev := range evs {
		if _, ok := ev.(Done); ok {
			t.Error("a failed turn also ended in Done")
		}
	}
	sawReceipt := false
	for _, ev := range evs {
		_, ok := ev.(ReceiptVerified)
		sawReceipt = sawReceipt || ok
	}
	if !sawReceipt {
		t.Error("the receipt was not reported before the error")
	}
}

// The stream tally counts what a frame costs on the wire, its SSE encoding. A
// usage report is an event the caller may render or not, so it counts nothing.
func TestStreamEmitter_FrameSizes(t *testing.T) {
	var got []Event
	em := &streamEmitter{
		yield:  func(ev Event, _ error) bool { got = append(got, ev); return true },
		cancel: func() {},
	}
	f := Frame{Event: "message", Data: []byte(`{"x":1}`), Sealed: true}
	if n, _ := em.frame(outFrame{frame: f}); n != len(f.SSE()) {
		t.Errorf("frame size = %d, want its SSE encoding's %d", n, len(f.SSE()))
	}
	usage := &usageReport{receipt: &ticket.UsageReceipt{}, ticket: &ticket.Ticket{}}
	if n, _ := em.frame(outFrame{usage: usage}); n != 0 {
		t.Errorf("usage report size = %d, want 0", n)
	}
	if len(got) != 2 {
		t.Fatalf("events = %v, want the frame then the receipt", got)
	}
	if _, ok := got[1].(ReceiptVerified); !ok {
		t.Errorf("usage report emitted %T, want ReceiptVerified", got[1])
	}
}

// A caller that leaves after generation completes must not stop the stream
// before the receipt tail: the receipt is where the operator gets paid.
func TestForwardRawStream_DisconnectAfterGenerationStillReachesTail(t *testing.T) {
	cut := make(chan struct{})
	var method atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method.Store(r.Method)
		w.Header().Set("Content-Type", "text/event-stream")
		fl := w.(http.Flusher)
		_, _ = io.WriteString(w, "data: done\n\n")
		fl.Flush()
		<-cut
		_, _ = io.WriteString(w, "data: after\n\ndata: tail\n\n")
		fl.Flush()
	}))
	defer upstream.Close()

	s := &Client{log: slog.New(slog.NewTextHandler(io.Discard, nil)), httpClient: &http.Client{}}
	clientCtx, leave := context.WithCancel(context.Background())

	var genComplete, sawTail atomic.Bool
	factory := func(*http.Response) (frameTransform, error) {
		return func(f Frame) (outFrame, error) {
			switch string(f.Data) {
			case "done":
				genComplete.Store(true)
				leave()
				close(cut)
			case "tail":
				sawTail.Store(true)
			}
			return outFrame{frame: f}, nil
		}, nil
	}
	s.forwardRawStream(clientCtx, &recEmitter{}, upstream.URL, "", []byte("{}"), "application/json", nil, nil,
		factory, func(emitter, *http.Response, []byte) error { return nil }, &genComplete)

	if !sawTail.Load() {
		t.Error("the stream ended before the tail frame after the client left")
	}
	if got := method.Load(); got != http.MethodPost {
		t.Errorf("streaming forward used method %v, want POST", got)
	}
}

// The non-streaming forward posts too: every inference route is a POST, and a
// node answers anything else with 405.
func TestForwardRawNonStream_Posts(t *testing.T) {
	var method string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method = r.Method
	}))
	defer upstream.Close()

	s := &Client{log: slog.New(slog.NewTextHandler(io.Discard, nil)), httpClient: &http.Client{}}
	s.forwardRawNonStream(context.Background(), &recEmitter{}, upstream.URL, "", []byte("{}"),
		"application/json", nil, nil, func(emitter, *http.Response, []byte) error { return nil })
	if method != http.MethodPost {
		t.Errorf("forward used method %q, want POST", method)
	}
}

// After the open, a node refusing admission is a paid turn interrupted, and
// its code is what a caller branches on.
func TestNonStreamResponder_PreEnvelopeErrorIsInterrupted(t *testing.T) {
	s := &Client{log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	responder := s.buildNonStreamResponder(context.Background(), nil, "", nil, Operator{}, nil,
		nil, endpointChatCompletions, "m", 0, 0, nil)

	for _, tc := range []struct {
		name, body, wantCode string
	}{
		{"node error", `{"error":{"message":"bad ticket","type":"invalid_request_error","code":"ticket_invalid"}}`, "ticket_invalid"},
		{"unparseable page", `<html>504</html>`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			em := &recEmitter{}
			resp := &http.Response{StatusCode: 402, Header: http.Header{}}
			resp.Header.Set("Retry-After", "3")
			setNodeHeaders(resp.Header)
			if err := responder(em, resp, []byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			if em.failed == nil || em.replied != nil {
				t.Fatalf("failed %v replied %v, want a failure", em.failed, em.replied)
			}
			if em.failed.Kind != KindInterrupted || em.failed.Code != tc.wantCode {
				t.Errorf("Kind %q Code %q, want interrupted %q", em.failed.Kind, em.failed.Code, tc.wantCode)
			}
			up, ok := em.failed.Err.(*NodeReply)
			if !ok || up.Status != 402 {
				t.Fatalf("Err = %v, want the node's 402 reply", em.failed.Err)
			}
			if !strings.Contains(string(up.Body), "{") {
				t.Errorf("reply body %q, want JSON", up.Body)
			}
			if em.failed.RetryAfter == 0 {
				t.Error("RetryAfter not copied from the node's Retry-After")
			}
			assertNodeHeader(t, "NodeReply", up.Header)
		})
	}
}

// setNodeHeaders gives h the protocol fields a node sends, one a hostile node
// invents, and an ordinary one.
func setNodeHeaders(h http.Header) {
	h.Set("X-Zs-Settle-Group", "pre-signed")
	h.Set("X-Zs-Receipt", "receipt")
	h.Set("X-Zs-Evil", "x")
	h.Set("X-Request-Id", "req-1")
}

// assertNodeHeader checks that h is a node header set as an SDK caller may
// see it: SPEC §5.2 step 4 strips every X-Zs-* field, the settle group above
// all, since it carries the operator's pre-signed half.
func assertNodeHeader(t *testing.T, where string, h http.Header) {
	t.Helper()
	for k := range h {
		if strings.HasPrefix(k, "X-Zs-") {
			t.Errorf("%s header carries the node's %s", where, k)
		}
	}
	if h.Get("X-Request-Id") != "req-1" {
		t.Errorf("%s header dropped X-Request-Id: %v", where, h)
	}
}

// ResponseStarted hands the caller the node's headers, never its protocol
// fields, for a single-body reply and a stream alike.
func TestStreamEmitter_ResponseStartedStripsProtocolHeaders(t *testing.T) {
	for _, streaming := range []bool{false, true} {
		var started *ResponseStarted
		em := &streamEmitter{
			yield: func(ev Event, _ error) bool {
				if rs, ok := ev.(ResponseStarted); ok {
					started = &rs
				}
				return true
			},
			cancel: func() {},
		}
		h := http.Header{}
		setNodeHeaders(h)
		if streaming {
			_ = em.open(200, h)
		} else {
			em.reply(200, h, []byte("{}"), nil)
		}
		if started == nil {
			t.Fatalf("streaming=%v: no ResponseStarted", streaming)
		}
		assertNodeHeader(t, "ResponseStarted", started.Header)
	}
}

// The usage report carries the fee snapshot as taken, including that the rate
// was unknown: a caller told the rate is a known 0 would show a total debit
// with no platform fee in it.
func TestUsageReport_Event(t *testing.T) {
	u := &usageReport{
		receipt:      &ticket.UsageReceipt{TicketID: "tid"},
		ticket:       &ticket.Ticket{MaxPrice: 9},
		op:           Operator{ID: 7, NodeID: 2, OwnerAddr: "OWNER"},
		openFees:     3,
		settleFees:   5,
		algoUSDPrice: 0.25,
	}
	ev := u.event()
	if ev.FeeBpsKnown || ev.FeeBps != 0 {
		t.Errorf("cold rate reported as FeeBps=%d known=%v", ev.FeeBps, ev.FeeBpsKnown)
	}
	if ev.Receipt.TicketID != "tid" || ev.Ticket.MaxPrice != 9 || ev.Target != (NodeRef{Op: 7, Node: 2}) || ev.OwnerAddr != "OWNER" {
		t.Errorf("event = %+v, want the receipt, ticket and node it was built from", ev)
	}
	if ev.OpenFeesMicroAlgos != 3 || ev.SettleFeesMicroAlgos != 5 || ev.AlgoUSD != 0.25 {
		t.Errorf("fees = open %d settle %d algo %v, want 3, 5, 0.25", ev.OpenFeesMicroAlgos, ev.SettleFeesMicroAlgos, ev.AlgoUSD)
	}

	u.feeBps, u.haveFee = 150, true
	if ev := u.event(); !ev.FeeBpsKnown || ev.FeeBps != 150 {
		t.Errorf("warm rate reported as FeeBps=%d known=%v, want 150 known", ev.FeeBps, ev.FeeBpsKnown)
	}
}
