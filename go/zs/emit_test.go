/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

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

// A pass-through [DONE] ends the stream; Empty reports whether any sealed
// content came before it. Sealed content that happens to read "[DONE]" is
// content, not the end.
func TestStreamEmitter_DoneAtSentinel(t *testing.T) {
	for _, tc := range []struct {
		name      string
		frames    []Frame
		wantDone  int
		wantEmpty bool
	}{
		{"content", []Frame{{Data: []byte("{}"), Sealed: true}, {Data: doneSentinel}}, 1, false},
		{"empty", []Frame{{Data: doneSentinel}}, 1, true},
		{"sealed [DONE] is content", []Frame{{Data: doneSentinel, Sealed: true}, {Data: doneSentinel}}, 1, false},
		{"no sentinel", []Frame{{Data: doneSentinel, Sealed: true}}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var dones []Done
			em := &streamEmitter{
				yield: func(ev Event, _ error) bool {
					if d, ok := ev.(Done); ok {
						dones = append(dones, d)
					}
					return true
				},
				cancel: func() {},
			}
			for _, f := range tc.frames {
				em.frame(outFrame{frame: f})
			}
			if len(dones) != tc.wantDone {
				t.Fatalf("Done fired %d times, want %d", len(dones), tc.wantDone)
			}
			if tc.wantDone > 0 && dones[0].Empty != tc.wantEmpty {
				t.Errorf("done = %+v, want Empty=%v", dones[0], tc.wantEmpty)
			}
		})
	}
}

// A single-body reply ends in Done too, and an empty body is reported as one.
func TestStreamEmitter_ReplyDone(t *testing.T) {
	for _, tc := range []struct {
		body      []byte
		wantEmpty bool
	}{
		{nil, true},
		{[]byte("{}"), false},
	} {
		var last Event
		em := &streamEmitter{
			yield:  func(ev Event, _ error) bool { last = ev; return true },
			cancel: func() {},
		}
		em.reply(200, http.Header{}, tc.body, nil)
		d, ok := last.(Done)
		if !ok || d.Empty != tc.wantEmpty {
			t.Errorf("body %q: last event %+v, want Done{Empty: %v}", tc.body, last, tc.wantEmpty)
		}
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
	responder := s.buildHayaiNonStreamResponder(context.Background(), nil, "", nil, Operator{}, nil,
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
