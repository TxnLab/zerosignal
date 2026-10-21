/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/websocket"
)

type wsCall struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params"`
}

// fakePubSub is an RPC pubsub endpoint the test drives frame by frame.
type fakePubSub struct {
	url    string
	header chan http.Header
	conns  chan *websocket.Conn
	calls  chan wsCall
}

func newFakePubSub(t *testing.T) *fakePubSub {
	t.Helper()
	f := &fakePubSub{header: make(chan http.Header, 4), conns: make(chan *websocket.Conn, 4), calls: make(chan wsCall, 16)}
	srv := httptest.NewServer(websocket.Server{Handler: func(ws *websocket.Conn) {
		f.header <- ws.Request().Header.Clone()
		f.conns <- ws
		for {
			var c wsCall
			if err := websocket.JSON.Receive(ws, &c); err != nil {
				return
			}
			f.calls <- c
		}
	}})
	t.Cleanup(srv.Close)
	f.url = "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?api-key=secret"
	return f
}

func (f *fakePubSub) conn(t *testing.T) *websocket.Conn {
	t.Helper()
	select {
	case ws := <-f.conns:
		return ws
	case <-time.After(5 * time.Second):
		t.Fatal("no connection")
		return nil
	}
}

func (f *fakePubSub) next(t *testing.T) wsCall {
	t.Helper()
	select {
	case c := <-f.calls:
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no call")
		return wsCall{}
	}
}

func sendFrame(t *testing.T, ws *websocket.Conn, format string, a ...any) {
	t.Helper()
	if err := websocket.Message.Send(ws, fmt.Sprintf(format, a...)); err != nil {
		t.Fatal(err)
	}
}

func dial(t *testing.T, f *fakePubSub, header http.Header) (*PubSub, *websocket.Conn) {
	t.Helper()
	p, err := DialPubSub(t.Context(), f.url, PubSubOptions{Header: header})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p, f.conn(t)
}

// subscribe arms a watch, answering the subscribe with subID.
func subscribe(t *testing.T, p *PubSub, f *fakePubSub, ws *websocket.Conn, c Commitment, subID uint64) (*SignatureSubscription, wsCall) {
	t.Helper()
	type out struct {
		s   *SignatureSubscription
		err error
	}
	done := make(chan out, 1)
	go func() {
		s, err := p.SignatureSubscribe(t.Context(), testSig, c)
		done <- out{s, err}
	}()
	call := f.next(t)
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":%d,"id":%d}`, subID, call.ID)
	o := <-done
	if o.err != nil {
		t.Fatal(o.err)
	}
	return o.s, call
}

func waitDone(t *testing.T, s *SignatureSubscription) (SignatureResult, error) {
	t.Helper()
	select {
	case <-s.Done():
		return s.Result()
	case <-time.After(5 * time.Second):
		t.Fatal("subscription never ended")
		return SignatureResult{}, nil
	}
}

func TestSignatureSubscribeNotifies(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, http.Header{"X-Api-Key": {"k1"}})
	if h := <-f.header; h.Get("X-Api-Key") != "k1" {
		t.Errorf("handshake header = %v", h)
	}

	ok, call := subscribe(t, p, f, ws, Finalized, 7)
	if call.Method != "signatureSubscribe" || string(call.Params) != `["`+testSig.String()+`",{"commitment":"finalized"}]` {
		t.Fatalf("call = %s %s", call.Method, call.Params)
	}
	failed, call := subscribe(t, p, f, ws, "", 8)
	if string(call.Params) != `["`+testSig.String()+`",{}]` {
		t.Fatalf("params with no commitment = %s", call.Params)
	}

	// The received notice is for a subscription that asked for it; this one is
	// still waiting after it.
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":5},"value":"receivedSignature"},"subscription":8}}`)
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":9},"value":{"err":{"InstructionError":[1,{"Custom":6001}]}}},"subscription":8}}`)
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":11},"value":{"err":null}},"subscription":7}}`)

	if r, err := waitDone(t, ok); err != nil || r.Slot != 11 || r.Err != nil {
		t.Fatalf("success = %+v, %v", r, err)
	}
	if r, err := waitDone(t, failed); err != nil || r.Slot != 9 || TxErrName(r.Err) != "InstructionError" {
		t.Fatalf("failure = %+v %s, %v", r, r.Err, err)
	}
}

func TestSignatureSubscribeRefused(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	errc := make(chan error, 1)
	go func() {
		_, err := p.SignatureSubscribe(t.Context(), testSig, Confirmed)
		errc <- err
	}()
	call := f.next(t)
	sendFrame(t, ws, `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":%d}`, call.ID)
	err := <-errc
	if e, ok := errors.AsType[*Error](err); !ok || e.Code != -32602 {
		t.Fatalf("err = %v", err)
	}
}

func TestDroppedSocketEndsEveryWatch(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	s, _ := subscribe(t, p, f, ws, Finalized, 3)
	_ = ws.Close()
	if _, err := waitDone(t, s); !errors.Is(err, ErrPubSubClosed) {
		t.Fatalf("err = %v, want ErrPubSubClosed", err)
	}
	<-p.Done()
	if !errors.Is(p.Err(), ErrPubSubClosed) {
		t.Fatalf("Err = %v", p.Err())
	}
	if _, err := p.SignatureSubscribe(t.Context(), testSig, Finalized); !errors.Is(err, ErrPubSubClosed) {
		t.Fatalf("subscribe after the drop: %v", err)
	}
}

func TestCloseEndsEveryWatch(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	s, _ := subscribe(t, p, f, ws, Finalized, 3)
	_ = p.Close()
	if _, err := waitDone(t, s); !errors.Is(err, ErrPubSubClosed) {
		t.Fatalf("err = %v, want ErrPubSubClosed", err)
	}
}

func TestUnsubscribe(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	s, _ := subscribe(t, p, f, ws, Finalized, 41)
	s.Unsubscribe()
	if _, err := waitDone(t, s); !errors.Is(err, ErrUnsubscribed) {
		t.Fatalf("err = %v", err)
	}
	if c := f.next(t); c.Method != "signatureUnsubscribe" || string(c.Params) != `[41]` {
		t.Fatalf("call = %s %s", c.Method, c.Params)
	}
	// A second unsubscribe sends nothing: the next call the RPC sees is the
	// next subscribe.
	s.Unsubscribe()
	_, call := subscribe(t, p, f, ws, Finalized, 42)
	if call.Method != "signatureSubscribe" {
		t.Fatalf("call = %s %s", call.Method, call.Params)
	}
}

// The RPC reuses an id once its watch has notified. A handle to the watch that
// ended must not end the one that now holds the id.
func TestStaleUnsubscribeLeavesTheReusedID(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	first, _ := subscribe(t, p, f, ws, Finalized, 7)
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":3},"value":{"err":null}},"subscription":7}}`)
	if r, err := waitDone(t, first); err != nil || r.Slot != 3 {
		t.Fatalf("first watch = %+v, %v", r, err)
	}
	second, _ := subscribe(t, p, f, ws, Finalized, 7)

	first.Unsubscribe()
	p.mu.Lock()
	holder := p.subs[7]
	p.mu.Unlock()
	if holder != second {
		t.Fatalf("id 7 is held by %p, want the second watch %p", holder, second)
	}
	// The next call the RPC sees is the next subscribe, not an unsubscribe of 7.
	if _, call := subscribe(t, p, f, ws, Finalized, 8); call.Method != "signatureSubscribe" {
		t.Fatalf("call = %s %s", call.Method, call.Params)
	}
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":4},"value":{"err":null}},"subscription":7}}`)
	if r, err := waitDone(t, second); err != nil || r.Slot != 4 {
		t.Fatalf("second watch = %+v, %v", r, err)
	}
	if r, err := first.Result(); err != nil || r.Slot != 3 {
		t.Fatalf("first watch after its unsubscribe = %+v, %v", r, err)
	}
}

// answeredCtx ends once the RPC's answer to every pending subscribe has been
// read, so SignatureSubscribe's wait finds the answer and the ctx's end
// together and may take either.
type answeredCtx struct {
	context.Context
	p    *PubSub
	done chan struct{}
}

func (c *answeredCtx) Done() <-chan struct{} {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(time.Millisecond) {
		c.p.mu.Lock()
		n := len(c.p.pending)
		c.p.mu.Unlock()
		if n == 0 {
			break
		}
	}
	return c.done
}

func (c *answeredCtx) Err() error { return context.Canceled }

// A subscribe whose ctx ended as the RPC refused it unsubscribes its handle,
// which never took an id and so reads as id 0. A live watch holding id 0 must
// keep it.
func TestFailedSubscribeLeavesTheWatchOnIDZero(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	live, _ := subscribe(t, p, f, ws, Finalized, 0)

	ended := make(chan struct{})
	close(ended)
	// The wait picks between the refusal and the ctx's end at random; the
	// handle is unsubscribed only on the second.
	for i := 0; ; i++ {
		if i == 64 {
			t.Fatal("the subscribe never took its ctx's end")
		}
		errc := make(chan error, 1)
		ctx := &answeredCtx{Context: t.Context(), p: p, done: ended}
		go func() {
			_, err := p.SignatureSubscribe(ctx, testSig, Finalized)
			errc <- err
		}()
		sendFrame(t, ws, `{"jsonrpc":"2.0","error":{"code":-32602,"message":"Invalid params"},"id":%d}`, f.next(t).ID)
		err := <-errc
		if errors.Is(err, context.Canceled) {
			break
		}
		if e, ok := errors.AsType[*Error](err); !ok || e.Code != -32602 {
			t.Fatalf("err = %v", err)
		}
	}

	p.mu.Lock()
	holder := p.subs[0]
	p.mu.Unlock()
	if holder != live {
		t.Fatalf("id 0 is held by %p, want the live watch %p", holder, live)
	}
	if _, call := subscribe(t, p, f, ws, Finalized, 1); call.Method != "signatureSubscribe" {
		t.Fatalf("call = %s %s", call.Method, call.Params)
	}
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":5},"value":{"err":null}},"subscription":0}}`)
	if r, err := waitDone(t, live); err != nil || r.Slot != 5 {
		t.Fatalf("live watch = %+v, %v", r, err)
	}
}

// The RPC answering two subscribes with one id would strand the first watch
// past the socket's end; the second is refused instead.
func TestRepeatedSubscriptionIDIsRefused(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	first, _ := subscribe(t, p, f, ws, Finalized, 5)
	errc := make(chan error, 1)
	go func() {
		_, err := p.SignatureSubscribe(t.Context(), testSig, Finalized)
		errc <- err
	}()
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":5,"id":%d}`, f.next(t).ID)
	if err := <-errc; err == nil || !strings.Contains(err.Error(), "already in use") {
		t.Fatalf("err = %v", err)
	}
	_ = ws.Close()
	if _, err := waitDone(t, first); !errors.Is(err, ErrPubSubClosed) {
		t.Fatalf("first watch: %v", err)
	}
}

func TestMalformedSubscribeErrorAnswers(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	errc := make(chan error, 1)
	go func() {
		_, err := p.SignatureSubscribe(t.Context(), testSig, Finalized)
		errc <- err
	}()
	sendFrame(t, ws, `{"jsonrpc":"2.0","error":{"code":"x","message":"bad"},"id":%d}`, f.next(t).ID)
	select {
	case err := <-errc:
		if err == nil || !strings.Contains(err.Error(), "malformed error") {
			t.Fatalf("err = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the subscribe never ended")
	}
}

// One frame past the cap is skipped, not the end of every watch.
func TestOversizedFrameIsSkipped(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	s, _ := subscribe(t, p, f, ws, Finalized, 6)
	sendFrame(t, ws, `{"pad":"%s"}`, strings.Repeat("x", pubsubMaxFrame))
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":3},"value":{"err":null}},"subscription":6}}`)
	if r, err := waitDone(t, s); err != nil || r.Slot != 3 {
		t.Fatalf("result = %+v, %v", r, err)
	}
}

// A subscribe its caller gave up on before the RPC armed it would otherwise
// hold a server-side subscription for the socket's life.
func TestAbandonedSubscribeIsDropped(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	ctx, cancel := context.WithCancel(t.Context())
	errc := make(chan error, 1)
	go func() {
		_, err := p.SignatureSubscribe(ctx, testSig, Finalized)
		errc <- err
	}()
	call := f.next(t)
	cancel()
	if err := <-errc; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":99,"id":%d}`, call.ID)
	if c := f.next(t); c.Method != "signatureUnsubscribe" || string(c.Params) != `[99]` {
		t.Fatalf("call = %s %s", c.Method, c.Params)
	}
}

// trackedListener shrinks each accepted connection's receive buffer, so a
// server that stops reading backs the client's writes up after less data, and
// keeps the connections so a test can close them under a blocked write.
type trackedListener struct {
	net.Listener
	mu    sync.Mutex
	conns []net.Conn
}

func (l *trackedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if tc, ok := c.(*net.TCPConn); ok {
		_ = tc.SetReadBuffer(4 << 10)
	}
	l.mu.Lock()
	l.conns = append(l.conns, c)
	l.mu.Unlock()
	return c, nil
}

func (l *trackedListener) closeConns() {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, c := range l.conns {
		_ = c.Close()
	}
}

// deafPubSub completes the handshake, arms the first subscribe as id 1, and
// never reads again. With ping set it instead pings without pause from the
// start, so the client's reader answers each one until its pong write blocks.
type deafPubSub struct {
	url   string
	pings atomic.Int64
}

// dialDeaf returns a socket to a deaf server. A test that fails with a write
// still blocked ends it by closing the server's side, before the socket's
// own Close runs.
func dialDeaf(t *testing.T, ping bool) (*PubSub, *deafPubSub) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tl := &trackedListener{Listener: ln}
	quit := make(chan struct{})
	f := &deafPubSub{}
	srv := httptest.NewUnstartedServer(websocket.Server{Handler: func(ws *websocket.Conn) {
		if !ping {
			var c wsCall
			if websocket.JSON.Receive(ws, &c) == nil {
				_ = websocket.Message.Send(ws, fmt.Sprintf(`{"jsonrpc":"2.0","result":1,"id":%d}`, c.ID))
			}
			<-quit
			return
		}
		ws.PayloadType = websocket.PingFrame
		payload := []byte(strings.Repeat("p", 125))
		for {
			if _, err := ws.Write(payload); err != nil {
				return
			}
			f.pings.Add(1)
		}
	}})
	srv.Listener = tl
	srv.Start()
	t.Cleanup(srv.Close)
	f.url = "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws"
	p, err := DialPubSub(t.Context(), f.url, PubSubOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	t.Cleanup(func() {
		close(quit)
		tl.closeConns()
	})
	return p, f
}

// shortWriteTimeout shortens pubsubWriteTimeout for one test.
func shortWriteTimeout(t *testing.T) time.Duration {
	t.Helper()
	prev := pubsubWriteTimeout
	pubsubWriteTimeout = 200 * time.Millisecond
	t.Cleanup(func() { pubsubWriteTimeout = prev })
	return pubsubWriteTimeout
}

// writeMargin is how much past the write timeout a bounded call may take on
// a loaded machine.
const writeMargin = 2 * time.Second

// A subscribe to a peer that stopped reading returns once its write times
// out rather than holding its caller, whose ctx bounds only the wait for the
// answer. The timed-out write ends the socket as a drop does: the watch
// already armed ends, and a later subscribe is refused as closed rather than
// failing alone on the write error the library keeps.
func TestSubscribeToADeafPeerIsBounded(t *testing.T) {
	timeout := shortWriteTimeout(t)
	p, _ := dialDeaf(t, false)
	watch, err := p.SignatureSubscribe(t.Context(), testSig, Finalized)
	if err != nil {
		t.Fatal(err)
	}
	ended, cancel := context.WithCancel(t.Context())
	cancel()

	type out struct {
		err  error
		took time.Duration
	}
	res := make(chan out, 1)
	go func() {
		// Each subscribe sends its frame before it sees its ended ctx, so the
		// loop fills the socket until one write blocks.
		for {
			start := time.Now()
			_, err := p.SignatureSubscribe(ended, testSig, Finalized)
			if !errors.Is(err, context.Canceled) {
				res <- out{err, time.Since(start)}
				return
			}
		}
	}()
	select {
	case o := <-res:
		if !errors.Is(o.err, os.ErrDeadlineExceeded) {
			t.Fatalf("err = %v, want a write deadline", o.err)
		}
		if o.took > timeout+writeMargin {
			t.Fatalf("the blocked subscribe took %v, want about %v", o.took, timeout)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a subscribe to a peer that stopped reading never returned")
	}

	if _, err := waitDone(t, watch); !errors.Is(err, ErrPubSubClosed) {
		t.Fatalf("the armed watch ended with %v, want ErrPubSubClosed", err)
	}
	select {
	case <-p.Done():
	default:
		t.Fatal("Done is open after the write failed")
	}
	if err := p.Err(); !errors.Is(err, ErrPubSubClosed) || !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Err = %v, want ErrPubSubClosed for the write deadline", err)
	}
	if _, err := p.SignatureSubscribe(t.Context(), testSig, Finalized); !errors.Is(err, ErrPubSubClosed) {
		t.Fatalf("subscribe after the failed write: %v, want ErrPubSubClosed", err)
	}

	closed := make(chan struct{})
	go func() {
		_ = p.Close()
		close(closed)
	}()
	select {
	case <-closed:
	case <-time.After(timeout + writeMargin):
		t.Fatal("Close on a socket the peer stopped reading never returned")
	}
}

// Close behind a write that no deadline bounds, the reader's answer to a
// ping on a socket nothing was ever sent on, returns once the close frame
// times out.
func TestCloseBehindABlockedPongIsBounded(t *testing.T) {
	timeout := shortWriteTimeout(t)
	p, f := dialDeaf(t, true)

	// The pings stall once the reader stops reading, stuck writing a pong.
	last, still := int64(-1), time.Now()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(20 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the client's reader never stopped reading the pings")
		}
		if n := f.pings.Load(); n != last {
			last, still = n, time.Now()
		} else if time.Since(still) > 300*time.Millisecond {
			break
		}
	}

	closed := make(chan struct{})
	start := time.Now()
	go func() {
		_ = p.Close()
		close(closed)
	}()
	select {
	case <-closed:
		if took := time.Since(start); took > timeout+writeMargin {
			t.Fatalf("Close took %v, want about %v", took, timeout)
		}
	case <-time.After(timeout + writeMargin):
		t.Fatal("Close behind a blocked pong never returned")
	}
}

func TestDialPubSubRefusesEndpoints(t *testing.T) {
	for _, e := range []string{
		"http://rpc.example/?api-key=secret", "rpc.example/?api-key=secret", "://secret",
		"wss://user:secret@rpc.example/", "wss://rpc.example/%zz?api-key=secret",
	} {
		_, err := DialPubSub(t.Context(), e, PubSubOptions{})
		if err == nil || strings.Contains(err.Error(), "secret") {
			t.Errorf("%q: err = %v", e, err)
		}
	}
}

// Each half of the userinfo is refused on its own, before any dial: one to
// this closed port would fail with another message.
func TestDialPubSubRefusesEitherCredential(t *testing.T) {
	for _, e := range []string{"wss://:secret@127.0.0.1:1/", "wss://secret@127.0.0.1:1/"} {
		_, err := DialPubSub(t.Context(), e, PubSubOptions{})
		if err == nil || !strings.Contains(err.Error(), "carries credentials") || strings.Contains(err.Error(), "secret") {
			t.Errorf("%q: err = %v", e, err)
		}
	}
}

func TestDialErrorKeepsTheKeyOut(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?api-key=secret"
	srv.Close()
	_, err := DialPubSub(t.Context(), u, PubSubOptions{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}
