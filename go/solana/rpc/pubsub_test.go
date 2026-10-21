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
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestDialErrorKeepsTheKeyOut(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws?api-key=secret"
	srv.Close()
	_, err := DialPubSub(t.Context(), u, PubSubOptions{})
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("err = %v", err)
	}
}
