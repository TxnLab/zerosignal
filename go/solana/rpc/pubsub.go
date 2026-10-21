/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/net/websocket"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The confirmation watch is a signatureSubscribe push, not a getSignatureStatuses
// poll: the public endpoints answer a poll with 429 after about ten calls,
// while a subscription stays within their limits. A dropped socket ends every
// watch on it with ErrPubSubClosed, and the caller polls from there. Nothing
// here notices an upstream that keeps the socket open and stops sending, so a
// watch can stay pending: the caller bounds it, by the blockhash's
// lastValidBlockHeight or a timer, and polls once that passes.
//
// golang.org/x/net/websocket rather than another WebSocket module: this module
// already requires x/net, and a new one would enter every consumer's build. It
// answers the server's pings; it sends none, so the socket is the caller's to
// redial after an idle proxy drops it. It does not reassemble a message split
// across frames, which Agave never sends for frames this small; such pieces
// are dropped as unreadable. It dials directly, never through an HTTP proxy.

// ErrPubSubClosed ends every subscription on a socket that closed, and every
// later subscribe on it.
var ErrPubSubClosed = errors.New("solana rpc: pubsub socket closed")

// ErrUnsubscribed ends a subscription its caller cancelled.
var ErrUnsubscribed = errors.New("solana rpc: unsubscribed")

// pubsubMaxFrame bounds one frame. A signature notification is a few hundred
// bytes; the library's default is 32 MiB.
const pubsubMaxFrame = 1 << 20

// pubsubWriteTimeout bounds one frame's write, so a peer that stopped reading
// stalls neither a subscribe past its ctx nor Close. A variable only so a test
// can wait out a shorter one.
var pubsubWriteTimeout = 10 * time.Second

// PubSubOptions tunes DialPubSub. The zero value is a plain dial.
type PubSubOptions struct {
	// Header rides the handshake, for a provider that takes its API key in one.
	Header http.Header
	// TLSConfig is the wss dial's; nil is the default roots.
	TLSConfig *tls.Config
	// Dialer makes the TCP connection; nil is a zero net.Dialer. The socket
	// takes no HTTP proxy, so a host that must keep its IP from the RPC
	// routes this dial itself or polls instead of watching.
	Dialer *net.Dialer
}

// PubSub is one WebSocket to an RPC's pubsub endpoint, carrying any number of
// subscriptions. It is safe for concurrent use.
type PubSub struct {
	ws *websocket.Conn

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]*SignatureSubscription // by request id, until the RPC answers the subscribe
	subs    map[uint64]*SignatureSubscription // by subscription id, until it notifies
	err     error                             // set before done closes
	done    chan struct{}
}

// DialPubSub opens a socket to endpoint, a ws or wss URL. ctx bounds the
// dial and handshake only. As with NewClient, no error spells the endpoint.
func DialPubSub(ctx context.Context, endpoint string, o PubSubOptions) (*PubSub, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("solana rpc: pubsub endpoint: %w", stripURL(err))
	}
	origin := *u
	switch u.Scheme {
	case "ws":
		origin.Scheme = "http"
	case "wss":
		origin.Scheme = "https"
	default:
		return nil, errors.New("solana rpc: pubsub endpoint is not ws or wss")
	}
	if u.User != nil {
		return nil, errors.New("solana rpc: pubsub endpoint carries credentials; pass them in Header")
	}
	origin.Path, origin.RawQuery, origin.Fragment = "", "", ""
	cfg, err := websocket.NewConfig(endpoint, origin.String())
	if err != nil {
		return nil, fmt.Errorf("solana rpc: pubsub endpoint: %w", stripURL(err))
	}
	cfg.Header, cfg.TlsConfig, cfg.Dialer = o.Header, o.TLSConfig, o.Dialer
	ws, err := cfg.DialContext(ctx)
	if err != nil {
		// A *websocket.DialError spells out the endpoint.
		if de, ok := errors.AsType[*websocket.DialError](err); ok {
			err = de.Err
		}
		return nil, fmt.Errorf("solana rpc: pubsub dial: %w", err)
	}
	ws.MaxPayloadBytes = pubsubMaxFrame
	p := &PubSub{
		ws:      ws,
		pending: map[uint64]*SignatureSubscription{},
		subs:    map[uint64]*SignatureSubscription{},
		done:    make(chan struct{}),
	}
	go p.read()
	return p, nil
}

// Close closes the socket, ending every subscription on it.
func (p *PubSub) Close() error {
	p.fail(ErrPubSubClosed)
	// The close frame waits behind any write in flight, which the deadline bounds.
	_ = p.ws.SetWriteDeadline(time.Now().Add(pubsubWriteTimeout))
	return p.ws.Close()
}

// Done is closed once the socket has ended; Err then says why.
func (p *PubSub) Done() <-chan struct{} { return p.done }

// Err is why the socket ended, wrapping ErrPubSubClosed, or nil while it is open.
func (p *PubSub) Err() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.err
}

// SignatureResult is a watched transaction's outcome at the commitment
// watched for.
type SignatureResult struct {
	Slot uint64
	// Err is the TransactionError it landed with, nil for a success (see
	// TxErrName).
	Err json.RawMessage
}

// SignatureSubscription is one signatureSubscribe. The RPC sends one
// notification and drops the subscription itself.
type SignatureSubscription struct {
	p     *PubSub
	armed chan error // the RPC's answer to the subscribe; buffered

	// Guarded by p.mu.
	id        uint64
	abandoned bool

	once   sync.Once
	done   chan struct{}
	result SignatureResult
	err    error
}

// SignatureSubscribe watches sig until it reaches c, returning once the RPC
// has armed the watch. ctx bounds that wait only; the watch then lasts until
// it notifies, Unsubscribe, or the socket ends.
func (p *PubSub) SignatureSubscribe(ctx context.Context, sig solana.Signature, c Commitment) (*SignatureSubscription, error) {
	s := &SignatureSubscription{p: p, armed: make(chan error, 1), done: make(chan struct{})}
	p.mu.Lock()
	if p.err != nil {
		err := p.err
		p.mu.Unlock()
		return nil, err
	}
	p.nextID++
	reqID := p.nextID
	p.pending[reqID] = s
	p.mu.Unlock()

	cfg := map[string]Commitment{}
	if c != "" {
		cfg["commitment"] = c
	}
	if err := p.send(reqID, "signatureSubscribe", []any{sig.String(), cfg}); err != nil {
		p.mu.Lock()
		delete(p.pending, reqID)
		closed := p.err
		p.mu.Unlock()
		// A socket that failed under the write says so as ErrPubSubClosed.
		if closed != nil {
			return nil, closed
		}
		return nil, err
	}
	select {
	case err := <-s.armed:
		if err != nil {
			return nil, err
		}
		return s, nil
	case <-p.done:
		return nil, p.Err()
	case <-ctx.Done():
		p.mu.Lock()
		_, waiting := p.pending[reqID]
		// The answer may still come; the reader then drops what it arms.
		s.abandoned = waiting
		p.mu.Unlock()
		if !waiting {
			s.Unsubscribe()
		}
		return nil, ctx.Err()
	}
}

// Done is closed once the subscription has ended; Result then holds its outcome.
func (s *SignatureSubscription) Done() <-chan struct{} { return s.done }

// Result is the notification, or the error that ended the subscription
// without one: ErrUnsubscribed, or one wrapping ErrPubSubClosed. It is valid
// once Done is closed.
func (s *SignatureSubscription) Result() (SignatureResult, error) {
	<-s.done
	return s.result, s.err
}

// Unsubscribe ends the subscription with ErrUnsubscribed, unless it has
// already ended.
func (s *SignatureSubscription) Unsubscribe() {
	p := s.p
	p.mu.Lock()
	cur, live := p.subs[s.id]
	live = live && cur == s
	if live {
		delete(p.subs, s.id)
	}
	p.mu.Unlock()
	if live {
		p.unsubscribe(s.id)
		s.finish(SignatureResult{}, ErrUnsubscribed)
	}
}

func (s *SignatureSubscription) finish(r SignatureResult, err error) {
	s.once.Do(func() {
		s.result, s.err = r, err
		close(s.done)
	})
}

func (p *PubSub) send(id uint64, method string, params []any) error {
	b, err := json.Marshal(request{JSONRPC: "2.0", ID: id, Method: method, Params: params})
	if err != nil {
		return fmt.Errorf("solana rpc %s: encode params: %w", method, err)
	}
	_ = p.ws.SetWriteDeadline(time.Now().Add(pubsubWriteTimeout))
	// A string goes as a text frame, which is what the RPC reads.
	if err := websocket.Message.Send(p.ws, string(b)); err != nil {
		return fmt.Errorf("solana rpc %s: %w", method, err)
	}
	return nil
}

// unsubscribe asks the RPC to drop a subscription, off the caller's
// goroutine: a write the server is slow to read would stall the reader.
func (p *PubSub) unsubscribe(subID uint64) {
	p.mu.Lock()
	p.nextID++
	reqID := p.nextID
	p.mu.Unlock()
	go func() { _ = p.send(reqID, "signatureUnsubscribe", []any{subID}) }()
}

type pubsubMessage struct {
	ID     *uint64         `json:"id"`
	Result json.RawMessage `json:"result"`
	// Raw, so a malformed error still answers its subscribe rather than
	// failing the frame's decode and leaving the subscribe waiting.
	Error  json.RawMessage `json:"error"`
	Method string          `json:"method"`
	Params struct {
		Result       json.RawMessage `json:"result"`
		Subscription uint64          `json:"subscription"`
	} `json:"params"`
}

func (p *PubSub) read() {
	for {
		var frame []byte
		err := websocket.Message.Receive(p.ws, &frame)
		if errors.Is(err, websocket.ErrFrameTooLarge) {
			// The next Receive drains it; one stray frame is no reason to end
			// every watch.
			continue
		}
		if err != nil {
			p.fail(fmt.Errorf("%w: %v", ErrPubSubClosed, err))
			_ = p.ws.Close()
			return
		}
		var m pubsubMessage
		if json.Unmarshal(frame, &m) != nil {
			continue
		}
		switch {
		case m.ID != nil:
			p.answer(*m.ID, &m)
		case m.Method == "signatureNotification":
			p.notify(m.Params.Subscription, m.Params.Result)
		}
	}
}

func (p *PubSub) answer(reqID uint64, m *pubsubMessage) {
	p.mu.Lock()
	s := p.pending[reqID]
	if s == nil {
		// An unsubscribe's answer.
		p.mu.Unlock()
		return
	}
	delete(p.pending, reqID)
	if len(m.Error) > 0 && string(m.Error) != "null" {
		p.mu.Unlock()
		var e struct {
			Code    int             `json:"code"`
			Message string          `json:"message"`
			Data    json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(m.Error, &e); err != nil {
			s.armed <- fmt.Errorf("solana rpc signatureSubscribe: malformed error: %w", err)
			return
		}
		s.armed <- &Error{Method: "signatureSubscribe", Code: e.Code, Message: e.Message, Data: e.Data}
		return
	}
	var subID uint64
	if err := json.Unmarshal(m.Result, &subID); err != nil {
		p.mu.Unlock()
		s.armed <- fmt.Errorf("solana rpc signatureSubscribe: subscription id: %w", err)
		return
	}
	if s.abandoned {
		p.mu.Unlock()
		p.unsubscribe(subID)
		return
	}
	// A repeated id would overwrite the first watch, which then outlives
	// even the socket: fail would never see it. Not unsubscribed, since the
	// first watch holds that id.
	if _, taken := p.subs[subID]; taken {
		p.mu.Unlock()
		s.armed <- fmt.Errorf("solana rpc signatureSubscribe: subscription id %d is already in use", subID)
		return
	}
	// Registered before the reader reads on, so a notification right behind
	// the answer finds it.
	s.id = subID
	p.subs[subID] = s
	p.mu.Unlock()
	s.armed <- nil
}

func (p *PubSub) notify(subID uint64, raw json.RawMessage) {
	var r struct {
		Context struct {
			Slot uint64 `json:"slot"`
		} `json:"context"`
		Value *struct {
			Err json.RawMessage `json:"err"`
		} `json:"value"`
	}
	// A value that is not an object is the "receivedSignature" notice, which
	// is sent only to a subscription that asked for it; this one never does.
	if json.Unmarshal(raw, &r) != nil || r.Value == nil {
		return
	}
	p.mu.Lock()
	s := p.subs[subID]
	delete(p.subs, subID)
	p.mu.Unlock()
	if s != nil {
		s.finish(SignatureResult{Slot: r.Context.Slot, Err: nullToNil(r.Value.Err)}, nil)
	}
}

func (p *PubSub) fail(err error) {
	p.mu.Lock()
	if p.err != nil {
		p.mu.Unlock()
		return
	}
	p.err = err
	subs := p.subs
	p.subs = map[uint64]*SignatureSubscription{}
	close(p.done)
	p.mu.Unlock()
	for _, s := range subs {
		s.finish(SignatureResult{}, err)
	}
}
