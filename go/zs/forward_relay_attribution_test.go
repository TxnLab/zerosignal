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
	"sync/atomic"
	"testing"
	"time"
)

// forwardAttributionServer is the minimum Client forwardRawNonStream touches:
// a real http.Client (the transport failure has to be genuine — a stubbed
// classifier would test the classifier, which relay_reputation_dispatch_test.go
// already does) and an observable reputation store.
func forwardAttributionServer(rep RelayReputation) *Client {
	return &Client{
		log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		httpClient: &http.Client{},
		relayRep:   rep,
	}
}

// The payer hangs up while the non-streaming forward is in flight. That leg
// rides r.Context() and Do blocks for the whole generation, so the proxy's own
// cancellation is what ends the request — and the relay must not be charged for
// a socket we tore down ourselves. Driven at the seam rather than at
// attributeRelayHop because the defect was the seam bypassing the shared
// verdict entirely; a classifier-level test cannot see that.
func TestForwardRawNonStream_CallerHangUpChargesNoRelay(t *testing.T) {
	// Never answers: the request is still in flight when the payer disconnects.
	// Parked on the test's own channel rather than r.Context(), because the
	// server only notices the disconnect once it reads from the connection —
	// which it will not do while this handler is holding it, so waiting on the
	// request context here wedges Close instead of the forward.
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		<-release
	}))
	defer upstream.Close()
	defer close(release)

	rep := newFakeRelayRep()
	s := forwardAttributionServer(rep)
	hop := &RelayHop{RelayID: 5, TargetID: 9, BaseURL: upstream.URL}

	ctx, cancel := context.WithCancel(context.Background())

	go func() {
		time.Sleep(25 * time.Millisecond)
		cancel()
	}()

	s.forwardRawNonStream(ctx, &recEmitter{}, upstream.URL, "", []byte("{}"), "application/json", nil, hop,
		func(emitter, *http.Response, []byte) error { return nil })

	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v after the payer hung up; the proxy cancelled that socket, not the relay",
			rep.outcomes)
	}
}

// The floor the test above must not sink through: with the payer still
// connected, a relay we cannot reach at all is charged. "Never record on a
// transport failure" would satisfy the caller-abort test and silently retire
// the one attribution rule that works against a fleet where no relay stamps a
// hop marker.
func TestForwardRawNonStream_UnreachableRelayIsCharged(t *testing.T) {
	// A closed listener: the dial is refused, so Do fails before any response.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	rep := newFakeRelayRep()
	s := forwardAttributionServer(rep)
	hop := &RelayHop{RelayID: 5, TargetID: 9, BaseURL: deadURL}

	s.forwardRawNonStream(context.Background(), &recEmitter{}, deadURL, "", []byte("{}"), "application/json", nil, hop,
		func(emitter, *http.Response, []byte) error { return nil })

	got, ok := rep.last(hop.RelayRef())
	if !ok {
		t.Fatal("an unreachable relay was not charged for a transport failure")
	}
	if got {
		t.Error("an unreachable relay was credited")
	}
}

// The streaming seam, and the reason it is NOT the non-streaming one with a
// different forwarder: forwardRawStream sends under
// context.WithoutCancel(ctx), so the payer's state says nothing about the
// socket. The payer here has already hung up and the relay is STILL charged —
// which is what makes this the pin for threading upstreamCtx rather than ctx
// into the attribution. Handing it the payer's ctx would read this as a caller
// abort and let a relay that refuses every streaming forward accrue nothing.
func TestForwardRawStream_UnreachableRelayIsChargedDespiteCallerHangUp(t *testing.T) {
	// A closed listener: the dial is refused, so Do fails before any response.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	rep := newFakeRelayRep()
	s := forwardAttributionServer(rep)
	hop := &RelayHop{RelayID: 5, TargetID: 9, BaseURL: deadURL}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var genComplete atomic.Bool

	s.forwardRawStream(ctx, &recEmitter{}, deadURL, "", []byte("{}"), "application/json", nil, hop,
		passFrames,
		func(emitter, *http.Response, []byte) error { return nil },
		&genComplete, nil)

	got, ok := rep.last(hop.RelayRef())
	if !ok {
		t.Fatal("an unreachable relay was not charged on the streaming seam")
	}
	if got {
		t.Error("an unreachable relay was credited on the streaming seam")
	}
}
