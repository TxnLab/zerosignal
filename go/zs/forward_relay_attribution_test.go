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
	"slices"
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

// The streaming seam's floor: with the payer still connected, a relay we
// cannot reach is charged.
func TestForwardRawStream_UnreachableRelayIsCharged(t *testing.T) {
	// A closed listener: the dial is refused, so Do fails before any response.
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	rep := newFakeRelayRep()
	s := forwardAttributionServer(rep)
	hop := &RelayHop{RelayID: 5, TargetID: 9, BaseURL: deadURL}
	var genComplete atomic.Bool

	s.forwardRawStream(context.Background(), &recEmitter{}, deadURL, "", []byte("{}"), "application/json", nil, hop,
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

// The streaming forward rides a context detached from the payer's, but until
// the node's headers arrive a payer who leaves still cancels it: the forward
// ends at once rather than at the header backstop, and the relay is not
// charged for a socket the SDK tore down itself.
func TestForwardRawStream_CallerHangUpBeforeHeadersEndsItAndChargesNoRelay(t *testing.T) {
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
	var genComplete atomic.Bool
	em := &recEmitter{}

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forwardRawStream(ctx, em, upstream.URL, "", []byte("{}"), "application/json", nil, hop,
			passFrames, func(emitter, *http.Response, []byte) error { return nil }, &genComplete, nil)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the payer left before the headers and the forward kept waiting")
	}
	if len(rep.outcomes) != 0 {
		t.Errorf("recorded %v after the payer hung up", rep.outcomes)
	}
	if em.failed == nil || em.failed.Code != "upstream_unreachable" {
		t.Errorf("failed with %v, want upstream_unreachable", em.failed)
	}
}

// A buffered reply's headers come once the generation is done, so a payer who
// leaves mid-body doesn't end the read: the body carries the receipt the
// settle is checked against.
func TestForwardRawStream_CallerHangUpMidBufferedReplyStillReadsIt(t *testing.T) {
	left := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sseWrite(w, `{"partial":`)
		<-left
		sseWrite(w, `true}`)
	}))
	defer upstream.Close()

	s := forwardAttributionServer(nil)
	s.cfg.StreamIdle = StreamIdle{Off: true}
	ctx, cancel := context.WithCancel(context.Background())
	var genComplete atomic.Bool
	em := &recEmitter{}
	var got []byte
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forwardRawStream(ctx, em, upstream.URL, "", []byte("{}"), "application/json", nil, nil,
			passFrames, func(_ emitter, _ *http.Response, b []byte) error { got = b; return nil }, &genComplete, nil)
	}()
	time.Sleep(25 * time.Millisecond)
	cancel()
	time.Sleep(25 * time.Millisecond)
	close(left)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the forward did not return")
	}
	if em.failed != nil || string(got) != `{"partial":true}` {
		t.Errorf("failed %v, got %q; want the whole reply read", em.failed, got)
	}
}

// A forward the payer ended is logged at debug; one that failed on its own,
// at its level.
func TestForwardRawNonStream_LogsWhatThePayerEndedAtDebug(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close()
	release := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		sseWrite(w, `{"partial":`)
		<-release
	}))
	defer silent.Close()
	defer close(release)

	gone, cancel := context.WithCancel(context.Background())
	cancel()
	leaving, leave := context.WithCancel(context.Background())
	defer leave()
	for _, tc := range []struct {
		name      string
		ctx       context.Context
		url       string
		msg       string
		level     slog.Level
		streaming bool
	}{
		{"request, payer gone", gone, silent.URL, "operator request failed", slog.LevelDebug, false},
		{"request, payer there", context.Background(), deadURL, "operator request failed", slog.LevelError, false},
		{"body, payer left", leaving, silent.URL, "operator reply read failed", slog.LevelDebug, false},
		{"stream request, payer gone", gone, silent.URL, "upstream request failed", slog.LevelDebug, true},
		{"stream request, payer there", context.Background(), deadURL, "upstream request failed", slog.LevelError, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var levels []slog.Level
			s := forwardAttributionServer(nil)
			s.log = slog.New(levelRecorder{&levels, tc.msg})
			s.cfg.StreamIdle = StreamIdle{Off: true}
			if tc.ctx == leaving {
				go func() {
					time.Sleep(25 * time.Millisecond)
					leave()
				}()
			}
			respond := func(emitter, *http.Response, []byte) error { return nil }
			if tc.streaming {
				var genComplete atomic.Bool
				s.forwardRawStream(tc.ctx, &recEmitter{}, tc.url, "", []byte("{}"), "application/json", nil, nil,
					passFrames, respond, &genComplete, nil)
			} else {
				s.forwardRawNonStream(tc.ctx, &recEmitter{}, tc.url, "", []byte("{}"), "application/json", nil, nil, respond)
			}
			if !slices.Equal(levels, []slog.Level{tc.level}) {
				t.Errorf("%q logged at %v, want %v", tc.msg, levels, tc.level)
			}
		})
	}
}

// levelRecorder records the level of each record whose message is msg.
type levelRecorder struct {
	levels *[]slog.Level
	msg    string
}

func (levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (r levelRecorder) Handle(_ context.Context, rec slog.Record) error {
	if rec.Message == r.msg {
		*r.levels = append(*r.levels, rec.Level)
	}
	return nil
}
func (r levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return r }
func (r levelRecorder) WithGroup(string) slog.Handler      { return r }
