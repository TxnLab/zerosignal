/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"testing"
	"time"
)

func TestRelayLatency_RecordAndRead(t *testing.T) {
	s := &ChainOperatorSource{}
	relay := NodeRef{Op: 2, Node: 0}
	target := NodeRef{Op: 9, Node: 0}
	s.RecordRelayedRTT(relay, target, 120*time.Millisecond)

	if ms, ok := s.RelayLatencyForTarget(relay, target); !ok || ms != 120 {
		t.Errorf("pair latency = %v ok=%v, want 120/true", ms, ok)
	}
	if ms, n, ok := s.TargetLatency(target); !ok || ms != 120 || n != 1 {
		t.Errorf("target = %v samples=%d ok=%v, want 120/1/true", ms, n, ok)
	}
}

func TestRelayLatency_EWMABlend(t *testing.T) {
	s := &ChainOperatorSource{}
	r, tg := NodeRef{Op: 2}, NodeRef{Op: 9}
	s.RecordRelayedRTT(r, tg, 100*time.Millisecond)
	s.RecordRelayedRTT(r, tg, 200*time.Millisecond)
	want := 0.3*200 + 0.7*100 // 130
	if ms, ok := s.RelayLatencyForTarget(r, tg); !ok || ms != want {
		t.Errorf("ewma = %v, want %v", ms, want)
	}
	if _, n, _ := s.TargetLatency(tg); n != 2 {
		t.Errorf("samples = %d, want 2", n)
	}
}

func TestRelayLatency_DirectUpdatesOnlyTarget(t *testing.T) {
	s := &ChainOperatorSource{}
	tg := NodeRef{Op: 9}
	s.RecordDirectRTT(tg, 80*time.Millisecond)
	if _, _, ok := s.TargetLatency(tg); !ok {
		t.Errorf("direct sample should set the target aggregate")
	}
	if _, ok := s.RelayLatencyForTarget(NodeRef{Op: 2}, tg); ok {
		t.Errorf("a direct sample has no relay leg to attribute")
	}
}

func TestRelayLatency_PairThenEndpointFallback(t *testing.T) {
	s := &ChainOperatorSource{}
	r := NodeRef{Op: 2}
	s.RecordRelayedRTT(r, NodeRef{Op: 9}, 100*time.Millisecond) // pair(2→9)=100, endpoint=100
	s.RecordRelayedRTT(r, NodeRef{Op: 8}, 300*time.Millisecond) // pair(2→8)=300, endpoint ewma=160
	// A measured pair wins verbatim, not the relay's blended endpoint figure.
	if ms, ok := s.RelayLatencyForTarget(r, NodeRef{Op: 9}); !ok || ms != 100 {
		t.Errorf("measured pair should win: %v", ms)
	}
	// An unmeasured pair falls back to the relay endpoint aggregate.
	endpoint := 0.3*300 + 0.7*100 // 160
	if ms, ok := s.RelayLatencyForTarget(r, NodeRef{Op: 7}); !ok || ms != endpoint {
		t.Errorf("unmeasured pair should fall back to endpoint %v, got %v", endpoint, ms)
	}
}

func TestRelayLatency_EvictsOverCap(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &ChainOperatorSource{latClock: func() time.Time { return now }, LatencyStateMax: 10}
	// 50 distinct, all-fresh (relay,target) pairs — the O(n²) map must stay <= cap.
	for i := 0; i < 50; i++ {
		s.RecordRelayedRTT(NodeRef{Op: 1, Node: uint64(i)}, NodeRef{Op: 2, Node: uint64(i)}, 100*time.Millisecond)
	}
	s.latMu.Lock()
	got := len(s.pairLat)
	s.latMu.Unlock()
	if got > 10 {
		t.Fatalf("pairLat size = %d, want <= 10 (cap not enforced)", got)
	}
}

func TestRelayLatency_EvictionReclaimsStaleFirst(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &ChainOperatorSource{latClock: func() time.Time { return now }, LatencyStateMax: 10}
	for i := 0; i < 10; i++ { // fill to cap
		s.RecordRelayedRTT(NodeRef{Op: 1, Node: uint64(i)}, NodeRef{Op: 2, Node: uint64(i)}, 100*time.Millisecond)
	}
	now = now.Add(latencyStaleAfter + time.Second) // all 10 entries now stale
	// One more push crosses the cap and triggers eviction, which reclaims the
	// stale entries before touching any live one — leaving only this fresh pair.
	s.RecordRelayedRTT(NodeRef{Op: 3}, NodeRef{Op: 4}, 100*time.Millisecond)
	s.latMu.Lock()
	got := len(s.pairLat)
	s.latMu.Unlock()
	if got != 1 {
		t.Fatalf("pairLat size = %d after stale sweep, want 1", got)
	}
}

func TestRelayLatency_Staleness(t *testing.T) {
	now := time.Unix(1000, 0)
	s := &ChainOperatorSource{latClock: func() time.Time { return now }}
	r, tg := NodeRef{Op: 2}, NodeRef{Op: 9}
	s.RecordRelayedRTT(r, tg, 100*time.Millisecond)

	now = now.Add(latencyStaleAfter + time.Second)
	if _, ok := s.RelayLatencyForTarget(r, tg); ok {
		t.Errorf("stale pair should read as absent")
	}
	if _, _, ok := s.TargetLatency(tg); ok {
		t.Errorf("stale target should read as absent")
	}
	// A fresh sample after the gap restarts the EWMA (samples=1, no blend).
	s.RecordRelayedRTT(r, tg, 500*time.Millisecond)
	if ms, n, ok := s.TargetLatency(tg); !ok || ms != 500 || n != 1 {
		t.Errorf("post-stale restart = %v/%d, want 500/1", ms, n)
	}
}

func TestRelayLatency_KeysByNodeNotOperator(t *testing.T) {
	s := &ChainOperatorSource{}
	s.RecordRelayedRTT(NodeRef{Op: 2, Node: 0}, NodeRef{Op: 9, Node: 0}, 100*time.Millisecond)
	// A sibling node of the same operator must not inherit the latency.
	if _, ok := s.RelayLatencyForTarget(NodeRef{Op: 2, Node: 1}, NodeRef{Op: 9, Node: 0}); ok {
		t.Errorf("relay sibling 2/1 must not inherit 2/0's latency")
	}
	if _, _, ok := s.TargetLatency(NodeRef{Op: 9, Node: 1}); ok {
		t.Errorf("target sibling 9/1 must not inherit 9/0's latency")
	}
}

func TestRelayLatency_IgnoresNegative(t *testing.T) {
	s := &ChainOperatorSource{}
	tg := NodeRef{Op: 9}
	s.RecordDirectRTT(tg, -5*time.Millisecond)
	if _, _, ok := s.TargetLatency(tg); ok {
		t.Errorf("a negative sample should be ignored")
	}
}
