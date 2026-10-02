/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"errors"
	"net/http"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

func selOp(id uint64, owner string) selection.Operator {
	return selection.Operator{
		ID:           id,
		OwnerAddr:    owner,
		BaseURL:      "https://relay.example",
		ProtoVersion: wire.ProtoVersion,
		Reachable:    true,
	}
}

func TestApplyRelay_NilHopIsNoOp(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/v1/zs/details", nil)
	if err := ApplyRelay(req, nil, "/v1/zs/details", http.MethodGet); err != nil {
		t.Fatalf("ApplyRelay(nil): %v", err)
	}
	if req.URL.String() != "https://target.example/v1/zs/details" || req.Method != http.MethodGet {
		t.Errorf("nil hop mutated the request: %s %s", req.Method, req.URL)
	}
	if req.Header.Get(wire.RelayTargetHeader) != "" {
		t.Errorf("nil hop set relay headers")
	}
}

func TestApplyRelay_RewritesToRelay(t *testing.T) {
	req, _ := http.NewRequest(http.MethodGet, "https://target.example/v1/zs/details", nil)
	hop := &RelayHop{BaseURL: "https://relay.example", TargetID: 7}
	if err := ApplyRelay(req, hop, "/v1/zs/details", http.MethodGet); err != nil {
		t.Fatalf("ApplyRelay: %v", err)
	}
	if want := "https://relay.example" + wire.RelayPath; req.URL.String() != want {
		t.Errorf("URL = %s, want %s", req.URL, want)
	}
	if req.Method != http.MethodPost {
		t.Errorf("Method = %s, want POST (relay route is always POSTed)", req.Method)
	}
	if got := req.Header.Get(wire.RelayTargetHeader); got != "7" {
		t.Errorf("%s = %q, want 7", wire.RelayTargetHeader, got)
	}
	if got := req.Header.Get(wire.RelayPathHeader); got != "/v1/zs/details" {
		t.Errorf("%s = %q", wire.RelayPathHeader, got)
	}
	if got := req.Header.Get(wire.RelayMethodHeader); got != http.MethodGet {
		t.Errorf("%s = %q, want GET (the inner method)", wire.RelayMethodHeader, got)
	}
}

var noLatency = func(NodeRef) (float64, bool) { return 0, false }

func TestSelectRelayHopWeighted_Eligibility(t *testing.T) {
	ops := []selection.Operator{selOp(1, "A"), selOp(2, "B"), selOp(3, "C")}
	target := ops[0]
	hop, err := SelectRelayHopWeighted(ops, target, 0, noLatency) // eligible sorted [2,3]; seed 0 → 2
	if err != nil {
		t.Fatalf("SelectRelayHopWeighted: %v", err)
	}
	if hop.TargetID != 1 {
		t.Errorf("hop.TargetID = %d, want 1", hop.TargetID)
	}
	if hop.RelayID != 2 {
		t.Errorf("hop.RelayID = %d, want 2 (eligible sorted [2,3]; seed 0 → 2)", hop.RelayID)
	}
	if hop.BaseURL != "https://relay.example" {
		t.Errorf("hop.BaseURL = %q", hop.BaseURL)
	}

	// Single operator → no eligible relay.
	if _, err := SelectRelayHopWeighted([]selection.Operator{selOp(1, "A")}, selOp(1, "A"), 0, noLatency); !errors.Is(err, selection.ErrNoRelay) {
		t.Errorf("want ErrNoRelay, got %v", err)
	}
}

func TestSelectRelayHopWeighted_ColdStartRotation(t *testing.T) {
	ops := []selection.Operator{selOp(1, "A"), selOp(2, "B"), selOp(3, "C")}
	target := ops[0] // eligible sorted [2,3]
	// With no latency known, the pick is the deterministic pool[seed % len]
	// rotation — identical to the pre-weighting behavior, so a cold proxy is
	// unchanged. Even seed → relay 2, odd seed → relay 3.
	for _, seed := range []uint64{0, 2, 4} {
		hop, err := SelectRelayHopWeighted(ops, target, seed, noLatency)
		if err != nil || hop.RelayID != 2 {
			t.Errorf("seed %d: got relay %v (err %v), want 2", seed, hopRelay(hop), err)
		}
	}
	for _, seed := range []uint64{1, 3, 5} {
		hop, err := SelectRelayHopWeighted(ops, target, seed, noLatency)
		if err != nil || hop.RelayID != 3 {
			t.Errorf("seed %d: got relay %v (err %v), want 3", seed, hopRelay(hop), err)
		}
	}
	if _, err := SelectRelayHopWeighted([]selection.Operator{selOp(1, "A")}, selOp(1, "A"), 0, noLatency); !errors.Is(err, selection.ErrNoRelay) {
		t.Errorf("want ErrNoRelay on empty pool, got %v", err)
	}
}

func hopRelay(h *RelayHop) any {
	if h == nil {
		return nil
	}
	return h.RelayID
}

// sweepWeighted runs the weighted pick across an even sweep of the uint64 seed
// space and counts which relay each seed lands on — deterministic, no RNG.
func sweepWeighted(t *testing.T, ops []selection.Operator, target selection.Operator, latencyOf func(NodeRef) (float64, bool)) map[uint64]int {
	t.Helper()
	const n = 2000
	counts := map[uint64]int{}
	for i := 0; i < n; i++ {
		seed := uint64(i) * (^uint64(0) / n)
		hop, err := SelectRelayHopWeighted(ops, target, seed, latencyOf)
		if err != nil {
			t.Fatalf("SelectRelayHopWeighted: %v", err)
		}
		counts[hop.RelayID]++
	}
	return counts
}

func TestSelectRelayHopWeighted_BiasesTowardFast(t *testing.T) {
	ops := []selection.Operator{selOp(1, "A"), selOp(2, "B"), selOp(3, "C")} // relays sorted [2,3]
	lat := func(r NodeRef) (float64, bool) {
		switch r.Op {
		case 2:
			return 50, true
		case 3:
			return 5000, true
		}
		return 0, false
	}
	const n = 2000
	counts := sweepWeighted(t, ops, ops[0], lat)
	// Two eligible relays. Without the floor a 100×-faster relay would take ~98%;
	// the uniform-mixing floor caps any relay at ~(1-FLOOR)+FLOOR/n and floors
	// every relay at FLOOR/n — so the slow relay keeps a real share (SPEC § 3f
	// diffusion) and the fast one can't run away.
	capShare := 1 - latencyFloorFraction + latencyFloorFraction/2
	floorShare := latencyFloorFraction / 2
	if counts[2] <= counts[3] {
		t.Errorf("fast relay 2 (%d) should beat slow relay 3 (%d)", counts[2], counts[3])
	}
	if capN := int(capShare*float64(n)) + 1; counts[2] > capN {
		t.Errorf("fast relay 2 not capped by the floor: %d/%d (cap ~%d)", counts[2], n, capN)
	}
	if floorN := int(floorShare*float64(n)) - 1; counts[3] < floorN {
		t.Errorf("slow relay 3 below the floor share: %d/%d (floor ~%d)", counts[3], n, floorN)
	}
}

func TestSelectRelayHopWeighted_ExploresUnknown(t *testing.T) {
	ops := []selection.Operator{selOp(1, "A"), selOp(2, "B"), selOp(3, "C"), selOp(4, "D")} // relays [2,3,4]
	lat := func(r NodeRef) (float64, bool) {
		switch r.Op {
		case 2:
			return 50, true
		case 3:
			return 5000, true
		}
		return 0, false // relay 4: no sample yet
	}
	counts := sweepWeighted(t, ops, ops[0], lat)
	// The unknown relay (median weight) is explored — meaningfully sampled, and
	// ranked between the fast and slow shares.
	if counts[4] < 200 { // ~10% of 2000
		t.Errorf("unknown relay 4 under-explored: %d/2000", counts[4])
	}
	if !(counts[2] > counts[4] && counts[4] > counts[3]) {
		t.Errorf("want fast(2) > unknown(4) > slow(3); got 2=%d 4=%d 3=%d", counts[2], counts[4], counts[3])
	}
}

func TestRandomRelaySeed_Varies(t *testing.T) {
	// Not a strict guarantee, but two reads colliding is astronomically
	// unlikely; this catches a stuck/zeroed source.
	a, b := RandomRelaySeed(), RandomRelaySeed()
	if a == b {
		t.Errorf("two RandomRelaySeed() calls returned the same value %d", a)
	}
}
