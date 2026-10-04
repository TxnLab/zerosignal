/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/inject"
	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/steering"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// TestChainOperatorSource_EnrichPopulatesToolDetails verifies that the
// fetcher's per-operator /v1/zs/details probe populates
// BuiltinTools, MaxToolIters, Models, and ModelCapacities on the
// operator in place, and sets Reachable + LastRefreshAt.
func TestChainOperatorSource_EnrichPopulatesToolDetails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/zs/details" {
			t.Fatalf("path = %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"models":[
				{"id":"gpt-4o-mini","context_window":128000,"max_output_tokens":16384}
			],
			"builtin_tools":[
				{"type":"zs_web_search","name":"zs_web_search","description":"search","parameters":{}},
				{"type":"zs_web_read","name":"zs_web_read","description":"read","parameters":{}}
			],
			"max_tool_iterations":5,
			"min_charge_output_tokens":1000,
			"min_charge_algo_txns":9,
			"min_charge_microusdc":1620
		}`))
	}))
	defer srv.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 2*time.Second),
		DetailsTimeout: 2 * time.Second,
		Log:            discardLogger(),
	}

	ops := []Operator{{ID: 7, BaseURL: srv.URL}}
	source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if !got.Reachable {
		t.Fatalf("Reachable = false, want true")
	}
	if got.LastRefreshAt.IsZero() {
		t.Fatalf("LastRefreshAt not set")
	}
	if len(got.Models) != 1 || got.Models[0] != "gpt-4o-mini" {
		t.Fatalf("Models = %v", got.Models)
	}
	cap, ok := got.ModelCapacities["gpt-4o-mini"]
	if !ok {
		t.Fatalf("ModelCapacities missing gpt-4o-mini")
	}
	if cap.ContextWindow != 128000 || cap.MaxOutputTokens != 16384 {
		t.Fatalf("ModelCapacity = %+v", cap)
	}
	if len(got.BuiltinTools) != 2 {
		t.Fatalf("BuiltinTools len = %d, want 2", len(got.BuiltinTools))
	}
	if !got.SupportsBuiltinTool("zs_web_search") || !got.SupportsBuiltinTool("zs_web_read") {
		t.Fatalf("SupportsBuiltinTool lookup failed: %+v", got.BuiltinTools)
	}
	if got.MaxToolIters != 5 {
		t.Fatalf("MaxToolIters = %d, want 5", got.MaxToolIters)
	}
	if got.MinChargeOutputTokens != 1000 || got.MinChargeAlgoTxns != 9 || got.MinChargeMicroUSDC != 1620 {
		t.Fatalf("min-charge fields = (out=%d, algo=%d, µusdc=%d), want (1000, 9, 1620)",
			got.MinChargeOutputTokens, got.MinChargeAlgoTxns, got.MinChargeMicroUSDC)
	}
}

// TestChainOperatorSource_EnrichBoundsConcurrency verifies that enrich caps
// the number of simultaneous per-operator details probes at
// DetailsConcurrency — the guard that keeps a large fleet's probe fan-out
// from opening a socket per node at once and blowing the refresh timeout.
func TestChainOperatorSource_EnrichBoundsConcurrency(t *testing.T) {
	var inflight, maxInflight atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inflight.Add(1)
		for { // record the high-water mark of concurrent in-flight probes
			m := maxInflight.Load()
			if n <= m || maxInflight.CompareAndSwap(m, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond) // hold the slot so probes overlap
		inflight.Add(-1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[]}`))
	}))
	defer srv.Close()

	const limit = 8
	source := &ChainOperatorSource{
		Details:            NewDetailsClient(srv.Client(), 2*time.Second),
		DetailsTimeout:     2 * time.Second,
		DetailsConcurrency: limit,
		Log:                discardLogger(),
	}

	ops := make([]Operator, 100)
	for i := range ops {
		ops[i] = Operator{ID: uint64(i + 1), BaseURL: srv.URL}
	}
	source.enrich(context.Background(), ops, nil)

	if got := maxInflight.Load(); got > limit {
		t.Fatalf("max concurrent probes = %d, want <= %d (cap not enforced)", got, limit)
	}
	if got := maxInflight.Load(); got < 2 {
		t.Fatalf("max concurrent probes = %d; test never exercised overlap", got)
	}
}

// TestChainOperatorSource_EnrichProbeFailureMarksUnreachable verifies
// that a per-operator details probe failure sets Reachable=false and
// LastRefreshAt, but does NOT mutate capability fields — that's the
// hook the registry's carry-forward logic depends on.
func TestChainOperatorSource_EnrichProbeFailureMarksUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 500*time.Millisecond),
		DetailsTimeout: 500 * time.Millisecond,
		Log:            discardLogger(),
	}

	// Seed the operator with existing capability data — enrich must
	// NOT clobber it on probe failure. The registry's
	// carryForwardLastGood does the merge; enrich just leaves things
	// alone for it to see.
	ops := []Operator{{
		ID:           7,
		BaseURL:      srv.URL,
		Models:       []string{"existing"},
		BuiltinTools: []BuiltinToolDef{{Type: "zs_web_search"}},
		MaxToolIters: 3,
	}}
	source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.Reachable {
		t.Fatalf("Reachable = true, want false on 500")
	}
	if got.LastRefreshAt.IsZero() {
		t.Fatalf("LastRefreshAt not set even on failure")
	}
	if len(got.Models) != 1 || got.Models[0] != "existing" {
		t.Fatalf("Models clobbered on failure: %v", got.Models)
	}
	if len(got.BuiltinTools) != 1 || got.BuiltinTools[0].Type != "zs_web_search" {
		t.Fatalf("BuiltinTools clobbered on failure: %v", got.BuiltinTools)
	}
	if got.MaxToolIters != 3 {
		t.Fatalf("MaxToolIters clobbered: %d", got.MaxToolIters)
	}
}

// TestEnrich_RelayHopDownDoesNotPenalizeTarget is the regression for the field
// report: in privacy mode, a target's details probe routes through a relay, and
// when that relay hop is itself unreachable the *target* must NOT be marked
// unreachable (its status is simply unknown this cycle). Here T (id 1) is
// reachable only via relay R (id 2), and R is down — so T's probe can't get
// through. R, in turn, is probed via relay T, whose endpoint reports it
// couldn't reach R (relay_upstream_unreachable), a genuine target-down signal,
// so R is correctly marked down.
func TestEnrich_RelayHopDownDoesNotPenalizeTarget(t *testing.T) {
	// T's relay endpoint: always answers the relayed probe of R with
	// "upstream unreachable" (R is down behind it).
	relayT := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"type":"proxy_error","code":"` + protorelay.CodeUpstreamUnreachable + `","message":"down"}}`))
	}))
	defer relayT.Close()

	// R's relay endpoint, but R is dead: start then close so the address
	// refuses connections — a guaranteed-dead relay hop.
	relayR := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadRelayURL := relayR.URL
	relayR.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(nil, 500*time.Millisecond),
		DetailsTimeout: 500 * time.Millisecond,
		Privacy:        true,
		Log:            discardLogger(),
	}
	// Both known-reachable last cycle, so each is an eligible relay for the other.
	source.recordReachable(NodeRef{Op: 1}, true)
	source.recordReachable(NodeRef{Op: 2}, true)

	ops := []Operator{
		{ID: 1, OwnerAddr: "A", BaseURL: relayT.URL, Reachable: true},
		{ID: 2, OwnerAddr: "B", BaseURL: deadRelayURL, Reachable: true},
	}
	source.enrich(context.Background(), ops, nil)

	if !ops[0].Reachable {
		t.Fatalf("target T marked unreachable when only its relay was down")
	}
	if !source.recallReachable(NodeRef{Op: 1}) {
		t.Fatalf("target T reachability hint was overwritten; want left true")
	}
	if ops[1].Reachable {
		t.Fatalf("R should be unreachable (relay reported upstream_unreachable)")
	}
	if source.recallReachable(NodeRef{Op: 2}) {
		t.Fatalf("R reachability hint should be false")
	}
}

// TestProbeOne_CodelessRelayFrontDoorDoesNotBenchTarget is the regression pin
// for the outage this work came from.
//
// A relay whose CDN / ingress answers a code-less 504 used to be indistinguishable
// from the TARGET's gateway doing the same, so probeOne took the "target-side
// failure" branch: it set op.Reachable = false on a perfectly healthy node and
// recorded it unreachable, which dropped that node out of advertisable() and
// therefore out of /v1/models — while the relay that actually broke kept a
// spotless streak and got re-drawn at full weight next cycle. One dead relay
// could quietly evict healthy nodes from discovery for hours.
//
// With the 9.1 marker the probe can tell the two apart, so this must now land
// on the hop-error branch: target untouched, relay charged.
func TestProbeOne_CodelessRelayFrontDoorDoesNotBenchTarget(t *testing.T) {
	// A healthy target, only ever reached THROUGH a relay in privacy mode.
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"id":"gpt-4o-mini","context_window":8192}]}`))
	}))
	defer target.Close()

	// The broken relay: its front door answers an HTML 504 with no protocol
	// code and — crucially — no hop marker, even though it advertises 9.1.
	var frontDoorHits atomic.Int32
	badRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		frontDoorHits.Add(1)
		w.Header().Set("Content-Type", "text/html")
		// 502 = could-not-connect, so the marker rule can decide. A 504 would be
		// an ambiguous gateway TIMEOUT (the relay may be waiting on a slow
		// target) and must charge nobody — see the details_test table.
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`<html><body>502 Bad Gateway</body></html>`))
	}))
	defer badRelay.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(nil, 500*time.Millisecond),
		DetailsTimeout: 500 * time.Millisecond,
		Privacy:        true,
		Log:            discardLogger(),
	}

	// Only ONE eligible relay for the target, so every probe attempt must go
	// through the broken one — no rotation can rescue this and mask the bug.
	op := Operator{
		ID: 1, NodeID: 1, OwnerAddr: "A", BaseURL: target.URL,
		ProtoVersion: wire.ProtoVersion, Reachable: true,
	}
	relay := Operator{
		ID: 2, NodeID: 1, OwnerAddr: "B", BaseURL: badRelay.URL,
		ProtoVersion: wire.ProtoVersion, Reachable: true,
	}
	source.recordReachable(RefOf(op), true)
	source.recordReachable(RefOf(relay), true)

	selAll := []selection.Operator{op.Selection(), relay.Selection()}
	now := time.Now()
	source.probeOne(context.Background(), source.Details, nil, selAll, &op, now, discardLogger())

	if frontDoorHits.Load() == 0 {
		t.Fatal("the probe never went through the broken relay; the fixture isn't exercising the path")
	}
	if !op.Reachable {
		t.Error("healthy TARGET was marked unreachable because its RELAY's front door 502'd — " +
			"this is the mis-attribution that evicted good nodes from discovery")
	}
	if !source.recallReachable(RefOf(op)) {
		t.Error("target's cross-cycle reachability hint was flipped false by a relay-side failure")
	}
	// And the party that actually broke is the one charged.
	if source.recallReachable(RefOf(relay)) {
		t.Error("the relay whose front door answered was not recorded unreachable")
	}
	if !source.RelayDownranked(RefOf(relay)) && frontDoorHits.Load() < steering.RelayDownrankThreshold {
		// Fewer attempts than the threshold is fine; assert at least one strike.
		if _, streak := source.relayFailStreak[RefOf(relay)]; !streak {
			t.Error("the broken relay accrued no forward-failure streak")
		}
	}
}

// TestBuildSelAll_SeedsBootstrapNotCurrentVersion pins the seeding trap. An
// UNPROBED peer gets a provisional proto_version so cold-start relay selection
// can bootstrap (privacy mode needs a relay to run the probe that learns the
// real one). That seed must keep the peer relay-ELIGIBLE while never implying a
// minor-gated CAPABILITY it has not demonstrated: seeding the full
// wire.ProtoVersion would make every never-probed relay read as hop-marker
// capable, and its first code-less 5xx would be charged to it for omitting a
// header nobody had established it could set.
func TestBuildSelAll_SeedsBootstrapNotCurrentVersion(t *testing.T) {
	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	// ProtoVersion empty = never probed.
	ops := []Operator{{ID: 1, NodeID: 1, OwnerAddr: "A", BaseURL: "https://a.example"}}

	sel := source.buildSelAll(ops)
	if len(sel) != 1 {
		t.Fatalf("buildSelAll returned %d entries, want 1", len(sel))
	}
	got := sel[0].ProtoVersion
	if got != wire.BootstrapProtoVersion() {
		t.Fatalf("seeded proto_version = %q, want %q", got, wire.BootstrapProtoVersion())
	}
	if !wire.ProtoVersionCompatible(got) {
		t.Errorf("seed %q is not relay-eligible; cold start would deadlock", got)
	}
	if wire.SetsRelayHopHeader(got) {
		t.Errorf("seed %q implies hop-marker support; a never-probed node cannot owe us a header", got)
	}
}

// TestProbeDetailsWithRetry_RotatesPastDeadRelay verifies the retry: a dead
// relay hop is skipped (and recorded down), and the probe re-rotates to another
// eligible relay and succeeds rather than failing the whole probe.
func TestProbeDetailsWithRetry_RotatesPastDeadRelay(t *testing.T) {
	upRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"id":"gpt-4o-mini","context_window":8192}]}`))
	}))
	defer upRelay.Close()

	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	client := NewDetailsClient(nil, time.Second)

	target := Operator{ID: 1, OwnerAddr: "A", BaseURL: "https://target.example:9000"}
	selAll := []selection.Operator{
		{ID: 1, OwnerAddr: "A", BaseURL: target.BaseURL, ProtoVersion: wire.ProtoVersion, Reachable: true},
		{ID: 2, OwnerAddr: "B", BaseURL: deadURL, ProtoVersion: wire.ProtoVersion, Reachable: true},
		{ID: 3, OwnerAddr: "C", BaseURL: upRelay.URL, ProtoVersion: wire.ProtoVersion, Reachable: true},
	}

	resp, hop, err := source.probeDetailsWithRetry(context.Background(), client, selAll, target, discardLogger())
	if err != nil {
		t.Fatalf("expected success after rotating past dead relay, got %v", err)
	}
	if hop == nil || hop.RelayID != 3 {
		t.Fatalf("expected success via relay id 3, got hop %+v", hop)
	}
	if len(resp.Models) != 1 || resp.Models[0].ID != "gpt-4o-mini" {
		t.Fatalf("models = %+v", resp.Models)
	}
}

// upstreamUnreachableRelay answers every relayed probe with the relay's claim
// that the target is down.
func upstreamUnreachableRelay(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(wire.RelayHopHeader, wire.RelayHopHeaderValue)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"type":"proxy_error","code":"` + protorelay.CodeUpstreamUnreachable + `","message":"down"}}`))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// relayProbeFixture is a target only ever probed through the given relays, each
// eligible and of a distinct owner.
func relayProbeFixture(relayURLs ...string) (Operator, []selection.Operator) {
	target := Operator{ID: 1, OwnerAddr: "A", BaseURL: "https://target.example:9000"}
	selAll := []selection.Operator{
		{ID: 1, OwnerAddr: "A", BaseURL: target.BaseURL, ProtoVersion: wire.ProtoVersion, Reachable: true},
	}
	for i, u := range relayURLs {
		selAll = append(selAll, selection.Operator{
			ID: uint64(i + 2), OwnerAddr: string(rune('B' + i)), BaseURL: u,
			ProtoVersion: wire.ProtoVersion, Reachable: true,
		})
	}
	return target, selAll
}

// One relay's view of the target is not proof it is down: the probe rotates to
// a relay that reaches it. The claim, contradicted by the target having been
// seen up, counts against the relay that made it; the relay is not marked
// unreachable, since it answered.
func TestProbeDetailsWithRetry_RotatesPastUpstreamUnreachable(t *testing.T) {
	upRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"models":[{"id":"m"}]}`))
	}))
	defer upRelay.Close()
	claims := upstreamUnreachableRelay(t)

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(claims.URL, upRelay.URL)
	source.recordReachable(RefOf(target), true)
	claimer := NodeRef{Op: 2}
	source.recordReachable(claimer, true)

	// The pick is weighted-random, so run until the claiming relay was tried
	// first at least once.
	for i := 0; i < 50 && source.relayFailStreak[claimer].Count == 0; i++ {
		resp, hop, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
		if err != nil {
			t.Fatalf("probe failed with a relay that reaches the target: %v", err)
		}
		if hop == nil || hop.RelayID != 3 || len(resp.Models) != 1 {
			t.Fatalf("hop %+v, models %+v: want the details through relay 3", hop, resp.Models)
		}
	}
	if source.relayFailStreak[claimer].Count == 0 {
		t.Fatal("a contradicted relay_upstream_unreachable claim left the relay's streak clean")
	}
	if !source.recallReachable(claimer) {
		t.Error("a relay that answered was recorded unreachable")
	}
}

// When every relay that worked said the target is down, the target is down:
// the probe returns the relay's claim as a target-side error, not a hop error,
// even when a dead relay was tried too.
func TestProbeDetailsWithRetry_EveryWorkingRelaySaysDown(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	for _, relays := range [][]string{
		{upstreamUnreachableRelay(t).URL, upstreamUnreachableRelay(t).URL},
		{upstreamUnreachableRelay(t).URL, deadURL},
	} {
		// The pick is weighted-random; enough runs try the dead relay both
		// first and last, so the claim must win whichever came last.
		for range 20 {
			source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
			target, selAll := relayProbeFixture(relays...)
			_, hop, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
			var upErr *RelayUpstreamUnreachableError
			if !errors.As(err, &upErr) {
				t.Fatalf("relays %v: err = %v, want the relay's upstream claim", relays, err)
			}
			if hop == nil || hop.RelayID != upErr.RelayID {
				t.Errorf("hop %+v, want the relay that made the claim (%d)", hop, upErr.RelayID)
			}
		}

		source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
		target, selAll := relayProbeFixture(relays...)
		op := target
		source.probeOne(context.Background(), NewDetailsClient(nil, time.Second), nil, selAll, &op, time.Now(), discardLogger())
		if op.Reachable || !op.Probed {
			t.Errorf("relays %v: Reachable %v Probed %v, want the target recorded down", relays, op.Reachable, op.Probed)
		}
	}
}

// A lone claim no other relay could check is judged by our last view of the
// target: about a target already seen down it is credited.
func TestProbeDetailsWithRetry_LoneClaimAboutADownTargetIsCredited(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := dead.URL
	dead.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(upstreamUnreachableRelay(t).URL, deadURL)
	source.recordReachable(RefOf(target), false)
	claimer := NodeRef{Op: 2}
	source.RecordRelayOutcome(claimer, false)

	_, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
	if upErr := (*RelayUpstreamUnreachableError)(nil); !errors.As(err, &upErr) {
		t.Fatalf("err = %v, want the relay's upstream claim", err)
	}
	if _, streak := source.relayFailStreak[claimer]; streak {
		t.Error("a claim about a target already seen down kept the relay's strike")
	}
}

// Relays that agree the target is down back each other up, even when our last
// view had it up: it has just gone down, and none of them lied.
func TestProbeDetailsWithRetry_AgreeingClaimsAreNotCharged(t *testing.T) {
	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(upstreamUnreachableRelay(t).URL, upstreamUnreachableRelay(t).URL)
	source.recordReachable(RefOf(target), true)

	_, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
	if upErr := (*RelayUpstreamUnreachableError)(nil); !errors.As(err, &upErr) {
		t.Fatalf("err = %v, want the relays' upstream claim", err)
	}
	for _, r := range []NodeRef{{Op: 2}, {Op: 3}} {
		if _, streak := source.relayFailStreak[r]; streak {
			t.Errorf("relay %v was charged for a claim another relay corroborated", r)
		}
	}
}

// A claim another relay disproves in the same probe is charged, whatever our
// last view of the target said.
func TestProbeDetailsWithRetry_ClaimDisprovedInTheProbeIsCharged(t *testing.T) {
	upRelay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"models":[{"id":"m"}]}`))
	}))
	defer upRelay.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(upstreamUnreachableRelay(t).URL, upRelay.URL)
	claimer := NodeRef{Op: 2}

	for i := 0; i < 50 && source.relayFailStreak[claimer].Count == 0; i++ {
		source.recordReachable(RefOf(target), false)
		if _, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger()); err != nil {
			t.Fatalf("probe failed with a relay that reaches the target: %v", err)
		}
	}
	if source.relayFailStreak[claimer].Count == 0 {
		t.Fatal("a claim another relay disproved in the same probe was not charged")
	}
}

// claimThenCancel answers each request with a relay's upstream claim and
// cancels the probe's context as it does, or with the context's error once
// cancelled.
type claimThenCancel struct{ cancel context.CancelFunc }

func (c claimThenCancel) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	c.cancel()
	return &http.Response{
		StatusCode: http.StatusBadGateway,
		Status:     "502 Bad Gateway",
		Header:     http.Header{wire.RelayHopHeader: {wire.RelayHopHeaderValue}},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"` + protorelay.CodeUpstreamUnreachable + `"}}`)),
		Request:    req,
	}, nil
}

// A probe cancelled after one relay's claim never heard the others, so the
// claim is not the verdict of every working relay: the target stays as it was.
func TestProbeOne_CancelAfterAClaimLeavesTheTarget(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewDetailsClient(&http.Client{Transport: claimThenCancel{cancel}}, time.Second)

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture("http://relay-b.example", "http://relay-c.example")
	target.Reachable = true
	source.recordReachable(RefOf(target), true)

	_, _, err := source.probeDetailsWithRetry(ctx, client, selAll, target, discardLogger())
	if upErr := (*RelayUpstreamUnreachableError)(nil); errors.As(err, &upErr) {
		t.Fatalf("a cancelled probe returned a relay's claim as the target's failure: %v", err)
	}

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	client = NewDetailsClient(&http.Client{Transport: claimThenCancel{cancel}}, time.Second)
	op := target
	source.probeOne(ctx, client, nil, selAll, &op, time.Now(), discardLogger())
	if !op.Reachable || op.Probed || !source.recallReachable(RefOf(target)) {
		t.Errorf("Reachable %v Probed %v recall %v: a cancelled probe changed the target",
			op.Reachable, op.Probed, source.recallReachable(RefOf(target)))
	}
}

// Cancelled after the only relay's claim, with no relay left to try: the probe
// returns the cancel, not the claim and not a hop.
func TestProbeDetailsWithRetry_CancelAfterTheOnlyClaimReturnsTheCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	client := NewDetailsClient(&http.Client{Transport: claimThenCancel{cancel}}, time.Second)
	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture("http://relay-b.example")

	_, hop, err := source.probeDetailsWithRetry(ctx, client, selAll, target, discardLogger())
	if !errors.Is(err, context.Canceled) || hop != nil {
		t.Fatalf("err %v hop %+v, want context.Canceled and no hop", err, hop)
	}
}

// A cancelled direct probe learned nothing about the target either.
func TestProbeOne_CancelledDirectProbeLeavesTheTarget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	source := &ChainOperatorSource{Log: discardLogger()}
	op := Operator{ID: 1, OwnerAddr: "A", BaseURL: srv.URL, Reachable: true}
	source.recordReachable(RefOf(op), true)
	source.probeOne(ctx, NewDetailsClient(nil, time.Second), nil, nil, &op, time.Now(), discardLogger())
	if !op.Reachable || op.Probed || !source.recallReachable(RefOf(op)) {
		t.Errorf("Reachable %v Probed %v: a cancelled direct probe changed the target", op.Reachable, op.Probed)
	}
}

// A relay that claimed the target down is not asked again in the same probe:
// asked again, it would back up its own claim, and could spend every attempt.
// Alone and about a target last seen up, its claim is charged once.
func TestProbeDetailsWithRetry_AClaimingRelayIsAskedOnce(t *testing.T) {
	var hits atomic.Int32
	claim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set(wire.RelayHopHeader, wire.RelayHopHeaderValue)
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"code":"` + protorelay.CodeUpstreamUnreachable + `"}}`))
	}))
	defer claim.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(claim.URL)
	source.recordReachable(RefOf(target), true)

	_, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
	if upErr := (*RelayUpstreamUnreachableError)(nil); !errors.As(err, &upErr) {
		t.Fatalf("err = %v, want the relay's claim", err)
	}
	if hits.Load() != 1 {
		t.Errorf("the claiming relay was asked %d times, want 1", hits.Load())
	}
	if got := source.relayFailStreak[NodeRef{Op: 2}].Count; got != 1 {
		t.Errorf("streak = %d, want 1: a lone claim about a target seen up is charged", got)
	}
}

// The target's own error status, forwarded by another relay, disproves a claim
// that it was unreachable, whatever our last view of it.
func TestProbeDetailsWithRetry_TargetStatusDisprovesAClaim(t *testing.T) {
	forwards404 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(wire.RelayHopHeader, wire.RelayHopHeaderValue)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer forwards404.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(upstreamUnreachableRelay(t).URL, forwards404.URL)
	claimer := NodeRef{Op: 2}
	for i := 0; i < 50 && source.relayFailStreak[claimer].Count == 0; i++ {
		source.recordReachable(RefOf(target), false)
		_, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
		if upErr := (*RelayUpstreamUnreachableError)(nil); errors.As(err, &upErr) {
			t.Fatalf("a relay reached the target, yet the probe returned the claim: %v", err)
		}
	}
	if source.relayFailStreak[claimer].Count == 0 {
		t.Fatal("a claim the target's own status disproved was not charged")
	}
}

// A 2xx whose body breaks off (not by our deadline) is still a 2xx the relay
// forwarded: the relay is credited and the target's body is at fault.
func TestProbeDetailsWithRetry_BrokenBodyCreditsTheRelay(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1000")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"models":[`))
		w.(http.Flusher).Flush()
		conn, _, err := w.(http.Hijacker).Hijack()
		if err == nil {
			_ = conn.Close()
		}
	}))
	defer relay.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(relay.URL)
	ref := NodeRef{Op: 2}
	source.RecordRelayOutcome(ref, false)

	_, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
	if bodyErr := (*DetailsBodyError)(nil); !errors.As(err, &bodyErr) {
		t.Fatalf("err = %v, want a body error", err)
	}
	if _, streak := source.relayFailStreak[ref]; streak {
		t.Error("the relay that forwarded the 2xx kept its failure streak")
	}
	if _, ok := source.RelayLatencyForTarget(ref, RefOf(target)); !ok {
		t.Error("the relay that forwarded the 2xx got no round-trip sample")
	}
}

// cancelThenBusy cancels the probe's context as the relay answers relay_busy.
type cancelThenBusy struct{ cancel context.CancelFunc }

func (c cancelThenBusy) RoundTrip(req *http.Request) (*http.Response, error) {
	c.cancel()
	return &http.Response{
		StatusCode: http.StatusServiceUnavailable,
		Status:     "503 Service Unavailable",
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader(`{"error":{"code":"` + protorelay.CodeBusy + `"}}`)),
		Request:    req,
	}, nil
}

// A relay code read in full outranks a cancel that lands after it: the relay
// said it failed, so it is charged.
func TestDetails_ARelayCodeOutranksALateCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hop := &RelayHop{BaseURL: "http://relay.example", TargetID: 3, RelayID: 9}
	_, err := NewDetailsClient(&http.Client{Transport: cancelThenBusy{cancel}}, time.Second).
		Fetch(ctx, "https://target.example:9000", hop)
	var hopErr *RelayHopError
	if !errors.As(err, &hopErr) || hopErr.CallerAborted {
		t.Fatalf("err = %v, want a chargeable RelayHopError", err)
	}
}

// The probe's own deadline charges no relay (SPEC § 10): a relay is silent
// while it waits on a slow target, so a timeout says nothing about it. The
// relay is skipped for this probe, and the target's status is unknown.
func TestProbeDetailsWithRetry_OwnDeadlineChargesNoRelay(t *testing.T) {
	release := make(chan struct{})
	var hits [2]atomic.Int32
	slow := func(i int) string {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[i].Add(1)
			select {
			case <-release:
			case <-r.Context().Done():
			}
		}))
		t.Cleanup(srv.Close)
		return srv.URL
	}
	relays := []string{slow(0), slow(1)}
	defer close(release)

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(relays...)
	for _, r := range []NodeRef{{Op: 2}, {Op: 3}} {
		source.recordReachable(r, true)
	}

	_, _, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, 50*time.Millisecond), selAll, target, discardLogger())
	var hopErr *RelayHopError
	if !errors.As(err, &hopErr) || !hopErr.CallerAborted {
		t.Fatalf("err = %v, want a RelayHopError marked CallerAborted", err)
	}
	if hits[0].Load() == 0 || hits[1].Load() == 0 {
		t.Errorf("hits %d/%d: a timed-out relay must be rotated past, not end the probe", hits[0].Load(), hits[1].Load())
	}
	for _, r := range []NodeRef{{Op: 2}, {Op: 3}} {
		if !source.recallReachable(r) {
			t.Errorf("the probe's own timeout recorded relay %v unreachable", r)
		}
		if _, streak := source.relayFailStreak[r]; streak {
			t.Errorf("the probe's own timeout charged relay %v a strike", r)
		}
	}
}

// A 2xx the target sent through a relay credits the relay even when the body
// won't decode: the relay forwarded it.
func TestProbeDetailsWithRetry_BadBodyCreditsTheRelay(t *testing.T) {
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`not json`))
	}))
	defer relay.Close()

	source := &ChainOperatorSource{Privacy: true, Log: discardLogger()}
	target, selAll := relayProbeFixture(relay.URL)
	ref := NodeRef{Op: 2}
	source.RecordRelayOutcome(ref, false)

	_, hop, err := source.probeDetailsWithRetry(context.Background(), NewDetailsClient(nil, time.Second), selAll, target, discardLogger())
	var bodyErr *DetailsBodyError
	if !errors.As(err, &bodyErr) || hop == nil {
		t.Fatalf("err %v hop %+v, want a body error through the relay", err, hop)
	}
	if _, streak := source.relayFailStreak[ref]; streak {
		t.Error("the relay that forwarded the 2xx kept its failure streak")
	}
	if _, ok := source.RelayLatencyForTarget(ref, RefOf(target)); !ok {
		t.Error("the relay that forwarded the 2xx got no round-trip sample")
	}
}

// newTEEEnrichFixture builds an Operator + stub node server wired for the
// enrich() path: a real Algorand signing keypair, a signed ephemeral
// advertisement served on /v1/zs/details, and an attestation bundle bound to
// that same ephemeral recipient. Returns the operator with its on-chain fields
// (SigningAddr / TicketSigningKey / BaseURL) populated the way
// ResolveOperatorRecords would.
//
// advertiseTEE defaults to true; pass boolPtr(false) for the
// "operator does not advertise TEE" case.
func newTEEEnrichFixture(t *testing.T, operatorID uint64, advertiseTEE *bool) (Operator, *httptest.Server) {
	t.Helper()
	signingAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatalf("generate signing keypair: %v", err)
	}
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate age identity: %v", err)
	}
	adv := signEphemeralAdv(t, signingAddr, priv, operatorID, testEnrichNodeID,
		ageID.Recipient().String(), time.Now().Add(5*time.Minute).Unix())

	advertise := true
	if advertiseTEE != nil {
		advertise = *advertiseTEE
	}
	srv := teeStubServer(t, operatorID, adv, advertise, nil)
	return Operator{
		ID:               operatorID,
		NodeID:           testEnrichNodeID,
		BaseURL:          srv.URL,
		SigningAddr:      signingAddr,
		TicketSigningKey: pub,
	}, srv
}

func boolPtr(b bool) *bool { return &b }

// teeStubServer returns an httptest server that serves /v1/zs/details
// (with optional TEE advertisement plus the node's signed ephemeral
// advertisement) and /v1/zs/attestation (matching stub bundle).
//
// adv is load-bearing, not fixture noise: the TEE key-binding target is the
// node's ephemeral age recipient, and enrich() populates that from the signed
// advertisement (applyEphemeralAdvertisement) immediately before probing
// attestation. Without a verifiable ephemeral there is nothing to bind to and
// the verifier fails closed — so the bundle's NodePubkey must equal
// adv.AgePubkey for the happy path.
func teeStubServer(t *testing.T, operatorID uint64, adv ticket.EphemeralAdvertisement, advertiseTEE bool, mutateBundle func(*inject.TEEEvidenceBundle)) *httptest.Server {
	t.Helper()
	nodePubkey := adv.AgePubkey
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/zs/details":
			details := inject.OperatorDetails{
				Models: []inject.OperatorDetailsModel{
					{ID: "gpt-4o-mini", ContextWindow: 8192},
				},
				EphemeralAgePubkey: adv.AgePubkey,
				EphemeralExpiry:    adv.Expiry,
				EphemeralIssuedAt:  adv.IssuedAt,
				EphemeralSig:       adv.Sig,
			}
			if advertiseTEE {
				details.TEE = &inject.TEEAdvertisement{
					Mode:        inject.TEEModeStub,
					AttestedAt:  time.Now().UTC(),
					EvidenceURL: "/v1/zs/attestation",
				}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(details)
		case "/v1/zs/attestation":
			b := stubBundleFor(nodePubkey, operatorID)
			if mutateBundle != nil {
				mutateBundle(&b)
			}
			w.Header().Set("Content-Type", inject.AttestationContentType)
			_ = json.NewEncoder(w).Encode(b)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestEnrich_TEEAdvertisedAndVerified(t *testing.T) {
	op, srv := newTEEEnrichFixture(t, 7, nil)
	defer srv.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 2*time.Second),
		Attestation:    NewAttestationClient(srv.Client(), 2*time.Second),
		TEEVerifier:    &tee.BundleVerifier{AllowStub: true},
		DetailsTimeout: 2 * time.Second,
		Log:            discardLogger(),
	}
	ops := []Operator{op}
	source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.TEE == nil {
		t.Fatalf("TEE advertisement present but op.TEE is nil")
	}
	if !got.TEE.Verified {
		t.Errorf("Verified = false; FailureTag = %q", got.TEE.FailureTag)
	}
	if got.TEE.Mode != inject.TEEModeStub {
		t.Errorf("Mode = %q, want %q", got.TEE.Mode, inject.TEEModeStub)
	}
	if got.TEE.VerifierID != tee.VerifierIDBuiltin {
		t.Errorf("VerifierID = %q, want %q", got.TEE.VerifierID, tee.VerifierIDBuiltin)
	}
	if !got.IsTEEAttested() {
		t.Errorf("IsTEEAttested should be true after successful verification")
	}
}

func TestEnrich_TEEStubRejectedWhenAllowStubFalse(t *testing.T) {
	op, srv := newTEEEnrichFixture(t, 7, nil)
	defer srv.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 2*time.Second),
		Attestation:    NewAttestationClient(srv.Client(), 2*time.Second),
		TEEVerifier:    &tee.BundleVerifier{AllowStub: false}, // production posture
		DetailsTimeout: 2 * time.Second,
		Log:            discardLogger(),
	}
	ops := []Operator{op}
	source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.TEE == nil {
		t.Fatalf("TEE status should be populated even on failure (for diagnostics)")
	}
	if got.TEE.Verified {
		t.Errorf("Verified = true with AllowStub=false")
	}
	if got.TEE.FailureTag != tee.FailureStubNotAllowed {
		t.Errorf("FailureTag = %q, want %q", got.TEE.FailureTag, tee.FailureStubNotAllowed)
	}
	if got.IsTEEAttested() {
		t.Errorf("IsTEEAttested should be false when verification fails")
	}
}

func TestEnrich_TEEMissingAdvertisement(t *testing.T) {
	op, srv := newTEEEnrichFixture(t, 7, boolPtr(false)) // does NOT advertise TEE
	defer srv.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 2*time.Second),
		Attestation:    NewAttestationClient(srv.Client(), 2*time.Second),
		TEEVerifier:    &tee.BundleVerifier{AllowStub: true},
		DetailsTimeout: 2 * time.Second,
		Log:            discardLogger(),
	}
	ops := []Operator{op}
	source.enrich(context.Background(), ops, nil)

	if ops[0].TEE != nil {
		t.Errorf("TEE should be nil when operator does not advertise; got %+v", ops[0].TEE)
	}
	if ops[0].IsTEEAttested() {
		t.Errorf("IsTEEAttested should be false when operator does not advertise")
	}
}

func TestEnrich_TEEFetchFailureCapturedInStatus(t *testing.T) {
	// /v1/zs/details advertises TEE but /v1/zs/attestation
	// returns 503. The fetcher should populate op.TEE with
	// FailureFetchFailed and not crash.
	op, _ := testOperatorAndPubkey(t, 7)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/zs/details":
			details := inject.OperatorDetails{
				Models: []inject.OperatorDetailsModel{
					{ID: "m1", ContextWindow: 1024},
				},
				TEE: &inject.TEEAdvertisement{
					Mode:        inject.TEEModeStub,
					AttestedAt:  time.Now().UTC(),
					EvidenceURL: "/v1/zs/attestation",
				},
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(details)
		case "/v1/zs/attestation":
			http.Error(w, "down", http.StatusServiceUnavailable)
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
	}))
	defer srv.Close()
	op.BaseURL = srv.URL

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 500*time.Millisecond),
		Attestation:    NewAttestationClient(srv.Client(), 500*time.Millisecond),
		TEEVerifier:    &tee.BundleVerifier{AllowStub: true},
		DetailsTimeout: 500 * time.Millisecond,
		Log:            discardLogger(),
	}
	ops := []Operator{op}
	source.enrich(context.Background(), ops, nil)

	got := ops[0]
	if got.TEE == nil {
		t.Fatalf("TEE should be populated for diagnostics on fetch failure")
	}
	if got.TEE.Verified {
		t.Errorf("Verified = true on fetch failure")
	}
	if got.TEE.FailureTag != tee.FailureFetchFailed {
		t.Errorf("FailureTag = %q, want %q", got.TEE.FailureTag, tee.FailureFetchFailed)
	}
	// Reachable should still be true — only attestation failed,
	// the basic details probe succeeded.
	if !got.Reachable {
		t.Errorf("Reachable should remain true; only attestation failed")
	}
}

func TestEnrich_TEEVerifierNilDisablesTEE(t *testing.T) {
	// When the proxy isn't configured for TEE verification
	// (TEEVerifier nil), an operator that advertises TEE just gets
	// op.TEE = nil — they're treated as not-attested for routing
	// without the proxy attempting any verification.
	op, srv := newTEEEnrichFixture(t, 7, nil)
	defer srv.Close()

	source := &ChainOperatorSource{
		Details:        NewDetailsClient(srv.Client(), 2*time.Second),
		Attestation:    NewAttestationClient(srv.Client(), 2*time.Second),
		TEEVerifier:    nil, // disabled
		DetailsTimeout: 2 * time.Second,
		Log:            discardLogger(),
	}
	ops := []Operator{op}
	source.enrich(context.Background(), ops, nil)

	if ops[0].TEE != nil {
		t.Errorf("TEE should be nil when verifier is disabled; got %+v", ops[0].TEE)
	}
}

// TestResolveOperatorRecords_PopulatesMetrics verifies that the
// on-chain reliability tail of an OperatorRecord is copied verbatim
// onto Operator.Metrics, including the windowed-revenue reads against
// the daily ring and the derived latency mean.
func TestResolveOperatorRecords_PopulatesMetrics(t *testing.T) {
	signingAddr, _, _, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ownerAddr, _, _, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}

	op := escrow.OperatorRecord{
		ID:        9,
		OwnerAddr: ownerAddr,
		Status:    escrow.OperatorStatusActive,
	}
	currentDay := uint64(time.Now().Unix()) / escrow.SecondsPerDay
	node := escrow.NodeRecord{
		OperatorID:  9,
		NodeID:      1,
		SigningAddr: signingAddr,
		BaseURL:     "https://node.example:9090",
		RecordMetrics: escrow.RecordMetrics{
			LastActivityAt:            1_700_000_000,
			TicketsOpened:             100,
			TicketsSettled:            70,
			TicketsLapsedSettled:      5,
			TicketsRefundedInactive:   3,
			TicketsProtested:          2,
			TicketsFrozenDispute:      1,
			TotalRefundedInactiveUsdc: 30_000,
			TotalProtestedUsdc:        15_000,
			TotalFrozenDisputeUsdc:    9_000,
			LatencyTotalMs:            150_000,
			LatencyEwmaMs:             1_800,
			TotalRevenueGross:         1_234_500,
		},
		// Deliberately NOT 70+5: this node also served image-primary settles,
		// which bump the settle counters without folding a TTFT. 150_000/60 =
		// 2500, where the old settle-count denominator would report 2000.
		LatencySamples: 60,
	}
	// Seed today's revenue bucket so all three windows see it.
	node.BucketsLastDay = currentDay
	node.RevenueBuckets[currentDay%escrow.RevenueBucketCount] = 12_000

	o, err := resolveOperatorNode(op, node, currentDay)
	if err != nil {
		t.Fatalf("resolveOperatorNode: %v", err)
	}
	if o.ID != 9 || o.NodeID != 1 {
		t.Errorf("identity = %d/%d, want 9/1", o.ID, o.NodeID)
	}
	m := o.Metrics
	if m.LastActivityAt != 1_700_000_000 {
		t.Errorf("LastActivityAt = %d", m.LastActivityAt)
	}
	if m.TicketsOpened != 100 || m.TicketsSettled != 70 || m.TicketsLapsedSettled != 5 ||
		m.TicketsRefundedInactive != 3 || m.TicketsProtested != 2 || m.TicketsFrozenDispute != 1 {
		t.Errorf("counters wrong: %+v", m)
	}
	if m.TotalRefundedInactiveUsdc != 30_000 || m.TotalProtestedUsdc != 15_000 || m.TotalFrozenDisputeUsdc != 9_000 {
		t.Errorf("dispute exposure wrong: %+v", m)
	}
	if m.LatencyTotalMs != 150_000 || m.LatencyEwmaMs != 1_800 {
		t.Errorf("latency aggregates wrong: %+v", m)
	}
	if m.LatencySamples != 60 {
		t.Errorf("LatencySamples = %d, want 60", m.LatencySamples)
	}
	// 150_000 / 60 samples. Dividing by the 75-settle population gives 2000 —
	// the understatement latencySamples exists to fix.
	if got := m.LatencyMeanMs(); got != 2_500 {
		t.Errorf("LatencyMeanMs() = %d, want 2500", got)
	}
	if m.TotalRevenueGross != 1_234_500 {
		t.Errorf("revenue wrong: %+v", m)
	}
	// 30d / 7d windows include any slot inside their span; immune to a
	// midnight day-flip between the seed above and the read. 24h is exact in practice.
	if m.Revenue30dUsdc != 12_000 || m.Revenue7dUsdc != 12_000 {
		t.Errorf("windowed revenue wrong: 24h=%d 7d=%d 30d=%d", m.Revenue24hUsdc, m.Revenue7dUsdc, m.Revenue30dUsdc)
	}

	// A zero-valued node (fresh node) yields a zero metrics block.
	node0 := escrow.NodeRecord{
		OperatorID: 10, NodeID: 1, SigningAddr: signingAddr,
		BaseURL: "https://fresh.example",
	}
	o0, err := resolveOperatorNode(escrow.OperatorRecord{ID: 10, OwnerAddr: ownerAddr, Status: escrow.OperatorStatusActive}, node0, currentDay)
	if err != nil {
		t.Fatalf("resolveOperatorNode(zero): %v", err)
	}
	if got := o0.Metrics; got != (OperatorMetrics{}) {
		t.Errorf("fresh node metrics non-zero: %+v", got)
	}
}

// stubVerifier hands probeAttestation a fixed verdict and keeps the node it was
// asked about, so the test is about the plumbing on either side of Verify
// rather than about verification.
type stubVerifier struct {
	v   tee.Verdict
	got *tee.Node
}

func (s stubVerifier) Verify(_ context.Context, _ inject.TEEAdvertisement, _ inject.TEEEvidenceBundle, node tee.Node) tee.Verdict {
	*s.got = node
	return s.v
}

// Pins the two hand-offs in probeAttestation: the operator's identity into the
// verifier (the key binding checks against it), and the verified list back onto
// TEEStatus. Every other test builds a TEEStatus literal by hand, so nulling
// either line leaves them green.
func TestProbeAttestation_HandsOffToAndFromTheVerifier(t *testing.T) {
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", inject.AttestationContentType)
		_ = json.NewEncoder(w).Encode(inject.TEEEvidenceBundle{Mode: inject.TEEModeDstackTDX})
	}))
	defer node.Close()

	var asked tee.Node
	src := &ChainOperatorSource{TEEVerifier: stubVerifier{v: tee.Verdict{
		Pass:             true,
		VerifierID:       tee.VerifierIDDstack,
		AttestedModelIDs: []string{"qwen3-30b"},
	}, got: &asked}}
	op := &Operator{ID: 7, NodeID: 3, BaseURL: node.URL, EphemeralRecipientPubkey: "age1recipient"}
	details := inject.OperatorDetails{TEE: &inject.TEEAdvertisement{
		Mode: inject.TEEModeDstackTDX, EvidenceURL: "/v1/zs/attestation",
	}}

	src.probeAttestation(context.Background(), op, details,
		NewAttestationClient(nil, 0), nil, discardLogger())

	if want := (tee.Node{OperatorID: 7, NodeID: 3, EphemeralRecipientPubkey: "age1recipient"}); asked != want {
		t.Errorf("the verifier was asked about %+v, want %+v", asked, want)
	}
	if op.TEE == nil {
		t.Fatal("probeAttestation left op.TEE nil on a passing verdict")
	}
	if !slices.Equal(op.TEE.AttestedModelIDs, []string{"qwen3-30b"}) {
		t.Errorf("the verified model list did not reach TEEStatus: %+v", op.TEE.AttestedModelIDs)
	}
}

// Ensure printing the TEE struct in test failure messages works.
var _ = fmt.Sprintf("%+v", TEEStatus{})
