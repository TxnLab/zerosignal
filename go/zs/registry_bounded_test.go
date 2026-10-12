/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// boundedFakeSource implements the split chain-read + subset-probe interface
// (chainFetcher + subsetEnricher), so the DynamicRegistryProvider takes its
// bounded demand-driven probing path. It captures the probe set it was
// handed each cycle. FetchChain returns the chain-read template (ids + on-chain
// metrics, no capabilities); EnrichSubset marks the selected nodes probed-good.
type boundedFakeSource struct {
	chainOps []Operator

	mu       sync.Mutex
	probed   map[NodeRef]bool
	probeAll bool
}

func (b *boundedFakeSource) clone() []Operator {
	out := make([]Operator, len(b.chainOps))
	copy(out, b.chainOps) // Operator is a value type; elements are copied
	return out
}

func (b *boundedFakeSource) Fetch(_ context.Context) ([]Operator, error) { return b.clone(), nil }

func (b *boundedFakeSource) FetchChain(_ context.Context) ([]Operator, error) { return b.clone(), nil }

func (b *boundedFakeSource) EnrichSubset(_ context.Context, ops []Operator, probeSet map[NodeRef]bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.probed = map[NodeRef]bool{}
	b.probeAll = probeSet == nil
	now := time.Now()
	for i := range ops {
		if probeSet == nil || probeSet[RefOf(ops[i])] {
			b.probed[RefOf(ops[i])] = true
			ops[i].Reachable = true
			ops[i].Probed = true
			ops[i].ReachableAsOf = now
			ops[i].LastRefreshAt = now
		}
	}
}

func (b *boundedFakeSource) probedRefs() map[NodeRef]bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[NodeRef]bool, len(b.probed))
	for k := range b.probed {
		out[k] = true
	}
	return out
}

func (b *boundedFakeSource) didProbeAll() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.probeAll
}

// chainReadOp builds a chain-read-shaped Operator: identity + on-chain metrics,
// no capabilities (those arrive only via a probe).
func chainReadOp(id uint64, ttftMs uint64) Operator {
	return Operator{
		ID:        id,
		OwnerAddr: fmt.Sprintf("O%d", id),
		BaseURL:   "http://x",
		Metrics:   OperatorMetrics{LatencyEwmaMs: ttftMs},
	}
}

func boundedReg(t *testing.T, src *boundedFakeSource, initial []Operator, cfg DynamicRegistryConfig) *DynamicRegistryProvider {
	t.Helper()
	reg, err := NewDynamicRegistryProvider(src, initial, cfg, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	return reg
}

// TestDynamicRegistry_BoundedProbeCount: a fleet larger than the budget probes
// exactly probe_budget nodes per cycle (the constant-fan-out scaling win).
func TestDynamicRegistry_BoundedProbeCount(t *testing.T) {
	const budget = 10
	ops := make([]Operator, 50)
	for i := range ops {
		ops[i] = chainReadOp(uint64(i+1), 0)
	}
	src := &boundedFakeSource{chainOps: ops}
	reg := boundedReg(t, src, nil, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: 0, ProbeBudget: budget,
	})
	reg.refresh(context.Background())

	if src.didProbeAll() {
		t.Fatal("fleet (50) over budget (10): expected a bounded probe set, got probe-all")
	}
	if got := len(src.probedRefs()); got != budget {
		t.Fatalf("probed %d nodes, want budget %d", got, budget)
	}
}

// TestDynamicRegistry_SmallFleetProbesAll: a fleet at or under the budget still
// probes every node (the original probe-everything behavior preserved for small deployments).
func TestDynamicRegistry_SmallFleetProbesAll(t *testing.T) {
	const budget = 10
	ops := make([]Operator, 5)
	for i := range ops {
		ops[i] = chainReadOp(uint64(i+1), 0)
	}
	src := &boundedFakeSource{chainOps: ops}
	reg := boundedReg(t, src, nil, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: 0, ProbeBudget: budget,
	})
	reg.refresh(context.Background())

	if !src.didProbeAll() {
		t.Fatalf("fleet (5) under budget (%d) should probe all; got bounded set %v", budget, src.probedRefs())
	}
}

// TestDynamicRegistry_SweepCoversFleet: with no demand, the rolling sweep
// re-probes every node within ceil(fleet/budget) cycles.
func TestDynamicRegistry_SweepCoversFleet(t *testing.T) {
	const budget = 10
	const N = 25
	ops := make([]Operator, N)
	for i := range ops {
		ops[i] = chainReadOp(uint64(i+1), 0)
	}
	src := &boundedFakeSource{chainOps: ops}
	reg := boundedReg(t, src, nil, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: 0, ProbeBudget: budget,
	})

	covered := map[NodeRef]bool{}
	for cycle := 0; cycle < 3; cycle++ { // ceil(25/10) = 3
		reg.refresh(context.Background())
		for ref := range src.probedRefs() {
			covered[ref] = true
		}
	}
	if len(covered) != N {
		t.Fatalf("rolling sweep covered %d/%d nodes after 3 cycles", len(covered), N)
	}
}

// TestDynamicRegistry_DemandPrioritizesFastServers: a demanded model's fastest
// known servers are probed each cycle even when the rolling sweep wouldn't reach
// them yet — the "hot models stay fresh" property.
func TestDynamicRegistry_DemandPrioritizesFastServers(t *testing.T) {
	const budget = 8
	const N = 40
	chainOps := make([]Operator, N)
	prevOps := make([]Operator, N)
	for i := 0; i < N; i++ {
		id := uint64(i + 1)
		// TTFT descends with index, so the HIGH ids are fastest (TTFT 1..4 for
		// ids 40..37) and sit well past the sweep's first-cycle window (cursor 0
		// covers the low ids) — so only demand can put them in this cycle.
		chainOps[i] = chainReadOp(id, uint64(N-i))
		prevOps[i] = reachableOp(id, "hot") // prev catalog: node serves "hot", recent
	}
	src := &boundedFakeSource{chainOps: chainOps}
	reg := boundedReg(t, src, prevOps, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: 0,
		ProbeBudget: budget, TargetTopK: 4,
	})
	reg.RecordModelDemand("hot")
	reg.refresh(context.Background())

	probed := src.probedRefs()
	for _, id := range []uint64{40, 39, 38, 37} { // the 4 fastest "hot" servers
		if !probed[NodeRef{Op: id, Node: 0}] {
			t.Fatalf("fastest demanded 'hot' server node %d not probed; probed=%v", id, probed)
		}
	}
}

// TestDynamicRegistry_ProbesUnknownNodesBeforeTheSweep: a node new on chain,
// far past the sweep cursor, is probed in the next bounded cycle, while a node
// that was tried and never answered waits its turn. It fails if the registry
// stops carrying LastRefreshAt or ReachableAsOf onto the rows before it picks
// the probe set: every row would then look unknown, and the set would be the
// plain sweep's.
func TestDynamicRegistry_ProbesUnknownNodesBeforeTheSweep(t *testing.T) {
	const N = 20
	prev := make([]Operator, N)
	for i := range prev {
		prev[i] = chainReadOp(uint64(i+1), 0)
		prev[i].Reachable, prev[i].ReachableAsOf, prev[i].LastRefreshAt = true, time.Now(), time.Now()
	}
	// Tried last cycle and down: known, though it never answered.
	prev[14].Reachable, prev[14].ReachableAsOf = false, time.Time{}

	chain := make([]Operator, N+1)
	for i := range chain {
		chain[i] = chainReadOp(uint64(i+1), 0)
	}
	src := &boundedFakeSource{chainOps: chain}
	reg := boundedReg(t, src, prev, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: 0, ProbeBudget: 4,
	})
	reg.refresh(context.Background())

	want := map[NodeRef]bool{{Op: 1}: true, {Op: 2}: true, {Op: 3}: true, {Op: N + 1}: true}
	if got := src.probedRefs(); !maps.Equal(got, want) {
		t.Fatalf("probed %v, want %v: the new node ahead of the sweep, the failed one not", got, want)
	}
}

// TestDynamicRegistry_PersistsSeedAtStartup: the seed snapshot is written to
// CatalogPath during construction — not only after the first (~refresh_interval
// away) background refresh — so the catalog file exists from startup.
func TestDynamicRegistry_PersistsSeedAtStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	seed := []Operator{reachableOp(1, "m1"), reachableOp(2, "m2")}
	_ = boundedReg(t, &boundedFakeSource{}, seed, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: time.Hour,
		CatalogPath: path,
	})
	loaded, err := LoadCatalog(path) // no refresh triggered
	if err != nil {
		t.Fatalf("LoadCatalog after construction: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("seed snapshot not persisted at startup: %d operators", len(loaded))
	}
}

// TestDynamicRegistry_PersistsOnRefresh: a refresh writes the catalog to
// CatalogPath so a restart can warm-start from it.
func TestDynamicRegistry_PersistsOnRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "catalog.json")
	src := &boundedFakeSource{chainOps: []Operator{chainReadOp(1, 0), chainReadOp(2, 0)}}
	reg := boundedReg(t, src, nil, DynamicRegistryConfig{
		RefreshInterval: time.Hour, RefreshTimeout: time.Second, MaxCacheAge: 0,
		CatalogPath: path,
	})
	reg.refresh(context.Background())

	loaded, err := LoadCatalog(path)
	if err != nil {
		t.Fatalf("LoadCatalog after refresh: %v", err)
	}
	if len(loaded) != 2 {
		t.Fatalf("persisted %d operators, want 2", len(loaded))
	}
}
