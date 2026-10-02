/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeSource is a test OperatorSource that returns a canned slice (or
// error) and records how many times Fetch was called.
type fakeSource struct {
	mu      sync.Mutex
	ops     []Operator
	err     error
	calls   int
	onFetch func() // optional hook called at the start of each Fetch
}

func (f *fakeSource) Fetch(ctx context.Context) ([]Operator, error) {
	f.mu.Lock()
	if f.onFetch != nil {
		hook := f.onFetch
		f.mu.Unlock()
		hook()
		f.mu.Lock()
	}
	f.calls++
	ops := append([]Operator(nil), f.ops...)
	err := f.err
	f.mu.Unlock()
	return ops, err
}

func (f *fakeSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeSource) setOps(ops []Operator, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ops = ops
	f.err = err
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func reachableOp(id uint64, model string) Operator {
	op := sampleOp(id, "A"+string(rune('A'+id)), model)
	op.Reachable = true
	op.LastRefreshAt = time.Now()
	// A probed-good node always carries ReachableAsOf in production (probeOne
	// sets both); the registry's carry window / discovery gate keys off it, so
	// fixtures must set it too or they'd read as aged-out.
	op.ReachableAsOf = time.Now()
	return op
}

func TestDynamicRegistry_SeededSnapshotServesReadsWithoutRefresh(t *testing.T) {
	src := &fakeSource{}
	reg, err := NewDynamicRegistryProvider(src, []Operator{reachableOp(1, "m")}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	// Read without Start — the seeded snapshot must be returned and
	// the source must NOT be called (we're well within MaxCacheAge).
	ops, err := reg.Operators(context.Background(), "m")
	if err != nil {
		t.Fatalf("Operators: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != 1 {
		t.Fatalf("Operators = %+v", ops)
	}
	if src.callCount() != 0 {
		t.Fatalf("source called %d times, want 0 (within cache age)", src.callCount())
	}
}

func TestDynamicRegistry_LazyRefreshWhenStale(t *testing.T) {
	// Seed with op 1, arrange source to return op 2 on refresh.
	src := &fakeSource{ops: []Operator{reachableOp(2, "m")}}
	reg, err := NewDynamicRegistryProvider(src, []Operator{reachableOp(1, "m")}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0, // every read is "stale"
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	ops, err := reg.Operators(context.Background(), "m")
	if err != nil {
		t.Fatalf("Operators: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != 2 {
		t.Fatalf("after stale refresh, got %+v, want op 2", ops)
	}
	if src.callCount() != 1 {
		t.Fatalf("source called %d times, want 1", src.callCount())
	}
}

func TestDynamicRegistry_LazyRefreshFailureKeepsPreviousSnapshot(t *testing.T) {
	src := &fakeSource{err: errors.New("chain down")}
	reg, err := NewDynamicRegistryProvider(src, []Operator{reachableOp(1, "m")}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	ops, err := reg.Operators(context.Background(), "m")
	if err != nil {
		t.Fatalf("Operators: %v", err)
	}
	if len(ops) != 1 || ops[0].ID != 1 {
		t.Fatalf("keep previous snapshot on refresh failure, got %+v", ops)
	}
	if src.callCount() != 1 {
		t.Fatalf("source called %d times, want 1", src.callCount())
	}
}

func TestDynamicRegistry_ConcurrentLazyRefreshCoalesces(t *testing.T) {
	var inFetch atomic.Int32
	release := make(chan struct{})
	src := &fakeSource{
		ops: []Operator{reachableOp(1, "m")},
		onFetch: func() {
			inFetch.Add(1)
			<-release
		},
	}
	reg, err := NewDynamicRegistryProvider(src, []Operator{reachableOp(1, "m")}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0, // force refresh on every read
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}

	const readers = 16
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = reg.Operators(context.Background(), "m")
		}()
	}

	// Wait until the first refresh is running, then release it. The
	// other readers must coalesce — inFetch should never exceed 1
	// while this one is blocked, and total fetches stays small.
	deadline := time.Now().Add(2 * time.Second)
	for inFetch.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := inFetch.Load(); got != 1 {
		close(release)
		wg.Wait()
		t.Fatalf("in-flight fetches = %d during coalesce, want 1", got)
	}
	close(release)
	wg.Wait()

	// After release, subsequent waiters may or may not each trigger
	// another refresh (they release the mutex in fifo order with a
	// still-stale snapshot). The important invariant is that we
	// didn't fan out to {readers} parallel fetches — the mutex
	// serialized them, which is the coalesce guarantee we care about.
	if got := src.callCount(); got > readers {
		t.Fatalf("source called %d times, want <= %d (serialized, not parallel)", got, readers)
	}
}

func TestDynamicRegistry_BackgroundRefresh(t *testing.T) {
	src := &fakeSource{ops: []Operator{reachableOp(1, "m"), reachableOp(2, "m")}}
	reg, err := NewDynamicRegistryProvider(src, []Operator{reachableOp(1, "m")}, DynamicRegistryConfig{
		RefreshInterval: 10 * time.Millisecond,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour, // only background refresh can fire
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	reg.Start(ctx)
	defer reg.Stop()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		ops, err := reg.Operators(context.Background(), "m")
		if err == nil && len(ops) == 2 {
			return // background refresh picked up the new op
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("background refresh never produced op 2 (source calls = %d)", src.callCount())
}

func TestDynamicRegistry_LifecycleIdempotent(t *testing.T) {
	src := &fakeSource{ops: []Operator{reachableOp(1, "m")}}
	reg, err := NewDynamicRegistryProvider(src, nil, DynamicRegistryConfig{
		RefreshInterval: 10 * time.Millisecond,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reg.Start(ctx)
	reg.Start(ctx) // second call — no-op
	reg.Stop()
	reg.Stop() // second call — no-op
	// Start-after-Stop is a no-op; must not panic or relaunch.
	reg.Start(ctx)
}

func TestDynamicRegistry_CarryForwardLastGood(t *testing.T) {
	// Seed with a reachable operator with a known models list. Next
	// fetch returns the same operator but with Reachable=false and
	// empty Models/Tools/Caps — carryForwardLastGood must repopulate
	// those from the previous snapshot so routing keeps working.
	first := reachableOp(1, "m")
	first.Models = []string{"m", "other"}
	first.ModelCapacities = map[string]ModelCapacity{"m": {ContextWindow: 8000}}
	first.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	first.MaxToolIters = 3

	second := sampleOp(1, "A", "") // empty models
	second.Models = nil
	second.Reachable = false

	src := &fakeSource{ops: []Operator{second}}
	reg, err := NewDynamicRegistryProvider(src, []Operator{first}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0, // force lazy refresh
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}

	// Trigger the refresh via a read.
	got, err := reg.Resolve(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Reachable {
		t.Fatalf("op.Reachable = true, want false (fetcher reported unreachable)")
	}
	if len(got.Models) != 2 {
		t.Fatalf("op.Models = %v, want preserved [m other]", got.Models)
	}
	if _, ok := got.ModelCapacities["m"]; !ok {
		t.Fatalf("op.ModelCapacities not carried forward: %v", got.ModelCapacities)
	}
	if len(got.BuiltinTools) != 1 {
		t.Fatalf("op.BuiltinTools = %v, want carried forward", got.BuiltinTools)
	}
	if got.MaxToolIters != 3 {
		t.Fatalf("op.MaxToolIters = %d, want 3 (carried forward)", got.MaxToolIters)
	}
}

// TestDynamicRegistry_CarryWindowAdvertisesUnprobedButRecent is the core
// behavior: under bounded probing a node is often NOT probed this cycle
// (Probed=false). One whose last successful probe is within max_carry_age keeps
// advertising; one whose last-good has aged past the window drops off.
func TestDynamicRegistry_CarryWindowAdvertisesUnprobedButRecent(t *testing.T) {
	recent := reachableOp(1, "fresh") // ReachableAsOf = now
	recent.Reachable = false          // not confirmed this cycle...
	recent.Probed = false             // ...and not probed → carry window applies
	recent.Models = []string{"fresh"}

	aged := reachableOp(2, "aged")
	aged.Reachable = false
	aged.Probed = false
	aged.ReachableAsOf = time.Now().Add(-2 * time.Hour) // beyond the 90m default window
	aged.Models = []string{"aged"}

	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{recent, aged}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got := reg.AllModels(context.Background())
	if len(got) != 1 || got[0] != "fresh" {
		t.Fatalf("AllModels = %v, want only [fresh] (unprobed-but-recent advertised, aged-out dropped)", got)
	}
}

// TestDynamicRegistry_CarryForwardAgesOutPastWindow verifies the staleness bound:
// a node whose last-good is older than max_carry_age is NOT resurrected by
// carry-forward, so it leaves both dispatch (empty Models) and discovery.
func TestDynamicRegistry_CarryForwardAgesOutPastWindow(t *testing.T) {
	prev := reachableOp(1, "m")
	prev.ReachableAsOf = time.Now().Add(-2 * time.Hour) // aged out (default window 90m)
	prev.Models = []string{"m", "other"}

	fresh := sampleOp(1, "A", "") // fresh fetch: not probed this cycle, no models
	fresh.Models = nil
	fresh.Reachable = false

	src := &fakeSource{ops: []Operator{fresh}}
	reg, err := NewDynamicRegistryProvider(src, []Operator{prev}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0, // force a lazy refresh on read
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got, err := reg.Resolve(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got.Models != nil {
		t.Fatalf("Models = %v, want nil (aged-out node not carried forward)", got.Models)
	}
}

func TestDynamicRegistry_AllModelsDedupes(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m", "x"}
	op2 := reachableOp(2, "m")
	op2.Models = []string{"m", "y"}
	src := &fakeSource{}
	reg, err := NewDynamicRegistryProvider(src, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got := reg.AllModels(context.Background())
	if len(got) != 3 {
		t.Fatalf("AllModels len = %d, want 3 (m, x, y)", len(got))
	}
}

// TestDynamicRegistry_AllModelsExcludesUnreachable verifies that an
// operator carrying forward a stale Models list while unreachable does
// NOT contribute to the AllModels discovery surface. Dispatch's
// Operators(model) keeps the carried-forward entry (separately tested
// below); the discovery surface should only advertise what dispatch can
// actually serve right now.
func TestDynamicRegistry_AllModelsExcludesUnreachable(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m", "shared"}
	op2 := reachableOp(2, "m")
	op2.Reachable = false
	op2.Probed = true // probed-down this cycle → excluded from discovery
	op2.Models = []string{"shared", "stale"}
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got := reg.AllModels(context.Background())
	want := map[string]bool{"m": true, "shared": true}
	if len(got) != len(want) {
		t.Fatalf("AllModels = %v, want only reachable union %v", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("AllModels included %q from an unreachable operator", m)
		}
	}
}

// TestDynamicRegistry_AllModelDetailsExcludesUnreachable mirrors the
// AllModels filter for the richer model-capability view.
func TestDynamicRegistry_AllModelDetailsExcludesUnreachable(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m"}
	op1.ModelCapacities = map[string]ModelCapacity{"m": {ContextWindow: 8000}}
	op2 := reachableOp(2, "m")
	op2.Reachable = false
	op2.Probed = true // probed-down this cycle → excluded from discovery
	op2.Models = []string{"stale"}
	op2.ModelCapacities = map[string]ModelCapacity{"stale": {ContextWindow: 4000}}
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got := reg.AllModelDetails(context.Background())
	if len(got) != 1 || got[0].ID != "m" {
		t.Fatalf("AllModelDetails = %+v, want only [m]", got)
	}
}

// TestDynamicRegistry_AllBuiltinToolsExcludesUnreachable mirrors the
// AllModels filter for built-in tool advertisement.
func TestDynamicRegistry_AllBuiltinToolsExcludesUnreachable(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	op2 := reachableOp(2, "m")
	op2.Reachable = false
	op2.Probed = true // probed-down this cycle → excluded from discovery
	op2.BuiltinTools = []BuiltinToolDef{{Type: "zs_image_search"}}
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got := reg.AllBuiltinTools(context.Background())
	if len(got) != 1 || got[0].Type != "zs_web_search" {
		t.Fatalf("AllBuiltinTools = %+v, want only [zs_web_search]", got)
	}
}

// TestDynamicRegistry_AllNodeVersionsExcludesUnreachable mirrors the
// AllModels filter for node version advertisement.
func TestDynamicRegistry_AllNodeVersionsExcludesUnreachable(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.NodeVersion = "abc1234"
	op2 := reachableOp(2, "m")
	op2.Reachable = false
	op2.NodeVersion = "def5678"
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got := reg.AllNodeVersions(context.Background())
	if len(got) != 1 || got[0] != "abc1234" {
		t.Fatalf("AllNodeVersions = %+v, want only [abc1234]", got)
	}
}

// TestDynamicRegistry_OperatorsKeepsUnreachableForDispatch locks in the
// counterpart invariant: dispatch (Operators(model)) must continue to
// return an unreachable operator that's carrying forward a Models list,
// because the operator's reserve path may still be healthy across a
// brief details-endpoint outage. This is the sibling guarantee to the
// AllModels filter — discovery hides the operator, dispatch keeps it.
func TestDynamicRegistry_OperatorsKeepsUnreachableForDispatch(t *testing.T) {
	op := reachableOp(1, "carried")
	op.Reachable = false
	op.Probed = true // probed this cycle and found down → hidden from discovery
	op.Models = []string{"carried"}
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	got, err := reg.Operators(context.Background(), "carried")
	if err != nil {
		t.Fatalf("Operators: %v", err)
	}
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("Operators(carried) = %+v, want unreachable op 1 (dispatch resilience)", got)
	}
	// And it must not appear in the discovery surface.
	if mods := reg.AllModels(context.Background()); len(mods) != 0 {
		t.Fatalf("AllModels = %+v, want empty (operator unreachable)", mods)
	}
}

func TestDynamicRegistry_AllOperatorsReturnsCopy(t *testing.T) {
	op1 := reachableOp(1, "m")
	op2 := reachableOp(2, "n")
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}

	got := reg.AllOperators(context.Background())
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}

	got[0].ID = 999
	again := reg.AllOperators(context.Background())
	if again[0].ID != 1 {
		t.Errorf("snapshot slice was aliased: again[0].ID = %d, want 1", again[0].ID)
	}
}

func TestDynamicRegistry_RejectsNilSource(t *testing.T) {
	_, err := NewDynamicRegistryProvider(nil, nil, DynamicRegistryConfig{}, discardLogger())
	if err == nil {
		t.Fatal("expected error for nil source")
	}
}

func TestDynamicRegistry_RejectsZeroID(t *testing.T) {
	_, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{{ID: 0, BaseURL: "http://a"}}, DynamicRegistryConfig{}, discardLogger())
	if err == nil {
		t.Fatal("expected error for zero ID in seed")
	}
}

// TestDynamicRegistry_RefreshPicksUpNewTools verifies that a refresh
// cycle propagates newly-advertised BuiltinTools / MaxToolIters from
// the source into the snapshot, and that reads (Resolve,
// AllBuiltinTools) see the new values without needing a restart.
func TestDynamicRegistry_RefreshPicksUpNewTools(t *testing.T) {
	// Seed: operator with zero tools advertised.
	seed := reachableOp(1, "m")
	seed.BuiltinTools = nil
	seed.MaxToolIters = 0

	// Next Fetch returns the same operator with two tools + iter cap.
	refreshed := reachableOp(1, "m")
	refreshed.BuiltinTools = []BuiltinToolDef{
		{Type: "zs_web_search"},
		{Type: "zs_web_read"},
	}
	refreshed.MaxToolIters = 4

	src := &fakeSource{ops: []Operator{refreshed}}
	reg, err := NewDynamicRegistryProvider(src, []Operator{seed}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0, // force lazy refresh on first read
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}

	// Resolve triggers the lazy refresh — the resolved operator must
	// carry the newly-advertised tool data.
	op, err := reg.Resolve(context.Background(), 1, 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if len(op.BuiltinTools) != 2 {
		t.Fatalf("BuiltinTools len = %d after refresh, want 2", len(op.BuiltinTools))
	}
	if !op.SupportsBuiltinTool("zs_web_search") || !op.SupportsBuiltinTool("zs_web_read") {
		t.Fatalf("SupportsBuiltinTool missed a newly-advertised tool: %+v", op.BuiltinTools)
	}
	if op.MaxToolIters != 4 {
		t.Fatalf("MaxToolIters = %d after refresh, want 4", op.MaxToolIters)
	}

	// AllBuiltinTools (used by the proxy's GET /v1/zs/details
	// aggregation) must also surface the newly-advertised tools.
	all := reg.AllBuiltinTools(context.Background())
	if len(all) != 2 {
		t.Fatalf("AllBuiltinTools len = %d, want 2: %+v", len(all), all)
	}
}

// TestDynamicRegistry_RefreshPicksUpRemovedTools verifies that a tool
// dropped from an operator's advertisement is reflected after a
// refresh — no stale union.
func TestDynamicRegistry_RefreshPicksUpRemovedTools(t *testing.T) {
	seed := reachableOp(1, "m")
	seed.BuiltinTools = []BuiltinToolDef{
		{Type: "zs_web_search"},
		{Type: "zs_web_read"},
	}
	seed.MaxToolIters = 5

	refreshed := reachableOp(1, "m")
	refreshed.BuiltinTools = []BuiltinToolDef{
		{Type: "zs_web_search"},
	}
	refreshed.MaxToolIters = 2

	src := &fakeSource{ops: []Operator{refreshed}}
	reg, err := NewDynamicRegistryProvider(src, []Operator{seed}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     0,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}

	all := reg.AllBuiltinTools(context.Background())
	if len(all) != 1 || all[0].Type != "zs_web_search" {
		t.Fatalf("AllBuiltinTools after refresh = %+v, want [zs_web_search]", all)
	}
	op, _ := reg.Resolve(context.Background(), 1, 0)
	if op.MaxToolIters != 2 {
		t.Fatalf("MaxToolIters = %d, want 2 (refreshed cap)", op.MaxToolIters)
	}
}

func TestDynamicRegistry_SnapshotAgeSentinel(t *testing.T) {
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, nil, DynamicRegistryConfig{}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	if got := reg.SnapshotAge(); got != -1 {
		t.Fatalf("SnapshotAge with no snapshot = %v, want -1", got)
	}
}
