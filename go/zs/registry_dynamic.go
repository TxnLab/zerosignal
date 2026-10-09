/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
)

// DefaultRefreshInterval is the background cadence at which the
// registry re-fetches the on-chain operator set and re-probes every
// operator's /v1/zs/details endpoint. Chosen to be frequent enough
// that a newly-registered operator starts serving within a few minutes
// and infrequent enough that idle proxies don't hammer algod.
const DefaultRefreshInterval = 5 * time.Minute

// DefaultRefreshTimeout bounds one full refresh cycle (chain read +
// per-operator details probes in parallel). Past this deadline the
// cycle is abandoned and the last-known-good snapshot is retained.
const DefaultRefreshTimeout = 30 * time.Second

// DefaultMaxCacheAge is the hard ceiling on snapshot age. A registry
// read that observes a snapshot older than this triggers a synchronous
// refresh before returning — the caller pays the latency but never
// sees stale data past this bound. Set generously relative to
// DefaultRefreshInterval so the lazy path rarely fires during
// healthy operation.
const DefaultMaxCacheAge = 15 * time.Minute

// DefaultProbeBudget caps how many /v1/zs/details probes one background refresh
// issues once the fleet exceeds it. Sized so budget/DetailsConcurrency ×
// DetailsTimeout stays inside DefaultRefreshTimeout even when privacy mode
// rotates every probe through maxDiscoveryRelayAttempts relays
// (96/24 × 3 × 2s = 24s < 30s), while the rolling sweep still covers a
// ~1000-node fleet within a handful of cycles. A fleet at or under the budget
// is probed in full (the original probe-everything behavior).
const DefaultProbeBudget = 96

// DefaultTargetTopK is how many of a demanded model's fastest known servers a
// bounded cycle re-probes, keeping the nodes we actually route to fresh (price +
// ephemeral) rather than waiting for the sweep to reach them.
const DefaultTargetTopK = 8

// defaultDemandMax bounds the recently-requested-model set that drives
// demand-prioritized probing.
const defaultDemandMax = 32

// probeDecodeNormTokens is the fixed token count the probe-priority score
// normalizes decode throughput against. A light term next to TTFT, since decode
// rate is the noisier signal.
//
// Deliberately independent of the dispatch-side decodeNormTokens, which is now
// 32: that one was lowered because it was letting a per-node speed aggregate
// override price, and none of that reasoning applies here. Choosing which nodes
// to re-probe is not choosing where to route — a stale-but-fast node is worth
// refreshing regardless of how much its aggregate should count once it's a
// candidate. Don't unify the two just because they once agreed.
const probeDecodeNormTokens = 128

// DefaultMaxCarryAge is how long a node keeps advertising its
// last-probed capabilities after its most recent SUCCESSFUL probe
// (Operator.ReachableAsOf). It is the discovery/dispatch carry window: a
// node probed-good now stays in /v1/models etc. until now-ReachableAsOf
// exceeds this, even across the cycles where bounded probing doesn't
// re-probe it. It MUST comfortably exceed the sweep period — the time for
// bounded probing to revisit every node, ~= fleet/probe_budget *
// refresh_interval — or nodes flicker out of discovery between sweeps. The
// 90m default covers a ~1000-node fleet at budget 96 / 5m interval (~55m
// sweep) with headroom; raise it for larger fleets or a smaller budget.
const DefaultMaxCarryAge = 90 * time.Minute

// registrySnapshot is the immutable slice of operators held by the
// registry between refresh cycles. Every field on the snapshot is
// populated at construction and never mutated again; concurrent readers
// hold a stable view for as long as they keep the pointer.
type registrySnapshot struct {
	operators []Operator
	byNode    map[NodeRef]Operator
	fetchedAt time.Time
}

// DynamicRegistryProvider implements RegistryProvider with a
// continuously-refreshing snapshot. A background goroutine re-fetches
// every refreshInterval; any read that sees a snapshot older than
// maxCacheAge triggers a synchronous refresh before returning. Failed
// refreshes are logged and the previous snapshot is retained, so
// transient chain / operator outages never surface as empty-registry
// errors to the dispatch path.
type DynamicRegistryProvider struct {
	source          OperatorSource
	log             *slog.Logger
	refreshInterval time.Duration
	refreshTimeout  time.Duration
	maxCacheAge     time.Duration
	maxCarryAge     time.Duration
	// allowStaging is the payer's opt-in to on-chain staging nodes, a discovery
	// gate like maxCarryAge above: see advertisable.
	allowStaging bool

	// Bounded probing. probeBudget caps how many /v1/zs/details probes one
	// background refresh issues (0 = unbounded, probe every node); targetTopK is
	// how many of a demanded model's fastest known servers a cycle re-probes.
	probeBudget int
	targetTopK  int
	// sweepCursor is the round-robin position of the rolling sweep that fills a
	// cycle's probe budget beyond the demand picks, so every node is eventually
	// re-probed. Only refreshLocked touches it (serialized by refreshMu).
	sweepCursor int

	// catalogPath, when non-empty, is where each refreshed snapshot is persisted
	// so a restart warm-starts from the last-known catalog. Empty disables
	// persistence (tests, or an operator who opts out). The two fields below are
	// touched only by persist, which runs serialized under refreshMu (and once in
	// the constructor before Start), so they need no separate lock.
	catalogPath string
	// catalogSum is the sha256 of the last catalog bytes written; persist skips a
	// re-write when the new snapshot marshals identically (an idle fleet churns no
	// disk). Zero value never collides with a real write (json is never empty).
	catalogSum [32]byte
	// catalogDirOK records that path's directory has been created, so persist
	// MkdirAlls once rather than every cycle. Reset on any write error so a
	// vanished dir self-heals on the next attempt.
	catalogDirOK bool

	// demandMu guards the recently-requested-model set that prioritizes probes.
	demandMu  sync.Mutex
	demand    map[string]int64 // model id -> monotonic last-requested seq
	demandSeq int64
	demandMax int

	// snap is the live snapshot pointer. Readers atomically Load it
	// and never mutate. Writers build a fresh snapshot and Store it.
	snap atomic.Pointer[registrySnapshot]

	// refreshMu serializes refresh cycles. Double-checked locking on
	// the snapshot pointer under this mutex coalesces concurrent lazy
	// refresh attempts into a single fetch.
	refreshMu sync.Mutex

	// lifecycleMu guards started/stopped/cancel/done so Start+Stop
	// are safe to interleave. Start launches the background loop
	// once; Stop cancels it and waits for completion. Repeated calls
	// to either are harmless.
	lifecycleMu sync.Mutex
	started     bool
	stopped     bool
	cancel      context.CancelFunc
	done        chan struct{}
}

// DynamicRegistryConfig carries the tunables for a
// DynamicRegistryProvider. Negative values pick package defaults.
//
// MaxCacheAge has a special-case sentinel: exactly 0 means "every read
// is stale" — the lazy refresh path fires unconditionally on the first
// read. This is what tests use to deterministically force the lazy
// refresh path; in production, leave it negative (or unset) to take
// DefaultMaxCacheAge. A small positive value like 1ns is *not* a
// reliable always-stale knob: monotonic-clock resolution can let
// `time.Since(fetchedAt)` return 0 for a freshly-built snapshot,
// keeping it spuriously "fresh".
type DynamicRegistryConfig struct {
	RefreshInterval time.Duration
	RefreshTimeout  time.Duration
	MaxCacheAge     time.Duration
	// MaxCarryAge is the discovery/dispatch carry window (see
	// DefaultMaxCarryAge). Zero or negative picks the default.
	MaxCarryAge time.Duration
	// ProbeBudget / TargetTopK bound demand-driven probing. Zero or
	// negative picks the defaults (DefaultProbeBudget / DefaultTargetTopK); a
	// fleet at or under ProbeBudget is probed in full.
	ProbeBudget int
	TargetTopK  int
	// CatalogPath, when non-empty, persists each refreshed snapshot there
	// for a warm restart. Empty disables persistence.
	CatalogPath string
	// AllowStaging opts the payer in to nodes their operator flagged staging
	// on-chain (zs.allow_staging). False — the zero value and the default —
	// holds them out of every discovery aggregate; see advertisable. It
	// deliberately has no normalization branch in the constructor: the safe
	// value and the zero value are the same one.
	AllowStaging bool
}

// NewDynamicRegistryProvider builds a registry seeded with initialOps
// (the result of the startup fetch — so the first request doesn't pay
// a cold-cache penalty). Pass Start(ctx) afterwards to launch the
// background refresher; reads work even without Start, but they'll
// only see new data via the lazy max_cache_age path.
func NewDynamicRegistryProvider(source OperatorSource, initialOps []Operator, cfg DynamicRegistryConfig, log *slog.Logger) (*DynamicRegistryProvider, error) {
	if source == nil {
		return nil, fmt.Errorf("operator source is nil")
	}
	if log == nil {
		log = slog.Default()
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultRefreshInterval
	}
	if cfg.RefreshTimeout <= 0 {
		cfg.RefreshTimeout = DefaultRefreshTimeout
	}
	// 0 is the "every read is stale" sentinel (see DynamicRegistryConfig
	// godoc). Only fall through to the default for truly unset/negative
	// values.
	if cfg.MaxCacheAge < 0 {
		cfg.MaxCacheAge = DefaultMaxCacheAge
	}
	if cfg.MaxCarryAge <= 0 {
		cfg.MaxCarryAge = DefaultMaxCarryAge
	}
	if cfg.ProbeBudget <= 0 {
		cfg.ProbeBudget = DefaultProbeBudget
	}
	if cfg.TargetTopK <= 0 {
		cfg.TargetTopK = DefaultTargetTopK
	}
	p := &DynamicRegistryProvider{
		source:          source,
		log:             log,
		refreshInterval: cfg.RefreshInterval,
		refreshTimeout:  cfg.RefreshTimeout,
		maxCacheAge:     cfg.MaxCacheAge,
		maxCarryAge:     cfg.MaxCarryAge,
		allowStaging:    cfg.AllowStaging,
		probeBudget:     cfg.ProbeBudget,
		targetTopK:      cfg.TargetTopK,
		catalogPath:     cfg.CatalogPath,
		demand:          make(map[string]int64),
		demandMax:       defaultDemandMax,
	}
	if initialOps != nil {
		snap, err := buildSnapshot(initialOps)
		if err != nil {
			return nil, err
		}
		p.snap.Store(snap)
		// Persist the seed snapshot immediately, not just after the first
		// background refresh (~refresh_interval away) — so the catalog file exists
		// from startup and a fast restart is covered.
		p.persist(snap.operators)
		// Every later refresh diffs against this seed, so a node broke at boot
		// that stays broke never transitions; name it now or never.
		p.logUnderfundedIn(snap.operators)
	}
	return p, nil
}

// Start launches the background refresh goroutine. Idempotent — the
// second call is a no-op. If Stop has already been invoked, Start is a
// no-op (the registry is stopped for the lifetime of the process).
// Pass a context whose cancellation aligns with the proxy's lifetime;
// Stop also cancels the loop.
func (p *DynamicRegistryProvider) Start(ctx context.Context) {
	p.lifecycleMu.Lock()
	defer p.lifecycleMu.Unlock()
	if p.started || p.stopped {
		return
	}
	loopCtx, cancel := context.WithCancel(ctx)
	p.cancel = cancel
	p.done = make(chan struct{})
	p.started = true
	go p.run(loopCtx)
}

// Stop halts the background refresh goroutine and waits for it to
// finish. Idempotent. Safe to call even if Start was never invoked.
func (p *DynamicRegistryProvider) Stop() {
	p.lifecycleMu.Lock()
	if p.stopped {
		p.lifecycleMu.Unlock()
		return
	}
	p.stopped = true
	cancel := p.cancel
	done := p.done
	started := p.started
	p.lifecycleMu.Unlock()

	if cancel != nil {
		cancel()
	}
	if started {
		<-done
	}
}

// run drives the background refresh ticker. Each tick is bounded by
// refreshTimeout; failed cycles are logged and the previous snapshot
// is retained.
func (p *DynamicRegistryProvider) run(ctx context.Context) {
	defer close(p.done)
	ticker := time.NewTicker(p.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.refresh(ctx)
		}
	}
}

// ensureFresh is the lazy-refresh guard invoked by every read path. If
// the current snapshot is within maxCacheAge the call is essentially
// free (one atomic load). If the snapshot is missing or stale the
// caller blocks for a single refresh cycle; concurrent callers coalesce
// onto the same refresh via refreshMu + double-checked load.
func (p *DynamicRegistryProvider) ensureFresh(ctx context.Context) {
	if snap := p.snap.Load(); snap != nil && time.Since(snap.fetchedAt) < p.maxCacheAge {
		return
	}
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	if snap := p.snap.Load(); snap != nil && time.Since(snap.fetchedAt) < p.maxCacheAge {
		return
	}
	p.refreshLocked(ctx)
}

// refresh runs one refresh cycle under refreshMu. Separate from
// refreshLocked so the ticker can acquire the mutex itself (tests want
// to call refresh directly).
func (p *DynamicRegistryProvider) refresh(ctx context.Context) {
	p.refreshMu.Lock()
	defer p.refreshMu.Unlock()
	p.refreshLocked(ctx)
}

// refreshLocked assumes refreshMu is held. Produces this cycle's operator set
// (bounded demand-driven probing when the source supports it, else the unbounded
// Fetch), merges forward last-known capabilities for nodes not re-probed this
// cycle, logs the deltas, and atomically swaps the snapshot.
func (p *DynamicRegistryProvider) refreshLocked(ctx context.Context) {
	cycleCtx, cancel := context.WithTimeout(ctx, p.refreshTimeout)
	defer cancel()

	prev := p.snap.Load()
	newOps, err := p.fetchAndProbe(cycleCtx, prev)
	if err != nil {
		p.log.Warn("operator refresh failed; keeping previous snapshot",
			slog.Any("err", err),
			slog.Bool("have_snapshot", prev != nil),
		)
		return
	}

	next, err := buildSnapshot(newOps)
	if err != nil {
		p.log.Warn("operator refresh produced invalid snapshot; keeping previous",
			slog.Any("err", err))
		return
	}

	p.logTransitions(prev, next)
	p.snap.Store(next)
	p.persist(next.operators)
}

// persist writes the refreshed catalog to disk for a warm restart. Runs
// under refreshMu (serialized), best-effort — a failed save is logged and only
// costs a colder next start. No-op when catalogPath is empty, or when the
// snapshot marshals identically to the last write (an idle fleet churns no disk).
func (p *DynamicRegistryProvider) persist(ops []Operator) {
	if p.catalogPath == "" {
		return
	}
	data, err := marshalCatalog(ops)
	if err != nil {
		p.log.Warn("failed to marshal operator catalog", slog.Any("err", err))
		return
	}
	sum := sha256.Sum256(data)
	if sum == p.catalogSum {
		return // unchanged since the last write — skip the disk I/O
	}
	if err := writeCatalog(p.catalogPath, data, !p.catalogDirOK); err != nil {
		p.catalogDirOK = false // re-create the dir on the next attempt if it vanished
		p.log.Warn("failed to persist operator catalog",
			slog.Any("err", err), slog.String("path", p.catalogPath))
		return
	}
	p.catalogDirOK = true
	p.catalogSum = sum
}

// chainFetcher / subsetEnricher are the split-refresh capabilities the bounded
// path needs: read the chain without probing, then probe a chosen subset. The
// production *ChainOperatorSource implements both; fake test sources implement
// only Fetch and take the unbounded fallback.
type chainFetcher interface {
	FetchChain(ctx context.Context) ([]Operator, error)
}
type subsetEnricher interface {
	EnrichSubset(ctx context.Context, ops []Operator, probeSet map[NodeRef]bool)
}

var (
	_ chainFetcher   = (*ChainOperatorSource)(nil)
	_ subsetEnricher = (*ChainOperatorSource)(nil)
)

// fetchAndProbe produces this cycle's operator set. When the source supports the
// split chain-read + subset-probe interface (the production ChainOperatorSource)
// and a probe budget is set, it runs bounded demand-driven probing: read the
// chain, pre-seed last-known capabilities from prev, pick a bounded probe set,
// then probe only that subset — so the per-cycle /v1/zs/details fan-out is
// constant regardless of fleet size. Otherwise it falls back to the
// unbounded Fetch + post-hoc carry-forward (fake sources, or probe_budget<=0).
func (p *DynamicRegistryProvider) fetchAndProbe(ctx context.Context, prev *registrySnapshot) ([]Operator, error) {
	cf, okCF := p.source.(chainFetcher)
	se, okSE := p.source.(subsetEnricher)
	if !okCF || !okSE || p.probeBudget <= 0 {
		newOps, err := p.source.Fetch(ctx)
		if err != nil {
			return nil, err
		}
		p.carryForwardLastGood(prev, newOps)
		return newOps, nil
	}

	chainOps, err := cf.FetchChain(ctx)
	if err != nil {
		return nil, err
	}
	// Stable (id, node) order so the rolling sweep cursor advances deterministically
	// across cycles.
	sort.Slice(chainOps, func(i, j int) bool {
		if chainOps[i].ID != chainOps[j].ID {
			return chainOps[i].ID < chainOps[j].ID
		}
		return chainOps[i].NodeID < chainOps[j].NodeID
	})
	// Pre-seed last-known capabilities onto every node BEFORE probing (all are
	// unreachable at this point, so carryForwardLastGood carries them all), so a
	// node this cycle skips keeps advertising/routing via the carry window.
	p.carryForwardLastGood(prev, chainOps)
	probeSet := p.selectProbeSet(chainOps)
	se.EnrichSubset(ctx, chainOps, probeSet)
	if probeSet != nil {
		p.log.Debug("bounded operator probe",
			slog.Int("fleet", len(chainOps)),
			slog.Int("probed", len(probeSet)),
			slog.Int("budget", p.probeBudget),
		)
	}
	return chainOps, nil
}

// selectProbeSet chooses which nodes to probe this cycle, bounded by probeBudget.
// nil means "probe every node" (budget disabled or the fleet fits under it). The
// set is the union of (1) each recently-requested model's fastest known servers
// (up to targetTopK), so the nodes we route to stay fresh, and (2) a rolling
// round-robin sweep that fills the remaining budget so every node is eventually
// re-probed and new models get discovered. At least a quarter of the budget is
// reserved for the sweep so coverage always progresses even under heavy demand.
func (p *DynamicRegistryProvider) selectProbeSet(ops []Operator) map[NodeRef]bool {
	set, cursor := probeSelection(ops, p.snapshotDemand(), p.probeBudget, p.targetTopK, p.sweepCursor)
	p.sweepCursor = cursor
	return set
}

// probeSelection is selectProbeSet without the provider: ops in (id, node)
// order, demand most-recent first, and the sweep cursor in and out. The TS SDK
// mirrors it as selectProbeSet in sdk/src/catalog/probe.ts, pinned by
// testdata/probe_set_vectors.json.
func probeSelection(ops []Operator, demand []string, budget, targetTopK, cursor int) (map[NodeRef]bool, int) {
	if budget <= 0 || len(ops) <= budget {
		return nil, cursor
	}
	// At least 1 for any budget past the early return above.
	demandCap := budget - budget/4
	set := make(map[NodeRef]bool, budget)
	for _, m := range demand {
		if len(set) >= demandCap {
			break
		}
		servers := serversForModel(ops, m)
		sortByResponsiveness(servers)
		for i := 0; i < len(servers) && i < targetTopK && len(set) < demandCap; i++ {
			set[RefOf(servers[i])] = true
		}
	}
	n := len(ops)
	scanned := 0
	for ; scanned < n && len(set) < budget; scanned++ {
		set[RefOf(ops[(cursor+scanned)%n])] = true
	}
	return set, (cursor + scanned) % n
}

// serversForModel returns the ops whose (carried-forward or freshly-probed)
// catalog serves model.
func serversForModel(ops []Operator, model string) []Operator {
	var out []Operator
	for _, op := range ops {
		if op.ServesModel(model) {
			out = append(out, op)
		}
	}
	return out
}

// sortByResponsiveness orders ops fastest-first by their on-chain responsiveness
// (probe-priority key), so a demanded model's quickest known servers are probed
// before its slower ones.
func sortByResponsiveness(ops []Operator) {
	sort.SliceStable(ops, func(i, j int) bool {
		return responsivenessScore(ops[i]) < responsivenessScore(ops[j])
	})
}

// responsivenessScore is a probe-priority key (lower = probe first): the node's
// on-chain co-signed TTFT plus a light decode term. A node with no on-chain
// latency signal sorts last (the rolling sweep picks it up instead of crowding
// out a known-fast server). Mirrors the dispatch-side responsiveness banding in
// spirit; the TS SDK's probeResponsivenessScore matches it exactly, pinned
// through probe_set_vectors.json.
func responsivenessScore(op Operator) uint64 {
	ttft := op.Metrics.LatencyEwmaMs
	if ttft == 0 {
		return ^uint64(0) // no signal → sort last
	}
	score := ttft
	if tps := op.Metrics.TokensPerSecEwma; tps > 0 {
		score += probeDecodeNormTokens * 1000 / tps
	}
	return score
}

// RecordModelDemand notes that model was just requested, so the next bounded
// refresh prioritizes probing its fastest known servers. Bounded to the
// most-recent demandMax models. No-op on empty. Safe for concurrent use.
func (p *DynamicRegistryProvider) RecordModelDemand(model string) {
	if model == "" {
		return
	}
	p.demandMu.Lock()
	defer p.demandMu.Unlock()
	if p.demand == nil {
		p.demand = make(map[string]int64)
	}
	p.demandSeq++
	p.demand[model] = p.demandSeq
	if p.demandMax > 0 && len(p.demand) > p.demandMax {
		oldestK, oldestSeq := "", int64(1)<<62
		for k, seq := range p.demand {
			if seq < oldestSeq {
				oldestK, oldestSeq = k, seq
			}
		}
		delete(p.demand, oldestK)
	}
}

// snapshotDemand returns the recently-requested models, most-recent first.
func (p *DynamicRegistryProvider) snapshotDemand() []string {
	p.demandMu.Lock()
	defer p.demandMu.Unlock()
	if len(p.demand) == 0 {
		return nil
	}
	type ms struct {
		model string
		seq   int64
	}
	all := make([]ms, 0, len(p.demand))
	for k, seq := range p.demand {
		all = append(all, ms{k, seq})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].seq > all[j].seq })
	out := make([]string, len(all))
	for i, x := range all {
		out[i] = x.model
	}
	return out
}

// carryForwardLastGood copies Models, ModelCapacities, BuiltinTools,
// MaxToolIters, versions, and ReachableAsOf from a previous snapshot onto any
// operator not confirmed live this cycle (Reachable=false — either probed and
// failed, or, under bounded probing, not probed at all). This keeps a node
// routable + advertised across the gaps between probes: its reserve path may
// still be healthy, and a cached Models list lets sizing + selection continue.
//
// The carry is bounded by max_carry_age (keyed off the node's last SUCCESSFUL
// probe, ReachableAsOf): once a node's last-good passes the window it ages out —
// we stop carrying its capabilities, so it drops from both discovery
// (advertisable) and dispatch (empty Models) until a fresh probe revives it.
// This is the seam that keeps the model catalog complete while bounded probing
// re-probes only a fraction of the fleet each cycle, without masking a
// genuinely-gone node indefinitely.
func (p *DynamicRegistryProvider) carryForwardLastGood(prev *registrySnapshot, newOps []Operator) {
	if prev == nil {
		return
	}
	now := time.Now()
	for i := range newOps {
		if newOps[i].Reachable {
			continue
		}
		old, ok := prev.byNode[RefOf(newOps[i])]
		if !ok {
			continue
		}
		// Only carry within the window. ReachableAsOf==zero means the node was
		// never confirmed live (nothing worth carrying); past the window it has
		// aged out.
		if old.ReachableAsOf.IsZero() || now.Sub(old.ReachableAsOf) >= p.maxCarryAge {
			continue
		}
		carryCaps(&newOps[i], old)
	}
}

// carryCaps fills dst's un-probed capability fields (and its ReachableAsOf carry
// clock) from a last-known src, leaving anything dst already has untouched. It's
// the shared field-copy used by the registry's carry-forward and by MergeCatalog
// at startup (persist.go). The window / eligibility decision is the caller's; this
// only copies.
func carryCaps(dst *Operator, src Operator) {
	if dst.ReachableAsOf.IsZero() {
		dst.ReachableAsOf = src.ReachableAsOf
	}
	if dst.Models == nil {
		dst.Models = src.Models
	}
	if dst.ModelCapacities == nil {
		dst.ModelCapacities = src.ModelCapacities
	}
	if dst.BuiltinTools == nil {
		dst.BuiltinTools = src.BuiltinTools
	}
	if dst.MaxToolIters == 0 {
		dst.MaxToolIters = src.MaxToolIters
	}
	if dst.ToolHeadroomPerIteration == 0 {
		dst.ToolHeadroomPerIteration = src.ToolHeadroomPerIteration
	}
	if dst.NodeVersion == "" {
		dst.NodeVersion = src.NodeVersion
	}
	if dst.ProtoVersion == "" {
		dst.ProtoVersion = src.ProtoVersion
	}
}

// logTransitions emits structured log lines for the changes between
// prev and next: operators added, operators removed,
// reachable↔unreachable transitions, signer funding transitions, and
// model-list changes. Quiet when nothing changed (the common case).
func (p *DynamicRegistryProvider) logTransitions(prev, next *registrySnapshot) {
	if prev == nil {
		p.log.Info("operator registry refreshed",
			slog.Int("count", len(next.operators)),
			slog.Int("reachable", countReachable(next.operators)),
		)
		p.logUnderfundedIn(next.operators)
		return
	}

	for _, op := range next.operators {
		old, existed := prev.byNode[RefOf(op)]
		if !existed {
			p.log.Info("node added",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.String("base_url", op.BaseURL),
				slog.Bool("reachable", op.Reachable),
			)
			if op.SignerUnderfunded() {
				p.logSignerUnderfunded(op)
			}
			continue
		}
		switch was, is := old.SignerUnderfunded(), op.SignerUnderfunded(); {
		case !was && is:
			p.logSignerUnderfunded(op)
		case was && !is && op.SignerSpendableMicroAlgos == nil:
			// A rotated signer whose first read failed: nothing says it was
			// funded, only that it is no longer known to be broke.
			p.log.Info("node signing account balance is unknown (signer changed); routing to it again",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.String("signing_addr", op.SigningAddr),
			)
		case was && !is:
			p.log.Info("node signing account topped up; routing to it again",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.String("signing_addr", op.SigningAddr),
				slog.Uint64("signer_spendable_microalgos", *op.SignerSpendableMicroAlgos),
			)
		}
		if old.Reachable != op.Reachable {
			p.log.Info("node reachability changed",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.Bool("from", old.Reachable),
				slog.Bool("to", op.Reachable),
			)
		}
		if !stringSlicesEqual(old.Models, op.Models) {
			p.log.Info("node model list changed",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.Int("from_count", len(old.Models)),
				slog.Int("to_count", len(op.Models)),
			)
		}
		if !builtinToolTypesEqual(old.BuiltinTools, op.BuiltinTools) {
			p.log.Info("node builtin tools changed",
				slog.Uint64("operator_id", op.ID),
				slog.Uint64("node_id", op.NodeID),
				slog.Int("from_count", len(old.BuiltinTools)),
				slog.Int("to_count", len(op.BuiltinTools)),
			)
		}
	}
	for _, old := range prev.operators {
		if _, stillPresent := next.byNode[RefOf(old)]; !stillPresent {
			p.log.Info("node removed",
				slog.Uint64("operator_id", old.ID),
				slog.Uint64("node_id", old.NodeID),
				slog.String("base_url", old.BaseURL),
			)
		}
	}
}

// logSignerUnderfunded is WARN rather than Info because it silently removes
// models from this payer's catalog: without it, "why did my model vanish" has
// no answer in the proxy log.
func (p *DynamicRegistryProvider) logSignerUnderfunded(op Operator) {
	var spendable uint64
	if op.SignerSpendableMicroAlgos != nil {
		spendable = *op.SignerSpendableMicroAlgos
	}
	p.log.Warn("node signing account is below the routing floor; not routing to it until topped up",
		slog.Uint64("operator_id", op.ID),
		slog.Uint64("node_id", op.NodeID),
		slog.String("signing_addr", op.SigningAddr),
		slog.Uint64("signer_spendable_microalgos", spendable),
		slog.Uint64("floor_microalgos", selection.MinSignerSpendableMicroAlgos),
	)
}

func (p *DynamicRegistryProvider) logUnderfundedIn(ops []Operator) {
	for _, op := range ops {
		if op.SignerUnderfunded() {
			p.logSignerUnderfunded(op)
		}
	}
}

// Operators implements RegistryProvider. Triggers a lazy refresh when
// the snapshot is older than maxCacheAge.
func (p *DynamicRegistryProvider) Operators(ctx context.Context, model string) ([]Operator, error) {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return nil, fmt.Errorf("operator registry uninitialised")
	}
	out := make([]Operator, 0, len(snap.operators))
	for _, op := range snap.operators {
		if op.ServesModel(model) {
			out = append(out, op)
		}
	}
	return out, nil
}

// Resolve implements RegistryProvider. Triggers a lazy refresh when
// stale.
func (p *DynamicRegistryProvider) Resolve(ctx context.Context, operatorID, nodeID uint64) (Operator, error) {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return Operator{}, ErrOperatorUnknown
	}
	op, ok := snap.byNode[NodeRef{Op: operatorID, Node: nodeID}]
	if !ok {
		return Operator{}, ErrOperatorUnknown
	}
	return op, nil
}

// ephemeralReprober is the subset of OperatorSource that can re-probe a single
// operator's /v1/zs/details on demand. *ChainOperatorSource satisfies it;
// fake sources in tests need not — the dynamic registry then falls back to a
// plain re-check.
type ephemeralReprober interface {
	ReprobeEphemeral(ctx context.Context, all []Operator, target Operator) Operator
}

// The production source must keep satisfying ephemeralReprober — otherwise the
// type assertion in ReprobeEphemeral silently degrades to the no-op re-check and
// the dispatch self-heal stops working without a build break. (Mirrors the
// RelayLatency / RelayReputation assertions.)
var _ ephemeralReprober = (*ChainOperatorSource)(nil)

// ReprobeEphemeral implements RegistryProvider: it live-re-probes op's
// /v1/zs/details out of band from the scheduled refresh cycle to pick up a
// node's freshly-minted ephemeral recipient (e.g. after a restart), returning
// the refreshed operator and whether it can now seal. The refreshed value is
// deliberately NOT written back into the snapshot — the next scheduled refresh
// reconciles it; this only heals the in-flight request, so it never races the
// background snapshot swap. When the backing source can't re-probe (a non-chain
// test source) it falls back to re-checking the operator as-is.
func (p *DynamicRegistryProvider) ReprobeEphemeral(ctx context.Context, op Operator) (Operator, bool) {
	reprober, ok := p.source.(ephemeralReprober)
	if !ok {
		_, err := op.SealRecipient(time.Now())
		return op, err == nil
	}
	var all []Operator
	if snap := p.snap.Load(); snap != nil {
		all = snap.operators
	}
	refreshed := reprober.ReprobeEphemeral(ctx, all, op)
	_, err := refreshed.SealRecipient(time.Now())
	return refreshed, err == nil
}

// advertisable reports whether op's capabilities should surface on the discovery
// aggregates (/v1/models, /v1/zs/details, builtin tools). It is the ONE gate all
// of them share — deliberately, because a second near-synonymous predicate is how
// the next aggregate method comes to consult the wrong one. Four rules:
//
// 1. Staging. A node its operator flagged on-chain (NodeRecord.staging) is held
// out unless the payer opted in via zs.allow_staging. The proxy must advertise
// exactly what it routes to: SelectTargets' staging step already refuses these as
// targets, so listing their models promises capacity that dispatch then answers
// with 400 no_production_operator — and, more quietly, lets a staging node set the
// cross-operator context-window and "from $X" price floor for a model nobody can
// buy. Mirrors the client's picker (filterStaging in selection-adapter.ts).
//
// 2. Wire compatibility. A node on a different wire-protocol major can never be
// sealed for, so SelectTargets refuses it and the request ends in 400
// no_compatible_operator — the same advertise-then-refuse shape as staging. See
// wireIncompatible on why an empty ProtoVersion is correctly treated as
// incompatible here and cannot strand a node awaiting its first probe.
//
// 2b. Signer funding. A node whose signing account is known to be below the
// routing floor can't pay the fees of the open/settle it would sign, so
// SelectTargets refuses it and a model only it serves ends in 503
// no_funded_operator — the same advertise-then-refuse shape again. An unknown
// balance (nil) advertises, matching selection's fail-open.
//
// 3. Reachability. Under bounded probing most nodes aren't probed each cycle, so a
// raw Reachable gate would drop every un-probed-but-fine node. The rule splits on
// whether the node was actually probed this cycle:
//   - probed this cycle → trust the fresh result (Reachable). A node we just
//     confirmed down drops from discovery promptly, exactly as before.
//   - not probed this cycle → fall back to the carry window: advertise while its
//     last successful probe (ReachableAsOf) is within max_carry_age, so it stays
//     visible across the gaps between its probes and ages out once genuinely gone.
func (p *DynamicRegistryProvider) advertisable(op Operator, now time.Time) bool {
	if HeldOutStaging(op, p.allowStaging) || wireIncompatible(op) || op.SignerUnderfunded() {
		return false
	}
	if op.Probed {
		return op.Reachable
	}
	return !op.ReachableAsOf.IsZero() && now.Sub(op.ReachableAsOf) < p.maxCarryAge
}

// AllModels implements RegistryProvider. Triggers a lazy refresh when
// stale. Only nodes within the carry window (advertisable) contribute, so the
// discovery surface advertises models some node was recently confirmed to serve
// — carried-forward Models lists remain in the snapshot for Operators(model)'s
// benefit, but a model no node has reached within max_carry_age drops off.
func (p *DynamicRegistryProvider) AllModels(ctx context.Context) []string {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return nil
	}
	now := time.Now()
	seen := make(map[string]struct{})
	var out []string
	for _, op := range snap.operators {
		if !p.advertisable(op, now) {
			continue
		}
		for _, m := range op.Models {
			if _, ok := seen[m]; !ok {
				seen[m] = struct{}{}
				out = append(out, m)
			}
		}
	}
	return out
}

// AllBuiltinTools implements RegistryProvider. Triggers a lazy refresh
// when stale. Only nodes within the carry window contribute — see AllModels.
func (p *DynamicRegistryProvider) AllBuiltinTools(ctx context.Context) []BuiltinToolDef {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return nil
	}
	now := time.Now()
	seen := make(map[string]struct{})
	var out []BuiltinToolDef
	for _, op := range snap.operators {
		if !p.advertisable(op, now) {
			continue
		}
		for _, t := range op.BuiltinTools {
			if _, ok := seen[t.Type]; ok {
				continue
			}
			seen[t.Type] = struct{}{}
			out = append(out, t)
		}
	}
	return out
}

// AllNodeVersions implements RegistryProvider. Triggers a lazy refresh
// when stale.
func (p *DynamicRegistryProvider) AllNodeVersions(ctx context.Context) []string {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return nil
	}
	return collectNodeVersions(snap.operators, p.allowStaging)
}

// AllModelDetails implements RegistryProvider. Triggers a lazy refresh
// when stale. Only nodes within the carry window contribute — see AllModels.
func (p *DynamicRegistryProvider) AllModelDetails(ctx context.Context) []inject.OperatorDetailsModel {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return nil
	}
	now := time.Now()
	seen := make(map[string]*inject.OperatorDetailsModel)
	// Coordinates: collected here and folded in a second pass (mirrors the
	// static impl — the streaming merge below can't compute a mode). One vote
	// per reachable node, like the rest of this aggregate. Advisory.
	coordsByModel := make(map[string][]*inject.ModelCoordinates)
	// Collected for the cross-operator weights consensus/mismatch folded in the
	// second pass (mirrors coordsByModel; keep in sync with the static registry).
	digestsByModel := make(map[string][]string)
	// Model IDENTITY keys (declared HF source, else the frontier canonical),
	// consensus-folded in the second pass (mirrors the static registry).
	sourcesByModel := make(map[string][]string)
	canonicalsByModel := make(map[string][]string)
	for _, op := range snap.operators {
		if !p.advertisable(op, now) {
			continue
		}
		for _, m := range op.Models {
			cap := op.ModelCapacities[m]
			if cap.Coordinates != nil {
				coordsByModel[m] = append(coordsByModel[m], cap.Coordinates)
			}
			if cap.WeightsDigest != "" {
				digestsByModel[m] = append(digestsByModel[m], cap.WeightsDigest)
			}
			if cap.Source != "" {
				sourcesByModel[m] = append(sourcesByModel[m], cap.Source)
			}
			if cap.CanonicalID != "" {
				canonicalsByModel[m] = append(canonicalsByModel[m], cap.CanonicalID)
			}
			if existing, ok := seen[m]; ok {
				existing.InputModalities = unionStrings(existing.InputModalities, cap.InputModalities)
				existing.OutputModalities = unionStrings(existing.OutputModalities, cap.OutputModalities)
				existing.Tags = unionStrings(existing.Tags, cap.Tags)
				existing.ToolUse = aggregateBool(existing.ToolUse, cap.ToolUse)
				existing.Reasoning = aggregateReasoning(existing.Reasoning, cap.Reasoning)
				if cap.ContextWindow > 0 && (existing.ContextWindow == 0 || cap.ContextWindow < existing.ContextWindow) {
					existing.ContextWindow = cap.ContextWindow
				}
				if cap.MaxOutputTokens > 0 && (existing.MaxOutputTokens == 0 || cap.MaxOutputTokens < existing.MaxOutputTokens) {
					existing.MaxOutputTokens = cap.MaxOutputTokens
				}
				// Pricing: surface the cheapest declared rate across
				// operators (a "from $X" advertising number). The
				// authoritative per-request rate is whichever operator
				// actually serves the reserve, signed into the ticket.
				if cap.InputUSDPer1M > 0 && (existing.InputRateUSDPer1M == 0 || cap.InputUSDPer1M < existing.InputRateUSDPer1M) {
					existing.InputRateUSDPer1M = cap.InputUSDPer1M
				}
				if cap.OutputUSDPer1M > 0 && (existing.OutputRateUSDPer1M == 0 || cap.OutputUSDPer1M < existing.OutputRateUSDPer1M) {
					existing.OutputRateUSDPer1M = cap.OutputUSDPer1M
				}
				// Cache-read discount: lowest advertised across operators
				// ("from $X"), nil-preserving so a model no operator discounts
				// stays without a cache line.
				existing.CacheReadRateUSDPer1M = minRatePtr(existing.CacheReadRateUSDPer1M, cap.CacheReadUSDPer1M)
				// Long-context (surcharge) tier: display-only cross-operator min,
				// mirroring registry.go's AllModelDetails — lowest threshold among
				// tier-advertising operators and lowest of each high rate. Per-operator
				// values stay intact on op.ModelCapacities (that is what
				// verifyReservePrice uses); this aggregate is discovery display only.
				existing.LongContextThresholdTokens = minNonZero(existing.LongContextThresholdTokens, cap.LongContextThresholdTokens)
				existing.LongContextInputRateUSDPer1M = minRatePtr(existing.LongContextInputRateUSDPer1M, cap.LongContextInputUSDPer1M)
				existing.LongContextOutputRateUSDPer1M = minRatePtr(existing.LongContextOutputRateUSDPer1M, cap.LongContextOutputUSDPer1M)
				existing.LongContextCacheReadRateUSDPer1M = minRatePtr(existing.LongContextCacheReadRateUSDPer1M, cap.LongContextCacheReadUSDPer1M)
				// Image factors: surface the lowest declared (non-zero)
				// value across operators — consistent with the rate
				// fields' "from $X" semantics. Absence on every operator
				// means the model is not wired for that endpoint.
				if cap.ImageToolRateMicroUSDC > 0 && (existing.ImageToolRateMicroUSDC == 0 || cap.ImageToolRateMicroUSDC < existing.ImageToolRateMicroUSDC) {
					existing.ImageToolRateMicroUSDC = cap.ImageToolRateMicroUSDC
				}
				if cap.ImageEditToolRateMicroUSDC > 0 && (existing.ImageEditToolRateMicroUSDC == 0 || cap.ImageEditToolRateMicroUSDC < existing.ImageEditToolRateMicroUSDC) {
					existing.ImageEditToolRateMicroUSDC = cap.ImageEditToolRateMicroUSDC
				}
				if cap.ImageRateMicroUSDC > 0 && (existing.ImageRateMicroUSDC == 0 || cap.ImageRateMicroUSDC < existing.ImageRateMicroUSDC) {
					existing.ImageRateMicroUSDC = cap.ImageRateMicroUSDC
				}
				if cap.ImageEditRateMicroUSDC > 0 && (existing.ImageEditRateMicroUSDC == 0 || cap.ImageEditRateMicroUSDC < existing.ImageEditRateMicroUSDC) {
					existing.ImageEditRateMicroUSDC = cap.ImageEditRateMicroUSDC
				}
				// Display-only companions (representative price at the operator's
				// default size, and its per-image ceiling) — same rule; see the
				// coherence note in registry.go's AllModelDetails.
				existing.ImageToolBaseMicroUSDC = minNonZero(existing.ImageToolBaseMicroUSDC, cap.ImageToolBaseMicroUSDC)
				existing.ImageEditToolBaseMicroUSDC = minNonZero(existing.ImageEditToolBaseMicroUSDC, cap.ImageEditToolBaseMicroUSDC)
				existing.ImageDefaultMicroUSDC = minNonZero(existing.ImageDefaultMicroUSDC, cap.ImageDefaultMicroUSDC)
				existing.ImageEditDefaultMicroUSDC = minNonZero(existing.ImageEditDefaultMicroUSDC, cap.ImageEditDefaultMicroUSDC)
				existing.ImageCapMicroUSDC = minNonZero(existing.ImageCapMicroUSDC, cap.ImageCapMicroUSDC)
				existing.ImageEditCapMicroUSDC = minNonZero(existing.ImageEditCapMicroUSDC, cap.ImageEditCapMicroUSDC)
				// Eligibility is price-independent (free rate routes advertise a 0
				// rate): any operator serving the route makes the aggregate serve it.
				if cap.ServesImageGen() {
					existing.ServesImageGen = true
				}
				if cap.ServesImageEdit() {
					existing.ServesImageEdit = true
				}
			} else {
				seen[m] = &inject.OperatorDetailsModel{
					ID:                               m,
					ContextWindow:                    cap.ContextWindow,
					MaxOutputTokens:                  cap.MaxOutputTokens,
					InputModalities:                  append([]string(nil), cap.InputModalities...),
					OutputModalities:                 append([]string(nil), cap.OutputModalities...),
					InputRateUSDPer1M:                cap.InputUSDPer1M,
					OutputRateUSDPer1M:               cap.OutputUSDPer1M,
					CacheReadRateUSDPer1M:            minRatePtr(nil, cap.CacheReadUSDPer1M),
					LongContextThresholdTokens:       cap.LongContextThresholdTokens,
					LongContextInputRateUSDPer1M:     minRatePtr(nil, cap.LongContextInputUSDPer1M),
					LongContextOutputRateUSDPer1M:    minRatePtr(nil, cap.LongContextOutputUSDPer1M),
					LongContextCacheReadRateUSDPer1M: minRatePtr(nil, cap.LongContextCacheReadUSDPer1M),
					Reasoning:                        aggregateReasoning(nil, cap.Reasoning),
					ToolUse:                          aggregateBool(nil, cap.ToolUse),
					Tags:                             append([]string(nil), cap.Tags...),
					ImageToolRateMicroUSDC:           cap.ImageToolRateMicroUSDC,
					ImageEditToolRateMicroUSDC:       cap.ImageEditToolRateMicroUSDC,
					ImageToolBaseMicroUSDC:           cap.ImageToolBaseMicroUSDC,
					ImageEditToolBaseMicroUSDC:       cap.ImageEditToolBaseMicroUSDC,
					ImageRateMicroUSDC:               cap.ImageRateMicroUSDC,
					ImageEditRateMicroUSDC:           cap.ImageEditRateMicroUSDC,
					ImageDefaultMicroUSDC:            cap.ImageDefaultMicroUSDC,
					ImageEditDefaultMicroUSDC:        cap.ImageEditDefaultMicroUSDC,
					ImageCapMicroUSDC:                cap.ImageCapMicroUSDC,
					ImageEditCapMicroUSDC:            cap.ImageEditCapMicroUSDC,
					ServesImageGen:                   cap.ServesImageGen(),
					ServesImageEdit:                  cap.ServesImageEdit(),
				}
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	for m, d := range seen {
		d.Coordinates = aggregateCoordinates(coordsByModel[m])
		d.WeightsDigest, d.WeightsMismatch = aggregateDigest(digestsByModel[m])
		d.Source = aggregateSource(sourcesByModel[m])
		// canonical_id only rides when there is no source (mirror the node's
		// per-model rule and the static registry).
		if d.Source == "" {
			d.CanonicalID = aggregateIdentity(canonicalsByModel[m])
		}
	}
	out := make([]inject.OperatorDetailsModel, 0, len(seen))
	for _, d := range seen {
		out = append(out, *d)
	}
	return out
}

// AllOperators implements RegistryProvider. Triggers a lazy refresh
// when stale. Returns a copy of the snapshot's operator slice so the
// caller can iterate without holding a reference into the registry's
// internal state.
//
// Deliberately NOT staging-filtered, unlike the aggregates above: the proxy
// builds its relay pool from this (Server.relayPool), and SPEC's staging gate
// covers target selection only — a relay forwards bytes and runs no inference, so
// a staging node is a perfectly good hop and excluding it would shrink the pool
// SPEC §3f diffusion depends on. Callers that want the payer-facing production
// view apply zs.allow_staging themselves; handleOperators does.
func (p *DynamicRegistryProvider) AllOperators(ctx context.Context) []Operator {
	p.ensureFresh(ctx)
	snap := p.snap.Load()
	if snap == nil {
		return nil
	}
	return append([]Operator(nil), snap.operators...)
}

// SnapshotAge returns how long ago the current snapshot was fetched.
// Returns the sentinel -1 when no snapshot has been loaded yet. Used
// by tests and by /healthz-style introspection.
func (p *DynamicRegistryProvider) SnapshotAge() time.Duration {
	snap := p.snap.Load()
	if snap == nil {
		return -1
	}
	return time.Since(snap.fetchedAt)
}

// buildSnapshot validates and constructs an immutable snapshot from
// the given operators. Mirrors NewStaticRegistryProvider's constraints:
// non-zero IDs, no duplicates.
func buildSnapshot(ops []Operator) (*registrySnapshot, error) {
	byNode := make(map[NodeRef]Operator, len(ops))
	for _, op := range ops {
		if op.ID == 0 {
			return nil, fmt.Errorf("operator missing id (0 is reserved)")
		}
		ref := RefOf(op)
		if _, dup := byNode[ref]; dup {
			return nil, fmt.Errorf("duplicate node %d/%d", op.ID, op.NodeID)
		}
		byNode[ref] = op
	}
	return &registrySnapshot{
		operators: append([]Operator(nil), ops...),
		byNode:    byNode,
		fetchedAt: time.Now(),
	}, nil
}

func countReachable(ops []Operator) int {
	n := 0
	for _, op := range ops {
		if op.Reachable {
			n++
		}
	}
	return n
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	ac := append([]string(nil), a...)
	bc := append([]string(nil), b...)
	sort.Strings(ac)
	sort.Strings(bc)
	for i := range ac {
		if ac[i] != bc[i] {
			return false
		}
	}
	return true
}

func builtinToolTypesEqual(a, b []BuiltinToolDef) bool {
	if len(a) != len(b) {
		return false
	}
	aTypes := make([]string, len(a))
	bTypes := make([]string, len(b))
	for i := range a {
		aTypes[i] = a[i].Type
	}
	for i := range b {
		bTypes[i] = b[i].Type
	}
	return stringSlicesEqual(aTypes, bTypes)
}
