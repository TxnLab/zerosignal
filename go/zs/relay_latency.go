/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import "time"

// RelayLatency is the proxy's per-process, client-observed network-RTT store —
// the "how fast" signal that complements the "can I reach it" signals
// (lastReachable, RelayReputation). The proxy is a localhost single-user (payer)
// process, so this is genuinely the payer's own vantage on the mesh, the exact
// analog of the TS SDK's RelayLatencyStore (sdk/src/routing/latency.ts) — same
// EWMA, same three keyings, same staleness gate, same eviction. It lets
// relayHopFor prefer relays that are fast FOR A GIVEN TARGET and pickCandidates
// demote pathologically-slow targets, as the fleet grows and paths diverge.
//
// Why it lives here and not in the shared proto selection policy: latency is
// stateful/per-process and vantage-specific, so it is not a pure function of the
// static inputs the golden vectors pin — it can't be golden-vectored, so (like
// RelayReputation and lastReachable) it stays an app-side refinement layered over
// the pure SelectRelay/SelectTargets ordering. Fed only by SUCCESSFUL,
// pre-/no-inference round-trips (the /v1/zs/details probe and the reserve POST
// — clean network RTT, no model time). Both sources blend into one EWMA per key:
// they do slightly different server-side work (reserve signs a ticket; details is
// a cheap GET) but both are network-dominated, and we only need coarse relative
// ranking + an outlier gate, so the small constant offset doesn't change ordering.
// Keyed by the NODE's (operator id, node id) NodeRef, never operator id alone.
//
// Three keyings, all updated by one relayed sample; a direct sample updates only
// the target:
//   - PAIR   (relay,target) — full browser→relay→target→back path. Primary "which
//     relay is fastest for this target" signal.
//   - RELAY  relay node      — the relay endpoint leg, aggregated over the targets
//     it forwarded for. Fallback when a specific pair has no sample yet.
//   - TARGET target node     — aggregate RTT to a target over all relays + direct.
//     Drives the target slow-outlier demote.
type RelayLatency interface {
	// RecordRelayedRTT folds one successful relayed round-trip into the pair,
	// relay-endpoint, and target keyings.
	RecordRelayedRTT(relay, target NodeRef, d time.Duration)
	// RecordDirectRTT folds one successful direct (privacy-off) round-trip into
	// the target keying only — there is no relay leg to attribute.
	RecordDirectRTT(target NodeRef, d time.Duration)
	// RelayLatencyForTarget is the estimate for routing through relay TO target:
	// the specific pair when known, else the relay endpoint aggregate, else
	// (0, false) — the caller treats unknown as "explore".
	RelayLatencyForTarget(relay, target NodeRef) (ms float64, ok bool)
	// TargetLatency is a target's aggregate EWMA plus its sample count (so the
	// demote pass can require LatencyMinSamples of confidence before reordering),
	// or (0, 0, false) when no fresh sample.
	TargetLatency(target NodeRef) (ewmaMs float64, samples int, ok bool)
}

const (
	// latencyEWMAAlpha weights each new sample at 30%, damping a one-off spike (a
	// 429-backoff-inflated reserve, a GC pause) while letting a real shift settle
	// in a few samples. Mirror of the client's LATENCY_EWMA_ALPHA.
	latencyEWMAAlpha = 0.3
	// latencyStaleAfter: a sample older than this is untrusted — readers return
	// (prune) it and a new sample restarts the EWMA rather than blending across a
	// gap. It equals the default refresh interval, so a sample from the discovery probe
	// alone goes stale around the node's next probe, and stays stale while
	// bounded probing skips the node. Reserve round-trips are what keep a path in
	// use warm; a path we stopped using ages out within minutes.
	latencyStaleAfter = 5 * time.Minute
	// LatencyMinSamples is the confidence floor for a *demotion* decision (the
	// target slow-outlier pass). One sample is too noisy to reorder on; the relay
	// weighting tolerates a single sample because it only biases, never excludes.
	LatencyMinSamples = 2
	// DefaultLatencyStateMax caps each latency EWMA map's live entry count when
	// ChainOperatorSource.LatencyStateMax is unset. The pair map is the O(n²) one
	// (relay×target); this bounds its worst-case footprint under fleet churn on top
	// of the staleness prune. High enough that normal single-payer operation never
	// hits it.
	DefaultLatencyStateMax = 4096
)

// latStat is one EWMA estimate: the smoothed RTT in ms, how many samples back it,
// and when last updated (for the staleness gate).
type latStat struct {
	ewmaMs  float64
	samples int
	at      time.Time
}

// pairKey addresses a (relay, target) pair. Both NodeRefs are comparable structs,
// so the pair is a valid map key.
type pairKey struct {
	relay  NodeRef
	target NodeRef
}

// latNow returns the clock used for latency staleness. latClock is nil in
// production (→ time.Now) and set by tests to drive the staleness gate
// deterministically; it lives per-source so parallel tests don't share it.
func (s *ChainOperatorSource) latNow() time.Time {
	if s.latClock != nil {
		return s.latClock()
	}
	return time.Now()
}

// observe folds one sample into an EWMA map entry. A missing or stale prior
// restarts the average from this sample (samples = 1) rather than blending across
// a gap. The map must be non-nil (callers lazy-init under the lock).
func observe[K comparable](m map[K]latStat, key K, d time.Duration, now time.Time) {
	ms := float64(d.Microseconds()) / 1000.0
	if ms < 0 {
		return
	}
	prev, ok := m[key]
	if !ok || now.Sub(prev.at) > latencyStaleAfter {
		m[key] = latStat{ewmaMs: ms, samples: 1, at: now}
		return
	}
	m[key] = latStat{
		ewmaMs:  latencyEWMAAlpha*ms + (1-latencyEWMAAlpha)*prev.ewmaMs,
		samples: prev.samples + 1,
		at:      now,
	}
}

// readFresh returns a stat if present and within the staleness window, pruning it
// otherwise so the map self-trims. Safe on a nil map (read/delete are no-ops).
func readFresh[K comparable](m map[K]latStat, key K, now time.Time) (latStat, bool) {
	st, ok := m[key]
	if !ok {
		return latStat{}, false
	}
	if now.Sub(st.at) > latencyStaleAfter {
		delete(m, key)
		return latStat{}, false
	}
	return st, true
}

// latStateMax resolves the per-map live-entry cap (DefaultLatencyStateMax when
// unset). Callers hold latMu.
func (s *ChainOperatorSource) latStateMax() int {
	if s.LatencyStateMax > 0 {
		return s.LatencyStateMax
	}
	return DefaultLatencyStateMax
}

// evictOversize bounds a latency map to cap live entries. It first reclaims dead
// weight (entries past the staleness window — normally enough), then, only if the
// live set still exceeds cap, evicts oldest-by-timestamp until at cap. Runs only
// when len(m) > cap, so the steady-state (under cap) cost is a single length
// check. The map's latStat.at drives both passes. Callers hold latMu.
func evictOversize[K comparable](m map[K]latStat, maxLive int, now time.Time) {
	if maxLive <= 0 || len(m) <= maxLive {
		return
	}
	for k, st := range m {
		if now.Sub(st.at) > latencyStaleAfter {
			delete(m, k)
		}
	}
	for len(m) > maxLive {
		var oldestK K
		var oldestAt time.Time
		first := true
		for k, st := range m {
			if first || st.at.Before(oldestAt) {
				oldestK, oldestAt, first = k, st.at, false
			}
		}
		delete(m, oldestK)
	}
}

// RecordRelayedRTT implements RelayLatency. Safe for concurrent use (called from
// the discovery enrich goroutines and the inference request goroutines).
func (s *ChainOperatorSource) RecordRelayedRTT(relay, target NodeRef, d time.Duration) {
	now := s.latNow()
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if s.pairLat == nil {
		s.pairLat = make(map[pairKey]latStat)
	}
	if s.relayLat == nil {
		s.relayLat = make(map[NodeRef]latStat)
	}
	if s.targetLat == nil {
		s.targetLat = make(map[NodeRef]latStat)
	}
	observe(s.pairLat, pairKey{relay: relay, target: target}, d, now)
	observe(s.relayLat, relay, d, now)
	observe(s.targetLat, target, d, now)
	maxLive := s.latStateMax()
	evictOversize(s.pairLat, maxLive, now)
	evictOversize(s.relayLat, maxLive, now)
	evictOversize(s.targetLat, maxLive, now)
}

// RecordDirectRTT implements RelayLatency. Safe for concurrent use.
func (s *ChainOperatorSource) RecordDirectRTT(target NodeRef, d time.Duration) {
	now := s.latNow()
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if s.targetLat == nil {
		s.targetLat = make(map[NodeRef]latStat)
	}
	observe(s.targetLat, target, d, now)
	evictOversize(s.targetLat, s.latStateMax(), now)
}

// RelayLatencyForTarget implements RelayLatency. Safe for concurrent use.
func (s *ChainOperatorSource) RelayLatencyForTarget(relay, target NodeRef) (float64, bool) {
	now := s.latNow()
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if st, ok := readFresh(s.pairLat, pairKey{relay: relay, target: target}, now); ok {
		return st.ewmaMs, true
	}
	if st, ok := readFresh(s.relayLat, relay, now); ok {
		return st.ewmaMs, true
	}
	return 0, false
}

// TargetLatency implements RelayLatency. Safe for concurrent use.
func (s *ChainOperatorSource) TargetLatency(target NodeRef) (float64, int, bool) {
	now := s.latNow()
	s.latMu.Lock()
	defer s.latMu.Unlock()
	if st, ok := readFresh(s.targetLat, target, now); ok {
		return st.ewmaMs, st.samples, true
	}
	return 0, 0, false
}

var _ RelayLatency = (*ChainOperatorSource)(nil)
