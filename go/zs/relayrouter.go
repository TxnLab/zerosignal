/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"crypto/rand"
	"encoding/binary"
	"net/http"
	"net/url"
	"sort"

	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

// RelayHop identifies the relay an outbound operator request is routed through
// in transport-privacy mode (SPEC.md § 3f). A nil *RelayHop means "send
// directly to the target" — the pre-relay behavior.
type RelayHop struct {
	// BaseURL is the relay node's root (where RelayPath lives).
	BaseURL string
	// TargetID / TargetNodeID are the destination's on-chain operator id and
	// node id; the relay resolves the pair to a base URL via its own
	// directory (we never send the target URL).
	TargetID     uint64
	TargetNodeID uint64
	// RelayID / RelayNodeID are the relay's own on-chain (operator id, node id)
	// pair. Not needed to address the hop (BaseURL does that) — they're carried
	// for observability so request logs can name the exact relay node that
	// tunneled a request, paired with the target's (operator_id, node_id) on the
	// same line (see the proxy's relayAttr helper). A relay is a single node, so
	// it is identified by the pair just like any other routing target.
	RelayID     uint64
	RelayNodeID uint64
	// RelayProtoVersion is the proto_version this relay node ADVERTISED at
	// discovery, carried on the hop so a response-attribution site can gate the
	// wire.RelayHopHeader rule (wire.SetsRelayHopHeader) without reaching back
	// into the registry mid-request.
	//
	// It must be the advertised value, never a bootstrap-seeded one: seeding an
	// unprobed peer with the full build version would make it read as
	// marker-capable and charge it for a header nobody established it could
	// set. buildSelAll seeds wire.BootstrapProtoVersion() precisely so this
	// stays honest — see that function and wire.BootstrapProtoVersion.
	RelayProtoVersion string
}

// RelayRef is the relay node's (operator id, node id) key — how the proxy's
// reachability and relay-reputation stores address it. A relay is a single node,
// so reliability state keys on the pair, never the operator id alone.
func (h *RelayHop) RelayRef() NodeRef { return NodeRef{Op: h.RelayID, Node: h.RelayNodeID} }

// TargetRef is the destination node's (operator id, node id) key.
func (h *RelayHop) TargetRef() NodeRef { return NodeRef{Op: h.TargetID, Node: h.TargetNodeID} }

// latencyWeightBiasMS is the additive bias in the inverse-latency weight
// 1/(latency+bias). It keeps a near-zero latency from producing a runaway weight
// and dampens the bias between already-fast relays (5ms vs 10ms shouldn't be a 2×
// preference — with bias 50 it's 55 vs 60), so weighting only meaningfully
// separates relays that differ by a lot. Mirror of the client's
// LATENCY_WEIGHT_BIAS_MS. Tunable.
const latencyWeightBiasMS = 50.0

// latencyFloorFraction is the uniform-mixing floor (mirror of the client's
// LATENCY_FLOOR_FRACTION): the fraction of selection mass spread evenly across
// ALL eligible relays regardless of latency, so weighting can never fully starve
// one. It caps any relay's per-request share at
// ~(1-latencyFloorFraction)+latencyFloorFraction/n and floors every relay at
// latencyFloorFraction/n — what keeps the SPEC § 3f anti-profiling diffusion
// meaningful under a large latency gap (without it a 100×-faster relay would take
// ~98% of traffic).
//
// Tuning to a target ceiling. That cap is also the MOST a single relay can
// capture even if it games its measured RTT (answers probes/reserves fast) to
// pull a target's traffic toward itself — so the floor doubles as the § 3f
// adversarial capture bound. To hold any one relay to at most a fraction C of a
// target's requests:
//
//	latencyFloorFraction ≈ (1 − C) · n/(n−1)   (needs C ≥ 1/n — you can't cap
//	                                             below uniform; clamp to ≤ 1)
//
//	ceiling C │ n=4   n=10  n=100    e.g. 100 relays, ≤25% each → FLOOR ≈ 0.76
//	   25%    │ 1.00  0.83  0.76     (≤50% → ~0.51, ≤75% → ~0.25).
//	   50%    │ 0.67  0.56  0.51
//	   75%    │ 0.33  0.28  0.25
//
// The 0.15 default is latency-first (ceiling ≈ 0.85 + 0.15/n ≈ 85–93%): fine when
// you trust relays not to game RTT, loose if you don't. Two caveats: (1) the
// ceiling is a WORST case — only approached when one relay is far faster than ALL
// others; with a normal latency spread the busiest relay sits well below it (a
// handful of percent at n=100). (2) A tight ceiling at large n forces FLOOR ≈ 1−C,
// which largely cancels the latency bias — this single knob can't deliver both a
// tight cap and strong latency preference (a hard per-relay probability cap would,
// but isn't built). Tunable — raise to favor diffusion, lower to favor latency.
const latencyFloorFraction = 0.15

// SelectRelayHopWeighted picks a relay hop for an already-chosen target. Eligibility
// + diversity come from the shared selection.EligibleRelays policy (relay ≠ target,
// owner-key diversity, version-compatible, best-effort /16, reachable-preferred —
// not duplicated here, so it can't drift from the /16 + owner-key guards); the pick
// within that eligible pool is a latency-weighted seeded draw (weightedRelayPick)
// instead of plain pool[seed % len], biasing toward fast relays while keeping
// bounded rotation. seed selects/rotates per request (pass RandomRelaySeed()).
// latencyOf returns the relay's latency for the current target (ok=false when
// unknown). Returns selection.ErrNoRelay when no operator qualifies — callers MUST
// hard-fail rather than route direct. Mirror of the client's selectRelayHopWeighted.
func SelectRelayHopWeighted(allSel []selection.Operator, target selection.Operator, seed uint64, latencyOf func(relay NodeRef) (float64, bool)) (*RelayHop, error) {
	pool := selection.EligibleRelays(allSel, target)
	if len(pool) == 0 {
		return nil, selection.ErrNoRelay
	}
	relay := weightedRelayPick(pool, seed, latencyOf)
	return &RelayHop{
		BaseURL:           relay.BaseURL,
		TargetID:          target.ID,
		TargetNodeID:      target.NodeID,
		RelayID:           relay.ID,
		RelayNodeID:       relay.NodeID,
		RelayProtoVersion: relay.ProtoVersion,
	}, nil
}

// weightedRelayPick picks from an already-eligible, (id, node_id)-sorted pool,
// biasing toward faster relays while still SPREADING across them (so no single
// relay accumulates a session-long client→target profile — the anti-profiling
// property of plain seed rotation, preserved but weighted). Weight = 1/(latency +
// bias). A relay with no sample yet gets the MEDIAN of the known weights —
// "average", so cold relays keep being sampled (explore) rather than buried or
// blindly favored. The weighted distribution is then mixed with uniform by
// latencyFloorFraction so no relay is starved and the fastest can't exceed
// ~(1-FLOOR)+FLOOR/n of the mass — the floor that keeps SPEC § 3f diffusion
// meaningful under a large latency gap. When NOTHING is known the pick is exactly
// pool[seed % len], so a cold proxy behaves identically to before until latency
// data warms.
func weightedRelayPick(pool []selection.Operator, seed uint64, latencyOf func(relay NodeRef) (float64, bool)) selection.Operator {
	lats := make([]float64, len(pool))
	hasLat := make([]bool, len(pool))
	var known []float64
	for i, op := range pool {
		if ms, ok := latencyOf(NodeRef{Op: op.ID, Node: op.NodeID}); ok {
			lats[i], hasLat[i] = ms, true
			known = append(known, 1/(ms+latencyWeightBiasMS))
		}
	}
	if len(known) == 0 {
		return pool[seed%uint64(len(pool))]
	}
	explore := medianFloat(known)
	weights := make([]float64, len(pool))
	rawTotal := 0.0
	for i := range pool {
		if hasLat[i] {
			weights[i] = 1 / (lats[i] + latencyWeightBiasMS)
		} else {
			weights[i] = explore
		}
		rawTotal += weights[i]
	}
	// Mix with uniform by the floor: w' = (1-FLOOR)·w + FLOOR·(rawTotal/n). This
	// preserves the sum (draw unchanged) while flooring every relay's share at
	// FLOOR/n and capping the fastest at ~(1-FLOOR)+FLOOR/n.
	uniform := rawTotal / float64(len(pool))
	total := 0.0
	for i := range weights {
		weights[i] = (1-latencyFloorFraction)*weights[i] + latencyFloorFraction*uniform
		total += weights[i]
	}
	// Deterministic draw from the per-request seed (uint64 → uniform [0,1)).
	r := (float64(seed) / float64(1<<64)) * total
	acc := 0.0
	for i := range pool {
		acc += weights[i]
		if r < acc {
			return pool[i]
		}
	}
	return pool[len(pool)-1]
}

// medianFloat returns the median of xs (xs is non-empty at every call site).
func medianFloat(xs []float64) float64 {
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// RandomRelaySeed returns a fresh cryptographically-random uint64 for relay
// rotation. On the (practically impossible) crypto/rand failure it returns 0,
// which still yields a valid pick (the lowest-id eligible relay) — never a
// panic on the request hot path.
func RandomRelaySeed() uint64 {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0
	}
	return binary.BigEndian.Uint64(b[:])
}

// ApplyRelay rewrites req in place to route an inner request through hop: it
// repoints the URL at the relay's RelayPath, forces POST (the relay route is
// always POSTed regardless of the inner method), and adds the X-Zs-Relay-*
// headers identifying the inner request. The request body and inner
// Content-Type are preserved — the relay forwards them verbatim. A nil hop is
// a no-op, so callers can unconditionally call this and let the hop decide.
//
// innerPath/innerMethod describe the inner request the relay reconstructs
// against the target (e.g. "/v1/zs/reserve", "POST").
func ApplyRelay(req *http.Request, hop *RelayHop, innerPath, innerMethod string) error {
	if hop == nil {
		return nil
	}
	rr := protorelay.BuildRequest(hop.BaseURL, hop.TargetID, hop.TargetNodeID, innerPath, innerMethod)
	u, err := url.Parse(rr.URL)
	if err != nil {
		return err
	}
	req.URL = u
	req.Host = u.Host
	req.Method = http.MethodPost
	req.Header.Set(wire.RelayTargetHeader, rr.Target)
	req.Header.Set(wire.RelayTargetNodeHeader, rr.TargetNode)
	req.Header.Set(wire.RelayPathHeader, rr.Path)
	req.Header.Set(wire.RelayMethodHeader, rr.Method)
	return nil
}
