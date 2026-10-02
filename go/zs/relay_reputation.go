/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"time"

	"github.com/TxnLab/zerosignal/go/steering"
)

// The thresholds, cooldowns, and decay arithmetic are steering's, golden-vectored
// against its TS twin in proto/ts/src/steering. client/src/operators/
// relay-reputation.ts still carries its own copy until it adopts that module, so
// a change here must be made there by hand until then. What stays here
// is the store: which streak a given piece of evidence lands on, and the
// reachability differential that decides whether it lands at all. Those depend
// on what THIS process has observed, so they can't be shared.
//
// The downrank is soft: a demoted relay drops to the fallback tier, never
// hard-excluded, so the cold-start fallback (SelectRelay falls back to the full
// eligible set when none are preferred) is preserved.
//
// Each streak ages by its own cooldown, matched to its EVIDENCE RATE:
// steering.RelayReputationCooldown for the two probe-fed streaks, the 6x longer
// steering.RelayTimeoutCooldown for the one with no probe feeder. The failure
// streak is fed by probeDetailsWithRetry every DefaultRefreshInterval (5m); the
// timeout streak only by paid inferences that failed, which
// SelectRelayHopWeighted spreads across the whole pool.

func (s *ChainOperatorSource) relayRepNow() time.Time {
	if s.relayRepClock != nil {
		return s.relayRepClock()
	}
	return time.Now()
}

func bumpRelayReputation(m map[NodeRef]steering.Evidence, relay NodeRef, now time.Time, cooldown time.Duration) map[NodeRef]steering.Evidence {
	if m == nil {
		m = make(map[NodeRef]steering.Evidence)
	}
	m[relay] = steering.Bump(m[relay], now, cooldown)
	return m
}

// pruneAndReadRelayReputation returns the surviving streak, writing back the
// aged entry (or deleting one whose evidence has fully decayed). It runs once
// per relay per relayPool build, which is per request; steering.Decay is
// idempotent at one instant, so that doesn't compound. The caller must hold
// relayRepMu.
func pruneAndReadRelayReputation(m map[NodeRef]steering.Evidence, relay NodeRef, now time.Time, cooldown time.Duration) int {
	e, ok := m[relay]
	if !ok {
		return 0
	}
	decayed, alive := steering.Decay(e, now, cooldown)
	if !alive {
		delete(m, relay)
		return 0
	}
	// Count changes exactly when At did, so this skips the write on the common
	// path where no whole cooldown has elapsed.
	if decayed.Count != e.Count {
		m[relay] = decayed
	}
	return decayed.Count
}

// RelayReputation is the proxy's soft, per-relay reliability signal: it tracks
// whether *forwards through* an operator (used as a transport-privacy relay)
// succeed, distinct from the per-operator Reachable bool (the operator's own
// target-probe health). The inference path reports outcomes here; relay
// selection consults RelayDownranked to deprioritize — never hard-exclude — a
// relay that systematically drops forwards. This is what catches a
// non-compliant 3.0 fork that advertises the relay route (so it stays a valid
// target) but strips the forwarding path: every forward through it either fails
// loudly (a hop error → RecordRelayOutcome) or is black-holed behind a
// relay_upstream_unreachable claim it can't substantiate (the differential
// RecordRelayUpstreamUnreachable below), so its failure streak climbs and it
// gets downranked.
//
// Every method keys by the relay's (operator id, node id) NodeRef, never the
// operator id alone: a relay is a single node (operator/node split — see the
// repo AGENTS.md), so one operator's nodes have independent reliability. Keying
// by operator id alone would let a healthy sibling node's success reset (or a
// dead sibling's failures inflate) a streak that belongs to a different
// endpoint, and would re-tier every node of an operator off whichever node was
// probed last.
type RelayReputation interface {
	// RecordRelayOutcome notes whether a forward through the relay node succeeded.
	// A success resets that node's failure streak; a failure increments it.
	RecordRelayOutcome(relay NodeRef, ok bool)
	// RecordRelayUpstreamUnreachable records a relay's claim (a
	// relay_upstream_unreachable response) that target was down. That code is
	// the one relay error attributed to the *target* rather than the relay, so a
	// non-compliant fork could otherwise black-hole every forward behind it and
	// never accrue a streak. The store resolves the ambiguity differentially: a
	// claim about a target we independently observed reachable this cycle (its
	// own details probe succeeded, possibly via another relay) is contradicted
	// and counts against the relay; an uncorroborated claim about a possibly-dead
	// target credits the relay, so an honest forwarder isn't punished for a
	// target that really is down.
	RecordRelayUpstreamUnreachable(relay, target NodeRef)
	// RecordRelayForwardedTargetFault records that a relay which PROVABLY ran
	// its handler (it stamped wire.RelayHopHeader) returned a code-less
	// transient status — so the status is nominally the target's. Resolved
	// differentially like RecordRelayUpstreamUnreachable but PENALTY-ONLY: a
	// claim contradicted by our own probes counts against the relay, and an
	// uncorroborated one records nothing rather than crediting. See the
	// implementation for why this one may not credit.
	RecordRelayForwardedTargetFault(relay, target NodeRef)
	// RecordRelayStaleEphemeral notes that the relay node served a hard-valid but
	// stale ephemeral advertisement (older than ticket.FreshnessTarget) for some
	// target — i.e. it replayed an older key block than the target should have.
	// It increments a SEPARATE staleness streak (not the forward-failure streak):
	// a stale block still forwarded successfully, so the same-cycle forward
	// credit (RecordRelayOutcome(relay, true), fired by the discovery probe)
	// must not reset the staleness signal. A relay that only ever serves stale
	// blocks crosses steering.RelayDownrankThreshold into the fallback tier.
	RecordRelayStaleEphemeral(relay NodeRef)
	// RecordRelayFreshEphemeral clears the relay node's staleness streak — called
	// when it served a fresh (in-FreshnessTarget) ephemeral block, so a relay
	// fronting an honest, rotating node isn't penalized once it recovers. It
	// does NOT touch the forward-failure streak.
	RecordRelayFreshEphemeral(relay NodeRef)
	// RecordRelayForwardTimeout records that a forward through the relay died
	// with a gateway timeout (steering.IsForwardTimeoutStatus) that the shared
	// verdict left unattributed. It increments a THIRD streak, separate from
	// both of the above, and is penalty-only with the same differential guard as
	// RecordRelayForwardedTargetFault. See the implementation for why it must be
	// its own streak and why it may never credit.
	RecordRelayForwardTimeout(relay, target NodeRef)
	// RelayDownranked reports whether the relay node has accrued enough
	// consecutive forward failures OR stale-ephemeral advertisements
	// (steering.RelayDownrankThreshold, either streak) — or enough unattributed forward
	// timeouts (steering.RelayTimeoutDownrankThreshold) — to be deprioritized in relay
	// selection.
	//
	// Despite the read-shaped name this is the aging seam, and an implementation
	// backed by accrued evidence is expected to MUTATE here: a downranked relay
	// stops being selected, so it never earns the success that would clear it,
	// and a call is the only occasion to notice that time has passed. Callers may
	// treat it as a query; implementers may not assume it is one.
	RelayDownranked(relay NodeRef) bool
}

// RecordRelayOutcome implements RelayReputation. Safe for concurrent use
// (called from the discovery enrich goroutines and the inference request
// goroutines).
func (s *ChainOperatorSource) RecordRelayOutcome(relay NodeRef, ok bool) {
	s.relayRepMu.Lock()
	defer s.relayRepMu.Unlock()
	if ok {
		// A successful forward clears the streak so a recovered relay returns
		// to the preferred tier immediately. delete keeps the map sparse.
		delete(s.relayFailStreak, relay)
		return
	}
	s.relayFailStreak = bumpRelayReputation(s.relayFailStreak, relay, s.relayRepNow(), steering.RelayReputationCooldown)
}

// RecordRelayUpstreamUnreachable implements RelayReputation. The relay claims
// targetID was unreachable; believe it only when our own probes don't
// contradict it. recallReachable and RecordRelayOutcome take distinct mutexes
// and are called sequentially (not nested), so there is no lock-ordering risk.
// Safe for concurrent use.
func (s *ChainOperatorSource) RecordRelayUpstreamUnreachable(relay, target NodeRef) {
	// Target independently seen reachable ⇒ the "target down" claim is a lie (or
	// at least a drop) ⇒ count it against the relay. Target down/unknown ⇒ credit
	// the relay rather than punish an honest forwarder for a dead target.
	s.RecordRelayOutcome(relay, !s.recallReachable(target))
}

// RecordRelayForwardedTargetFault implements RelayReputation. Same differential
// shape as RecordRelayUpstreamUnreachable, minus the credit: contradicted ⇒
// penalize, otherwise ⇒ record NOTHING.
//
// The asymmetry is deliberate and load-bearing. relay_upstream_unreachable is
// an explicit CLAIM the relay chose to make, so validating it either way is
// fair — a relay that stakes its reputation on "the target is down" and turns
// out right has earned the credit. A code-less transient status that merely
// arrived with a hop marker is a much weaker signal: the relay asserted nothing
// beyond "my handler ran", and the status could equally be its own upstream
// path failing. Crediting on that would let ordinary fleet churn keep a
// half-broken relay permanently under the downrank threshold — every target
// restart wiping the streak — which is exactly the spotless-streak failure the
// AttrUnknown "record nothing" rule was written to prevent.
func (s *ChainOperatorSource) RecordRelayForwardedTargetFault(relay, target NodeRef) {
	if !s.recallReachable(target) {
		// Uncorroborated: the target may well be the broken party. Neither
		// credit nor penalty.
		return
	}
	s.RecordRelayOutcome(relay, false)
}

// RecordRelayStaleEphemeral implements RelayReputation. A stale ephemeral
// served via relayID increments a SEPARATE staleness streak — NOT the
// forward-failure streak, because the stale block still forwarded fine and the
// discovery probe credits relayFailStreak in the same cycle; folding the two
// would let that credit reset the staleness signal before it ever crossed the
// threshold. Safe for concurrent use (called from the discovery enrich
// goroutines).
func (s *ChainOperatorSource) RecordRelayStaleEphemeral(relay NodeRef) {
	s.relayRepMu.Lock()
	defer s.relayRepMu.Unlock()
	s.relayStaleStreak = bumpRelayReputation(s.relayStaleStreak, relay, s.relayRepNow(), steering.RelayReputationCooldown)
}

// RecordRelayFreshEphemeral implements RelayReputation. A fresh block over
// relayID clears its staleness streak (delete keeps the map sparse); it does
// not touch the forward-failure streak. Safe for concurrent use.
func (s *ChainOperatorSource) RecordRelayFreshEphemeral(relay NodeRef) {
	s.relayRepMu.Lock()
	defer s.relayRepMu.Unlock()
	delete(s.relayStaleStreak, relay)
}

// RecordRelayForwardTimeout implements RelayReputation. A forward through relay
// died with a gateway timeout that the shared verdict could not attribute.
//
// Two properties make this safe to act on despite transient.NarrowRelayed
// abstaining, and both are load-bearing.
//
// It is PENALTY-ONLY with the same differential as
// RecordRelayForwardedTargetFault: a timeout is charged only when our own probes
// independently reached the target. Two things weaken that guard here more than
// there, and both are the reason this streak is separate and costs more strikes
// rather than being folded into relayFailStreak. A details probe is a tiny GET,
// so it succeeds against a target whose *generation* is slow — the exact
// confound we are trying to exclude. And lastReachable is the most recent probe
// outcome ACROSS refresh cycles (ProbeBudget can skip a node), so it can be
// arbitrarily stale; "we saw this target up" is the only thing separating "the
// relay's front door is wedged" from "the target is slow", and it is a weaker
// statement than it reads.
//
// It is a THIRD streak, for the same reason relayStaleStreak is a second one,
// and the reason is sharper here. The failure this catches is a front door that
// only kills BYTE-SILENT forwards: a relayed non-streaming request is silent for
// its whole duration (the relay writes nothing until its target's headers
// arrive), while streamed forwards stay alive on the node's SSE keepalive and
// reserve round-trips finish in milliseconds. So the very relay that times out
// every buffered forward is also credited by RecordRelayOutcome many times a
// minute on the shapes that still work. Folding the two would let those credits
// delete the evidence long before it crossed any threshold — the same
// same-cycle-credit trap relayStaleStreak was split out to avoid. For the same
// reason a success must never clear this streak; only decay ages it.
func (s *ChainOperatorSource) RecordRelayForwardTimeout(relay, target NodeRef) {
	if !s.recallReachable(target) {
		// Uncorroborated: we have no independent evidence the target was even
		// up, so the timeout is at least as likely to be its own. Record nothing.
		return
	}
	s.relayRepMu.Lock()
	defer s.relayRepMu.Unlock()
	s.relayTimeoutStreak = bumpRelayReputation(s.relayTimeoutStreak, relay, s.relayRepNow(), steering.RelayTimeoutCooldown)
}

// RelayDownranked implements RelayReputation. Any streak crossing its own
// threshold downranks the relay. Safe for concurrent use.
//
// Despite the read-shaped name this MUTATES: it is where accrued evidence ages
// (steering.Decay), because a relay buried below a healthy preferred pool
// stops being selected and so never earns the success that would clear it. That
// makes the sweep lazy and per-key — a relay nobody asks about again keeps its
// entry — which is why it takes the write lock, not a read lock.
func (s *ChainOperatorSource) RelayDownranked(relay NodeRef) bool {
	s.relayRepMu.Lock()
	defer s.relayRepMu.Unlock()
	now := s.relayRepNow()
	failures := pruneAndReadRelayReputation(s.relayFailStreak, relay, now, steering.RelayReputationCooldown)
	stale := pruneAndReadRelayReputation(s.relayStaleStreak, relay, now, steering.RelayReputationCooldown)
	timeouts := pruneAndReadRelayReputation(s.relayTimeoutStreak, relay, now, steering.RelayTimeoutCooldown)
	return steering.RelayDownranked(failures, stale, timeouts)
}

var _ RelayReputation = (*ChainOperatorSource)(nil)
