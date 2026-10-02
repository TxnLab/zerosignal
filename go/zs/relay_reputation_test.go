/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/steering"
)

// TestRelayReputation_DownrankAfterThreshold: consecutive forward failures
// downrank a relay once they reach steering.RelayDownrankThreshold; a success resets the
// streak so a recovered relay is no longer downranked.
func TestRelayReputation_DownrankAfterThreshold(t *testing.T) {
	s := &ChainOperatorSource{}
	relay := NodeRef{Op: 42, Node: 1}

	// Below the threshold: not yet downranked.
	for i := 0; i < steering.RelayDownrankThreshold-1; i++ {
		s.RecordRelayOutcome(relay, false)
		if s.RelayDownranked(relay) {
			t.Fatalf("downranked after %d failures; threshold is %d", i+1, steering.RelayDownrankThreshold)
		}
	}

	// Crossing the threshold: downranked.
	s.RecordRelayOutcome(relay, false)
	if !s.RelayDownranked(relay) {
		t.Fatalf("not downranked after %d consecutive failures", steering.RelayDownrankThreshold)
	}

	// A single success clears the streak — recovered relay returns to favor.
	s.RecordRelayOutcome(relay, true)
	if s.RelayDownranked(relay) {
		t.Fatal("still downranked after a successful forward; streak should reset")
	}
}

// TestRelayReputation_DownrankDecaysWithoutSelection: evidence ages out one unit
// per cooldown, not all at once, and it does so on a read — the only occasion a
// relay nobody selects anymore gets to recover. Reading twice at one instant must
// not compound, because the production reader (relayPool) runs per request.
func TestRelayReputation_DownrankDecaysWithoutSelection(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	s := &ChainOperatorSource{relayRepClock: func() time.Time { return now }}
	relay := NodeRef{Op: 42, Node: 1}

	for i := 0; i < steering.RelayDownrankThreshold; i++ {
		s.RecordRelayOutcome(relay, false)
	}
	if !s.RelayDownranked(relay) {
		t.Fatal("relay should be downranked before the cooldown")
	}

	// Deliberately a fractional offset: only the unconsumed remainder proves at
	// advanced by the windows spent rather than to now, which is what keeps the
	// total decay rate at one unit per cooldown across a run of partial reads.
	now = start.Add(steering.RelayReputationCooldown * 3 / 2)
	if s.RelayDownranked(relay) {
		t.Fatal("relay remained downranked after a cooldown of decay")
	}
	if got := s.relayFailStreak[relay].Count; got != steering.RelayDownrankThreshold-1 {
		t.Fatalf("count after one cooldown = %d, want %d", got, steering.RelayDownrankThreshold-1)
	}
	if s.RelayDownranked(relay); s.relayFailStreak[relay].Count != steering.RelayDownrankThreshold-1 {
		t.Fatalf("a second read at the same instant compounded the decay to %d",
			s.relayFailStreak[relay].Count)
	}

	now = start.Add(steering.RelayDownrankThreshold * steering.RelayReputationCooldown)
	if s.RelayDownranked(relay) {
		t.Fatal("relay remained downranked after its evidence fully decayed")
	}
	if _, ok := s.relayFailStreak[relay]; ok {
		t.Fatal("fully decayed forward-failure entry was not deleted on read")
	}
}

// TestRelayReputation_DecayedStreakRedownranksOnNextFailure: decay is why the
// downrank is escapable, but it must not hand a chronically broken relay a clean
// slate every quiet cooldown. One aged-out unit means one new failure re-crosses
// the threshold — a shorter leash on a repeat offender than on a first-time one.
func TestRelayReputation_DecayedStreakRedownranksOnNextFailure(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	s := &ChainOperatorSource{relayRepClock: func() time.Time { return now }}
	relay := NodeRef{Op: 42, Node: 1}

	for i := 0; i < steering.RelayDownrankThreshold; i++ {
		s.RecordRelayOutcome(relay, false)
	}
	now = start.Add(steering.RelayReputationCooldown)
	s.RecordRelayOutcome(relay, false)

	if !s.RelayDownranked(relay) {
		t.Fatal("a single failure after one cooldown should re-cross the threshold")
	}
	if got := s.relayFailStreak[relay].Count; got != steering.RelayDownrankThreshold {
		t.Fatalf("count after decay + one failure = %d, want %d", got, steering.RelayDownrankThreshold)
	}
}

// TestRelayReputation_StaleEphemeralDownrankDecays: the staleness streak decays on
// the same schedule. It matters more here — its only other clear (a fresh block
// over the same relay) also requires having been selected.
func TestRelayReputation_StaleEphemeralDownrankDecays(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	now := start
	s := &ChainOperatorSource{relayRepClock: func() time.Time { return now }}
	relay := NodeRef{Op: 42, Node: 1}

	for i := 0; i < steering.RelayDownrankThreshold; i++ {
		s.RecordRelayStaleEphemeral(relay)
	}
	if !s.RelayDownranked(relay) {
		t.Fatal("stale-ephemeral streak should downrank the relay")
	}

	now = start.Add(steering.RelayDownrankThreshold * steering.RelayReputationCooldown)
	if s.RelayDownranked(relay) {
		t.Fatal("stale-ephemeral downrank remained after its evidence fully decayed")
	}
	if _, ok := s.relayStaleStreak[relay]; ok {
		t.Fatal("fully decayed stale-ephemeral entry was not deleted on read")
	}
}

// TestRelayReputation_IndependentPerRelay: one bad relay does not downrank
// another, an unseen relay is never downranked, and — because reputation keys by
// (operator id, node id) — a dead relay node never downranks a healthy SIBLING
// node under the same operator.
func TestRelayReputation_IndependentPerRelay(t *testing.T) {
	s := &ChainOperatorSource{}
	bad := NodeRef{Op: 1, Node: 1}
	for i := 0; i < steering.RelayDownrankThreshold; i++ {
		s.RecordRelayOutcome(bad, false)
	}
	if !s.RelayDownranked(bad) {
		t.Fatal("relay 1/1 should be downranked")
	}
	if s.RelayDownranked(NodeRef{Op: 2, Node: 1}) {
		t.Fatal("relay 2/1 (never failed) must not be downranked")
	}
	if s.RelayDownranked(NodeRef{Op: 999, Node: 1}) {
		t.Fatal("an unseen relay must not be downranked")
	}
	// Node granularity is the whole point of the NodeRef key: a sibling node of
	// the same operator is independent, so 1/1's failures must not tar 1/2.
	if s.RelayDownranked(NodeRef{Op: 1, Node: 2}) {
		t.Fatal("sibling node 1/2 downranked by 1/1's failures; reputation must key by (operator, node)")
	}
}

// TestRelayReputation_SuccessFromZero: recording a success for a relay that
// has no streak is a no-op (and doesn't create spurious state).
func TestRelayReputation_SuccessFromZero(t *testing.T) {
	s := &ChainOperatorSource{}
	relay := NodeRef{Op: 7, Node: 1}
	s.RecordRelayOutcome(relay, true)
	if s.RelayDownranked(relay) {
		t.Fatal("relay 7 downranked after only a success")
	}
}

// TestRelayReputation_UpstreamUnreachableDifferential: a relay_upstream_unreachable
// claim counts against the relay only when the target was independently observed
// reachable (the claim is contradicted → the relay is dropping forwards while
// blaming the target). An uncorroborated claim about a down/unknown target
// credits the relay so an honest forwarder isn't punished for a dead target.
func TestRelayReputation_UpstreamUnreachableDifferential(t *testing.T) {
	relay := NodeRef{Op: 1, Node: 1}
	healthyTarget := NodeRef{Op: 10, Node: 1}
	deadTarget := NodeRef{Op: 20, Node: 1}

	t.Run("contradicted claim downranks the relay", func(t *testing.T) {
		s := &ChainOperatorSource{}
		s.recordReachable(healthyTarget, true) // we've seen the target up elsewhere
		for i := 0; i < steering.RelayDownrankThreshold; i++ {
			s.RecordRelayUpstreamUnreachable(relay, healthyTarget)
		}
		if !s.RelayDownranked(relay) {
			t.Fatalf("relay not downranked after %d contradicted upstream_unreachable claims", steering.RelayDownrankThreshold)
		}
	})

	t.Run("uncorroborated claim credits the relay", func(t *testing.T) {
		s := &ChainOperatorSource{}
		// deadTarget never recorded reachable → recallReachable is false.
		for i := 0; i < steering.RelayDownrankThreshold*2; i++ {
			s.RecordRelayUpstreamUnreachable(relay, deadTarget)
		}
		if s.RelayDownranked(relay) {
			t.Fatal("relay downranked for honestly reporting a dead target as unreachable")
		}
	})

	t.Run("a credited claim resets a prior streak", func(t *testing.T) {
		s := &ChainOperatorSource{}
		s.RecordRelayOutcome(relay, false)
		s.RecordRelayOutcome(relay, false)                  // streak = 2
		s.RecordRelayUpstreamUnreachable(relay, deadTarget) // dead target → credit → reset
		s.RecordRelayOutcome(relay, false)
		if s.RelayDownranked(relay) {
			t.Fatal("streak not reset by a credited upstream_unreachable claim")
		}
	})
}

// TestRelayReputation_ForwardTimeoutDifferential: an unattributed forward
// timeout counts against the relay only when the target was independently
// observed reachable. Unlike the upstream_unreachable claim it is PENALTY-ONLY —
// an uncorroborated timeout records nothing rather than crediting, because the
// relay asserted nothing at all (it never even wrote its hop marker).
// Each streak ages its standing evidence by its OWN cooldown when new evidence
// arrives, not only when it is read. A bump that aged the timeout streak on the
// 10m cooldown would hold it near 1 forever; one that aged a probe-fed streak on
// the 60m cooldown would let ordinary weather accumulate into a downrank.
func TestRelayReputation_BumpAgesByTheStreaksOwnCooldown(t *testing.T) {
	relay := NodeRef{Op: 1, Node: 1}
	target := NodeRef{Op: 10, Node: 1}
	start := time.Unix(1_700_000_000, 0)
	// Past two short cooldowns, inside one long one.
	later := start.Add(25 * time.Minute)

	probeFed := map[string]func(*ChainOperatorSource){
		"forward failure": func(s *ChainOperatorSource) { s.RecordRelayOutcome(relay, false) },
		"stale ephemeral": func(s *ChainOperatorSource) { s.RecordRelayStaleEphemeral(relay) },
	}
	for name, record := range probeFed {
		t.Run(name, func(t *testing.T) {
			now := start
			s := &ChainOperatorSource{relayRepClock: func() time.Time { return now }}
			for range steering.RelayDownrankThreshold - 1 {
				record(s)
			}
			now = later
			record(s)
			if s.RelayDownranked(relay) {
				t.Fatal("evidence 25m old was not aged by the 10m cooldown before the new unit was added")
			}
		})
	}

	t.Run("forward timeout", func(t *testing.T) {
		now := start
		s := &ChainOperatorSource{relayRepClock: func() time.Time { return now }}
		s.recordReachable(target, true)
		for range steering.RelayTimeoutDownrankThreshold - 1 {
			s.RecordRelayForwardTimeout(relay, target)
		}
		now = later
		s.RecordRelayForwardTimeout(relay, target)
		if !s.RelayDownranked(relay) {
			t.Fatal("timeout evidence 25m old was aged by the 10m cooldown; it must last the 60m one")
		}
	})
}

func TestRelayReputation_ForwardTimeoutDifferential(t *testing.T) {
	relay := NodeRef{Op: 1, Node: 1}
	healthyTarget := NodeRef{Op: 10, Node: 1}
	unseenTarget := NodeRef{Op: 20, Node: 1}

	t.Run("contradicted timeout downranks at its own threshold", func(t *testing.T) {
		s := &ChainOperatorSource{}
		s.recordReachable(healthyTarget, true)
		// One short of the timeout threshold must NOT downrank — this is what
		// proves the higher threshold is live rather than decorative. Note it is
		// already past steering.RelayDownrankThreshold, so a fold into relayFailStreak
		// would have fired here.
		for range steering.RelayTimeoutDownrankThreshold - 1 {
			s.RecordRelayForwardTimeout(relay, healthyTarget)
		}
		if s.RelayDownranked(relay) {
			t.Fatalf("downranked after %d timeouts; timeout threshold is %d",
				steering.RelayTimeoutDownrankThreshold-1, steering.RelayTimeoutDownrankThreshold)
		}
		s.RecordRelayForwardTimeout(relay, healthyTarget)
		if !s.RelayDownranked(relay) {
			t.Fatalf("not downranked after %d contradicted timeouts", steering.RelayTimeoutDownrankThreshold)
		}
	})

	t.Run("uncorroborated timeout records nothing", func(t *testing.T) {
		s := &ChainOperatorSource{}
		// Establish a DIRTY failure streak first. On a clean store "records
		// nothing" and "records a credit" are indistinguishable — both leave an
		// empty map and an undownranked relay — so the most plausible wrong edit
		// here (copying RecordRelayUpstreamUnreachable's
		// `s.RecordRelayOutcome(relay, !reachable)`, which CREDITS on this branch)
		// would survive. Only a pre-existing streak can observe the credit.
		for range steering.RelayDownrankThreshold {
			s.RecordRelayOutcome(relay, false)
		}
		if !s.RelayDownranked(relay) {
			t.Fatal("precondition: relay should be downranked on the failure streak")
		}
		// unseenTarget never recorded reachable → recallReachable is false, so
		// the timeout is at least as likely to be the target's own slowness.
		for range steering.RelayTimeoutDownrankThreshold * 2 {
			s.RecordRelayForwardTimeout(relay, unseenTarget)
		}
		if !s.RelayDownranked(relay) {
			t.Fatal("uncorroborated timeout CREDITED the relay and cleared its failure streak; it must record nothing")
		}
		if _, ok := s.relayTimeoutStreak[relay]; ok {
			t.Fatal("uncorroborated timeout accrued timeout evidence; it must record nothing")
		}
	})

	t.Run("a success does not clear the timeout streak", func(t *testing.T) {
		// The whole reason this is a third streak. A relay behind a 60s front
		// door still carries every streamed forward and every reserve, so
		// RecordRelayOutcome(true) fires constantly against it; if that cleared
		// the timeout evidence it could never reach the threshold.
		s := &ChainOperatorSource{}
		s.recordReachable(healthyTarget, true)
		for range steering.RelayTimeoutDownrankThreshold {
			s.RecordRelayForwardTimeout(relay, healthyTarget)
			s.RecordRelayOutcome(relay, true) // a streamed forward succeeds
		}
		if !s.RelayDownranked(relay) {
			t.Fatal("interleaved successes erased the timeout streak")
		}
	})

	t.Run("decay ages the timeout streak", func(t *testing.T) {
		start := time.Unix(1_700_000_000, 0)
		now := start
		s := &ChainOperatorSource{relayRepClock: func() time.Time { return now }}
		s.recordReachable(healthyTarget, true)
		for range steering.RelayTimeoutDownrankThreshold {
			s.RecordRelayForwardTimeout(relay, healthyTarget)
		}
		if !s.RelayDownranked(relay) {
			t.Fatal("relay should be downranked before the cooldown")
		}
		// Ages on the TIMEOUT cooldown, not the failure one. At the failure
		// cooldown this read would be 6 windows deep and the entry gone, so this
		// also pins that the two streaks are decayed on separate clocks.
		if now = start.Add(steering.RelayReputationCooldown * 3 / 2); !s.RelayDownranked(relay) {
			t.Fatal("timeout streak decayed on the FAILURE cooldown; it must use steering.RelayTimeoutCooldown")
		}
		// A fractional offset, read and then acted on at SEPARATE instants. Only
		// the separation can observe `at` advancing by the windows CONSUMED
		// rather than to now: at one instant both forms agree, because the
		// follow-up bump decays by zero steps either way.
		now = start.Add(steering.RelayTimeoutCooldown * 3 / 2)
		if s.RelayDownranked(relay) {
			t.Fatal("relay remained downranked after a cooldown of decay")
		}
		if got := s.relayTimeoutStreak[relay].Count; got != steering.RelayTimeoutDownrankThreshold-1 {
			t.Fatalf("count after one cooldown = %d, want %d", got, steering.RelayTimeoutDownrankThreshold-1)
		}
		// at should now be start+1c. Advancing to start+2c consumes exactly one
		// more whole window; under an `at = now` mutant at would be start+1.5c
		// and this second read would consume none, leaving the count one higher.
		now = start.Add(steering.RelayTimeoutCooldown * 2)
		s.RelayDownranked(relay)
		if got := s.relayTimeoutStreak[relay].Count; got != steering.RelayTimeoutDownrankThreshold-2 {
			t.Fatalf("count after two cooldowns = %d, want %d — `at` did not advance by the windows consumed",
				got, steering.RelayTimeoutDownrankThreshold-2)
		}
		now = start.Add(steering.RelayTimeoutDownrankThreshold * steering.RelayTimeoutCooldown)
		if s.RelayDownranked(relay) {
			t.Fatal("relay remained downranked after its evidence fully decayed")
		}
		if _, ok := s.relayTimeoutStreak[relay]; ok {
			t.Fatal("fully decayed timeout entry was not deleted on read")
		}
	})

	t.Run("timeout evidence does not leak into the forward-failure streak", func(t *testing.T) {
		s := &ChainOperatorSource{}
		s.recordReachable(healthyTarget, true)
		for range steering.RelayTimeoutDownrankThreshold {
			s.RecordRelayForwardTimeout(relay, healthyTarget)
		}
		if _, ok := s.relayFailStreak[relay]; ok {
			t.Fatal("a forward timeout wrote to relayFailStreak; the two must stay separate")
		}
		if _, ok := s.relayStaleStreak[relay]; ok {
			t.Fatal("a forward timeout wrote to relayStaleStreak")
		}
	})
}
