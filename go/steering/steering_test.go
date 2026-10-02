/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package steering_test

// Invariants the fixed vectors can't reach, checked over random inputs. Each
// one is a property a caller relies on without knowing it: a read that ages
// evidence must be repeatable, a backwards clock must never add evidence, and a
// consensus must not depend on the order a payer happened to probe operators in.

import (
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/steering"
	"github.com/TxnLab/zerosignal/go/transient"
)

const trials = 5000

func rng(t *testing.T) *rand.Rand {
	t.Helper()
	return rand.New(rand.NewPCG(1, 2))
}

// randInstant is within a few hours either side of t0, at millisecond
// resolution like every timestamp a payer records.
func randInstant(r *rand.Rand) time.Time {
	return t0.Add(time.Duration(r.Int64N(int64(6*time.Hour/time.Millisecond))-int64(3*time.Hour/time.Millisecond)) * time.Millisecond)
}

func randCooldown(r *rand.Rand) time.Duration {
	return []time.Duration{steering.RelayReputationCooldown, steering.RelayTimeoutCooldown, time.Second}[r.IntN(3)]
}

// The literals, not the symbols: each is mirrored in TS and quoted in AGENTS.md,
// and every other test spells them by name, so a drift would pass there.
func TestConstantsArePinned(t *testing.T) {
	if steering.RelayDownrankThreshold != 3 || steering.RelayReputationCooldown != 10*time.Minute {
		t.Error("relay failure streak: want threshold 3, cooldown 10m")
	}
	if steering.RelayTimeoutDownrankThreshold != 5 || steering.RelayTimeoutCooldown != 60*time.Minute {
		t.Error("relay timeout streak: want threshold 5, cooldown 60m")
	}
	if steering.TargetBackoffBase != 30*time.Second || steering.TargetBackoffCap != 5*time.Minute {
		t.Error("target backoff: want base 30s, cap 5m")
	}
	if steering.WeightsConsensusMinOwners != 2 {
		t.Error("weights consensus: want 2 owners")
	}
	// Each relation is the compensation for the timeout streak's evidence being
	// weaker and rarer than the failure streak's.
	if steering.RelayTimeoutDownrankThreshold <= steering.RelayDownrankThreshold {
		t.Error("the timeout threshold must stay strictly higher than the failure threshold")
	}
	if steering.RelayTimeoutCooldown <= steering.RelayReputationCooldown {
		t.Error("the timeout cooldown must stay strictly longer: that streak has no probe feeder")
	}
}

// A status in both sets would be charged twice for one failure: once as a
// relay fault on the failure streak, once on the timeout streak. Checked
// against transient itself so the assertion tracks the golden-vectored set.
func TestForwardTimeoutStatusesAreDisjointFromTheFrontDoorSet(t *testing.T) {
	timeouts := 0
	for s := range 1000 {
		if !steering.IsForwardTimeoutStatus(s) {
			continue
		}
		timeouts++
		if transient.IsRelayFrontDoorStatus(s) {
			t.Errorf("status %d is in both the timeout set and transient's front-door set", s)
		}
	}
	if timeouts != 3 {
		t.Errorf("%d timeout statuses, want 3 (408, 504, 524)", timeouts)
	}
}

func TestDecayProperties(t *testing.T) {
	r := rng(t)
	for range trials {
		e := steering.Evidence{Count: r.IntN(12), At: randInstant(r)}
		now, cd := randInstant(r), randCooldown(r)
		got, alive := steering.Decay(e, now, cd)

		if alive != (got.Count > 0) || (!alive && got != steering.Evidence{}) {
			t.Fatalf("Decay(%+v, %v) = %+v, %v: alive must mean count > 0, dead must be the zero value", e, now, got, alive)
		}
		if got.Count > e.Count {
			t.Fatalf("Decay grew evidence: %d → %d (now %v, at %v)", e.Count, got.Count, now, e.At)
		}
		if now.Before(e.At) && e.Count > 0 && got != e {
			t.Fatalf("a backwards clock changed evidence: %+v → %+v", e, got)
		}
		if alive && (got.At.Before(e.At) || got.At.After(now) && !now.Before(e.At)) {
			t.Fatalf("At moved outside [old At, now]: %v → %v (now %v)", e.At, got.At, now)
		}
		// The aging seam is read once per relay per request; reading twice at
		// the same instant must not compound.
		if again, _ := steering.Decay(got, now, cd); again != got {
			t.Fatalf("Decay not idempotent at one instant: %+v → %+v", got, again)
		}
		// The residual fraction survives, so reading at an intermediate instant
		// changes nothing about a later read.
		if now.After(e.At) {
			mid := e.At.Add(time.Duration(r.Int64N(int64(now.Sub(e.At)) + 1)))
			step, _ := steering.Decay(e, mid, cd)
			if twice, _ := steering.Decay(step, now, cd); twice != got {
				t.Fatalf("Decay via %v = %+v, direct = %+v", mid, twice, got)
			}
		}
		// Count lost is exactly the whole cooldowns elapsed, clamped at zero.
		if now.After(e.At) && e.Count > 0 {
			want := max(e.Count-int(now.Sub(e.At)/cd), 0)
			if got.Count != want {
				t.Fatalf("Decay count = %d, want %d", got.Count, want)
			}
		}

		b := steering.Bump(e, now, cd)
		if b.Count != got.Count+1 || !b.At.Equal(now) {
			t.Fatalf("Bump(%+v, %v) = %+v, want count %d at now", e, now, b, got.Count+1)
		}
	}
}

func TestBackoffProperties(t *testing.T) {
	prev := time.Duration(0)
	for n := 1; n <= 200; n++ {
		w := steering.BackoffWindow(n)
		if w < prev || w < steering.TargetBackoffBase || w > steering.TargetBackoffCap {
			t.Fatalf("BackoffWindow(%d) = %v after %v: must be nondecreasing within [base, cap]", n, w, prev)
		}
		prev = w
	}
	if w := steering.BackoffWindow(1 << 30); w != steering.TargetBackoffCap {
		t.Fatalf("BackoffWindow(huge) = %v, want the cap", w)
	}

	r := rng(t)
	for range trials {
		var b steering.Backoff
		at := randInstant(r)
		for range 1 + r.IntN(8) {
			b = steering.RecordFailure(b, at)
		}
		floor := time.Duration(r.Int64N(int64(10 * time.Minute)))
		now := randInstant(r)
		rem, forget := steering.BackoffRemaining(b, now, floor)

		// A clock behind the last failure holds the demotion (see
		// BackoffRemaining); from the failure on, it never outlasts the window.
		if limit := max(b.Until.Sub(b.At), floor); rem < 0 || !now.Before(b.At) && rem > limit {
			t.Fatalf("remaining %v outside [0, %v]", rem, limit)
		}
		if rem > 0 && forget {
			t.Fatal("a record still demoting its target was marked to forget")
		}
		if later, _ := steering.BackoffRemaining(b, now.Add(time.Second), floor); later > rem {
			t.Fatalf("remaining grew with time: %v → %v", rem, later)
		}
		if lower, _ := steering.BackoffRemaining(b, now, 0); lower > rem {
			t.Fatalf("a floor shortened the window: %v with floor, %v without", rem, lower)
		}
		if next := steering.RecordFailure(b, now); next.Failures != b.Failures+1 ||
			next.Until.Sub(next.At) < b.Until.Sub(b.At) {
			t.Fatalf("a renewed failure must escalate: %+v → %+v", b, next)
		}
	}
}

func TestWeightsConsensusProperties(t *testing.T) {
	r := rng(t)
	digests := []string{"sha256:aa", "sha256:bb", "sha256:cc", ""}
	owners := []string{"A", "B", "C", "D", "E", ""}
	for range trials {
		claims := make([]steering.DigestClaim, r.IntN(9))
		for i := range claims {
			claims[i] = steering.DigestClaim{Owner: owners[r.IntN(len(owners))], Digest: digests[r.IntN(len(digests))]}
		}
		want := steering.WeightsConsensus(claims)

		// The order a payer probed operators in must not choose the reference.
		shuffled := slices.Clone(claims)
		r.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := steering.WeightsConsensus(shuffled); got != want {
			t.Fatalf("consensus depends on order: %q vs %q for %+v", want, got, claims)
		}
		// One owner's extra nodes are one opinion.
		if len(claims) > 0 {
			dup := append(slices.Clone(claims), claims[r.IntN(len(claims))])
			if got := steering.WeightsConsensus(dup); got != want {
				t.Fatalf("a repeated claim changed the consensus: %q → %q", want, got)
			}
		}
		if want == "" {
			for _, c := range claims {
				if steering.ContradictsWeightsConsensus(c.Digest, want) {
					t.Fatal("no consensus, yet a claim contradicts it")
				}
			}
			continue
		}
		// A consensus is a digest someone advertised, carried by at least the
		// minimum number of distinct owners.
		backers := map[string]bool{}
		for _, c := range claims {
			if c.Owner != "" && c.Digest == want {
				backers[c.Owner] = true
			}
		}
		if len(backers) < steering.WeightsConsensusMinOwners {
			t.Fatalf("consensus %q has %d owners behind it", want, len(backers))
		}
		if steering.ContradictsWeightsConsensus("", want) {
			t.Fatal("silence contradicted a consensus")
		}
		if steering.ContradictsWeightsConsensus(strings.ToUpper(want), want) {
			t.Fatal("an ASCII-uppercased copy of the consensus contradicted it")
		}
	}
}
