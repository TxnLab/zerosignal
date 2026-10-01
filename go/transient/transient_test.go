/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transient_test

import (
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/transient"
)

// The rule that pays for this package: a bare 504 is retryable and belongs to
// nobody, while the same status carrying a node code stays terminal so the
// node's own semantics keep ownership.
func TestClassify_BareStatusVsCodedStatus(t *testing.T) {
	bare := transient.Classify(504, "")
	if !bare.Retryable || bare.Attribution != transient.AttrUnknown {
		t.Errorf("bare 504 = %+v, want retryable/unknown", bare)
	}
	coded := transient.Classify(503, "provider_unavailable")
	if coded.Retryable || coded.Attribution != transient.AttrNone {
		t.Errorf("coded 503 = %+v, want terminal/none", coded)
	}
}

// A relay hop error must attribute to the relay regardless of the status it
// rode in on — that verdict is what makes a post-payment retry safe, since it
// proves the target never consumed the ticket.
func TestClassify_HopErrorAttributionIgnoresStatus(t *testing.T) {
	for _, status := range []int{400, 404, 502, 503} {
		got := transient.Classify(status, relay.CodeBusy)
		if !got.Retryable || got.Attribution != transient.AttrRelay {
			t.Errorf("status %d + relay_busy = %+v, want retryable/relay", status, got)
		}
	}
}

// relay_upstream_unreachable is the relay's CLAIM about the target, so it must
// not be treated as a relay-side fault — callers apply their own differential
// handling to it, and mislabeling it AttrRelay would make it safe to retry
// post-payment when it is not.
func TestClassify_UpstreamUnreachableAttributesToTarget(t *testing.T) {
	got := transient.Classify(502, relay.CodeUpstreamUnreachable)
	if !got.Retryable || got.Attribution != transient.AttrTarget {
		t.Errorf("relay_upstream_unreachable = %+v, want retryable/target", got)
	}
}

// A transport failure produced no response at all; callers pass status 0 and
// may narrow the attribution from context (relayed mode knows it reached the
// relay, not the target).
func TestClassify_TransportFailureIsRetryable(t *testing.T) {
	got := transient.Classify(transient.TransportFailureStatus, "")
	if !got.Retryable || got.Attribution != transient.AttrUnknown {
		t.Errorf("transport failure = %+v, want retryable/unknown", got)
	}
}

// Out-of-range indices clamp rather than panic, so raising InnerAttempts or
// Sweeps without extending the tables degrades to a constant wait.
// TestNarrowRelayed covers every rule, and the two inversions that would do
// real damage: charging a target for a relay's broken front door, and charging
// a relay for a header its generation was never asked to set.
func TestNarrowRelayed(t *testing.T) {
	const (
		marked   = true
		unmarked = false
		floorOK  = true
		preFloor = false
	)
	tests := []struct {
		name     string
		status   int
		code     string
		evidence transient.RelayEvidence
		want     transient.Attribution
	}{
		// Rule 1 — passthrough.
		{"direct bare 504 is untouched", 504, "",
			transient.RelayEvidence{}, transient.AttrUnknown},
		{"relayed hop code keeps its relay attribution", 503, relay.CodeBusy,
			transient.RelayEvidence{Relayed: true, HopMarker: marked, RelayMarksHops: floorOK}, transient.AttrRelay},
		{"relayed upstream_unreachable keeps its target attribution", 502, relay.CodeUpstreamUnreachable,
			transient.RelayEvidence{Relayed: true, HopMarker: marked, RelayMarksHops: floorOK}, transient.AttrTarget},
		{"relayed terminal code is untouched", 400, "context_length_exceeded",
			transient.RelayEvidence{Relayed: true, RelayMarksHops: floorOK}, transient.AttrNone},

		// Rule 2 — no response at all. Version-independent: the socket we
		// opened was the relay's, and there is no marker to be missing.
		{"relayed transport failure blames the relay with no version gate", transient.TransportFailureStatus, "",
			transient.RelayEvidence{Relayed: true}, transient.AttrRelay},
		{"relayed transport failure outranks a stale marker", transient.TransportFailureStatus, "",
			transient.RelayEvidence{Relayed: true, HopMarker: marked, RelayMarksHops: floorOK}, transient.AttrRelay},

		// Rule 3 — the relay ran and forwarded, so the code-less status came
		// from the target. Lands on AttrTarget, which callers already treat
		// differentially rather than at face value.
		{"marked code-less 504 blames the target", 504, "",
			transient.RelayEvidence{Relayed: true, HopMarker: marked, RelayMarksHops: floorOK}, transient.AttrTarget},
		{"a marker needs no version gate — presence is self-evident", 504, "",
			transient.RelayEvidence{Relayed: true, HopMarker: marked, RelayMarksHops: preFloor}, transient.AttrTarget},

		// Rule 4 — the fix. A >=9.1 relay that ran its handler would have marked,
		// and these statuses all mean its front door could not get a connection
		// to it at all: the shapes a relay that is genuinely DOWN produces.
		{"unmarked 502 from a marking relay blames the relay", 502, "",
			transient.RelayEvidence{Relayed: true, HopMarker: unmarked, RelayMarksHops: floorOK}, transient.AttrRelay},
		{"unmarked cloudflare 521 origin-down blames the relay", 521, "",
			transient.RelayEvidence{Relayed: true, HopMarker: unmarked, RelayMarksHops: floorOK}, transient.AttrRelay},
		{"unmarked cloudflare 522 connect-timeout blames the relay", 522, "",
			transient.RelayEvidence{Relayed: true, HopMarker: unmarked, RelayMarksHops: floorOK}, transient.AttrRelay},

		// Rule 4's timeout carve-out — the distinction the review surfaced. A
		// relay is byte-silent for the whole forward window (it cannot flush a
		// marker without committing to a status it doesn't yet know), so a
		// gateway RESPONSE timeout is indistinguishable between "relay wedged"
		// and "relay waiting on a slow target". Charging here would bench
		// whoever fronts the slowest targets. Contrast 522 above: that is a
		// CONNECT timeout, which does prove the relay is unreachable.
		{"unmarked 504 gateway timeout stays unattributed", 504, "",
			transient.RelayEvidence{Relayed: true, HopMarker: unmarked, RelayMarksHops: floorOK}, transient.AttrUnknown},
		{"unmarked cloudflare 524 response timeout stays unattributed", 524, "",
			transient.RelayEvidence{Relayed: true, HopMarker: unmarked, RelayMarksHops: floorOK}, transient.AttrUnknown},
		{"a MARKED timeout is still the target's", 504, "",
			transient.RelayEvidence{Relayed: true, HopMarker: marked, RelayMarksHops: floorOK}, transient.AttrTarget},

		// Rule 2 — our own cancel/deadline. Without this a user hitting stop, or
		// a client-side reserve timeout that expired while the relay was
		// legitimately waiting on a slow target, charges the relay for a socket
		// WE tore down.
		{"caller-aborted transport failure charges nobody", transient.TransportFailureStatus, "",
			transient.RelayEvidence{Relayed: true, CallerAborted: true}, transient.AttrUnknown},
		{"caller-aborted outranks marker absence", 502, "",
			transient.RelayEvidence{Relayed: true, RelayMarksHops: floorOK, CallerAborted: true}, transient.AttrUnknown},

		// Rule 5 — the residue. Charging here would blame the entire
		// un-upgraded fleet for a header that did not exist when it shipped.
		{"unmarked 502 from a pre-floor relay stays unattributed", 502, "",
			transient.RelayEvidence{Relayed: true, HopMarker: unmarked, RelayMarksHops: preFloor}, transient.AttrUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := transient.NarrowRelayed(transient.Classify(tc.status, tc.code), tc.status, tc.evidence)
			if got.Attribution != tc.want {
				t.Fatalf("NarrowRelayed(Classify(%d, %q), %+v).Attribution = %q, want %q",
					tc.status, tc.code, tc.evidence, got.Attribution, tc.want)
			}
		})
	}
}

// Narrowing must never change whether a failure is worth retrying — it only
// answers WHO to charge. A rule that flipped Retryable would silently turn a
// rideable CDN blip into a hard failure (or the reverse), independent of any
// reputation bookkeeping.
func TestNarrowRelayed_PreservesRetryable(t *testing.T) {
	evidences := []transient.RelayEvidence{
		{},
		{Relayed: true},
		{Relayed: true, HopMarker: true},
		{Relayed: true, RelayMarksHops: true},
		{Relayed: true, HopMarker: true, RelayMarksHops: true},
	}
	statuses := []int{transient.TransportFailureStatus, 404, 429, 500, 502, 503, 504, 522, 200}
	for _, status := range statuses {
		for _, e := range evidences {
			before := transient.Classify(status, "")
			after := transient.NarrowRelayed(before, status, e)
			if before.Retryable != after.Retryable {
				t.Fatalf("status %d evidence %+v: Retryable flipped %v -> %v",
					status, e, before.Retryable, after.Retryable)
			}
		}
	}
}

func TestDelayTablesClamp(t *testing.T) {
	if got := transient.InnerDelay(0); got != 0 {
		t.Errorf("InnerDelay(0) = %v, want 0 (first try is immediate)", got)
	}
	if got := transient.SweepDelay(0); got != 0 {
		t.Errorf("SweepDelay(0) = %v, want 0 (first sweep is immediate)", got)
	}
	last := transient.InnerDelay(transient.InnerAttempts - 1)
	if got := transient.InnerDelay(transient.InnerAttempts + 50); got != last {
		t.Errorf("InnerDelay past end = %v, want clamp to %v", got, last)
	}
	if got := transient.InnerDelay(-3); got != 0 {
		t.Errorf("InnerDelay(-3) = %v, want clamp to 0", got)
	}
	lastSweep := transient.SweepDelay(transient.Sweeps - 1)
	if got := transient.SweepDelay(transient.Sweeps + 50); got != lastSweep {
		t.Errorf("SweepDelay past end = %v, want clamp to %v", got, lastSweep)
	}
}

// The whole schedule must fit inside the deadline with room to actually make
// the attempts — a table that sums past OverallDeadline would silently never
// reach its last sweep.
func TestScheduleFitsDeadline(t *testing.T) {
	var total time.Duration
	for i := 0; i < transient.Sweeps; i++ {
		total += transient.SweepDelay(i)
	}
	if total >= transient.OverallDeadline {
		t.Errorf("sweep delays total %v >= deadline %v; the last sweep can never run",
			total, transient.OverallDeadline)
	}
}

func TestWait_RetryAfterWinsWhenLonger(t *testing.T) {
	d, ok := transient.Wait(500*time.Millisecond, 5*time.Second, time.Minute)
	if !ok || d != 5*time.Second {
		t.Errorf("Wait = (%v, %v), want (5s, true)", d, ok)
	}
}

// Stopping at the boundary is deliberate: sleeping right up to the deadline
// only delays the error the caller is going to surface anyway.
func TestWait_StopsWhenWaitWouldConsumeBudget(t *testing.T) {
	if _, ok := transient.Wait(10*time.Second, 0, 10*time.Second); ok {
		t.Error("Wait ok=true when the delay equals the remaining budget; want stop")
	}
	if _, ok := transient.Wait(time.Second, 0, 0); ok {
		t.Error("Wait ok=true with no budget remaining; want stop")
	}
	if _, ok := transient.Wait(0, 90*time.Second, time.Minute); ok {
		t.Error("Wait ok=true when Retry-After exceeds the budget; want stop")
	}
}

// The front-door set must stay a strict, deliberate partition of the retryable
// statuses. Two failure modes this catches, both silent:
//
//   - a status charged to a relay that Classify never even calls retryable —
//     dead weight in the set, since rule 1 returns before rule 4 can see it;
//   - a NEW retryable status added for some unrelated reason, quietly
//     inheriting "charge the relay" (the exact hazard that made the old
//     derived `retryable minus timeouts` form wrong).
//
// The only members of retryableStatuses that may sit outside the front-door set
// are the transport sentinel (rule 3 owns it) and the three timeouts, which are
// unattributable because a relay is byte-silent while forwarding. Adding a
// retryable status therefore forces an explicit choice here rather than
// defaulting to a penalty.
func TestRelayFrontDoorStatusPartitionsRetryable(t *testing.T) {
	unattributable := map[int]bool{
		transient.TransportFailureStatus: true,
		408:                              true,
		504:                              true,
		524:                              true,
	}
	// Every status either port could be handed. Wider than the retryable set on
	// purpose, so a front-door member that is NOT retryable is caught too.
	for status := 0; status <= 599; status++ {
		front := transient.IsRelayFrontDoorStatus(status)
		// Classify with no code: retryable iff the status is infrastructure weather.
		retryable := transient.Classify(status, "").Retryable
		switch {
		case front && !retryable:
			t.Errorf("status %d is front-door but not retryable; rule 4 can never see it "+
				"(Classify returns before NarrowRelayed runs)", status)
		case retryable && !front && !unattributable[status]:
			t.Errorf("status %d is retryable but neither front-door nor a known "+
				"unattributable timeout — decide which it is rather than letting it "+
				"default to no penalty", status)
		case front && unattributable[status]:
			t.Errorf("status %d is both front-door and unattributable", status)
		}
	}
}
