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

// ageBackoff moves ref's record d into the past, as if that much time had
// passed since its last failure.
func ageBackoff(s *ChainOperatorSource, ref NodeRef, d time.Duration) {
	s.tgtBackoffMu.Lock()
	defer s.tgtBackoffMu.Unlock()
	e := s.tgtBackoff[ref]
	e.At = e.At.Add(-d)
	e.Until = e.Until.Add(-d)
	s.tgtBackoff[ref] = e
}

// A node that serves us is healthy again and must return to the preferred tier
// at once — not serve out a window it has already disproved.
func TestTargetBackoff_SuccessClearsWindow(t *testing.T) {
	s := &ChainOperatorSource{}
	ref := NodeRef{Op: 1, Node: 2}

	s.RecordTargetOutcome(ref, false)
	if !s.TargetBackedOff(ref) {
		t.Fatal("node not backed off after a failure")
	}
	s.RecordTargetOutcome(ref, true)
	if s.TargetBackedOff(ref) {
		t.Error("success did not clear the backoff window")
	}
}

// Keyed by the (operator, node) pair: one operator's dead node must never bench
// its healthy siblings.
func TestTargetBackoff_KeyedByNodeNotOperator(t *testing.T) {
	s := &ChainOperatorSource{}
	dead := NodeRef{Op: 7, Node: 1}
	sibling := NodeRef{Op: 7, Node: 2}

	s.RecordTargetOutcome(dead, false)
	if !s.TargetBackedOff(dead) {
		t.Error("failing node not backed off")
	}
	if s.TargetBackedOff(sibling) {
		t.Error("a sibling node of the same operator was backed off")
	}
}

// The failure count survives an elapsed window, which is what makes the backoff
// exponential under the "demote, don't skip" model: the node floats back into
// rotation, and if it fails again the next window doubles instead of restarting.
func TestTargetBackoff_StreakSurvivesElapsedWindow(t *testing.T) {
	s := &ChainOperatorSource{}
	ref := NodeRef{Op: 1, Node: 1}

	s.RecordTargetOutcome(ref, false)
	// Expire the first window without a success.
	ageBackoff(s, ref, steering.BackoffWindow(1)+time.Second)

	if s.TargetBackedOff(ref) {
		t.Fatal("still backed off after the window lapsed; traffic must re-probe it")
	}

	s.RecordTargetOutcome(ref, false)
	s.tgtBackoffMu.Lock()
	got := s.tgtBackoff[ref]
	s.tgtBackoffMu.Unlock()
	if got.Failures != 2 {
		t.Errorf("failures = %d, want 2 (streak must survive an elapsed window)", got.Failures)
	}
	if want := steering.BackoffWindow(2); got.Until.Sub(got.At) != want {
		t.Errorf("second window = %v, want %v (doubled)", got.Until.Sub(got.At), want)
	}
}

// A node we stopped routing to entirely shouldn't be remembered forever.
func TestTargetBackoff_SelfTrimsOnRead(t *testing.T) {
	s := &ChainOperatorSource{}
	ref := NodeRef{Op: 1, Node: 1}

	s.RecordTargetOutcome(ref, false)
	ageBackoff(s, ref, steering.BackoffWindow(1)+steering.TargetBackoffCap+time.Minute)

	if s.TargetBackedOff(ref) {
		t.Fatal("long-lapsed entry still reports backed off")
	}
	s.tgtBackoffMu.Lock()
	_, present := s.tgtBackoff[ref]
	s.tgtBackoffMu.Unlock()
	if present {
		t.Error("long-lapsed entry was not pruned on read")
	}
}

// An unknown node is never backed off — the store is sparse, so a miss must not
// read as a failure.
func TestTargetBackoff_UnknownNodeIsClean(t *testing.T) {
	s := &ChainOperatorSource{}
	if s.TargetBackedOff(NodeRef{Op: 99, Node: 99}) {
		t.Error("an unseen node reported as backed off")
	}
}
