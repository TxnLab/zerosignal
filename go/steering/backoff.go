/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package steering

import "time"

// A target that keeps failing is demoted for a window that doubles per
// consecutive failure: 30s, 1m, 2m, 4m, then 5m. Demoted, never skipped, so a
// model one node serves stays reachable, and real traffic re-probes the node
// each time a window lapses.
const (
	// TargetBackoffBase is the first window: the client's 30s probe-staleness
	// window, so the node's reachability can re-settle before it is tried again.
	TargetBackoffBase = 30 * time.Second

	// TargetBackoffCap bounds the window: long enough to stop hammering a dead
	// node, short enough that a recovered one isn't exiled. It is also the grace
	// period after a lapsed window before the record is forgotten.
	TargetBackoffCap = 5 * time.Minute
)

// Backoff is one target node's failure record. Failures survives a lapsed
// window, so a renewed failure escalates rather than restarting at the base.
// The zero value is "no failures".
type Backoff struct {
	Failures int
	At       time.Time // the last failure
	Until    time.Time // the end of the current window
}

// BackoffWindow is the window for the n-th consecutive failure,
// min(TargetBackoffBase·2^(n-1), TargetBackoffCap), or 0 for n < 1.
func BackoffWindow(failures int) time.Duration {
	if failures < 1 {
		return 0
	}
	d := TargetBackoffBase
	for i := 1; i < failures; i++ {
		if d *= 2; d >= TargetBackoffCap {
			return TargetBackoffCap
		}
	}
	return d
}

// RecordFailure adds a failure at now and re-arms the window. A success is not
// a step here: it clears the record outright.
func RecordFailure(b Backoff, now time.Time) Backoff {
	n := b.Failures + 1
	return Backoff{Failures: n, At: now, Until: now.Add(BackoffWindow(n))}
}

// BackoffRemaining reports how long b keeps its target demoted at now, and
// whether the record has gone stale enough to forget: its window lapsed at
// least TargetBackoffCap ago.
//
// floor raises the window to at least floor past the last failure. Dispatch
// passes 0. A discovery probe passes its own refetch cooldown, so a node it
// found unreachable is skipped by every probe trigger for that long rather than
// only for the 30s first window.
//
// A wall clock that steps backwards holds the demotion until it catches up
// with Until, as it pauses Decay. A Go caller reading time.Now() is immune:
// its timestamps carry a monotonic reading. Bounding this for a wall-clock
// caller needs a re-anchored record written back, which is the store's job.
func BackoffRemaining(b Backoff, now time.Time, floor time.Duration) (remaining time.Duration, forget bool) {
	if b.Failures < 1 {
		return 0, true
	}
	until := b.Until
	if f := b.At.Add(floor); f.After(until) {
		until = f
	}
	if now.Before(until) {
		return until.Sub(now), false
	}
	return 0, now.Sub(until) >= TargetBackoffCap
}
