/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"time"

	"github.com/TxnLab/zerosignal/go/steering"
)

// Per-target-node EXPONENTIAL backoff — the third app-side routing-failure
// store, alongside relay_reputation.go (a relay's forward-failure streak) and
// relay_latency.go (client-observed RTT). Those two are *relay*-side; this one
// is *target*-side: it tracks nodes we dispatch INFERENCE to and that keep
// failing us, and demotes them for a growing window so a persistently-broken
// node stops costing every request a doomed round-trip.
//
// The window arithmetic is steering's (30s doubling to a 5m cap),
// golden-vectored against its TS twin in proto/ts/src/steering, which the TS
// SDK's TargetBackoffStore (sdk/src/routing/backoff.ts) calls, so the two SDKs
// route around a sick node identically. The store stays here: what it holds
// depends on which dispatches THIS process made.
//
// What records here is narrow on purpose. A transient failure attributed to the
// TARGET counts; a relay-side fault does not (relay reputation owns that), and
// an unattributable gateway error counts for NEITHER — see transient.AttrUnknown.
// Charging a target for a relay's broken CDN is how you bench a healthy node
// during someone else's outage, and during a fleet-wide restart it would bench
// most of the network at once.

// TargetBackoff is the proxy's per-target-node dispatch-failure memory.
//
// Keyed by the (operator id, node id) pair like every other routing store: a
// target is a single node (operator/node split — see the repo AGENTS.md), so
// one operator's dead node must never back off its healthy siblings.
type TargetBackoff interface {
	// RecordTargetOutcome notes whether a dispatch to this node served us. A
	// success clears the backoff outright (healthy again, straight back to the
	// preferred tier); a failure increments the consecutive count and re-arms the
	// window, doubling it each time up to the cap.
	//
	// Call ok=false ONLY for a target-attributable transient failure. Never for a
	// request-shape fault (it would recur on every peer and isn't the node's
	// fault), never for a relay-side fault, and never for an unattributable
	// gateway error.
	RecordTargetOutcome(target NodeRef, ok bool)

	// TargetBackedOff reports whether the node is inside an active window, i.e.
	// whether candidate selection should demote it below known-good peers.
	TargetBackedOff(target NodeRef) bool
}

// RecordTargetOutcome implements TargetBackoff. Safe for concurrent use (called
// from request goroutines).
func (s *ChainOperatorSource) RecordTargetOutcome(target NodeRef, ok bool) {
	s.tgtBackoffMu.Lock()
	defer s.tgtBackoffMu.Unlock()
	if ok {
		// delete rather than zero: the map stays sparse, holding only nodes that
		// are currently failing.
		delete(s.tgtBackoff, target)
		return
	}
	if s.tgtBackoff == nil {
		s.tgtBackoff = make(map[NodeRef]steering.Backoff)
	}
	s.tgtBackoff[target] = steering.RecordFailure(s.tgtBackoff[target], time.Now())
}

// TargetBackedOff implements TargetBackoff. Safe for concurrent use.
//
// Once a window lapses this returns false and the node floats back into the
// usable tier, so real traffic re-probes it. If that retry fails again the
// streak climbs and the next window doubles; a clean dispatch resets it to zero.
// So a node is never permanently banned — it only stays buried longer while it
// keeps failing. A node left alone for a full cap-length grace period is pruned
// on read, so the map self-trims instead of holding entries for nodes we have
// stopped routing to at all.
func (s *ChainOperatorSource) TargetBackedOff(target NodeRef) bool {
	s.tgtBackoffMu.Lock()
	defer s.tgtBackoffMu.Unlock()
	b, ok := s.tgtBackoff[target]
	if !ok {
		return false
	}
	remaining, forget := steering.BackoffRemaining(b, time.Now(), 0)
	if forget {
		delete(s.tgtBackoff, target)
	}
	return remaining > 0
}

var _ TargetBackoff = (*ChainOperatorSource)(nil)
