/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Per-target-node exponential backoff, mirroring proto/go/zs/target_backoff.go.
// The relay stores track nodes that forward for us; this tracks nodes we send
// inference to that keep failing, and demotes them for a doubling window
// (30s, 1m, 2m, 4m, then 5m) so a dead target stops costing a round trip
// every turn.
//
// Demoted, never dropped: a model only one node serves stays reachable as a
// last resort. When a window lapses the node floats back and real traffic
// retries it; another failure doubles the next window, and a clean completion
// resets the streak.

import { type Backoff, backoffRemaining, recordFailure } from '@txnlab/zs-proto/steering'

import type { Clock } from '../ports.js'
import { type NodeRef, nodeRefString } from '../types.js'

export class TargetBackoffStore {
    readonly #clock: Clock
    // Sparse: an entry exists only after a failure, and a success deletes it.
    readonly #backoff = new Map<string, Backoff>()

    constructor(clock: Clock) {
        this.#clock = clock
    }

    /**
     * recordTargetOutcome notes whether a dispatch to the node served us. Record
     * a failure only for a target-attributable transient failure: never a
     * request-shape fault, which recurs on every peer, never a relay-side
     * fault, and never an unattributable gateway error.
     */
    recordTargetOutcome(target: NodeRef, ok: boolean, now: number = this.#clock()): void {
        const key = nodeRefString(target)
        if (ok) {
            this.#backoff.delete(key)
            return
        }
        this.#backoff.set(key, recordFailure(this.#backoff.get(key), now))
    }

    /**
     * targetBackoffRemainingMs is how long the node stays demoted, or 0.
     *
     * floorMs raises the window to at least floorMs past the last failure.
     * Dispatch passes 0, so a node floats back quickly. Discovery passes its
     * refetch cooldown, so a node corroborated unreachable is skipped by every
     * probe trigger for the whole cooldown: the 30s first window is shorter than
     * the probe heartbeat and would leave a gap.
     *
     * The failure count outlives a lapsed window, so a renewed failure
     * escalates, unless the node went a full cap-length grace period
     * untouched; then the record is pruned here.
     */
    targetBackoffRemainingMs(target: NodeRef, now: number = this.#clock(), floorMs = 0): number {
        const key = nodeRefString(target)
        let b = this.#backoff.get(key)
        if (b === undefined) return 0
        if (now < b.at) {
            // The wall clock stepped back. Unanchored, the demotion would last
            // the window plus the step; Go's monotonic clock never sees it.
            // Shift the record so the window runs from now.
            const shift = b.at - now
            b = { failures: b.failures, at: now, until: b.until - shift }
            this.#backoff.set(key, b)
        }
        const { remainingMs, forget } = backoffRemaining(b, now, floorMs)
        if (forget) this.#backoff.delete(key)
        return remainingMs
    }

    /** targetBackedOff reports whether candidate selection should demote the node below known-good peers. */
    targetBackedOff(target: NodeRef, now: number = this.#clock()): boolean {
        return this.targetBackoffRemainingMs(target, now) > 0
    }

    clear(): void {
        this.#backoff.clear()
    }
}
