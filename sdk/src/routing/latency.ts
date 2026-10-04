/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Payer-observed network latency, mirroring proto/go/zs/relay_latency.go. The
// reliability stores answer "can I reach it"; this answers "how fast", so
// routing can prefer relays close to the payer and to the target, and demote
// pathologically slow targets.
//
// Latency stays out of the shared selection policy: that policy is
// golden-vectored and avoids float metrics, and each payer's RTT is its own
// vantage.
//
// Fed only by successful round trips that run no inference (a reserve, a
// details probe), so the number is network time. Both sources blend into one
// EWMA per key; their small constant difference doesn't change an ordering.
// Three keyings:
//   - pair, relay→target: the full payer→relay→target path, the primary
//     signal for which relay is fastest for this target.
//   - relay: the payer→relay leg over every target it forwarded for; the
//     fallback when a pair has no sample.
//   - target: over all relays and direct; drives the slow-target demotion.
// A relayed sample updates all three; a direct one only the target.

import { defaults } from '../config.js'
import type { Clock } from '../ports.js'
import { type NodeRef, nodeRefString } from '../types.js'

/**
 * Each sample weighs 30%: a one-off spike (a backoff-inflated reserve, a GC
 * pause) is damped while a real shift settles in a few samples.
 */
export const LATENCY_EWMA_ALPHA = 0.3

/**
 * A sample older than this is untrusted: reads prune it, and a new sample
 * restarts the average instead of blending across the gap. Well above the
 * probe interval, so a steadily probed path stays warm.
 */
export const LATENCY_STALE_MS = 5 * 60_000

/**
 * The samples a target needs before its latency can demote it. Relay weighting
 * only biases and never excludes, so it takes a single sample.
 */
export const LATENCY_MIN_SAMPLES = 2

/** A latency estimate: the EWMA in ms, the samples behind it, and when it was last updated. */
export interface LatencyStat {
    ewmaMs: number
    samples: number
    at: number
}

/** The live entries each keying holds when maxEntries is unset, as in Go. */
export const DEFAULT_LATENCY_STATE_MAX = defaults.discovery.latencyStateMax

export interface RelayLatencyOptions {
    clock: Clock
    /**
     * Live entries per keying; the pair keying is O(relays × targets). Zero,
     * negative or absent is DEFAULT_LATENCY_STATE_MAX, never unbounded.
     */
    maxEntries?: number
}

export class RelayLatencyStore {
    readonly #clock: Clock
    readonly #max: number
    readonly #pair = new Map<string, LatencyStat>()
    readonly #relay = new Map<string, LatencyStat>()
    readonly #target = new Map<string, LatencyStat>()

    constructor(opts: RelayLatencyOptions) {
        this.#clock = opts.clock
        const max = opts.maxEntries ?? 0
        this.#max = Number.isFinite(max) && max > 0 ? max : DEFAULT_LATENCY_STATE_MAX
    }

    /** recordRelayedRtt folds a relayed round trip into the pair, relay and target keyings. */
    recordRelayedRtt(relay: NodeRef, target: NodeRef, ms: number, now: number = this.#clock()): void {
        this.#observe(this.#pair, pairKey(relay, target), ms, now)
        this.#observe(this.#relay, nodeRefString(relay), ms, now)
        this.#observe(this.#target, nodeRefString(target), ms, now)
    }

    /** recordDirectRtt folds a direct round trip into the target keying: there is no relay leg. */
    recordDirectRtt(target: NodeRef, ms: number, now: number = this.#clock()): void {
        this.#observe(this.#target, nodeRefString(target), ms, now)
    }

    /**
     * relayLatencyForTarget is the estimate for routing through relay to
     * target: the pair when known, else the relay's aggregate, else undefined,
     * which relay weighting treats as explore.
     */
    relayLatencyForTarget(relay: NodeRef, target: NodeRef, now: number = this.#clock()): number | undefined {
        return (
            readFresh(this.#pair, pairKey(relay, target), now)?.ewmaMs ??
            readFresh(this.#relay, nodeRefString(relay), now)?.ewmaMs
        )
    }

    /** targetLatency is the target's aggregate, with its sample count for the LATENCY_MIN_SAMPLES gate. */
    targetLatency(target: NodeRef, now: number = this.#clock()): LatencyStat | undefined {
        return readFresh(this.#target, nodeRefString(target), now)
    }

    clear(): void {
        this.#pair.clear()
        this.#relay.clear()
        this.#target.clear()
    }

    // A missing or stale prior restarts the average from this sample.
    #observe(m: Map<string, LatencyStat>, key: string, ms: number, now: number): void {
        if (!(ms >= 0) || !Number.isFinite(ms)) return
        const prev = m.get(key)
        if (prev === undefined || now - prev.at > LATENCY_STALE_MS) {
            m.set(key, { ewmaMs: ms, samples: 1, at: now })
        } else {
            m.set(key, {
                ewmaMs: LATENCY_EWMA_ALPHA * ms + (1 - LATENCY_EWMA_ALPHA) * prev.ewmaMs,
                samples: prev.samples + 1,
                at: now,
            })
        }
        evictOversize(m, this.#max, now)
    }
}

function pairKey(relay: NodeRef, target: NodeRef): string {
    return `${nodeRefString(relay)}->${nodeRefString(target)}`
}

function readFresh(m: Map<string, LatencyStat>, key: string, now: number): LatencyStat | undefined {
    const s = m.get(key)
    if (s === undefined) return undefined
    if (now < s.at) {
        // The wall clock stepped back: re-date the sample so it stays fresh for
        // LATENCY_STALE_MS from here, not that plus the step.
        const redated = { ...s, at: now }
        m.set(key, redated)
        return redated
    }
    if (now - s.at > LATENCY_STALE_MS) {
        m.delete(key)
        return undefined
    }
    return s
}

// evictOversize bounds m to max live entries: stale entries go first, which is
// normally enough, then the oldest by timestamp. It does nothing under the cap,
// so the steady-state cost is one size check.
function evictOversize(m: Map<string, LatencyStat>, max: number, now: number): void {
    if (m.size <= max) return
    for (const [k, s] of m) {
        if (now - s.at > LATENCY_STALE_MS) m.delete(k)
    }
    while (m.size > max) {
        let oldestKey: string | undefined
        let oldestAt = Infinity
        for (const [k, s] of m) {
            if (s.at < oldestAt) {
                oldestKey = k
                oldestAt = s.at
            }
        }
        if (oldestKey === undefined) break
        m.delete(oldestKey)
    }
}
