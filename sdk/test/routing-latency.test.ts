/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import {
    DEFAULT_LATENCY_STATE_MAX,
    LATENCY_EWMA_ALPHA,
    LATENCY_STALE_MS as STALE,
    RelayLatencyStore,
} from '../src/routing/index.js'

const relay = { op: 2, node: 0 }
const target = { op: 9, node: 0 }
const other = { op: 8, node: 0 }

function store(maxEntries = 4096, clock = () => 0): RelayLatencyStore {
    return new RelayLatencyStore({ clock, maxEntries })
}

describe('RelayLatencyStore', () => {
    it('folds a relayed sample into the pair, relay and target keyings', () => {
        const s = store()
        s.recordRelayedRtt(relay, target, 120, 1_000)
        expect(s.relayLatencyForTarget(relay, target, 1_000)).toBe(120)
        expect(s.relayLatencyForTarget(relay, other, 1_000)).toBe(120)
        expect(s.targetLatency(target, 1_000)).toEqual({ ewmaMs: 120, samples: 1, at: 1_000 })
    })

    it('folds a direct sample into the target only', () => {
        const s = store()
        s.recordDirectRtt(target, 80, 1_000)
        expect(s.targetLatency(target, 1_000)?.ewmaMs).toBe(80)
        expect(s.relayLatencyForTarget(target, relay, 1_000)).toBeUndefined()
    })

    it('blends with the EWMA alpha', () => {
        const s = store()
        s.recordRelayedRtt(relay, target, 100, 1_000)
        s.recordRelayedRtt(relay, target, 200, 1_100)
        expect(s.relayLatencyForTarget(relay, target, 1_100)).toBeCloseTo(
            LATENCY_EWMA_ALPHA * 200 + (1 - LATENCY_EWMA_ALPHA) * 100,
            9,
        )
        expect(s.targetLatency(target, 1_100)?.samples).toBe(2)
    })

    it('treats a stale sample as absent, prunes it, and restarts the average', () => {
        const s = store()
        s.recordRelayedRtt(relay, target, 100, 1_000)
        expect(s.targetLatency(target, 1_000 + STALE)).toBeDefined()
        expect(s.targetLatency(target, 1_000 + STALE + 1)).toBeUndefined()
        expect(s.targetLatency(target, 1_000)).toBeUndefined()

        const later = 1_000 + STALE + 1
        s.recordRelayedRtt(relay, target, 500, later)
        expect(s.relayLatencyForTarget(relay, target, later)).toBe(500)
        expect(s.targetLatency(target, later)?.samples).toBe(1)
    })

    it('prefers the pair over the relay aggregate', () => {
        const s = store()
        s.recordRelayedRtt(relay, target, 100, 1_000)
        s.recordRelayedRtt(relay, other, 300, 1_100)
        expect(s.relayLatencyForTarget(relay, target, 1_100)).toBe(100)
        expect(s.relayLatencyForTarget(relay, { op: 7, node: 0 }, 1_100)).toBeCloseTo(160, 9)
        expect(s.relayLatencyForTarget({ op: 5, node: 0 }, target, 1_100)).toBeUndefined()
    })

    it('keys by node', () => {
        const s = store()
        s.recordRelayedRtt(relay, target, 100, 1_000)
        expect(s.relayLatencyForTarget({ op: 2, node: 1 }, target, 1_000)).toBeUndefined()
        expect(s.targetLatency({ op: 9, node: 1 }, 1_000)).toBeUndefined()
    })

    it('ignores a negative or non-finite sample', () => {
        const s = store()
        for (const ms of [Number.NaN, -5, Infinity]) s.recordRelayedRtt(relay, target, ms, 1_000)
        expect(s.targetLatency(target, 1_000)).toBeUndefined()
    })

    // A browser's coarsened timer can measure 0; dropped, such a node would be
    // unexplored forever. Go accepts it too.
    it('keeps a 0ms sample', () => {
        const s = store()
        s.recordDirectRtt(target, 0, 1_000)
        expect(s.targetLatency(target, 1_000)).toEqual({ ewmaMs: 0, samples: 1, at: 1_000 })
    })

    // The write and read paths, and Go, agree: a sample exactly
    // LATENCY_STALE_MS old is still fresh.
    it('blends a sample exactly the stale window after the last', () => {
        const s = store()
        s.recordDirectRtt(target, 100, 0)
        s.recordDirectRtt(target, 200, STALE)
        expect(s.targetLatency(target, STALE)).toEqual({ ewmaMs: 130, samples: 2, at: STALE })
    })

    it('reads the clock when no time is given', () => {
        let now = 1_000
        const s = store(4096, () => now)
        s.recordDirectRtt(target, 50)
        expect(s.targetLatency(target)?.at).toBe(1_000)
        now += STALE + 1
        expect(s.targetLatency(target)).toBeUndefined()
    })

    // The pair keying grows with relays × targets.
    it('holds each keying to maxEntries, evicting stale entries and then the oldest', () => {
        const s = store(2)
        s.recordDirectRtt({ op: 1, node: 0 }, 10, 0)
        s.recordDirectRtt({ op: 2, node: 0 }, 10, STALE)
        s.recordDirectRtt({ op: 3, node: 0 }, 10, STALE + 1)
        expect(s.targetLatency({ op: 1, node: 0 }, 0)).toBeUndefined()
        expect(s.targetLatency({ op: 2, node: 0 }, STALE + 1)).toBeDefined()

        s.recordDirectRtt({ op: 2, node: 0 }, 10, STALE + 3)
        s.recordDirectRtt({ op: 4, node: 0 }, 10, STALE + 4)
        expect(s.targetLatency({ op: 3, node: 0 }, STALE + 4)).toBeUndefined()
        expect(s.targetLatency({ op: 2, node: 0 }, STALE + 4)).toBeDefined()
        expect(s.targetLatency({ op: 4, node: 0 }, STALE + 4)).toBeDefined()
    })

    it('treats an unset, non-positive or non-finite maxEntries as the Go default, never unbounded', () => {
        expect(DEFAULT_LATENCY_STATE_MAX).toBe(4096)
        for (const maxEntries of [0, -1, Infinity, Number.NaN, undefined]) {
            const s = new RelayLatencyStore({ clock: () => 0, ...(maxEntries === undefined ? {} : { maxEntries }) })
            for (let i = 0; i <= DEFAULT_LATENCY_STATE_MAX; i++) s.recordDirectRtt({ op: i, node: 0 }, 10, i)
            expect(s.targetLatency({ op: 0, node: 0 }, DEFAULT_LATENCY_STATE_MAX)).toBeUndefined()
            expect(s.targetLatency({ op: 1, node: 0 }, DEFAULT_LATENCY_STATE_MAX)).toBeDefined()
        }
    })

    it('a backwards clock step keeps a sample fresh for at most the stale window', () => {
        const s = store()
        s.recordDirectRtt(target, 50, 86_400_000)
        expect(s.targetLatency(target, 0)).toBeDefined()
        expect(s.targetLatency(target, STALE)).toBeDefined()
        expect(s.targetLatency(target, STALE + 1)).toBeUndefined()
    })

    it('clear forgets every keying', () => {
        const s = store()
        s.recordRelayedRtt(relay, target, 100, 1_000)
        s.clear()
        expect(s.relayLatencyForTarget(relay, target, 1_000)).toBeUndefined()
        expect(s.targetLatency(target, 1_000)).toBeUndefined()
    })
})
