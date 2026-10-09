/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import {
    RELAY_ENDPOINT_DOWN_TTL_MS as DOWN_TTL,
    RELAY_UNREACHABLE_TTL_MS as TTL,
    RelayHealthStore,
    RelayReputationStore,
} from '../src/routing/index.js'
import { type NodeRef, nodeRefString as k } from '../src/index.js'

const r2 = { op: 2, node: 0 }
const r5 = { op: 5, node: 0 }

function harness() {
    let now = 0
    const charged: NodeRef[] = []
    const store = new RelayHealthStore({
        clock: () => now,
        reputation: {
            recordRelayOutcome: (r, ok) => {
                expect(ok).toBe(false)
                charged.push(r)
            },
        },
    })
    return { store, charged, at: (t: number) => (now = t) }
}

describe('RelayHealthStore exclusions', () => {
    it('excludes relays just marked unreachable, by nodeRefString', () => {
        const { store } = harness()
        expect(store.relayExclusions().size).toBe(0)
        store.markRelayUnreachable(r2)
        store.markRelayUnreachable(r5)
        expect(store.relayExclusions()).toEqual(new Set([k(r2), k(r5)]))
    })

    it('ages a mark out at its TTL, and the prune is durable', () => {
        const { store } = harness()
        store.markRelayUnreachable(r2)
        expect(store.relayExclusions(TTL - 1)).toEqual(new Set([k(r2)]))
        expect(store.relayExclusions(TTL)).toEqual(new Set())
        expect(store.relayExclusions(0)).toEqual(new Set())
    })

    it('reads the clock when no time is given', () => {
        const h = harness()
        h.store.markRelayUnreachable(r2)
        h.at(TTL)
        expect(h.store.relayExclusions()).toEqual(new Set())
    })

    it('a re-mark refreshes the window', () => {
        const h = harness()
        h.store.markRelayUnreachable(r2)
        h.at(TTL - 1)
        h.store.markRelayUnreachable(r2)
        expect(h.store.relayExclusions(TTL + 10).has(k(r2))).toBe(true)
    })

    it('parks a dead endpoint for the long TTL, outliving a transient mark', () => {
        const { store } = harness()
        store.markRelayEndpointDead(r2)
        store.markRelayUnreachable(r5)
        expect(store.relayExclusions(TTL + 1)).toEqual(new Set([k(r2)]))
        expect(store.relayExclusions(DOWN_TTL)).toEqual(new Set())
    })

    it('markRelayReachable clears only that relay', () => {
        const { store } = harness()
        store.markRelayUnreachable(r2)
        store.markRelayUnreachable(r5)
        store.markRelayReachable(r2)
        expect(store.relayExclusions()).toEqual(new Set([k(r5)]))
    })

    it('keys by node: a dead node leaves its operator sibling eligible', () => {
        const { store } = harness()
        store.markRelayEndpointDead({ op: 3, node: 4 })
        expect(store.relayExclusions()).toEqual(new Set([k({ op: 3, node: 4 })]))
    })
})

describe('RelayHealthStore verdict', () => {
    it('is undefined without direct evidence, and a transient mark leaves it so', () => {
        const { store } = harness()
        expect(store.relayReachVerdict(r2)).toBeUndefined()
        store.markRelayUnreachable(r2)
        expect(store.relayReachVerdict(r2)).toBeUndefined()
    })

    it('flips on each direct contact', () => {
        const { store } = harness()
        store.markRelayEndpointDead(r2)
        expect(store.relayReachVerdict(r2)).toBe(false)
        store.markRelayReachable(r2)
        expect(store.relayReachVerdict(r2)).toBe(true)
        store.markRelayEndpointDead(r2)
        expect(store.relayReachVerdict(r2)).toBe(false)
    })

    // Otherwise a never-reachable relay bounces back into the preferred tier
    // every time its park lapses.
    it('a false verdict outlives the park', () => {
        const { store } = harness()
        store.markRelayEndpointDead(r2)
        expect(store.relayExclusions(DOWN_TTL).size).toBe(0)
        expect(store.relayReachVerdict(r2)).toBe(false)
    })

    it('is per node', () => {
        const { store } = harness()
        store.markRelayEndpointDead({ op: 3, node: 4 })
        expect(store.relayReachVerdict({ op: 3, node: 2 })).toBeUndefined()
    })
})

describe('recordRelayTransportFailure', () => {
    it('parks the relay, sets the false verdict, and charges its reputation', () => {
        const { store, charged } = harness()
        store.recordRelayTransportFailure(r2)
        expect(store.relayExclusions(DOWN_TTL - 1)).toEqual(new Set([k(r2)]))
        expect(store.relayReachVerdict(r2)).toBe(false)
        expect(charged).toEqual([r2])
    })

    it('lands on a real reputation store', () => {
        const reputation = new RelayReputationStore({ clock: () => 0, targetReachable: () => false })
        const store = new RelayHealthStore({ clock: () => 0, reputation })
        store.recordRelayTransportFailure(r2)
        expect(reputation.standing(r2).failures).toBe(1)
    })
})

describe('RelayHealthStore parks', () => {
    // The stranding fallback can send one request through an endpoint-dead
    // relay; its hop failure must not cut the park to 30s.
    it('a transient mark never shortens a longer park', () => {
        const h = harness()
        h.store.markRelayEndpointDead(r2)
        h.at(60_000)
        h.store.markRelayUnreachable(r2)
        expect(h.store.relayExclusions(DOWN_TTL - 1).has(k(r2))).toBe(true)
        expect(h.store.relayExclusions(DOWN_TTL).has(k(r2))).toBe(false)
    })

    it('a longer mark extends a shorter one', () => {
        const h = harness()
        h.store.markRelayUnreachable(r2)
        h.at(1_000)
        h.store.markRelayEndpointDead(r2)
        expect(h.store.relayExclusions(1_000 + DOWN_TTL - 1).has(k(r2))).toBe(true)
    })

    // Go's monotonic clock never sees a step; a wall clock must not stretch a
    // park by the size of the step.
    // With no read in between to re-date it, the prior park's remainder is
    // capped at its own ttl rather than stretched by the step.
    it('a mark after a backwards step keeps at most the prior ttl', () => {
        const h = harness()
        h.at(1_000)
        h.store.markRelayEndpointDead(r2)
        h.at(0)
        h.store.markRelayUnreachable(r2)
        expect(h.store.relayExclusions(DOWN_TTL - 1).has(k(r2))).toBe(true)
        expect(h.store.relayExclusions(DOWN_TTL).has(k(r2))).toBe(false)
    })

    it('a backwards clock step leaves a park at most its ttl', () => {
        const h = harness()
        h.at(86_400_000)
        h.store.markRelayUnreachable(r2)
        expect(h.store.relayExclusions(0).has(k(r2))).toBe(true)
        expect(h.store.relayExclusions(TTL - 1).has(k(r2))).toBe(true)
        expect(h.store.relayExclusions(TTL).has(k(r2))).toBe(false)
    })
})

it('holds at most 2048 verdicts, evicting the oldest', () => {
    const { store } = harness()
    for (let i = 0; i <= 2048; i++) store.markRelayReachable({ op: i, node: 0 })
    expect(store.relayReachVerdict({ op: 0, node: 0 })).toBeUndefined()
    expect(store.relayReachVerdict({ op: 1, node: 0 })).toBe(true)
    expect(store.relayReachVerdict({ op: 2048, node: 0 })).toBe(true)
})

it('clear forgets exclusions and verdicts', () => {
    const { store } = harness()
    store.markRelayEndpointDead(r2)
    store.markRelayReachable(r5)
    store.clear()
    expect(store.relayExclusions().size).toBe(0)
    expect(store.relayReachVerdict(r2)).toBeUndefined()
    expect(store.relayReachVerdict(r5)).toBeUndefined()
})
