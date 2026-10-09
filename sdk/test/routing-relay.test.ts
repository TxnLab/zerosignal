/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import type { Operator as SelectionOperator } from '@txnlab/zs-proto/selection'
import {
    PROTO_VERSION,
    RELAY_METHOD_HEADER,
    RELAY_PATH,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
} from '@txnlab/zs-proto/wire'

import { boundedMapSet } from '../src/routing/bounded-map.js'
import {
    LATENCY_FLOOR_FRACTION,
    type LatencyOf,
    NodeExclusionStore,
    type RelayHop,
    applyRelay,
    randomRelaySeed,
    relayRef,
    selectRelayHopWeighted,
    targetRef,
} from '../src/routing/index.js'
import { nodeRefString } from '../src/index.js'

function op(o: Partial<SelectionOperator> = {}): SelectionOperator {
    return {
        id: 1,
        node_id: 0,
        owner_addr: `OWNER-${o.id ?? 1}`,
        base_url: `https://op${o.id ?? 1}-${o.node_id ?? 0}.example`,
        proto_version: PROTO_VERSION,
        reachable: true,
        tee_attested: false,
        models: [],
        model_capacities: {},
        builtin_tools: [],
        ...o,
    }
}

describe('selectRelayHopWeighted', () => {
    const target = op({ id: 1 })
    const none: LatencyOf = () => undefined

    it('picks an eligible relay and carries both node refs and its advertised version', () => {
        const relay = op({ id: 2, node_id: 3, proto_version: '9.9' })
        const hop = selectRelayHopWeighted([target, relay], target, 0, none)
        expect(hop).toEqual<RelayHop>({
            baseUrl: 'https://op2-3.example',
            targetId: 1,
            targetNodeId: 0,
            relayId: 2,
            relayNodeId: 3,
            relayProtoVersion: '9.9',
        })
        expect(relayRef(hop!)).toEqual({ op: 2, node: 3 })
        expect(targetRef(hop!)).toEqual({ op: 1, node: 0 })
    })

    it('returns null when nothing but the target, or its owner, is eligible', () => {
        expect(selectRelayHopWeighted([target], target, 0, none)).toBeNull()
        expect(selectRelayHopWeighted([target, op({ id: 2, owner_addr: 'OWNER-1' })], target, 0, none)).toBeNull()
    })

    it('drops excluded relay nodes by nodeRefString, leaving siblings eligible', () => {
        const a = op({ id: 2, node_id: 1 })
        const b = op({ id: 2, node_id: 2 })
        const hop = selectRelayHopWeighted([target, a, b], target, 0, none, new Set([nodeRefString({ op: 2, node: 1 })]))
        expect([hop?.relayId, hop?.relayNodeId]).toEqual([2, 2])
        expect(selectRelayHopWeighted([target, a], target, 0, none, new Set(['2/1']))).toBeNull()
    })

    it('asks latencyOf by relay node', () => {
        const asked: string[] = []
        selectRelayHopWeighted([target, op({ id: 2, node_id: 5 })], target, 0, (r) => {
            asked.push(nodeRefString(r))
            return undefined
        })
        expect(asked).toEqual(['2/5'])
    })

    // A cold tab routes exactly as the unweighted rotation did.
    it('with no latency, picks pool[seed % len]', () => {
        const pool = [target, op({ id: 2 }), op({ id: 3 })]
        for (const seed of [0, 2, 4]) expect(selectRelayHopWeighted(pool, target, seed, none)?.relayId).toBe(2)
        for (const seed of [1, 3, 5]) expect(selectRelayHopWeighted(pool, target, seed, none)?.relayId).toBe(3)
    })

    // Go's seed is a uint64 and can't be negative or fractional; here it is a
    // number, read as a uint32 on both paths.
    it('reads a negative or fractional seed as a uint32 rather than crashing', () => {
        const pool = [target, op({ id: 2 }), op({ id: 3 })]
        expect(selectRelayHopWeighted(pool, target, -1, none)?.relayId).toBe(3)
        expect(selectRelayHopWeighted(pool, target, 2.5, none)?.relayId).toBe(2)
        expect(selectRelayHopWeighted(pool, target, -1, () => 10)?.relayId).toBe(3)
    })

    // With an even count of known relays the explore weight is the mean of the
    // middle two, as Go's medianFloat. Relays at 10ms and 200ms weigh 1/60 and
    // 1/250, so the cold relay weighs their mean; after the floor mix the
    // cumulative shares are 0.507 and 0.667. Taking either middle weight alone
    // moves the boundaries to 0.429 and 0.571 (or 0.62 and 0.68).
    it('explores a cold relay at the mean of the middle two weights', () => {
        const pool = [target, op({ id: 2 }), op({ id: 3 }), op({ id: 4 })]
        const lat: LatencyOf = (r) => (r.op === 2 ? 10 : r.op === 3 ? 200 : undefined)
        const at = (f: number) => selectRelayHopWeighted(pool, target, Math.floor(f * 0x1_0000_0000), lat)?.relayId
        expect([at(0.45), at(0.6), at(0.65), at(0.7)]).toEqual([2, 3, 3, 4])
    })

    const SWEEP = 1000
    function sweep(pool: SelectionOperator[], latencyOf: LatencyOf): Map<number, number> {
        const counts = new Map<number, number>()
        for (let i = 0; i < SWEEP; i++) {
            const hop = selectRelayHopWeighted(pool, target, Math.floor((i / SWEEP) * 0x1_0000_0000), latencyOf)
            if (hop) counts.set(hop.relayId, (counts.get(hop.relayId) ?? 0) + 1)
        }
        return counts
    }
    const lat = (r: { op: number }) => (r.op === 2 ? 50 : r.op === 3 ? 5000 : undefined)

    // The floor is the §3f diffusion bound: without it the fast relay takes ~98%.
    it('biases toward the faster relay within the floor', () => {
        const c = sweep([target, op({ id: 2 }), op({ id: 3 })], lat)
        const cap = 1 - LATENCY_FLOOR_FRACTION + LATENCY_FLOOR_FRACTION / 2
        expect(c.get(2)!).toBeGreaterThan(c.get(3)!)
        expect(c.get(2)!).toBeLessThanOrEqual(Math.ceil(cap * SWEEP) + 1)
        expect(c.get(3)!).toBeGreaterThanOrEqual(Math.floor((LATENCY_FLOOR_FRACTION / 2) * SWEEP) - 1)
    })

    it('explores a relay with no sample at the median weight', () => {
        const c = sweep([target, op({ id: 2 }), op({ id: 3 }), op({ id: 4 })], lat)
        expect(c.get(4)!).toBeGreaterThan(100)
        expect(c.get(2)!).toBeGreaterThan(c.get(4)!)
        expect(c.get(4)!).toBeGreaterThan(c.get(3)!)
    })
})

describe('applyRelay', () => {
    const hop: RelayHop = {
        baseUrl: 'https://relay.example',
        targetId: 7,
        targetNodeId: 4,
        relayId: 2,
        relayNodeId: 0,
        relayProtoVersion: '',
    }

    it('passes a direct request through, copying its headers', () => {
        const headers = { a: '1' }
        const out = applyRelay(null, 'https://t.example/v1/zs/reserve', 'POST', headers)
        expect(out).toEqual({ url: 'https://t.example/v1/zs/reserve', method: 'POST', headers: { a: '1' } })
        expect(out.headers).not.toBe(headers)
    })

    it('repoints to the relay route as a POST with the relay headers', () => {
        const out = applyRelay(hop, 'https://t.example/v1/zs/details?x=1', 'GET', { Accept: 'application/json' })
        expect(out.url).toBe(`https://relay.example${RELAY_PATH}`)
        expect(out.method).toBe('POST')
        expect(out.headers).toEqual({
            Accept: 'application/json',
            [RELAY_TARGET_HEADER]: '7',
            [RELAY_TARGET_NODE_HEADER]: '4',
            [RELAY_PATH_HEADER]: '/v1/zs/details',
            [RELAY_METHOD_HEADER]: 'GET',
        })
    })

    it("never lets a caller's header, under any spelling, override the relay headers", () => {
        const out = applyRelay(hop, 'https://t.example/v1/chat/completions', 'POST', {
            // None in canonical spelling: those keys are overwritten by the
            // spread whether or not the filter catches them.
            [RELAY_TARGET_HEADER.toLowerCase()]: '999',
            [RELAY_TARGET_NODE_HEADER.toLowerCase()]: '999',
            [RELAY_PATH_HEADER.toUpperCase()]: '/evil',
            [RELAY_METHOD_HEADER.toUpperCase()]: 'DELETE',
            'Content-Type': 'application/json',
        })
        expect(out.headers).toEqual({
            'Content-Type': 'application/json',
            [RELAY_TARGET_HEADER]: '7',
            [RELAY_TARGET_NODE_HEADER]: '4',
            [RELAY_PATH_HEADER]: '/v1/chat/completions',
            [RELAY_METHOD_HEADER]: 'POST',
        })
    })

    it('keeps an explicit inner path with its query', () => {
        const inner = '/v1/zs/details?model=alpha&expand=coordinates%2Cdigest'
        expect(applyRelay(hop, `https://t.example${inner}`, 'GET', {}, inner).headers[RELAY_PATH_HEADER]).toBe(inner)
    })
})

it('randomRelaySeed is a uint32', () => {
    const seed = randomRelaySeed()
    expect(Number.isInteger(seed)).toBe(true)
    expect(seed).toBeGreaterThanOrEqual(0)
    expect(seed).toBeLessThanOrEqual(0xffffffff)
})

describe('NodeExclusionStore', () => {
    it('is sticky, idempotent and keyed by node', () => {
        const s = new NodeExclusionStore()
        s.excludeNode({ op: 7, node: 1 })
        s.excludeNode({ op: 7, node: 1 })
        expect(s.nodeExcluded({ op: 7, node: 1 })).toBe(true)
        expect(s.nodeExcluded({ op: 7, node: 2 })).toBe(false)
        expect(s.nodeExcluded({ op: 8, node: 1 })).toBe(false)
        s.clear()
        expect(s.nodeExcluded({ op: 7, node: 1 })).toBe(false)
    })
})

describe('boundedMapSet', () => {
    it('evicts the oldest past max', () => {
        const m = new Map<string, number>()
        for (let i = 0; i < 100; i++) boundedMapSet(m, `k${i}`, i, 10)
        expect([m.size, m.has('k99'), m.has('k89')]).toEqual([10, true, false])
    })

    // A bulk re-set of the live fleet must not evict a node it just refreshed.
    it('a re-set moves the key to newest', () => {
        const m = new Map<string, number>()
        for (let i = 0; i < 10; i++) boundedMapSet(m, `k${i}`, i, 10)
        boundedMapSet(m, 'k0', 999, 10)
        boundedMapSet(m, 'k10', 10, 10)
        expect([m.get('k0'), m.has('k1'), m.size]).toEqual([999, false, 10])
    })

    it('max ≤ 0 is unbounded', () => {
        const m = new Map<string, number>()
        for (let i = 0; i < 50; i++) boundedMapSet(m, `k${i}`, i, 0)
        expect(m.size).toBe(50)
    })
})
