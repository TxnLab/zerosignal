/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { ModelDemand, type ProbeNode, probeResponsivenessScore, selectProbeSet } from '../src/catalog/index.js'

interface VectorNode {
    op: number
    node: number
    ttft_ewma_ms: number
    tokens_per_sec_ewma: number
    models: string[]
    last_refresh_at_ms: number
    reachable_as_of_ms: number
}

interface Vectors {
    probe: Array<{
        name: string
        nodes: VectorNode[]
        demand: string[]
        budget: number
        target_top_k: number
        cursor: number
        want: Array<{ probe_all: boolean; set: Array<[number, number]>; cursor: number }>
    }>
    demand: Array<{ name: string; demand_max: number; record: string[]; want: string[] }>
}

const vectors: Vectors = JSON.parse(
    readFileSync(new URL('../../testdata/probe_set_vectors.json', import.meta.url), 'utf8'),
)

const byRef = (a: [number, number], b: [number, number]) => a[0] - b[0] || a[1] - b[1]

describe('selectProbeSet vectors', () => {
    it.each(vectors.probe.map((v) => [v.name, v] as const))('%s', (_, v) => {
        // bigint ids and metrics, as an app reading the chain holds them.
        const nodes: ProbeNode[] = v.nodes.map((n) => ({
            op: BigInt(n.op),
            node: BigInt(n.node),
            ttftEwmaMs: BigInt(n.ttft_ewma_ms),
            tokensPerSecEwma: BigInt(n.tokens_per_sec_ewma),
            models: n.models,
            // Never is absent, as on an operator the registry never tried.
            ...(n.last_refresh_at_ms !== 0 && { lastRefreshAt: n.last_refresh_at_ms }),
            ...(n.reachable_as_of_ms !== 0 && { reachableAsOf: n.reachable_as_of_ms }),
        }))
        let cursor = v.cursor
        const got = v.want.map(() => {
            const sel = selectProbeSet(nodes, v.demand, v.budget, v.target_top_k, cursor)
            cursor = sel.cursor
            return {
                probe_all: sel.probe === null,
                set: (sel.probe ?? []).map((n) => [Number(n.op), Number(n.node)] as [number, number]).sort(byRef),
                cursor: sel.cursor,
            }
        })
        expect(got).toEqual(v.want)
    })

    it('reads number ids and metrics the same as bigint ones', () => {
        for (const v of vectors.probe) {
            const nodes: ProbeNode[] = v.nodes.map((n) => ({
                op: n.op,
                node: n.node,
                ttftEwmaMs: n.ttft_ewma_ms,
                tokensPerSecEwma: n.tokens_per_sec_ewma,
                models: n.models,
                // 0 as given, which reads as never just as absent does.
                lastRefreshAt: n.last_refresh_at_ms,
                reachableAsOf: n.reachable_as_of_ms,
            }))
            let cursor = v.cursor
            for (const want of v.want) {
                const sel = selectProbeSet(nodes, v.demand, v.budget, v.target_top_k, cursor)
                cursor = sel.cursor
                expect(
                    {
                        probe_all: sel.probe === null,
                        set: (sel.probe ?? []).map((n) => [Number(n.op), Number(n.node)] as [number, number]).sort(byRef),
                        cursor: sel.cursor,
                    },
                    v.name,
                ).toEqual(want)
            }
        }
    })
})

describe('ModelDemand vectors', () => {
    it.each(vectors.demand.map((v) => [v.name, v] as const))('%s', (_, v) => {
        const d = new ModelDemand(v.demand_max)
        for (const m of v.record) d.record(m)
        expect(d.snapshot()).toEqual(v.want)
    })

    it('clear forgets every model', () => {
        const d = new ModelDemand()
        d.record('a')
        d.clear()
        expect(d.snapshot()).toEqual([])
    })

    it('defaults to 32 models', () => {
        const d = new ModelDemand()
        for (let i = 0; i < 40; i++) d.record(`m${i}`)
        expect(d.snapshot()).toHaveLength(32)
        expect(d.snapshot()[0]).toBe('m39')
    })
})

describe('probeResponsivenessScore', () => {
    it('reads no TTFT as the last possible score', () => {
        expect(probeResponsivenessScore({})).toBe((1n << 64n) - 1n)
        expect(probeResponsivenessScore({ ttftEwmaMs: 0, tokensPerSecEwma: 50 })).toBe((1n << 64n) - 1n)
    })

    it('wraps at uint64 as Go does', () => {
        expect(probeResponsivenessScore({ ttftEwmaMs: (1n << 64n) - 1n, tokensPerSecEwma: 128000n })).toBe(0n)
    })
})
