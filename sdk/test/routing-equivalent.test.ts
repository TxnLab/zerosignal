/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { ENDPOINT_RESPONSES, type Constraints, type Operator } from '@txnlab/zs-proto/selection'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import {
    type IdentityRow,
    type ModelIdentity,
    consensusCanonicalForModel,
    consensusDigestForModel,
    consensusSourceForModel,
    equivalentSpellingLists,
    mergeOrderedByCost,
    modelIdentityMatcher,
    sourceIdentityKey,
} from '../src/routing/index.js'

interface Row extends IdentityRow {
    id: number
}

function row(id: number, models: Record<string, ModelIdentity>, reachability = 'ok'): Row {
    return { id, reachability, modelInfos: new Map(Object.entries(models)) }
}

describe('sourceIdentityKey', () => {
    it('strips the scheme and revision and folds case', () => {
        expect(sourceIdentityKey('hf:Org/Model@abc123')).toBe('org/model')
        expect(sourceIdentityKey('org/model')).toBe('org/model')
    })
})

describe('identity consensus', () => {
    it('takes the digest every reachable server agrees on', () => {
        const rows = [row(1, { a: { weightsDigest: 'd1' } }), row(2, { a: { weightsDigest: 'd1' } })]
        expect(consensusDigestForModel(rows, 'a')).toBe('d1')
    })

    it('aborts on a reachable disagreement, even with a down server agreeing', () => {
        const rows = [
            row(1, { a: { weightsDigest: 'd1' } }),
            row(2, { a: { weightsDigest: 'd2' } }),
            row(3, { a: { weightsDigest: 'd1' } }, 'failing'),
        ]
        expect(consensusDigestForModel(rows, 'a')).toBeUndefined()
    })

    it('lets reachable servers outvote a cached down one', () => {
        const rows = [
            row(1, { a: { weightsDigest: 'd1' } }),
            row(2, { a: { weightsDigest: 'd1' } }),
            row(3, { a: { weightsDigest: 'd2' } }, 'failing'),
        ]
        expect(consensusDigestForModel(rows, 'a')).toBe('d1')
    })

    it('counts a declared-but-degenerate source as dissent', () => {
        // "hf:" keys to the empty string: a declaration, not silence.
        const mixed = [row(1, { a: { source: 'hf:' } }), row(2, { a: { source: 'org/m' } })]
        expect(consensusSourceForModel(mixed, 'a')).toBeUndefined()
        // And it still marks the model as sourced, blocking the canonical tier.
        const degenerate = [row(1, { a: { source: 'hf:', canonicalId: 'c' } })]
        expect(consensusCanonicalForModel(degenerate, 'a')).toBeUndefined()
    })

    it('blocks the canonical tier when digests exist, even disagreeing ones', () => {
        const rows = [
            row(1, { a: { weightsDigest: 'd1', canonicalId: 'c' } }),
            row(2, { a: { weightsDigest: 'd2', canonicalId: 'c' } }),
        ]
        expect(consensusCanonicalForModel(rows, 'a')).toBeUndefined()
    })

    it('falls back to cached rows when no reachable server has an opinion', () => {
        const rows = [row(1, { a: { weightsDigest: 'd1' } }, 'failing'), row(2, { a: {} })]
        expect(consensusDigestForModel(rows, 'a')).toBe('d1')
    })

    it('uses the source tier only when nobody publishes a digest', () => {
        const sourced = [row(1, { a: { source: 'hf:Org/M@r1' } }), row(2, { a: { source: 'org/m' } })]
        expect(consensusSourceForModel(sourced, 'a')).toBe('org/m')
        const withDigest = [...sourced, row(3, { a: { weightsDigest: 'd1' } }, 'failing')]
        expect(consensusSourceForModel(withDigest, 'a')).toBeUndefined()
    })

    it('uses the canonical tier only when nobody publishes a digest or source', () => {
        const rows = [row(1, { a: { canonicalId: 'X-AI/Grok' } }), row(2, { a: { canonicalId: 'x-ai/grok' } })]
        expect(consensusCanonicalForModel(rows, 'a')).toBe('x-ai/grok')
        expect(consensusCanonicalForModel([...rows, row(3, { a: { source: 'o/m' } })], 'a')).toBeUndefined()
    })
})

describe('modelIdentityMatcher', () => {
    it('is undefined with no identity at any tier', () => {
        expect(modelIdentityMatcher([row(1, { a: {} })], 'a')).toBeUndefined()
    })

    it('matches by digest under the digest tier', () => {
        const q = modelIdentityMatcher([row(1, { a: { weightsDigest: 'd1' } })], 'a')!
        expect(q({ weightsDigest: 'd1' })).toBe(true)
        expect(q({ weightsDigest: 'd2' })).toBe(false)
        expect(q({ source: 'o/m' })).toBe(false)
        expect(q(undefined)).toBe(false)
    })

    it('never lets a digest-bearing peer ride on a source match', () => {
        const q = modelIdentityMatcher([row(1, { a: { source: 'o/m' } })], 'a')!
        expect(q({ source: 'hf:O/M@x' })).toBe(true)
        expect(q({ source: 'o/m', weightsDigest: 'd1' })).toBe(false)
    })

    it('never lets a sourced peer ride on a canonical match', () => {
        const q = modelIdentityMatcher([row(1, { a: { canonicalId: 'c' } })], 'a')!
        expect(q({ canonicalId: 'C' })).toBe(true)
        expect(q({ canonicalId: 'c', source: 'o/m' })).toBe(false)
    })
})

function op(id: number, models: string[], price = 1): Operator {
    return {
        id,
        node_id: 0,
        owner_addr: `owner${id}`,
        base_url: `https://op${id}.example`,
        proto_version: PROTO_VERSION,
        reachable: true,
        tee_attested: false,
        models,
        model_capacities: Object.fromEntries(
            models.map((m) => [
                m,
                {
                    context_window: 128_000,
                    max_output_tokens: 4096,
                    serves_image_gen: false,
                    serves_image_edit: false,
                    offers_image_gen_tool: false,
                    offers_image_edit_tool: false,
                    input_usd_per_1m: price,
                    output_usd_per_1m: price,
                    image_rate_micro_usdc: 0,
                    image_edit_rate_micro_usdc: 0,
                },
            ]),
        ),
        builtin_tools: [],
    }
}

const constraints: Omit<Constraints, 'model' | 'affinity_policy'> = {
    input_tokens: 0,
    max_output_tokens: 0,
    endpoint: ENDPOINT_RESPONSES,
    require_tee: false,
    allow_staging: false,
    requested_tools: null,
    image_tool_gen_budget: 0,
    image_tool_edit_budget: 0,
}

describe('equivalentSpellingLists', () => {
    const rows = [
        row(1, { a: { weightsDigest: 'd1' } }),
        row(2, { b: { weightsDigest: 'd1' } }),
        row(3, { b: { weightsDigest: 'd2' } }),
        row(4, { c: { weightsDigest: 'd1' }, a: { weightsDigest: 'd1' } }),
    ]
    const ops = [op(1, ['a']), op(2, ['b'], 3), op(3, ['b'], 1), op(4, ['c', 'a'], 2)]
    const rowOf = (o: Operator) => rows.find((r) => r.id === o.id)
    const shape = (lists: { row: Row; modelId: string }[][]) => lists.map((l) => l.map((c) => `${c.row.id}/${c.modelId}`))

    it('lists each other spelling of the same model, one price-ordered list per id', () => {
        // Op 3 serves b under a different digest, so it doesn't ride along on
        // op 2's match; op 4's 'a' is the selected id itself.
        const lists = equivalentSpellingLists('a', rows, rowOf, ops, [{ id: 1, node_id: 0 }], constraints)
        expect(shape(lists)).toEqual([['2/b'], ['4/c']])
    })

    it('skips only nodes actually tried', () => {
        const lists = equivalentSpellingLists('a', rows, rowOf, ops, [{ id: 4, node_id: 0 }], constraints)
        expect(shape(lists)).toEqual([['2/b']])
    })

    it('rechecks a node per spelling before marking it seen', () => {
        // Node 3 serves b under the wrong digest and c under the right one: the
        // failed b check must not keep it out of the c list.
        const r = [
            row(1, { a: { weightsDigest: 'd1' } }),
            row(2, { b: { weightsDigest: 'd1' } }),
            row(3, { b: { weightsDigest: 'd2' }, c: { weightsDigest: 'd1' } }),
        ]
        const o = [op(1, ['a']), op(2, ['b']), op(3, ['b', 'c'])]
        const lists = equivalentSpellingLists('a', r, (x) => r.find((y) => y.id === x.id), o, [], constraints)
        expect(shape(lists)).toEqual([['2/b'], ['3/c']])
    })

    it('lists a node at most once across spellings', () => {
        const r = [
            row(1, { a: { weightsDigest: 'd1' } }),
            row(2, { b: { weightsDigest: 'd1' }, c: { weightsDigest: 'd1' } }),
        ]
        const o = [op(1, ['a']), op(2, ['b', 'c'])]
        const lists = equivalentSpellingLists('a', r, (x) => r.find((y) => y.id === x.id), o, [], constraints)
        expect(shape(lists)).toEqual([['2/b']])
    })

    it('keys tried nodes by operator AND node', () => {
        // Operator 2's node 0 was tried; its node 1 is a different endpoint.
        const r = [row(1, { a: { weightsDigest: 'd1' } }), row(2, { b: { weightsDigest: 'd1' } })]
        const o = [op(1, ['a']), { ...op(2, ['b']), node_id: 1 }]
        const lists = equivalentSpellingLists('a', r, (x) => r.find((y) => y.id === x.id), o, [{ id: 2, node_id: 0 }], constraints)
        expect(lists.map((l) => l.map((c) => c.modelId))).toEqual([['b']])
    })

    it('is empty when the model has no identity', () => {
        const bare = [row(1, { a: {} }), row(2, { b: {} })]
        expect(equivalentSpellingLists('a', bare, (o) => bare.find((r) => r.id === o.id), ops, [], constraints)).toEqual([])
    })
})

describe('mergeOrderedByCost', () => {
    const cost = (x: { c: number }) => x.c

    it('merges by cost and keeps each list’s order', () => {
        const a = [{ n: 'a1', c: 1 }, { n: 'a2', c: 5 }]
        const b = [{ n: 'b1', c: 2 }, { n: 'b2', c: 3 }]
        expect(mergeOrderedByCost([a, b], cost).map((x) => x.n)).toEqual(['a1', 'b1', 'b2', 'a2'])
    })

    it('keeps the earlier list’s element on a tie', () => {
        const a = [{ n: 'a1', c: 2 }]
        const b = [{ n: 'b1', c: 2 }]
        expect(mergeOrderedByCost([b, a], cost).map((x) => x.n)).toEqual(['b1', 'a1'])
        expect(mergeOrderedByCost([a, b], cost).map((x) => x.n)).toEqual(['a1', 'b1'])
    })

    it('sorts unpriceable candidates last and treats two as a tie', () => {
        const a = [{ n: 'a1', c: Infinity }]
        const b = [{ n: 'b1', c: Infinity }, { n: 'b2', c: Infinity }]
        const c = [{ n: 'c1', c: 4 }]
        expect(mergeOrderedByCost([a, b, c], cost).map((x) => x.n)).toEqual(['c1', 'a1', 'b1', 'b2'])
    })

    it('handles empty input', () => {
        expect(mergeOrderedByCost([[], []], cost)).toEqual([])
    })
})
