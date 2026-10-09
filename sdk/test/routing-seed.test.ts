/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { ENDPOINT_RESPONSES, type Constraints, type Operator } from '@txnlab/zs-proto/selection'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { selectTargetsForOperator, withSelectedCandidate } from '../src/routing/index.js'

const MODEL = 'm1'

function op(id: number, nodeId: number, opts: Partial<Operator> & { imageTool?: boolean; price?: number } = {}): Operator {
    const { imageTool = false, price = 1, ...rest } = opts
    return {
        id,
        node_id: nodeId,
        owner_addr: `owner${id}`,
        base_url: `https://op${id}-${nodeId}.example`,
        proto_version: PROTO_VERSION,
        reachable: true,
        tee_attested: false,
        models: [MODEL],
        model_capacities: {
            [MODEL]: {
                context_window: 128_000,
                max_output_tokens: 4096,
                serves_image_gen: false,
                serves_image_edit: false,
                offers_image_gen_tool: imageTool,
                offers_image_edit_tool: imageTool,
                input_usd_per_1m: price,
                output_usd_per_1m: price,
                image_rate_micro_usdc: 0,
                image_edit_rate_micro_usdc: 0,
            },
        },
        builtin_tools: [],
        ...rest,
    }
}

const constraints = (over: Partial<Constraints> = {}): Omit<Constraints, 'affinity_policy'> => ({
    model: MODEL,
    input_tokens: 0,
    max_output_tokens: 0,
    endpoint: ENDPOINT_RESPONSES,
    require_tee: false,
    allow_staging: false,
    requested_tools: null,
    image_tool_gen_budget: 0,
    image_tool_edit_budget: 0,
    ...over,
})

const refs = (ops: Operator[]): string[] => ops.map((o) => `${o.id}:${o.node_id}`)

describe('selectTargetsForOperator', () => {
    it('puts the selected operator first even when a peer is cheaper', () => {
        const ops = [op(1, 0, { price: 1 }), op(2, 0, { price: 5 })]
        const { result, preferred } = selectTargetsForOperator(ops, constraints(), 2)
        expect(preferred && refs([preferred])).toEqual(['2:0'])
        expect(refs(result.operators)).toEqual(['2:0', '1:0'])
    })

    it('seeds with the operator’s top-ranked node, not its first', () => {
        // Node 0 offers no image tool; with an image-tool budget the shared
        // policy ranks node 1 above it, and the seed follows that ranking.
        const ops = [op(1, 0), op(1, 1, { imageTool: true }), op(2, 0, { imageTool: true })]
        const { result, preferred } = selectTargetsForOperator(
            ops,
            constraints({ image_tool_gen_budget: 1, image_tool_edit_budget: 1 }),
            1,
        )
        expect(preferred && refs([preferred])).toEqual(['1:1'])
        expect(refs(result.operators)[0]).toBe('1:1')
    })

    it('still seeds an operator the first pass filtered out', () => {
        const ops = [op(1, 0), op(2, 0, { proto_version: '1.0' })]
        const { result, preferred } = selectTargetsForOperator(ops, constraints(), 2)
        expect(preferred && refs([preferred])).toEqual(['2:0'])
        expect(refs(result.operators)[0]).toBe('2:0')
    })

    it('does not seed a staging node past allow_staging', () => {
        const ops = [op(1, 0), op(2, 0, { staging: true })]
        const held = selectTargetsForOperator(ops, constraints(), 2)
        expect(held.preferred).toBeNull()
        expect(refs(held.result.operators)).toEqual(['1:0'])

        const allowed = selectTargetsForOperator(ops, constraints({ allow_staging: true }), 2)
        expect(allowed.preferred && refs([allowed.preferred])).toEqual(['2:0'])
    })

    it('seeds a filtered-out staging node when allow_staging is on', () => {
        // The first pass drops op 2 for its version, so only the fallback can
        // seed it, and allow_staging decides whether staging holds it out.
        const ops = [op(1, 0), op(2, 0, { staging: true, proto_version: '1.0' })]
        const { preferred } = selectTargetsForOperator(ops, constraints({ allow_staging: true }), 2)
        expect(preferred && refs([preferred])).toEqual(['2:0'])
    })

    it('does not seed an unattested node past require_tee', () => {
        const ops = [op(1, 0, { tee_attested: true }), op(2, 0)]
        const { result, preferred } = selectTargetsForOperator(ops, constraints({ require_tee: true }), 2)
        expect(preferred).toBeNull()
        expect(refs(result.operators)).toEqual(['1:0'])
    })

    it('has no seed for an operator absent from the list', () => {
        const ops = [op(1, 0), op(2, 0)]
        const { result, preferred } = selectTargetsForOperator(ops, constraints(), 9)
        expect(preferred).toBeNull()
        expect(refs(result.operators)).toEqual(['1:0', '2:0'])
    })
})

describe('withSelectedCandidate', () => {
    const isSel = (x: string) => x === 'sel'

    it('prepends the pick when it is missing', () => {
        expect(withSelectedCandidate(['a', 'b'], 'sel', isSel, false)).toEqual(['sel', 'a', 'b'])
    })

    it('leaves a present pick where it is, even when demoted', () => {
        expect(withSelectedCandidate(['a', 'sel'], 'sel', isSel, false)).toEqual(['a', 'sel'])
    })

    it('never re-adds a held-out pick', () => {
        expect(withSelectedCandidate(['a'], 'sel', isSel, true)).toEqual(['a'])
        expect(withSelectedCandidate([], 'sel', isSel, true)).toEqual([])
    })
})
