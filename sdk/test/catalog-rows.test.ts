/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import {
    REACHABILITY_RANK,
    type RankedModelInfo,
    type RankedRow,
    type Reachability,
    compareUniqueModelRows,
    deriveWeightsConsensus,
    modelInfoIsSpecialist,
    modelInfoOffersImageTools,
    pickColdStartDefault,
    rowServesWireId,
} from '../src/catalog/index.js'

function row(modelId: string, op: bigint, info: RankedModelInfo | null): RankedRow {
    return { modelId, defaultOperator: { id: op }, defaultModelInfo: info }
}

describe('pickColdStartDefault', () => {
    it('returns null on an empty list', () => {
        expect(pickColdStartDefault([])).toBeNull()
    })

    it('picks the lowest input price', () => {
        const rows = [row('m-a', 2n, { inputUsdPer1m: 4 }), row('m-b', 7n, { inputUsdPer1m: 1.5 }), row('m-c', 5n, { inputUsdPer1m: 2.5 })]
        expect(pickColdStartDefault(rows)?.modelId).toBe('m-b')
    })

    it('breaks an input tie on output price before operator id', () => {
        const rows = [
            row('m-dear-out', 2n, { inputUsdPer1m: 2, outputUsdPer1m: 12 }),
            row('m-cheap-out', 50n, { inputUsdPer1m: 2, outputUsdPer1m: 4 }),
        ]
        expect(pickColdStartDefault(rows)?.modelId).toBe('m-cheap-out')
    })

    it('breaks a full price tie on operator id, then model id', () => {
        expect(pickColdStartDefault([row('m-a', 7n, { inputUsdPer1m: 2 }), row('m-b', 2n, { inputUsdPer1m: 2 })])?.modelId).toBe('m-b')
        expect(pickColdStartDefault([row('m-z', 3n, null), row('m-y', 3n, null)])?.modelId).toBe('m-y')
    })

    it('ranks a priced row before an unpriced one, on each axis', () => {
        expect(pickColdStartDefault([row('m-unpriced', 1n, {}), row('m-priced', 99n, { inputUsdPer1m: 5 })])?.modelId).toBe('m-priced')
        expect(
            pickColdStartDefault([
                row('m-no-out', 1n, { inputUsdPer1m: 1 }),
                row('m-out', 99n, { inputUsdPer1m: 1, outputUsdPer1m: 9 }),
            ])?.modelId,
        ).toBe('m-out')
    })

    it('ranks image tools above price only when asked', () => {
        const rows = [row('m-text', 1n, { inputUsdPer1m: 1 }), row('m-tool', 2n, { inputUsdPer1m: 5, imageToolRateMicroUsdc: 80_000 })]
        expect(pickColdStartDefault(rows, true)?.modelId).toBe('m-tool')
        expect(pickColdStartDefault(rows, false)?.modelId).toBe('m-text')
        // Unasked, as when the comparator goes straight to Array.prototype.sort,
        // which passes two arguments.
        expect(pickColdStartDefault(rows)?.modelId).toBe('m-text')
        expect([...rows].reverse().sort(compareUniqueModelRows)[0]?.modelId).toBe('m-text')
    })

    it('keeps the first of two tied rows', () => {
        const a = row('m-same', 3n, { inputUsdPer1m: 1 })
        const b = row('m-same', 3n, { inputUsdPer1m: 1 })
        expect(pickColdStartDefault([a, b])).toBe(a)
    })
})

describe('compareUniqueModelRows: specialists rank last', () => {
    it.each(['medical', 'x-ray', 'code', 'MEDICAL'])('a %s specialist ranks after a pricier general model', (tag) => {
        const specialist = row('m-s', 1n, { inputUsdPer1m: 0, tags: [tag] })
        const general = row('m-g', 2n, { inputUsdPer1m: 5 })
        expect(compareUniqueModelRows(general, specialist)).toBeLessThan(0)
        expect(compareUniqueModelRows(specialist, general)).toBeGreaterThan(0)
    })

    it('is a preference, not a filter: specialists still rank by price', () => {
        const rows = [row('m-a', 7n, { inputUsdPer1m: 4, tags: ['medical'] }), row('m-b', 2n, { inputUsdPer1m: 1.5, tags: ['x-ray'] })]
        expect(pickColdStartDefault(rows)?.modelId).toBe('m-b')
    })

    it('a maturity tag is not a specialty', () => {
        expect(modelInfoIsSpecialist({ tags: ['nsfw', 'uncensored'] })).toBe(false)
    })

    it('image tools, when asked for, outrank the specialist rule', () => {
        const rows = [
            row('m-tool-specialist', 1n, { inputUsdPer1m: 5, imageToolRateMicroUsdc: 80_000, tags: ['medical'] }),
            row('m-plain', 2n, { inputUsdPer1m: 1 }),
        ]
        expect(pickColdStartDefault(rows, true)?.modelId).toBe('m-tool-specialist')
        expect(pickColdStartDefault(rows, false)?.modelId).toBe('m-plain')
    })
})

describe('modelInfoOffersImageTools', () => {
    it('reads a positive finite rate on either tool', () => {
        expect(modelInfoOffersImageTools({ imageToolRateMicroUsdc: 1 })).toBe(true)
        expect(modelInfoOffersImageTools({ imageEditToolRateMicroUsdc: 1 })).toBe(true)
    })

    it('reads zero, negative, non-finite and absent as none', () => {
        for (const v of [0, -1, Number.POSITIVE_INFINITY, Number.NaN, undefined]) {
            expect(modelInfoOffersImageTools({ imageToolRateMicroUsdc: v, imageEditToolRateMicroUsdc: v })).toBe(false)
        }
        expect(modelInfoOffersImageTools(null)).toBe(false)
    })
})

describe('rowServesWireId', () => {
    const merged = {
        modelId: 'glm-5.2',
        servingOperators: [{ modelIds: ['glm-5.2'] }, { modelIds: ['zai-org/GLM-5.2', 'glm-5.2-alias'] }],
    }

    it('covers the row id and every serving spelling', () => {
        for (const id of ['glm-5.2', 'zai-org/GLM-5.2', 'glm-5.2-alias']) expect(rowServesWireId(merged, id)).toBe(true)
    })

    it('is exact: no case folding', () => {
        expect(rowServesWireId(merged, 'zai-org/glm-5.2')).toBe(false)
    })

    it('covers the row id even when no serving operator lists it', () => {
        const row = { modelId: 'm-own', servingOperators: [{ modelIds: ['m-peer'] }] }
        expect(rowServesWireId(row, 'm-own')).toBe(true)
        expect(rowServesWireId({ modelId: 'm-own', servingOperators: [] }, 'm-own')).toBe(true)
    })
})

describe('deriveWeightsConsensus', () => {
    const da = `sha256:${'a'.repeat(64)}`
    const db = `sha256:${'b'.repeat(64)}`
    const op = (reachability: Reachability, weightsDigest?: string) => ({ modelInfo: { weightsDigest }, reachability })

    it('agreeing reachable nodes give a consensus', () => {
        expect(deriveWeightsConsensus([op('ok', da), op('ok', da)])).toEqual({ weightsMismatch: false, weightsConsensus: da })
    })

    it('two distinct reachable digests are a mismatch', () => {
        expect(deriveWeightsConsensus([op('ok', da), op('ok', db)])).toEqual({ weightsMismatch: true })
    })

    it('only ok nodes vote', () => {
        for (const r of ['probing', 'incompatible', 'failing', 'no-relay'] as const) {
            expect(deriveWeightsConsensus([op('ok', da), op(r, db)])).toEqual({ weightsMismatch: false, weightsConsensus: da })
        }
    })

    it('silence abstains, and no digest at all is neither', () => {
        expect(deriveWeightsConsensus([op('ok', da), op('ok'), op('ok', ''), { modelInfo: null, reachability: 'ok' }])).toEqual({
            weightsMismatch: false,
            weightsConsensus: da,
        })
        expect(deriveWeightsConsensus([])).toEqual({ weightsMismatch: false })
    })
})

describe('REACHABILITY_RANK', () => {
    it('orders ok first and incompatible last', () => {
        const order = (Object.keys(REACHABILITY_RANK) as Reachability[]).sort((a, b) => REACHABILITY_RANK[a] - REACHABILITY_RANK[b])
        expect(order).toEqual(['ok', 'probing', 'no-relay', 'failing', 'incompatible'])
    })

    it('is frozen', () => {
        expect(Object.isFrozen(REACHABILITY_RANK)).toBe(true)
    })
})
