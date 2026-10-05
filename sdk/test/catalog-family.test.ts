/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import { type FamilyAffordability, type RankedRow, rankFamilyCandidates } from '../src/catalog/index.js'

interface Row extends RankedRow {
    free: boolean
    affordable: boolean
}

function row(modelId: string, price: number, opts: { free?: boolean; affordable?: boolean; tools?: boolean } = {}): Row {
    const { free = false, affordable = true, tools = false } = opts
    return {
        modelId,
        defaultOperator: { id: 1n },
        defaultModelInfo: { inputUsdPer1m: price, imageToolRateMicroUsdc: tools ? 1 : undefined },
        free,
        affordable,
    }
}

const isAffordable = (r: Row) => r.affordable
const isFree = (r: Row) => r.free
const funded: FamilyAffordability<Row> = { isAffordable, isFree, balance: 'funded' }
const trial: FamilyAffordability<Row> = { isAffordable, isFree, balance: 'free-only' }
const loading: FamilyAffordability<Row> = { isAffordable, isFree, balance: 'loading' }
const ids = (rows: Row[]) => rows.map((r) => r.modelId)

describe('rankFamilyCandidates', () => {
    const free = row('free', 0, { free: true })
    const freeDear = row('free-unaffordable', 0, { free: true, affordable: false })
    const cheap = row('cheap', 1)
    const dear = row('dear', 9, { affordable: false })

    it('ranks the affordable paid rows for a funded payer, free ones dropped', () => {
        expect(ids(rankFamilyCandidates([dear, free, cheap], funded, false))).toEqual(['cheap'])
    })

    it('keeps free rows for a payer that is not funded', () => {
        expect(ids(rankFamilyCandidates([dear, cheap, free], loading, false))).toEqual(['free', 'cheap'])
        expect(ids(rankFamilyCandidates([dear, cheap, free], trial, false))).toEqual(['free', 'cheap'])
    })

    it('gives a free-only payer nothing when no row is affordable', () => {
        expect(rankFamilyCandidates([dear], trial, false)).toEqual([])
    })

    it('keeps a funded payer that can afford nothing on the paid rows, even just one', () => {
        expect(ids(rankFamilyCandidates([freeDear, dear], funded, false))).toEqual(['dear'])
        const dearer = row('dearer', 20, { affordable: false })
        expect(ids(rankFamilyCandidates([dearer, freeDear, dear], funded, false))).toEqual(['dear', 'dearer'])
    })

    it('falls back to every row when a funded payer has only free ones', () => {
        expect(ids(rankFamilyCandidates([freeDear], funded, false))).toEqual(['free-unaffordable'])
    })

    it('keeps every row while the balance loads and nothing is affordable', () => {
        expect(ids(rankFamilyCandidates([dear, free], { ...loading, isAffordable: () => false }, false))).toEqual(['free', 'dear'])
    })

    it('counts every row affordable when affordability is unknown', () => {
        // Free-only is the one balance where "nothing affordable" differs from
        // "everything affordable": it returns nothing.
        expect(ids(rankFamilyCandidates([dear, cheap], { balance: 'free-only' }, false))).toEqual(['cheap', 'dear'])
        expect(ids(rankFamilyCandidates([dear, cheap], { balance: 'funded' }, false))).toEqual(['cheap', 'dear'])
    })

    it('reads a missing isFree as no row being free', () => {
        expect(ids(rankFamilyCandidates([free, cheap], { isAffordable, balance: 'funded' }, false))).toEqual(['free', 'cheap'])
    })

    it('ranks by compareUniqueModelRows, image tools first when asked', () => {
        const tools = row('tools', 5, { tools: true })
        expect(ids(rankFamilyCandidates([tools, cheap], funded, true))).toEqual(['tools', 'cheap'])
        expect(ids(rankFamilyCandidates([tools, cheap], funded, false))).toEqual(['cheap', 'tools'])
    })

    it('leaves its input alone on every path', () => {
        // The funded fallback to every row is the one path where no filter has
        // already copied the input.
        const input = [freeDear, row('free-b', 0, { free: true, affordable: false })]
        rankFamilyCandidates(input, funded, false)
        expect(ids(input)).toEqual(['free-unaffordable', 'free-b'])
        const unknown = [dear, cheap]
        rankFamilyCandidates(unknown, { balance: 'loading' }, false)
        expect(ids(unknown)).toEqual(['dear', 'cheap'])
    })

    it('calls the predicates with the row alone', () => {
        // Array.prototype.filter passes (row, index, array); a predicate with an
        // optional second parameter would read the index as an argument.
        const seen: unknown[][] = []
        const record = (...a: unknown[]) => (seen.push(a), true)
        rankFamilyCandidates([cheap], { isAffordable: record, isFree: (...a) => !record(...a), balance: 'funded' }, false)
        expect(seen).toEqual([[cheap], [cheap]])
    })
})
