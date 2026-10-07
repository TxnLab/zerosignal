/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// verifyReservePrice, checked against testdata/reserve_price_vectors.json,
// which Go's reservePriceViolation generates from the same advertisements.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { parseOperatorDetails } from '@txnlab/zs-proto/inject'
import type { Ticket } from '@txnlab/zs-proto/ticket'

import { detailsFieldsOf, modelPricingOf, operatorPricingOf, verifyReservePrice } from '../src/index.js'

interface Scenario {
    name: string
    details: unknown
    model: string
    reserve_input_count: number
    image_tool_budget: number
    image_edit_tool_budget: number
    ticket: Ticket
    fee_bps: number | null
    want: { check: string; field: string; want: number; got: number } | null
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/reserve_price_vectors.json', import.meta.url), 'utf8'),
) as { scenarios: Scenario[] }

function call(sc: Scenario) {
    const details = parseOperatorDetails(sc.details)
    if (details === null) throw new Error(`${sc.name}: details do not parse`)
    return {
        ticket: sc.ticket,
        pricing: modelPricingOf(details, sc.model),
        feeBps: async () => sc.fee_bps,
        reserveInputCount: sc.reserve_input_count,
        imageToolBudget: sc.image_tool_budget,
        imageEditToolBudget: sc.image_edit_tool_budget,
    }
}

describe('verifyReservePrice vectors', () => {
    it('covers every scenario', () => expect(vectors.scenarios.length).toBeGreaterThan(0))
    it.each(vectors.scenarios.map((s) => [s.name, s] as const))('%s', async (_name, sc) => {
        const v = await verifyReservePrice(call(sc))
        expect(v === null ? null : { check: v.check, field: v.field, want: v.want, got: v.got }).toEqual(sc.want)
    })
})

// Go's gate reads the routable operator the details were copied onto, which is
// the path operatorPricingOf takes.
describe('verifyReservePrice vectors through the operator', () => {
    it.each(vectors.scenarios.map((s) => [s.name, s] as const))('%s', async (_name, sc) => {
        const details = parseOperatorDetails(sc.details)!
        const pricing = operatorPricingOf(detailsFieldsOf(details), sc.model)
        const v = await verifyReservePrice({ ...call(sc), pricing })
        expect(v === null ? null : { check: v.check, field: v.field, want: v.want, got: v.got }).toEqual(sc.want)
    })
})

describe('verifyReservePrice fee', () => {
    const refused = vectors.scenarios.find((s) => s.name === 'an inflated max_price is refused')!
    const imageBudget = vectors.scenarios.find((s) => s.name === 'an image-tool budget fails open')!

    it('fails open when the fee read throws', async () => {
        const v = await verifyReservePrice({
            ...call(refused),
            feeBps: () => Promise.reject(new Error('algod')),
        })
        expect(v).toBeNull()
    })

    it('reads no fee when an image-tool budget skips the gate', async () => {
        let reads = 0
        await verifyReservePrice({
            ...call(imageBudget),
            feeBps: async () => {
                reads++
                return 100
            },
        })
        expect(reads).toBe(0)
    })
})
