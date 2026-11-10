/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Replays testdata/open_refusal_vectors.json, which Go generates from
// openRefusalCategory and poolRefusal: the category the payer reads from a
// node's refusal of an open it was handed, and whether it is the prepaid pool.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { openRefusalCategory, poolRefusal } from '../src/sealed.js'

interface Vector {
    name: string
    body: string
    category: string
    pool: boolean
}

const vectors: Vector[] = JSON.parse(readFileSync(new URL('../../testdata/open_refusal_vectors.json', import.meta.url), 'utf8'))

describe('open refusal vectors', () => {
    it('has cases on both sides of the pool', () => {
        expect(vectors.some((v) => v.pool)).toBe(true)
        expect(vectors.some((v) => !v.pool && v.category !== '')).toBe(true)
    })

    it.each(vectors)('$name', (v) => {
        const category = openRefusalCategory(v.body)
        expect(category).toBe(v.category)
        expect(poolRefusal(category)).toBe(v.pool)
    })
})
