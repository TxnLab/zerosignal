/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl byte-parity test for the image-pricing primitive. Loads
// proto/testdata/image_vectors.json (produced by
// proto/go/imageprice/vectors_test.go) and asserts the TypeScript port of
// normalizeSize / dimensions / factor / perImageMicroUSDC / costMicroUSDC
// produces identical numbers. If this fails, the TS imageprice logic has
// drifted from the Go reference — which would desync the client reserve sizing
// from the node gate (→ image_budget_exceeded). Sync both sides, then
// regenerate the vectors on the Go side.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
    normalizeSize,
    dimensions,
    factor,
    perImageMicroUSDC,
    costMicroUSDC,
} from '../src/imageprice/index.js'

interface FactorCase {
    size: string
    quality: string
    normalized_size: string
    normalized_ok: boolean
    w: number
    h: number
    dims_ok: boolean
    factor_num: number
    factor_den: number
    per_image_micro_usdc: number[]
}

interface CostCase {
    image_rate: number
    n: number
    size: string
    quality: string
    expected_micro_usdc: number
}

interface ImageVectorsFile {
    version: number
    comment: string
    sample_rates: number[]
    cases: FactorCase[]
    cost_cases: CostCase[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'image_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as ImageVectorsFile

describe('cross-impl image pricing vectors (proto/testdata/image_vectors.json)', () => {
    it('vectors file is current schema', () => {
        expect(vectors.version).toBe(1)
        expect(vectors.sample_rates.length).toBeGreaterThan(0)
        expect(vectors.cases.length).toBeGreaterThan(0)
        expect(vectors.cost_cases.length).toBeGreaterThan(0)
    })

    for (const c of vectors.cases) {
        it(`factor: ${c.size || '<empty>'} / ${c.quality || '<empty>'}`, () => {
            const ns = normalizeSize(c.size)
            expect(ns.value).toBe(c.normalized_size)
            expect(ns.ok).toBe(c.normalized_ok)

            const d = dimensions(c.size)
            expect(d.w).toBe(c.w)
            expect(d.h).toBe(c.h)
            expect(d.ok).toBe(c.dims_ok)

            const f = factor(c.size, c.quality)
            expect(Number(f.num)).toBe(c.factor_num)
            expect(Number(f.den)).toBe(c.factor_den)

            vectors.sample_rates.forEach((rate, i) => {
                expect(Number(perImageMicroUSDC(rate, c.size, c.quality))).toBe(
                    c.per_image_micro_usdc[i],
                )
            })
        })
    }

    for (const c of vectors.cost_cases) {
        it(`cost: n=${c.n} ${c.size} / ${c.quality} @ ${c.image_rate}`, () => {
            expect(Number(costMicroUSDC(c.image_rate, c.n, c.size, c.quality))).toBe(
                c.expected_micro_usdc,
            )
        })
    }
})
