/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// rankByResponsiveness, its helpers and orderCandidates, checked against
// testdata/banding_vectors.json, which Go's bandByResponsiveness and
// orderCandidates generate.
// Order, bands and flags compare exactly. Scores compare within 1e-6 relative
// (absolute below 1): Go may fuse a multiply-add on some architectures, and the
// fixture rounds them to 1e-6.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import {
    type BandingInput,
    DECODE_NORM_TOKENS,
    LATENCY_MIN_SAMPLES,
    MAX_BANDS_FROM_MEDIAN,
    type ResponsivenessMode,
    TARGET_RESPONSIVENESS_BAND_MS,
    bandByResponsiveness,
    catalogConfidence,
    confidenceWeightedMedian,
    orderCandidates,
    rankByResponsiveness,
} from '../src/routing/index.js'

type Catalog = (string[] | null)[] | null

interface VectorCandidate {
    rtt_ms?: number
    rtt_samples?: number
    ttft_ewma_ms: number
    tokens_per_sec_ewma: number
    catalog: Catalog
    pinned: boolean
}

interface VectorDetail {
    index: number
    signal: boolean
    pinned: boolean
    rtt_eff: number
    ttft_eff: number
    decode_eff: number
    score: number
    band: number
}

interface VectorFile {
    constants: {
        target_responsiveness_band_ms: number
        max_bands_from_median: number
        decode_norm_tokens: number
        latency_min_samples: number
    }
    confidence_weighted_median: { values: number[] | null; weights: number[] | null; want: number }[]
    catalog_confidence: { catalog: Catalog; want: number }[]
    post_pass: {
        name: string
        mode: ResponsivenessMode
        candidates: (VectorCandidate & { contradicts: boolean; backed_off: boolean; backoff_pinned: boolean })[]
        order: number[]
    }[]
    cases: {
        name: string
        mode: ResponsivenessMode
        candidates: VectorCandidate[]
        order: number[]
        details: VectorDetail[] | null
    }[]
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/banding_vectors.json', import.meta.url), 'utf8'),
) as VectorFile

const TOLERANCE = 1e-6

// The fixture rounds to 1e-6, so toBeCloseTo(want, 6) (strictly under 5e-7)
// would have no margin for a value whose seventh decimal is near 5.
function expectNear(got: number, want: number): void {
    expect(Math.abs(got - want)).toBeLessThanOrEqual(TOLERANCE * Math.max(1, Math.abs(want)))
}

function catalogOf(c: Catalog): BandingInput['catalog'] {
    return c === null ? undefined : c.map((m) => m ?? undefined)
}

function inputOf(c: VectorCandidate): BandingInput {
    return {
        ...(c.rtt_ms !== undefined ? { rtt: { ewmaMs: c.rtt_ms, samples: c.rtt_samples ?? 0 } } : {}),
        ttftEwmaMs: c.ttft_ewma_ms,
        tokensPerSecEwma: c.tokens_per_sec_ewma,
        catalog: catalogOf(c.catalog),
        pinned: c.pinned,
    }
}

describe('banding vectors', () => {
    it('has every section', () => {
        expect(vectors.cases.length).toBeGreaterThan(0)
        expect(vectors.confidence_weighted_median.length).toBeGreaterThan(0)
        expect(vectors.catalog_confidence.length).toBeGreaterThan(0)
    })

    it('shares Go constants', () => {
        expect(TARGET_RESPONSIVENESS_BAND_MS).toBe(vectors.constants.target_responsiveness_band_ms)
        expect(MAX_BANDS_FROM_MEDIAN).toBe(vectors.constants.max_bands_from_median)
        expect(DECODE_NORM_TOKENS).toBe(vectors.constants.decode_norm_tokens)
        expect(LATENCY_MIN_SAMPLES).toBe(vectors.constants.latency_min_samples)
    })

    for (const c of vectors.confidence_weighted_median) {
        it(`confidenceWeightedMedian(${JSON.stringify(c.values)}, ${JSON.stringify(c.weights)})`, () => {
            expectNear(confidenceWeightedMedian(c.values ?? [], c.weights ?? []), c.want)
        })
    }

    for (const c of vectors.catalog_confidence) {
        it(`catalogConfidence(${JSON.stringify(c.catalog)})`, () => {
            expectNear(catalogConfidence(catalogOf(c.catalog)), c.want)
        })
    }

    for (const c of vectors.cases) {
        it(c.name, () => {
            const got = rankByResponsiveness(c.candidates.map(inputOf), c.mode)
            expect(got.order).toEqual(c.order)
            if (c.details === null) {
                expect(got.details).toBeNull()
                return
            }
            expect(got.details).not.toBeNull()
            expect(got.details!.map((d) => [d.index, d.signal, d.pinned, d.band])).toEqual(
                c.details.map((d) => [d.index, d.signal, d.pinned, d.band]),
            )
            got.details!.forEach((d, k) => {
                const want = c.details![k]!
                for (const [g, w] of [
                    [d.rttEff, want.rtt_eff],
                    [d.ttftEff, want.ttft_eff],
                    [d.decodeEff, want.decode_eff],
                    [d.score, want.score],
                ] as const) {
                    expectNear(g, w)
                }
            })
        })
    }
})

describe('orderCandidates vectors', () => {
    it('has cases', () => {
        expect(vectors.post_pass.length).toBeGreaterThan(0)
    })

    for (const c of vectors.post_pass) {
        it(c.name, () => {
            const items = c.candidates.map((cand, i) => ({ i, cand }))
            const out = orderCandidates(
                items,
                ({ cand }) => ({
                    ...inputOf(cand),
                    contradicted: cand.contradicts,
                    backedOff: cand.backed_off,
                    backoffPinned: cand.backoff_pinned,
                }),
                c.mode,
            )
            expect(out.map((x) => x.i)).toEqual(c.order)
        })
    }
})

describe('bandByResponsiveness', () => {
    it('applies the ranked order to the caller’s items', () => {
        const c = vectors.cases.find((v) => v.details !== null && v.order.some((o, i) => o !== i))!
        const items = c.candidates.map((cand, i) => ({ i, cand }))
        const out = bandByResponsiveness(items, (x) => inputOf(x.cand), c.mode)
        expect(out.map((x) => x.i)).toEqual(c.order)
    })
})
