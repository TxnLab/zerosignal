/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Shared image-pricing primitive — the TypeScript mirror of
// proto/go/imageprice. Turns an OpenAI-style (size, quality) request into a
// deterministic microUSDC charge given the operator's per-1024²-standard
// `imageRate`. Pinned byte-for-byte against the Go side by
// proto/testdata/image_vectors.json, because the node reserve gate, the proxy
// reserve sizing, and this (client) reserve sizing must all compute the
// identical number or the node rejects with image_budget_exceeded.
//
//   per_image_microUSDC = ceil(imageRate × factor(size, quality))
//   factor = areaScale × qualityMult                       // a reduced rational
//   areaScale = (w·h) / (1024·1024)                        // 2048² ≈ 4× 1024²
//   qualityMult: low 0.25 / medium·standard·auto·"" 1.0 / high·hd 4.0
//
// All arithmetic that touches `imageRate × num` uses BigInt — the product can
// exceed 2^53 for large rates/areas, so Number would silently lose precision
// and desync from Go's uint64.

// Reference dimensions: a 1024×1024 "standard"-quality image is the unit
// (factor == 1). imageRate is the operator's microUSDC price for it.
export const REF_WIDTH = 1024
export const REF_HEIGHT = 1024

// MAX_DIMENSION caps a parsed pixel dimension used for *pricing* (not the
// canonicalized backend string — see normalizeSize). Identical ceiling to the
// Go side; no real backend serves anything near it.
export const MAX_DIMENSION = 16384

// maxParseInt bounds a single parsed integer so the TS (Number) and Go
// (strconv) parses agree exactly.
const MAX_PARSE_INT = 1_000_000

export interface NormalizedSize {
    value: string
    ok: boolean
}

export interface Dims {
    w: number
    h: number
    ok: boolean
}

export interface Rational {
    num: bigint
    den: bigint
}

/**
 * Canonicalizes a loosely-specified size to the backend form ("WxH" or a "W:H"
 * ratio token), ok=false for empty/unparseable. Single source of truth for
 * size-string parsing (mirrors proto/go/imageprice.NormalizeSize, which node
 * imagecommon.NormalizeSize delegates to). Does NOT clamp to MAX_DIMENSION —
 * only the pricing path (dimensions) clamps.
 */
export function normalizeSize(size: string): NormalizedSize {
    const p = parseSize(size)
    if (!p.ok) return { value: '', ok: false }
    if (p.ratio) return { value: `${p.w}:${p.h}`, ok: true }
    return { value: `${p.w}x${p.h}`, ok: true }
}

/**
 * Parses a pricing-relevant pixel size. ok=false for an aspect-ratio ("W:H"),
 * "auto", empty, or unparseable input — all of which price at the
 * 1024²-standard reference. Pixel dimensions are clamped to [1, MAX_DIMENSION].
 */
export function dimensions(size: string): Dims {
    const p = parseSize(size)
    if (!p.ok || p.ratio) return { w: 0, h: 0, ok: false }
    return { w: clampDim(p.w), h: clampDim(p.h), ok: true }
}

/**
 * Pinned quality multiplier as a rational: low → 1/4, high·hd → 4/1, everything
 * else ("" / medium / standard / auto / unrecognized) → 1/1.
 */
export function qualityMult(quality: string): Rational {
    switch (quality.trim().toLowerCase()) {
        case 'low':
            return { num: 1n, den: 4n }
        case 'high':
        case 'hd':
            return { num: 4n, den: 1n }
        default:
            return { num: 1n, den: 1n }
    }
}

/** Pricing multiplier for (size, quality) as a reduced rational over the 1024²-standard reference. */
export function factor(size: string, quality: string): Rational {
    const q = qualityMult(quality)
    const d = dimensions(size)
    let area: bigint
    let ref: bigint
    if (d.ok) {
        area = BigInt(d.w) * BigInt(d.h)
        ref = BigInt(REF_WIDTH) * BigInt(REF_HEIGHT)
    } else {
        // Aspect-ratio / auto / empty / unparseable → the reference image.
        area = 1n
        ref = 1n
    }
    return reduce(area * q.num, ref * q.den)
}

/** Exact charge for ONE image at the given per-1024²-standard imageRate: ceil(imageRate × factor). */
export function perImageMicroUSDC(imageRate: bigint | number, size: string, quality: string): bigint {
    const rate = BigInt(imageRate)
    const f = factor(size, quality)
    const a = rate * f.num
    return (a + f.den - 1n) / f.den // ceilDiv
}

/**
 * Charge for n images sharing one size/quality (the dedicated-route case):
 * n × perImageMicroUSDC (per-image ceil then multiply, matching the unit the
 * tool path sums per produced image). n < 1 yields 0.
 */
export function costMicroUSDC(imageRate: bigint | number, n: number, size: string, quality: string): bigint {
    if (n < 1) return 0n
    return BigInt(n) * perImageMicroUSDC(imageRate, size, quality)
}

// --- internals ---------------------------------------------------------------

interface ParsedSize {
    w: number
    h: number
    ratio: boolean
    ok: boolean
}

// Shared size parser. ratio=true ⇒ w/h are "W:H" ratio components (no pixel
// scale); otherwise w/h are pixels. Mirror of proto/go/imageprice.parseSize.
function parseSize(size: string): ParsedSize {
    const s = size.trim().toLowerCase()
    if (s === '') return { w: 0, h: 0, ratio: false, ok: false }
    // Aspect ratio "W:H" — before the multiplicative separators.
    const colon = s.indexOf(':')
    if (colon >= 0) {
        const a = parsePosInt(s.slice(0, colon))
        if (a.ok) {
            const b = parsePosInt(s.slice(colon + 1))
            if (b.ok) return { w: a.n, h: b.n, ratio: true, ok: true }
        }
        return { w: 0, h: 0, ratio: false, ok: false }
    }
    for (const sep of ['x', '*', '×', '/', ' ']) {
        const i = s.indexOf(sep)
        if (i >= 0) {
            const a = parsePosInt(s.slice(0, i))
            const b = parsePosInt(s.slice(i + sep.length))
            if (a.ok && b.ok) return { w: a.n, h: b.n, ratio: false, ok: true }
            return { w: 0, h: 0, ratio: false, ok: false }
        }
    }
    // "Nk" shorthand → (N·1024)² square.
    if (s.endsWith('k')) {
        const a = parsePosInt(s.slice(0, -1))
        if (a.ok) {
            const d = a.n * 1024
            return { w: d, h: d, ratio: false, ok: true }
        }
        return { w: 0, h: 0, ratio: false, ok: false }
    }
    const n = parsePosInt(s)
    if (n.ok) return { w: n.n, h: n.n, ratio: false, ok: true }
    return { w: 0, h: 0, ratio: false, ok: false }
}

// Strictly-decimal positive integer in (0, MAX_PARSE_INT]. No sign, digits
// only, bounded — so Go and TS agree exactly.
function parsePosInt(s: string): { n: number; ok: boolean } {
    const t = s.trim()
    if (t === '') return { n: 0, ok: false }
    let n = 0
    for (let i = 0; i < t.length; i++) {
        const c = t.charCodeAt(i)
        if (c < 48 || c > 57) return { n: 0, ok: false }
        n = n * 10 + (c - 48)
        if (n > MAX_PARSE_INT) return { n: 0, ok: false }
    }
    if (n <= 0) return { n: 0, ok: false }
    return { n, ok: true }
}

function clampDim(d: number): number {
    if (d < 1) return 1
    if (d > MAX_DIMENSION) return MAX_DIMENSION
    return d
}

function gcd(a: bigint, b: bigint): bigint {
    while (b !== 0n) {
        const t = a % b
        a = b
        b = t
    }
    return a
}

function reduce(num: bigint, den: bigint): Rational {
    if (num === 0n) return { num: 0n, den: 1n }
    const g = gcd(num, den)
    return { num: num / g, den: den / g }
}
