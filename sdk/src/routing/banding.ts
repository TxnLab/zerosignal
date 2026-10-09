/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Responsiveness banding over a price-ordered candidate list, mirroring
// bandByResponsiveness and its helpers in proto/go/zs/dispatch.go, pinned by
// testdata/banding_vectors.json. It lives here rather than in the shared
// selection policy because it reads float metrics and the payer's own RTT,
// which that policy deliberately avoids.

import { LATENCY_MIN_SAMPLES } from './latency.js'

/**
 * Responsiveness band width (ms). A target outranks a cheaper peer only when
 * it is about one band faster, so small differences never reorder (price
 * still decides within a band) while a slow CPU node lands a band or more
 * behind a fast GPU one.
 */
export const TARGET_RESPONSIVENESS_BAND_MS = 500

/**
 * How far responsiveness may move a candidate from the pack. Every term is a
 * speed proxy rather than a measurement of this request on this model (see
 * catalogConfidence), so an unbounded spread would let an apparent speed edge
 * override any price advantage. One band either side leaves ahead of / with /
 * behind the pack and hands every finer distinction back to price.
 */
export const MAX_BANDS_FROM_MEDIAN = 1

/**
 * The response length that turns tokens/sec into a ms term
 * (NORM / tokensPerSec · 1000). Sized so the term lands in TTFT's magnitude:
 * on-chain tok/s is the noisiest signal, and at 128 it ran three to thirteen
 * bands against TTFT's one and decided the whole ordering. Not the request's
 * max output, an inflated bound that would swamp the score.
 */
export const DECODE_NORM_TOKENS = 32

/** The sort modes banding understands; `price` skips it. Same strings as selection's SORT_*. */
export type ResponsivenessMode = '' | 'price' | 'latency' | 'throughput'

/** What banding reads about one candidate. */
export interface BandingInput {
    /** The payer's own RTT to the target, or undefined when it has no fresh sample. */
    rtt?: { ewmaMs: number; samples: number } | undefined
    /** The node's co-signed on-chain TTFT EWMA (NodeRecord.latencyEwmaMs); 0 when none. */
    ttftEwmaMs: number
    /** The node's on-chain decode throughput EWMA (NodeRecord.tokensPerSecEwma); 0 when none. */
    tokensPerSecEwma: number
    /**
     * Each served model's output modalities (undefined: none declared), or
     * undefined when the node's catalog is unknown.
     */
    catalog?: readonly (readonly string[] | undefined)[] | undefined
    /** The affinity-preferred node, kept first regardless of band. */
    pinned: boolean
}

/**
 * One input to a score: a value in ms and the confidence that it describes
 * this request's model on this node. `wanted` is separate from a zero
 * confidence because a term the sort mode drops must not count toward
 * `signal` the way a wanted but unfilled one does.
 */
export interface ResponsivenessTerm {
    value: number
    confidence: number
    wanted: boolean
}

/** One candidate's banding inputs and verdict, in final order. */
export interface RankDetail {
    /** The candidate's index in the input list. */
    index: number
    rtt: ResponsivenessTerm
    ttft: ResponsivenessTerm
    decode: ResponsivenessTerm
    rttEff: number
    ttftEff: number
    decodeEff: number
    score: number
    band: number
    pinned: boolean
    signal: boolean
}

// Median of xs, 0 when empty: the even-length branch would otherwise read
// s[-1] and return NaN, which an additive score carries silently into every
// comparison.
function median(xs: readonly number[]): number {
    if (xs.length === 0) return 0
    const s = [...xs].sort((a, b) => a - b)
    const mid = Math.floor(s.length / 2)
    return s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2
}

/**
 * The weighted quantile at p=0.5, interpolated between the two values either
 * side of the half-weight point; 0 when empty or weightless. At equal weights
 * it is the plain median, average of the two middles included, so only a set
 * with differing confidences moves. Taking the first value past the half-weight
 * point instead would need an exact float equality on an accumulated sum to
 * get that average, which 1/sqrt(n) weights don't give.
 */
export function confidenceWeightedMedian(values: readonly number[], weights: readonly number[]): number {
    if (values.length === 0) return 0
    const order = values.map((_, i) => i).sort((a, b) => values[a]! - values[b]!)
    const total = weights.reduce((acc, w) => acc + w, 0)
    if (total <= 0) return 0
    // Each value sits at the midpoint of its own weight, which is what lands
    // equal weights on the plain median.
    const half = total / 2
    const pos: number[] = []
    let cum = 0
    for (const i of order) {
        pos.push(cum + weights[i]! / 2)
        cum += weights[i]!
    }
    for (let k = 0; k < order.length; k++) {
        if (pos[k]! < half) continue
        if (k === 0) return values[order[0]!]!
        const span = pos[k]! - pos[k - 1]!
        if (span <= 0) return values[order[k]!]!
        const lo = values[order[k - 1]!]!
        return lo + ((half - pos[k - 1]!) / span) * (values[order[k]!]! - lo)
    }
    return values[order[order.length - 1]!]!
}

/**
 * Whether a model can settle as token output, the only settles that move the
 * on-chain TTFT and tokens/sec. Undeclared modalities count as yes.
 */
export function producesTokens(outputModalities: readonly string[] | undefined): boolean {
    if (!outputModalities || outputModalities.length === 0) return true
    return outputModalities.some((m) => m.toLowerCase() === 'text')
}

/**
 * How far a node's on-chain speed figures can be trusted for one model:
 * 1/sqrt(n) over the token-output models it serves, 0 for an unknown or
 * all-image catalog.
 *
 * The chain keeps one TTFT and one tokens/sec per node, folded on every
 * settle whatever the model (settle() takes no model, so as not to link a
 * payer's settlements), so each figure is a mean over the node's traffic. This
 * is pessimistic on purpose: traffic can't be observed, so breadth stands in as
 * an upper bound on dilution. A fabricated speed edge costs the payer money; a
 * missed real one costs some latency. Image-only models never wrote to the
 * figures and don't count; undeclared ones are assumed to.
 */
export function catalogConfidence(catalog: BandingInput['catalog']): number {
    if (!catalog) return 0
    let n = 0
    for (const mods of catalog) if (producesTokens(mods)) n++
    return n < 1 ? 0 : 1 / Math.sqrt(n)
}

/**
 * A target's expected response time as separate terms, each lower-is-faster:
 * RTT (the payer's own observation, model-independent, so trusted as
 * measured), TTFT and decode (on-chain, discounted by catalogConfidence).
 *
 * The terms stay separate because an unfillable term must not be dropped: on
 * an additive lower-is-faster score a missing term reads as infinitely fast.
 * At a decode norm of 128, a node that never reported usage outranked an
 * honest 40 tok/s node by six bands. `mode` selects the wanted terms: all three
 * by default, RTT + TTFT for latency, decode alone for throughput.
 */
export function responsivenessTerms(
    c: BandingInput,
    mode: ResponsivenessMode,
): { rtt: ResponsivenessTerm; ttft: ResponsivenessTerm; decode: ResponsivenessTerm } {
    const wantFirstToken = mode !== 'throughput'
    const wantDecode = mode !== 'latency'
    const chain = catalogConfidence(c.catalog)
    const rttTrusted = wantFirstToken && c.rtt !== undefined && c.rtt.samples >= LATENCY_MIN_SAMPLES
    const ttft = wantFirstToken ? c.ttftEwmaMs : 0
    const tps = wantDecode ? c.tokensPerSecEwma : 0
    return {
        rtt: { value: rttTrusted ? c.rtt!.ewmaMs : 0, confidence: rttTrusted ? 1 : 0, wanted: wantFirstToken },
        ttft: { value: ttft > 0 ? ttft : 0, confidence: ttft > 0 ? chain : 0, wanted: wantFirstToken },
        decode: {
            value: tps > 0 ? (DECODE_NORM_TOKENS / tps) * 1000 : 0,
            confidence: tps > 0 ? chain : 0,
            wanted: wantDecode,
        },
    }
}

/**
 * Each term's contribution: median + confidence·(value − median), over a
 * confidence-weighted median; an unwanted term contributes 0.
 *
 * Toward the median, never toward zero, which would make an untrusted term look
 * faster. The median is weighted because a value at the median is unmoved by
 * the shrink: with one vote each, a majority of diluted nodes would set the
 * reference and keep their flattering numbers while a lone specialist kept its
 * honest, worse one.
 */
export function shrinkToMedian(terms: readonly ResponsivenessTerm[]): number[] {
    const confident = terms.filter((t) => t.wanted && t.confidence > 0)
    const med = confidenceWeightedMedian(
        confident.map((t) => t.value),
        confident.map((t) => t.confidence),
    )
    return terms.map((t) => (t.wanted ? med + t.confidence * (t.value - med) : 0))
}

/**
 * Bands a price-ordered list by responsiveness: score each candidate, bucket
 * the scores into bands, fastest band first, price order within a band. The
 * pinned candidate stays first. Returns the input indices in final order and
 * each candidate's detail, or `details: null` with the input order when no
 * banding ran (price mode, under two candidates, or nobody with any signal).
 *
 * Shrinking toward the median keeps an unfillable or diluted term mid-pack, and
 * the clamp to MAX_BANDS_FROM_MEDIAN bounds how far speed may move anyone. A
 * candidate with no signal sits in the median band.
 */
export function rankByResponsiveness(
    inputs: readonly BandingInput[],
    mode: ResponsivenessMode,
): { order: number[]; details: RankDetail[] | null } {
    const identity = inputs.map((_, i) => i)
    if (mode === 'price' || inputs.length < 2) return { order: identity, details: null }
    const terms = inputs.map((c) => responsivenessTerms(c, mode))
    const rttEff = shrinkToMedian(terms.map((t) => t.rtt))
    const ttftEff = shrinkToMedian(terms.map((t) => t.ttft))
    const decodeEff = shrinkToMedian(terms.map((t) => t.decode))
    const details: RankDetail[] = terms.map((t, i) => ({
        index: i,
        ...t,
        rttEff: rttEff[i]!,
        ttftEff: ttftEff[i]!,
        decodeEff: decodeEff[i]!,
        score: rttEff[i]! + ttftEff[i]! + decodeEff[i]!,
        band: 0,
        pinned: inputs[i]!.pinned,
        signal:
            (t.rtt.wanted && t.rtt.confidence > 0) ||
            (t.ttft.wanted && t.ttft.confidence > 0) ||
            (t.decode.wanted && t.decode.confidence > 0),
    }))
    const known = details.filter((d) => d.signal).map((d) => d.score)
    if (known.length === 0) return { order: identity, details: null }
    // Scores are never negative, where Math.round and Go's math.Round agree.
    const medianBand = Math.round(median(known) / TARGET_RESPONSIVENESS_BAND_MS)
    for (const d of details) {
        d.band = d.signal
            ? Math.min(
                  medianBand + MAX_BANDS_FROM_MEDIAN,
                  Math.max(medianBand - MAX_BANDS_FROM_MEDIAN, Math.round(d.score / TARGET_RESPONSIVENESS_BAND_MS)),
              )
            : medianBand
    }
    // The pin is its own sort key: the clamp can produce a band at or below
    // any sentinel band it could be given.
    const ordered = [...details].sort((x, y) => {
        if (x.pinned !== y.pinned) return x.pinned ? -1 : 1
        return x.band !== y.band ? x.band - y.band : x.index - y.index
    })
    return { order: ordered.map((d) => d.index), details: ordered }
}

/** rankByResponsiveness applied to a list: `inputOf` reads each item's banding input. */
export function bandByResponsiveness<T>(
    list: readonly T[],
    inputOf: (item: T) => BandingInput,
    mode: ResponsivenessMode,
): T[] {
    const { order } = rankByResponsiveness(list.map(inputOf), mode)
    return order.map((i) => list[i]!)
}
