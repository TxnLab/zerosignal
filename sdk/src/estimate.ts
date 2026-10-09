/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's estimate of a request's size, before any operator is chosen.
// Mirror of proto/go/zs/tokenize: SafeEstimator and EstimateWithRegistry.

import { BOUND_VERSION_1, inputTokenBoundVersion } from '@txnlab/zs-proto/tokenize'

import { decodeGoFields } from './gojson.js'

export interface Estimate {
    /** The v1 input bound over the whole body. */
    inputTokens: number
    /** The caller's max_output, a per-model default, or in derive mode the ceiling, for display. */
    maxOutputTokens: number
    /** The caller omitted max_output and no per-model default applies: size each operator from its capacity. */
    deriveMaxOutput: boolean
    /** The base ceiling a derive-mode request derives against; 0 otherwise. */
    maxOutputCeiling: number
}

/** The knobs EstimateWithRegistry reads; the Client fills them from its Config. */
export interface EstimatePolicy {
    /** Per-model max_output for a request that omits one. A 0 entry is unset. */
    maxOutputByModel: Record<string, number>
    /** The derive-mode ceiling; 0 refuses a request that omits max_output. */
    fallbackMaxOutput: number
}

/** MaxOutputRequiredError is a request that omits max_output where no default applies. */
export class MaxOutputRequiredError extends Error {
    constructor() {
        super('tokenize: max_output_tokens required (body has none and no default configured)')
        this.name = 'MaxOutputRequiredError'
    }
}

/**
 * extractMaxOutput reads the first of max_completion_tokens, max_output_tokens
 * and max_tokens that is set above 0, or 0 when none is. It throws where Go's
 * decode of the three into *uint64 fails, which takes the whole body: invalid
 * JSON anywhere, a non-object, or one of the three that is not an integer in
 * uint64. An empty body is 0. A value above 2^53 loses precision here and is
 * exact in Go; either way no operator declares a window that large.
 */
export function extractMaxOutput(body: string | Uint8Array): number {
    if (body.length === 0) return 0
    const f = decodeGoFields(body, {
        max_tokens: 'uint64ptr',
        max_completion_tokens: 'uint64ptr',
        max_output_tokens: 'uint64ptr',
    })
    for (const v of [f.max_completion_tokens, f.max_output_tokens, f.max_tokens]) {
        if (typeof v === 'bigint' && v > 0n) return Number(v)
    }
    return 0
}

/**
 * estimate sizes a request and resolves its max_output, in order: the caller's
 * own value, flat; else the model's configured default, flat; else, with a
 * fallback above 0, derive mode against it; else MaxOutputRequiredError.
 */
export function estimate(model: string, body: string | Uint8Array, policy: EstimatePolicy): Estimate {
    const maxOut = extractMaxOutput(body)
    const est: Estimate = {
        inputTokens: inputTokenBoundVersion(body, BOUND_VERSION_1),
        maxOutputTokens: maxOut,
        deriveMaxOutput: false,
        maxOutputCeiling: 0,
    }
    if (maxOut > 0) return est
    const byModel = Object.hasOwn(policy.maxOutputByModel, model) ? (policy.maxOutputByModel[model] ?? 0) : 0
    if (byModel > 0) return { ...est, maxOutputTokens: byModel }
    if (policy.fallbackMaxOutput === 0) throw new MaxOutputRequiredError()
    return {
        ...est,
        maxOutputTokens: policy.fallbackMaxOutput,
        deriveMaxOutput: true,
        maxOutputCeiling: policy.fallbackMaxOutput,
    }
}
