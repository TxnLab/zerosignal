/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Sizes a request against one operator's declared capacity: the max_output it
// charges, whether it fits, and the input count its reserve commits to. Mirror
// of proto/go/zs/sizing.go and dispatch.go's reserveInputCount.

import { bodyDrivesServerSideToolGrowth } from '@txnlab/zs-proto/inject'
import { effectiveInputTokens, effectiveMaxOutput as effectiveMaxOutputOf, fitsContextWindow } from '@txnlab/zs-proto/selection'
import {
    BOUND_VERSION_1,
    BOUND_VERSION_2,
    bodyHasPreviousResponseId,
    inputTokenBoundVersion,
    reserveInputCount as reserveInputCountOf,
} from '@txnlab/zs-proto/tokenize'
import { usesTightInputBound } from '@txnlab/zs-proto/wire'

import type { ModelCapacity, Operator } from './operator.js'

/** The tool-loop input headroom per iteration for an operator that declares none. */
export const DEFAULT_TOOL_HEADROOM_PER_ITERATION = 4000
/** The least input a reserve commits to, below any declared window's cap. */
export const RESERVE_MIN_INPUT_COUNT = 256

/** SizingRequest is what the sizing filter and the reserve leg both read. */
export interface SizingRequest {
    model: string
    /** The v1 input bound. */
    inputTokens: number
    /** The flat max_output, or in derive mode the ceiling, for display only. */
    maxOutputTokens: number
    /** The v2 input bound, charged to an operator that supports it; 0 is not supplied. */
    inputTokensV2: number
    /** Size each operator's max_output from its declared capacity. */
    deriveMaxOutput: boolean
    /** The base ceiling derive mode clamps to. */
    maxOutputCeiling: number
}

/** capacityOf is op's capacity for model, or undefined when it declares none, as a Go map miss. */
export function capacityOf(op: Pick<Operator, 'modelCapacities'>, model: string): ModelCapacity | undefined {
    return Object.hasOwn(op.modelCapacities, model) ? op.modelCapacities[model] : undefined
}

/**
 * effectiveMaxOutput is the max_output req charges op: the number the sizing
 * filter admits on and the reserve escrows. An operator without a capacity for
 * the model derives from a zero window and cap, which is the ceiling.
 */
export function effectiveMaxOutput(op: Pick<Operator, 'modelCapacities'>, req: SizingRequest): number {
    const mc = capacityOf(op, req.model)
    return effectiveMaxOutputOf(mc?.contextWindow ?? 0, mc?.maxOutputTokens ?? 0, {
        unspecified: req.deriveMaxOutput,
        flat: req.maxOutputTokens,
        ceiling: req.maxOutputCeiling,
    })
}

/**
 * fits reports whether op can serve req under its declared capacity. No
 * capacity for the model is unbounded.
 */
export function fits(op: Pick<Operator, 'modelCapacities' | 'protoVersion'>, req: SizingRequest): boolean {
    const mc = capacityOf(op, req.model)
    if (mc === undefined) return true
    const maxOut = effectiveMaxOutput(op, req)
    const input = effectiveInputTokens(op.protoVersion, req.inputTokens, req.inputTokensV2)
    if (!fitsContextWindow(input, maxOut, mc.contextWindow)) return false
    if (mc.maxOutputTokens > 0 && maxOut > mc.maxOutputTokens) return false
    return true
}

/**
 * maxDeclaredOutput is the largest max_output_tokens any of ops declares for
 * model, or 0 when one of them declares none: a pool with an uncapped operator
 * has no ceiling to clamp a request to.
 */
export function maxDeclaredOutput(ops: readonly Pick<Operator, 'modelCapacities'>[], model: string): number {
    let max = 0
    for (const op of ops) {
        const mc = capacityOf(op, model)
        if (mc === undefined || mc.maxOutputTokens === 0) return 0
        if (mc.maxOutputTokens > max) max = mc.maxOutputTokens
    }
    return max
}

/** boundVersionFor is the input bound op's reserve is measured with. */
export function boundVersionFor(op: Pick<Operator, 'protoVersion'>): number {
    return usesTightInputBound(op.protoVersion) ? BOUND_VERSION_2 : BOUND_VERSION_1
}

/** The input count a reserve commits to, and the bound version it measured with. */
export interface ReserveInput {
    count: number
    boundVersion: number
}

/**
 * reserveInputCount is the input count op's reserve commits to for body. A
 * body continuing a server-side response chain can't be measured, so where the
 * window allows it reserves all of the window the output leaves; otherwise it
 * is the body's bound plus tool-loop headroom, floored and capped to the window.
 */
export function reserveInputCount(
    op: Pick<Operator, 'modelCapacities' | 'protoVersion' | 'maxToolIters' | 'toolHeadroomPerIteration'>,
    model: string,
    body: string | Uint8Array,
    maxOutputTokens: number,
): ReserveInput {
    const boundVersion = boundVersionFor(op)
    const bodyBound = inputTokenBoundVersion(body, boundVersion)
    const contextWindow = capacityOf(op, model)?.contextWindow ?? 0
    if (bodyHasPreviousResponseId(body) && contextWindow > maxOutputTokens) {
        return { count: contextWindow - maxOutputTokens, boundVersion }
    }
    const count = reserveInputCountOf({
        bodyBound,
        carriesTools: bodyDrivesServerSideToolGrowth(body),
        maxToolIterations: op.maxToolIters > 0 ? op.maxToolIters : 0,
        perIterHeadroom: op.toolHeadroomPerIteration || DEFAULT_TOOL_HEADROOM_PER_ITERATION,
        maxOutput: maxOutputTokens,
        contextWindow,
        floor: RESERVE_MIN_INPUT_COUNT,
    })
    return { count, boundVersion }
}
