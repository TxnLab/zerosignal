/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The worst-case price a request can be admitted at, from what the candidates
// advertise, for a spend guard to check before anything is reserved. Mirror of
// proto/go/zs/admit.go.

import { BPS_DENOMINATOR, RATE_DENOMINATOR_TOKENS, isLongContext, usdRateToMicroUSDCPer1M } from '@txnlab/zs-proto/pricing'

import type { Operator } from './operator.js'
import { type SizingRequest, capacityOf, effectiveMaxOutput, reserveInputCount } from './sizing.js'

type Candidate = Pick<
    Operator,
    'modelCapacities' | 'protoVersion' | 'maxToolIters' | 'toolHeadroomPerIteration'
>

/**
 * admitEstimate is the lowest advertised max_price across candidates, or null
 * when it can't be known: the fee not yet read, no candidates, or any one of
 * them unpriced for the model. Null admits on the guard's other checks.
 */
export function admitEstimate(
    candidates: readonly Candidate[],
    model: string,
    body: string | Uint8Array,
    sizing: SizingRequest,
    feeBps: number | null,
): number | null {
    if (feeBps === null || candidates.length === 0) return null
    let lowest: number | null = null
    for (const op of candidates) {
        const price = advertisedMaxPrice(op, model, body, sizing, feeBps)
        if (price === null) return null
        if (lowest === null || price < lowest) lowest = price
    }
    return lowest
}

/**
 * advertisedMaxPrice is the max_price op would sign for the request at its
 * advertised rates: the reserve's own input count and max_output, the
 * long-context tier where the input reaches it, and the fee grossed up. Null
 * when op prices the model at 0 on either leg, has no long-context rates for a
 * long request, or the arithmetic overflows uint64. It leaves out the minimum
 * charge and tool headroom, which only raise the price a ticket may carry.
 */
export function advertisedMaxPrice(
    op: Candidate,
    model: string,
    body: string | Uint8Array,
    sizing: SizingRequest,
    feeBps: number,
): number | null {
    const mc = capacityOf(op, model)
    if (mc === undefined || mc.inputUsdPer1m === 0 || mc.outputUsdPer1m === 0) return null
    const maxOut = effectiveMaxOutput(op, sizing)
    const { count: input } = reserveInputCount(op, model, body, maxOut)
    let inUsd = mc.inputUsdPer1m
    let outUsd = mc.outputUsdPer1m
    if (isLongContext(input, mc.longContextThresholdTokens)) {
        if (mc.longContextInputUsdPer1m === undefined || mc.longContextOutputUsdPer1m === undefined) return null
        inUsd = mc.longContextInputUsdPer1m
        outUsd = mc.longContextOutputUsdPer1m
    }
    const inRate = microRate(inUsd)
    const outRate = microRate(outUsd)
    if (inRate === null || outRate === null) return null
    const inCost = ceilMulDiv(BigInt(input), inRate, BigInt(RATE_DENOMINATOR_TOKENS))
    const outCost = ceilMulDiv(BigInt(maxOut), outRate, BigInt(RATE_DENOMINATOR_TOKENS))
    if (inCost === null || outCost === null || inCost + outCost > U64_MAX) return null
    const base = inCost + outCost
    if (feeBps === 0) return Number(base)
    const fee = ceilMulDiv(base, BigInt(feeBps), BigInt(BPS_DENOMINATOR))
    if (fee === null || base + fee > U64_MAX) return null
    return Number(base + fee)
}

const U64_MAX = (1n << 64n) - 1n

// microRate is Go's USDRateToMicroUSDCPer1M, which also refuses a rate past
// uint64 that zs-proto's number twin passes through.
function microRate(usd: number): bigint | null {
    let r: number
    try {
        r = usdRateToMicroUSDCPer1M(usd)
    } catch {
        return null
    }
    return r > 2 ** 64 ? null : BigInt(r)
}

// ceilMulDiv is Go's pricing.ceilMulDiv: null where a*b overflows uint64.
function ceilMulDiv(a: bigint, b: bigint, d: bigint): bigint | null {
    if (a === 0n || b === 0n) return 0n
    const p = a * b
    if (p > U64_MAX) return null
    return (p + d - 1n) / d
}
