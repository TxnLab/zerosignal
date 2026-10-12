/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's price gate on a just-reserved ticket, run before escrow opens
// against it. Mirrors proto/go/zs's verifyReservePrice;
// testdata/reserve_price_vectors.json pins it against Go's.
//
// A node can sign a well-formed ticket at an inflated rate or an arbitrary
// max_price, and only this gate compares the ticket against what the node
// advertised. A missing reference skips only the checks that need it (SPEC
// § 3a "Fail-open"), so cold state never blocks an honest send and a node
// can't switch the whole gate off. The fee not yet read is bounded at the
// contract's fee cap, and an image-tool budget (whose per-image amount
// max_price folds in but the ticket doesn't carry) by the advertised per-image
// caps; max_price is then checked as at most the result. A headroom that
// overflows skips max_price, and a model the node's catalog doesn't list
// leaves only cache_read_discount. A per-call tool fee's headroom it
// reproduces exactly.

import type { OperatorDetails } from '@txnlab/zs-proto/inject'
import {
    type Advertised,
    PROTOCOL_FEE_BPS_MAX,
    type Violation,
    defaultPolicy,
    imageToolHeadroom,
    verifyTicketPrice,
    verifyUnadvertised,
} from '@txnlab/zs-proto/pricing'
import type { Ticket } from '@txnlab/zs-proto/ticket'

import type { Operator } from './operator.js'
import { capacityOf } from './sizing.js'

/**
 * A model's pricing as its node advertises it on /v1/zs/details, with the
 * operator-level minimum charge and tool-loop cap. An absent rate is a rate of
 * 0, which the gate enforces: it is not a missing reference.
 */
export interface ModelPricing {
    inputUsdPer1m?: number | undefined
    outputUsdPer1m?: number | undefined
    /** Absent when cached reads are not discounted. */
    cacheReadUsdPer1m?: number | undefined
    longContextThresholdTokens?: number | undefined
    longContextInputUsdPer1m?: number | undefined
    longContextOutputUsdPer1m?: number | undefined
    longContextCacheReadUsdPer1m?: number | undefined
    minChargeOutputTokens?: number | undefined
    minChargeMicroUsdc?: number | undefined
    maxToolIterations?: number | undefined
    /** Per-call microUSDC by canonical tool name; a zs_ name is a node built-in. */
    toolCallRatesMicroUsdc?: Record<string, number> | undefined
    vendorToolCatchAllMicroUsdc?: number | undefined
    vendorToolCallCap?: number | undefined
    vendorToolTokensPerCall?: number | undefined
    /** The worst-case microUSDC cost of one image from the gen / edit tool. */
    imageToolRateMicroUsdc?: number | undefined
    imageEditToolRateMicroUsdc?: number | undefined
}

/**
 * modelPricingOf is model's pricing in a node's advertisement, or null when
 * the node doesn't list it. A model listed twice reads as its last entry, as
 * Go's registry keys the list by id; but parseOperatorDetails has already
 * dropped an entry that is malformed, which Go's decoder keeps.
 */
export function modelPricingOf(d: OperatorDetails, model: string): ModelPricing | null {
    let m: OperatorDetails['models'][number] | undefined
    for (const e of d.models) if (e.id === model) m = e
    if (m === undefined) return null
    return {
        inputUsdPer1m: m.input_rate_usd_per_1m,
        outputUsdPer1m: m.output_rate_usd_per_1m,
        cacheReadUsdPer1m: m.cache_read_rate_usd_per_1m,
        longContextThresholdTokens: m.long_context_threshold_tokens,
        longContextInputUsdPer1m: m.long_context_input_rate_usd_per_1m,
        longContextOutputUsdPer1m: m.long_context_output_rate_usd_per_1m,
        longContextCacheReadUsdPer1m: m.long_context_cache_read_rate_usd_per_1m,
        minChargeOutputTokens: d.min_charge_output_tokens,
        minChargeMicroUsdc: d.min_charge_microusdc,
        maxToolIterations: d.max_tool_iterations,
        toolCallRatesMicroUsdc: m.tool_call_rates_micro_usdc,
        vendorToolCatchAllMicroUsdc: m.vendor_tool_catchall_micro_usdc,
        vendorToolCallCap: m.vendor_tool_call_cap,
        vendorToolTokensPerCall: m.vendor_tool_tokens_per_call,
        imageToolRateMicroUsdc: m.image_tool_rate_micro_usdc,
        imageEditToolRateMicroUsdc: m.image_edit_tool_rate_micro_usdc,
    }
}

/**
 * operatorPricingOf is model's pricing on a routable operator, or null when it
 * declares no capacity for the model, as Go's reservePriceViolation reads it
 * off zs.Operator.
 */
export function operatorPricingOf(
    op: Pick<Operator, 'modelCapacities' | 'minChargeOutputTokens' | 'minChargeMicroUsdc' | 'maxToolIters'>,
    model: string,
): ModelPricing | null {
    const mc = capacityOf(op, model)
    if (mc === undefined) return null
    return {
        inputUsdPer1m: mc.inputUsdPer1m,
        outputUsdPer1m: mc.outputUsdPer1m,
        cacheReadUsdPer1m: mc.cacheReadUsdPer1m,
        longContextThresholdTokens: mc.longContextThresholdTokens,
        longContextInputUsdPer1m: mc.longContextInputUsdPer1m,
        longContextOutputUsdPer1m: mc.longContextOutputUsdPer1m,
        longContextCacheReadUsdPer1m: mc.longContextCacheReadUsdPer1m,
        minChargeOutputTokens: op.minChargeOutputTokens,
        minChargeMicroUsdc: op.minChargeMicroUsdc,
        maxToolIterations: op.maxToolIters,
        toolCallRatesMicroUsdc: mc.toolCallRatesMicroUsdc,
        vendorToolCatchAllMicroUsdc: mc.vendorToolCatchAllMicroUsdc,
        vendorToolCallCap: mc.vendorToolCallCap,
        vendorToolTokensPerCall: mc.vendorToolTokensPerCall,
        imageToolRateMicroUsdc: mc.imageToolRateMicroUsdc,
        imageEditToolRateMicroUsdc: mc.imageEditToolRateMicroUsdc,
    }
}

export interface ReservePriceCall {
    ticket: Ticket
    /** The serving node's pricing for the request's model, or null when its catalog doesn't list it. */
    pricing: ModelPricing | null
    /**
     * The on-chain protocol fee in basis points, or null when it can't be read
     * now. Called only when max_price can otherwise be recomputed; a throw
     * reads as null.
     */
    feeBps(): Promise<number | null>
    /** The payer's own input bound for the request; 0 skips that check. */
    reserveInputCount: number
    imageToolBudget?: number
    imageEditToolBudget?: number
}

/** verifyReservePrice returns the ticket's first price violation, or null to accept. */
export async function verifyReservePrice(call: ReservePriceCall): Promise<Violation | null> {
    const p = call.pricing
    if (p === null) return verifyUnadvertised(call.ticket)
    const pol = defaultPolicy()
    const { zs, vendor } = maxToolRates(p)
    const toolReserve = toolFeeReserveU64(
        Math.max(p.maxToolIterations ?? 0, 0),
        zs,
        p.vendorToolCallCap ?? 0,
        vendor,
        p.vendorToolTokensPerCall ?? 0,
        call.ticket.input_rate,
    )
    // The image-tool budget's headroom isn't on the ticket, so it is bounded
    // from the advertised per-image caps and max_price is checked as at most
    // the result.
    const imageBudget = call.imageToolBudget ?? 0
    const editBudget = call.imageEditToolBudget ?? 0
    const gen = imageToolHeadroom(imageBudget, p.imageToolRateMicroUsdc ?? 0, pol)
    const edit = imageToolHeadroom(editBudget, p.imageEditToolRateMicroUsdc ?? 0, pol)
    let extra: bigint | null = null
    if (toolReserve !== null && gen !== null && edit !== null) {
        const sum = toolReserve + gen + edit
        if (sum <= MAX_U64) extra = sum
    }
    let feeBps: number | null = null
    if (extra === null) {
        // Overflow: the ceiling can't be bounded, but the advertised rates
        // still bound the signed ones.
        pol.skipMaxPrice = true
    } else {
        if (imageBudget > 0 || editBudget > 0) pol.maxPriceAtMost = true
        try {
            feeBps = await call.feeBps()
        } catch {
            feeBps = null
        }
        if (feeBps === null) {
            // The fee isn't read yet: the contract's cap bounds every fee the
            // ticket could have been priced at.
            feeBps = PROTOCOL_FEE_BPS_MAX
            pol.maxPriceAtMost = true
        }
    }
    const adv: Advertised = {
        inputUsdPer1m: p.inputUsdPer1m ?? 0,
        outputUsdPer1m: p.outputUsdPer1m ?? 0,
        minChargeOutputTokens: p.minChargeOutputTokens ?? 0,
        minChargeMicroUsdc: p.minChargeMicroUsdc ?? 0,
    }
    // An absent optional is no reference, and its bound is skipped.
    if (p.cacheReadUsdPer1m !== undefined) adv.cacheReadRateUsdPer1m = p.cacheReadUsdPer1m
    if (p.longContextThresholdTokens !== undefined) adv.longContextThresholdTokens = p.longContextThresholdTokens
    if (p.longContextInputUsdPer1m !== undefined) adv.longContextInputUsdPer1m = p.longContextInputUsdPer1m
    if (p.longContextOutputUsdPer1m !== undefined) adv.longContextOutputUsdPer1m = p.longContextOutputUsdPer1m
    if (p.longContextCacheReadUsdPer1m !== undefined) {
        adv.longContextCacheReadRateUsdPer1m = p.longContextCacheReadUsdPer1m
    }
    // Past 2^53 the number rounds, which moves only a violation's reported
    // want: an expected max_price that large is past any max_price a ticket's
    // number carries, so the gate refuses where Go's does.
    return verifyTicketPrice(call.ticket, adv, feeBps ?? 0, call.reserveInputCount, Number(extra ?? 0n), pol)
}

const MAX_U64 = (1n << 64n) - 1n
const RATE_DENOMINATOR = 1_000_000n

// toolFeeReserveU64 is zs-proto's toolFeeReserveMicroUSDC in exact uint64
// arithmetic, or null where Go's ToolFeeReserveMicroUSDC overflows. max_price
// is skipped only there: the advertised values are the node's, so skipping any
// sooner would let a node switch that check off.
function toolFeeReserveU64(
    maxToolIterations: number,
    maxZsRatePerCall: number,
    vendorCallCap: number,
    maxVendorRatePerCall: number,
    vendorTokensPerCall: number,
    inputRate: number,
): bigint | null {
    const parts: bigint[] = []
    if (maxZsRatePerCall > 0 && maxToolIterations > 0) {
        parts.push(BigInt(maxToolIterations) * BigInt(maxZsRatePerCall))
    }
    if (vendorCallCap > 0) {
        if (maxVendorRatePerCall > 0) parts.push(BigInt(vendorCallCap) * BigInt(maxVendorRatePerCall))
        if (vendorTokensPerCall > 0 && inputRate > 0) {
            const tokens = BigInt(vendorCallCap) * BigInt(vendorTokensPerCall)
            if (tokens > MAX_U64) return null
            // Go checks the product before it divides.
            const product = tokens * BigInt(inputRate)
            if (product > MAX_U64) return null
            parts.push((product + RATE_DENOMINATOR - 1n) / RATE_DENOMINATOR)
        }
    }
    let total = 0n
    for (const v of parts) {
        if (v > MAX_U64) return null
        total += v
        if (total > MAX_U64) return null
    }
    return total
}

// maxToolRates is the priciest per-call zs_ and vendor rate, the vendor one
// including the catch-all: Go's MaxZsToolRateMicroUSDC and
// MaxVendorToolRateMicroUSDC.
function maxToolRates(p: ModelPricing): { zs: number; vendor: number } {
    let zs = 0
    let vendor = p.vendorToolCatchAllMicroUsdc ?? 0
    for (const [name, rate] of Object.entries(p.toolCallRatesMicroUsdc ?? {})) {
        if (name.startsWith('zs_')) {
            if (rate > zs) zs = rate
        } else if (rate > vendor) {
            vendor = rate
        }
    }
    return { zs, vendor }
}
