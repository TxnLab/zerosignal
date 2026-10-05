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
// advertised. It fails open when a reference is missing, so cold state never
// blocks an honest send: the fee not yet read, a model the node's catalog
// doesn't list, or an image-tool budget, whose per-image amount max_price
// folds in and this can't reproduce. A per-call tool fee's headroom it does
// reproduce, so the rate and minimum-charge bounds keep running for a model
// that prices tools.

import type { OperatorDetails } from '@txnlab/zs-proto/inject'
import {
    type Advertised,
    type Violation,
    defaultPolicy,
    verifyTicketPrice,
} from '@txnlab/zs-proto/pricing'
import type { Ticket } from '@txnlab/zs-proto/ticket'

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
    }
}

export interface ReservePriceCall {
    ticket: Ticket
    /** The serving node's pricing for the request's model, or null when its catalog doesn't list it. */
    pricing: ModelPricing | null
    /**
     * The on-chain protocol fee in basis points, or null when it can't be read
     * now. Called only once the image-tool skip has passed; a throw reads as null.
     */
    feeBps(): Promise<number | null>
    /** The payer's own input bound for the request; 0 skips that check. */
    reserveInputCount: number
    imageToolBudget?: number
    imageEditToolBudget?: number
}

/** verifyReservePrice returns the ticket's first price violation, or null to accept. */
export async function verifyReservePrice(call: ReservePriceCall): Promise<Violation | null> {
    if ((call.imageToolBudget ?? 0) > 0 || (call.imageEditToolBudget ?? 0) > 0) return null
    let feeBps: number | null
    try {
        feeBps = await call.feeBps()
    } catch {
        feeBps = null
    }
    if (feeBps === null) return null
    const p = call.pricing
    if (p === null) return null
    const { zs, vendor } = maxToolRates(p)
    const toolReserve = toolFeeReserveU64(
        Math.max(p.maxToolIterations ?? 0, 0),
        zs,
        p.vendorToolCallCap ?? 0,
        vendor,
        p.vendorToolTokensPerCall ?? 0,
        call.ticket.input_rate,
    )
    if (toolReserve === null) return null
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
    return verifyTicketPrice(call.ticket, adv, feeBps, call.reserveInputCount, Number(toolReserve), defaultPolicy())
}

const MAX_U64 = (1n << 64n) - 1n
const RATE_DENOMINATOR = 1_000_000n

// toolFeeReserveU64 is zs-proto's toolFeeReserveMicroUSDC in exact uint64
// arithmetic, or null where Go's ToolFeeReserveMicroUSDC overflows. The gate
// fails open only there: the advertised values are the node's, so failing open
// any sooner would let a node switch the gate off.
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
