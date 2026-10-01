/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Shared token-pricing primitive — the TypeScript mirror of proto/go/pricing.
// The node prices a reserve with this math and the client verifies a signed
// ticket's price against it before escrowing (see ./verify). Pinned byte-for-
// byte against the Go side by proto/testdata/pricing_vectors.json, because a
// payer-side verifier must recompute exactly what the node signed — any drift
// refuses honest requests or admits over-priced ones.
//
// Two rounding shapes are load-bearing and deliberately different, matching Go:
//   - the reserve ceiling (rateBasedMaxPrice) rounds the input and output legs
//     with two SEPARATE ceils;
//   - the settle charge (ceilInputCost) rounds the cached + non-cached input
//     sub-legs together under a SINGLE ceil, so an unset cache_read_rate (== the
//     input rate) reproduces the pre-cache flat charge byte-for-byte.
//
// All arithmetic that multiplies a token count by a rate uses BigInt — the
// product can exceed 2^53, so Number would silently lose precision and desync
// from Go's uint64. Results (max_price, charge, …) are within 2^53 and returned
// as number.
//
// All money is microUSDC; all rates are microUSDC per 1,000,000 tokens.

export const RATE_DENOMINATOR_TOKENS = 1_000_000
export const BPS_DENOMINATOR = 10_000
export const ALGORAND_MIN_TXN_FEE_MICRO_ALGOS = 1_000

// ceilDiv over non-negative bigints: ceil(num/den).
function ceilDiv(num: bigint, den: bigint): bigint {
  if (num <= 0n) return 0n
  return (num + den - 1n) / den
}

/**
 * Reports whether a request whose signed input_count is inputCount falls into the
 * operator's long-context (high) pricing tier. threshold === 0 means the operator
 * advertises no tier (flat pricing), so this is always false; otherwise the
 * request is in the high tier iff inputCount >= threshold. Two properties are
 * load-bearing: the tier is decided by input (prompt) tokens ALONE (only
 * input_count is committed on the ticket, so node and verifier resolve the same
 * tier from the same value), and the boundary is INCLUSIVE (a request exactly at
 * threshold pays the high rate). Mirrors Go pricing.IsLongContext byte-for-byte.
 */
export function isLongContext(inputCount: number, threshold: number): boolean {
  return threshold > 0 && inputCount >= threshold
}

/**
 * Converts a USD-per-1M-tokens rate to microUSDC per 1M tokens with ceiling
 * rounding. 0 is free; non-finite or negative rates throw (mirrors the Go
 * error). This is the exact conversion the node applies to an operator's
 * configured (and advertised) USD rate.
 */
export function usdRateToMicroUSDCPer1M(usdPer1M: number): number {
  if (!Number.isFinite(usdPer1M) || usdPer1M < 0) {
    throw new Error(`usd_per_1m out of range: ${usdPer1M}`)
  }
  if (usdPer1M === 0) return 0
  return Math.ceil(usdPer1M * 1_000_000)
}

/**
 * Settle-time input leg: ceil((nonCached*inputRate + cached*cacheReadRate)/1e6)
 * — a SINGLE ceil over the combined numerator. When cacheReadRate == inputRate
 * the numerator is exactly inputTokens*inputRate, reproducing the pre-cache flat
 * cost; because cacheReadRate <= inputRate a single ceil keeps the discounted
 * cost <= the flat cost.
 */
export function ceilInputCost(nonCached: number, inputRate: number, cached: number, cacheReadRate: number): number {
  const num = BigInt(nonCached) * BigInt(inputRate) + BigInt(cached) * BigInt(cacheReadRate)
  return Number(ceilDiv(num, BigInt(RATE_DENOMINATOR_TOKENS)))
}

/**
 * Reserve-time rate ceiling for a token ticket:
 * ceil(inputCount*inputRate/1e6) + ceil(maxOutputCount*outputRate/1e6) — two
 * SEPARATE ceils. No cache-read term, no min-charge floor, no protocol fee.
 */
export function rateBasedMaxPrice(inputCount: number, maxOutputCount: number, inputRate: number, outputRate: number): number {
  const inputCost = ceilDiv(BigInt(inputCount) * BigInt(inputRate), BigInt(RATE_DENOMINATOR_TOKENS))
  const outputCost = ceilDiv(BigInt(maxOutputCount) * BigInt(outputRate), BigInt(RATE_DENOMINATOR_TOKENS))
  return Number(inputCost + outputCost)
}

/**
 * µALGO component of the minimum charge: ceil(algoTxns*minTxnFee*algoUSD), or 0
 * when unpaid, no txns are floored, or the oracle is unavailable (algoUSD <= 0).
 * The algoUSD <= 0 short-circuit precedes the finiteness guard, matching Go.
 */
export function algoTxnFloorMicroUSDC(paid: boolean, algoTxns: number, algoUSD: number): number {
  if (!paid || algoTxns === 0 || algoUSD <= 0) return 0
  if (!Number.isFinite(algoUSD)) throw new Error(`algo_usd out of range: ${algoUSD}`)
  const costMicroAlgos = algoTxns * ALGORAND_MIN_TXN_FEE_MICRO_ALGOS
  return Math.ceil(costMicroAlgos * algoUSD)
}

/**
 * Node reserve-time minimum charge: max(ceil(minOutputTokens*outputRate/1e6),
 * algoTxnFloorMicroUSDC(...)). Only the node (which holds the live ALGO/USD
 * price) computes this; a payer-side verifier uses minChargeFloor instead.
 */
export function reserveMinPrice(minOutputTokens: number, outputRate: number, algoTxns: number, algoUSD: number, paid: boolean): number {
  const tokenFloor = Number(ceilDiv(BigInt(minOutputTokens) * BigInt(outputRate), BigInt(RATE_DENOMINATOR_TOKENS)))
  const algoFloor = algoTxnFloorMicroUSDC(paid, algoTxns, algoUSD)
  return Math.max(tokenFloor, algoFloor)
}

/**
 * baseMax + ceil(baseMax*feeBps/1e4): the operator's base ceiling grossed up by
 * the additive protocol fee (the contract's pfee global, basis points). feeBps
 * === 0 is a pass-through.
 */
export function grossUpForFee(baseMax: number, feeBps: number): number {
  if (feeBps === 0) return baseMax
  const fee = Number(ceilDiv(BigInt(baseMax) * BigInt(feeBps), BigInt(BPS_DENOMINATOR)))
  return baseMax + fee
}

/**
 * Pre-gross-up escrow ceiling for a token ticket:
 * max(rateBasedMaxPrice + extraBaseMicroUSDC, minPrice). extraBaseMicroUSDC is
 * any additive per-request budget folded into the base before the floor and fee
 * (e.g. an image-tool budget on a /v1/responses ticket); 0 for a plain token
 * ticket.
 */
export function expectedBaseMax(inputCount: number, maxOutputCount: number, inputRate: number, outputRate: number, minPrice: number, extraBaseMicroUSDC: number): number {
  const rateBased = rateBasedMaxPrice(inputCount, maxOutputCount, inputRate, outputRate)
  const base = rateBased + extraBaseMicroUSDC
  return Math.max(base, minPrice)
}

/**
 * Full reserve-time escrow ceiling for a token ticket:
 * grossUpForFee(expectedBaseMax(...), feeBps). This is exactly the value the node
 * signs as ticket.max_price, so a verifier asserts ticket.max_price ===
 * expectedMaxPrice(...) with the on-chain feeBps (check C1).
 */
export function expectedMaxPrice(inputCount: number, maxOutputCount: number, inputRate: number, outputRate: number, minPrice: number, extraBaseMicroUSDC: number, feeBps: number): number {
  return grossUpForFee(expectedBaseMax(inputCount, maxOutputCount, inputRate, outputRate, minPrice, extraBaseMicroUSDC), feeBps)
}

/**
 * The additive max_price headroom a per-call tool-pricing model folds into the
 * reserve (SPEC.md "Per-call tool pricing"). Mirrors the Go
 * pricing.ToolFeeReserveMicroUSDC byte-for-byte so the node and the payer-side
 * verifier compute identical values (it is the extraBaseMicroUSDC term passed to
 * expectedMaxPrice). Two worst-case components:
 *   - node zs_ built-in fees: maxToolIterations * maxZsRatePerCall (0 when the
 *     builtin-tool loop is disabled, i.e. maxToolIterations === 0 — the same
 *     condition under which the node omits max_tool_iterations from
 *     /v1/zs/details, so the verifier reproduces 0 too);
 *   - vendor server-side tool fees: vendorCallCap * maxVendorRatePerCall, plus
 *     the input-token cost of the per-call context inflation
 *     (vendorCallCap * vendorTokensPerCall priced at inputRateMicroUSDCPer1M).
 * Each component is 0 unless the model prices that class of tool. All rates are
 * per-call microUSDC; inputRate is microUSDC per 1M tokens.
 */
export function toolFeeReserveMicroUSDC(
  maxToolIterations: number,
  maxZsRatePerCall: number,
  vendorCallCap: number,
  maxVendorRatePerCall: number,
  vendorTokensPerCall: number,
  inputRateMicroUSDCPer1M: number,
): number {
  let total = 0
  if (maxZsRatePerCall > 0 && maxToolIterations > 0) {
    total += maxToolIterations * maxZsRatePerCall
  }
  if (vendorCallCap > 0) {
    if (maxVendorRatePerCall > 0) {
      total += vendorCallCap * maxVendorRatePerCall
    }
    if (vendorTokensPerCall > 0 && inputRateMicroUSDCPer1M > 0) {
      total += rateBasedMaxPrice(vendorCallCap * vendorTokensPerCall, 0, inputRateMicroUSDCPer1M, 0)
    }
  }
  return total
}

/**
 * Payer-side reference for the signed min_price (check C3):
 * max(ceil(minChargeOutputTokens*outputRate/1e6), minChargeMicroUSDC), using the
 * ticket's own output_rate and the operator's advertised min-charge basis.
 */
export function minChargeFloor(minChargeOutputTokens: number, outputRate: number, minChargeMicroUSDC: number): number {
  const tokenFloor = Number(ceilDiv(BigInt(minChargeOutputTokens) * BigInt(outputRate), BigInt(RATE_DENOMINATOR_TOKENS)))
  return Math.max(tokenFloor, minChargeMicroUSDC)
}

/**
 * Settle-time charge for actual usage:
 * clamp(max(ceilInputCost(...) + ceil(actualOutput*outputRate/1e6), minPrice), 0,
 * baseMax). Zero input and output short-circuit to 0 (inference failure). Never
 * throws — matching the node's settle behavior of falling back to the base
 * ceiling.
 */
export function chargeFor(actualInput: number, cachedInput: number, actualOutput: number, inputRate: number, cacheReadRate: number, outputRate: number, minPrice: number, baseMax: number): number {
  if (actualInput === 0 && actualOutput === 0) return 0

  let cached = cachedInput
  if (cached > actualInput) cached = actualInput
  const nonCached = actualInput - cached

  const inCost = ceilInputCost(nonCached, inputRate, cached, cacheReadRate)
  const outCost = Number(ceilDiv(BigInt(actualOutput) * BigInt(outputRate), BigInt(RATE_DENOMINATOR_TOKENS)))

  let charged = inCost + outCost
  if (charged < minPrice) {
    if (minPrice > baseMax) return baseMax
    charged = minPrice
  }
  if (charged > baseMax) return baseMax
  return charged
}
