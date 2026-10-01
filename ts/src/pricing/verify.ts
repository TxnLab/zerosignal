/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Payer-side ticket-price verifier — the TypeScript mirror of
// proto/go/pricing.VerifyTicketPrice. Recomputes what the node signed and
// refuses a ticket whose price is inconsistent or exceeds the advertised pricing
// before the client escrows against it. See proto/SPEC.md §3a "Payer-side price
// verification".

import type { Ticket } from '../ticket/index.js'
import { UsageType } from '../ticket/index.js'
import { expectedMaxPrice, isLongContext, minChargeFloor, usdRateToMicroUSDCPer1M } from './pricing.js'

/**
 * Operator's published pricing for a model, from /v1/zs/details. Missing or
 * non-finite required fields normalize to 0, matching Go's zero value; optional
 * fields are handled per the fail-open rules in verifyTicketPrice.
 */
export interface Advertised {
  /** input_rate_usd_per_1m (0 = free). */
  inputUsdPer1m: number
  /** output_rate_usd_per_1m (0 = free). */
  outputUsdPer1m: number
  /**
   * cache_read_rate_usd_per_1m: undefined when no cache-read discount is
   * advertised; a present 0 means free cached reads.
   */
  cacheReadRateUsdPer1m?: number
  /** min_charge_output_tokens; with minChargeMicroUsdc, both 0 ⇒ no min_charge_bound reference. */
  minChargeOutputTokens: number
  /** min_charge_microusdc (advertised µALGO-component value). */
  minChargeMicroUsdc: number
  /**
   * long_context_threshold_tokens: the prompt-token count at/above which the
   * operator's long-context (high) pricing tier applies (xAI's context-size
   * cliff). 0/undefined ⇒ no tier (flat pricing) and the three fields below are
   * ignored. When set, longContextInputUsdPer1m / longContextOutputUsdPer1m are
   * the high-tier rates (>= their base counterparts — a surcharge, enforced by
   * long_context_ordering). The verifier resolves which comparand to bound the
   * signed rates against via isLongContext(t.input_count, longContextThresholdTokens).
   */
  longContextThresholdTokens?: number
  /** High-tier input/output rates; undefined tolerated (falls back to base). */
  longContextInputUsdPer1m?: number
  longContextOutputUsdPer1m?: number
  /**
   * High-tier cache-read rate, mirroring cacheReadRateUsdPer1m's nil-vs-zero
   * semantics for the high tier: undefined when the high tier advertises no
   * cache-read discount, a present 0 meaning free cached reads in the high tier.
   */
  longContextCacheReadRateUsdPer1m?: number
}

/** Tunes the verifier's tolerances and fail-open behavior. */
export interface Policy {
  /**
   * Bounds a signed rate / min-charge against its advertised value:
   * ticket.rate <= ceil(advertisedMicro * rateMaxMultiple). A multiple (not an
   * additive slack) preserves the interim client gate's semantics and absorbs a
   * legitimate reprice. 1.0 = exact-or-cheaper; the interim gate used 2.0.
   */
  rateMaxMultiple: number
  /**
   * Bounds a signed input_count against the caller's own tokenize bound:
   * ticket.input_count <= floor(reserveInputCount*(1+inputCountTolerance)). Reuse
   * the node's input_budget_tolerance (0.10).
   */
  inputCountTolerance: number
  /**
   * Skips checks that lack a usable reference instead of failing them.
   * Recommended true — an honest send must never be blocked by absent catalog
   * data.
   */
  failOpen: boolean
}

/** Preserves the interim gate's 2x rate ceiling, 0.10 input tolerance, fail-open. */
export function defaultPolicy(): Policy {
  return { rateMaxMultiple: 2.0, inputCountTolerance: 0.1, failOpen: true }
}

/**
 * A failed check. want is the maximum allowed (or exact expected, for the
 * max_price check); got is the signed value. Both are microUSDC except for
 * input_count_bound (token counts).
 */
export interface Violation {
  check: 'max_price' | 'rate_bound' | 'min_charge_bound' | 'input_count_bound' | 'cache_read_discount' | 'cache_read_bound' | 'long_context_ordering' | 'long_context_tier'
  field: string
  want: number
  got: number
  detail: string
}

// scaleByMultiple returns ceil(v * mult). mult <= 1 (or v === 0) yields v.
function scaleByMultiple(v: number, mult: number): number {
  if (mult <= 1.0 || v === 0) return v
  return Math.ceil(v * mult)
}

// scaleByTolerance returns floor(v * (1+tol)). tol <= 0 (or v === 0) yields v.
function scaleByTolerance(v: number, tol: number): number {
  if (tol <= 0 || v === 0) return v
  return Math.floor(v * (1.0 + tol))
}

// JSON-decoded objects can violate the compile-time number contract with a
// missing, null, or non-finite value. Go decodes the equivalent value field to
// its zero value, so normalize the required numeric state once at the verifier
// boundary. Negative finite advertised rates deliberately remain invalid and
// continue through checkRateBound's fail-open policy, matching Go.
function finiteOrZero(v: number): number {
  return Number.isFinite(v) ? v : 0
}

// Preserve the optional fields' nil-vs-present contract: null/undefined means
// no advertised reference, while a present but non-finite number is the same
// unusable numeric value Go's JSON boundary rejects and therefore normalizes to
// the conservative zero reference here.
function optionalFiniteOrZero(v: number | null | undefined): number | undefined {
  return v == null ? undefined : finiteOrZero(v)
}

// checkLongContextOrdering enforces that an advertised long-context tier is a
// surcharge, not a discount: the high input/output rates must be >= their base
// counterparts. The caller runs it only when a tier is advertised
// (longContextThresholdTokens > 0). An absent high rate makes no ordering claim
// and is skipped — the tier resolution then falls back to the base rate, which
// rate_bound still bounds. want/got stay 0: an advertisement-consistency
// violation, not a value-bound, so the detail carries the meaning.
//
// `!= null` (not `!== undefined`) is load-bearing on every optional field in this
// file: Advertised is public package API, and a caller building it straight from
// a JSON details payload naturally lands `null` on an absent field. Under a
// `!== undefined` guard `null` is treated as present and then coerces to 0 in the
// comparison, which reads as "advertised $0" — a spurious ordering violation
// here, and a spurious cache_read_bound of 0 below. Go's `!= nil` has no such
// hole; this keeps the two verifiers deciding alike.
function checkLongContextOrdering(adv: Advertised): Violation | null {
  if (adv.longContextInputUsdPer1m != null && adv.longContextInputUsdPer1m < adv.inputUsdPer1m) {
    return { check: 'long_context_ordering', field: 'long_context_input_rate', want: 0, got: 0,
      detail: 'advertised long-context input rate is below the base input rate; a tier must be a surcharge, not a discount' }
  }
  if (adv.longContextOutputUsdPer1m != null && adv.longContextOutputUsdPer1m < adv.outputUsdPer1m) {
    return { check: 'long_context_ordering', field: 'long_context_output_rate', want: 0, got: 0,
      detail: 'advertised long-context output rate is below the base output rate; a tier must be a surcharge, not a discount' }
  }
  return null
}

// checkRateBound bounds a signed micro rate against an advertised USD/1M rate.
function checkRateBound(check: Violation['check'], field: string, ticketRate: number, advUsdPer1m: number, pol: Policy): Violation | null {
  let advMicro: number
  try {
    advMicro = usdRateToMicroUSDCPer1M(advUsdPer1m)
  } catch (e) {
    if (pol.failOpen) return null
    return { check, field, want: 0, got: ticketRate, detail: `advertised rate invalid: ${String(e)}` }
  }
  const bound = scaleByMultiple(advMicro, pol.rateMaxMultiple)
  if (ticketRate > bound) {
    return { check, field, want: bound, got: ticketRate, detail: 'signed rate exceeds the advertised rate' }
  }
  return null
}

/**
 * Checks a signed ticket's price before the client escrows, returning the first
 * violation or null if acceptable. Runs the token-ticket checks below, each named
 * by the Violation.check it reports:
 *
 *   - max_price           max_price === expectedMaxPrice(...) (exact, from the
 *                         ticket's own signed numbers + the on-chain feeBps)
 *   - rate_bound          input_rate / output_rate <= advertised * rateMaxMultiple
 *   - min_charge_bound    min_price <= advertised minChargeFloor * rateMaxMultiple
 *   - input_count_bound   input_count <= reserveInputCount * (1 + inputCountTolerance)
 *   - cache_read_discount cache_read_rate <= input_rate (internal invariant, no external ref)
 *   - cache_read_bound    cache_read_rate <= advertised cache-read rate * rateMaxMultiple
 *   - long_context_ordering advertised high-tier input/output rate >= its base counterpart (surcharge)
 *   - long_context_tier    a tiered input_count needs the caller's own bound to be tiered too
 *
 * When the operator advertises a long-context tier (adv.longContextThresholdTokens
 * > 0), rate_bound and cache_read_bound resolve the advertised comparand to the
 * HIGH-tier rate for a ticket whose signed input_count is at/above the threshold
 * (isLongContext) — the tier is decided by the same signed count the node used at
 * reserve, so no separate max() ceiling is needed. max_price stays an exact
 * recompute from the ticket's own signed (already tier-resolved) rates.
 * long_context_tier is what makes resolving off the SIGNED count safe: it refuses
 * a ticket whose count was raised across the threshold when the caller's own bound
 * sits below it, so the input_count tolerance can't be spent buying a whole tier.
 *
 * feeBps is the on-chain protocol fee (pfee). reserveInputCount is the caller's
 * own tokenize reserve value for this request (0 ⇒ skip input_count_bound).
 * imageToolBudget is any additive per-request budget folded into the reserve
 * (image tools on a /v1/responses ticket; 0 for a plain token ticket) so the
 * max_price recompute reproduces it exactly. Image / character / seconds tickets
 * are skipped (null).
 */
export function verifyTicketPrice(
  t: Ticket,
  adv: Advertised,
  feeBps: number,
  reserveInputCount: number,
  imageToolBudget: number,
  pol: Policy,
): Violation | null {
  // Do not mutate the signed object. The verifier is total over the malformed
  // runtime shapes a JSON caller can supply even though Ticket's static fields
  // are required numbers.
  t = {
    ...t,
    input_count: finiteOrZero(t.input_count),
    max_output_count: finiteOrZero(t.max_output_count),
    input_rate: finiteOrZero(t.input_rate),
    output_rate: finiteOrZero(t.output_rate),
    cache_read_rate: finiteOrZero(t.cache_read_rate),
    min_price: finiteOrZero(t.min_price),
    max_price: finiteOrZero(t.max_price),
  }
  adv = {
    ...adv,
    inputUsdPer1m: finiteOrZero(adv.inputUsdPer1m),
    outputUsdPer1m: finiteOrZero(adv.outputUsdPer1m),
    cacheReadRateUsdPer1m: optionalFiniteOrZero(adv.cacheReadRateUsdPer1m),
    minChargeOutputTokens: finiteOrZero(adv.minChargeOutputTokens),
    minChargeMicroUsdc: finiteOrZero(adv.minChargeMicroUsdc),
    longContextThresholdTokens: optionalFiniteOrZero(adv.longContextThresholdTokens),
    longContextInputUsdPer1m: optionalFiniteOrZero(adv.longContextInputUsdPer1m),
    longContextOutputUsdPer1m: optionalFiniteOrZero(adv.longContextOutputUsdPer1m),
    longContextCacheReadRateUsdPer1m: optionalFiniteOrZero(adv.longContextCacheReadRateUsdPer1m),
  }

  if (
    t.output_usage_type === UsageType.Images ||
    t.output_usage_type === UsageType.Characters ||
    t.output_usage_type === UsageType.Seconds
  ) {
    return null // priced per-image / per-char / per-second, not per-token
  }

  // cache_read_discount — a cache read is always a discount. No external reference; runs always.
  if (t.cache_read_rate > t.input_rate) {
    return {
      check: 'cache_read_discount',
      field: 'cache_read_rate',
      want: t.input_rate,
      got: t.cache_read_rate,
      detail: 'cache_read_rate exceeds input_rate; a cache read must be a discount',
    }
  }

  // max_price — internal consistency (exact). Recompute from the ticket's own
  // signed rates/counts + the on-chain fee.
  const wantMax = expectedMaxPrice(t.input_count, t.max_output_count, t.input_rate, t.output_rate, t.min_price, imageToolBudget, feeBps)
  if (t.max_price !== wantMax) {
    return {
      check: 'max_price',
      field: 'max_price',
      want: wantMax,
      got: t.max_price,
      detail: 'max_price does not match rates x counts grossed up by the protocol fee',
    }
  }

  // long_context tier — resolve which advertised rate set the signed rates are
  // bounded against. The tier is decided by the ticket's OWN signed input_count
  // (isLongContext), the identical value the node used at reserve to pick which
  // rates to sign, so both sides agree deterministically. inputAdv/outputAdv/
  // cacheAdv default to the base tier and are lifted to the high tier below.
  let inputAdv = adv.inputUsdPer1m
  let outputAdv = adv.outputUsdPer1m
  let cacheAdv = adv.cacheReadRateUsdPer1m
  if (adv.longContextThresholdTokens != null && adv.longContextThresholdTokens > 0) {
    // long_context_ordering — a tier must be a surcharge, not a discount. Runs
    // whenever a tier is advertised, independent of this ticket's tier — it
    // validates the advertisement itself, which every ticket relies on.
    const orderViol = checkLongContextOrdering(adv)
    if (orderViol) return orderViol
    // long_context_tier — the node may not cross the price cliff on a count the
    // caller doesn't agree crossed it. input_count_bound alone does not cover
    // this: it tolerates a signed count up to reserveInputCount * (1 +
    // inputCountTolerance), and a <=10% count inflation is enough to jump a whole
    // tier — a 2x multiplier on the entire request, which rate_bound then waves
    // through because an exactly-2x surcharge sits precisely on the base *
    // rateMaxMultiple boundary. So check the TIER, not the count: an honest node
    // only ever clamps input_count DOWN, so a sub-threshold request can never
    // legitimately come back tiered. Skipped when the caller has no bound of its
    // own (reserveInputCount === 0), same as input_count_bound.
    if (
      reserveInputCount > 0 &&
      isLongContext(t.input_count, adv.longContextThresholdTokens) &&
      !isLongContext(reserveInputCount, adv.longContextThresholdTokens)
    ) {
      return { check: 'long_context_tier', field: 'input_count',
        want: reserveInputCount, got: t.input_count,
        detail: "input_count was raised across the long-context threshold; the caller's own bound is below it" }
    }
    if (isLongContext(t.input_count, adv.longContextThresholdTokens)) {
      if (adv.longContextInputUsdPer1m != null) inputAdv = adv.longContextInputUsdPer1m
      if (adv.longContextOutputUsdPer1m != null) outputAdv = adv.longContextOutputUsdPer1m
      // In the high tier the base cache-read discount does not apply: the comparand
      // is the high-tier cache-read rate. Absent (no high-tier discount advertised)
      // skips cache_read_bound entirely, leaving the signed rate bounded by
      // cache_read_discount (<= high input_rate) + input rate_bound.
      cacheAdv = adv.longContextCacheReadRateUsdPer1m ?? undefined
    }
  }

  // rate_bound — signed rates must not exceed advertised (tier-appropriate) (× the multiple).
  const inRateViol = checkRateBound('rate_bound', 'input_rate', t.input_rate, inputAdv, pol)
  if (inRateViol) return inRateViol
  const outRateViol = checkRateBound('rate_bound', 'output_rate', t.output_rate, outputAdv, pol)
  if (outRateViol) return outRateViol

  // cache_read_bound — signed cache-read rate must honor the advertised (tier-appropriate)
  // discount, when one is advertised.
  if (cacheAdv != null) {
    const cacheReadViol = checkRateBound('cache_read_bound', 'cache_read_rate', t.cache_read_rate, cacheAdv, pol)
    if (cacheReadViol) return cacheReadViol
  }

  // min_charge_bound — signed min_price must not exceed the advertised minimum charge, when a
  // floor is advertised.
  if (adv.minChargeOutputTokens > 0 || adv.minChargeMicroUsdc > 0) {
    const floor = minChargeFloor(adv.minChargeOutputTokens, t.output_rate, adv.minChargeMicroUsdc)
    const bound = scaleByMultiple(floor, pol.rateMaxMultiple)
    if (t.min_price > bound) {
      return { check: 'min_charge_bound', field: 'min_price', want: bound, got: t.min_price, detail: 'min_price exceeds the advertised minimum charge' }
    }
  }

  // input_count_bound — input_count must not exceed the caller's own tokenized reserve bound.
  if (reserveInputCount > 0) {
    const bound = scaleByTolerance(reserveInputCount, pol.inputCountTolerance)
    if (t.input_count > bound) {
      return { check: 'input_count_bound', field: 'input_count', want: bound, got: t.input_count, detail: 'input_count exceeds the reserve tokenized bound' }
    }
  }

  return null
}
