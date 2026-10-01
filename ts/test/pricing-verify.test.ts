/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Unit tests for the TS ticket-price verifier, mirroring
// proto/go/pricing/verify_test.go so the two verifiers make the same decisions.

import { describe, it, expect } from 'vitest'

import { type Ticket, UsageType } from '../src/ticket/index.js'
import { type Advertised, defaultPolicy, expectedMaxPrice, verifyTicketPrice } from '../src/pricing/index.js'

const FEE_BPS = 100 // 1%

// validTicket has an internally-consistent max_price (max_price passes) priced at
// $2/$4/1M with a real cache-read discount.
function validTicket(): Ticket {
  return {
    ticket_id: 't',
    operator_id: 1,
    node_id: 1,
    input_count: 1000,
    max_output_count: 500,
    input_rate: 2_000_000,
    output_rate: 4_000_000,
    cache_read_rate: 1_000_000,
    min_price: 1000,
    max_price: 4040, // 4000 + ceil(4000*100/1e4)
    expires_at: 0,
    model: 'm',
    stream: false,
    commit_k: 'k',
    input_usage_type: UsageType.Tokens,
    // None is what the node signs on a real chat ticket (it never sets the usage
    // type); the token checks must run for it, not just for Tokens.
    output_usage_type: UsageType.None,
  }
}

function validAdvertised(): Advertised {
  return {
    inputUsdPer1m: 2.0,
    outputUsdPer1m: 4.0,
    cacheReadRateUsdPer1m: 1.0,
    minChargeOutputTokens: 1000,
    minChargeMicroUsdc: 100,
  }
}

function verify(t: Ticket, adv: Advertised) {
  return verifyTicketPrice(t, adv, FEE_BPS, 1000, 0, defaultPolicy())
}

describe('verifyTicketPrice', () => {
  it('accepts a valid ticket', () => {
    expect(verify(validTicket(), validAdvertised())).toBeNull()
  })

  it('max_price: flags an inflated max_price', () => {
    const t = validTicket()
    t.max_price = 5000
    expect(verify(t, validAdvertised())?.check).toBe('max_price')
  })

  it('rate_bound: flags a rate above advertised', () => {
    const t = validTicket()
    t.input_rate = 5_000_000
    t.max_price = 7070 // keep max_price consistent: 5000+2000=7000; +70
    expect(verify(t, validAdvertised())?.check).toBe('rate_bound')
  })

  it('min_charge_bound: flags a min_price above advertised', () => {
    const t = validTicket()
    t.min_price = 9000
    t.max_price = 9090 // base=max(4000,9000)=9000; +90
    expect(verify(t, validAdvertised())?.check).toBe('min_charge_bound')
  })

  it('input_count_bound: flags input_count above the reserve bound', () => {
    const t = validTicket()
    t.input_count = 2000 // bound floor(1000*1.10)=1100
    t.max_price = 6060 // rateBased=4000+2000=6000; +60
    expect(verify(t, validAdvertised())?.check).toBe('input_count_bound')
  })

  it('cache_read_discount: flags cache_read_rate above input_rate', () => {
    const t = validTicket()
    t.cache_read_rate = 3_000_000
    expect(verify(t, validAdvertised())?.check).toBe('cache_read_discount')
  })

  it('cache_read_bound: flags cache_read_rate above advertised', () => {
    const t = validTicket()
    t.cache_read_rate = 500_000
    const adv = validAdvertised()
    adv.cacheReadRateUsdPer1m = 0.1 // 100000 micro, x2 = 200000 < 500000
    expect(verify(t, adv)?.check).toBe('cache_read_bound')
  })

  it('cache_read_bound: skipped when not advertised', () => {
    const t = validTicket()
    t.cache_read_rate = 1_999_999
    const adv = validAdvertised()
    adv.cacheReadRateUsdPer1m = undefined
    expect(verify(t, adv)).toBeNull()
  })

  it('input_count_bound: skipped when no reserve bound', () => {
    const t = validTicket()
    t.input_count = 9_000_000
    t.max_price = expectedMaxPrice(t.input_count, t.max_output_count, t.input_rate, t.output_rate, t.min_price, 0, FEE_BPS)
    expect(verifyTicketPrice(t, validAdvertised(), FEE_BPS, 0, 0, defaultPolicy())).toBeNull()
  })

  // validTicket is OutputUsageType None (the production chat value); a Tokens
  // ticket must run the same checks so a scope regression can't silently disable
  // verification on real chat tickets.
  it('also verifies a Tokens-typed ticket', () => {
    const t = validTicket()
    t.output_usage_type = UsageType.Tokens
    t.max_price = 5000 // max_price inconsistent
    expect(verify(t, validAdvertised())?.check).toBe('max_price')
  })

  it('skips image tickets', () => {
    const t = validTicket()
    t.output_usage_type = UsageType.Images
    t.max_price = 999_999_999
    expect(verify(t, validAdvertised())).toBeNull()
  })

  it('folds an image-tool budget into max_price', () => {
    const t = validTicket()
    t.max_price = 14140 // base=max(4000+10000,1000)=14000; +140
    expect(verifyTicketPrice(t, validAdvertised(), FEE_BPS, 1000, 10_000, defaultPolicy())).toBeNull()
    // omitting the budget makes the same max_price look inflated => max_price
    expect(verify(t, validAdvertised())?.check).toBe('max_price')
  })

  it('enforces a zero rate for a free model', () => {
    const t = validTicket()
    t.input_rate = 1_000_000
    t.output_rate = 0
    t.max_price = expectedMaxPrice(t.input_count, t.max_output_count, t.input_rate, t.output_rate, t.min_price, 0, FEE_BPS)
    const adv: Advertised = { inputUsdPer1m: 0, outputUsdPer1m: 0, minChargeOutputTokens: 0, minChargeMicroUsdc: 0 }
    expect(verifyTicketPrice(t, adv, FEE_BPS, 1000, 0, defaultPolicy())?.check).toBe('rate_bound')
  })

  it.each([
    ['missing', undefined],
    ['null', null],
    ['NaN', Number.NaN],
    ['infinite', Number.POSITIVE_INFINITY],
  ])('treats a %s required advertised rate as Go zero, not a fail-open skip', (_name, value) => {
    const adv = validAdvertised()
    adv.inputUsdPer1m = value as unknown as number
    const v = verify(validTicket(), adv)
    expect(v?.check).toBe('rate_bound')
    expect(v?.field).toBe('input_rate')
    expect(v?.want).toBe(0)
  })

  it('returns a violation instead of throwing for a missing signed ticket number', () => {
    const t = validTicket()
    t.input_count = undefined as unknown as number

    expect(() => verify(t, validAdvertised())).not.toThrow()
    const v = verify(t, validAdvertised())
    expect(v?.check).toBe('max_price')
    expect(v?.field).toBe('max_price')
    expect(v?.want).toBe(2020)
  })

  // --- long-context surcharge tier (proto 9.3) ---

  // tierAdvertised returns validAdvertised() plus a long-context tier at
  // `threshold` tokens, high input/output/cache rates double the base ($4/$8/$2);
  // the high cache rate ($2) is still strictly below the high input rate ($4).
  function tierAdvertised(threshold: number): Advertised {
    return {
      ...validAdvertised(),
      longContextThresholdTokens: threshold,
      longContextInputUsdPer1m: 4.0,
      longContextOutputUsdPer1m: 8.0,
      longContextCacheReadRateUsdPer1m: 2.0,
    }
  }

  it.each([Number.NaN, Number.POSITIVE_INFINITY])(
    'normalizes a present non-finite optional cache rate (%s) to zero',
    (value) => {
      const adv = validAdvertised()
      adv.cacheReadRateUsdPer1m = value
      const v = verify(validTicket(), adv)
      expect(v?.check).toBe('cache_read_bound')
      expect(v?.field).toBe('cache_read_rate')
      expect(v?.want).toBe(0)
    },
  )

  it.each([
    ['long-context input', 'longContextInputUsdPer1m', 'long_context_input_rate'],
    ['long-context output', 'longContextOutputUsdPer1m', 'long_context_output_rate'],
  ] as const)('normalizes a non-finite %s rate instead of failing open', (_name, field, wantField) => {
    for (const value of [Number.NaN, Number.POSITIVE_INFINITY]) {
      const adv = tierAdvertised(800)
      adv[field] = value
      const v = verify(validTicket(), adv)
      expect(v?.check).toBe('long_context_ordering')
      expect(v?.field).toBe(wantField)
    }
  })

  it.each([Number.NaN, Number.POSITIVE_INFINITY])(
    'normalizes a present non-finite long-context cache rate (%s) to zero',
    (value) => {
      const t = validTicket()
      t.input_rate = 4_000_000
      t.output_rate = 8_000_000
      t.cache_read_rate = 2_000_000
      t.max_price = 8080
      const adv = tierAdvertised(800)
      adv.longContextCacheReadRateUsdPer1m = value
      const v = verify(t, adv)
      expect(v?.check).toBe('cache_read_bound')
      expect(v?.field).toBe('cache_read_rate')
      expect(v?.want).toBe(0)
    },
  )

  it.each([undefined, null])('preserves an absent optional cache rate (%s)', (value) => {
    const adv = validAdvertised()
    adv.cacheReadRateUsdPer1m = value as unknown as undefined
    expect(verify(validTicket(), adv)).toBeNull()
  })

  it('long_context: a tier-2 ticket passes against a tier-advertising operator', () => {
    const t = validTicket()
    t.input_rate = 4_000_000 // high input $4
    t.output_rate = 8_000_000 // high output $8
    t.cache_read_rate = 2_000_000 // high cache $2 (< high input, a real discount)
    t.max_price = 8080 // 4000+4000=8000; +80
    expect(verify(t, tierAdvertised(800))).toBeNull()
  })

  it('long_context: a sub-threshold base ticket passes against a tier operator', () => {
    // input_count 1000 < threshold 2000 => tier 1; the tier is display-only here.
    expect(verify(validTicket(), tierAdvertised(2000))).toBeNull()
  })

  it('long_context: a high rate on a sub-threshold count is bounded against base', () => {
    // The tier is decided by input_count, not by which rates were signed. A >2x
    // high rate makes the base×2 bound bite (an exactly-2x rate would pass it).
    const adv = validAdvertised()
    adv.longContextThresholdTokens = 2000
    adv.longContextInputUsdPer1m = 5.0 // 2.5x base $2, above the base×2 bound
    adv.longContextOutputUsdPer1m = 10.0
    const t = validTicket()
    t.input_count = 1000 // < threshold 2000 => tier 1, base comparand
    t.input_rate = 5_000_000 // high input signed anyway
    t.max_price = 7070 // 5000+2000=7000; +70
    const v = verify(t, adv)
    expect(v?.check).toBe('rate_bound')
    expect(v?.field).toBe('input_rate')
  })

  it('long_context: an ordering violation (high < base) is rejected', () => {
    const adv = validAdvertised()
    adv.longContextThresholdTokens = 2000
    adv.longContextInputUsdPer1m = 1.0 // < base $2 => ordering violation
    adv.longContextOutputUsdPer1m = 8.0
    expect(verify(validTicket(), adv)?.check).toBe('long_context_ordering')
  })
  it('long_context: cache_read_bound uses the HIGH-tier cache rate above the threshold', () => {
    // Base cache $0.5 (bound $1), high cache $1.5 (bound $3), high input $4 — so a
    // signed $2.5 is well above the base bound and passes only because the
    // comparand switched to the high tier.
    const adv = tierAdvertised(800) // input_count 1000 >= 800 => tier 2
    adv.cacheReadRateUsdPer1m = 0.5
    adv.longContextCacheReadRateUsdPer1m = 1.5
    const t = validTicket()
    t.input_rate = 4_000_000
    t.output_rate = 8_000_000
    t.cache_read_rate = 2_500_000
    t.max_price = 8080
    expect(verify(t, adv)).toBeNull()

    // Above the high tier's bound ($3) but still <= the high input rate ($4), so
    // cache_read_bound fires — not cache_read_discount.
    t.cache_read_rate = 3_500_000
    expect(verify(t, adv)?.check).toBe('cache_read_bound')

    // A sub-threshold ticket is judged against the base bound ($1) instead. $1.5
    // is under the base input rate ($2), so cache_read_discount passes and
    // cache_read_bound is what refuses it.
    const subAdv = { ...adv, longContextThresholdTokens: 5000 }
    const t1 = validTicket()
    t1.cache_read_rate = 1_500_000
    expect(verify(t1, subAdv)?.check).toBe('cache_read_bound')
  })

  it('long_context: no advertised high cache rate skips cache_read_bound in the high tier', () => {
    // An operator that advertises a tier but no high-tier cache discount makes no
    // high-tier claim, so cache_read_bound is skipped there — the signed rate is
    // held only by cache_read_discount. The base discount does NOT carry over.
    const adv = tierAdvertised(800)
    adv.longContextCacheReadRateUsdPer1m = undefined
    const t = validTicket()
    t.input_rate = 4_000_000
    t.output_rate = 8_000_000
    t.cache_read_rate = 4_000_000 // == high input: no discount, far above base $1 x2
    t.max_price = 8080
    expect(verify(t, adv)).toBeNull()

    t.cache_read_rate = 5_000_000
    expect(verify(t, adv)?.check).toBe('cache_read_discount')
  })

  it('long_context: a count raised across the threshold beyond the caller bound is rejected', () => {
    // The input_count tolerance (10%) must not be spendable on a whole tier. The
    // caller's bound is 1000, below the 1050 threshold; the node signs 1090 —
    // inside input_count_bound's 1100 ceiling — to cross it and bill the 2x rates.
    // rate_bound alone would wave that through, because an exactly-2x surcharge
    // sits precisely on the base x rateMaxMultiple boundary.
    const adv = tierAdvertised(1050)
    adv.longContextInputUsdPer1m = 4.0 // exactly 2x base $2
    adv.longContextOutputUsdPer1m = 8.0
    const t = validTicket()
    t.input_count = 1090
    t.input_rate = 4_000_000
    t.output_rate = 8_000_000
    t.cache_read_rate = 2_000_000
    t.max_price = 8444 // 4360+4000=8360; +84
    const v = verify(t, adv)
    expect(v?.check).toBe('long_context_tier')
    expect(v?.field).toBe('input_count')

    // The same inflation BELOW the threshold is still fine — input_count_bound
    // governs it, not the tier check.
    const t2 = validTicket()
    t2.input_count = 1090
    t2.max_price = 4222 // 2180+2000=4180; +42
    expect(verify(t2, tierAdvertised(5000))).toBeNull()
  })

  it('long_context: a tier both sides agree on passes', () => {
    // Caller bound 1000 and signed count 1000 are both at/above the threshold.
    const t = validTicket()
    t.input_rate = 4_000_000
    t.output_rate = 8_000_000
    t.cache_read_rate = 2_000_000
    t.max_price = 8080
    expect(verify(t, tierAdvertised(1000))).toBeNull()
  })
})

// Advertised is public package API and a caller may build it straight from a
// JSON details payload, where an absent optional field naturally lands as `null`
// rather than `undefined`. Every optional guard in verify.ts is `!= null` so a
// null decodes as "not advertised" — matching Go's `!= nil` — instead of
// coercing to 0 and manufacturing a violation out of nothing.
describe('verifyTicketPrice: null-vs-undefined on optional advertised fields', () => {
  function nulled(): Advertised {
    return {
      inputUsdPer1m: 2.0,
      outputUsdPer1m: 4.0,
      cacheReadRateUsdPer1m: null as unknown as undefined,
      minChargeOutputTokens: 1000,
      minChargeMicroUsdc: 100,
      longContextThresholdTokens: 800,
      longContextInputUsdPer1m: null as unknown as undefined,
      longContextOutputUsdPer1m: null as unknown as undefined,
      longContextCacheReadRateUsdPer1m: null as unknown as undefined,
    }
  }

  it('treats a null high rate as not advertised, not as $0', () => {
    // Under a `!== undefined` guard this would compare `null < 2.0` (i.e. 0 < 2)
    // and report a bogus long_context_ordering violation.
    expect(verify(validTicket(), nulled())).toBeNull()
  })

  it('treats a null cache-read rate as no discount, not as a $0 bound', () => {
    // A $0 bound would refuse the ticket's non-zero signed cache_read_rate.
    const adv = nulled()
    adv.longContextThresholdTokens = undefined
    expect(verify(validTicket(), adv)).toBeNull()
  })

  it('treats a null threshold as no tier', () => {
    const adv = nulled()
    adv.longContextThresholdTokens = null as unknown as undefined
    expect(verify(validTicket(), adv)).toBeNull()
  })
})
