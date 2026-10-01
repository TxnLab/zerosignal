/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl byte-parity test for the shared token-pricing math. Loads
// proto/testdata/pricing_vectors.json (generated from the Go pricer via
// `cd proto/go && go test ./pricing -run TestVectors -update`) and asserts the
// TS mirror produces the identical value for every case. If this drifts, the
// node's pricer and the payer-side verifier disagree across languages.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
  usdRateToMicroUSDCPer1M,
  ceilInputCost,
  chargeFor,
  reserveMinPrice,
  minChargeFloor,
  expectedMaxPrice,
  toolFeeReserveMicroUSDC,
  isLongContext,
} from '../src/pricing/index.js'

interface UsdRateCase {
  name: string
  usd_per_1m: number
  expected: number
}
interface InputCostCase {
  name: string
  non_cached: number
  input_rate: number
  cached: number
  cache_read_rate: number
  expected: number
}
interface ChargeCase {
  name: string
  actual_input: number
  cached_input: number
  actual_output: number
  input_rate: number
  cache_read_rate: number
  output_rate: number
  min_price: number
  base_max: number
  expected: number
}
interface ReserveMinPriceCase {
  name: string
  min_output_tokens: number
  output_rate: number
  algo_txns: number
  algo_usd: number
  paid: boolean
  expected: number
}
interface MinChargeFloorCase {
  name: string
  min_charge_output_tokens: number
  output_rate: number
  min_charge_micro_usdc: number
  expected: number
}
interface MaxPriceCase {
  name: string
  input_count: number
  max_output_count: number
  input_rate: number
  output_rate: number
  min_price: number
  extra_base: number
  fee_bps: number
  expected: number
}
interface ToolFeeReserveCase {
  name: string
  max_tool_iterations: number
  max_zs_rate: number
  call_cap: number
  max_vendor_rate: number
  tokens_per_call: number
  input_rate: number
  expected: number
}
interface LongContextCase {
  name: string
  input_count: number
  threshold: number
  expected: boolean
}
interface PricingVectorsFile {
  version: number
  comment: string
  usd_rate: UsdRateCase[]
  input_cost: InputCostCase[]
  charge: ChargeCase[]
  reserve_min_price: ReserveMinPriceCase[]
  min_charge_floor: MinChargeFloorCase[]
  max_price: MaxPriceCase[]
  tool_fee_reserve: ToolFeeReserveCase[]
  long_context: LongContextCase[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'pricing_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as PricingVectorsFile

describe('pricing vectors', () => {
  for (const c of vectors.usd_rate) {
    it(`usdRateToMicroUSDCPer1M: ${c.name}`, () => {
      expect(usdRateToMicroUSDCPer1M(c.usd_per_1m)).toBe(c.expected)
    })
  }
  for (const c of vectors.input_cost) {
    it(`ceilInputCost: ${c.name}`, () => {
      expect(ceilInputCost(c.non_cached, c.input_rate, c.cached, c.cache_read_rate)).toBe(c.expected)
    })
  }
  for (const c of vectors.charge) {
    it(`chargeFor: ${c.name}`, () => {
      expect(
        chargeFor(c.actual_input, c.cached_input, c.actual_output, c.input_rate, c.cache_read_rate, c.output_rate, c.min_price, c.base_max),
      ).toBe(c.expected)
    })
  }
  for (const c of vectors.reserve_min_price) {
    it(`reserveMinPrice: ${c.name}`, () => {
      expect(reserveMinPrice(c.min_output_tokens, c.output_rate, c.algo_txns, c.algo_usd, c.paid)).toBe(c.expected)
    })
  }
  for (const c of vectors.min_charge_floor) {
    it(`minChargeFloor: ${c.name}`, () => {
      expect(minChargeFloor(c.min_charge_output_tokens, c.output_rate, c.min_charge_micro_usdc)).toBe(c.expected)
    })
  }
  for (const c of vectors.max_price) {
    it(`expectedMaxPrice: ${c.name}`, () => {
      expect(expectedMaxPrice(c.input_count, c.max_output_count, c.input_rate, c.output_rate, c.min_price, c.extra_base, c.fee_bps)).toBe(
        c.expected,
      )
    })
  }
  for (const c of vectors.tool_fee_reserve) {
    it(`toolFeeReserveMicroUSDC: ${c.name}`, () => {
      expect(
        toolFeeReserveMicroUSDC(c.max_tool_iterations, c.max_zs_rate, c.call_cap, c.max_vendor_rate, c.tokens_per_call, c.input_rate),
      ).toBe(c.expected)
    })
  }
  for (const c of vectors.long_context) {
    it(`isLongContext: ${c.name}`, () => {
      expect(isLongContext(c.input_count, c.threshold)).toBe(c.expected)
    })
  }
})
