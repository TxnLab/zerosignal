/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pricing_test

// The verify section of pricing_vectors.json: VerifyTicketPrice's decision for
// each check and each boundary, so the TS verifier is held to Go's answers
// rather than to a hand copy of Go's tests.

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/pricing"
	"github.com/TxnLab/zerosignal/go/ticket"
)

type verifyTicketJSON struct {
	InputCount      uint64           `json:"input_count"`
	MaxOutputCount  uint64           `json:"max_output_count"`
	InputRate       uint64           `json:"input_rate"`
	OutputRate      uint64           `json:"output_rate"`
	CacheReadRate   uint64           `json:"cache_read_rate"`
	MinPrice        uint64           `json:"min_price"`
	MaxPrice        uint64           `json:"max_price"`
	OutputUsageType ticket.UsageType `json:"output_usage_type"`
}

// Optional rates are omitted when nil, which is how an absent advertisement
// reaches both verifiers; a present 0 means free.
type verifyAdvertisedJSON struct {
	InputUsdPer1M                    float64  `json:"input_usd_per_1m"`
	OutputUsdPer1M                   float64  `json:"output_usd_per_1m"`
	CacheReadRateUsdPer1M            *float64 `json:"cache_read_rate_usd_per_1m,omitempty"`
	MinChargeOutputTokens            uint64   `json:"min_charge_output_tokens"`
	MinChargeMicroUSDC               uint64   `json:"min_charge_micro_usdc"`
	LongContextThresholdTokens       uint64   `json:"long_context_threshold_tokens"`
	LongContextInputUsdPer1M         *float64 `json:"long_context_input_usd_per_1m,omitempty"`
	LongContextOutputUsdPer1M        *float64 `json:"long_context_output_usd_per_1m,omitempty"`
	LongContextCacheReadRateUsdPer1M *float64 `json:"long_context_cache_read_rate_usd_per_1m,omitempty"`
}

type verifyPolicyJSON struct {
	RateMaxMultiple     float64 `json:"rate_max_multiple"`
	InputCountTolerance float64 `json:"input_count_tolerance"`
	FailOpen            bool    `json:"fail_open"`
}

// Detail is prose and is not compared.
type verifyViolationJSON struct {
	Check string `json:"check"`
	Field string `json:"field"`
	Want  uint64 `json:"want"`
	Got   uint64 `json:"got"`
}

type verifyVector struct {
	Name              string               `json:"name"`
	Ticket            verifyTicketJSON     `json:"ticket"`
	Advertised        verifyAdvertisedJSON `json:"advertised"`
	FeeBps            uint64               `json:"fee_bps"`
	ReserveInputCount uint64               `json:"reserve_input_count"`
	ImageToolBudget   uint64               `json:"image_tool_budget"`
	Policy            verifyPolicyJSON     `json:"policy"`
	// Expected is null when the ticket passes.
	Expected *verifyViolationJSON `json:"expected"`
}

type verifyCase struct {
	name    string
	t       ticket.Ticket
	adv     pricing.Advertised
	fee     uint64
	reserve uint64
	budget  uint64
	pol     pricing.Policy
	// consistent recomputes max_price from the case's own numbers, so only the
	// check under test can refuse it.
	consistent bool
}

func buildVerifyVectors(t *testing.T) []verifyVector {
	f := func(v float64) *float64 { return &v }
	// $2/$4/1M with a real cache-read discount and a min charge; max_price 4040.
	base := func(name string) verifyCase {
		return verifyCase{
			name: name,
			t: ticket.Ticket{
				InputCount: 1000, MaxOutputCount: 500,
				InputRate: 2_000_000, OutputRate: 4_000_000, CacheReadRate: 1_000_000,
				MinPrice: 1000, MaxPrice: 4040, OutputUsageType: ticket.UsageTypeNone,
			},
			adv: pricing.Advertised{
				InputUsdPer1M: 2, OutputUsdPer1M: 4, CacheReadRateUsdPer1M: f(1),
				MinChargeOutputTokens: 1000, MinChargeMicroUSDC: 100,
			},
			fee: 100, reserve: 1000, pol: pricing.DefaultPolicy(),
		}
	}
	// High tier at 2.5x the base, $5/$10 with cache $2: past the base's 2x bound,
	// so a ticket signing these passes only if the comparand lifts to the tier.
	tiered := func(name string, threshold uint64) verifyCase {
		c := base(name)
		c.adv.LongContextThresholdTokens = threshold
		c.adv.LongContextInputUsdPer1M = f(5)
		c.adv.LongContextOutputUsdPer1M = f(10)
		c.adv.LongContextCacheReadRateUsdPer1M = f(2)
		return c
	}
	highRates := func(c *verifyCase) {
		c.t.InputRate, c.t.OutputRate, c.t.CacheReadRate = 5_000_000, 10_000_000, 2_000_000
		c.consistent = true
	}
	with := func(c verifyCase, mut func(*verifyCase)) verifyCase { mut(&c); return c }

	cases := []verifyCase{
		base("valid"),
		with(base("tokens_usage_type_verified"), func(c *verifyCase) {
			c.t.OutputUsageType = ticket.UsageTypeTokens
			c.t.MaxPrice = 5000
		}),
		with(base("image_ticket_skipped"), func(c *verifyCase) {
			c.t.OutputUsageType = ticket.UsageTypeImages
			c.t.MaxPrice = 1
			c.t.InputRate = 99_000_000
		}),

		// max_price
		with(base("max_price_inflated"), func(c *verifyCase) { c.t.MaxPrice = 5000 }),
		with(base("max_price_one_under"), func(c *verifyCase) { c.t.MaxPrice = 4039 }),
		with(base("max_price_with_image_tool_budget"), func(c *verifyCase) { c.budget = 10_000; c.consistent = true }),
		with(base("max_price_missing_image_tool_budget"), func(c *verifyCase) { c.budget = 10_000 }),
		with(base("max_price_fee_ceil"), func(c *verifyCase) { c.fee = 250; c.t.InputCount = 1001; c.consistent = true }),
		// 2^50 tokens at 2^50 µUSDC/1M: the recompute overflows uint64, and every
		// input stays inside a JS number's exact range.
		with(base("max_price_overflow_fail_open"), func(c *verifyCase) {
			c.t.InputCount, c.t.InputRate, c.t.CacheReadRate = 1<<50, 1<<50, 0
			c.adv.InputUsdPer1M, c.adv.CacheReadRateUsdPer1M = 1<<40, nil
			c.reserve = 0
		}),
		with(base("max_price_overflow_fail_closed"), func(c *verifyCase) {
			c.t.InputCount, c.t.InputRate, c.t.CacheReadRate = 1<<50, 1<<50, 0
			c.adv.InputUsdPer1M, c.adv.CacheReadRateUsdPer1M = 1<<40, nil
			c.reserve = 0
			c.pol.FailOpen = false
		}),
		// Each overflow guard at its edge, with safe integers. Fail-closed, so the
		// verdict is max_price's and no later check masks it.
		with(base("product_exactly_u64_max"), func(c *verifyCase) { // (2^32-1)(2^32+1) = 2^64-1
			c.t.InputCount, c.t.InputRate, c.t.CacheReadRate = 4294967295, 4294967297, 0
			c.pol.FailOpen = false
		}),
		with(base("input_product_overflow"), func(c *verifyCase) {
			c.t.InputCount, c.t.InputRate, c.t.CacheReadRate = 1<<32, 1<<32, 0
			c.pol.FailOpen = false
		}),
		with(base("output_product_overflow"), func(c *verifyCase) {
			c.t.MaxOutputCount, c.t.OutputRate = 1<<32, 1<<32
			c.pol.FailOpen = false
		}),
		with(base("fee_product_overflow"), func(c *verifyCase) {
			c.t.MinPrice = 1<<53 - 1
			c.fee = 10_000
			c.pol.FailOpen = false
		}),
		// The recompute lands past 2^53 without overflowing uint64: TS must still
		// compare exactly, not as a float.
		with(base("max_price_past_2_53"), func(c *verifyCase) { c.t.MinPrice = 1<<53 - 1 }),

		// rate_bound
		with(base("input_rate_above_2x"), func(c *verifyCase) { c.t.InputRate = 5_000_000; c.consistent = true }),
		with(base("input_rate_at_2x"), func(c *verifyCase) { c.t.InputRate = 4_000_000; c.consistent = true }),
		with(base("input_rate_one_over_2x"), func(c *verifyCase) { c.t.InputRate = 4_000_001; c.consistent = true }),
		with(base("output_rate_above_2x"), func(c *verifyCase) { c.t.OutputRate = 8_000_001; c.consistent = true }),
		with(base("strict_policy_one_over"), func(c *verifyCase) {
			c.pol.RateMaxMultiple = 1
			c.t.InputRate = 2_000_001
			c.consistent = true
		}),
		with(base("fractional_multiple_ceils"), func(c *verifyCase) {
			c.pol.RateMaxMultiple = 1.5
			c.adv.InputUsdPer1M = 0.000001 // 1 µUSDC/1M, ×1.5 → ceil 2
			c.adv.CacheReadRateUsdPer1M = nil
			c.t.InputRate, c.t.CacheReadRate = 2, 0
			c.consistent = true
		}),
		with(base("negative_advertised_rate_fail_open"), func(c *verifyCase) { c.adv.InputUsdPer1M = -1 }),
		with(base("negative_advertised_rate_fail_closed"), func(c *verifyCase) {
			c.adv.InputUsdPer1M = -1
			c.pol.FailOpen = false
		}),
		with(base("free_model_zero_rates"), func(c *verifyCase) {
			c.adv = pricing.Advertised{}
			c.t.InputRate, c.t.OutputRate, c.t.CacheReadRate, c.t.MinPrice = 0, 0, 0, 0
			c.consistent = true
		}),
		with(base("free_model_nonzero_rate"), func(c *verifyCase) {
			c.adv = pricing.Advertised{}
			c.t.InputRate, c.t.OutputRate, c.t.CacheReadRate, c.t.MinPrice = 1, 0, 0, 0
			c.consistent = true
		}),

		// min_charge_bound
		with(base("min_price_above_2x_floor"), func(c *verifyCase) { c.t.MinPrice = 9000; c.consistent = true }),
		with(base("min_price_at_2x_floor"), func(c *verifyCase) { c.t.MinPrice = 8000; c.consistent = true }),
		with(base("min_price_micro_dominant"), func(c *verifyCase) {
			c.adv.MinChargeOutputTokens, c.adv.MinChargeMicroUSDC = 100, 5000
			c.t.MinPrice = 10_001
			c.consistent = true
		}),
		with(base("min_price_unbounded_without_floor"), func(c *verifyCase) {
			c.adv.MinChargeOutputTokens, c.adv.MinChargeMicroUSDC = 0, 0
			c.t.MinPrice = 1_000_000
			c.consistent = true
		}),

		// input_count_bound
		with(base("input_count_above_tolerance"), func(c *verifyCase) { c.t.InputCount = 2000; c.consistent = true }),
		with(base("input_count_at_tolerance"), func(c *verifyCase) { c.t.InputCount = 1100; c.consistent = true }),
		with(base("input_count_one_over_tolerance"), func(c *verifyCase) { c.t.InputCount = 1101; c.consistent = true }),
		with(base("input_count_floored_node"), func(c *verifyCase) { c.reserve = 69; c.t.InputCount = 256; c.consistent = true }),
		with(base("input_count_floor_rounds_down"), func(c *verifyCase) { c.reserve = 15; c.t.InputCount = 17; c.consistent = true }),
		with(base("input_count_zero_tolerance"), func(c *verifyCase) {
			c.pol.InputCountTolerance = 0
			c.t.InputCount = 1001
			c.consistent = true
		}),
		with(base("input_count_skipped_without_reserve"), func(c *verifyCase) {
			c.reserve = 0
			c.t.InputCount = 9_000_000
			c.consistent = true
		}),

		// cache_read_discount / cache_read_bound
		with(base("cache_read_above_input_rate"), func(c *verifyCase) { c.t.CacheReadRate = 3_000_000 }),
		with(base("cache_read_equals_input_rate"), func(c *verifyCase) {
			c.adv.CacheReadRateUsdPer1M = nil
			c.t.CacheReadRate = 2_000_000
		}),
		with(base("cache_read_above_advertised"), func(c *verifyCase) {
			c.adv.CacheReadRateUsdPer1M = f(0.1)
			c.t.CacheReadRate = 500_000
		}),
		with(base("cache_read_unbounded_without_advert"), func(c *verifyCase) {
			c.adv.CacheReadRateUsdPer1M = nil
			c.t.CacheReadRate = 1_999_999
		}),
		with(base("cache_read_free_advert_enforces_zero"), func(c *verifyCase) {
			c.adv.CacheReadRateUsdPer1M = f(0)
			c.t.CacheReadRate = 1
		}),

		// long-context tier
		with(tiered("tier2_high_rates", 800), highRates),
		tiered("tier1_against_tier_operator", 2000),
		with(tiered("tier_at_threshold_agrees", 1000), highRates),
		// One under the threshold the high rates are judged against the base.
		with(tiered("tier_one_below_threshold_bounded_by_base", 1001), highRates),
		with(base("high_rate_below_threshold_bounded_by_base"), func(c *verifyCase) {
			c.adv.LongContextThresholdTokens = 2000
			c.adv.LongContextInputUsdPer1M, c.adv.LongContextOutputUsdPer1M = f(5), f(10)
			c.t.InputRate = 5_000_000
			c.consistent = true
		}),
		with(base("ordering_input_discount"), func(c *verifyCase) {
			c.adv.LongContextThresholdTokens = 2000
			c.adv.LongContextInputUsdPer1M, c.adv.LongContextOutputUsdPer1M = f(1), f(8)
		}),
		with(base("ordering_output_discount"), func(c *verifyCase) {
			c.adv.LongContextThresholdTokens = 2000
			c.adv.LongContextInputUsdPer1M, c.adv.LongContextOutputUsdPer1M = f(4), f(3)
		}),
		with(tiered("tier_cache_bound_within_high", 800), func(c *verifyCase) {
			c.adv.CacheReadRateUsdPer1M, c.adv.LongContextCacheReadRateUsdPer1M = f(0.5), f(1.5)
			highRates(c)
			c.t.CacheReadRate = 2_500_000
		}),
		with(tiered("tier_cache_bound_above_high", 800), func(c *verifyCase) {
			c.adv.CacheReadRateUsdPer1M, c.adv.LongContextCacheReadRateUsdPer1M = f(0.5), f(1.5)
			highRates(c)
			c.t.CacheReadRate = 3_500_000
		}),
		with(tiered("tier_no_high_cache_skips_bound", 800), func(c *verifyCase) {
			c.adv.LongContextCacheReadRateUsdPer1M = nil
			highRates(c)
			c.t.CacheReadRate = 5_000_000 // == the high input rate: no discount at all
		}),
		with(tiered("tier_missing_high_input_falls_back_to_base", 800), func(c *verifyCase) {
			c.adv.LongContextInputUsdPer1M = nil
			highRates(c)
			c.t.InputRate = 4_000_001
		}),
		with(tiered("tier_raised_above_caller", 1050), func(c *verifyCase) {
			highRates(c)
			c.t.InputCount = 1090
		}),
		with(tiered("tier_raised_by_one_token", 1001), func(c *verifyCase) {
			highRates(c)
			c.t.InputCount = 1001
		}),
		with(tiered("tier_check_skipped_without_reserve", 1050), func(c *verifyCase) {
			highRates(c)
			c.t.InputCount = 1090
			c.reserve = 0
		}),
		with(base("inflation_below_threshold_passes"), func(c *verifyCase) {
			c.adv.LongContextThresholdTokens = 5000
			c.adv.LongContextInputUsdPer1M, c.adv.LongContextOutputUsdPer1M = f(4), f(8)
			c.t.InputCount = 1090
			c.consistent = true
		}),
	}

	out := make([]verifyVector, 0, len(cases))
	for _, c := range cases {
		if c.consistent {
			mp, err := pricing.ExpectedMaxPrice(c.t.InputCount, c.t.MaxOutputCount, c.t.InputRate, c.t.OutputRate, c.t.MinPrice, c.budget, c.fee)
			c.t.MaxPrice = mustU64(t, c.name, mp, err)
		}
		v := verifyVector{
			Name: c.name,
			Ticket: verifyTicketJSON{
				InputCount: c.t.InputCount, MaxOutputCount: c.t.MaxOutputCount,
				InputRate: c.t.InputRate, OutputRate: c.t.OutputRate, CacheReadRate: c.t.CacheReadRate,
				MinPrice: c.t.MinPrice, MaxPrice: c.t.MaxPrice, OutputUsageType: c.t.OutputUsageType,
			},
			Advertised: verifyAdvertisedJSON{
				InputUsdPer1M: c.adv.InputUsdPer1M, OutputUsdPer1M: c.adv.OutputUsdPer1M,
				CacheReadRateUsdPer1M: c.adv.CacheReadRateUsdPer1M,
				MinChargeOutputTokens: c.adv.MinChargeOutputTokens, MinChargeMicroUSDC: c.adv.MinChargeMicroUSDC,
				LongContextThresholdTokens:       c.adv.LongContextThresholdTokens,
				LongContextInputUsdPer1M:         c.adv.LongContextInputUsdPer1M,
				LongContextOutputUsdPer1M:        c.adv.LongContextOutputUsdPer1M,
				LongContextCacheReadRateUsdPer1M: c.adv.LongContextCacheReadRateUsdPer1M,
			},
			FeeBps: c.fee, ReserveInputCount: c.reserve, ImageToolBudget: c.budget,
			Policy: verifyPolicyJSON{
				RateMaxMultiple: c.pol.RateMaxMultiple, InputCountTolerance: c.pol.InputCountTolerance, FailOpen: c.pol.FailOpen,
			},
		}
		if viol := pricing.VerifyTicketPrice(c.t, c.adv, c.fee, c.reserve, c.budget, c.pol); viol != nil {
			v.Expected = &verifyViolationJSON{Check: viol.Check, Field: viol.Field, Want: viol.Want, Got: viol.Got}
		}
		out = append(out, v)
	}
	return out
}
