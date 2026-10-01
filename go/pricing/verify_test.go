/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pricing_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/pricing"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// ptr is a tiny helper for the *float64 advertised cache-read rate.
func ptr(f float64) *float64 { return &f }

const testFeeBps = 100 // 1%

// validTicket returns a token ticket whose max_price is internally consistent
// (max_price passes) at testFeeBps, priced at $2/$4/1M with a genuine cache-read
// discount. Callers mutate a field to exercise one check at a time.
func validTicket() ticket.Ticket {
	// ExpectedMaxPrice(1000,500,2e6,4e6,minPrice=1000,extra=0,fee=100):
	//   rateBased = ceil(1000*2e6/1e6)+ceil(500*4e6/1e6) = 2000+2000 = 4000
	//   base      = max(4000,1000) = 4000
	//   max_price = 4000 + ceil(4000*100/1e4) = 4000+40 = 4040
	return ticket.Ticket{
		InputCount:     1000,
		MaxOutputCount: 500,
		InputRate:      2_000_000,
		OutputRate:     4_000_000,
		CacheReadRate:  1_000_000, // < input_rate: a real discount
		MinPrice:       1000,
		MaxPrice:       4040,
		// None is what the node signs on a real chat ticket (it never sets the
		// usage type); the token checks must run for it, not just for Tokens.
		OutputUsageType: ticket.UsageTypeNone,
	}
}

func validAdvertised() pricing.Advertised {
	return pricing.Advertised{
		InputUsdPer1M:         2.0,
		OutputUsdPer1M:        4.0,
		CacheReadRateUsdPer1M: ptr(1.0),
		MinChargeOutputTokens: 1000,
		MinChargeMicroUSDC:    100,
	}
}

// verify runs VerifyTicketPrice with the default policy and a reserve bound of
// 1000 (matches the valid ticket's input_count) and no image-tool budget.
func verify(t ticket.Ticket, adv pricing.Advertised) *pricing.Violation {
	return pricing.VerifyTicketPrice(t, adv, testFeeBps, 1000, 0, pricing.DefaultPolicy())
}

func TestVerify_Valid(t *testing.T) {
	if v := verify(validTicket(), validAdvertised()); v != nil {
		t.Fatalf("expected valid ticket to pass, got %v", v)
	}
}

func TestVerify_MaxPrice_Inflated(t *testing.T) {
	tk := validTicket()
	tk.MaxPrice = 5000 // inconsistent with rates x counts x fee
	v := verify(tk, validAdvertised())
	if v == nil || v.Check != "max_price" {
		t.Fatalf("expected max_price violation, got %v", v)
	}
}

func TestVerify_RateBound_AboveAdvertised(t *testing.T) {
	tk := validTicket()
	// Inflate input_rate AND keep max_price internally consistent so max_price passes
	// and rate_bound is the one that trips.
	tk.InputRate = 5_000_000
	// ExpectedMaxPrice(1000,500,5e6,4e6,1000,0,100) = 5000+2000=7000; +70 = 7070
	tk.MaxPrice = 7070
	v := verify(tk, validAdvertised()) // advertised input $2 => 2e6, x2 = 4e6 < 5e6
	if v == nil || v.Check != "rate_bound" {
		t.Fatalf("expected rate_bound violation, got %v", v)
	}
}

func TestVerify_MinChargeBound_AboveAdvertised(t *testing.T) {
	tk := validTicket()
	// Advertised floor = max(ceil(1000*4e6/1e6),100)=4000; x2 = 8000.
	tk.MinPrice = 9000
	// Keep max_price consistent: base=max(4000,9000)=9000; +90 = 9090.
	tk.MaxPrice = 9090
	v := verify(tk, validAdvertised())
	if v == nil || v.Check != "min_charge_bound" {
		t.Fatalf("expected min_charge_bound violation, got %v", v)
	}
}

func TestVerify_InputCountBound_AboveReserveBound(t *testing.T) {
	tk := validTicket()
	tk.InputCount = 2000 // reserve bound 1000, x1.10 = 1100
	// Keep max_price consistent: rateBased=ceil(2000*2e6/1e6)+2000=4000+2000=6000; +60=6060.
	tk.MaxPrice = 6060
	v := verify(tk, validAdvertised())
	if v == nil || v.Check != "input_count_bound" {
		t.Fatalf("expected input_count_bound violation, got %v", v)
	}
}

func TestVerify_CacheReadDiscount_AboveInputRate(t *testing.T) {
	tk := validTicket()
	tk.CacheReadRate = 3_000_000 // > input_rate 2e6; cache_read_discount trips before max_price
	v := verify(tk, validAdvertised())
	if v == nil || v.Check != "cache_read_discount" {
		t.Fatalf("expected cache_read_discount violation, got %v", v)
	}
}

func TestVerify_CacheReadBound_AboveAdvertised(t *testing.T) {
	tk := validTicket()
	tk.CacheReadRate = 500_000 // <= input_rate 2e6 (cache_read_discount ok), max_price unaffected (max_price ok)
	adv := validAdvertised()
	adv.CacheReadRateUsdPer1M = ptr(0.1) // => 100000 micro, x2 = 200000 < 500000
	v := verify(tk, adv)
	if v == nil || v.Check != "cache_read_bound" {
		t.Fatalf("expected cache_read_bound violation, got %v", v)
	}
}

func TestVerify_CacheReadBound_SkippedWhenNotAdvertised(t *testing.T) {
	tk := validTicket()
	tk.CacheReadRate = 1_999_999 // large discount-denial, but <= input_rate
	adv := validAdvertised()
	adv.CacheReadRateUsdPer1M = nil // no advertised cache discount => cache_read_bound skipped
	if v := verify(tk, adv); v != nil {
		t.Fatalf("expected pass when cache rate not advertised, got %v", v)
	}
}

func TestVerify_InputCountBound_SkippedWhenNoReserveBound(t *testing.T) {
	tk := validTicket()
	tk.InputCount = 9_000_000
	// Keep max_price consistent with the huge input_count.
	mp, err := pricing.ExpectedMaxPrice(tk.InputCount, tk.MaxOutputCount, tk.InputRate, tk.OutputRate, tk.MinPrice, 0, testFeeBps)
	if err != nil {
		t.Fatalf("recompute max_price: %v", err)
	}
	tk.MaxPrice = mp
	// reserveInputCount = 0 => input_count_bound skipped.
	if v := pricing.VerifyTicketPrice(tk, validAdvertised(), testFeeBps, 0, 0, pricing.DefaultPolicy()); v != nil {
		t.Fatalf("expected pass when no reserve bound provided, got %v", v)
	}
}

// Production chat tickets are OutputUsageType None (validTicket); an explicit
// Tokens ticket must run the same checks, so a scope regression to "Tokens only"
// (which would silently stop verifying real chat tickets) breaks here while a
// regression to "None only" breaks the None-based suite above.
func TestVerify_TokensUsageTypeAlsoVerified(t *testing.T) {
	tk := validTicket()
	tk.OutputUsageType = ticket.UsageTypeTokens
	tk.MaxPrice = 5000 // max_price inconsistent
	if v := verify(tk, validAdvertised()); v == nil || v.Check != "max_price" {
		t.Fatalf("expected max_price violation for Tokens-typed ticket, got %v", v)
	}
}

func TestVerify_ImageTicketSkipped(t *testing.T) {
	tk := validTicket()
	tk.OutputUsageType = ticket.UsageTypeImages
	tk.MaxPrice = 999_999_999 // wildly inconsistent; still skipped
	if v := verify(tk, validAdvertised()); v != nil {
		t.Fatalf("expected image ticket to be skipped, got %v", v)
	}
}

func TestVerify_ImageToolBudgetFoldedIntoMaxPrice(t *testing.T) {
	tk := validTicket()
	const budget = 10_000
	// base = max(4000+10000,1000)=14000; +140 = 14140.
	tk.MaxPrice = 14140
	if v := pricing.VerifyTicketPrice(tk, validAdvertised(), testFeeBps, 1000, budget, pricing.DefaultPolicy()); v != nil {
		t.Fatalf("expected pass with image-tool budget folded into max_price, got %v", v)
	}
	// Without passing the budget, the same ticket's max_price looks inflated => max_price.
	if v := verify(tk, validAdvertised()); v == nil || v.Check != "max_price" {
		t.Fatalf("expected max_price violation when budget omitted, got %v", v)
	}
}

func TestVerify_FreeModelEnforcesZeroRate(t *testing.T) {
	// Advertised free (input $0) but the ticket signs a non-zero input rate.
	tk := ticket.Ticket{
		InputCount: 1000, MaxOutputCount: 500,
		InputRate: 1_000_000, OutputRate: 0, CacheReadRate: 1_000_000,
		MinPrice: 0, OutputUsageType: ticket.UsageTypeTokens,
	}
	mp, err := pricing.ExpectedMaxPrice(tk.InputCount, tk.MaxOutputCount, tk.InputRate, tk.OutputRate, tk.MinPrice, 0, testFeeBps)
	if err != nil {
		t.Fatalf("recompute max_price: %v", err)
	}
	tk.MaxPrice = mp // max_price consistent
	adv := pricing.Advertised{InputUsdPer1M: 0, OutputUsdPer1M: 0}
	v := pricing.VerifyTicketPrice(tk, adv, testFeeBps, 1000, 0, pricing.DefaultPolicy())
	if v == nil || v.Check != "rate_bound" {
		t.Fatalf("expected rate_bound violation (free advertised, non-zero signed), got %v", v)
	}
}

// --- long-context surcharge tier (proto 9.3) ---

// tierAdvertised returns validAdvertised() plus a long-context tier at `threshold`
// tokens, with high input/output/cache rates double the base ($4 / $8 / $2). The
// high cache rate ($2) is still strictly below the high input rate ($4), a real
// high-tier discount.
func tierAdvertised(threshold uint64) pricing.Advertised {
	adv := validAdvertised()
	adv.LongContextThresholdTokens = threshold
	adv.LongContextInputUsdPer1M = ptr(4.0)
	adv.LongContextOutputUsdPer1M = ptr(8.0)
	adv.LongContextCacheReadRateUsdPer1M = ptr(2.0)
	return adv
}

func TestVerify_LongContext_Tier2Passes(t *testing.T) {
	// input_count 1000 >= threshold 800 => tier 2; the ticket signs the high rates
	// and must be bounded against the HIGH advertised comparands, so it passes.
	tk := validTicket()
	tk.InputRate = 4_000_000     // high input $4
	tk.OutputRate = 8_000_000    // high output $8
	tk.CacheReadRate = 2_000_000 // high cache $2 (< high input, a real discount)
	// ExpectedMaxPrice(1000,500,4e6,8e6,minPrice=1000,extra=0,fee=100):
	//   rateBased = ceil(1000*4e6/1e6)+ceil(500*8e6/1e6) = 4000+4000 = 8000
	//   max_price = 8000 + ceil(8000*100/1e4) = 8000+80 = 8080
	tk.MaxPrice = 8080
	if v := verify(tk, tierAdvertised(800)); v != nil {
		t.Fatalf("expected tier-2 ticket to pass against a tier-advertising operator, got %v", v)
	}
}

func TestVerify_LongContext_Tier1PassesAgainstTierOperator(t *testing.T) {
	// input_count 1000 < threshold 2000 => tier 1; the plain base ticket must still
	// pass against a tier-advertising operator (the tier is display-only here).
	if v := verify(validTicket(), tierAdvertised(2000)); v != nil {
		t.Fatalf("expected sub-threshold base ticket to pass, got %v", v)
	}
}

func TestVerify_LongContext_HighRateSubThresholdBoundedAgainstBase(t *testing.T) {
	// A node that signs the HIGH input rate onto a SUB-threshold input_count must be
	// bounded against the BASE advertised rate — the tier is decided by input_count,
	// not by which rates were signed. A >2x high rate makes the base×2 bound bite
	// (an exactly-2x rate would pass it by the rollover coincidence).
	adv := validAdvertised()
	adv.LongContextThresholdTokens = 2000
	adv.LongContextInputUsdPer1M = ptr(5.0) // 2.5x base $2, above the base×2 bound
	adv.LongContextOutputUsdPer1M = ptr(10.0)
	tk := validTicket()
	tk.InputCount = 1000     // < threshold 2000 => tier 1, base comparand
	tk.InputRate = 5_000_000 // high input signed anyway
	// ExpectedMaxPrice(1000,500,5e6,4e6,1000,0,100) = 5000+2000=7000; +70 = 7070.
	tk.MaxPrice = 7070
	v := verify(tk, adv)
	if v == nil || v.Check != "rate_bound" || v.Field != "input_rate" {
		t.Fatalf("expected rate_bound (input_rate) violation for a high rate on a sub-threshold count, got %v", v)
	}
}

func TestVerify_LongContext_OrderingViolation(t *testing.T) {
	// Advertised high input rate BELOW the base => the tier is a discount, not a
	// surcharge; long_context_ordering must reject whenever a tier is advertised,
	// regardless of this ticket's tier (input_count 1000 < threshold 2000).
	adv := validAdvertised()
	adv.LongContextThresholdTokens = 2000
	adv.LongContextInputUsdPer1M = ptr(1.0) // < base $2 => ordering violation
	adv.LongContextOutputUsdPer1M = ptr(8.0)
	v := verify(validTicket(), adv)
	if v == nil || v.Check != "long_context_ordering" {
		t.Fatalf("expected long_context_ordering violation, got %v", v)
	}
}

func TestVerify_LongContext_TierCacheReadBound(t *testing.T) {
	// In the high tier the comparand for cache_read_bound is the HIGH-tier
	// cache-read rate, not the base one. Base cache $0.5 (bound $1), high cache
	// $1.5 (bound $3), high input $4 — so a signed $2.5 is well ABOVE the base
	// bound and passes only because the comparand switched to the high tier.
	adv := tierAdvertised(800) // input_count 1000 >= 800 => tier 2
	adv.CacheReadRateUsdPer1M = ptr(0.5)
	adv.LongContextCacheReadRateUsdPer1M = ptr(1.5)
	tk := validTicket()
	tk.InputRate = 4_000_000
	tk.OutputRate = 8_000_000
	tk.CacheReadRate = 2_500_000
	tk.MaxPrice = 8080
	if v := verify(tk, adv); v != nil {
		t.Fatalf("expected a cache-read rate within the HIGH tier's bound to pass, got %v", v)
	}
	// Above the high tier's bound ($3), but still <= the high input rate ($4), so
	// cache_read_bound is what fires — not cache_read_discount.
	tk.CacheReadRate = 3_500_000
	v := verify(tk, adv)
	if v == nil || v.Check != "cache_read_bound" {
		t.Fatalf("expected cache_read_bound against the HIGH tier's rate, got %v", v)
	}
	// A SUB-threshold ticket is judged against the base bound ($1) instead. $1.5 is
	// under the base input rate ($2), so cache_read_discount passes and
	// cache_read_bound is what refuses it.
	subAdv := adv
	subAdv.LongContextThresholdTokens = 5000 // input_count 1000 < 5000 => tier 1
	tk1 := validTicket()
	tk1.CacheReadRate = 1_500_000
	v = verify(tk1, subAdv)
	if v == nil || v.Check != "cache_read_bound" {
		t.Fatalf("expected the BASE cache bound below the threshold, got %v", v)
	}
}

func TestVerify_LongContext_NoHighCacheRateSkipsBound(t *testing.T) {
	// An operator that advertises a tier but NO high-tier cache-read discount
	// (nil) makes no high-tier claim, so cache_read_bound is skipped there — the
	// signed rate is then held only by cache_read_discount (<= the high input
	// rate). The base discount deliberately does NOT carry into the high tier.
	adv := tierAdvertised(800)
	adv.LongContextCacheReadRateUsdPer1M = nil
	tk := validTicket()
	tk.InputRate = 4_000_000
	tk.OutputRate = 8_000_000
	tk.CacheReadRate = 4_000_000 // == high input: no discount, far above base $1 x2
	tk.MaxPrice = 8080
	if v := verify(tk, adv); v != nil {
		t.Fatalf("expected an undiscounted high-tier cache rate to pass when no high rate is advertised, got %v", v)
	}
	// cache_read_discount still holds the line above the high input rate.
	tk.CacheReadRate = 5_000_000
	v := verify(tk, adv)
	if v == nil || v.Check != "cache_read_discount" {
		t.Fatalf("expected cache_read_discount to still bound the signed rate, got %v", v)
	}
}

func TestVerify_LongContext_TierRaisedAboveCallerBound(t *testing.T) {
	// The input_count tolerance (10%) must not be spendable on a whole tier. The
	// caller's own bound is 1000, below the 1050 threshold; the node signs 1090 —
	// within input_count_bound's 1100 ceiling — to cross it and bill the 2x rates.
	// rate_bound alone would wave that through, because an exactly-2x surcharge
	// sits precisely on the base x RateMaxMultiple boundary.
	adv := tierAdvertised(1050)
	adv.LongContextInputUsdPer1M = ptr(4.0) // exactly 2x base $2
	adv.LongContextOutputUsdPer1M = ptr(8.0)
	tk := validTicket()
	tk.InputCount = 1090
	tk.InputRate = 4_000_000
	tk.OutputRate = 8_000_000
	tk.CacheReadRate = 2_000_000
	// ExpectedMaxPrice(1090,500,4e6,8e6,1000,0,100) = 4360+4000 = 8360; +84 = 8444.
	tk.MaxPrice = 8444
	v := verify(tk, adv)
	if v == nil || v.Check != "long_context_tier" || v.Field != "input_count" {
		t.Fatalf("expected long_context_tier violation for a count raised across the threshold, got %v", v)
	}
	// The same inflation BELOW the threshold is still fine — it is bounded by
	// input_count_bound, not by the tier check.
	adv2 := tierAdvertised(5000)
	tk2 := validTicket()
	tk2.InputCount = 1090
	// ExpectedMaxPrice(1090,500,2e6,4e6,1000,0,100) = 2180+2000 = 4180; +42 = 4222.
	tk2.MaxPrice = 4222
	if v := verify(tk2, adv2); v != nil {
		t.Fatalf("expected a sub-threshold count within tolerance to pass, got %v", v)
	}
}

func TestVerify_LongContext_TierAgreesWithCallerBound(t *testing.T) {
	// Both the caller's bound (1000) and the signed count (1000) are at/above the
	// threshold, so the tier is legitimate and long_context_tier does not fire.
	tk := validTicket()
	tk.InputRate = 4_000_000
	tk.OutputRate = 8_000_000
	tk.CacheReadRate = 2_000_000
	tk.MaxPrice = 8080
	if v := verify(tk, tierAdvertised(1000)); v != nil {
		t.Fatalf("expected a tier both sides agree on to pass, got %v", v)
	}
}
