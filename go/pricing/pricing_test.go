/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pricing_test

import (
	"math"
	"testing"

	"github.com/TxnLab/zerosignal/go/pricing"
)

func TestUSDRateToMicroUSDCPer1M_Errors(t *testing.T) {
	for _, bad := range []float64{-1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := pricing.USDRateToMicroUSDCPer1M(bad); err == nil {
			t.Errorf("USDRateToMicroUSDCPer1M(%v): expected error", bad)
		}
	}
	if v, err := pricing.USDRateToMicroUSDCPer1M(0); err != nil || v != 0 {
		t.Errorf("USDRateToMicroUSDCPer1M(0) = (%d,%v), want (0,nil)", v, err)
	}
}

// A cache-read discount must never make the settle charge exceed the flat
// (no-discount) charge — the single-combined-ceil property.
func TestCeilInputCost_DiscountNeverAboveFlat(t *testing.T) {
	const inputRate = 2_000_000
	for _, total := range []uint64{1, 7, 1000, 999_999} {
		for _, cached := range []uint64{0, 1, total / 2, total} {
			if cached > total {
				continue
			}
			flat, err := pricing.CeilInputCost(total, inputRate, 0, inputRate)
			if err != nil {
				t.Fatal(err)
			}
			// cache_read_rate strictly below input_rate
			disc, err := pricing.CeilInputCost(total-cached, inputRate, cached, inputRate/4)
			if err != nil {
				t.Fatal(err)
			}
			if disc > flat {
				t.Errorf("total=%d cached=%d: discounted %d > flat %d", total, cached, disc, flat)
			}
		}
	}
}

// An unset cache rate (== input_rate) must reproduce the flat charge exactly,
// regardless of how many tokens are "cached".
func TestCeilInputCost_UnsetEqualsFlat(t *testing.T) {
	const inputRate = 3_333_333
	for _, total := range []uint64{1, 7, 1000, 12_345} {
		flat, err := pricing.CeilInputCost(total, inputRate, 0, inputRate)
		if err != nil {
			t.Fatal(err)
		}
		for _, cached := range []uint64{0, 1, total} {
			got, err := pricing.CeilInputCost(total-cached, inputRate, cached, inputRate)
			if err != nil {
				t.Fatal(err)
			}
			if got != flat {
				t.Errorf("total=%d cached=%d: %d != flat %d", total, cached, got, flat)
			}
		}
	}
}

func TestExpectedMaxPrice_OverflowErrors(t *testing.T) {
	// A rate near MaxUint64 with a large count overflows the intermediate product.
	if _, err := pricing.ExpectedMaxPrice(math.MaxUint64, 0, math.MaxUint64, 0, 0, 0, 0); err == nil {
		t.Error("expected overflow error for saturating inputs")
	}
}

// ChargeFor never errors: on internal overflow it falls back to baseMax.
func TestChargeFor_OverflowFallsBackToBaseMax(t *testing.T) {
	const baseMax = 42
	got := pricing.ChargeFor(math.MaxUint64, 0, math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64, 0, baseMax)
	if got != baseMax {
		t.Errorf("ChargeFor overflow: got %d, want baseMax %d", got, baseMax)
	}
}

func TestGrossUpForFee_ZeroIsPassThrough(t *testing.T) {
	got, err := pricing.GrossUpForFee(12_345, 0)
	if err != nil || got != 12_345 {
		t.Errorf("GrossUpForFee(x,0) = (%d,%v), want (12345,nil)", got, err)
	}
}
