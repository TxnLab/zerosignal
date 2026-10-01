/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pricing

import "testing"

func TestToolFeeReserveMicroUSDC(t *testing.T) {
	cases := []struct {
		name                                                            string
		iters, maxZs, callCap, maxVendor, tokensPerCall, inputRatePer1M uint64
		want                                                            uint64
	}{
		{"nothing priced", 20, 0, 0, 0, 0, 2_000_000, 0},
		{"zs only: iters×rate", 20, 4000, 0, 0, 0, 2_000_000, 80000},
		{"zs term dropped when iterations 0", 0, 4000, 0, 0, 0, 2_000_000, 0},
		{"vendor fee only: cap×rate", 0, 0, 10, 6000, 0, 2_000_000, 60000},
		// token inflation: ceil(10×3000 × 2e6 / 1e6) = ceil(30000 × 2) = 60000.
		{"vendor fee + token inflation", 0, 0, 10, 6000, 3000, 2_000_000, 60000 + 60000},
		{"token inflation 0 when input rate 0", 0, 0, 10, 6000, 3000, 0, 60000},
		{"combined zs + vendor + inflation", 20, 4000, 10, 6000, 3000, 2_000_000, 80000 + 60000 + 60000},
		// no callCap ⇒ no vendor term at all even with a vendor rate.
		{"vendor rate ignored without call cap", 0, 0, 0, 6000, 3000, 2_000_000, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ToolFeeReserveMicroUSDC(c.iters, c.maxZs, c.callCap, c.maxVendor, c.tokensPerCall, c.inputRatePer1M)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != c.want {
				t.Errorf("got %d, want %d", got, c.want)
			}
		})
	}
}

func TestToolFeeReserveMicroUSDC_Overflow(t *testing.T) {
	// A giant zs_ rate × iterations overflows and must error, not wrap.
	if _, err := ToolFeeReserveMicroUSDC(20, ^uint64(0), 0, 0, 0, 0); err == nil {
		t.Error("expected overflow error on absurd zs_ rate")
	}
}
