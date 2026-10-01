/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"testing"
)

func TestNetFee(t *testing.T) {
	cases := []struct {
		name          string
		amountCharged uint64
		feeBps        uint64
		discountBps   uint64
		want          uint64
	}{
		{"no fee", 1_000_000, 0, 0, 0},
		{"10pct no discount", 1_000_000, 1000, 0, 100_000},
		{"10pct 80pct discount", 5_000_000, 1000, 8000, 100_000}, // gross 500k, -80% = 100k (matches contract HAY-discount test)
		{"zero charge", 0, 1000, 0, 0},
		{"floor on gross", 7, 1000, 0, 0},                     // 7*1000/10000 = 0 (floored)
		{"discount clamp >100pct", 1_000_000, 1000, 12000, 0}, // defensive clamp to 10000
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := NetFee(c.amountCharged, c.feeBps, c.discountBps); got != c.want {
				t.Errorf("NetFee(%d, %d, %d) = %d, want %d", c.amountCharged, c.feeBps, c.discountBps, got, c.want)
			}
		})
	}
}

func TestComputeFeeBreakdown(t *testing.T) {
	// maxPrice grossed up to base + worst-case fee (1_100_000); 10% fee, no
	// discount → netFee 100_000, refund 0, totalDebit 1_100_000.
	b := ComputeFeeBreakdown(1_000_000, 1_100_000, 1000, 0)
	if b.AmountCharged != 1_000_000 || b.NetFee != 100_000 || b.Refund != 0 || b.TotalDebit != 1_100_000 {
		t.Errorf("full-charge breakdown = %+v", b)
	}

	// Headroom case: base 100_000 of a 1_000_000 ceiling, 10% fee → netFee
	// 10_000, refund 890_000, totalDebit 110_000.
	b = ComputeFeeBreakdown(100_000, 1_000_000, 1000, 0)
	if b.NetFee != 10_000 || b.Refund != 890_000 || b.TotalDebit != 110_000 {
		t.Errorf("headroom breakdown = %+v", b)
	}

	// HAY discount enlarges the refund: base 5_000_000 of 5_500_000, 10% fee,
	// 80% discount → netFee 100_000, refund 400_000.
	b = ComputeFeeBreakdown(5_000_000, 5_500_000, 1000, 8000)
	if b.NetFee != 100_000 || b.Refund != 400_000 || b.TotalDebit != 5_100_000 {
		t.Errorf("discount breakdown = %+v", b)
	}

	// Corrupt/over-budget snapshot clamps refund to 0 rather than underflowing.
	b = ComputeFeeBreakdown(1_000_000, 500_000, 1000, 0)
	if b.Refund != 0 {
		t.Errorf("over-budget refund = %d, want 0", b.Refund)
	}
}

// TestSettleInnerCount pins the disbursement-inner bound the settle composers
// size their fee from.
func TestSettleInnerCount(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		amountCharged, maxPrice uint64
		want                    uint64
	}{
		{"free model: nothing escrowed, nothing charged", 0, 0, 0},
		{"zero charge (failed request): refund only", 0, 1_000, 1},
		{"paid, unspent headroom: payout + fee + refund", 400, 1_000, 3},
		{"paid, ticket spent exactly: payout + fee", 1_000, 1_000, 2},
		{"paid, charged above ceiling (corrupt): payout + fee", 1_000, 400, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := SettleInnerCount(tc.amountCharged, tc.maxPrice); got != tc.want {
				t.Fatalf("SettleInnerCount(%d, %d) = %d, want %d",
					tc.amountCharged, tc.maxPrice, got, tc.want)
			}
		})
	}
}

// TestSettleInnerCountNeverUnderCounts is the safety property the whole
// fee-sizing change rests on: for every (amountCharged, maxPrice, feeBps) the
// contract could see, the bound must be >= the number of disbursement inners
// finalizeSettlement actually submits. An under-count under-pools the group fee
// and reverts the settle. The bound deliberately ignores feeBps, so sweep it.
func TestSettleInnerCountNeverUnderCounts(t *testing.T) {
	amounts := []uint64{0, 1, 7, 999, 1_000, 123_456}
	maxPrices := []uint64{0, 1, 7, 999, 1_000, 1_001, 123_456, 1_000_000}

	for _, feeBps := range []uint64{0, 1, 5, 100, 250, 999, 1_000, 1_999, 2_000} {
		for _, charged := range amounts {
			for _, maxPrice := range maxPrices {
				// The contract asserts amountCharged + netFee <= maxPrice, so
				// skip the combinations it would reject outright.
				b := ComputeFeeBreakdown(charged, maxPrice, feeBps, 0)
				if b.TotalDebit > maxPrice {
					continue
				}
				// Mirror finalizeSettlement's three independent guards.
				var actual uint64
				if charged > 0 {
					actual++ // operator payout
				}
				if b.NetFee > 0 {
					actual++ // treasury fee
				}
				if b.Refund > 0 {
					actual++ // payer refund
				}
				if got := SettleInnerCount(charged, maxPrice); got < actual {
					t.Fatalf("under-count: SettleInnerCount(%d, %d) = %d < actual %d (feeBps=%d)",
						charged, maxPrice, got, actual, feeBps)
				}
			}
		}
	}
}
