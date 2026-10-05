/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/pricing"
	"github.com/TxnLab/zerosignal/go/ticket"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// fakeFeeWallet is a minimal WalletOpener that also satisfies feeRateCapable so
// feeRateNow can read a controllable protocol-fee rate.
type fakeFeeWallet struct{ fee uint64 }

func (fakeFeeWallet) Open(context.Context, *ticket.Ticket, Operator, []types.SignedTxn) (*OpenHandle, error) {
	return nil, nil
}
func (fakeFeeWallet) PayerAddr() string                                { return "" }
func (w fakeFeeWallet) ProtocolFeeBps(context.Context) (uint64, error) { return w.fee, nil }

func f64ptr(f float64) *float64 { return &f }

// newPriceTestServer returns a Client wired just enough for verifyReservePrice:
// a fee-capable wallet and (when feeKnown) a warm fee cache at feeBps.
func newPriceTestServer(feeBps uint64, feeKnown bool) *Client {
	s := &Client{wallet: fakeFeeWallet{fee: feeBps}}
	if feeKnown {
		s.feeRate.feeBps = feeBps
		s.feeRate.ok = true
		s.feeRate.fetchedAt = time.Now()
	}
	return s
}

// priceTestOperator advertises $2/$4/1M with a genuine cache-read discount and a
// min charge, matching priceTestTicket's internally-consistent max_price.
func priceTestOperator() Operator {
	return Operator{
		ID:     1,
		NodeID: 1,
		ModelCapacities: map[string]ModelCapacity{
			"m": {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0, CacheReadUSDPer1M: f64ptr(1.0)},
		},
		MinChargeOutputTokens: 1000,
		MinChargeMicroUSDC:    100,
	}
}

func priceTestReq() ticket.ReserveRequest {
	return ticket.ReserveRequest{Model: "m", InputCount: 1000, MaxOutputCount: 500}
}

func priceTestTicket() *ticket.Ticket {
	// max_price = ceil(1000*2e6/1e6)+ceil(500*4e6/1e6) = 4000; +ceil(4000*100/1e4)=40 => 4040.
	return &ticket.Ticket{
		Model:          "m",
		InputCount:     1000,
		MaxOutputCount: 500,
		InputRate:      2_000_000,
		OutputRate:     4_000_000,
		CacheReadRate:  1_000_000,
		MinPrice:       1000,
		MaxPrice:       4040,
		// None is what the node signs on a real chat ticket (it never sets the
		// usage type); VerifyTicketPrice must run the token checks for it.
		OutputUsageType: ticket.UsageTypeNone,
	}
}

func TestVerifyReservePrice_ValidTicketAccepted(t *testing.T) {
	s := newPriceTestServer(100, true)
	if v := s.verifyReservePrice(priceTestOperator(), priceTestReq(), priceTestTicket()); v != nil {
		t.Fatalf("expected valid ticket to pass, got %+v", v)
	}
}

func TestVerifyReservePrice_InflatedMaxPriceRejected(t *testing.T) {
	s := newPriceTestServer(100, true)
	tk := priceTestTicket()
	tk.MaxPrice = 5000 // inconsistent with rates x counts x fee
	v := s.verifyReservePrice(priceTestOperator(), priceTestReq(), tk)
	if v == nil || v.Check != "max_price" {
		t.Fatalf("expected max_price violation, got %+v", v)
	}
}

// A node that still floors input_count signs more than the payer reserved; the
// payer's own count is what that is judged against, so the ticket is refused.
func TestVerifyReservePrice_FlooredInputCountRejected(t *testing.T) {
	s := newPriceTestServer(100, true)
	tk := priceTestTicket()
	tk.InputCount = 256
	mp, err := pricing.ExpectedMaxPrice(tk.InputCount, tk.MaxOutputCount, tk.InputRate, tk.OutputRate, tk.MinPrice, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	tk.MaxPrice = mp
	req := ticket.ReserveRequest{Model: "m", InputCount: 69, MaxOutputCount: 500}
	v := s.verifyReservePrice(priceTestOperator(), req, tk)
	if v == nil || v.Check != "input_count_bound" || v.Want != 75 {
		t.Fatalf("expected input_count_bound against the payer's 69 (bound 75), got %+v", v)
	}
}

// Confirms InputUSDPer1M maps to the input rate (not swapped with output).
func TestVerifyReservePrice_RateAboveAdvertisedRejected(t *testing.T) {
	s := newPriceTestServer(100, true)
	op := priceTestOperator()
	op.ModelCapacities["m"] = ModelCapacity{InputUSDPer1M: 1.0, OutputUSDPer1M: 4.0, CacheReadUSDPer1M: f64ptr(1.0)}
	tk := priceTestTicket()
	tk.InputRate = 3_000_000 // advertised $1 => 1e6, x2 = 2e6 < 3e6
	tk.MaxPrice = 5050       // keep max_price consistent: 3000+2000=5000; +50
	v := s.verifyReservePrice(op, priceTestReq(), tk)
	if v == nil || v.Check != "rate_bound" || v.Field != "input_rate" {
		t.Fatalf("expected rate_bound input_rate violation, got %+v", v)
	}
}

// TestVerifyReservePrice_LongContextTier2Accepted: a ticket whose input_count
// reaches the advertised threshold signs the high rates, and the proxy bounds
// them against the HIGH advertised comparands — so it passes.
func TestVerifyReservePrice_LongContextTier2Accepted(t *testing.T) {
	s := newPriceTestServer(100, true)
	op := priceTestOperator()
	op.ModelCapacities["m"] = ModelCapacity{
		InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0, CacheReadUSDPer1M: f64ptr(1.0),
		LongContextThresholdTokens:   500, // req InputCount 1000 >= 500 => tier 2
		LongContextInputUSDPer1M:     f64ptr(4.0),
		LongContextOutputUSDPer1M:    f64ptr(8.0),
		LongContextCacheReadUSDPer1M: f64ptr(2.0),
	}
	tk := priceTestTicket()
	tk.InputRate = 4_000_000     // high input $4
	tk.OutputRate = 8_000_000    // high output $8
	tk.CacheReadRate = 2_000_000 // high cache $2 (< high input, a real discount)
	// max_price = ceil(1000*4e6/1e6)+ceil(500*8e6/1e6) = 8000; +ceil(8000*100/1e4)=80 => 8080.
	tk.MaxPrice = 8080
	if v := s.verifyReservePrice(op, priceTestReq(), tk); v != nil {
		t.Fatalf("expected tier-2 ticket to pass, got %+v", v)
	}
}

// TestVerifyReservePrice_LongContextHighRateSubThresholdRejected: signing the high
// rate onto a SUB-threshold input_count is bounded against the BASE rate — the
// tier is decided by input_count, not by which rates were signed.
func TestVerifyReservePrice_LongContextHighRateSubThresholdRejected(t *testing.T) {
	s := newPriceTestServer(100, true)
	op := priceTestOperator()
	op.ModelCapacities["m"] = ModelCapacity{
		InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0, CacheReadUSDPer1M: f64ptr(1.0),
		LongContextThresholdTokens: 2000, // req InputCount 1000 < 2000 => tier 1
		LongContextInputUSDPer1M:   f64ptr(5.0),
		LongContextOutputUSDPer1M:  f64ptr(10.0),
	}
	tk := priceTestTicket()
	tk.InputRate = 5_000_000 // high input signed on a sub-threshold count; base×2 = 4e6 bites
	// max_price = ceil(1000*5e6/1e6)+ceil(500*4e6/1e6) = 7000; +70 => 7070.
	tk.MaxPrice = 7070
	v := s.verifyReservePrice(op, priceTestReq(), tk)
	if v == nil || v.Check != "rate_bound" || v.Field != "input_rate" {
		t.Fatalf("expected rate_bound input_rate violation, got %+v", v)
	}
}

func TestVerifyReservePrice_FailsOpenOnColdFeeCache(t *testing.T) {
	s := newPriceTestServer(100, false) // fee not cached yet
	tk := priceTestTicket()
	tk.MaxPrice = 5000 // would be a max_price violation if the check ran
	if v := s.verifyReservePrice(priceTestOperator(), priceTestReq(), tk); v != nil {
		t.Fatalf("expected fail-open on cold fee cache, got %+v", v)
	}
}

func TestVerifyReservePrice_FailsOpenOnCatalogMiss(t *testing.T) {
	s := newPriceTestServer(100, true)
	op := priceTestOperator()
	op.ModelCapacities = nil // no advertised capacity entry for the model
	tk := priceTestTicket()
	tk.MaxPrice = 5000 // would be a max_price violation if the check ran
	if v := s.verifyReservePrice(op, priceTestReq(), tk); v != nil {
		t.Fatalf("expected fail-open on catalog miss, got %+v", v)
	}
}

func TestVerifyReservePrice_FailsOpenOnImageToolBudget(t *testing.T) {
	s := newPriceTestServer(100, true)
	req := priceTestReq()
	req.ImageToolBudget = 4 // additive budget max_price can't reproduce here => skip
	tk := priceTestTicket()
	tk.MaxPrice = 5000 // would be a max_price violation if the check ran
	if v := s.verifyReservePrice(priceTestOperator(), req, tk); v != nil {
		t.Fatalf("expected fail-open with image-tool budget, got %+v", v)
	}
}

// The image-tool skip comes before the fee read, so a skipped gate never
// refreshes the fee cache.
func TestReservePriceViolation_ImageBudgetReadsNoFee(t *testing.T) {
	for _, req := range []ticket.ReserveRequest{
		{Model: "m", InputCount: 1000, ImageToolBudget: 4},
		{Model: "m", InputCount: 1000, ImageEditToolBudget: 2},
	} {
		v := reservePriceViolation(priceTestOperator(), req, priceTestTicket(), func() (uint64, bool) {
			t.Fatal("fee read with an image-tool budget")
			return 0, false
		})
		if v != nil {
			t.Fatalf("expected the gate skipped, got %+v", v)
		}
	}
}

// A tool-pricing model's inflated max_price is REPRODUCED (not skipped): the
// vendor fee headroom (call_cap × rate) is folded into the expected max_price so
// the max_price recompute reconciles and the ticket passes.
func TestVerifyReservePrice_ToolPricingReproducedAccepts(t *testing.T) {
	s := newPriceTestServer(100, true)
	op := priceTestOperator()
	mc := op.ModelCapacities["m"]
	mc.ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 6000}
	mc.VendorToolCallCap = 10
	op.ModelCapacities["m"] = mc
	tk := priceTestTicket()
	// rate-based 4000 + tool reserve (10 × 6000 = 60000) = 64000; grossUp 100bps => 64640.
	tk.MaxPrice = 64640
	if v := s.verifyReservePrice(op, priceTestReq(), tk); v != nil {
		t.Fatalf("expected reproduced tool-pricing ticket to pass, got %+v", v)
	}
}

// The hole the earlier skip-based version left: a tool-pricing model that inflates
// the TOKEN rate must STILL be caught by the advertised-rate bound — reproduction
// keeps the rate / min-charge / cache-read checks running.
func TestVerifyReservePrice_ToolPricingStillChecksTokenRate(t *testing.T) {
	s := newPriceTestServer(100, true)
	op := priceTestOperator()
	mc := op.ModelCapacities["m"]
	mc.ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 6000}
	mc.VendorToolCallCap = 10
	op.ModelCapacities["m"] = mc
	tk := priceTestTicket()
	tk.InputRate = 5_000_000 // advertised $2 => 2e6, ×2 = 4e6 < 5e6 => rate_bound violation
	// Keep max_price consistent so the check reaches rate_bound: rate-based 5000+2000=7000; +60000=67000; grossUp=67670.
	tk.MaxPrice = 67670
	v := s.verifyReservePrice(op, priceTestReq(), tk)
	if v == nil || v.Check != "rate_bound" || v.Field != "input_rate" {
		t.Fatalf("expected rate_bound input_rate violation (exploit closed), got %+v", v)
	}
}
