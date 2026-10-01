/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package pricing_test

// Cross-impl byte-parity test for the shared token-pricing math. Generates /
// verifies proto/testdata/pricing_vectors.json — a language-neutral fixture that
// pins USDRateToMicroUSDCPer1M, CeilInputCost, ChargeFor, ReserveMinPrice,
// MinChargeFloor, ExpectedMaxPrice, and ToolFeeReserveMicroUSDC. proto/ts/src/pricing loads the same file
// and asserts equality, so the node's pricer and the payer-side verifier can
// never silently drift across languages.
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./pricing -run TestVectors -update
//
// Without -update, this test asserts the on-disk file matches what the current
// code produces and fails with a regen hint otherwise.

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/pricing"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/pricing_vectors.json")

const pricingVectorsPath = "../../testdata/pricing_vectors.json"

type usdRateVector struct {
	Name     string  `json:"name"`
	USDPer1M float64 `json:"usd_per_1m"`
	Expected uint64  `json:"expected"`
}

type inputCostVector struct {
	Name          string `json:"name"`
	NonCached     uint64 `json:"non_cached"`
	InputRate     uint64 `json:"input_rate"`
	Cached        uint64 `json:"cached"`
	CacheReadRate uint64 `json:"cache_read_rate"`
	Expected      uint64 `json:"expected"`
}

type chargeVector struct {
	Name          string `json:"name"`
	ActualInput   uint64 `json:"actual_input"`
	CachedInput   uint64 `json:"cached_input"`
	ActualOutput  uint64 `json:"actual_output"`
	InputRate     uint64 `json:"input_rate"`
	CacheReadRate uint64 `json:"cache_read_rate"`
	OutputRate    uint64 `json:"output_rate"`
	MinPrice      uint64 `json:"min_price"`
	BaseMax       uint64 `json:"base_max"`
	Expected      uint64 `json:"expected"`
}

type reserveMinPriceVector struct {
	Name            string  `json:"name"`
	MinOutputTokens uint64  `json:"min_output_tokens"`
	OutputRate      uint64  `json:"output_rate"`
	AlgoTxns        uint64  `json:"algo_txns"`
	AlgoUSD         float64 `json:"algo_usd"`
	Paid            bool    `json:"paid"`
	Expected        uint64  `json:"expected"`
}

type minChargeFloorVector struct {
	Name                  string `json:"name"`
	MinChargeOutputTokens uint64 `json:"min_charge_output_tokens"`
	OutputRate            uint64 `json:"output_rate"`
	MinChargeMicroUSDC    uint64 `json:"min_charge_micro_usdc"`
	Expected              uint64 `json:"expected"`
}

type maxPriceVector struct {
	Name           string `json:"name"`
	InputCount     uint64 `json:"input_count"`
	MaxOutputCount uint64 `json:"max_output_count"`
	InputRate      uint64 `json:"input_rate"`
	OutputRate     uint64 `json:"output_rate"`
	MinPrice       uint64 `json:"min_price"`
	ExtraBase      uint64 `json:"extra_base"`
	FeeBps         uint64 `json:"fee_bps"`
	Expected       uint64 `json:"expected"`
}

type toolFeeReserveVector struct {
	Name              string `json:"name"`
	MaxToolIterations uint64 `json:"max_tool_iterations"`
	MaxZsRate         uint64 `json:"max_zs_rate"`
	CallCap           uint64 `json:"call_cap"`
	MaxVendorRate     uint64 `json:"max_vendor_rate"`
	TokensPerCall     uint64 `json:"tokens_per_call"`
	InputRate         uint64 `json:"input_rate"`
	Expected          uint64 `json:"expected"`
}

type longContextVector struct {
	Name       string `json:"name"`
	InputCount uint64 `json:"input_count"`
	Threshold  uint64 `json:"threshold"`
	Expected   bool   `json:"expected"`
}

type pricingVectorsFile struct {
	Version         int                     `json:"version"`
	Comment         string                  `json:"comment"`
	USDRate         []usdRateVector         `json:"usd_rate"`
	InputCost       []inputCostVector       `json:"input_cost"`
	Charge          []chargeVector          `json:"charge"`
	ReserveMinPrice []reserveMinPriceVector `json:"reserve_min_price"`
	MinChargeFloor  []minChargeFloorVector  `json:"min_charge_floor"`
	MaxPrice        []maxPriceVector        `json:"max_price"`
	ToolFeeReserve  []toolFeeReserveVector  `json:"tool_fee_reserve"`
	LongContext     []longContextVector     `json:"long_context"`
}

func mustU64(t *testing.T, name string, v uint64, err error) uint64 {
	t.Helper()
	if err != nil {
		t.Fatalf("vector %q produced an error (inputs must not overflow): %v", name, err)
	}
	return v
}

func buildPricingVectors(t *testing.T) *pricingVectorsFile {
	usd := []usdRateVector{
		{Name: "free", USDPer1M: 0},
		{Name: "half", USDPer1M: 0.5},
		{Name: "two", USDPer1M: 2},
		{Name: "frac_ceil", USDPer1M: 1.0000011},
		{Name: "high", USDPer1M: 1000},
	}
	for i := range usd {
		v, err := pricing.USDRateToMicroUSDCPer1M(usd[i].USDPer1M)
		usd[i].Expected = mustU64(t, usd[i].Name, v, err)
	}

	inputCost := []inputCostVector{
		{Name: "no_cache", NonCached: 1000, InputRate: 2_000_000, Cached: 0, CacheReadRate: 2_000_000},
		{Name: "unset_cache_equals_input", NonCached: 700, InputRate: 2_000_000, Cached: 300, CacheReadRate: 2_000_000},
		{Name: "discounted", NonCached: 700, InputRate: 2_000_000, Cached: 300, CacheReadRate: 500_000},
		{Name: "free_cache", NonCached: 700, InputRate: 2_000_000, Cached: 300, CacheReadRate: 0},
		{Name: "all_cached", NonCached: 0, InputRate: 2_000_000, Cached: 1000, CacheReadRate: 500_000},
		{Name: "single_token_ceil", NonCached: 1, InputRate: 1, Cached: 0, CacheReadRate: 0},
		{Name: "bigint_range", NonCached: 10_000_000, InputRate: 1_000_000_000, Cached: 0, CacheReadRate: 0},
	}
	for i := range inputCost {
		c := &inputCost[i]
		v, err := pricing.CeilInputCost(c.NonCached, c.InputRate, c.Cached, c.CacheReadRate)
		c.Expected = mustU64(t, c.Name, v, err)
	}

	charge := []chargeVector{
		{Name: "zero_usage", ActualInput: 0, CachedInput: 0, ActualOutput: 0, InputRate: 2_000_000, CacheReadRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 1000, BaseMax: 100_000},
		{Name: "normal", ActualInput: 1000, CachedInput: 0, ActualOutput: 500, InputRate: 2_000_000, CacheReadRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 1000, BaseMax: 100_000},
		{Name: "under_min", ActualInput: 1, CachedInput: 0, ActualOutput: 1, InputRate: 2_000_000, CacheReadRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 5000, BaseMax: 100_000},
		{Name: "over_base_max", ActualInput: 1_000_000, CachedInput: 0, ActualOutput: 1_000_000, InputRate: 2_000_000, CacheReadRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 1000, BaseMax: 100},
		{Name: "cached_discount", ActualInput: 1000, CachedInput: 800, ActualOutput: 0, InputRate: 2_000_000, CacheReadRate: 500_000, OutputRate: 4_000_000, MinPrice: 0, BaseMax: 1_000_000},
		{Name: "cached_over_input", ActualInput: 100, CachedInput: 500, ActualOutput: 0, InputRate: 2_000_000, CacheReadRate: 0, OutputRate: 4_000_000, MinPrice: 0, BaseMax: 100_000},
		{Name: "min_gt_base_max", ActualInput: 1, CachedInput: 0, ActualOutput: 1, InputRate: 2_000_000, CacheReadRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 5000, BaseMax: 100},
	}
	for i := range charge {
		c := &charge[i]
		c.Expected = pricing.ChargeFor(c.ActualInput, c.CachedInput, c.ActualOutput, c.InputRate, c.CacheReadRate, c.OutputRate, c.MinPrice, c.BaseMax)
	}

	reserveMin := []reserveMinPriceVector{
		{Name: "unpaid_free", MinOutputTokens: 1000, OutputRate: 0, AlgoTxns: 2, AlgoUSD: 0.2, Paid: false},
		{Name: "token_floor", MinOutputTokens: 1000, OutputRate: 4_000_000, AlgoTxns: 0, AlgoUSD: 0, Paid: true},
		{Name: "algo_floor", MinOutputTokens: 100, OutputRate: 4_000_000, AlgoTxns: 8, AlgoUSD: 0.25, Paid: true},
		{Name: "oracle_out", MinOutputTokens: 100, OutputRate: 4_000_000, AlgoTxns: 8, AlgoUSD: 0, Paid: true},
	}
	for i := range reserveMin {
		c := &reserveMin[i]
		v, err := pricing.ReserveMinPrice(c.MinOutputTokens, c.OutputRate, c.AlgoTxns, c.AlgoUSD, c.Paid)
		c.Expected = mustU64(t, c.Name, v, err)
	}

	minChargeFloor := []minChargeFloorVector{
		{Name: "token_dominant", MinChargeOutputTokens: 1000, OutputRate: 4_000_000, MinChargeMicroUSDC: 100},
		{Name: "micro_dominant", MinChargeOutputTokens: 100, OutputRate: 4_000_000, MinChargeMicroUSDC: 5000},
		{Name: "zero", MinChargeOutputTokens: 0, OutputRate: 4_000_000, MinChargeMicroUSDC: 0},
	}
	for i := range minChargeFloor {
		c := &minChargeFloor[i]
		c.Expected = pricing.MinChargeFloor(c.MinChargeOutputTokens, c.OutputRate, c.MinChargeMicroUSDC)
	}

	maxPrice := []maxPriceVector{
		{Name: "no_fee", InputCount: 1000, MaxOutputCount: 500, InputRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 0, ExtraBase: 0, FeeBps: 0},
		{Name: "with_fee", InputCount: 1000, MaxOutputCount: 500, InputRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 0, ExtraBase: 0, FeeBps: 100},
		{Name: "min_floor_bump", InputCount: 1, MaxOutputCount: 1, InputRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 5000, ExtraBase: 0, FeeBps: 100},
		{Name: "image_tool_budget", InputCount: 1000, MaxOutputCount: 500, InputRate: 2_000_000, OutputRate: 4_000_000, MinPrice: 0, ExtraBase: 10_000, FeeBps: 100},
		{Name: "fee_ceil", InputCount: 1, MaxOutputCount: 0, InputRate: 1_000_001, OutputRate: 0, MinPrice: 0, ExtraBase: 0, FeeBps: 250},
	}
	for i := range maxPrice {
		c := &maxPrice[i]
		v, err := pricing.ExpectedMaxPrice(c.InputCount, c.MaxOutputCount, c.InputRate, c.OutputRate, c.MinPrice, c.ExtraBase, c.FeeBps)
		c.Expected = mustU64(t, c.Name, v, err)
	}

	toolFee := []toolFeeReserveVector{
		{Name: "nothing_priced", MaxToolIterations: 20, MaxZsRate: 0, CallCap: 0, MaxVendorRate: 0, TokensPerCall: 0, InputRate: 2_000_000},
		{Name: "zs_only", MaxToolIterations: 20, MaxZsRate: 4000, CallCap: 0, MaxVendorRate: 0, TokensPerCall: 0, InputRate: 2_000_000},
		{Name: "zs_iters_zero", MaxToolIterations: 0, MaxZsRate: 4000, CallCap: 0, MaxVendorRate: 0, TokensPerCall: 0, InputRate: 2_000_000},
		{Name: "vendor_fee_only", MaxToolIterations: 0, MaxZsRate: 0, CallCap: 10, MaxVendorRate: 6000, TokensPerCall: 0, InputRate: 2_000_000},
		{Name: "vendor_fee_plus_inflation", MaxToolIterations: 0, MaxZsRate: 0, CallCap: 10, MaxVendorRate: 6000, TokensPerCall: 3000, InputRate: 2_000_000},
		{Name: "inflation_zero_input_rate", MaxToolIterations: 0, MaxZsRate: 0, CallCap: 10, MaxVendorRate: 6000, TokensPerCall: 3000, InputRate: 0},
		{Name: "vendor_rate_no_cap", MaxToolIterations: 0, MaxZsRate: 0, CallCap: 0, MaxVendorRate: 6000, TokensPerCall: 3000, InputRate: 2_000_000},
		{Name: "combined", MaxToolIterations: 20, MaxZsRate: 4000, CallCap: 10, MaxVendorRate: 6000, TokensPerCall: 3000, InputRate: 2_000_000},
		{Name: "bigint_range", MaxToolIterations: 20, MaxZsRate: 1_000_000, CallCap: 64, MaxVendorRate: 1_000_000, TokensPerCall: 4000, InputRate: 1_000_000_000},
	}
	for i := range toolFee {
		c := &toolFee[i]
		v, err := pricing.ToolFeeReserveMicroUSDC(c.MaxToolIterations, c.MaxZsRate, c.CallCap, c.MaxVendorRate, c.TokensPerCall, c.InputRate)
		c.Expected = mustU64(t, c.Name, v, err)
	}

	// long_context — IsLongContext boundary cases: the tier is decided by
	// input_count ALONE, the boundary is INCLUSIVE (>=), and threshold==0 disables
	// the tier entirely.
	longContext := []longContextVector{
		{Name: "below_threshold", InputCount: 199_999, Threshold: 200_000},
		{Name: "at_threshold", InputCount: 200_000, Threshold: 200_000},
		{Name: "above_threshold", InputCount: 200_001, Threshold: 200_000},
		{Name: "zero_input_with_tier", InputCount: 0, Threshold: 200_000},
		{Name: "no_tier_threshold_zero", InputCount: 500_000, Threshold: 0},
	}
	for i := range longContext {
		c := &longContext[i]
		c.Expected = pricing.IsLongContext(c.InputCount, c.Threshold)
	}

	return &pricingVectorsFile{
		Version: 3,
		Comment: "Cross-impl byte-parity vectors for shared token pricing. " +
			"Regenerate via: cd proto/go && go test ./pricing -run TestVectors -update. " +
			"Loaded by proto/go/pricing/vectors_test.go and proto/ts/test/pricing-vectors.test.ts.",
		USDRate:         usd,
		InputCost:       inputCost,
		Charge:          charge,
		ReserveMinPrice: reserveMin,
		MinChargeFloor:  minChargeFloor,
		MaxPrice:        maxPrice,
		ToolFeeReserve:  toolFee,
		LongContext:     longContext,
	}
}

func TestVectors(t *testing.T) {
	want := buildPricingVectors(t)
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateVectors {
		if err := os.WriteFile(pricingVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", pricingVectorsPath)
		return
	}

	onDisk, err := os.ReadFile(pricingVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(onDisk, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./pricing -run TestVectors -update", pricingVectorsPath)
	}
}
