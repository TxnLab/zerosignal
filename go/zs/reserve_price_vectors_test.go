/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/reserve_price_vectors.json: the payer's
// price gate on a just-reserved ticket (reservePriceViolation), which the TS
// SDK mirrors as verifyReservePrice in sdk/src/reserve-price.ts. Each scenario
// is the node's /v1/zs/details advertisement as it came off the wire, so the
// vectors pin the advertisement's mapping onto the gate's inputs as well as the
// gate itself.
//
//	cd proto/go && go test ./zs -run TestReservePriceVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/pricing"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const reservePriceVectorsPath = "../../testdata/reserve_price_vectors.json"

type reservePriceWant struct {
	Check string `json:"check"`
	Field string `json:"field"`
	Want  uint64 `json:"want"`
	Got   uint64 `json:"got"`
}

type reservePriceScenario struct {
	Name string `json:"name"`
	// Details is the serving node's advertisement. A request model it does not
	// list is a catalog miss.
	Details inject.OperatorDetails `json:"details"`
	Model   string                 `json:"model"`
	// ReserveInputCount is the payer's own input bound for the request.
	ReserveInputCount   uint64        `json:"reserve_input_count"`
	ImageToolBudget     uint64        `json:"image_tool_budget"`
	ImageEditToolBudget uint64        `json:"image_edit_tool_budget"`
	Ticket              ticket.Ticket `json:"ticket"`
	// FeeBps is the on-chain protocol fee, or null when it is not yet known.
	FeeBps *uint64 `json:"fee_bps"`
	// Want is the first violation, or null when the gate accepts.
	Want *reservePriceWant `json:"want"`
}

// priceVectorDetails advertises $2/$4/1M with a cache-read discount and a
// minimum charge, the rates priceVectorTicket is signed at.
func priceVectorDetails() inject.OperatorDetails {
	return inject.OperatorDetails{
		Models: []inject.OperatorDetailsModel{{
			ID: "m", InputRateUSDPer1M: 2, OutputRateUSDPer1M: 4, CacheReadRateUSDPer1M: f64ptr(1),
		}},
		MinChargeOutputTokens: 1000,
		MinChargeMicroUSDC:    100,
	}
}

func priceVectorTicket() ticket.Ticket {
	return *priceTestTicket()
}

func feePtr(v uint64) *uint64 { return &v }

// withMaxPrice re-derives max_price from the ticket's own numbers, so the
// scenario reaches the check it is about.
func withMaxPrice(t ticket.Ticket, extra, feeBps uint64) ticket.Ticket {
	mp, err := pricing.ExpectedMaxPrice(t.InputCount, t.MaxOutputCount, t.InputRate, t.OutputRate, t.MinPrice, extra, feeBps)
	if err != nil {
		panic(err)
	}
	t.MaxPrice = mp
	return t
}

func reservePriceScenarios() []reservePriceScenario {
	base := func(name string) reservePriceScenario {
		return reservePriceScenario{
			Name: name, Details: priceVectorDetails(), Model: "m", ReserveInputCount: 1000,
			Ticket: priceVectorTicket(), FeeBps: feePtr(100),
		}
	}
	var out []reservePriceScenario
	add := func(name string, edit func(*reservePriceScenario)) {
		sc := base(name)
		edit(&sc)
		out = append(out, sc)
	}
	model := func(sc *reservePriceScenario) *inject.OperatorDetailsModel { return &sc.Details.Models[0] }

	add("a ticket priced as advertised passes", func(*reservePriceScenario) {})
	add("an inflated max_price is refused", func(sc *reservePriceScenario) { sc.Ticket.MaxPrice = 5000 })
	add("an input count above the payer's own bound is refused", func(sc *reservePriceScenario) {
		sc.Ticket.InputCount = 256
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
		sc.ReserveInputCount = 69
	})
	add("an input rate above the advertised one is refused", func(sc *reservePriceScenario) {
		model(sc).InputRateUSDPer1M = 1
		sc.Ticket.InputRate = 3_000_000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	add("a model that advertises no rate is priced as free, not waved through", func(sc *reservePriceScenario) {
		model(sc).InputRateUSDPer1M, model(sc).OutputRateUSDPer1M, model(sc).CacheReadRateUSDPer1M = 0, 0, nil
	})
	add("a min_price above the advertised minimum charge is refused", func(sc *reservePriceScenario) {
		sc.Ticket.MinPrice = 9000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	add("a cache-read rate above the input rate is refused", func(sc *reservePriceScenario) {
		sc.Ticket.CacheReadRate = 2_500_000
	})
	add("the long-context tier bounds a long ticket by its high rates", func(sc *reservePriceScenario) {
		m := model(sc)
		m.LongContextThresholdTokens = 500
		m.LongContextInputRateUSDPer1M, m.LongContextOutputRateUSDPer1M, m.LongContextCacheReadRateUSDPer1M = f64ptr(4), f64ptr(8), f64ptr(2)
		sc.Ticket.InputRate, sc.Ticket.OutputRate, sc.Ticket.CacheReadRate = 4_000_000, 8_000_000, 2_000_000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	add("a high rate signed below the threshold is bounded by the base rate", func(sc *reservePriceScenario) {
		m := model(sc)
		m.LongContextThresholdTokens = 2000
		m.LongContextInputRateUSDPer1M, m.LongContextOutputRateUSDPer1M = f64ptr(5), f64ptr(10)
		sc.Ticket.InputRate = 5_000_000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	add("an unknown fee fails open", func(sc *reservePriceScenario) {
		sc.FeeBps = nil
		sc.Ticket.MaxPrice = 5000
	})
	add("a catalog miss fails open", func(sc *reservePriceScenario) {
		sc.Model = "other"
		sc.Ticket.Model = "other"
		sc.Ticket.MaxPrice = 5000
	})
	add("an image-tool budget fails open", func(sc *reservePriceScenario) {
		sc.ImageToolBudget = 4
		sc.Ticket.MaxPrice = 5000
	})
	add("an image-edit-tool budget fails open", func(sc *reservePriceScenario) {
		sc.ImageEditToolBudget = 2
		sc.Ticket.MaxPrice = 5000
	})
	add("a dedicated image ticket is not priced per token", func(sc *reservePriceScenario) {
		sc.Ticket.OutputUsageType = ticket.UsageTypeImages
		sc.Ticket.MaxPrice = 5000
	})
	add("a vendor tool's headroom is reproduced", func(sc *reservePriceScenario) {
		model(sc).ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 6000}
		model(sc).VendorToolCallCap = 10
		sc.Ticket = withMaxPrice(sc.Ticket, 60_000, 100)
	})
	add("a tool-pricing model still has its token rate bounded", func(sc *reservePriceScenario) {
		model(sc).ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 6000}
		model(sc).VendorToolCallCap = 10
		sc.Ticket.InputRate = 5_000_000
		sc.Ticket = withMaxPrice(sc.Ticket, 60_000, 100)
	})
	add("the vendor catch-all and per-call tokens are reproduced", func(sc *reservePriceScenario) {
		m := model(sc)
		m.ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 2000}
		m.VendorToolCatchAllMicroUSDC = 3000
		m.VendorToolCallCap = 2
		m.VendorToolTokensPerCall = 1000
		// 2 × 3000, plus 2 × 1000 tokens at the ticket's $2 input rate.
		sc.Ticket = withMaxPrice(sc.Ticket, 10_000, 100)
	})
	add("a zs_ tool's headroom scales by the operator's max_tool_iterations", func(sc *reservePriceScenario) {
		model(sc).ToolCallRatesMicroUSDC = map[string]uint64{"zs_web_read": 500, "web_search": 0}
		sc.Details.MaxToolIterations = 4
		sc.Ticket = withMaxPrice(sc.Ticket, 2000, 100)
	})
	add("a zs_ tool adds no headroom without max_tool_iterations", func(sc *reservePriceScenario) {
		model(sc).ToolCallRatesMicroUSDC = map[string]uint64{"zs_web_read": 500}
		sc.Ticket = withMaxPrice(sc.Ticket, 2000, 100)
	})
	add("a tool headroom that overflows fails open", func(sc *reservePriceScenario) {
		model(sc).VendorToolCatchAllMicroUSDC = 1 << 30
		model(sc).VendorToolCallCap = 1 << 40
		sc.Ticket.MaxPrice = 5000
	})
	// Between 2^53 and uint64 overflow the headroom is exact in Go, so the gate
	// runs: an SDK that failed open on a number's precision would differ here.
	add("a tool headroom past 2^53 still runs the gate", func(sc *reservePriceScenario) {
		model(sc).VendorToolCatchAllMicroUSDC = 1 << 30
		model(sc).VendorToolCallCap = 1 << 24
		sc.Ticket.MaxPrice = 5000
	})
	add("a per-call token headroom whose price overflows fails open", func(sc *reservePriceScenario) {
		model(sc).VendorToolCallCap = 10_000_000
		model(sc).VendorToolTokensPerCall = 10_000_000
		sc.Ticket.MaxPrice = 5000
	})
	add("a headroom whose fee gross-up overflows skips only the max_price check", func(sc *reservePriceScenario) {
		model(sc).VendorToolCatchAllMicroUSDC = 1<<32 - 1
		model(sc).VendorToolCallCap = 1 << 32
		sc.Ticket.MaxPrice = 5000
	})
	add("a headroom whose fee gross-up overflows still has its token rate bounded", func(sc *reservePriceScenario) {
		model(sc).VendorToolCatchAllMicroUSDC = 1<<32 - 1
		model(sc).VendorToolCallCap = 1 << 32
		sc.Ticket.InputRate = 5_000_000
		sc.Ticket.MaxPrice = 5000
	})
	add("a named vendor rate above the catch-all sets the headroom", func(sc *reservePriceScenario) {
		m := model(sc)
		m.ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 5000}
		m.VendorToolCatchAllMicroUSDC = 3000
		m.VendorToolCallCap = 2
		sc.Ticket = withMaxPrice(sc.Ticket, 10_000, 100)
	})
	add("the priciest zs_ rate sets the headroom", func(sc *reservePriceScenario) {
		model(sc).ToolCallRatesMicroUSDC = map[string]uint64{"zs_a": 200, "zs_b": 500, "zs_c": 100}
		sc.Details.MaxToolIterations = 4
		sc.Ticket = withMaxPrice(sc.Ticket, 2000, 100)
	})
	// High rates more than the policy's 2x above base, and input unlike output,
	// so the ticket passes only through the tier's own input and output rates.
	add("a long ticket passes only through the tier's own rates", func(sc *reservePriceScenario) {
		m := model(sc)
		m.LongContextThresholdTokens = 500
		m.LongContextInputRateUSDPer1M, m.LongContextOutputRateUSDPer1M = f64ptr(5), f64ptr(10)
		sc.Ticket.InputRate, sc.Ticket.OutputRate = 5_000_000, 18_000_000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	add("a cache-read rate above the advertised one is refused", func(sc *reservePriceScenario) {
		model(sc).CacheReadRateUSDPer1M = f64ptr(0.5)
		sc.Ticket.CacheReadRate = 1_500_000
	})
	add("a long ticket's cache-read rate is bounded by the tier's", func(sc *reservePriceScenario) {
		m := model(sc)
		m.LongContextThresholdTokens = 500
		m.LongContextInputRateUSDPer1M, m.LongContextOutputRateUSDPer1M = f64ptr(4), f64ptr(8)
		m.LongContextCacheReadRateUSDPer1M = f64ptr(0.5)
		sc.Ticket.InputRate, sc.Ticket.OutputRate, sc.Ticket.CacheReadRate = 4_000_000, 8_000_000, 1_500_000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	add("a zero fee still runs the gate", func(sc *reservePriceScenario) {
		sc.FeeBps = feePtr(0)
		sc.Ticket.MaxPrice = 5000
	})
	add("an advertised cache-read rate of 0 is a bound, not an absence", func(sc *reservePriceScenario) {
		model(sc).CacheReadRateUSDPer1M = f64ptr(0)
	})
	add("a per-call token headroom rounds up", func(sc *reservePriceScenario) {
		m := model(sc)
		m.InputRateUSDPer1M = 1.5
		m.VendorToolCallCap = 3
		m.VendorToolTokensPerCall = 1
		sc.Ticket.InputRate = 1_500_000
		// 3 tokens at 1.5 microUSDC each is 4.5, which the node rounds to 5.
		sc.Ticket = withMaxPrice(sc.Ticket, 5, 100)
	})
	add("a zs_ rate does not count toward the vendor rate", func(sc *reservePriceScenario) {
		m := model(sc)
		m.ToolCallRatesMicroUSDC = map[string]uint64{"zs_web_read": 500, "web_search": 100}
		m.VendorToolCallCap = 2
		sc.Details.MaxToolIterations = 4
		sc.Ticket = withMaxPrice(sc.Ticket, 2200, 100)
	})
	add("a model listed twice is priced by its last entry", func(sc *reservePriceScenario) {
		first := inject.OperatorDetailsModel{ID: "m", InputRateUSDPer1M: 1, OutputRateUSDPer1M: 1}
		sc.Details.Models = append([]inject.OperatorDetailsModel{first}, sc.Details.Models...)
	})
	// Each part fits a uint64; only their sum overflows.
	add("tool headroom parts whose sum overflows fail open", func(sc *reservePriceScenario) {
		m := model(sc)
		m.ToolCallRatesMicroUSDC = map[string]uint64{"zs_x": 1 << 52}
		m.VendorToolCatchAllMicroUSDC = 1 << 52
		m.VendorToolCallCap = 2048
		sc.Details.MaxToolIterations = 2048
		sc.Ticket.InputRate = 5_000_000
		sc.Ticket.MaxPrice = 5000
	})
	add("an advertised minimum charge above the token floor raises the min_price bound", func(sc *reservePriceScenario) {
		sc.Details.MinChargeMicroUSDC = 10_000
		sc.Ticket.MinPrice = 15_000
		sc.Ticket = withMaxPrice(sc.Ticket, 0, 100)
	})
	return out
}

func runReservePriceScenario(sc reservePriceScenario) *reservePriceWant {
	op := Operator{
		ModelCapacities:       map[string]ModelCapacity{},
		MaxToolIters:          sc.Details.MaxToolIterations,
		MinChargeOutputTokens: sc.Details.MinChargeOutputTokens,
		MinChargeMicroUSDC:    sc.Details.MinChargeMicroUSDC,
	}
	for _, m := range sc.Details.Models {
		op.ModelCapacities[m.ID] = modelCapacityOf(m)
	}
	req := ticket.ReserveRequest{
		Model:               sc.Model,
		InputCount:          sc.ReserveInputCount,
		ImageToolBudget:     sc.ImageToolBudget,
		ImageEditToolBudget: sc.ImageEditToolBudget,
	}
	tk := sc.Ticket
	v := reservePriceViolation(op, req, &tk, func() (uint64, bool) {
		if sc.FeeBps == nil {
			return 0, false
		}
		return *sc.FeeBps, true
	})
	if v == nil {
		return nil
	}
	return &reservePriceWant{Check: v.Check, Field: v.Field, Want: v.Want, Got: v.Got}
}

func TestReservePriceVectors(t *testing.T) {
	scenarios := reservePriceScenarios()
	for i := range scenarios {
		scenarios[i].Want = runReservePriceScenario(scenarios[i])
	}
	f := struct {
		Comment   string                 `json:"comment"`
		Scenarios []reservePriceScenario `json:"scenarios"`
	}{
		Comment:   "Generated by proto/go/zs TestReservePriceVectors. Compare want exactly; a violation's detail is not pinned.",
		Scenarios: scenarios,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(reservePriceVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(reservePriceVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("reserve price differs from %s; if the change is intended, regenerate with -update and review the diff", reservePriceVectorsPath)
	}
}
