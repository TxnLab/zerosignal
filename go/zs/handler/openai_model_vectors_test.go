/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

// Generates / verifies proto/testdata/openai_model_vectors.json: the GET
// /v1/models entry the SDK serves for one aggregated model (modelEntryFor over
// inject.OpenAIModelFromDetails), at a known protocol fee or a cold one. It
// pins the USD-per-token rendering, the payer-net gross-up, the cases that
// publish no price, and the Hugging Face id. The TS SDK replays it against
// ts/src/inject/openaimodel.ts and sdk/src/fetch/models.ts.
//
//	cd proto/go && go test ./zs/handler -run TestOpenAIModelVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/inject"
)

const openAIModelVectorsPath = "../../../testdata/openai_model_vectors.json"

type openAIModelCase struct {
	Name    string                      `json:"name"`
	Details inject.OperatorDetailsModel `json:"details"`
	// FeeBps nil is a fee the SDK has not read yet.
	FeeBps *uint64            `json:"fee_bps"`
	Want   inject.OpenAIModel `json:"want"`
}

func openAIModelCases() []openAIModelCase {
	fee := func(v uint64) *uint64 { return &v }
	chat := func(in, out float64) inject.OperatorDetailsModel {
		return inject.OperatorDetailsModel{ID: "m", InputRateUSDPer1M: in, OutputRateUSDPer1M: out}
	}
	with := func(d inject.OperatorDetailsModel, f func(*inject.OperatorDetailsModel)) inject.OperatorDetailsModel {
		f(&d)
		return d
	}
	src := func(s string) inject.OperatorDetailsModel {
		return with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.Source = s })
	}
	return []openAIModelCase{
		{Name: "a bare id", Details: inject.OperatorDetailsModel{ID: "m"}, FeeBps: fee(0)},
		{Name: "rates render per token in decimal, never as a float quotient", Details: chat(0.1, 0.3), FeeBps: fee(0)},
		{Name: "a whole-dollar rate", Details: chat(3, 15), FeeBps: fee(0)},
		{Name: "a rate under a microdollar per token keeps its digits", Details: chat(0.000123, 0.0000001), FeeBps: fee(0)},
		{Name: "a large rate renders without an exponent", Details: chat(1234567.891, 5e21), FeeBps: fee(0)},
		{Name: "rates are grossed up by the protocol fee, to the microdollar", Details: chat(0.1, 3), FeeBps: fee(250)},
		{Name: "a fee that leaves a rate between microdollars rounds it", Details: chat(0.0000033, 1.2345674), FeeBps: fee(333)},
		{Name: "a cold fee publishes no price", Details: chat(1, 2), FeeBps: nil},
		{Name: "a zero input rate publishes no price", Details: chat(0, 2), FeeBps: fee(100)},
		{Name: "a zero output rate publishes no price", Details: chat(1, 0), FeeBps: fee(100)},
		{Name: "a discounted cache read is grossed up with the rates",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.CacheReadRateUSDPer1M = new(0.25) }), FeeBps: fee(1000)},
		{Name: "a free cache read renders as 0",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.CacheReadRateUSDPer1M = new(0.0) }), FeeBps: fee(1000)},
		{Name: "a dedicated image route publishes no token price",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) {
				d.ServesImageGen, d.ImageRateMicroUSDC, d.OutputModalities = true, 40000, []string{"image"}
			}), FeeBps: fee(0)},
		{Name: "an image-edit route publishes no token price",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.ServesImageEdit = true }), FeeBps: fee(0)},
		{Name: "real token rates beside an in-loop image tool keep their price",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.ImageToolRateMicroUSDC = 40000 }), FeeBps: fee(0)},
		{Name: "context and output ceilings fill context_length and top_provider",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.ContextWindow, d.MaxOutputTokens = 131072, 8192 }), FeeBps: fee(0)},
		{Name: "an output ceiling alone still fills top_provider",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) { d.MaxOutputTokens = 8192 }), FeeBps: fee(0)},
		{Name: "modalities fill architecture",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) {
				d.InputModalities, d.OutputModalities = []string{"text", "image"}, []string{"text"}
			}), FeeBps: fee(0)},
		{Name: "reasoning and tool_use ride as the details carry them",
			Details: with(chat(1, 2), func(d *inject.OperatorDetailsModel) {
				d.Reasoning = &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}}
				d.ToolUse = new(false)
			}), FeeBps: fee(0)},
		{Name: "an hf source becomes the repo id, revision dropped", Details: src("hf:Org/Model-1.5_b@main"), FeeBps: fee(0)},
		{Name: "an hf source is trimmed first", Details: src("  hf:org/model  "), FeeBps: fee(0)},
		{Name: "a source with another scheme gives no repo id", Details: src("gguf:org/model"), FeeBps: fee(0)},
		{Name: "a three-segment source gives no repo id", Details: src("hf:org/model/extra"), FeeBps: fee(0)},
		{Name: "a source with a space in a segment gives no repo id", Details: src("hf:org/my model"), FeeBps: fee(0)},
		{Name: "a source missing its model gives no repo id", Details: src("hf:org/"), FeeBps: fee(0)},
		{Name: "a source with a query string gives no repo id", Details: src("hf:org/model?x=1"), FeeBps: fee(0)},
		{Name: "the canonical id rides only without a repo id",
			Details: with(src("hf:org/model"), func(d *inject.OperatorDetailsModel) { d.CanonicalID = "org/model" }), FeeBps: fee(0)},
		{Name: "a canonical id beside an unusable source rides",
			Details: with(src("hf:org/"), func(d *inject.OperatorDetailsModel) { d.CanonicalID = "model-x" }), FeeBps: fee(0)},
	}
}

// openAIBuilderCase is inject.OpenAIModelFromDetails on its own, which
// modelEntryFor hides in part: it drops the price whenever a rate is 0, so
// the free-token shapes that price off the token rates never reach it.
type openAIBuilderCase struct {
	Name    string                      `json:"name"`
	Details inject.OperatorDetailsModel `json:"details"`
	Want    inject.OpenAIModel          `json:"want"`
}

const openAIBuilderCreated = 1700000000

func openAIBuilderCases() []openAIBuilderCase {
	free := func(f func(*inject.OperatorDetailsModel)) inject.OperatorDetailsModel {
		d := inject.OperatorDetailsModel{ID: "m"}
		f(&d)
		return d
	}
	out := []openAIBuilderCase{
		{Name: "free tokens with nothing else priced publish a zero price", Details: free(func(*inject.OperatorDetailsModel) {})},
		{Name: "free tokens beside an in-loop image tool publish no price",
			Details: free(func(d *inject.OperatorDetailsModel) { d.ImageToolRateMicroUSDC = 40000 })},
		{Name: "free tokens beside an in-loop image-edit tool publish no price",
			Details: free(func(d *inject.OperatorDetailsModel) { d.ImageEditToolRateMicroUSDC = 40000 })},
		{Name: "free tokens beside a per-call tool rate publish no price",
			Details: free(func(d *inject.OperatorDetailsModel) {
				d.ToolCallRatesMicroUSDC = map[string]uint64{"zs_web_search": 5000}
			})},
		{Name: "an image route with token rates publishes no price",
			Details: inject.OperatorDetailsModel{ID: "m", InputRateUSDPer1M: 1, OutputRateUSDPer1M: 2, ServesImageGen: true}},
	}
	for _, c := range openAIModelCases() {
		out = append(out, openAIBuilderCase{Name: c.Name, Details: c.Details})
	}
	return out
}

func TestOpenAIModelVectors(t *testing.T) {
	cases := openAIModelCases()
	for i := range cases {
		c := &cases[i]
		grossFactor, feeKnown := 1.0, false
		if c.FeeBps != nil {
			grossFactor, feeKnown = 1+float64(*c.FeeBps)/float64(escrow.BpsDenominator), true
		}
		c.Want = modelEntryFor(c.Details, grossFactor, feeKnown)
	}
	builder := openAIBuilderCases()
	for i := range builder {
		builder[i].Want = inject.OpenAIModelFromDetails(builder[i].Details, modelsOwnedBy, openAIBuilderCreated)
	}
	f := struct {
		Comment string              `json:"comment"`
		Owner   string              `json:"owned_by"`
		Cases   []openAIModelCase   `json:"cases"`
		Created int64               `json:"builder_created"`
		Builder []openAIBuilderCase `json:"builder"`
	}{
		Comment: "Generated by proto/go/zs/handler TestOpenAIModelVectors. want is the GET /v1/models entry for one aggregated model (details, as /v1/zs/details carries it) when the payer's protocol fee is fee_bps; null is a fee not read yet. Entries carry created 0 and owned_by as given. builder is inject.OpenAIModelFromDetails alone, at owned_by and builder_created, with no fee and no zero-rate rule.",
		Owner:   modelsOwnedBy,
		Cases:   cases,
		Created: openAIBuilderCreated,
		Builder: builder,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')
	if *updateVectors {
		if err := os.WriteFile(openAIModelVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(openAIModelVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("/v1/models entries differ from %s; if the change is intended, regenerate with -update and review the diff", openAIModelVectorsPath)
	}
}
