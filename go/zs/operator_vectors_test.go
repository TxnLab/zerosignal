/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/operator_vectors.json: a node's
// /v1/zs/details advertisement as the registry copies it onto an Operator
// (applyDetailsFields, modelCapacityOf) and the routing descriptor projected
// from it (Operator.Selection). The TS SDK mirrors them as detailsFieldsOf,
// modelCapacityOf and selectionOf in sdk/src/operator.ts. Keys are the SDK's
// field names, so a TS test compares its output to want as is.
//
//	cd proto/go && go test ./zs -run TestOperatorVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/tools"
)

const operatorVectorsPath = "../../testdata/operator_vectors.json"

// operatorVectorNode is what the registry knows of a node apart from its
// details: the chain record and the payer's own TEE verdict.
type operatorVectorNode struct {
	ID                        uint64  `json:"id"`
	NodeID                    uint64  `json:"node_id"`
	OwnerAddr                 string  `json:"owner_addr"`
	BaseURL                   string  `json:"base_url"`
	Reachable                 bool    `json:"reachable"`
	Staging                   bool    `json:"staging"`
	SignerSpendableMicroAlgos *uint64 `json:"signer_spendable_microalgos"`
	// TEEVerified is the verdict, or null when the node advertises no TEE.
	TEEVerified *bool `json:"tee_verified"`
}

type capacityVector struct {
	ContextWindow                uint64                   `json:"contextWindow"`
	MaxOutputTokens              uint64                   `json:"maxOutputTokens"`
	InputModalities              []string                 `json:"inputModalities,omitempty"`
	OutputModalities             []string                 `json:"outputModalities,omitempty"`
	InputUSDPer1M                float64                  `json:"inputUsdPer1m"`
	OutputUSDPer1M               float64                  `json:"outputUsdPer1m"`
	CacheReadUSDPer1M            *float64                 `json:"cacheReadUsdPer1m,omitempty"`
	LongContextThresholdTokens   uint64                   `json:"longContextThresholdTokens"`
	LongContextInputUSDPer1M     *float64                 `json:"longContextInputUsdPer1m,omitempty"`
	LongContextOutputUSDPer1M    *float64                 `json:"longContextOutputUsdPer1m,omitempty"`
	LongContextCacheReadUSDPer1M *float64                 `json:"longContextCacheReadUsdPer1m,omitempty"`
	Reasoning                    *inject.ModelReasoning   `json:"reasoning,omitempty"`
	ToolUse                      *bool                    `json:"toolUse,omitempty"`
	Tags                         []string                 `json:"tags,omitempty"`
	Coordinates                  *inject.ModelCoordinates `json:"coordinates,omitempty"`
	WeightsDigest                string                   `json:"weightsDigest"`
	WeightsUnverifiable          bool                     `json:"weightsUnverifiable"`
	Source                       string                   `json:"source"`
	CanonicalID                  string                   `json:"canonicalId"`
	Retention                    string                   `json:"retention"`
	ImageToolRateMicroUSDC       uint64                   `json:"imageToolRateMicroUsdc"`
	ImageEditToolRateMicroUSDC   uint64                   `json:"imageEditToolRateMicroUsdc"`
	ImageToolBaseMicroUSDC       uint64                   `json:"imageToolBaseMicroUsdc"`
	ImageEditToolBaseMicroUSDC   uint64                   `json:"imageEditToolBaseMicroUsdc"`
	ImageRateMicroUSDC           uint64                   `json:"imageRateMicroUsdc"`
	ImageEditRateMicroUSDC       uint64                   `json:"imageEditRateMicroUsdc"`
	ImageDefaultMicroUSDC        uint64                   `json:"imageDefaultMicroUsdc"`
	ImageEditDefaultMicroUSDC    uint64                   `json:"imageEditDefaultMicroUsdc"`
	ImageCapMicroUSDC            uint64                   `json:"imageCapMicroUsdc"`
	ImageEditCapMicroUSDC        uint64                   `json:"imageEditCapMicroUsdc"`
	AdvertisesImageGen           bool                     `json:"advertisesImageGen"`
	AdvertisesImageEdit          bool                     `json:"advertisesImageEdit"`
	ToolCallRatesMicroUSDC       map[string]uint64        `json:"toolCallRatesMicroUsdc,omitempty"`
	VendorToolCatchAllMicroUSDC  uint64                   `json:"vendorToolCatchAllMicroUsdc"`
	VendorToolCallCap            uint64                   `json:"vendorToolCallCap"`
	VendorToolTokensPerCall      uint64                   `json:"vendorToolTokensPerCall"`
}

func capacityVectorOf(c ModelCapacity) capacityVector {
	return capacityVector{
		ContextWindow: c.ContextWindow, MaxOutputTokens: c.MaxOutputTokens,
		InputModalities: c.InputModalities, OutputModalities: c.OutputModalities,
		InputUSDPer1M: c.InputUSDPer1M, OutputUSDPer1M: c.OutputUSDPer1M, CacheReadUSDPer1M: c.CacheReadUSDPer1M,
		LongContextThresholdTokens: c.LongContextThresholdTokens,
		LongContextInputUSDPer1M:   c.LongContextInputUSDPer1M, LongContextOutputUSDPer1M: c.LongContextOutputUSDPer1M,
		LongContextCacheReadUSDPer1M: c.LongContextCacheReadUSDPer1M,
		Reasoning:                    c.Reasoning, ToolUse: c.ToolUse, Tags: c.Tags, Coordinates: c.Coordinates,
		WeightsDigest: c.WeightsDigest, WeightsUnverifiable: c.WeightsUnverifiable,
		Source: c.Source, CanonicalID: c.CanonicalID, Retention: c.Retention,
		ImageToolRateMicroUSDC: c.ImageToolRateMicroUSDC, ImageEditToolRateMicroUSDC: c.ImageEditToolRateMicroUSDC,
		ImageToolBaseMicroUSDC: c.ImageToolBaseMicroUSDC, ImageEditToolBaseMicroUSDC: c.ImageEditToolBaseMicroUSDC,
		ImageRateMicroUSDC: c.ImageRateMicroUSDC, ImageEditRateMicroUSDC: c.ImageEditRateMicroUSDC,
		ImageDefaultMicroUSDC: c.ImageDefaultMicroUSDC, ImageEditDefaultMicroUSDC: c.ImageEditDefaultMicroUSDC,
		ImageCapMicroUSDC: c.ImageCapMicroUSDC, ImageEditCapMicroUSDC: c.ImageEditCapMicroUSDC,
		AdvertisesImageGen: c.AdvertisesImageGen, AdvertisesImageEdit: c.AdvertisesImageEdit,
		ToolCallRatesMicroUSDC:      c.ToolCallRatesMicroUSDC,
		VendorToolCatchAllMicroUSDC: c.VendorToolCatchAllMicroUSDC,
		VendorToolCallCap:           c.VendorToolCallCap, VendorToolTokensPerCall: c.VendorToolTokensPerCall,
	}
}

type builtinToolVector struct {
	Type string `json:"type"`
}

type detailsFieldsVector struct {
	Models                   []string                  `json:"models"`
	ModelCapacities          map[string]capacityVector `json:"modelCapacities"`
	BuiltinTools             []builtinToolVector       `json:"builtinTools"`
	MaxToolIters             int                       `json:"maxToolIters"`
	ToolHeadroomPerIteration uint64                    `json:"toolHeadroomPerIteration"`
	ProtoVersion             string                    `json:"protoVersion"`
	MinChargeOutputTokens    uint64                    `json:"minChargeOutputTokens"`
	MinChargeAlgoTxns        uint64                    `json:"minChargeAlgoTxns"`
	MinChargeMicroUSDC       uint64                    `json:"minChargeMicroUsdc"`
}

type operatorScenario struct {
	Name    string                 `json:"name"`
	Node    operatorVectorNode     `json:"node"`
	Details inject.OperatorDetails `json:"details"`
	// Fields is what applyDetailsFields copies onto the operator, and
	// Selection the descriptor Operator.Selection projects from the result.
	Fields    detailsFieldsVector `json:"fields"`
	Selection selection.Operator  `json:"selection"`
}

func operatorScenarios() []operatorScenario {
	u64 := func(v uint64) *uint64 { return &v }
	yes, no := true, false
	base := func(name string) operatorScenario {
		return operatorScenario{
			Name: name,
			Node: operatorVectorNode{ID: 7, NodeID: 2, OwnerAddr: "OWNER", BaseURL: "https://node.example.com", Reachable: true},
			Details: inject.OperatorDetails{
				Models:       []inject.OperatorDetailsModel{{ID: "m", InputRateUSDPer1M: 2, OutputRateUSDPer1M: 4, ContextWindow: 128000}},
				ProtoVersion: "9.10",
			},
		}
	}
	var out []operatorScenario
	add := func(name string, edit func(*operatorScenario)) {
		sc := base(name)
		edit(&sc)
		out = append(out, sc)
	}
	model := func(sc *operatorScenario) *inject.OperatorDetailsModel { return &sc.Details.Models[0] }

	add("a plain token model", func(*operatorScenario) {})
	add("every token field is carried", func(sc *operatorScenario) {
		m := model(sc)
		m.MaxOutputTokens = 32768
		m.InputModalities, m.OutputModalities = []string{"text", "image"}, []string{"text"}
		m.CacheReadRateUSDPer1M = f64ptr(0.5)
		m.LongContextThresholdTokens = 200000
		m.LongContextInputRateUSDPer1M, m.LongContextOutputRateUSDPer1M = f64ptr(4), f64ptr(8)
		m.LongContextCacheReadRateUSDPer1M = f64ptr(1)
		m.Reasoning = &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}, DefaultEffort: "low"}
		m.ToolUse = &yes
		m.Tags = []string{"code"}
		m.Coordinates = &inject.ModelCoordinates{Family: "qwen3", Parameters: 32, Quantization: "Q8_0"}
		m.WeightsDigest = "sha256:abc"
		m.Source = "hf:Qwen/Qwen3-32B"
		m.CanonicalID = "qwen/qwen3-32b"
		m.Retention = inject.RetentionNoUpstream
	})
	add("an advertised cache-read rate of 0 is kept", func(sc *operatorScenario) { model(sc).CacheReadRateUSDPer1M = f64ptr(0) })
	add("a retention tier this build does not know is dropped", func(sc *operatorScenario) { model(sc).Retention = "trust_me" })
	add("a reasoning model the node says cannot reason projects no flag", func(sc *operatorScenario) {
		model(sc).Reasoning = &inject.ModelReasoning{Supported: false}
	})
	add("an unverifiable weights claim is carried", func(sc *operatorScenario) { model(sc).WeightsUnverifiable = true })
	add("a dedicated image model serves on its rate alone", func(sc *operatorScenario) {
		m := model(sc)
		m.InputRateUSDPer1M, m.OutputRateUSDPer1M = 0, 0
		m.ImageRateMicroUSDC, m.ImageDefaultMicroUSDC, m.ImageCapMicroUSDC = 40000, 40000, 160000
		m.ServesImageEdit = true
	})
	add("a free dedicated image route is served by its flag", func(sc *operatorScenario) {
		m := model(sc)
		m.ServesImageGen = true
		m.ImageEditRateMicroUSDC, m.ImageEditDefaultMicroUSDC, m.ImageEditCapMicroUSDC = 50000, 50000, 200000
	})
	add("in-loop image tools are offered by their rates", func(sc *operatorScenario) {
		m := model(sc)
		m.ImageToolRateMicroUSDC, m.ImageToolBaseMicroUSDC = 30000, 1000
		m.ImageEditToolRateMicroUSDC, m.ImageEditToolBaseMicroUSDC = 35000, 1200
	})
	// Rate, default, cap and tool base each distinct, so no field can stand in
	// for another.
	add("each image price field is its own", func(sc *operatorScenario) {
		m := model(sc)
		m.ImageRateMicroUSDC, m.ImageDefaultMicroUSDC, m.ImageCapMicroUSDC = 40000, 41000, 160000
		m.ImageEditRateMicroUSDC, m.ImageEditDefaultMicroUSDC, m.ImageEditCapMicroUSDC = 50000, 52000, 200000
		m.ImageToolRateMicroUSDC, m.ImageToolBaseMicroUSDC = 30000, 1000
		m.ImageEditToolRateMicroUSDC, m.ImageEditToolBaseMicroUSDC = 35000, 1200
	})
	add("an image rate alone serves and orders the route", func(sc *operatorScenario) {
		model(sc).ImageRateMicroUSDC = 40000
		model(sc).ImageEditRateMicroUSDC = 50000
	})
	add("image defaults and caps alone serve nothing", func(sc *operatorScenario) {
		m := model(sc)
		m.ImageDefaultMicroUSDC, m.ImageCapMicroUSDC = 40000, 160000
		m.ImageEditDefaultMicroUSDC, m.ImageEditCapMicroUSDC = 50000, 200000
	})
	// One route only, so a projection that reads gen for edit (or the reverse)
	// differs.
	add("an image-gen-only model offers no edit route or tool", func(sc *operatorScenario) {
		model(sc).ImageRateMicroUSDC = 40000
		model(sc).ImageToolRateMicroUSDC = 30000
	})
	add("an image-edit-only model offers no gen route or tool", func(sc *operatorScenario) {
		model(sc).ServesImageEdit = true
		model(sc).ImageEditToolRateMicroUSDC = 35000
	})
	add("an image-tool base alone offers no tool", func(sc *operatorScenario) {
		model(sc).ImageToolBaseMicroUSDC = 1000
		model(sc).ImageEditToolBaseMicroUSDC = 1200
	})
	add("a model id that names an object prototype is an ordinary model", func(sc *operatorScenario) {
		sc.Details.Models = append(sc.Details.Models,
			inject.OperatorDetailsModel{ID: "__proto__", InputRateUSDPer1M: 3, OutputRateUSDPer1M: 5},
			inject.OperatorDetailsModel{ID: "constructor", InputRateUSDPer1M: 1, OutputRateUSDPer1M: 1})
	})
	add("tool-call rates and the vendor terms are carried", func(sc *operatorScenario) {
		m := model(sc)
		m.ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 6000, "zs_web_read": 500}
		m.VendorToolCatchAllMicroUSDC, m.VendorToolCallCap, m.VendorToolTokensPerCall = 3000, 10, 1000
		sc.Details.MaxToolIterations = 4
		sc.Details.ToolHeadroomPerIteration = 4096
		sc.Details.BuiltinTools = []tools.BuiltinToolAdvert{{Type: "zs_web_search"}, {Type: "zs_web_read"}}
	})
	add("the minimum charge is carried", func(sc *operatorScenario) {
		sc.Details.MinChargeOutputTokens, sc.Details.MinChargeAlgoTxns, sc.Details.MinChargeMicroUSDC = 1000, 2, 150
	})
	add("a node with no models routes nothing", func(sc *operatorScenario) {
		sc.Details.Models = nil
		sc.Details.ProtoVersion = ""
	})
	add("a model listed twice keeps both ids and the last capacity", func(sc *operatorScenario) {
		sc.Details.Models = append(sc.Details.Models, inject.OperatorDetailsModel{ID: "m", InputRateUSDPer1M: 1, OutputRateUSDPer1M: 1})
	})
	add("a staging node with a broke signer", func(sc *operatorScenario) {
		sc.Node.Staging = true
		sc.Node.SignerSpendableMicroAlgos = u64(0)
	})
	add("a funded signer is projected", func(sc *operatorScenario) { sc.Node.SignerSpendableMicroAlgos = u64(12_000_000) })
	add("an attested node", func(sc *operatorScenario) { sc.Node.TEEVerified = &yes })
	add("a TEE node whose evidence failed counts as unattested", func(sc *operatorScenario) { sc.Node.TEEVerified = &no })
	add("an unreachable node", func(sc *operatorScenario) { sc.Node.Reachable = false })
	return out
}

func runOperatorScenario(sc *operatorScenario) {
	n := sc.Node
	op := Operator{
		ID: n.ID, NodeID: n.NodeID, OwnerAddr: n.OwnerAddr, BaseURL: n.BaseURL,
		Reachable: n.Reachable, Staging: n.Staging, SignerSpendableMicroAlgos: n.SignerSpendableMicroAlgos,
	}
	if n.TEEVerified != nil {
		op.TEE = &TEEStatus{Verified: *n.TEEVerified}
	}
	applyDetailsFields(&op, sc.Details)

	caps := make(map[string]capacityVector, len(op.ModelCapacities))
	for id, c := range op.ModelCapacities {
		caps[id] = capacityVectorOf(c)
	}
	defs := make([]builtinToolVector, len(op.BuiltinTools))
	for i, t := range op.BuiltinTools {
		defs[i] = builtinToolVector(t)
	}
	sc.Fields = detailsFieldsVector{
		Models: op.Models, ModelCapacities: caps, BuiltinTools: defs,
		MaxToolIters: op.MaxToolIters, ToolHeadroomPerIteration: op.ToolHeadroomPerIteration,
		ProtoVersion:          op.ProtoVersion,
		MinChargeOutputTokens: op.MinChargeOutputTokens, MinChargeAlgoTxns: op.MinChargeAlgoTxns,
		MinChargeMicroUSDC: op.MinChargeMicroUSDC,
	}
	sc.Selection = op.Selection()
}

func TestOperatorVectors(t *testing.T) {
	scenarios := operatorScenarios()
	for i := range scenarios {
		runOperatorScenario(&scenarios[i])
	}
	f := struct {
		Comment   string             `json:"comment"`
		Scenarios []operatorScenario `json:"scenarios"`
	}{
		Comment:   "Generated by proto/go/zs TestOperatorVectors. fields and selection are compared exactly.",
		Scenarios: scenarios,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(operatorVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(operatorVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("operator projection differs from %s; if the change is intended, regenerate with -update and review the diff", operatorVectorsPath)
	}
}

// The vectors leave NodeVersion out, since the SDK's operator does not carry
// it; the registry's node-version listing reads it.
func TestApplyDetailsFields_CarriesNodeVersion(t *testing.T) {
	var op Operator
	applyDetailsFields(&op, inject.OperatorDetails{Version: "0.21.0+abc1234"})
	if op.NodeVersion != "0.21.0+abc1234" {
		t.Fatalf("NodeVersion = %q, want the advertised version", op.NodeVersion)
	}
}
