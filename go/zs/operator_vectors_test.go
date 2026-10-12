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
// probe_attestation is probeAttestation, the TEE verdict as it lands on the
// operator, mirrored by probeAttestation in sdk/src/attestation.ts.
// chain_nodes is the chain read, box bytes to the operator resolveOperatorNode
// builds, mirrored by ChainOperatorSource in sdk/src/registry/chain.ts.
//
//	cd proto/go && go test ./zs -run TestOperatorVectors -update

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/tools"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs/tee"
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
	// TEE is the verdict as it sits on the operator, or null when the node
	// advertises no TEE. Selection.tee_attested is the routing rule read from it.
	TEE *operatorVectorTEE `json:"tee"`
}

type operatorVectorTEE struct {
	Verified              bool `json:"verified"`
	OSImageChecked        bool `json:"os_image_checked"`
	ComposeReleaseChecked bool `json:"compose_release_checked"`
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
	yes := true
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
	// Attested is a pass that rested on both reference checks. Each case below
	// drops one input, so no single field can stand in for the conjunction.
	add("an attested node", func(sc *operatorScenario) {
		sc.Node.TEE = &operatorVectorTEE{Verified: true, OSImageChecked: true, ComposeReleaseChecked: true}
	})
	add("a pass on an untrusted OS image counts as unattested", func(sc *operatorScenario) {
		sc.Node.TEE = &operatorVectorTEE{Verified: true, ComposeReleaseChecked: true}
	})
	add("a pass on a compose that is no published release counts as unattested", func(sc *operatorScenario) {
		sc.Node.TEE = &operatorVectorTEE{Verified: true, OSImageChecked: true}
	})
	add("a pass with no measurement checks counts as unattested", func(sc *operatorScenario) {
		sc.Node.TEE = &operatorVectorTEE{Verified: true}
	})
	add("a TEE node whose evidence failed counts as unattested", func(sc *operatorScenario) {
		sc.Node.TEE = &operatorVectorTEE{OSImageChecked: true, ComposeReleaseChecked: true}
	})
	add("an unreachable node", func(sc *operatorScenario) { sc.Node.Reachable = false })
	return out
}

func runOperatorScenario(sc *operatorScenario) {
	n := sc.Node
	op := Operator{
		ID: n.ID, NodeID: n.NodeID, OwnerAddr: n.OwnerAddr, BaseURL: n.BaseURL,
		Reachable: n.Reachable, Staging: n.Staging, SignerSpendableMicroAlgos: n.SignerSpendableMicroAlgos,
	}
	if n.TEE != nil {
		op.TEE = &TEEStatus{Verified: n.TEE.Verified, OSImageChecked: n.TEE.OSImageChecked, ComposeReleaseChecked: n.TEE.ComposeReleaseChecked}
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

// probeVerdictVector is what the scenario's verifier returns.
// MeasurementChecks is null for a verdict that carries none (a refusal, a stub).
type probeVerdictVector struct {
	Pass              bool                     `json:"pass"`
	FailureTag        string                   `json:"failure_tag"`
	VerifierID        string                   `json:"verifier_id"`
	AttestedAtMs      int64                    `json:"attested_at_ms"`
	AttestedModelIDs  []string                 `json:"attested_model_ids"`
	MeasurementChecks *measurementChecksVector `json:"measurement_checks"`
	UpstreamCarveOuts []string                 `json:"upstream_carve_outs,omitempty"`
}

type measurementChecksVector struct {
	OSImage        bool `json:"os_image"`
	ComposeRelease bool `json:"compose_release"`
	ComposeHash    bool `json:"compose_hash"`
}

// teeStatusVector is a TEEStatus under the SDK's field names, attestedAt in
// Unix milliseconds and 0 for the zero time.
type teeStatusVector struct {
	Mode                  string   `json:"mode"`
	AttestedAt            int64    `json:"attestedAt"`
	VerifierID            string   `json:"verifierId"`
	Verified              bool     `json:"verified"`
	FailureTag            string   `json:"failureTag"`
	OSImageChecked        bool     `json:"osImageChecked"`
	ComposeReleaseChecked bool     `json:"composeReleaseChecked"`
	AttestedModelIDs      []string `json:"attestedModelIds"`
	UpstreamCarveOuts     []string `json:"upstreamCarveOuts,omitempty"`
}

type teeNodeVector struct {
	OperatorID               uint64 `json:"operatorId"`
	NodeID                   uint64 `json:"nodeId"`
	EphemeralRecipientPubkey string `json:"ephemeralRecipientPubkey"`
}

// probeAttestationScenario runs probeAttestation against an attestation
// endpoint answering EndpointStatus with EndpointBody, and a verifier that
// returns Verdict (null: verification is off). One test server is the node
// and, when Relayed, the relay too. "{base}" in the advertised evidence_url
// stands for the node's base URL.
type probeAttestationScenario struct {
	Name               string                   `json:"name"`
	OperatorID         uint64                   `json:"operator_id"`
	NodeID             uint64                   `json:"node_id"`
	EphemeralRecipient string                   `json:"ephemeral_recipient"`
	Advertised         *inject.TEEAdvertisement `json:"advertised"`
	Relayed            bool                     `json:"relayed"`
	Verdict            *probeVerdictVector      `json:"verdict"`
	EndpointStatus     int                      `json:"endpoint_status"`
	EndpointBody       string                   `json:"endpoint_body"`
	// The request the endpoint saw, all '' when it saw none: its method and
	// path, and the inner path and target a relay was asked to forward to.
	RequestMethod      string `json:"request_method"`
	RequestPath        string `json:"request_path"`
	RequestRelayPath   string `json:"request_relay_path"`
	RequestRelayTarget string `json:"request_relay_target"`
	// VerifiedNode is what the verifier was handed, null when it was not called.
	VerifiedNode *teeNodeVector `json:"verified_node"`
	// Want is the operator's TEEStatus, null for none, and Attested whether
	// routing counts it as attested.
	Want     *teeStatusVector `json:"want"`
	Attested bool             `json:"attested"`
}

type stubTEEVerifier struct {
	verdict tee.Verdict
	saw     *tee.Node
}

func (s *stubTEEVerifier) Verify(_ context.Context, _ inject.TEEAdvertisement, _ inject.TEEEvidenceBundle, node tee.Node) tee.Verdict {
	s.saw = &node
	return s.verdict
}

func probeAttestationScenarios() []probeAttestationScenario {
	const bundle = `{"mode":"dstack-tdx","generated_at":"2026-10-01T00:00:00Z","refresh_seconds":1200}`
	advertised := func() *inject.TEEAdvertisement {
		return &inject.TEEAdvertisement{Mode: inject.TEEModeDstackTDX, AttestedAt: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}
	}
	pass := func() *probeVerdictVector {
		return &probeVerdictVector{
			Pass: true, VerifierID: tee.VerifierIDDstack, AttestedAtMs: 1790812800000, AttestedModelIDs: []string{"m", "n"},
			MeasurementChecks: &measurementChecksVector{OSImage: true, ComposeRelease: true},
		}
	}
	base := func(name string) probeAttestationScenario {
		return probeAttestationScenario{
			Name: name, OperatorID: 7, NodeID: 2, EphemeralRecipient: "age1recipient",
			Advertised: advertised(), Verdict: pass(), EndpointStatus: 200, EndpointBody: bundle,
		}
	}
	var out []probeAttestationScenario
	add := func(name string, edit func(*probeAttestationScenario)) {
		sc := base(name)
		edit(&sc)
		out = append(out, sc)
	}
	add("a node advertising no TEE has no status", func(sc *probeAttestationScenario) { sc.Advertised = nil })
	add("verification off leaves every node without a status", func(sc *probeAttestationScenario) { sc.Verdict = nil })
	add("a passing verdict is copied, with its attested models", func(*probeAttestationScenario) {})
	add("a pass on both checks and a compose pin is attested", func(sc *probeAttestationScenario) {
		sc.Verdict.MeasurementChecks.ComposeHash = true
	})
	// A hand-pinned compose hash identifies a deployment, not a published
	// release, so it does not stand in for the release match.
	add("a pass on a pinned compose hash without the release match is not attested", func(sc *probeAttestationScenario) {
		sc.Verdict.MeasurementChecks = &measurementChecksVector{OSImage: true, ComposeHash: true}
	})
	add("a pass on the compose release alone is not attested", func(sc *probeAttestationScenario) {
		sc.Verdict.MeasurementChecks = &measurementChecksVector{ComposeRelease: true}
	})
	add("a pass with no measurement checks is not attested", func(sc *probeAttestationScenario) {
		sc.Verdict.MeasurementChecks = nil
	})
	add("a failing verdict is not attested whatever checks it carries", func(sc *probeAttestationScenario) {
		sc.Verdict.Pass = false
		sc.Verdict.FailureTag = tee.FailureAuxBindingMismatch
		sc.Verdict.AttestedModelIDs = nil
	})
	add("the evidence time is the verdict's, not the advertisement's", func(sc *probeAttestationScenario) {
		sc.Verdict.AttestedAtMs = 1790813400000
	})
	// The mode is the claim the evidence was checked against, never the bundle's word.
	add("the mode is the advertised one, whatever the bundle says", func(sc *probeAttestationScenario) {
		sc.EndpointBody = `{"mode":"stub","generated_at":"2026-10-01T00:00:00Z","refresh_seconds":1200}`
	})
	add("a passing verdict's upstream carve-outs are copied", func(sc *probeAttestationScenario) {
		sc.Verdict.UpstreamCarveOuts = []string{"root_backdoor_env:DSTACK_ROOT_PUBLIC_KEY"}
	})
	add("a signed empty catalog stays an empty list", func(sc *probeAttestationScenario) { sc.Verdict.AttestedModelIDs = []string{} })
	add("a failing verdict keeps its tag and evidence time", func(sc *probeAttestationScenario) {
		sc.Verdict = &probeVerdictVector{FailureTag: tee.FailureMeasurementMismatch, VerifierID: tee.VerifierIDDstack, AttestedAtMs: 1790812800000}
	})
	add("a verdict with no evidence time reports none", func(sc *probeAttestationScenario) {
		sc.Verdict = &probeVerdictVector{FailureTag: tee.FailureStaleEvidence, VerifierID: tee.VerifierIDBuiltin}
	})
	add("a node with no verified recipient is not fetched, and reads ephemeral_unavailable", func(sc *probeAttestationScenario) {
		sc.EphemeralRecipient = ""
	})
	add("ephemeral_unavailable with no advertised time reports none", func(sc *probeAttestationScenario) {
		sc.EphemeralRecipient = ""
		sc.Advertised.AttestedAt = time.Time{}
	})
	add("a relayed probe of a node with no verified recipient asks the relay for nothing", func(sc *probeAttestationScenario) {
		sc.Relayed = true
		sc.EphemeralRecipient = ""
	})
	// Neither advertising no TEE nor verification off may turn into a status
	// for want of a recipient: both come first.
	add("a node advertising no TEE and with no verified recipient has no status", func(sc *probeAttestationScenario) {
		sc.Advertised = nil
		sc.EphemeralRecipient = ""
	})
	add("verification off leaves a node with no verified recipient without a status", func(sc *probeAttestationScenario) {
		sc.Verdict = nil
		sc.EphemeralRecipient = ""
	})
	add("an error status is fetch_failed at the advertised time", func(sc *probeAttestationScenario) { sc.EndpointStatus = 404 })
	add("a server error is fetch_failed too", func(sc *probeAttestationScenario) { sc.EndpointStatus = 503 })
	add("fetch_failed with no advertised time reports none", func(sc *probeAttestationScenario) {
		sc.EndpointStatus = 500
		sc.Advertised.AttestedAt = time.Time{}
	})
	add("a body that is not a bundle is fetch_failed", func(sc *probeAttestationScenario) { sc.EndpointBody = "<html>" })
	add("a relative evidence URL is a path on the base", func(sc *probeAttestationScenario) { sc.Advertised.EvidenceURL = "attest/v2" })
	add("an evidence path is used as given", func(sc *probeAttestationScenario) { sc.Advertised.EvidenceURL = "/custom/evidence" })
	add("an absolute evidence URL is used as given", func(sc *probeAttestationScenario) { sc.Advertised.EvidenceURL = "{base}/abs/evidence" })
	add("a relayed probe asks the relay for the standard path", func(sc *probeAttestationScenario) { sc.Relayed = true })
	add("a relayed probe ignores an advertised evidence path", func(sc *probeAttestationScenario) {
		sc.Relayed = true
		sc.Advertised.EvidenceURL = "/custom/evidence"
	})
	add("a relayed error status is fetch_failed", func(sc *probeAttestationScenario) {
		sc.Relayed = true
		sc.EndpointStatus = 502
	})
	return out
}

func runProbeAttestationScenario(t *testing.T, sc *probeAttestationScenario) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sc.RequestMethod = r.Method
		sc.RequestPath = r.URL.Path
		sc.RequestRelayPath = r.Header.Get(wire.RelayPathHeader)
		sc.RequestRelayTarget = r.Header.Get(wire.RelayTargetHeader)
		w.WriteHeader(sc.EndpointStatus)
		_, _ = io.WriteString(w, sc.EndpointBody)
	}))
	defer srv.Close()

	var hop *RelayHop
	if sc.Relayed {
		hop = &RelayHop{BaseURL: srv.URL, TargetID: sc.OperatorID, TargetNodeID: sc.NodeID, RelayID: 9, RelayNodeID: 1}
	}
	details := inject.OperatorDetails{}
	if sc.Advertised != nil {
		advertised := *sc.Advertised
		advertised.EvidenceURL = strings.ReplaceAll(advertised.EvidenceURL, "{base}", srv.URL)
		details.TEE = &advertised
	}

	s := &ChainOperatorSource{}
	var stub *stubTEEVerifier
	if sc.Verdict != nil {
		v := tee.Verdict{
			Pass: sc.Verdict.Pass, FailureTag: sc.Verdict.FailureTag, VerifierID: sc.Verdict.VerifierID,
			AttestedModelIDs: sc.Verdict.AttestedModelIDs, UpstreamCarveOuts: sc.Verdict.UpstreamCarveOuts,
		}
		if c := sc.Verdict.MeasurementChecks; c != nil {
			v.MeasurementChecks = &tee.MeasurementChecks{OSImage: c.OSImage, ComposeRelease: c.ComposeRelease, ComposeHash: c.ComposeHash}
		}
		if sc.Verdict.AttestedAtMs != 0 {
			v.AttestedAt = time.UnixMilli(sc.Verdict.AttestedAtMs).UTC()
		}
		stub = &stubTEEVerifier{verdict: v}
		s.TEEVerifier = stub
	}
	op := Operator{ID: sc.OperatorID, NodeID: sc.NodeID, BaseURL: srv.URL, EphemeralRecipientPubkey: sc.EphemeralRecipient}
	s.probeAttestation(context.Background(), &op, details, NewAttestationClient(srv.Client(), 5*time.Second), hop, slog.New(slog.DiscardHandler))

	if stub != nil && stub.saw != nil {
		sc.VerifiedNode = &teeNodeVector{OperatorID: stub.saw.OperatorID, NodeID: stub.saw.NodeID, EphemeralRecipientPubkey: stub.saw.EphemeralRecipientPubkey}
	}
	if op.TEE != nil {
		var ms int64
		if !op.TEE.AttestedAt.IsZero() {
			ms = op.TEE.AttestedAt.UnixMilli()
		}
		sc.Want = &teeStatusVector{
			Mode: op.TEE.Mode, AttestedAt: ms, VerifierID: op.TEE.VerifierID, Verified: op.TEE.Verified,
			FailureTag:     op.TEE.FailureTag,
			OSImageChecked: op.TEE.OSImageChecked, ComposeReleaseChecked: op.TEE.ComposeReleaseChecked,
			AttestedModelIDs:  op.TEE.AttestedModelIDs,
			UpstreamCarveOuts: op.TEE.UpstreamCarveOuts,
		}
	}
	sc.Attested = op.IsTEEAttested()
	if sc.Want != nil && sc.Want.FailureTag == tee.FailureFetchFailed && sc.RequestPath == "" {
		t.Fatalf("%s: fetch_failed without a request", sc.Name)
	}
	if sc.Want != nil && sc.Want.FailureTag == tee.FailureEphemeralUnavailable && (sc.RequestPath != "" || sc.VerifiedNode != nil) {
		t.Fatalf("%s: ephemeral_unavailable after a fetch or a verify", sc.Name)
	}
}

// chainNodeScenario is one operator box and one of its node boxes as algod
// lists them, read on CurrentDay (Unix seconds / 86400). Want is the operator
// resolveOperatorNode builds, null when the node is left out; Skipped says why:
// "evicted" when the node fetch leaves an evicted operator's nodes out, or
// "base_url" when resolveOperatorNode refuses the URL. A signing address that
// won't decode has no case: the box holds 32 raw bytes, which always encode to
// a valid address.
type chainNodeScenario struct {
	Name           string           `json:"name"`
	CurrentDay     uint64           `json:"current_day"`
	OperatorID     uint64           `json:"operator_id"`
	OperatorBoxHex string           `json:"operator_box_hex"`
	NodeID         uint64           `json:"node_id"`
	NodeBoxHex     string           `json:"node_box_hex"`
	Want           *chainNodeVector `json:"want"`
	Skipped        string           `json:"skipped"`

	op   escrow.OperatorRecord
	node escrow.NodeRecord
}

// chainNodeVector is the chain-derived part of an Operator under the SDK's
// field names.
type chainNodeVector struct {
	ID                  uint64             `json:"id"`
	NodeID              uint64             `json:"nodeId"`
	NFDAppID            uint64             `json:"nfdAppId"`
	OwnerAddr           string             `json:"ownerAddr"`
	SigningAddr         string             `json:"signingAddr"`
	TicketSigningKeyHex string             `json:"ticketSigningKeyHex"`
	BaseURL             string             `json:"baseUrl"`
	Staging             bool               `json:"staging"`
	Metrics             chainMetricsVector `json:"metrics"`
}

type chainMetricsVector struct {
	LatencyEwmaMs             uint64 `json:"latencyEwmaMs"`
	TokensPerSecEwma          uint64 `json:"tokensPerSecEwma"`
	LastActivityAt            uint64 `json:"lastActivityAt"`
	TicketsOpened             uint64 `json:"ticketsOpened"`
	TicketsSettled            uint64 `json:"ticketsSettled"`
	TicketsLapsedSettled      uint64 `json:"ticketsLapsedSettled"`
	TicketsRefundedInactive   uint64 `json:"ticketsRefundedInactive"`
	TicketsProtested          uint64 `json:"ticketsProtested"`
	TicketsFrozenDispute      uint64 `json:"ticketsFrozenDispute"`
	TotalRefundedInactiveUsdc uint64 `json:"totalRefundedInactiveUsdc"`
	TotalProtestedUsdc        uint64 `json:"totalProtestedUsdc"`
	TotalFrozenDisputeUsdc    uint64 `json:"totalFrozenDisputeUsdc"`
	LatencyTotalMs            uint64 `json:"latencyTotalMs"`
	LatencySamples            uint64 `json:"latencySamples"`
	TotalRevenueGross         uint64 `json:"totalRevenueGross"`
	Revenue24hUsdc            uint64 `json:"revenue24hUsdc"`
	Revenue7dUsdc             uint64 `json:"revenue7dUsdc"`
	Revenue30dUsdc            uint64 `json:"revenue30dUsdc"`
}

const chainVectorApp = 1234

func chainNodeScenarios() []chainNodeScenario {
	const day = 20_000
	addr := func(fill byte) string {
		var a types.Address
		for i := range a {
			a[i] = fill + byte(i)
		}
		return a.String()
	}
	base := func(name string) chainNodeScenario {
		return chainNodeScenario{
			Name:       name,
			CurrentDay: day,
			op: escrow.OperatorRecord{
				ID: 7, OwnerAddr: addr(0x10), Status: escrow.OperatorStatusActive, NextNodeID: 3, LiveNodeCount: 1,
			},
			node: escrow.NodeRecord{
				OperatorID: 7, NodeID: 2, Status: escrow.NodeStatusActive, SigningAddr: addr(0x40),
				BaseURL: "https://node.example.com",
			},
		}
	}
	var out []chainNodeScenario
	add := func(name string, edit func(*chainNodeScenario)) {
		sc := base(name)
		edit(&sc)
		out = append(out, sc)
	}
	// ring sets the revenue bucket for each day given.
	ring := func(m *escrow.RecordMetrics, lastDay uint64, byDay map[uint64]uint64) {
		m.BucketsLastDay = lastDay
		for d, v := range byDay {
			m.RevenueBuckets[d%escrow.RevenueBucketCount] = v
		}
	}

	add("an active node with no history", func(*chainNodeScenario) {})
	add("a staging node", func(sc *chainNodeScenario) { sc.node.Staging = 1 })
	add("any non-zero staging byte is staging", func(sc *chainNodeScenario) { sc.node.Staging = 7 })
	add("the operator's NFD and owner come from its box", func(sc *chainNodeScenario) {
		sc.op.NFDAppID = 765_432_100
		sc.op.OwnerAddr = addr(0x80)
	})
	add("ids are read from the box names", func(sc *chainNodeScenario) {
		sc.op.ID, sc.node.OperatorID, sc.node.NodeID = 300, 300, 65_536
		sc.op.NextNodeID = 65_537
	})
	// Each field distinct, and the operator's rollup different from all of
	// them, so no field can stand in for another and the rollup can't stand in
	// for the node.
	add("every metric is the node's own", func(sc *chainNodeScenario) {
		m := &sc.node.RecordMetrics
		m.LastActivityAt, m.TicketsOpened, m.TicketsSettled, m.TicketsLapsedSettled = 1_790_000_000, 1001, 1002, 1003
		m.TicketsRefundedInactive, m.TotalRefundedInactiveUsdc, m.TicketsProtested = 1004, 1005, 1006
		m.TotalProtestedUsdc, m.TicketsFrozenDispute, m.TotalFrozenDisputeUsdc = 1007, 1008, 1009
		m.LatencyTotalMs, m.LatencyEwmaMs, m.TotalRevenueGross = 1010, 1011, 1012
		m.TotalInputTokens, m.TokensPerSecEwma = 1013, 1014
		sc.node.LatencySamples = 1015
		sc.node.UsdcEscrowed = 1016
		ring(m, day, map[uint64]uint64{day: 1017})
		r := &sc.op.RecordMetrics
		r.LastActivityAt, r.TicketsOpened, r.TicketsSettled, r.LatencyEwmaMs, r.TokensPerSecEwma = 9001, 9002, 9003, 9004, 9005
		r.TotalRevenueGross = 9006
		ring(r, day, map[uint64]uint64{day: 9007})
		sc.op.LatencySamples = 9008
	})
	add("revenue windows end on the current day", func(sc *chainNodeScenario) {
		ring(&sc.node.RecordMetrics, day, map[uint64]uint64{day: 100, day - 1: 200, day - 6: 400, day - 7: 800, day - 29: 1600})
	})
	add("a ring last written days ago", func(sc *chainNodeScenario) {
		ring(&sc.node.RecordMetrics, day-3, map[uint64]uint64{day - 3: 100, day - 5: 200, day - 10: 400})
	})
	add("a ring older than thirty days reads as no revenue", func(sc *chainNodeScenario) {
		ring(&sc.node.RecordMetrics, day-30, map[uint64]uint64{day - 30: 100, day - 31: 200})
	})
	add("a clock behind the ring reads no revenue", func(sc *chainNodeScenario) {
		ring(&sc.node.RecordMetrics, day+1, map[uint64]uint64{day + 1: 100, day: 200})
	})
	add("trailing slashes are trimmed from the base URL", func(sc *chainNodeScenario) { sc.node.BaseURL = "https://node.example.com/zs///" })
	add("an http base URL is accepted", func(sc *chainNodeScenario) { sc.node.BaseURL = "http://10.0.0.5:9090" })
	add("zero padding inside the stored length is trimmed", func(sc *chainNodeScenario) { sc.node.BaseURL = "https://node.example.com\x00\x00\x00" })
	add("a base URL with no scheme is skipped", func(sc *chainNodeScenario) { sc.node.BaseURL = "node.example.com" })
	add("an uppercase scheme is skipped", func(sc *chainNodeScenario) { sc.node.BaseURL = "HTTPS://node.example.com" })
	add("a non-http scheme is skipped", func(sc *chainNodeScenario) { sc.node.BaseURL = "ftp://node.example.com" })
	add("a bare scheme trims to no URL and is skipped", func(sc *chainNodeScenario) { sc.node.BaseURL = "https:///" })
	add("an empty base URL is skipped", func(sc *chainNodeScenario) { sc.node.BaseURL = "" })
	add("an evicted operator's node is left out", func(sc *chainNodeScenario) { sc.op.Status = escrow.OperatorStatusEvicted })
	// Only status 1 exists on chain, and an unregistered node's box is deleted;
	// the read does not look at the byte.
	add("a node's status byte is not read", func(sc *chainNodeScenario) { sc.node.Status = 0 })
	return out
}

// encodeRecordMetrics writes the shared metrics block in the contract's field
// order (go/escrow parseRecordMetrics).
func encodeRecordMetrics(b []byte, m escrow.RecordMetrics) []byte {
	for _, v := range []uint64{
		m.LastActivityAt, m.TicketsOpened, m.TicketsSettled, m.TicketsLapsedSettled, m.TicketsRefundedInactive,
		m.TotalRefundedInactiveUsdc, m.TicketsProtested, m.TotalProtestedUsdc, m.TicketsFrozenDispute,
		m.TotalFrozenDisputeUsdc, m.LatencyTotalMs, m.LatencyEwmaMs, m.TotalRevenueGross, m.BucketsLastDay,
	} {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	for _, v := range m.RevenueBuckets {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	b = binary.BigEndian.AppendUint64(b, m.TotalInputTokens)
	for _, v := range m.OutputUnits {
		b = binary.BigEndian.AppendUint64(b, v)
	}
	return binary.BigEndian.AppendUint64(b, m.TokensPerSecEwma)
}

func encodeOperatorBox(t *testing.T, op escrow.OperatorRecord) []byte {
	owner, err := types.DecodeAddress(op.OwnerAddr)
	if err != nil {
		t.Fatal(err)
	}
	b := append([]byte{}, owner[:]...)
	b = append(b, byte(op.Status))
	b = binary.BigEndian.AppendUint64(b, op.NFDAppID)
	b = binary.BigEndian.AppendUint64(b, op.NextNodeID)
	b = binary.BigEndian.AppendUint64(b, op.LiveNodeCount)
	b = encodeRecordMetrics(b, op.RecordMetrics)
	b = binary.BigEndian.AppendUint64(b, op.UsdcEscrowed)
	b = append(b, op.ReservedSlots[:]...)
	return binary.BigEndian.AppendUint64(b, op.LatencySamples)
}

func encodeNodeBox(t *testing.T, n escrow.NodeRecord) []byte {
	signer, err := types.DecodeAddress(n.SigningAddr)
	if err != nil {
		t.Fatal(err)
	}
	url := make([]byte, escrow.BaseURLMax)
	copy(url, n.BaseURL)
	b := append([]byte{byte(n.Status)}, signer[:]...)
	b = append(b, byte(len(n.BaseURL)))
	b = append(b, url...)
	b = encodeRecordMetrics(b, n.RecordMetrics)
	b = binary.BigEndian.AppendUint64(b, n.UsdcEscrowed)
	b = append(b, byte(n.Staging))
	b = append(b, n.ReservedSlots[:]...)
	return binary.BigEndian.AppendUint64(b, n.LatencySamples)
}

// boxListAlgod answers algod's paged box listing, values included, from boxes.
func boxListAlgod(t *testing.T, boxes map[string][]byte) algod.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/v2/applications/%d/boxes", chainVectorApp) || r.URL.Query().Get("include") != "values" {
			http.NotFound(w, r)
			return
		}
		prefix, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.URL.Query().Get("prefix"), "b64:"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		type box struct {
			Name  []byte `json:"name"`
			Value []byte `json:"value"`
		}
		list := []box{}
		for name, value := range boxes {
			if strings.HasPrefix(name, string(prefix)) {
				list = append(list, box{Name: []byte(name), Value: value})
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"boxes": list, "round": 100})
	}))
	t.Cleanup(srv.Close)
	c, err := algod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// runChainNodeScenario runs readChainNodes over the box listing on CurrentDay.
// The fetches are first run on their own, to check this test's encoder.
func runChainNodeScenario(t *testing.T, sc *chainNodeScenario) {
	opBox, nodeBox := encodeOperatorBox(t, sc.op), encodeNodeBox(t, sc.node)
	sc.OperatorID, sc.NodeID = sc.op.ID, sc.node.NodeID
	sc.OperatorBoxHex, sc.NodeBoxHex = hex.EncodeToString(opBox), hex.EncodeToString(nodeBox)
	c := boxListAlgod(t, map[string][]byte{
		string(escrow.OperatorBoxKey(sc.op.ID)):                       opBox,
		string(escrow.NodeBoxKey(sc.node.OperatorID, sc.node.NodeID)): nodeBox,
	})

	ctx := context.Background()
	var logged bytes.Buffer
	// Late in the day, so a clock read wrong by hours lands on the next one.
	at := time.Unix(int64(sc.CurrentDay)*escrow.SecondsPerDay+escrow.SecondsPerDay-1, 0)
	s := &ChainOperatorSource{
		EscrowAppID: chainVectorApp, Algod: c,
		Log:        slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelWarn})),
		chainClock: func() time.Time { return at },
	}
	records, err := s.fetchRecords(ctx)
	if err != nil || len(records) != 1 {
		t.Fatalf("%s: operators = %d, %v", sc.Name, len(records), err)
	}
	// The encoder above is this test's own; a decode that disagrees with it
	// would pin a case other than the one named.
	if got := records[0]; got.NFDAppID != sc.op.NFDAppID || got.Status != sc.op.Status || got.RecordMetrics != sc.op.RecordMetrics {
		t.Fatalf("%s: operator box decodes to %+v, encoded %+v", sc.Name, got, sc.op)
	}
	nodes, err := escrow.FetchNodesForOperators(ctx, chainVectorApp, records, c)
	if err != nil {
		t.Fatalf("%s: nodes: %v", sc.Name, err)
	}
	if len(nodes) == 1 {
		if got := nodes[0]; got.RecordMetrics != sc.node.RecordMetrics || got.Staging != sc.node.Staging || got.LatencySamples != sc.node.LatencySamples {
			t.Fatalf("%s: node box decodes to %+v, encoded %+v", sc.Name, got, sc.node)
		}
	}

	ops, err := s.readChainNodes(ctx)
	if err != nil {
		t.Fatalf("%s: readChainNodes: %v", sc.Name, err)
	}
	if len(ops) == 0 {
		switch {
		case strings.Contains(logged.String(), "skipping unparseable node record") && strings.Contains(logged.String(), "base_url"):
			sc.Skipped = "base_url"
		case len(nodes) == 0 && sc.op.Status == escrow.OperatorStatusEvicted:
			sc.Skipped = "evicted"
		default:
			t.Fatalf("%s: node left out for no reason this vector names; log: %s", sc.Name, logged.String())
		}
		return
	}
	o := ops[0]
	m := o.Metrics
	sc.Want = &chainNodeVector{
		ID: o.ID, NodeID: o.NodeID, NFDAppID: o.NFDAppID, OwnerAddr: o.OwnerAddr, SigningAddr: o.SigningAddr,
		TicketSigningKeyHex: hex.EncodeToString(o.TicketSigningKey), BaseURL: o.BaseURL, Staging: o.Staging,
		Metrics: chainMetricsVector{
			LatencyEwmaMs: m.LatencyEwmaMs, TokensPerSecEwma: m.TokensPerSecEwma, LastActivityAt: m.LastActivityAt,
			TicketsOpened: m.TicketsOpened, TicketsSettled: m.TicketsSettled, TicketsLapsedSettled: m.TicketsLapsedSettled,
			TicketsRefundedInactive: m.TicketsRefundedInactive, TicketsProtested: m.TicketsProtested,
			TicketsFrozenDispute: m.TicketsFrozenDispute, TotalRefundedInactiveUsdc: m.TotalRefundedInactiveUsdc,
			TotalProtestedUsdc: m.TotalProtestedUsdc, TotalFrozenDisputeUsdc: m.TotalFrozenDisputeUsdc,
			LatencyTotalMs: m.LatencyTotalMs, LatencySamples: m.LatencySamples, TotalRevenueGross: m.TotalRevenueGross,
			Revenue24hUsdc: m.Revenue24hUsdc, Revenue7dUsdc: m.Revenue7dUsdc, Revenue30dUsdc: m.Revenue30dUsdc,
		},
	}
}

func TestOperatorVectors(t *testing.T) {
	scenarios := operatorScenarios()
	for i := range scenarios {
		runOperatorScenario(&scenarios[i])
	}
	probes := probeAttestationScenarios()
	for i := range probes {
		runProbeAttestationScenario(t, &probes[i])
	}
	chain := chainNodeScenarios()
	for i := range chain {
		runChainNodeScenario(t, &chain[i])
	}
	f := struct {
		Comment          string                     `json:"comment"`
		Scenarios        []operatorScenario         `json:"scenarios"`
		ProbeAttestation []probeAttestationScenario `json:"probe_attestation"`
		ChainNodes       []chainNodeScenario        `json:"chain_nodes"`
	}{
		Comment:          "Generated by proto/go/zs TestOperatorVectors. fields, selection, each probe's request_path, verified_node, want and attested, and each chain node's want and skipped are compared exactly.",
		Scenarios:        scenarios,
		ProbeAttestation: probes,
		ChainNodes:       chain,
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
