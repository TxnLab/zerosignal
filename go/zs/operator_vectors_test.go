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
//
//	cd proto/go && go test ./zs -run TestOperatorVectors -update

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

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

// probeVerdictVector is what the scenario's verifier returns.
type probeVerdictVector struct {
	Pass             bool     `json:"pass"`
	FailureTag       string   `json:"failure_tag"`
	VerifierID       string   `json:"verifier_id"`
	AttestedAtMs     int64    `json:"attested_at_ms"`
	AttestedModelIDs []string `json:"attested_model_ids"`
}

// teeStatusVector is a TEEStatus under the SDK's field names, attestedAt in
// Unix milliseconds and 0 for the zero time.
type teeStatusVector struct {
	Mode             string   `json:"mode"`
	AttestedAt       int64    `json:"attestedAt"`
	VerifierID       string   `json:"verifierId"`
	Verified         bool     `json:"verified"`
	FailureTag       string   `json:"failureTag"`
	AttestedModelIDs []string `json:"attestedModelIds"`
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
	// Want is the operator's TEEStatus, null for none.
	Want *teeStatusVector `json:"want"`
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
		return &probeVerdictVector{Pass: true, VerifierID: tee.VerifierIDDstack, AttestedAtMs: 1790812800000, AttestedModelIDs: []string{"m", "n"}}
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
	add("the evidence time is the verdict's, not the advertisement's", func(sc *probeAttestationScenario) {
		sc.Verdict.AttestedAtMs = 1790813400000
	})
	// The mode is the claim the evidence was checked against, never the bundle's word.
	add("the mode is the advertised one, whatever the bundle says", func(sc *probeAttestationScenario) {
		sc.EndpointBody = `{"mode":"stub","generated_at":"2026-10-01T00:00:00Z","refresh_seconds":1200}`
	})
	add("a signed empty catalog stays an empty list", func(sc *probeAttestationScenario) { sc.Verdict.AttestedModelIDs = []string{} })
	add("a failing verdict keeps its tag and evidence time", func(sc *probeAttestationScenario) {
		sc.Verdict = &probeVerdictVector{FailureTag: tee.FailureMeasurementMismatch, VerifierID: tee.VerifierIDDstack, AttestedAtMs: 1790812800000}
	})
	add("a verdict with no evidence time reports none", func(sc *probeAttestationScenario) {
		sc.Verdict = &probeVerdictVector{FailureTag: tee.FailureStaleEvidence, VerifierID: tee.VerifierIDBuiltin}
	})
	add("a node with no verified recipient is handed none", func(sc *probeAttestationScenario) { sc.EphemeralRecipient = "" })
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
		v := tee.Verdict{Pass: sc.Verdict.Pass, FailureTag: sc.Verdict.FailureTag, VerifierID: sc.Verdict.VerifierID, AttestedModelIDs: sc.Verdict.AttestedModelIDs}
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
			FailureTag: op.TEE.FailureTag, AttestedModelIDs: op.TEE.AttestedModelIDs,
		}
	}
	if sc.Want != nil && sc.Want.FailureTag == tee.FailureFetchFailed && sc.RequestPath == "" {
		t.Fatalf("%s: fetch_failed without a request", sc.Name)
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
	f := struct {
		Comment          string                     `json:"comment"`
		Scenarios        []operatorScenario         `json:"scenarios"`
		ProbeAttestation []probeAttestationScenario `json:"probe_attestation"`
	}{
		Comment:          "Generated by proto/go/zs TestOperatorVectors. fields, selection, and each probe's request_path, verified_node and want are compared exactly.",
		Scenarios:        scenarios,
		ProbeAttestation: probes,
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
