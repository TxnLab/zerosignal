/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

// Cross-impl vectors for the discovery response (GET /v1/zs/details) and the
// retention helpers. proto/ts/test/details-vectors.test.ts replays them against
// proto/ts/src/inject/details.ts.
//
// The "full" body sets every field, so the TS parser must hand each one back
// unchanged: a JSON key the TS side doesn't know is dropped and fails there. The
// guard below fails here first when a field is added to the Go structs without
// being set in fullDetails, so a new field can't ride past both sides unseen.
//
// Regenerate after an intentional change:
//
//	cd proto/go && go test ./inject -run TestDetailsVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/tools"
)

const detailsVectorsPath = "../../testdata/details_vectors.json"

func fullDetails() inject.OperatorDetails {
	return inject.OperatorDetails{
		OperatorID:            7,
		NodeID:                2,
		OwnerAddr:             "OWNERADDR",
		SigningAddr:           "SIGNINGADDR",
		EphemeralAgePubkey:    "age1examplerecipient",
		EphemeralExpiry:       1_800_000_600,
		EphemeralIssuedAt:     1_800_000_000,
		EphemeralSig:          "c2lnbmF0dXJl",
		OracleSource:          "pyth",
		OracleHealthy:         true,
		AlgoUSDPrice:          0.2375,
		AlgoUSDAt:             time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC),
		MinChargeOutputTokens: 1000,
		MinChargeAlgoTxns:     7,
		MinChargeMicroUSDC:    1_663,
		BuiltinTools: []tools.BuiltinToolAdvert{
			{Type: "zs_web_search"}, {Type: "zs_web_read"},
		},
		MaxToolIterations:        20,
		ToolHeadroomPerIteration: 4000,
		Version:                  "0.25.0+5f344de [2026-09-03T06:05:20Z]",
		ProtoVersion:             "9.10",
		ConfigHash:               "sha256:00ff",
		TEE: &inject.TEEAdvertisement{
			Mode:        inject.TEEModeDstackTDX,
			AttestedAt:  time.Date(2026, 9, 30, 11, 55, 0, 0, time.UTC),
			EvidenceURL: "/v1/zs/attestation",
		},
		Models: []inject.OperatorDetailsModel{{
			ID:                               "qwen/qwen3-32b",
			InputRateUSDPer1M:                0.4,
			OutputRateUSDPer1M:               1.2,
			CacheReadRateUSDPer1M:            new(0.1),
			LongContextThresholdTokens:       128_000,
			LongContextInputRateUSDPer1M:     new(0.8),
			LongContextOutputRateUSDPer1M:    new(2.4),
			LongContextCacheReadRateUSDPer1M: new(0.2),
			ContextWindow:                    262_144,
			MaxOutputTokens:                  32_768,
			InputModalities:                  []string{"text", "image"},
			OutputModalities:                 []string{"text"},
			Reasoning:                        &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}, DefaultEffort: "low"},
			ToolUse:                          new(true),
			Tags:                             []string{"code"},
			Coordinates: &inject.ModelCoordinates{
				Family: "qwen/qwen3-32b", Parameters: 32_000_000_000, ActiveParameters: 32_000_000_000,
				Quantization: "Q8_0", Variant: "instruct",
			},
			Source:                      "hf:Qwen/Qwen3-32B",
			CanonicalID:                 "qwen/qwen3-32b",
			Retention:                   inject.RetentionTEEAttested,
			WeightsDigest:               "sha256:abcd",
			WeightsUnverifiable:         true,
			WeightsUnverifiableReason:   "split_weights",
			WeightsDigestTrust:          "node_supervised",
			WeightsDeclarationConflict:  true,
			WeightsRegistryMatch:        "matched",
			WeightsRegistryPath:         "Qwen3-32B-Q8_0.gguf",
			WeightsMismatch:             true,
			ImageToolRateMicroUSDC:      40_000,
			ImageEditToolRateMicroUSDC:  50_000,
			ImageToolBaseMicroUSDC:      20_000,
			ImageEditToolBaseMicroUSDC:  25_000,
			ImageRateMicroUSDC:          30_000,
			ImageEditRateMicroUSDC:      35_000,
			ImageDefaultMicroUSDC:       60_000,
			ImageEditDefaultMicroUSDC:   70_000,
			ImageCapMicroUSDC:           120_000,
			ImageEditCapMicroUSDC:       140_000,
			ServesImageGen:              true,
			ServesImageEdit:             true,
			ToolCallRatesMicroUSDC:      map[string]uint64{"web_search": 10_000, "zs_web_search": 0},
			VendorToolCatchAllMicroUSDC: 12_000,
			VendorToolCallCap:           5,
			VendorToolTokensPerCall:     3_000,
		}},
	}
}

// minimalDetails is what a node with nothing optional to say emits: the
// non-omitempty fields (models, oracle_healthy, the always-present rates) and
// Go's zero time.Time, which encoding/json writes rather than omits.
func minimalDetails() inject.OperatorDetails {
	return inject.OperatorDetails{Models: []inject.OperatorDetailsModel{{ID: "m"}}}
}

// assertEveryFieldSet fails when a JSON-tagged field of v's type is missing
// from the marshaled object, recursing into the named nested structs.
func assertEveryFieldSet(t *testing.T, where string, typ reflect.Type, obj map[string]any) {
	t.Helper()
	for f := range typ.Fields() {
		name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if name == "" || name == "-" {
			continue
		}
		val, ok := obj[name]
		if !ok {
			t.Errorf("fullDetails leaves %s.%s (json %q) unset; set it so the TS round trip covers it", where, f.Name, name)
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Pointer || ft.Kind() == reflect.Slice {
			ft = ft.Elem()
		}
		if ft.Kind() != reflect.Struct || ft == reflect.TypeFor[time.Time]() {
			continue
		}
		switch sub := val.(type) {
		case map[string]any:
			assertEveryFieldSet(t, where+"."+f.Name, ft, sub)
		case []any:
			for _, e := range sub {
				if m, ok := e.(map[string]any); ok {
					assertEveryFieldSet(t, where+"."+f.Name+"[]", ft, m)
				}
			}
		}
	}
}

type retentionCase struct {
	A    string `json:"a"`
	B    string `json:"b"`
	Want string `json:"want"`
}

type detailsVectorsFile struct {
	Version        int             `json:"version"`
	Comment        string          `json:"comment"`
	Full           json.RawMessage `json:"full"`
	Minimal        json.RawMessage `json:"minimal"`
	KnownRetention []string        `json:"known_retention"`
	Combine        []retentionCase `json:"combine_retention"`
	TEEModes       []string        `json:"tee_modes"`
}

func buildDetailsVectors(t *testing.T) detailsVectorsFile {
	t.Helper()
	full, err := json.Marshal(fullDetails())
	if err != nil {
		t.Fatalf("marshal full: %v", err)
	}
	var obj map[string]any
	if err := json.Unmarshal(full, &obj); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	assertEveryFieldSet(t, "OperatorDetails", reflect.TypeFor[inject.OperatorDetails](), obj)

	minimal, err := json.Marshal(minimalDetails())
	if err != nil {
		t.Fatalf("marshal minimal: %v", err)
	}

	// Every ordered pair over the known tiers, unknown (""), and an
	// unrecognized value, so the destination and evidence axes both get
	// exercised in both argument orders.
	inputs := append(inject.KnownRetentionTiers(), "", "retains_nothing_trust_me")
	var combine []retentionCase
	for _, a := range inputs {
		for _, b := range inputs {
			combine = append(combine, retentionCase{A: a, B: b, Want: inject.CombineRetention(a, b)})
		}
	}

	return detailsVectorsFile{
		Version: 1,
		Comment: "Cross-impl vectors for GET /v1/zs/details (inject.OperatorDetails) and the retention helpers. " +
			"Generated by proto/go/inject/details_vectors_test.go; regenerate with " +
			"`cd proto/go && go test ./inject -run TestDetailsVectors -update`.",
		Full:           full,
		Minimal:        minimal,
		KnownRetention: inject.KnownRetentionTiers(),
		Combine:        combine,
		TEEModes:       inject.KnownTEEModes(),
	}
}

func TestDetailsVectors(t *testing.T) {
	encoded, err := json.MarshalIndent(buildDetailsVectors(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')
	if *updateToolGrowthVectors {
		if err := os.WriteFile(detailsVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", detailsVectorsPath)
		return
	}
	onDisk, err := os.ReadFile(detailsVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(onDisk, encoded) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./inject -run TestDetailsVectors -update, "+
			"and port the change to proto/ts/src/inject/details.ts", detailsVectorsPath)
	}
}
