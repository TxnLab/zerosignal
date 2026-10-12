/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/persisted_catalog_vectors.json: the saved
// operator catalog, format version 1, as marshalCatalog writes it and
// decodeCatalog reads it back. The TS SDK replays it against
// sdk/src/registry/persist.ts:
//   - catalogs: TS writes each case's operators to exactly these bytes, and
//     reads the bytes back to the case's loaded operators. Go's encoding is
//     reproducible for them (UTC times at millisecond precision, no node
//     version), so the two SDKs' files are interchangeable byte for byte.
//   - loads: files only Go writes (a local zone, nanoseconds, a node version)
//     or that neither writes, which TS must still read as Go does.
//   - rejects: files both must refuse, so a torn or foreign file starts cold.
//
//	cd proto/go && go test ./zs -run TestPersistedCatalogVectors -update

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
)

const persistedCatalogVectorsPath = "../../testdata/persisted_catalog_vectors.json"

// catalogVecCapacity is ModelCapacity under neutral snake_case names, so the
// fixture states each field independently of the Go field names the file
// itself uses.
type catalogVecCapacity struct {
	ContextWindow                uint64                   `json:"context_window"`
	MaxOutputTokens              uint64                   `json:"max_output_tokens"`
	InputModalities              []string                 `json:"input_modalities"`
	OutputModalities             []string                 `json:"output_modalities"`
	InputUSDPer1M                float64                  `json:"input_usd_per_1m"`
	OutputUSDPer1M               float64                  `json:"output_usd_per_1m"`
	CacheReadUSDPer1M            *float64                 `json:"cache_read_usd_per_1m"`
	LongContextThresholdTokens   uint64                   `json:"long_context_threshold_tokens"`
	LongContextInputUSDPer1M     *float64                 `json:"long_context_input_usd_per_1m"`
	LongContextOutputUSDPer1M    *float64                 `json:"long_context_output_usd_per_1m"`
	LongContextCacheReadUSDPer1M *float64                 `json:"long_context_cache_read_usd_per_1m"`
	Reasoning                    *inject.ModelReasoning   `json:"reasoning"`
	ToolUse                      *bool                    `json:"tool_use"`
	Tags                         []string                 `json:"tags"`
	Coordinates                  *inject.ModelCoordinates `json:"coordinates"`
	WeightsDigest                string                   `json:"weights_digest"`
	WeightsUnverifiable          bool                     `json:"weights_unverifiable"`
	Source                       string                   `json:"source"`
	CanonicalID                  string                   `json:"canonical_id"`
	Retention                    string                   `json:"retention"`
	ImageToolRateMicroUSDC       uint64                   `json:"image_tool_rate_micro_usdc"`
	ImageEditToolRateMicroUSDC   uint64                   `json:"image_edit_tool_rate_micro_usdc"`
	ImageToolBaseMicroUSDC       uint64                   `json:"image_tool_base_micro_usdc"`
	ImageEditToolBaseMicroUSDC   uint64                   `json:"image_edit_tool_base_micro_usdc"`
	ImageRateMicroUSDC           uint64                   `json:"image_rate_micro_usdc"`
	ImageEditRateMicroUSDC       uint64                   `json:"image_edit_rate_micro_usdc"`
	ImageDefaultMicroUSDC        uint64                   `json:"image_default_micro_usdc"`
	ImageEditDefaultMicroUSDC    uint64                   `json:"image_edit_default_micro_usdc"`
	ImageCapMicroUSDC            uint64                   `json:"image_cap_micro_usdc"`
	ImageEditCapMicroUSDC        uint64                   `json:"image_edit_cap_micro_usdc"`
	AdvertisesImageGen           bool                     `json:"advertises_image_gen"`
	AdvertisesImageEdit          bool                     `json:"advertises_image_edit"`
	ToolCallRatesMicroUSDC       map[string]uint64        `json:"tool_call_rates_micro_usdc"`
	VendorToolCatchAllMicroUSDC  uint64                   `json:"vendor_tool_catch_all_micro_usdc"`
	VendorToolCallCap            uint64                   `json:"vendor_tool_call_cap"`
	VendorToolTokensPerCall      uint64                   `json:"vendor_tool_tokens_per_call"`
}

type catalogVecMetrics struct {
	LastActivityAt            uint64 `json:"last_activity_at"`
	TicketsOpened             uint64 `json:"tickets_opened"`
	TicketsSettled            uint64 `json:"tickets_settled"`
	TicketsLapsedSettled      uint64 `json:"tickets_lapsed_settled"`
	TicketsRefundedInactive   uint64 `json:"tickets_refunded_inactive"`
	TicketsProtested          uint64 `json:"tickets_protested"`
	TicketsFrozenDispute      uint64 `json:"tickets_frozen_dispute"`
	TotalRefundedInactiveUsdc uint64 `json:"total_refunded_inactive_usdc"`
	TotalProtestedUsdc        uint64 `json:"total_protested_usdc"`
	TotalFrozenDisputeUsdc    uint64 `json:"total_frozen_dispute_usdc"`
	LatencyTotalMs            uint64 `json:"latency_total_ms"`
	LatencyEwmaMs             uint64 `json:"latency_ewma_ms"`
	LatencySamples            uint64 `json:"latency_samples"`
	TokensPerSecEwma          uint64 `json:"tokens_per_sec_ewma"`
	TotalRevenueGross         uint64 `json:"total_revenue_gross"`
	Revenue24hUsdc            uint64 `json:"revenue_24h_usdc"`
	Revenue7dUsdc             uint64 `json:"revenue_7d_usdc"`
	Revenue30dUsdc            uint64 `json:"revenue_30d_usdc"`
}

// catalogVecOp is every persisted Operator field. Times are Unix ms, 0 for
// Go's zero time; the signing key is hex, "" for none.
type catalogVecOp struct {
	ID                       uint64                        `json:"id"`
	NodeID                   uint64                        `json:"node_id"`
	NFDAppID                 uint64                        `json:"nfd_app_id"`
	OwnerAddr                string                        `json:"owner_addr"`
	SigningAddr              string                        `json:"signing_addr"`
	TicketSigningKey         string                        `json:"ticket_signing_key"`
	BaseURL                  string                        `json:"base_url"`
	Staging                  bool                          `json:"staging"`
	Models                   []string                      `json:"models"`
	ModelCapacities          map[string]catalogVecCapacity `json:"model_capacities"`
	BuiltinTools             []string                      `json:"builtin_tools"`
	MaxToolIters             int                           `json:"max_tool_iters"`
	ToolHeadroomPerIteration uint64                        `json:"tool_headroom_per_iteration"`
	NodeVersion              string                        `json:"node_version"`
	ProtoVersion             string                        `json:"proto_version"`
	ReachableAsOfMs          int64                         `json:"reachable_as_of_ms"`
	Metrics                  catalogVecMetrics             `json:"metrics"`
	MinChargeOutputTokens    uint64                        `json:"min_charge_output_tokens"`
	MinChargeAlgoTxns        uint64                        `json:"min_charge_algo_txns"`
	MinChargeMicroUSDC       uint64                        `json:"min_charge_micro_usdc"`
}

func catalogVecCapacityOf(c ModelCapacity) catalogVecCapacity {
	return catalogVecCapacity{
		ContextWindow: c.ContextWindow, MaxOutputTokens: c.MaxOutputTokens,
		InputModalities: c.InputModalities, OutputModalities: c.OutputModalities,
		InputUSDPer1M: c.InputUSDPer1M, OutputUSDPer1M: c.OutputUSDPer1M, CacheReadUSDPer1M: c.CacheReadUSDPer1M,
		LongContextThresholdTokens: c.LongContextThresholdTokens, LongContextInputUSDPer1M: c.LongContextInputUSDPer1M,
		LongContextOutputUSDPer1M: c.LongContextOutputUSDPer1M, LongContextCacheReadUSDPer1M: c.LongContextCacheReadUSDPer1M,
		Reasoning: c.Reasoning, ToolUse: c.ToolUse, Tags: c.Tags, Coordinates: c.Coordinates,
		WeightsDigest: c.WeightsDigest, WeightsUnverifiable: c.WeightsUnverifiable,
		Source: c.Source, CanonicalID: c.CanonicalID, Retention: c.Retention,
		ImageToolRateMicroUSDC: c.ImageToolRateMicroUSDC, ImageEditToolRateMicroUSDC: c.ImageEditToolRateMicroUSDC,
		ImageToolBaseMicroUSDC: c.ImageToolBaseMicroUSDC, ImageEditToolBaseMicroUSDC: c.ImageEditToolBaseMicroUSDC,
		ImageRateMicroUSDC: c.ImageRateMicroUSDC, ImageEditRateMicroUSDC: c.ImageEditRateMicroUSDC,
		ImageDefaultMicroUSDC: c.ImageDefaultMicroUSDC, ImageEditDefaultMicroUSDC: c.ImageEditDefaultMicroUSDC,
		ImageCapMicroUSDC: c.ImageCapMicroUSDC, ImageEditCapMicroUSDC: c.ImageEditCapMicroUSDC,
		AdvertisesImageGen: c.AdvertisesImageGen, AdvertisesImageEdit: c.AdvertisesImageEdit,
		ToolCallRatesMicroUSDC:      c.ToolCallRatesMicroUSDC,
		VendorToolCatchAllMicroUSDC: c.VendorToolCatchAllMicroUSDC, VendorToolCallCap: c.VendorToolCallCap,
		VendorToolTokensPerCall: c.VendorToolTokensPerCall,
	}
}

func catalogVecOpOf(op Operator) catalogVecOp {
	v := catalogVecOp{
		ID: op.ID, NodeID: op.NodeID, NFDAppID: op.NFDAppID,
		OwnerAddr: op.OwnerAddr, SigningAddr: op.SigningAddr,
		TicketSigningKey: hex.EncodeToString(op.TicketSigningKey),
		BaseURL:          op.BaseURL, Staging: op.Staging,
		Models:          append([]string{}, op.Models...),
		ModelCapacities: map[string]catalogVecCapacity{},
		BuiltinTools:    []string{},
		MaxToolIters:    op.MaxToolIters, ToolHeadroomPerIteration: op.ToolHeadroomPerIteration,
		NodeVersion: op.NodeVersion, ProtoVersion: op.ProtoVersion,
		Metrics: catalogVecMetrics{
			LastActivityAt: op.Metrics.LastActivityAt, TicketsOpened: op.Metrics.TicketsOpened,
			TicketsSettled: op.Metrics.TicketsSettled, TicketsLapsedSettled: op.Metrics.TicketsLapsedSettled,
			TicketsRefundedInactive: op.Metrics.TicketsRefundedInactive, TicketsProtested: op.Metrics.TicketsProtested,
			TicketsFrozenDispute:      op.Metrics.TicketsFrozenDispute,
			TotalRefundedInactiveUsdc: op.Metrics.TotalRefundedInactiveUsdc, TotalProtestedUsdc: op.Metrics.TotalProtestedUsdc,
			TotalFrozenDisputeUsdc: op.Metrics.TotalFrozenDisputeUsdc,
			LatencyTotalMs:         op.Metrics.LatencyTotalMs, LatencyEwmaMs: op.Metrics.LatencyEwmaMs,
			LatencySamples: op.Metrics.LatencySamples, TokensPerSecEwma: op.Metrics.TokensPerSecEwma,
			TotalRevenueGross: op.Metrics.TotalRevenueGross, Revenue24hUsdc: op.Metrics.Revenue24hUsdc,
			Revenue7dUsdc: op.Metrics.Revenue7dUsdc, Revenue30dUsdc: op.Metrics.Revenue30dUsdc,
		},
		MinChargeOutputTokens: op.MinChargeOutputTokens, MinChargeAlgoTxns: op.MinChargeAlgoTxns,
		MinChargeMicroUSDC: op.MinChargeMicroUSDC,
	}
	if !op.ReachableAsOf.IsZero() {
		v.ReachableAsOfMs = op.ReachableAsOf.UnixMilli()
	}
	for m, c := range op.ModelCapacities {
		v.ModelCapacities[m] = catalogVecCapacityOf(c)
	}
	for _, t := range op.BuiltinTools {
		v.BuiltinTools = append(v.BuiltinTools, t.Type)
	}
	return v
}

func catalogVecOpsOf(ops []Operator) []catalogVecOp {
	out := make([]catalogVecOp, len(ops))
	for i, op := range ops {
		out[i] = catalogVecOpOf(op)
	}
	return out
}

type catalogCase struct {
	Name      string         `json:"name"`
	Operators []catalogVecOp `json:"operators"`
	Bytes     string         `json:"bytes"`
	Loaded    []catalogVecOp `json:"loaded"`
}

type catalogLoadCase struct {
	Name   string         `json:"name"`
	Bytes  string         `json:"bytes"`
	Loaded []catalogVecOp `json:"loaded"`
}

type catalogRejectCase struct {
	Name  string `json:"name"`
	Bytes string `json:"bytes"`
}

func catalogF64(v float64) *float64 { return &v }
func catalogBool(v bool) *bool      { return &v }

func catalogVecKey(seed byte) ed25519.PublicKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)).Public().(ed25519.PublicKey)
}

func catalogCases() []struct {
	name string
	ops  []Operator
} {
	full := Operator{
		ID: 12, NodeID: 3, NFDAppID: 7_654_321,
		OwnerAddr: "OWNERADDR", SigningAddr: "SIGNINGADDR", TicketSigningKey: catalogVecKey(1),
		BaseURL: "https://node.example:9090", Staging: true,
		Models: []string{"qwen3-32b", "flux-schnell"},
		ModelCapacities: map[string]ModelCapacity{
			"qwen3-32b": {
				ContextWindow: 131072, MaxOutputTokens: 32768,
				InputModalities: []string{"text", "image"}, OutputModalities: []string{"text"},
				InputUSDPer1M: 0.15, OutputUSDPer1M: 0.6, CacheReadUSDPer1M: catalogF64(0.075),
				LongContextThresholdTokens: 128000, LongContextInputUSDPer1M: catalogF64(0.3),
				LongContextOutputUSDPer1M: catalogF64(1.2), LongContextCacheReadUSDPer1M: catalogF64(0),
				Reasoning: &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}, DefaultEffort: "low"},
				ToolUse:   catalogBool(true), Tags: []string{"coding", "chat"},
				Coordinates: &inject.ModelCoordinates{Family: "qwen/qwen3-32b", Parameters: 32_000_000_000,
					ActiveParameters: 32_000_000_000, Quantization: "Q4_K_M", Variant: "instruct"},
				WeightsDigest: "sha256:abcd", Source: "hf:Qwen/Qwen3-32B@main", Retention: inject.RetentionNoUpstream,
				ImageToolRateMicroUSDC: 40_000, ImageEditToolRateMicroUSDC: 50_000,
				ImageToolBaseMicroUSDC: 30_000, ImageEditToolBaseMicroUSDC: 35_000,
				ToolCallRatesMicroUSDC:      map[string]uint64{"zs_web_search": 5000, "web_search": 10_000, "code_interpreter": 30_000},
				VendorToolCatchAllMicroUSDC: 20_000, VendorToolCallCap: 4, VendorToolTokensPerCall: 1500,
			},
			"flux-schnell": {
				OutputModalities:    []string{"image"},
				Reasoning:           &inject.ModelReasoning{Supported: false},
				ToolUse:             catalogBool(false),
				Coordinates:         &inject.ModelCoordinates{Family: "bfl/flux"},
				WeightsUnverifiable: true, CanonicalID: "flux-schnell",
				ImageRateMicroUSDC: 3000, ImageEditRateMicroUSDC: 4000,
				ImageDefaultMicroUSDC: 3000, ImageEditDefaultMicroUSDC: 4000,
				ImageCapMicroUSDC: 12_000, ImageEditCapMicroUSDC: 16_000,
				AdvertisesImageGen: true, AdvertisesImageEdit: true,
			},
		},
		BuiltinTools: []BuiltinToolDef{{Type: "zs_web_search"}, {Type: "zs_web_read"}},
		MaxToolIters: 8, ToolHeadroomPerIteration: 4096,
		ProtoVersion:  "9.11",
		ReachableAsOf: time.UnixMilli(1_800_000_000_123).UTC(),
		Metrics: OperatorMetrics{
			LastActivityAt: 1_799_999_000, TicketsOpened: 1000, TicketsSettled: 950, TicketsLapsedSettled: 20,
			TicketsRefundedInactive: 10, TicketsProtested: 3, TicketsFrozenDispute: 2,
			TotalRefundedInactiveUsdc: 12_345, TotalProtestedUsdc: 678, TotalFrozenDisputeUsdc: 90,
			LatencyTotalMs: 400_000, LatencyEwmaMs: 420, LatencySamples: 900, TokensPerSecEwma: 55,
			TotalRevenueGross: 9_876_543, Revenue24hUsdc: 1000, Revenue7dUsdc: 7000, Revenue30dUsdc: 30_000,
		},
		MinChargeOutputTokens: 1000, MinChargeAlgoTxns: 2, MinChargeMicroUSDC: 150,
	}
	unprobed := Operator{
		ID: 4, NodeID: 1, OwnerAddr: "OWNER4", SigningAddr: "SIGNER4", TicketSigningKey: catalogVecKey(2),
		BaseURL: "http://10.0.0.4:8080",
	}
	escapes := Operator{
		ID: 5, NodeID: 2, OwnerAddr: "OWNER5", SigningAddr: "SIGNER5", TicketSigningKey: catalogVecKey(3),
		BaseURL: "https://n5.example/?a=1&b=<2>",
		// Escaped as UTF-8 bytes so no editor turns them into raw characters:
		// e-acute, the fi ligature (above every surrogate in UTF-16, below U+1F600
		// in Go's byte order), and the two line separators Go escapes.
		Models: []string{"a<b>&c", "zeta", "Zeta", "\xc3\xa9t\xc3\xa9", "\U0001F600", "\xef\xac\x81x"},
		ModelCapacities: map[string]ModelCapacity{
			"a<b>&c":            {ContextWindow: 1, Tags: []string{"line\xe2\x80\xa8sep", "para\xe2\x80\xa9sep", "tab\there", "ctl\x01", "quote\"back\\slash", "nl\ncr\r", "bs\bff\f", "del\x7f"}},
			"zeta":              {ContextWindow: 2},
			"Zeta":              {ContextWindow: 3},
			"\xc3\xa9t\xc3\xa9": {ContextWindow: 4},
			"\U0001F600":        {ContextWindow: 5},
			"\xef\xac\x81x":     {ContextWindow: 6},
		},
		ProtoVersion:  "9.0",
		ReachableAsOf: time.UnixMilli(1_800_000_000_100).UTC(),
	}
	floats := Operator{
		ID: 6, NodeID: 1, OwnerAddr: "OWNER6", SigningAddr: "SIGNER6", TicketSigningKey: catalogVecKey(4),
		BaseURL: "https://n6.example",
		Models:  []string{"tiny", "huge"},
		ModelCapacities: map[string]ModelCapacity{
			"tiny": {InputUSDPer1M: 1e-7, OutputUSDPer1M: 0.000001, CacheReadUSDPer1M: catalogF64(1.5e-10), InputModalities: []string{}},
			"huge": {InputUSDPer1M: 1e21, OutputUSDPer1M: 123456789.125, CacheReadUSDPer1M: catalogF64(999999999999999900000), Tags: []string{}},
		},
		ProtoVersion:  "10",
		ReachableAsOf: time.UnixMilli(1_800_000_001_000).UTC(),
	}
	return []struct {
		name string
		ops  []Operator
	}{
		{"a node with every persisted field set", []Operator{full}},
		{"a chain row never probed", []Operator{unprobed}},
		{"text and map keys Go escapes and orders", []Operator{escapes}},
		{"floats at the format boundaries, and nodes kept in order", []Operator{floats, unprobed}},
		{"no nodes", []Operator{}},
	}
}

func catalogLoadCases(t *testing.T) []catalogLoadCase {
	local := Operator{
		ID: 8, NodeID: 1, OwnerAddr: "OWNER8", SigningAddr: "SIGNER8", TicketSigningKey: catalogVecKey(5),
		BaseURL: "https://n8.example", Models: []string{"m"},
		ModelCapacities: map[string]ModelCapacity{"m": {ContextWindow: 8192}},
		NodeVersion:     "0.21.0+abc1234 [2026-05-03T12:00:00Z]",
		ProtoVersion:    "9.11",
		ReachableAsOf:   time.Date(2027, 1, 15, 3, 4, 5, 123_456_789, time.FixedZone("", -7*3600)),
	}
	data, err := marshalCatalog([]Operator{local})
	if err != nil {
		t.Fatal(err)
	}
	return []catalogLoadCase{
		{Name: "a time in a local zone with nanoseconds, and a node version", Bytes: string(data)},
		{Name: "an unknown key and absent fields", Bytes: `{"version":1,"operators":[{"id":3,"node_id":1,"owner_addr":"O","signing_addr":"S","base_url":"https://x.example","reachable_as_of":"2027-01-15T10:00:00Z","metrics":{},"future_field":[1,2]}],"saved_by":"elsewhere"}`},
		{Name: "null operators", Bytes: `{"version":1,"operators":null}`},
		{Name: "a retention tier this build does not know is dropped on load, a known one kept", Bytes: `{"version":1,"operators":[{"id":3,"node_id":1,"model_capacities":{"a":{"Retention":"forever-private"},"b":{"Retention":"no_upstream"}}}]}`},
		{Name: "nulls where Go leaves the zero value", Bytes: `{"version":1,"operators":[{"id":3,"node_id":null,"owner_addr":null,"signing_addr":"S","ticket_signing_key":null,"base_url":"https://x.example","models":null,"model_capacities":{"m":null},"reachable_as_of":null,"metrics":null,"proto_version":"9.4"}]}`},
		{Name: "whitespace Go does not write", Bytes: "{\n  \"version\": 1,\n  \"operators\": [ { \"id\": 3, \"node_id\": 2, \"base_url\": \"https://x.example\", \"reachable_as_of\": \"2027-01-15T10:00:00.5+00:00\" } ]\n}\n"},
		// Truncated to the millisecond, as UnixMilli truncates: rounding would
		// carry into the next second.
		{Name: "a fraction of nine nines", Bytes: `{"version":1,"operators":[{"id":3,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00.999999999Z"}]}`},
		{Name: "the widest offsets both read", Bytes: `{"version":1,"operators":[{"id":3,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00+23:59"},{"id":4,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00-23:59"}]}`},
		{Name: "zone offsets at Go's outer bounds, hour 24 and minute 60", Bytes: `{"version":1,"operators":[{"id":3,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00+24:00"},{"id":4,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00-24:00"},{"id":5,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00+00:60"},{"id":6,"node_id":1,"reachable_as_of":"2027-01-15T10:00:00+24:01"}]}`},
	}
}

func catalogRejectCases() []catalogRejectCase {
	return []catalogRejectCase{
		{Name: "a newer format version", Bytes: `{"version":2,"operators":[]}`},
		{Name: "no version", Bytes: `{"operators":[]}`},
		{Name: "a torn, zero-length write", Bytes: ``},
		{Name: "a truncated write", Bytes: `{"version":1,"operators":[{"id":1`},
		{Name: "a top-level array", Bytes: `[]`},
		{Name: "a top-level null", Bytes: `null`},
		{Name: "operators that are not a list", Bytes: `{"version":1,"operators":{}}`},
		{Name: "a string where a version belongs", Bytes: `{"version":"1","operators":[]}`},
		{Name: "a string where an id belongs", Bytes: `{"version":1,"operators":[{"id":"1"}]}`},
		{Name: "a negative id", Bytes: `{"version":1,"operators":[{"id":-1}]}`},
		{Name: "a fractional id", Bytes: `{"version":1,"operators":[{"id":1.5}]}`},
		{Name: "a fractional rate count", Bytes: `{"version":1,"operators":[{"id":1,"model_capacities":{"m":{"ContextWindow":0.5}}}]}`},
		{Name: "a rate past float64's range", Bytes: `{"version":1,"operators":[{"id":1,"model_capacities":{"m":{"InputUSDPer1M":1e400}}}]}`},
		{Name: "a list where a model list belongs", Bytes: `{"version":1,"operators":[{"id":1,"models":"m"}]}`},
		{Name: "a number in a model list", Bytes: `{"version":1,"operators":[{"id":1,"models":[1]}]}`},
		{Name: "a string where a flag belongs", Bytes: `{"version":1,"operators":[{"id":1,"staging":"true"}]}`},
		{Name: "a time that is not RFC 3339", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"yesterday"}]}`},
		{Name: "a time with no zone", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-01-15T10:00:00"}]}`},
		{Name: "a time on a day that does not exist", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-02-30T10:00:00Z"}]}`},
		{Name: "a time at hour 24", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-01-15T24:00:00Z"}]}`},
		{Name: "a time at minute 60", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-01-15T00:60:00Z"}]}`},
		{Name: "a time at second 60", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-01-15T00:00:60Z"}]}`},
		{Name: "a zone offset of 25 hours", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-01-15T10:00:00+25:00"}]}`},
		{Name: "a zone offset of 61 minutes", Bytes: `{"version":1,"operators":[{"id":1,"reachable_as_of":"2027-01-15T10:00:00+00:61"}]}`},
		{Name: "a signing key that is not base64", Bytes: `{"version":1,"operators":[{"id":1,"ticket_signing_key":"!!!!"}]}`},
		{Name: "metrics that are not an object", Bytes: `{"version":1,"operators":[{"id":1,"metrics":[]}]}`},
	}
}

func TestPersistedCatalogVectors(t *testing.T) {
	var catalogs []catalogCase
	for _, c := range catalogCases() {
		data, err := marshalCatalog(c.ops)
		if err != nil {
			t.Fatal(err)
		}
		loaded, err := decodeCatalog(data)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		catalogs = append(catalogs, catalogCase{Name: c.name, Operators: catalogVecOpsOf(c.ops), Bytes: string(data), Loaded: catalogVecOpsOf(loaded)})
	}
	loads := catalogLoadCases(t)
	for i := range loads {
		loaded, err := decodeCatalog([]byte(loads[i].Bytes))
		if err != nil {
			t.Fatalf("%s: %v", loads[i].Name, err)
		}
		loads[i].Loaded = catalogVecOpsOf(loaded)
	}
	rejects := catalogRejectCases()
	for _, c := range rejects {
		if _, err := decodeCatalog([]byte(c.Bytes)); err == nil {
			t.Fatalf("%s: decodeCatalog accepted it", c.Name)
		}
	}

	f := struct {
		Comment       string              `json:"comment"`
		FormatVersion int                 `json:"format_version"`
		Catalogs      []catalogCase       `json:"catalogs"`
		Loads         []catalogLoadCase   `json:"loads"`
		Rejects       []catalogRejectCase `json:"rejects"`
	}{
		Comment:       "Generated by proto/go/zs TestPersistedCatalogVectors. The saved operator catalog, format_version 1. catalogs: bytes is exactly what Go writes for operators, and what TS must write too; loaded is what reading bytes back yields (proto_version floored to minor 0, and nothing a probe sets). loads: files only Go writes or that neither writes, read to loaded. rejects: files both refuse. Operators use neutral snake_case names; times are Unix ms, 0 for none; the signing key is hex, empty for none.",
		FormatVersion: catalogFormatVersion,
		Catalogs:      catalogs,
		Loads:         loads,
		Rejects:       rejects,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(persistedCatalogVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(persistedCatalogVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("persisted catalog differs from %s; if the change is intended, regenerate with -update and review the diff", persistedCatalogVectorsPath)
	}
}
