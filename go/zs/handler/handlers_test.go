/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

func TestHandleHealth(t *testing.T) {
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	s.handleHealth(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d", w.Result().StatusCode)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	if body := strings.TrimSpace(w.Body.String()); body != `{"status":"ok"}` {
		t.Errorf("body = %q", body)
	}
}

func TestHandleGetModel_MissingID(t *testing.T) {
	s := testServer(testConfig(), deps{})

	// Synthesize a request that has no path value set for {id}.
	req := httptest.NewRequest(http.MethodGet, "/v1/models/", nil)
	w := httptest.NewRecorder()
	s.handleGetModel(w, req)

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", w.Result().StatusCode)
	}
	var env openAIErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "missing_model_id" {
		t.Errorf("code = %q", env.Error.Code)
	}
}

// erroringReader fails on Read.
type erroringReader struct{}

func (erroringReader) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (erroringReader) Close() error             { return nil }

func TestDispatchStreamable_ReadBodyError(t *testing.T) {
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", erroringReader{})
	w := httptest.NewRecorder()
	s.dispatchStreamable(w, req, "/v1/chat/completions")

	if w.Result().StatusCode != http.StatusBadRequest {
		t.Errorf("status = %d", w.Result().StatusCode)
	}
}

func TestReadClientBody_BodyTooLarge(t *testing.T) {
	// Body one byte over the cap should trip MaxBytesReader and produce 413.
	oversized := strings.Repeat("a", MaxClientBodyBytes+1)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(oversized))
	w := httptest.NewRecorder()

	if _, ok := readClientBody(w, req); ok {
		t.Fatal("expected readClientBody to fail on oversized body")
	}
	if got := w.Result().StatusCode; got != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", got)
	}
	var env openAIErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "body_too_large" {
		t.Errorf("code = %q, want body_too_large", env.Error.Code)
	}
}

func TestHandleHayaiDetails_AggregatesAcrossOperators(t *testing.T) {
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		BuiltinTools: []hayai.BuiltinToolDef{
			{Type: "zs_web_search"},
			{Type: "zs_web_read"},
		},
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		BuiltinTools: []hayai.BuiltinToolDef{
			{Type: "zs_web_search"}, // dup
			{Type: "zs_image_search"},
		},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var body struct {
		BuiltinTools []struct {
			Type string `json:"type"`
		} `json:"builtin_tools"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.BuiltinTools) != 3 {
		t.Fatalf("len = %d, want 3: %+v", len(body.BuiltinTools), body.BuiltinTools)
	}
	seen := make(map[string]bool)
	for _, tool := range body.BuiltinTools {
		seen[tool.Type] = true
	}
	for _, typ := range []string{"zs_web_search", "zs_web_read", "zs_image_search"} {
		if !seen[typ] {
			t.Errorf("missing %q in response", typ)
		}
	}
}

func TestHandleHayaiDetails_AggregatesNodeVersions(t *testing.T) {
	// Two operators report distinct versions, a third dups op1's. We
	// expect the proxy to surface a sorted, deduped list.
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		NodeVersion: "0.21.0+abc1234 [2026-05-03T12:00:00Z]",
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		NodeVersion: "0.21.0+def5678 [2026-05-04T08:00:00Z]",
	}
	op3 := hayai.Operator{
		ID: 3, OwnerAddr: "C", BaseURL: "http://c", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		NodeVersion: "0.21.0+abc1234 [2026-05-03T12:00:00Z]", // dup of op1
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2, op3})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		NodeVersions []string `json:"node_versions"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []string{
		"0.21.0+abc1234 [2026-05-03T12:00:00Z]",
		"0.21.0+def5678 [2026-05-04T08:00:00Z]",
	}
	if len(body.NodeVersions) != len(want) {
		t.Fatalf("len = %d, want %d: %+v", len(body.NodeVersions), len(want), body.NodeVersions)
	}
	for i, v := range want {
		if body.NodeVersions[i] != v {
			t.Errorf("node_versions[%d] = %q, want %q", i, body.NodeVersions[i], v)
		}
	}
}

func TestHandleHayaiDetails_AggregatesPricingMin(t *testing.T) {
	// Two operators serve the same model at different rates; the aggregate
	// /v1/zs/details should surface the lowest declared rate per axis
	// ("from $X" semantic).
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {InputUSDPer1M: 0.50, OutputUSDPer1M: 1.50},
		},
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {InputUSDPer1M: 0.15, OutputUSDPer1M: 2.00},
		},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		FeeBps uint64 `json:"fee_bps"`
		Models []struct {
			ID             string  `json:"id"`
			InputUSDPer1M  float64 `json:"input_usd_per_1m"`
			OutputUSDPer1M float64 `json:"output_usd_per_1m"`
		} `json:"models"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Models) != 1 {
		t.Fatalf("models len = %d, want 1: %+v", len(body.Models), body.Models)
	}
	got := body.Models[0]
	if got.InputUSDPer1M != 0.15 {
		t.Errorf("input min = %v, want 0.15 (op2)", got.InputUSDPer1M)
	}
	if got.OutputUSDPer1M != 1.50 {
		t.Errorf("output min = %v, want 1.50 (op1)", got.OutputUSDPer1M)
	}
	// The default test wallet isn't fee-capable and the cache is cold, so
	// fee_bps is omitted (0) — consumers fall back to the raw operator rates.
	if body.FeeBps != 0 {
		t.Errorf("fee_bps = %d, want 0 (cold fee cache → omitted)", body.FeeBps)
	}
}

// TestHandleHayaiDetails_EmitsFeeBps proves the aggregate details endpoint
// surfaces the warm protocol fee so discovery consumers (e.g. `zs-proxy
// connect`) can gross the advertised operator rates up to payer-net.
func TestHandleHayaiDetails_EmitsFeeBps(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"m"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {InputUSDPer1M: 0.15, OutputUSDPer1M: 0.60},
		},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	// Warm the fee cache: the fee rate needs a fee-capable wallet AND a fresh
	// cache entry (a cold cache would kick a background refresh and report 0).
	s := testServer(testConfig(), deps{RegistryProvider: reg, Wallet: feeWallet{&fakeWallet{}, 200}})
	warmFee(t, s)

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		FeeBps uint64 `json:"fee_bps"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.FeeBps != 200 {
		t.Errorf("fee_bps = %d, want 200", body.FeeBps)
	}
}

func TestHandleHayaiOperators_PerOperatorView(t *testing.T) {
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "OWNER_A", SigningAddr: "SIGN_A",
		BaseURL: "http://a", Models: []string{"m", "n"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {ContextWindow: 128000, MaxOutputTokens: 4096, InputModalities: []string{"text", "image"}, OutputModalities: []string{"text"}, InputUSDPer1M: 0.15, OutputUSDPer1M: 0.60},
			"n": {ContextWindow: 32000, InputModalities: []string{"text"}, OutputModalities: []string{"text"}, InputUSDPer1M: 5.00, OutputUSDPer1M: 15.00},
		},
		BuiltinTools:          []hayai.BuiltinToolDef{{Type: "zs_web_search"}},
		NodeVersion:           "0.21.0+abc1234 [2026-05-03T12:00:00Z]",
		Reachable:             true,
		ProtoVersion:          wire.ProtoVersion,
		MaxToolIters:          8,
		MinChargeOutputTokens: 1000,
		MinChargeAlgoTxns:     9,
		MinChargeMicroUSDC:    1620,
		TEE: &hayai.TEEStatus{Mode: "dstack-tdx", Verified: true,
			AttestedModelIDs: []string{"m"}},
		Metrics: hayai.OperatorMetrics{
			LastActivityAt:            1_700_000_000,
			TicketsOpened:             100,
			TicketsSettled:            70,
			TicketsLapsedSettled:      5,
			TicketsRefundedInactive:   3,
			TicketsProtested:          2,
			TicketsFrozenDispute:      1,
			TotalRefundedInactiveUsdc: 30_000,
			TotalProtestedUsdc:        15_000,
			TotalFrozenDisputeUsdc:    9_000,
			LatencyTotalMs:            150_000,
			LatencyEwmaMs:             1_800,
			// Deliberately NOT 75 (= settled + lapsed): image-primary settles
			// bump those counters without folding a TTFT. 150_000/60 = 2500.
			LatencySamples:    60,
			TotalRevenueGross: 1_234_500,
			Revenue24hUsdc:    10_000,
			Revenue7dUsdc:     40_000,
			Revenue30dUsdc:    120_000,
		},
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "OWNER_B", SigningAddr: "SIGN_B",
		BaseURL: "http://b", Models: []string{"m"},
		// Wire-compatible on purpose — see the note on the other unreachable
		// fixtures: unreachability must be the only thing holding it out.
		Reachable: false, ProtoVersion: wire.ProtoVersion,
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil)
	w := httptest.NewRecorder()
	s.handleHayaiOperators(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var body struct {
		Operators []struct {
			OperatorID            uint64 `json:"operator_id"`
			OwnerAddr             string `json:"owner_addr"`
			SigningAddr           string `json:"signing_addr"`
			BaseURL               string `json:"base_url"`
			NodeVersion           string `json:"node_version"`
			Reachable             bool   `json:"reachable"`
			MaxToolIterations     int    `json:"max_tool_iterations"`
			MinChargeOutputTokens uint64 `json:"min_charge_output_tokens"`
			MinChargeAlgoTxns     uint64 `json:"min_charge_algo_txns"`
			MinChargeMicroUSDC    uint64 `json:"min_charge_microusdc"`
			TEE                   *struct {
				Mode             string   `json:"mode"`
				Verified         bool     `json:"verified"`
				AttestedModelIDs []string `json:"attested_model_ids"`
			} `json:"tee"`
			Metrics struct {
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
				LatencyMeanMs             uint64 `json:"latency_mean_ms"`
				TotalRevenueGrossUsdc     uint64 `json:"total_revenue_gross_usdc"`
				TotalRevenueNetUsdc       uint64 `json:"total_revenue_net_usdc"`
				Revenue24hUsdc            uint64 `json:"revenue_24h_usdc"`
				Revenue7dUsdc             uint64 `json:"revenue_7d_usdc"`
				Revenue30dUsdc            uint64 `json:"revenue_30d_usdc"`
			} `json:"metrics"`
			Models []struct {
				ID               string   `json:"id"`
				ContextWindow    uint64   `json:"context_window"`
				MaxOutputTokens  uint64   `json:"max_output_tokens"`
				InputModalities  []string `json:"input_modalities"`
				OutputModalities []string `json:"output_modalities"`
				InputUSDPer1M    float64  `json:"input_usd_per_1m"`
				OutputUSDPer1M   float64  `json:"output_usd_per_1m"`
			} `json:"models"`
			BuiltinTools []struct {
				Type string `json:"type"`
			} `json:"builtin_tools"`
		} `json:"operators"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Operators) != 2 {
		t.Fatalf("len = %d, want 2: %+v", len(body.Operators), body.Operators)
	}

	got1 := body.Operators[0]
	if got1.OperatorID != 1 {
		t.Errorf("[0].operator_id = %d, want 1", got1.OperatorID)
	}
	if got1.OwnerAddr != "OWNER_A" || got1.SigningAddr != "SIGN_A" {
		t.Errorf("[0] addresses = %q/%q", got1.OwnerAddr, got1.SigningAddr)
	}
	if !got1.Reachable {
		t.Errorf("[0].reachable = false, want true")
	}
	if got1.NodeVersion == "" {
		t.Errorf("[0].node_version empty")
	}
	if got1.MaxToolIterations != 8 {
		t.Errorf("[0].max_tool_iterations = %d, want 8", got1.MaxToolIterations)
	}
	if got1.MinChargeOutputTokens != 1000 || got1.MinChargeAlgoTxns != 9 || got1.MinChargeMicroUSDC != 1620 {
		t.Errorf("[0] min-charge = (out=%d, algo=%d, µusdc=%d), want (1000, 9, 1620)",
			got1.MinChargeOutputTokens, got1.MinChargeAlgoTxns, got1.MinChargeMicroUSDC)
	}
	// op2 was registered without min_charge — fields omitted (zero).
	if g2 := body.Operators[1]; g2.MinChargeOutputTokens != 0 || g2.MinChargeAlgoTxns != 0 || g2.MinChargeMicroUSDC != 0 {
		t.Errorf("[1] min-charge should be zero: out=%d algo=%d µusdc=%d", g2.MinChargeOutputTokens, g2.MinChargeAlgoTxns, g2.MinChargeMicroUSDC)
	}
	if got1.TEE == nil || got1.TEE.Mode != "dstack-tdx" || !got1.TEE.Verified ||
		!slices.Equal(got1.TEE.AttestedModelIDs, []string{"m"}) {
		t.Errorf("[0].tee = %+v", got1.TEE)
	}
	// Reliability metrics round-trip verbatim from the on-chain record,
	// with latency_mean_ms derived (150_000 / (70+5) = 2000).
	m := got1.Metrics
	if m.LastActivityAt != 1_700_000_000 {
		t.Errorf("[0].metrics.last_activity_at = %d", m.LastActivityAt)
	}
	if m.TicketsOpened != 100 || m.TicketsSettled != 70 || m.TicketsLapsedSettled != 5 ||
		m.TicketsRefundedInactive != 3 || m.TicketsProtested != 2 || m.TicketsFrozenDispute != 1 {
		t.Errorf("[0].metrics counters wrong: %+v", m)
	}
	if m.TotalRefundedInactiveUsdc != 30_000 || m.TotalProtestedUsdc != 15_000 || m.TotalFrozenDisputeUsdc != 9_000 {
		t.Errorf("[0].metrics dispute-exposure wrong: %+v", m)
	}
	// latency_mean_ms is 150_000 / latency_samples (60) = 2500. Dividing by the
	// 75-settle population would report 2000.
	if m.LatencyTotalMs != 150_000 || m.LatencyEwmaMs != 1_800 || m.LatencySamples != 60 ||
		m.LatencyMeanMs != 2_500 {
		t.Errorf("[0].metrics latency wrong: total=%d ewma=%d samples=%d mean=%d",
			m.LatencyTotalMs, m.LatencyEwmaMs, m.LatencySamples, m.LatencyMeanMs)
	}
	// Net mirrors gross under the additive fee model (the dedicated net field
	// is gone from the on-chain record).
	if m.TotalRevenueGrossUsdc != 1_234_500 || m.TotalRevenueNetUsdc != 1_234_500 {
		t.Errorf("[0].metrics revenue wrong: %+v", m)
	}
	if m.Revenue24hUsdc != 10_000 || m.Revenue7dUsdc != 40_000 || m.Revenue30dUsdc != 120_000 {
		t.Errorf("[0].metrics windowed revenue wrong: %+v", m)
	}
	// op2 was registered with no activity — metrics block present, all zero.
	m2 := body.Operators[1].Metrics
	if m2.TicketsOpened != 0 || m2.TotalRevenueGrossUsdc != 0 || m2.LatencyMeanMs != 0 {
		t.Errorf("[1].metrics should be zero-valued: %+v", m2)
	}
	if len(got1.Models) != 2 {
		t.Fatalf("[0].models len = %d", len(got1.Models))
	}
	// Verify per-model capability info round-trips with no UNION applied.
	modelByID := map[string]uint64{}
	for _, m := range got1.Models {
		modelByID[m.ID] = m.ContextWindow
	}
	if modelByID["m"] != 128000 || modelByID["n"] != 32000 {
		t.Errorf("[0] per-model context windows wrong: %+v", modelByID)
	}
	if len(got1.BuiltinTools) != 1 || got1.BuiltinTools[0].Type != "zs_web_search" {
		t.Errorf("[0].builtin_tools = %+v", got1.BuiltinTools)
	}
	// Pricing should round-trip from ModelCapacity → handler → JSON.
	pricingByID := map[string][2]float64{}
	for _, m := range got1.Models {
		pricingByID[m.ID] = [2]float64{m.InputUSDPer1M, m.OutputUSDPer1M}
	}
	if pricingByID["m"] != [2]float64{0.15, 0.60} {
		t.Errorf("[0] m pricing = %+v, want [0.15, 0.60]", pricingByID["m"])
	}
	if pricingByID["n"] != [2]float64{5.00, 15.00} {
		t.Errorf("[0] n pricing = %+v, want [5.00, 15.00]", pricingByID["n"])
	}

	got2 := body.Operators[1]
	if got2.OperatorID != 2 || got2.Reachable {
		t.Errorf("[1] = id %d reachable %v", got2.OperatorID, got2.Reachable)
	}
	if got2.TEE != nil {
		t.Errorf("[1].tee = %+v, want nil", got2.TEE)
	}
}

// TestHandleHayaiOperators_CoordinatesVerbatim asserts the per-operator surface
// shows EACH operator's own coordinates verbatim — no cross-operator
// aggregation — even when two operators disagree on a field (contrast the
// aggregate /v1/zs/details, which would omit the disputed field).
func TestHandleHayaiOperators_CoordinatesVerbatim(t *testing.T) {
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", SigningAddr: "SA", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion, Models: []string{"m"},
		ModelCapacities: map[string]hayai.ModelCapacity{"m": {Coordinates: &inject.ModelCoordinates{Family: "qwen/q", Quantization: "Q4"}}},
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", SigningAddr: "SB", BaseURL: "http://b", Reachable: true, ProtoVersion: wire.ProtoVersion, Models: []string{"m"},
		ModelCapacities: map[string]hayai.ModelCapacity{"m": {Coordinates: &inject.ModelCoordinates{Family: "qwen/q", Quantization: "Q5"}}},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil)
	w := httptest.NewRecorder()
	s.handleHayaiOperators(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		Operators []struct {
			OperatorID uint64 `json:"operator_id"`
			Models     []struct {
				ID          string                   `json:"id"`
				Coordinates *inject.ModelCoordinates `json:"coordinates"`
			} `json:"models"`
		} `json:"operators"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v\nbody: %s", err, w.Body.String())
	}
	quantByOp := map[uint64]string{}
	for _, o := range body.Operators {
		for _, mdl := range o.Models {
			if mdl.ID == "m" && mdl.Coordinates != nil {
				quantByOp[o.OperatorID] = mdl.Coordinates.Quantization
			}
		}
	}
	if quantByOp[1] != "Q4" {
		t.Errorf("op1 quant = %q, want Q4 verbatim", quantByOp[1])
	}
	if quantByOp[2] != "Q5" {
		t.Errorf("op2 quant = %q, want Q5 verbatim (NOT aggregated/omitted)", quantByOp[2])
	}
}

// A node attesting an empty catalog and a node with no verified list must
// stay distinguishable on the wire: [] versus null. Checked on the raw body,
// because decoding into a []string reads both as a nil-or-empty slice.
func TestHandleHayaiOperators_AttestedModelIDsNullVersusEmpty(t *testing.T) {
	op := func(id uint64, ids []string) hayai.Operator {
		return hayai.Operator{
			ID: id, BaseURL: fmt.Sprintf("http://%d", id), Reachable: true,
			ProtoVersion: wire.ProtoVersion, Models: []string{"m"},
			TEE: &hayai.TEEStatus{Mode: "dstack-tdx", Verified: ids != nil, AttestedModelIDs: ids},
		}
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op(1, []string{}), op(2, nil)})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})
	w := httptest.NewRecorder()
	s.handleHayaiOperators(w, httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil))

	raw := w.Body.String()
	for _, want := range []string{`"attested_model_ids":[]`, `"attested_model_ids":null`} {
		if !strings.Contains(raw, want) {
			t.Errorf("body lacks %s:\n%s", want, raw)
		}
	}
}

func TestHandleHayaiOperators_EmptyRegistryReturnsEmptyList(t *testing.T) {
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil)
	w := httptest.NewRecorder()
	s.handleHayaiOperators(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		Operators []json.RawMessage `json:"operators"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Operators == nil {
		t.Errorf("operators field absent — want []")
	}
	if len(body.Operators) != 0 {
		t.Errorf("len = %d, want 0", len(body.Operators))
	}
}

func TestHandleHayaiDetails_EmptyRegistryReturnsEmptyList(t *testing.T) {
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Errorf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		BuiltinTools []json.RawMessage `json:"builtin_tools"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// Always emits an array (even if empty) so clients can range without
	// a nil check.
	if body.BuiltinTools == nil {
		t.Fatalf("expected non-nil builtin_tools array")
	}
	if len(body.BuiltinTools) != 0 {
		t.Errorf("len = %d, want 0", len(body.BuiltinTools))
	}
}

// TestHandleListModels_ExcludesUnreachableOperators verifies that an
// unreachable operator's models do not leak into GET /v1/models even
// though the registry's snapshot still carries them forward (so
// dispatch's reserve path can keep trying the operator). Repros the
// "stale models in /refresh output" bug from the TUI.
func TestHandleListModels_ExcludesUnreachableOperators(t *testing.T) {
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"alive"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Models: []string{"stale"},
		// Wire-compatible on purpose: unreachability must be the ONLY reason this
		// operator is held out, or the test passes whichever gate you delete.
		Reachable: false, ProtoVersion: wire.ProtoVersion,
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	s.handleListModels(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data) != 1 || body.Data[0].ID != "alive" {
		t.Fatalf("data = %+v, want only [alive]", body.Data)
	}
}

// TestHandleListModels_AllOperatorsUnreachable_ReturnsEmptyList covers
// the "every operator is offline" state. AllModels returns empty because
// of the reachability filter, but we should NOT fall through to the
// upstream — that would advertise models the proxy can't actually
// dispatch via hayai. An empty list is the correct surface for "we know
// of operators, none are currently reachable".
func TestHandleListModels_AllOperatorsUnreachable_ReturnsEmptyList(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"stale"},
		// Wire-compatible on purpose: unreachability must be the ONLY reason this
		// operator is held out, or the test passes whichever gate you delete.
		Reachable: false, ProtoVersion: wire.ProtoVersion,
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	s.handleListModels(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Object != "list" {
		t.Errorf("object = %q, want list", body.Object)
	}
	if len(body.Data) != 0 {
		t.Errorf("data len = %d, want 0 (no fallthrough to upstream)", len(body.Data))
	}
}

func TestHandleListModels_EmptyRegistry_ReturnsEmptyList(t *testing.T) {
	// With no models, the list must still emit the canonical
	// {"object":"list","data":[]} shape. There is no upstream fallback.
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	s.handleListModels(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d", w.Result().StatusCode)
	}
	var body struct {
		Object string            `json:"object"`
		Data   []json.RawMessage `json:"data"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Object != "list" {
		t.Errorf("object = %q, want list", body.Object)
	}
	if body.Data == nil {
		t.Fatalf("data field absent — want []")
	}
	if len(body.Data) != 0 {
		t.Errorf("data len = %d, want 0", len(body.Data))
	}
}

func TestHandleGetModel_Found_OnChain(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"gpt-test"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		ModelCapacities: map[string]hayai.ModelCapacity{
			"gpt-test": {InputModalities: []string{"text", "image"}, OutputModalities: []string{"text"}},
		},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/models/gpt-test", nil)
	req.SetPathValue("id", "gpt-test")
	w := httptest.NewRecorder()
	s.handleGetModel(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}
	var body struct {
		ID           string `json:"id"`
		Object       string `json:"object"`
		OwnedBy      string `json:"owned_by"`
		Architecture *struct {
			InputModalities  []string `json:"input_modalities"`
			OutputModalities []string `json:"output_modalities"`
		} `json:"architecture"`
	}
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.ID != "gpt-test" || body.Object != "model" || body.OwnedBy != "zerosignal" {
		t.Errorf("body = %+v", body)
	}
	if body.Architecture == nil {
		t.Fatalf("architecture missing")
	}
	if len(body.Architecture.InputModalities) != 2 || len(body.Architecture.OutputModalities) != 1 {
		t.Errorf("modalities = %+v", body.Architecture)
	}
}

func TestHandleGetModel_NotFound_404(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"alive"},
		Reachable: true, ProtoVersion: wire.ProtoVersion,
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/models/does-not-exist", nil)
	req.SetPathValue("id", "does-not-exist")
	w := httptest.NewRecorder()
	s.handleGetModel(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Result().StatusCode)
	}
	var env openAIErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "model_not_found" {
		t.Errorf("code = %q, want model_not_found", env.Error.Code)
	}
}

func TestHandleGetModel_EmptyRegistry_404(t *testing.T) {
	s := testServer(testConfig(), deps{})

	req := httptest.NewRequest(http.MethodGet, "/v1/models/anything", nil)
	req.SetPathValue("id", "anything")
	w := httptest.NewRecorder()
	s.handleGetModel(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Result().StatusCode)
	}
	var env openAIErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Code != "model_not_found" {
		t.Errorf("code = %q, want model_not_found", env.Error.Code)
	}
}

func TestHandleGetModel_AllOperatorsUnreachable_404(t *testing.T) {
	// Operator advertises the model but is unreachable — the model is
	// not currently servable, so the lookup must 404 instead of returning
	// a stale entry.
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Models: []string{"stale"},
		// Wire-compatible on purpose: unreachability must be the ONLY reason this
		// operator is held out, or the test passes whichever gate you delete.
		Reachable: false, ProtoVersion: wire.ProtoVersion,
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/models/stale", nil)
	req.SetPathValue("id", "stale")
	w := httptest.NewRecorder()
	s.handleGetModel(w, req)

	if w.Result().StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Result().StatusCode)
	}
}

func TestReadClientBody_AtCapSucceeds(t *testing.T) {
	// Exactly the cap must still read cleanly.
	body := strings.Repeat("a", MaxClientBodyBytes)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	w := httptest.NewRecorder()

	got, ok := readClientBody(w, req)
	if !ok {
		t.Fatalf("readClientBody failed at cap, status = %d", w.Result().StatusCode)
	}
	if len(got) != MaxClientBodyBytes {
		t.Errorf("len = %d, want %d", len(got), MaxClientBodyBytes)
	}
}

// TestHandleHayai_WeightsSurfaces asserts the weights-digest fields appear on both
// the aggregate /v1/zs/details (consensus + mismatch) and the per-operator
// /v1/zs/operators (each operator's digest / unverifiable verbatim).
func TestHandleHayai_WeightsSurfaces(t *testing.T) {
	da := "sha256:" + strings.Repeat("a", 64)
	db := "sha256:" + strings.Repeat("b", 64)
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", SigningAddr: "SA", BaseURL: "http://a",
		Reachable: true, ProtoVersion: wire.ProtoVersion, Models: []string{"agree", "differ", "remote"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"agree":  {WeightsDigest: da},
			"differ": {WeightsDigest: da},
			"remote": {WeightsUnverifiable: true},
		},
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", SigningAddr: "SB", BaseURL: "http://b",
		Reachable: true, ProtoVersion: wire.ProtoVersion, Models: []string{"agree", "differ"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"agree":  {WeightsDigest: da},
			"differ": {WeightsDigest: db}, // disagrees with op1
		},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	// Aggregate: agree → consensus digest, no mismatch; differ → mismatch, no consensus.
	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)
	var agg struct {
		Models []struct {
			ID              string `json:"id"`
			WeightsDigest   string `json:"weights_digest"`
			WeightsMismatch bool   `json:"weights_mismatch"`
		} `json:"models"`
	}
	if err := json.NewDecoder(w.Body).Decode(&agg); err != nil {
		t.Fatalf("decode details: %v", err)
	}
	var sawAgree, sawDiffer bool
	for _, m := range agg.Models {
		switch m.ID {
		case "agree":
			sawAgree = true
			if m.WeightsDigest != da || m.WeightsMismatch {
				t.Errorf("agree aggregate = %q/%v, want %q/false", m.WeightsDigest, m.WeightsMismatch, da)
			}
		case "differ":
			sawDiffer = true
			if m.WeightsDigest != "" || !m.WeightsMismatch {
				t.Errorf("differ aggregate = %q/%v, want \"\"/true", m.WeightsDigest, m.WeightsMismatch)
			}
		}
	}
	if !sawAgree || !sawDiffer {
		t.Fatalf("aggregate missing models: agree=%v differ=%v", sawAgree, sawDiffer)
	}

	// Per-operator: op2's 'differ' digest is surfaced VERBATIM (db, not the
	// suppressed consensus); op1's 'remote' is unverifiable with no digest.
	req = httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil)
	w = httptest.NewRecorder()
	s.handleHayaiOperators(w, req)
	var perOp struct {
		Operators []struct {
			OperatorID uint64 `json:"operator_id"`
			Models     []struct {
				ID                  string `json:"id"`
				WeightsDigest       string `json:"weights_digest"`
				WeightsUnverifiable bool   `json:"weights_unverifiable"`
			} `json:"models"`
		} `json:"operators"`
	}
	if err := json.NewDecoder(w.Body).Decode(&perOp); err != nil {
		t.Fatalf("decode operators: %v", err)
	}
	var op2DifferOK, op1RemoteOK bool
	for _, o := range perOp.Operators {
		for _, m := range o.Models {
			if o.OperatorID == 2 && m.ID == "differ" {
				op2DifferOK = m.WeightsDigest == db && !m.WeightsUnverifiable
			}
			if o.OperatorID == 1 && m.ID == "remote" {
				op1RemoteOK = m.WeightsUnverifiable && m.WeightsDigest == ""
			}
		}
	}
	if !op2DifferOK {
		t.Errorf("op2 'differ' digest not surfaced verbatim as %q", db)
	}
	if !op1RemoteOK {
		t.Errorf("op1 'remote' not surfaced as unverifiable with no digest")
	}
}

// Retention reaches the wire. It is per-operator and deliberately NOT
// aggregated — every other advisory field on this entry describes the MODEL and
// is expected to agree across operators, while this describes each operator's
// own deployment, so two operators serving one model SHOULD differ and the
// endpoint must show both. Without this the field was written in fetcher.go and
// read nowhere: filtered, documented "display only", and displayed by nothing.
func TestHandleHayaiOperators_CarriesRetention(t *testing.T) {
	op1 := hayai.Operator{
		ID: 1, OwnerAddr: "A", SigningAddr: "SA", BaseURL: "http://a",
		Reachable: true, ProtoVersion: wire.ProtoVersion, Models: []string{"m", "quiet"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m":     {Retention: inject.RetentionUpstreamEnforced},
			"quiet": {}, // no signal — the honest state of most passthroughs
		},
	}
	op2 := hayai.Operator{
		ID: 2, OwnerAddr: "B", SigningAddr: "SB", BaseURL: "http://b",
		Reachable: true, ProtoVersion: wire.ProtoVersion, Models: []string{"m"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {Retention: inject.RetentionNoUpstream},
		},
	}
	reg, err := hayai.NewStaticRegistryProvider([]hayai.Operator{op1, op2})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	s := testServer(testConfig(), deps{RegistryProvider: reg})

	req := httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil)
	w := httptest.NewRecorder()
	s.handleHayaiOperators(w, req)

	var perOp struct {
		Operators []struct {
			OperatorID uint64 `json:"operator_id"`
			Models     []struct {
				ID        string `json:"id"`
				Retention string `json:"retention"`
			} `json:"models"`
		} `json:"operators"`
	}
	if err := json.NewDecoder(w.Body).Decode(&perOp); err != nil {
		t.Fatalf("decode operators: %v", err)
	}

	got := map[string]string{}
	for _, o := range perOp.Operators {
		for _, m := range o.Models {
			got[fmt.Sprintf("%d/%s", o.OperatorID, m.ID)] = m.Retention
		}
	}
	// The two operators disagree about the same model, and BOTH answers ship.
	if got["1/m"] != inject.RetentionUpstreamEnforced {
		t.Errorf("op1 m retention = %q, want %q", got["1/m"], inject.RetentionUpstreamEnforced)
	}
	if got["2/m"] != inject.RetentionNoUpstream {
		t.Errorf("op2 m retention = %q, want %q", got["2/m"], inject.RetentionNoUpstream)
	}
	// Absent stays absent: omitempty, and a consumer reads absence as unknown.
	if v, ok := got["1/quiet"]; !ok || v != "" {
		t.Errorf("op1 quiet retention = %q (present=%v), want empty", v, ok)
	}
}
