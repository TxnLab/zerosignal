/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/tools"
)

func TestOperatorDetails_OmitEmpty(t *testing.T) {
	// A nearly-empty advertisement: only an empty models list. All omitempty
	// fields must be absent from the wire so older clients see the same shape
	// they always have.
	d := OperatorDetails{
		Models: []OperatorDetailsModel{},
	}
	out, err := json.Marshal(d)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(out)
	wantPresent := []string{
		`"models":[]`,
		`"oracle_healthy":false`,
	}
	for _, s := range wantPresent {
		if !strings.Contains(got, s) {
			t.Errorf("expected %s in output, got %s", s, got)
		}
	}
	// algo_usd_at is intentionally NOT in wantAbsent: encoding/json
	// does not treat a zero time.Time as "empty", so the field has
	// always serialized as "0001-01-01T00:00:00Z" on the existing
	// node wire. Keeping that behavior preserves byte-for-byte
	// compatibility with current consumers.
	wantAbsent := []string{
		`operator_id`, `owner_addr`, `signing_addr`,
		`oracle_source`, `algo_usd_price`,
		`builtin_tools`, `max_tool_iterations`,
	}
	for _, s := range wantAbsent {
		if strings.Contains(got, s) {
			t.Errorf("did not expect %s in output, got %s", s, got)
		}
	}
}

func TestOperatorDetailsModel_CacheReadRate(t *testing.T) {
	// CacheReadRateUSDPer1M is a *float64 advertised ONLY when cached reads
	// are actually discounted. nil is elided; a non-nil pointer is emitted
	// even at 0.0 ("free cached reads" — the maximum discount, distinct from
	// "no discount"). Consumers decode absent as "not discounted", NOT as 0.
	free := 0.0
	discounted := 0.15
	cases := []struct {
		name       string
		rate       *float64
		wantInWire bool // is the field present on the wire?
	}{
		{"nil elided (no discount)", nil, false},
		{"zero emitted (free cached reads)", &free, true},
		{"positive emitted (discount)", &discounted, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := OperatorDetailsModel{
				ID:                    "m",
				InputRateUSDPer1M:     0.60,
				OutputRateUSDPer1M:    2.40,
				CacheReadRateUSDPer1M: tc.rate,
			}
			wire, err := json.Marshal(m)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			present := strings.Contains(string(wire), `"cache_read_rate_usd_per_1m"`)
			if present != tc.wantInWire {
				t.Fatalf("cache_read_rate_usd_per_1m present=%v want=%v; wire=%s", present, tc.wantInWire, wire)
			}
			var out OperatorDetailsModel
			if err := json.Unmarshal(wire, &out); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			switch {
			case tc.rate == nil && out.CacheReadRateUSDPer1M != nil:
				t.Fatalf("expected nil cache rate after round-trip, got %v", *out.CacheReadRateUSDPer1M)
			case tc.rate != nil && out.CacheReadRateUSDPer1M == nil:
				t.Fatalf("expected non-nil cache rate after round-trip, got nil")
			case tc.rate != nil && *out.CacheReadRateUSDPer1M != *tc.rate:
				t.Fatalf("cache rate round-trip mismatch: got %v want %v", *out.CacheReadRateUSDPer1M, *tc.rate)
			}
		})
	}
}

func TestOperatorDetails_RoundTrip(t *testing.T) {
	when := time.Unix(1_700_000_000, 0).UTC()
	in := OperatorDetails{
		OperatorID:  42,
		OwnerAddr:   "OWNER...",
		SigningAddr: "SIGNING...",
		Models: []OperatorDetailsModel{
			{
				ID:                 "google/gemma-4-26b-a4b",
				InputRateUSDPer1M:  0.15,
				OutputRateUSDPer1M: 0.60,
				ContextWindow:      30000,
				MaxOutputTokens:    8192,
				InputModalities:    []string{"text", "image"},
				OutputModalities:   []string{"text"},
			},
			{ID: "bare-model"},
		},
		OracleSource:      "coingecko",
		OracleHealthy:     true,
		AlgoUSDPrice:      0.18,
		AlgoUSDAt:         when,
		BuiltinTools:      []tools.BuiltinToolAdvert{{Type: "zs_web_search"}},
		MaxToolIterations: 4,
	}
	wire, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out OperatorDetails
	if err := json.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.OperatorID != 42 || out.SigningAddr != "SIGNING..." || out.OracleSource != "coingecko" {
		t.Fatalf("identity/oracle round-trip mismatch: %+v", out)
	}
	if len(out.Models) != 2 || out.Models[0].ID != "google/gemma-4-26b-a4b" || out.Models[0].ContextWindow != 30000 {
		t.Fatalf("models round-trip mismatch: %+v", out.Models)
	}
	if !out.AlgoUSDAt.Equal(when) {
		t.Fatalf("AlgoUSDAt round-trip mismatch: got %v want %v", out.AlgoUSDAt, when)
	}
	if len(out.BuiltinTools) != 1 || out.BuiltinTools[0].Type != "zs_web_search" {
		t.Fatalf("builtin_tools round-trip mismatch: %+v", out.BuiltinTools)
	}
	if out.MaxToolIterations != 4 {
		t.Fatalf("MaxToolIterations round-trip mismatch: got %d", out.MaxToolIterations)
	}
}

func TestOperatorDetails_DecodesNodeShape(t *testing.T) {
	// The JSON shape the node emits must decode cleanly into
	// OperatorDetails. This is a freeze test: any change to JSON tags
	// here that breaks decoding of this payload is a wire-format break.
	// The builtin_tools entry below carries the full descriptor
	// (name/description/parameters) on purpose — current nodes advertise
	// type-only, but a pre-trim node's richer entry must still decode
	// (the extra keys are ignored), so this doubles as a back-compat
	// guard. Only `type` is read off the decoded entry.
	wire := []byte(`{
		"operator_id": 1,
		"owner_addr": "OWN",
		"signing_addr": "SIG",
		"models": [
			{"id":"m","input_rate_usd_per_1m":1.0,"output_rate_usd_per_1m":2.0,
			 "context_window":32000,"max_output_tokens":4096,
			 "input_modalities":["text"],"output_modalities":["text"]}
		],
		"oracle_source": "coingecko",
		"oracle_healthy": true,
		"algo_usd_price": 0.18,
		"algo_usd_at": "2024-01-01T00:00:00Z",
		"builtin_tools": [{"type":"zs_web_search","name":"zs_web_search","description":"d","parameters":{}}],
		"max_tool_iterations": 3
	}`)
	var out OperatorDetails
	if err := json.Unmarshal(wire, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.OperatorID != 1 || out.OwnerAddr != "OWN" || out.SigningAddr != "SIG" {
		t.Fatalf("identity decode mismatch: %+v", out)
	}
	if len(out.Models) != 1 {
		t.Fatalf("models decode mismatch: %+v", out.Models)
	}
	m := out.Models[0]
	if m.ID != "m" || m.InputRateUSDPer1M != 1.0 || m.ContextWindow != 32000 || m.MaxOutputTokens != 4096 {
		t.Fatalf("model field decode mismatch: %+v", m)
	}
	if !out.OracleHealthy || out.OracleSource != "coingecko" || out.AlgoUSDPrice != 0.18 {
		t.Fatalf("oracle decode mismatch: %+v", out)
	}
	if len(out.BuiltinTools) != 1 || out.BuiltinTools[0].Type != "zs_web_search" || out.MaxToolIterations != 3 {
		t.Fatalf("tools decode mismatch: %+v", out)
	}
}
