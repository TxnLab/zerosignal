/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/wire"
)

// TestAllModelDetails_TagsAndCapsUnion: two operators serving the same model
// with different tags + capabilities. Tags OR-union, tool_use ORs, reasoning
// ORs Supported and unions AllowedEfforts while dropping DefaultEffort from
// the aggregate.
func TestAllModelDetails_TagsAndCapsUnion(t *testing.T) {
	tTrue := true
	op1 := Operator{
		ID:        1,
		OwnerAddr: "A",
		BaseURL:   "http://a",
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m1"},
		ModelCapacities: map[string]ModelCapacity{
			"m1": {
				Tags:      []string{"nsfw"},
				Reasoning: &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low"}, DefaultEffort: "low"},
			},
		},
	}
	op2 := Operator{
		ID:        2,
		OwnerAddr: "B",
		BaseURL:   "http://b",
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m1"},
		ModelCapacities: map[string]ModelCapacity{
			"m1": {
				Tags:      []string{"code"},
				ToolUse:   &tTrue,
				Reasoning: &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"high"}, DefaultEffort: "high"},
			},
		},
	}
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("expected 1 model, got %d", len(out))
	}
	m := out[0]
	// Tags OR-union: a tag appears if ANY operator declares it.
	if !reflect.DeepEqual(m.Tags, []string{"nsfw", "code"}) {
		t.Errorf("tags = %v, want [nsfw code]", m.Tags)
	}
	// tool_use OR: op2 advertises true → aggregate true.
	if m.ToolUse == nil || !*m.ToolUse {
		t.Errorf("tool_use = %v, want *true", m.ToolUse)
	}
	// reasoning: Supported OR, AllowedEfforts unioned, DefaultEffort dropped.
	if m.Reasoning == nil || !m.Reasoning.Supported {
		t.Fatalf("reasoning = %+v, want supported", m.Reasoning)
	}
	if !reflect.DeepEqual(m.Reasoning.AllowedEfforts, []string{"low", "high"}) {
		t.Errorf("allowed efforts = %v, want [low high]", m.Reasoning.AllowedEfforts)
	}
	if m.Reasoning.DefaultEffort != "" {
		t.Errorf("default effort = %q, want dropped (empty) in aggregate", m.Reasoning.DefaultEffort)
	}
}

// TestAllModelDetails_CacheReadAggregate: the cache-read discount aggregates
// as the LOWEST advertised value across operators ("from $X"), stays nil when
// no operator discounts, and keeps a pointed-to 0 (free cached reads) distinct
// from nil.
func TestAllModelDetails_CacheReadAggregate(t *testing.T) {
	rate := func(v float64) *float64 { return &v }

	// m-lowest: op1 discounts to 0.05, op2 to 0.02 → aggregate 0.02.
	// m-free: op1 free (0), op2 no discount (nil) → aggregate 0 (free wins,
	//         and free must survive as non-nil, not be treated as "unset").
	// m-none: neither operator discounts → aggregate nil (no cache line).
	op1 := Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m-lowest", "m-free", "m-none"},
		ModelCapacities: map[string]ModelCapacity{
			"m-lowest": {InputUSDPer1M: 0.10, CacheReadUSDPer1M: rate(0.05)},
			"m-free":   {InputUSDPer1M: 0.10, CacheReadUSDPer1M: rate(0)},
			"m-none":   {InputUSDPer1M: 0.10},
		},
	}
	op2 := Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m-lowest", "m-free", "m-none"},
		ModelCapacities: map[string]ModelCapacity{
			"m-lowest": {InputUSDPer1M: 0.10, CacheReadUSDPer1M: rate(0.02)},
			"m-free":   {InputUSDPer1M: 0.10}, // no discount
			"m-none":   {InputUSDPer1M: 0.10},
		},
	}
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	byID := make(map[string]inject.OperatorDetailsModel)
	for _, m := range reg.AllModelDetails(context.Background()) {
		byID[m.ID] = m
	}

	if c := byID["m-lowest"].CacheReadRateUSDPer1M; c == nil || *c != 0.02 {
		t.Errorf("m-lowest cache-read = %v, want *0.02 (cheapest across operators)", c)
	}
	if c := byID["m-free"].CacheReadRateUSDPer1M; c == nil || *c != 0 {
		t.Errorf("m-free cache-read = %v, want *0 (free cached reads, not nil)", c)
	}
	if c := byID["m-none"].CacheReadRateUSDPer1M; c != nil {
		t.Errorf("m-none cache-read = %v, want nil (no discount)", c)
	}

	// The aggregate pointer must not alias either operator's ModelCapacity.
	if c := byID["m-lowest"].CacheReadRateUSDPer1M; c == op1.ModelCapacities["m-lowest"].CacheReadUSDPer1M ||
		c == op2.ModelCapacities["m-lowest"].CacheReadUSDPer1M {
		t.Errorf("m-lowest cache-read pointer aliases a source ModelCapacity")
	}
}

// TestAllModelDetails_LongContextAggregate: the long-context (surcharge) tier
// aggregates cross-operator like the token/cache rates — lowest threshold and
// lowest of each high rate ("from $X", display-only; the per-operator
// ModelCapacities the verifier uses are untouched). A model no operator tiers has
// no tier fields; a tier on only one operator survives.
func TestAllModelDetails_LongContextAggregate(t *testing.T) {
	rate := func(v float64) *float64 { return &v }
	op1 := Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m-tier", "m-flat", "m-mixed"},
		ModelCapacities: map[string]ModelCapacity{
			"m-tier": {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0,
				LongContextThresholdTokens: 200000, LongContextInputUSDPer1M: rate(4.0), LongContextOutputUSDPer1M: rate(8.0), LongContextCacheReadUSDPer1M: rate(2.0)},
			"m-flat": {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0},
			"m-mixed": {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0,
				LongContextThresholdTokens: 128000, LongContextInputUSDPer1M: rate(4.0), LongContextOutputUSDPer1M: rate(8.0)},
		},
	}
	op2 := Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m-tier", "m-flat", "m-mixed"},
		ModelCapacities: map[string]ModelCapacity{
			"m-tier": {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0,
				LongContextThresholdTokens: 150000, LongContextInputUSDPer1M: rate(3.0), LongContextOutputUSDPer1M: rate(10.0), LongContextCacheReadUSDPer1M: rate(1.5)},
			"m-flat":  {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0},
			"m-mixed": {InputUSDPer1M: 2.0, OutputUSDPer1M: 4.0}, // no tier
		},
	}
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	byID := make(map[string]inject.OperatorDetailsModel)
	for _, m := range reg.AllModelDetails(context.Background()) {
		byID[m.ID] = m
	}

	// m-tier: lowest threshold (op2) mixed with the lowest of each high rate
	// (input from op2, output from op1) — the "from $X" display-only behavior.
	tier := byID["m-tier"]
	if tier.LongContextThresholdTokens != 150000 {
		t.Errorf("m-tier threshold = %d, want 150000 (lowest)", tier.LongContextThresholdTokens)
	}
	if tier.LongContextInputRateUSDPer1M == nil || *tier.LongContextInputRateUSDPer1M != 3.0 {
		t.Errorf("m-tier high input = %v, want *3.0 (lowest)", tier.LongContextInputRateUSDPer1M)
	}
	if tier.LongContextOutputRateUSDPer1M == nil || *tier.LongContextOutputRateUSDPer1M != 8.0 {
		t.Errorf("m-tier high output = %v, want *8.0 (lowest)", tier.LongContextOutputRateUSDPer1M)
	}
	if tier.LongContextCacheReadRateUSDPer1M == nil || *tier.LongContextCacheReadRateUSDPer1M != 1.5 {
		t.Errorf("m-tier high cache = %v, want *1.5 (lowest)", tier.LongContextCacheReadRateUSDPer1M)
	}

	// m-flat: no operator tiers → no tier fields.
	flat := byID["m-flat"]
	if flat.LongContextThresholdTokens != 0 || flat.LongContextInputRateUSDPer1M != nil || flat.LongContextOutputRateUSDPer1M != nil || flat.LongContextCacheReadRateUSDPer1M != nil {
		t.Errorf("m-flat carried a tier: threshold=%d in=%v out=%v cache=%v",
			flat.LongContextThresholdTokens, flat.LongContextInputRateUSDPer1M, flat.LongContextOutputRateUSDPer1M, flat.LongContextCacheReadRateUSDPer1M)
	}

	// m-mixed: only op1 tiers → its tier survives, with no high cache advertised.
	mixed := byID["m-mixed"]
	if mixed.LongContextThresholdTokens != 128000 {
		t.Errorf("m-mixed threshold = %d, want 128000 (op1's; op2 has no tier)", mixed.LongContextThresholdTokens)
	}
	if mixed.LongContextInputRateUSDPer1M == nil || *mixed.LongContextInputRateUSDPer1M != 4.0 {
		t.Errorf("m-mixed high input = %v, want *4.0", mixed.LongContextInputRateUSDPer1M)
	}
	if mixed.LongContextCacheReadRateUSDPer1M != nil {
		t.Errorf("m-mixed high cache = %v, want nil (op1 advertised none)", mixed.LongContextCacheReadRateUSDPer1M)
	}
}

// TestAllModelDetails_TagsSingleOperator: a single operator's tags + reasoning
// seed the aggregate, and DefaultEffort is dropped even with one operator.
func TestAllModelDetails_TagsSingleOperator(t *testing.T) {
	op := Operator{
		ID:        1,
		OwnerAddr: "A",
		BaseURL:   "http://a",
		Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m1"},
		ModelCapacities: map[string]ModelCapacity{
			"m1": {
				Tags:      []string{"nsfw"},
				Reasoning: &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"on"}, DefaultEffort: "on"},
			},
		},
	}
	reg, err := NewStaticRegistryProvider([]Operator{op})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("expected 1 model, got %d", len(out))
	}
	m := out[0]
	if !reflect.DeepEqual(m.Tags, []string{"nsfw"}) {
		t.Errorf("tags = %v, want [nsfw]", m.Tags)
	}
	if m.Reasoning == nil || m.Reasoning.DefaultEffort != "" {
		t.Errorf("seed default effort should be dropped: %+v", m.Reasoning)
	}
}

// TestAllModelDetails_ImageDisplayAggregate — the display-only image scalars
// (representative price at the operator's default size, and its per-image
// ceiling) aggregate under the same lowest-non-zero "from $X" rule as the
// rates, and a field no operator publishes stays absent rather than reading as
// free. Also pins the coherence property the range display depends on: an
// operator advertising a cap always advertises a default too, and never below
// its own cap, so min(default) <= min(cap) across the fleet.
func TestAllModelDetails_ImageDisplayAggregate(t *testing.T) {
	// img-pinned: op1 pins to 2k (default == cap == 22000), op2 leaves more
	//   headroom (default 5500, cap 88000) → aggregate 5500 → 22000.
	// img-bare:  neither operator declares knobs → both fields absent, the raw
	//   rate stays the whole story.
	op1 := Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"img-pinned", "img-bare"},
		ModelCapacities: map[string]ModelCapacity{
			"img-pinned": {
				ImageRateMicroUSDC:    5_500,
				ImageDefaultMicroUSDC: 22_000,
				ImageCapMicroUSDC:     22_000,
				AdvertisesImageGen:    true,
			},
			"img-bare": {ImageRateMicroUSDC: 100_000, AdvertisesImageGen: true},
		},
	}
	op2 := Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"img-pinned", "img-bare"},
		ModelCapacities: map[string]ModelCapacity{
			"img-pinned": {
				ImageRateMicroUSDC:    5_500,
				ImageDefaultMicroUSDC: 5_500,
				ImageCapMicroUSDC:     88_000,
				AdvertisesImageGen:    true,
			},
			"img-bare": {ImageRateMicroUSDC: 100_000, AdvertisesImageGen: true},
		},
	}
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	byID := make(map[string]inject.OperatorDetailsModel)
	for _, m := range reg.AllModelDetails(context.Background()) {
		byID[m.ID] = m
	}

	pinned := byID["img-pinned"]
	if pinned.ImageDefaultMicroUSDC != 5_500 {
		t.Errorf("img-pinned default = %d, want 5500 (cheapest across operators)", pinned.ImageDefaultMicroUSDC)
	}
	if pinned.ImageCapMicroUSDC != 22_000 {
		t.Errorf("img-pinned cap = %d, want 22000 (cheapest ceiling across operators)", pinned.ImageCapMicroUSDC)
	}
	if pinned.ImageDefaultMicroUSDC > pinned.ImageCapMicroUSDC {
		t.Errorf("aggregate default %d exceeds cap %d; the range would render backwards",
			pinned.ImageDefaultMicroUSDC, pinned.ImageCapMicroUSDC)
	}

	bare := byID["img-bare"]
	if bare.ImageDefaultMicroUSDC != 0 || bare.ImageCapMicroUSDC != 0 {
		t.Errorf("img-bare default/cap = %d/%d, want 0/0 (no operator declares knobs)",
			bare.ImageDefaultMicroUSDC, bare.ImageCapMicroUSDC)
	}
	if bare.ImageRateMicroUSDC != 100_000 {
		t.Errorf("img-bare rate = %d, want 100000 (unchanged)", bare.ImageRateMicroUSDC)
	}
}

// The in-loop tool's representative price rides the same passthrough. It was
// never threaded through the proxy at all, so a proxy-fronted client saw only
// the cap and rendered a range anchored on a unit rate nothing is billed at.
func TestAllModelDetails_ImageToolBaseAggregate(t *testing.T) {
	op1 := Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"chat"},
		ModelCapacities: map[string]ModelCapacity{
			"chat": {
				InputUSDPer1M:              0.10,
				ImageToolRateMicroUSDC:     22_000,
				ImageToolBaseMicroUSDC:     22_000,
				ImageEditToolRateMicroUSDC: 22_000,
				ImageEditToolBaseMicroUSDC: 22_000,
			},
		},
	}
	op2 := Operator{
		ID: 2, OwnerAddr: "B", BaseURL: "http://b", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"chat"},
		ModelCapacities: map[string]ModelCapacity{
			"chat": {
				InputUSDPer1M:          0.10,
				ImageToolRateMicroUSDC: 88_000,
				ImageToolBaseMicroUSDC: 5_500,
			},
		},
	}
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	for _, m := range reg.AllModelDetails(context.Background()) {
		if m.ID != "chat" {
			continue
		}
		if m.ImageToolBaseMicroUSDC != 5_500 {
			t.Errorf("tool base = %d, want 5500 (cheapest across operators)", m.ImageToolBaseMicroUSDC)
		}
		if m.ImageToolRateMicroUSDC != 22_000 {
			t.Errorf("tool cap = %d, want 22000", m.ImageToolRateMicroUSDC)
		}
		if m.ImageEditToolBaseMicroUSDC != 22_000 {
			t.Errorf("edit tool base = %d, want 22000 (only op1 offers the edit tool)", m.ImageEditToolBaseMicroUSDC)
		}
		return
	}
	t.Fatal("chat not aggregated")
}
