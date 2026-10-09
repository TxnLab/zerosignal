/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
)

func TestMaxDeclaredOutput(t *testing.T) {
	declaring := func(caps ...uint64) []Operator {
		ops := make([]Operator, len(caps))
		for i, c := range caps {
			ops[i] = Operator{ModelCapacities: map[string]ModelCapacity{
				"m": {ContextWindow: 262_144, MaxOutputTokens: c},
			}}
		}
		return ops
	}

	cases := []struct {
		name string
		ops  []Operator
		want uint64
	}{
		{
			// The MAX, not the min: a caller asking for a big budget should be
			// lowered to what the most generous operator can serve, not to what
			// the stingiest one can. Taking the min here would clamp every
			// request down to the pool's weakest node.
			name: "largest declared cap wins",
			ops:  declaring(8192, 32768, 16384),
			want: 32768,
		},
		{
			name: "single operator",
			ops:  declaring(32768),
			want: 32768,
		},
		{
			// One undeclared cap makes the whole pool unclampable: Fits treats an
			// undeclared cap as unbounded, so that operator CAN honor whatever the
			// caller asked for. Clamping would take capability away for nothing.
			name: "any operator declaring zero disables the clamp",
			ops:  declaring(32768, 0),
			want: 0,
		},
		{
			name: "operator with no capacity entry for the model disables the clamp",
			ops: append(declaring(32768), Operator{ModelCapacities: map[string]ModelCapacity{
				"other-model": {MaxOutputTokens: 1024},
			}}),
			want: 0,
		},
		{
			name: "operator with no capacities at all disables the clamp",
			ops:  append(declaring(32768), Operator{}),
			want: 0,
		},
		{
			// Nobody serves the model — pickCandidates turns this into its own
			// no_operator, so there is nothing to clamp against.
			name: "empty pool",
			ops:  nil,
			want: 0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MaxDeclaredOutput(tc.ops, "m"); got != tc.want {
				t.Errorf("MaxDeclaredOutput = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestFits_NoDeclaredCapacity(t *testing.T) {
	op := Operator{} // ModelCapacities is nil
	if !Fits(op, SizingRequest{Model: "m", InputTokens: 10_000, MaxOutputTokens: 10_000}) {
		t.Fatal("undeclared capacity should fit anything")
	}
	// Explicit empty map has the same meaning.
	op.ModelCapacities = map[string]ModelCapacity{}
	if !Fits(op, SizingRequest{Model: "m", InputTokens: 1, MaxOutputTokens: 1}) {
		t.Fatal("empty ModelCapacities should fit")
	}
}

func TestFits_ModelNotDeclared(t *testing.T) {
	op := Operator{
		ModelCapacities: map[string]ModelCapacity{
			"other-model": {ContextWindow: 100},
		},
	}
	// The filter is per-model: other-model has a cap, but the request
	// is for a model not in the table → treated as unbounded.
	if !Fits(op, SizingRequest{Model: "this-model", InputTokens: 10_000, MaxOutputTokens: 10_000}) {
		t.Fatal("unlisted model should bypass the filter")
	}
}

func TestFits_ContextWindow(t *testing.T) {
	op := Operator{
		ModelCapacities: map[string]ModelCapacity{
			"m": {ContextWindow: 100},
		},
	}
	tests := []struct {
		name string
		req  SizingRequest
		want bool
	}{
		{"exact", SizingRequest{Model: "m", InputTokens: 50, MaxOutputTokens: 50}, true},
		{"one-under", SizingRequest{Model: "m", InputTokens: 50, MaxOutputTokens: 49}, true},
		{"one-over", SizingRequest{Model: "m", InputTokens: 50, MaxOutputTokens: 51}, false},
		{"zero-in-out", SizingRequest{Model: "m", InputTokens: 0, MaxOutputTokens: 0}, true},
	}
	for _, tc := range tests {
		if got := Fits(op, tc.req); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}

func TestFits_MaxOutputCap(t *testing.T) {
	op := Operator{
		ModelCapacities: map[string]ModelCapacity{
			"m": {ContextWindow: 100_000, MaxOutputTokens: 256},
		},
	}
	// ContextWindow is loose, MaxOutputTokens is the active constraint.
	if !Fits(op, SizingRequest{Model: "m", InputTokens: 10, MaxOutputTokens: 256}) {
		t.Error("exact max-output should fit")
	}
	if Fits(op, SizingRequest{Model: "m", InputTokens: 10, MaxOutputTokens: 257}) {
		t.Error("exceeding max-output should not fit")
	}
}

func TestFits_OverflowGuard(t *testing.T) {
	op := Operator{
		ModelCapacities: map[string]ModelCapacity{
			"m": {ContextWindow: 200},
		},
	}
	// Two huge numbers that would wrap on sum — must not sneak past by
	// overflow.
	huge := uint64(1) << 63
	if Fits(op, SizingRequest{Model: "m", InputTokens: huge, MaxOutputTokens: huge}) {
		t.Error("overflow sum should not be treated as fitting")
	}
}

func opWithCap(mc ModelCapacity) Operator {
	return Operator{ModelCapacities: map[string]ModelCapacity{"m": mc}}
}

// TestEffectiveMaxOutput covers the per-operator resolution shared by the sizing
// filter and the reserve loop: flat when the caller specified a max, else the
// three DeriveMaxOutput branches (declared verbatim, proportionate ctx/4, flat
// fallback for an unbounded operator).
func TestEffectiveMaxOutput(t *testing.T) {
	reasoning := opWithCap(ModelCapacity{ContextWindow: 128000, Reasoning: &inject.ModelReasoning{Supported: true}})
	tests := []struct {
		name string
		op   Operator
		req  SizingRequest
		want uint64
	}{
		{
			name: "flat_when_specified",
			op:   opWithCap(ModelCapacity{ContextWindow: 4096}),
			req:  SizingRequest{Model: "m", MaxOutputTokens: 1234},
			want: 1234, // DeriveMaxOutput unset → flat value verbatim.
		},
		{
			name: "derive_declared_verbatim",
			op:   opWithCap(ModelCapacity{ContextWindow: 128000, MaxOutputTokens: 2048}),
			req:  SizingRequest{Model: "m", DeriveMaxOutput: true, MaxOutputCeiling: 8192},
			want: 2048,
		},
		{
			name: "derive_proportionate",
			op:   opWithCap(ModelCapacity{ContextWindow: 4096}),
			req:  SizingRequest{Model: "m", DeriveMaxOutput: true, MaxOutputCeiling: 8192},
			want: 1024, // ctx/4.
		},
		{
			name: "derive_proportionate_ceiling",
			op:   opWithCap(ModelCapacity{ContextWindow: 128000}),
			req:  SizingRequest{Model: "m", DeriveMaxOutput: true, MaxOutputCeiling: 8192},
			want: 8192, // ctx/4=32000 clamped to the base ceiling.
		},
		{
			// Reasoning no longer raises the ceiling — there is one ceiling now,
			// at the value that raise used. Identical inputs to
			// derive_proportionate_ceiling above, and identical result: pins the
			// advertised reasoning flag as inert for sizing.
			name: "derive_reasoning_does_not_raise_ceiling",
			op:   reasoning,
			req:  SizingRequest{Model: "m", DeriveMaxOutput: true, MaxOutputCeiling: 8192},
			want: 8192, // ctx/4=32000 clamped to the base ceiling, same as non-reasoning.
		},
		{
			// The ceiling every caller actually passes.
			name: "derive_default_ceiling",
			op:   opWithCap(ModelCapacity{ContextWindow: 262144}),
			req:  SizingRequest{Model: "m", DeriveMaxOutput: true, MaxOutputCeiling: selection.DefaultMaxOutputCeiling},
			want: selection.DefaultMaxOutputCeiling, // ctx/4=65536 clamped to 32768.
		},
		{
			name: "derive_no_capacity_is_flat_fallback",
			op:   Operator{}, // unbounded operator.
			req:  SizingRequest{Model: "m", DeriveMaxOutput: true, MaxOutputCeiling: 8192},
			want: 8192,
		},
	}
	for _, tc := range tests {
		if got := EffectiveMaxOutput(tc.op, tc.req); got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

// TestFits_DeriveMode confirms the fit check charges the per-operator derived
// max_output — a small-window operator survives (unlike the flat-ceiling path),
// a declared cap that plus input overflows the window is dropped, and a ceiling
// too high to clamp ctx/4 lets the larger reservation itself cause a miss.
func TestFits_DeriveMode(t *testing.T) {
	derive := func(input, ceiling uint64) SizingRequest {
		return SizingRequest{Model: "m", InputTokens: input, DeriveMaxOutput: true, MaxOutputCeiling: ceiling}
	}
	// Small window (4096) that a flat 8192 ceiling would exclude (100+8192>4096);
	// derived ctx/4=1024 → 100+1024<=4096 fits.
	small := opWithCap(ModelCapacity{ContextWindow: 4096})
	if Fits(small, SizingRequest{Model: "m", InputTokens: 100, MaxOutputTokens: 8192}) {
		t.Fatal("flat 8192 should NOT fit a 4096 window (control)")
	}
	if !Fits(small, derive(100, 8192)) {
		t.Fatal("derive mode should fit the small-window operator")
	}
	// Declared cap is authoritative: 200+4000 > 4096 → miss (proves derive used
	// the declared 4000, not ctx/4=1024 which would have fit).
	declared := opWithCap(ModelCapacity{ContextWindow: 4096, MaxOutputTokens: 4000})
	if Fits(declared, derive(200, 8192)) {
		t.Fatal("declared cap 4000 + input 200 should overflow the 4096 window")
	}
	// A ceiling above ctx/4 leaves the proportionate slice unclamped, and the
	// larger reservation can itself overflow: 31000+10000 > 40000 misses where
	// the 8192-clamped reservation fits.
	mid := opWithCap(ModelCapacity{ContextWindow: 40000})
	if Fits(mid, derive(31000, selection.DefaultMaxOutputCeiling)) {
		t.Fatal("unclamped reservation 10000 + input 31000 should overflow the 40000 window")
	}
	if !Fits(mid, derive(31000, 8192)) {
		t.Fatal("clamped reservation 8192 + input 31000 should fit the 40000 window")
	}
	// The advertised reasoning flag is inert for sizing: same window, same
	// ceiling, same verdict as the non-reasoning operator above.
	reason := opWithCap(ModelCapacity{ContextWindow: 40000, Reasoning: &inject.ModelReasoning{Supported: true}})
	if !Fits(reason, derive(31000, 8192)) {
		t.Fatal("reasoning must not change the derived reservation")
	}
}

// TestFits_PerOperatorInputBound covers the gap between the eligibility filter
// and the reserve leg.
//
// v1 prices every image at a flat 2048x2048 fallback (2805 tokens) while v2
// reads the real dimensions. Filtering an image request on the v1 number routes
// it away from small-window operators the reserve would then have fit
// comfortably — the filter and the escrow disagreeing about the same request.
func TestFits_PerOperatorInputBound(t *testing.T) {
	caps := map[string]ModelCapacity{"m": {ContextWindow: 3000}}
	newOp := func(version string) Operator {
		return Operator{ProtoVersion: version, ModelCapacities: caps}
	}
	// 2950 + 100 exceeds the window (FitsContextWindow is inclusive); 300 + 100
	// does not.
	req := SizingRequest{Model: "m", InputTokens: 2950, InputTokensV2: 300, MaxOutputTokens: 100}

	if Fits(newOp("9.1"), req) {
		t.Error("a 9.1 operator must be filtered on the v1 measurement — it cannot honour v2")
	}
	if !Fits(newOp("9.2"), req) {
		t.Error("a 9.2 operator must be filtered on the v2 measurement, the same one the reserve uses")
	}
	for _, v := range []string{"", "garbage", "9.0"} {
		if Fits(newOp(v), req) {
			t.Errorf("version %q must fail toward v1", v)
		}
	}

	// Opt-out: no v2 measurement supplied means every operator is filtered on
	// InputTokens, which is the pre-9.2 behaviour.
	noV2 := SizingRequest{Model: "m", InputTokens: 2950, MaxOutputTokens: 100}
	if Fits(newOp("9.2"), noV2) {
		t.Error("absent InputTokensV2 must fall back to InputTokens for every operator")
	}
}
