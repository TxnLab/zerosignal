/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/wire"
)

var (
	digestA = "sha256:" + strings.Repeat("a", 64)
	digestB = "sha256:" + strings.Repeat("b", 64)
)

func TestAggregateDigest(t *testing.T) {
	cases := []struct {
		name        string
		in          []string
		wantConsens string
		wantMis     bool
	}{
		{"all agree", []string{digestA, digestA}, digestA, false},
		{"single", []string{digestA}, digestA, false},
		{"two distinct → mismatch", []string{digestA, digestB}, "", true},
		{"three, one differs → mismatch", []string{digestA, digestA, digestB}, "", true},
		{"empties ignored", []string{digestA, "", digestA}, digestA, false},
		{"all empty", []string{"", ""}, "", false},
		{"nil", nil, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotC, gotM := aggregateDigest(tc.in)
			if gotC != tc.wantConsens || gotM != tc.wantMis {
				t.Fatalf("aggregateDigest(%v) = (%q,%v), want (%q,%v)", tc.in, gotC, gotM, tc.wantConsens, tc.wantMis)
			}
		})
	}
}

// weightsOp builds a one-model operator with the given hot weights signal.
func weightsOp(id uint64, digest string, unverifiable bool) Operator {
	return Operator{
		ID: id, OwnerAddr: "O", BaseURL: "http://x", Reachable: true, ReachableAsOf: time.Now(),
		ProtoVersion:    wire.ProtoVersion,
		Models:          []string{"m1"},
		ModelCapacities: map[string]ModelCapacity{"m1": {WeightsDigest: digest, WeightsUnverifiable: unverifiable}},
	}
}

func TestAllModelDetails_WeightsConsensusStatic(t *testing.T) {
	reg, err := NewStaticRegistryProvider([]Operator{weightsOp(1, digestA, false), weightsOp(2, digestA, false)})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v", out)
	}
	if out[0].WeightsDigest != digestA || out[0].WeightsMismatch {
		t.Errorf("agree → digest=%q mismatch=%v, want %q/false", out[0].WeightsDigest, out[0].WeightsMismatch, digestA)
	}
}

func TestAllModelDetails_WeightsMismatchStatic(t *testing.T) {
	reg, err := NewStaticRegistryProvider([]Operator{weightsOp(1, digestA, false), weightsOp(2, digestB, false)})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v", out)
	}
	// ≥2 distinct digests → mismatch flagged, no false consensus.
	if !out[0].WeightsMismatch || out[0].WeightsDigest != "" {
		t.Errorf("distinct → digest=%q mismatch=%v, want \"\"/true", out[0].WeightsDigest, out[0].WeightsMismatch)
	}
}

func TestAllModelDetails_WeightsVerifiablePlusUnverifiable(t *testing.T) {
	// op1 verifiable with a digest; op2 unverifiable (no digest). The
	// unverifiable operator is ignored — consensus comes from op1, no mismatch.
	reg, err := NewStaticRegistryProvider([]Operator{weightsOp(1, digestA, false), weightsOp(2, "", true)})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v", out)
	}
	if out[0].WeightsDigest != digestA || out[0].WeightsMismatch {
		t.Errorf("verifiable+unverifiable → digest=%q mismatch=%v, want %q/false", out[0].WeightsDigest, out[0].WeightsMismatch, digestA)
	}
}

func TestAllModelDetails_WeightsUnreachableExcluded(t *testing.T) {
	// op2 declares a conflicting digest but is UNREACHABLE → excluded from the
	// vote, so op1's digest stands and there is no false mismatch.
	op2 := weightsOp(2, digestB, false)
	op2.Reachable = false
	reg, err := NewStaticRegistryProvider([]Operator{weightsOp(1, digestA, false), op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v", out)
	}
	if out[0].WeightsDigest != digestA || out[0].WeightsMismatch {
		t.Errorf("unreachable excluded → digest=%q mismatch=%v, want %q/false", out[0].WeightsDigest, out[0].WeightsMismatch, digestA)
	}
}

// Both registry impls must agree (the standing "keep both in sync" rule).
func TestAllModelDetails_WeightsMismatchDynamic(t *testing.T) {
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{weightsOp(1, digestA, false), weightsOp(2, digestB, false)}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("dynamic AllModelDetails = %+v", out)
	}
	if !out[0].WeightsMismatch || out[0].WeightsDigest != "" {
		t.Errorf("dynamic distinct → digest=%q mismatch=%v, want \"\"/true; both impls must match", out[0].WeightsDigest, out[0].WeightsMismatch)
	}
}
