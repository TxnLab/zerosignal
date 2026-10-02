/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/wire"
)

func TestAggregateCoordinates(t *testing.T) {
	c := func(family, quant, variant string, params uint64) *inject.ModelCoordinates {
		return &inject.ModelCoordinates{Family: family, Quantization: quant, Variant: variant, Parameters: params}
	}

	// All agree → every field surfaces.
	got := aggregateCoordinates([]*inject.ModelCoordinates{
		c("qwen/q", "Q4", "instruct", 7_000_000_000),
		c("qwen/q", "Q4", "instruct", 7_000_000_000),
	})
	if got == nil || got.Family != "qwen/q" || got.Quantization != "Q4" || got.Variant != "instruct" || got.Parameters != 7_000_000_000 {
		t.Fatalf("agree = %+v", got)
	}

	// Disagree on quant only → family/params survive, quant omitted (no false
	// consensus); the rest agree.
	got = aggregateCoordinates([]*inject.ModelCoordinates{
		c("qwen/q", "Q4", "", 7_000_000_000),
		c("qwen/q", "Q5", "", 7_000_000_000),
	})
	if got.Family != "qwen/q" || got.Parameters != 7_000_000_000 {
		t.Errorf("agreed fields lost: %+v", got)
	}
	if got.Quantization != "" {
		t.Errorf("quant = %q, want omitted on disagreement", got.Quantization)
	}

	// Majority wins over a single outlier.
	got = aggregateCoordinates([]*inject.ModelCoordinates{c("f", "", "", 0), c("f", "", "", 0), c("g", "", "", 0)})
	if got == nil || got.Family != "f" {
		t.Errorf("majority = %+v, want family f", got)
	}

	// Two-way tie → omit.
	got = aggregateCoordinates([]*inject.ModelCoordinates{c("f", "", "", 0), c("g", "", "", 0)})
	if got != nil {
		t.Errorf("tie = %+v, want nil (no field has a unique mode)", got)
	}

	// Each field present on exactly one operator → each unique value wins.
	got = aggregateCoordinates([]*inject.ModelCoordinates{c("f", "", "", 0), c("", "Q4", "", 0)})
	if got == nil || got.Family != "f" || got.Quantization != "Q4" {
		t.Errorf("mixed presence = %+v", got)
	}

	// uint64 path: majority wins over an outlier; a 2-way tie omits.
	got = aggregateCoordinates([]*inject.ModelCoordinates{c("", "", "", 7_000_000_000), c("", "", "", 7_000_000_000), c("", "", "", 26_000_000_000)})
	if got == nil || got.Parameters != 7_000_000_000 {
		t.Errorf("params majority = %+v, want 7e9", got)
	}
	if got := aggregateCoordinates([]*inject.ModelCoordinates{c("", "", "", 7_000_000_000), c("", "", "", 26_000_000_000)}); got != nil {
		t.Errorf("params 2-way tie = %+v, want nil", got)
	}

	// Nothing declared → nil.
	if got := aggregateCoordinates([]*inject.ModelCoordinates{nil, {}}); got != nil {
		t.Errorf("empty = %+v, want nil", got)
	}
	if got := aggregateCoordinates(nil); got != nil {
		t.Errorf("nil input = %+v, want nil", got)
	}
}

func coordOp(id uint64, coords *inject.ModelCoordinates) Operator {
	return Operator{
		ID: id, OwnerAddr: "O", BaseURL: "http://x", Reachable: true, ReachableAsOf: time.Now(),
		ProtoVersion:    wire.ProtoVersion,
		Models:          []string{"m1"},
		ModelCapacities: map[string]ModelCapacity{"m1": {Coordinates: coords}},
	}
}

func TestAllModelDetails_CoordinatesStatic(t *testing.T) {
	op1 := coordOp(1, &inject.ModelCoordinates{Family: "qwen/q", Parameters: 7_000_000_000, Quantization: "Q4"})
	op2 := coordOp(2, &inject.ModelCoordinates{Family: "qwen/q", Parameters: 7_000_000_000, Quantization: "Q5"})
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 || out[0].Coordinates == nil {
		t.Fatalf("AllModelDetails = %+v", out)
	}
	co := out[0].Coordinates
	if co.Family != "qwen/q" || co.Parameters != 7_000_000_000 {
		t.Errorf("agreed coords lost: %+v", co)
	}
	if co.Quantization != "" {
		t.Errorf("quant = %q, want omitted (operators disagree)", co.Quantization)
	}
}

func TestAllModelDetails_CoordinatesUnreachableAndMixed(t *testing.T) {
	// op1 reachable declares family+quant; op2 UNREACHABLE declares a conflicting
	// quant (must be excluded from the vote, not force omission); op3 reachable
	// serves the model but declares NO coordinates (votes nothing).
	op1 := coordOp(1, &inject.ModelCoordinates{Family: "qwen/q", Quantization: "Q4"})
	op2 := coordOp(2, &inject.ModelCoordinates{Family: "qwen/q", Quantization: "Q5"})
	op2.Reachable = false
	op3 := coordOp(3, nil)
	reg, err := NewStaticRegistryProvider([]Operator{op1, op2, op3})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 || out[0].Coordinates == nil {
		t.Fatalf("AllModelDetails = %+v", out)
	}
	co := out[0].Coordinates
	// Only op1 votes (op2 unreachable, op3 declared nothing) → its Q4 stands;
	// the unreachable op2's conflicting Q5 did NOT trigger omit-on-disagreement.
	if co.Quantization != "Q4" {
		t.Errorf("quant = %q, want Q4 (unreachable conflicting vote excluded)", co.Quantization)
	}
	if co.Family != "qwen/q" {
		t.Errorf("family = %q, want qwen/q", co.Family)
	}
}

func TestAllModelDetails_CoordinatesDynamic(t *testing.T) {
	op1 := coordOp(1, &inject.ModelCoordinates{Family: "qwen/q", Quantization: "Q4"})
	op2 := coordOp(2, &inject.ModelCoordinates{Family: "qwen/q", Quantization: "Q5"})
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{op1, op2}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 || out[0].Coordinates == nil {
		t.Fatalf("dynamic AllModelDetails = %+v", out)
	}
	co := out[0].Coordinates
	if co.Family != "qwen/q" {
		t.Errorf("family = %q, want qwen/q", co.Family)
	}
	if co.Quantization != "" {
		t.Errorf("quant = %q, want omitted (disagreement); both impls must match", co.Quantization)
	}
}
