/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"testing"

	"github.com/TxnLab/zerosignal/go/wire"
)

// sampleOp is an ordinary, routable operator. ProtoVersion is this build's
// because the discovery aggregates hold out wire-incompatible nodes (empty reads
// as wire.LegacyProtoVersion, a different major), so a fixture without one would
// be invisible to every aggregate — a state dispatch also refuses, and therefore
// not what a test that isn't about versions means by "an operator".
func sampleOp(id uint64, addr, model string) Operator {
	return Operator{
		ID:           id,
		OwnerAddr:    addr,
		BaseURL:      "http://" + addr,
		Models:       []string{model},
		Reachable:    true,
		ProtoVersion: wire.ProtoVersion,
	}
}

func TestNewStaticRegistryProvider_RejectsDuplicateID(t *testing.T) {
	_, err := NewStaticRegistryProvider([]Operator{
		sampleOp(1, "A", "x"),
		sampleOp(1, "B", "y"),
	})
	if err == nil {
		t.Fatal("want duplicate-id error")
	}
}

func TestNewStaticRegistryProvider_RejectsZeroID(t *testing.T) {
	_, err := NewStaticRegistryProvider([]Operator{{OwnerAddr: "A", BaseURL: "http://a"}})
	if err == nil {
		t.Fatal("want missing-id error")
	}
}

func TestRegistry_OperatorsFiltersByModel(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{
		sampleOp(1, "A", "gpt-4o-mini"),
		sampleOp(2, "B", "gpt-4o"),
	})
	got, err := reg.Operators(context.Background(), "gpt-4o-mini")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != 1 {
		t.Errorf("Operators(gpt-4o-mini) = %+v", got)
	}
}

func TestRegistry_OperatorsPreservesConfiguredOrder(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{
		sampleOp(1, "A", "m"),
		sampleOp(2, "B", "m"),
		sampleOp(3, "C", "m"),
	})
	got, _ := reg.Operators(context.Background(), "m")
	if len(got) != 3 {
		t.Fatalf("len = %d", len(got))
	}
	for i, want := range []uint64{1, 2, 3} {
		if got[i].ID != want {
			t.Errorf("[%d] = %d, want %d", i, got[i].ID, want)
		}
	}
}

// An empty Models list means "serves nothing" — a node advertising zero models
// is not a routing candidate for any model, REGARDLESS of Reachable. This is the
// regression guard against the wildcard that made a reachable-but-empty node
// (e.g. a node whose whole catalog was dropped by the provenance gate) a
// tried-then-rejected candidate for every model, wasting reserve round-trips and
// masking no_operator as operators_busy.
func TestRegistry_EmptyModelsServesNothing(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{
		{ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true}, // reachable + empty
		sampleOp(2, "B", "gpt-4o"),
	})
	// Reachable + empty Models must NOT capture an arbitrary model.
	got, _ := reg.Operators(context.Background(), "anything")
	if len(got) != 0 {
		t.Errorf("reachable+empty-Models op must not wildcard; got %+v", got)
	}
	// And it must not shadow the real operator that actually serves the model.
	got2, _ := reg.Operators(context.Background(), "gpt-4o")
	if len(got2) != 1 || got2[0].ID != 2 {
		t.Errorf("only the model-serving op should match; got %+v", got2)
	}
}

// The unreachable + empty-Models case was already excluded (the earlier
// "operators_busy when one operator's details probe fails" fix); this keeps that
// covered alongside the reachable case above.
func TestRegistry_EmptyModelsAndUnreachableServesNothing(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{
		{ID: 1, OwnerAddr: "A", BaseURL: "http://a"}, // Reachable=false default
		sampleOp(2, "B", "gpt-4o"),
	})
	got, _ := reg.Operators(context.Background(), "gpt-4o")
	if len(got) != 1 || got[0].ID != 2 {
		t.Errorf("unreachable+empty-Models op should not match; got %+v", got)
	}
	got2, _ := reg.Operators(context.Background(), "something-else")
	if len(got2) != 0 {
		t.Errorf("unreachable+empty-Models op should not wildcard; got %+v", got2)
	}
}

func TestRegistry_Resolve(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{sampleOp(1, "A", "m"), sampleOp(2, "B", "m")})
	op, err := reg.Resolve(context.Background(), 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	if op.ID != 2 {
		t.Errorf("Resolve 2 → %d", op.ID)
	}
}

func TestRegistry_ResolveUnknown(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{sampleOp(1, "A", "m")})
	_, err := reg.Resolve(context.Background(), 999, 0)
	if !errors.Is(err, ErrOperatorUnknown) {
		t.Errorf("err = %v, want ErrOperatorUnknown", err)
	}
}

// One operator running two nodes must ingest (no duplicate-id rejection — the
// pre-split guard would have failed the whole build) and Resolve must address
// each node distinctly. The candidate path (Operators) returns both.
func TestRegistry_MultiNodeOperator(t *testing.T) {
	n1 := sampleOp(5, "A", "m")
	n1.NodeID = 1
	n2 := sampleOp(5, "A", "m")
	n2.NodeID = 2
	n2.BaseURL = "https://op5-b.example"

	reg, err := NewStaticRegistryProvider([]Operator{n1, n2})
	if err != nil {
		t.Fatalf("multi-node ingest rejected: %v", err)
	}
	got1, err := reg.Resolve(context.Background(), 5, 1)
	if err != nil || got1.NodeID != 1 {
		t.Errorf("Resolve(5,1) = (%+v, %v)", got1, err)
	}
	got2, err := reg.Resolve(context.Background(), 5, 2)
	if err != nil || got2.NodeID != 2 || got2.BaseURL != "https://op5-b.example" {
		t.Errorf("Resolve(5,2) = (%+v, %v)", got2, err)
	}
	if ops, _ := reg.Operators(context.Background(), "m"); len(ops) != 2 {
		t.Errorf("Operators(m) returned %d nodes, want 2", len(ops))
	}
	// A duplicate (id, node) IS still rejected.
	if _, err := NewStaticRegistryProvider([]Operator{n1, n1}); err == nil {
		t.Error("duplicate (id, node) should be rejected")
	}
}

func TestRegistry_AllBuiltinToolsDedupesUnion(t *testing.T) {
	op1 := sampleOp(1, "A", "m")
	op1.BuiltinTools = []BuiltinToolDef{
		{Type: "zs_web_search"},
		{Type: "zs_web_read"},
	}
	op2 := sampleOp(2, "B", "m")
	op2.BuiltinTools = []BuiltinToolDef{
		// duplicate type — collapses to a single entry in the union.
		{Type: "zs_web_search"},
		{Type: "zs_image_search"},
	}
	reg, _ := NewStaticRegistryProvider([]Operator{op1, op2})

	got := reg.AllBuiltinTools(context.Background())
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3: %+v", len(got), got)
	}

	byType := make(map[string]BuiltinToolDef, len(got))
	for _, t := range got {
		byType[t.Type] = t
	}
	for _, typ := range []string{"zs_web_search", "zs_web_read", "zs_image_search"} {
		if _, ok := byType[typ]; !ok {
			t.Errorf("missing %q in union", typ)
		}
	}
	// Dedup is by type only — name/description/parameters are no longer
	// carried in the advertisement (SPEC §3d), so the union is the set of
	// distinct types verified above.
}

func TestRegistry_AllBuiltinToolsEmptyWhenNoneAdvertised(t *testing.T) {
	reg, _ := NewStaticRegistryProvider([]Operator{sampleOp(1, "A", "m")})
	if got := reg.AllBuiltinTools(context.Background()); got != nil {
		t.Errorf("got %+v, want nil", got)
	}
}

func TestRegistry_AllOperatorsReturnsCopy(t *testing.T) {
	op1 := sampleOp(1, "A", "m")
	op2 := sampleOp(2, "B", "n")
	reg, _ := NewStaticRegistryProvider([]Operator{op1, op2})

	got := reg.AllOperators(context.Background())
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	if got[0].ID != 1 || got[1].ID != 2 {
		t.Errorf("ids = %d,%d, want 1,2", got[0].ID, got[1].ID)
	}

	// Mutating the returned slice must not affect a subsequent call.
	got[0].ID = 999
	again := reg.AllOperators(context.Background())
	if again[0].ID != 1 {
		t.Errorf("registry slice was aliased: again[0].ID = %d, want 1", again[0].ID)
	}
}
