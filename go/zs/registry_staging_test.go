/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/wire"
)

// The proxy must advertise exactly what it routes to. SelectTargets already
// refuses a staging node as a target unless the payer set zs.allow_staging, so a
// discovery surface that still lists its models promises capacity dispatch then
// answers with 503 no_production_operator — and lets that node set the
// cross-operator sizing and price floor for a model nobody can buy.
//
// These mirror the *ExcludesUnreachable family in registry_dynamic_test.go, with
// staging in place of unreachable, plus the two exclusions that must NOT happen.

// stagingOp is a reachable node its operator flagged staging on-chain.
func stagingOp(id uint64, model string) Operator {
	op := reachableOp(id, model)
	op.Staging = true
	return op
}

func stagingRegistry(t *testing.T, allowStaging bool, ops ...Operator) *DynamicRegistryProvider {
	t.Helper()
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, ops, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
		AllowStaging:    allowStaging,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	return reg
}

func TestDynamicRegistry_AllModelsExcludesStaging(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m", "shared"}
	op2 := stagingOp(2, "m")
	op2.Models = []string{"shared", "staging-only"}

	got := stagingRegistry(t, false, op1, op2).AllModels(context.Background())
	want := map[string]bool{"m": true, "shared": true}
	if len(got) != len(want) {
		t.Fatalf("AllModels = %v, want only the production union %v", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("AllModels included %q, served only by a staging node", m)
		}
	}
}

// TestDynamicRegistry_AllModelsIncludesStagingWhenAllowed pins the config
// threading: a payer who opted in sees the staging node's models.
func TestDynamicRegistry_AllModelsIncludesStagingWhenAllowed(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m"}
	op2 := stagingOp(2, "m")
	op2.Models = []string{"staging-only"}

	got := stagingRegistry(t, true, op1, op2).AllModels(context.Background())
	want := map[string]bool{"m": true, "staging-only": true}
	if len(got) != len(want) {
		t.Fatalf("AllModels = %v, want %v with allow_staging on", got, want)
	}
	for _, m := range got {
		if !want[m] {
			t.Errorf("AllModels = %v, unexpected %q", got, m)
		}
	}
}

func TestDynamicRegistry_AllModelDetailsExcludesStaging(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m"}
	op1.ModelCapacities = map[string]ModelCapacity{"m": {ContextWindow: 8000}}
	op2 := stagingOp(2, "m")
	op2.Models = []string{"staging-only"}
	op2.ModelCapacities = map[string]ModelCapacity{"staging-only": {ContextWindow: 4000}}

	got := stagingRegistry(t, false, op1, op2).AllModelDetails(context.Background())
	if len(got) != 1 || got[0].ID != "m" {
		t.Fatalf("AllModelDetails = %+v, want only [m]", got)
	}
}

// TestDynamicRegistry_StagingNodeDoesNotSetTheFloor is the quiet half of the bug:
// AllModelDetails folds sizing to the MINIMUM and price to the LOWEST across
// operators, so a staging node sharing a model with a production one drags the
// advertised context window and "from $X" rate down to numbers no payer can
// actually buy. Nothing 503s here — the number is just wrong.
func TestDynamicRegistry_StagingNodeDoesNotSetTheFloor(t *testing.T) {
	prod := reachableOp(1, "shared")
	prod.Models = []string{"shared"}
	prod.ModelCapacities = map[string]ModelCapacity{"shared": {
		ContextWindow:  128000,
		InputUSDPer1M:  1.0,
		OutputUSDPer1M: 2.0,
	}}
	staging := stagingOp(2, "shared")
	staging.Models = []string{"shared"}
	staging.ModelCapacities = map[string]ModelCapacity{"shared": {
		ContextWindow:  8000,
		InputUSDPer1M:  0.01,
		OutputUSDPer1M: 0.02,
	}}

	got := stagingRegistry(t, false, prod, staging).AllModelDetails(context.Background())
	if len(got) != 1 || got[0].ID != "shared" {
		t.Fatalf("AllModelDetails = %+v, want one entry for shared", got)
	}
	d := got[0]
	if d.ContextWindow != 128000 {
		t.Errorf("ContextWindow = %d, want 128000 (the staging node's 8000 must not set the floor)", d.ContextWindow)
	}
	if d.InputRateUSDPer1M != 1.0 {
		t.Errorf("InputRateUSDPer1M = %v, want 1.0 (not the staging node's unbuyable 0.01)", d.InputRateUSDPer1M)
	}
	if d.OutputRateUSDPer1M != 2.0 {
		t.Errorf("OutputRateUSDPer1M = %v, want 2.0 (not the staging node's unbuyable 0.02)", d.OutputRateUSDPer1M)
	}

	// The other arm, so the assertions above can't pass vacuously: with the payer
	// opted in, the staging node's numbers DO fold in and the floor drops.
	opted := stagingRegistry(t, true, prod, staging).AllModelDetails(context.Background())
	if len(opted) != 1 {
		t.Fatalf("AllModelDetails with allow_staging = %+v, want one entry", opted)
	}
	if opted[0].ContextWindow != 8000 || opted[0].InputRateUSDPer1M != 0.01 {
		t.Fatalf("with allow_staging: ContextWindow=%d InputRate=%v, want 8000/0.01 — "+
			"the staging node must fold in once opted in, or the assertions above prove nothing",
			opted[0].ContextWindow, opted[0].InputRateUSDPer1M)
	}
}

func TestDynamicRegistry_AllBuiltinToolsExcludesStaging(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	op2 := stagingOp(2, "m")
	op2.BuiltinTools = []BuiltinToolDef{{Type: "zs_image_search"}}

	got := stagingRegistry(t, false, op1, op2).AllBuiltinTools(context.Background())
	if len(got) != 1 || got[0].Type != "zs_web_search" {
		t.Fatalf("AllBuiltinTools = %+v, want only [zs_web_search]", got)
	}
}

func TestDynamicRegistry_AllNodeVersionsExcludesStaging(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.NodeVersion = "abc1234"
	op2 := stagingOp(2, "m")
	op2.NodeVersion = "def5678"

	got := stagingRegistry(t, false, op1, op2).AllNodeVersions(context.Background())
	if len(got) != 1 || got[0] != "abc1234" {
		t.Fatalf("AllNodeVersions = %+v, want only [abc1234]", got)
	}
}

// TestDynamicRegistry_AllOperatorsKeepsStagingForRelayUse is the hard constraint.
// proto/SPEC.md: the staging flag "gates TARGET selection only. Staging nodes
// remain usable as relays, since a relay forwards bytes and runs no inference."
// Server.relayPool builds the relay pool from AllOperators, so filtering staging
// there would silently shrink the pool SPEC §3f diffusion depends on. The
// payer-facing production view is applied by handleHayaiOperators instead.
func TestDynamicRegistry_AllOperatorsKeepsStagingForRelayUse(t *testing.T) {
	op := stagingOp(1, "m")

	got := stagingRegistry(t, false, op).AllOperators(context.Background())
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("AllOperators = %+v, want the staging node kept (it is still a valid relay hop)", got)
	}
	if !got[0].Staging {
		t.Error("AllOperators dropped the Staging flag; handleHayaiOperators needs it to filter and mark")
	}
}

// TestDynamicRegistry_OperatorsKeepsStagingForDispatch is the sibling of
// OperatorsKeepsUnreachableForDispatch. Operators(model) must keep the staging
// node so pickCandidates' RegistryCount stays accurate — that is what lets
// SelectTargets report staging_blocked (503 no_production_operator, with its
// actionable "enable zs.allow_staging" hint) rather than a bare "nobody serves
// this model" for a client that POSTs an id it never saw listed.
func TestDynamicRegistry_OperatorsKeepsStagingForDispatch(t *testing.T) {
	op := stagingOp(1, "staging-only")
	op.Models = []string{"staging-only"}
	reg := stagingRegistry(t, false, op)

	got, err := reg.Operators(context.Background(), "staging-only")
	if err != nil {
		t.Fatalf("Operators: %v", err)
	}
	if len(got) != 1 || got[0].ID != 1 {
		t.Fatalf("Operators(staging-only) = %+v, want the staging node (RegistryCount accuracy)", got)
	}
	// …and it must not reach the discovery surface.
	if mods := reg.AllModels(context.Background()); len(mods) != 0 {
		t.Fatalf("AllModels = %+v, want empty (the only node is staging)", mods)
	}
}

// --- wire-version gate ---
//
// The second half of "advertise exactly what you can route to". SelectTargets
// refuses a node on a different wire major and dispatch answers 503
// no_compatible_operator, so listing its models is the same advertise-then-refuse
// shape the staging gate closes above.

// incompatibleOp is reachable and serving, but speaks a wire major this build
// cannot seal for.
func incompatibleOp(id uint64, model string) Operator {
	op := reachableOp(id, model)
	op.ProtoVersion = "1.0" // wire.LegacyProtoVersion — major 1, this build is 9
	return op
}

func TestDynamicRegistry_AggregatesExcludeWireIncompatible(t *testing.T) {
	prod := reachableOp(1, "m")
	prod.Models = []string{"m"}
	prod.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	prod.NodeVersion = "abc1234"
	old := incompatibleOp(2, "m")
	old.Models = []string{"legacy-only"}
	old.ModelCapacities = map[string]ModelCapacity{"legacy-only": {ContextWindow: 4000}}
	old.BuiltinTools = []BuiltinToolDef{{Type: "zs_image_search"}}
	old.NodeVersion = "def5678"

	reg := stagingRegistry(t, false, prod, old)
	ctx := context.Background()

	if got := reg.AllModels(ctx); len(got) != 1 || got[0] != "m" {
		t.Errorf("AllModels = %v, want only [m]", got)
	}
	if got := reg.AllModelDetails(ctx); len(got) != 1 || got[0].ID != "m" {
		t.Errorf("AllModelDetails = %+v, want only [m]", got)
	}
	if got := reg.AllBuiltinTools(ctx); len(got) != 1 || got[0].Type != "zs_web_search" {
		t.Errorf("AllBuiltinTools = %+v, want only [zs_web_search]", got)
	}
	if got := reg.AllNodeVersions(ctx); len(got) != 1 || got[0] != "abc1234" {
		t.Errorf("AllNodeVersions = %v, want only [abc1234]", got)
	}
}

// TestWireIncompatible_EmptyVersionIsIncompatible pins the edge case the gate
// turns on. ProtoVersionCompatible maps "" to wire.LegacyProtoVersion, a
// different major than this build — so an unset version reads as incompatible,
// and a fixture (or a node whose details probe predates the field) silently
// vanishes from discovery. That is correct, because dispatch refuses it too; it
// is safe only because ProtoVersion is set by the details probe and every
// advertisable node has had a successful one.
func TestWireIncompatible_EmptyVersionIsIncompatible(t *testing.T) {
	if !wireIncompatible(Operator{}) {
		t.Error("empty ProtoVersion should read as incompatible (maps to LegacyProtoVersion)")
	}
	if wireIncompatible(Operator{ProtoVersion: wire.ProtoVersion}) {
		t.Error("this build's own version must be compatible")
	}
}

// TestDynamicRegistry_AllOperatorsKeepsWireIncompatible is the relay-pool twin of
// the staging constraint: EligibleRelays applies its own version rule and
// buildSelAll seeds an unprobed peer with BootstrapProtoVersion to keep it
// relay-eligible, so this method must hand over the unfiltered fleet.
func TestDynamicRegistry_AllOperatorsKeepsWireIncompatible(t *testing.T) {
	got := stagingRegistry(t, false, incompatibleOp(1, "m")).AllOperators(context.Background())
	if len(got) != 1 {
		t.Fatalf("AllOperators = %+v, want the wire-incompatible node kept (relay eligibility is decided downstream)", got)
	}
}

// TestStaticRegistry_AggregatesExcludeWireIncompatible is the static mirror of
// the gate above, and it is not redundant: every internal/server discovery test
// runs on StaticRegistryProvider, so this is the provider a handler-layer
// regression actually surfaces on. Without it, deleting the wireIncompatible
// conjunct from the static advertisable leaves the whole suite green.
func TestStaticRegistry_AggregatesExcludeWireIncompatible(t *testing.T) {
	prod := reachableOp(1, "m")
	prod.Models = []string{"m"}
	prod.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	prod.NodeVersion = "abc1234"
	old := incompatibleOp(2, "m")
	old.Models = []string{"legacy-only"}
	old.ModelCapacities = map[string]ModelCapacity{"legacy-only": {ContextWindow: 4000}}
	old.BuiltinTools = []BuiltinToolDef{{Type: "zs_image_search"}}
	old.NodeVersion = "def5678"

	reg := staticStaging(t, false, prod, old)
	ctx := context.Background()

	if got := reg.AllModels(ctx); len(got) != 1 || got[0] != "m" {
		t.Errorf("AllModels = %v, want only [m]", got)
	}
	if got := reg.AllModelDetails(ctx); len(got) != 1 || got[0].ID != "m" {
		t.Errorf("AllModelDetails = %+v, want only [m]", got)
	}
	if got := reg.AllBuiltinTools(ctx); len(got) != 1 || got[0].Type != "zs_web_search" {
		t.Errorf("AllBuiltinTools = %+v, want only [zs_web_search]", got)
	}
	if got := reg.AllNodeVersions(ctx); len(got) != 1 || got[0] != "abc1234" {
		t.Errorf("AllNodeVersions = %v, want only [abc1234]", got)
	}
	// Relay-pool constraint holds here too.
	if got := reg.AllOperators(ctx); len(got) != 2 {
		t.Errorf("AllOperators len = %d, want 2 (relay eligibility is decided downstream)", len(got))
	}
}

// --- static provider mirror ---

func staticStaging(t *testing.T, allowStaging bool, ops ...Operator) *StaticRegistryProvider {
	t.Helper()
	reg, err := NewStaticRegistryProviderWithConfig(ops, StaticRegistryConfig{AllowStaging: allowStaging})
	if err != nil {
		t.Fatalf("NewStaticRegistryProviderWithConfig: %v", err)
	}
	return reg
}

func TestStaticRegistry_AggregatesExcludeStaging(t *testing.T) {
	op1 := reachableOp(1, "m")
	op1.Models = []string{"m"}
	op1.ModelCapacities = map[string]ModelCapacity{"m": {ContextWindow: 8000}}
	op1.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	op1.NodeVersion = "abc1234"
	op2 := stagingOp(2, "m")
	op2.Models = []string{"staging-only"}
	op2.ModelCapacities = map[string]ModelCapacity{"staging-only": {ContextWindow: 4000}}
	op2.BuiltinTools = []BuiltinToolDef{{Type: "zs_image_search"}}
	op2.NodeVersion = "def5678"

	reg := staticStaging(t, false, op1, op2)
	ctx := context.Background()

	if got := reg.AllModels(ctx); len(got) != 1 || got[0] != "m" {
		t.Errorf("AllModels = %v, want only [m]", got)
	}
	if got := reg.AllModelDetails(ctx); len(got) != 1 || got[0].ID != "m" {
		t.Errorf("AllModelDetails = %+v, want only [m]", got)
	}
	if got := reg.AllBuiltinTools(ctx); len(got) != 1 || got[0].Type != "zs_web_search" {
		t.Errorf("AllBuiltinTools = %+v, want only [zs_web_search]", got)
	}
	if got := reg.AllNodeVersions(ctx); len(got) != 1 || got[0] != "abc1234" {
		t.Errorf("AllNodeVersions = %v, want only [abc1234]", got)
	}
	// The relay-pool constraint holds on this provider too.
	if got := reg.AllOperators(ctx); len(got) != 2 {
		t.Errorf("AllOperators len = %d, want 2 (staging nodes stay — relay pool)", len(got))
	}
}

func TestStaticRegistry_AllowStagingKeepsStaging(t *testing.T) {
	op := stagingOp(1, "staging-only")
	op.Models = []string{"staging-only"}

	got := staticStaging(t, true, op).AllModels(context.Background())
	if len(got) != 1 || got[0] != "staging-only" {
		t.Fatalf("AllModels = %v, want [staging-only] with allow_staging on", got)
	}
}

// TestStaticRegistry_DefaultConstructorIsStagingOff pins the one thing a
// two-constructor design can get wrong: NewStaticRegistryProvider must delegate
// with the production-safe default, not the permissive one.
func TestStaticRegistry_DefaultConstructorIsStagingOff(t *testing.T) {
	op := stagingOp(1, "staging-only")
	op.Models = []string{"staging-only"}

	reg, err := NewStaticRegistryProvider([]Operator{op})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	if got := reg.AllModels(context.Background()); len(got) != 0 {
		t.Fatalf("AllModels = %v, want empty — the default constructor must be staging-OFF", got)
	}
}
