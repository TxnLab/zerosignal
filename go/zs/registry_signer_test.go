/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
)

// The discovery surface must track routing: SelectTargets refuses a node whose
// signing account is below the floor, so its models leave the catalog too —
// while it stays in AllOperators (a broke node is still a valid relay hop) and
// in Operators(model) (RegistryCount accuracy for the 503).

func withSpendable(op Operator, v uint64) Operator {
	op.SignerSpendableMicroAlgos = &v
	return op
}

// signerFleet: a node exactly at the floor, one never read (nil), and one a
// microAlgo short serving a model nobody else does.
func signerFleet() (atFloor, unknown, broke Operator) {
	atFloor = withSpendable(reachableOp(1, "m"), selection.MinSignerSpendableMicroAlgos)
	atFloor.Models = []string{"m"}
	atFloor.BuiltinTools = []BuiltinToolDef{{Type: "zs_web_search"}}
	atFloor.NodeVersion = "v-floor"

	unknown = reachableOp(2, "u")
	unknown.Models = []string{"u"}
	unknown.NodeVersion = "v-unknown"

	broke = withSpendable(reachableOp(3, "broke-only"), selection.MinSignerSpendableMicroAlgos-1)
	broke.Models = []string{"broke-only"}
	broke.ModelCapacities = map[string]ModelCapacity{"broke-only": {ContextWindow: 4000}}
	broke.BuiltinTools = []BuiltinToolDef{{Type: "zs_image_search"}}
	broke.NodeVersion = "v-broke"
	return atFloor, unknown, broke
}

func assertSignerGate(t *testing.T, reg RegistryProvider) {
	t.Helper()
	ctx := context.Background()

	models := map[string]bool{}
	for _, m := range reg.AllModels(ctx) {
		models[m] = true
	}
	if !models["m"] || !models["u"] || models["broke-only"] || len(models) != 2 {
		t.Errorf("AllModels = %v, want exactly {m, u}: at-floor and never-read advertise, below-floor does not", models)
	}
	for _, d := range reg.AllModelDetails(ctx) {
		if d.ID == "broke-only" {
			t.Errorf("AllModelDetails includes %q, served only by an underfunded node", d.ID)
		}
	}
	for _, tool := range reg.AllBuiltinTools(ctx) {
		if tool.Type == "zs_image_search" {
			t.Error("AllBuiltinTools includes a tool only an underfunded node offers")
		}
	}
	for _, v := range reg.AllNodeVersions(ctx) {
		if v == "v-broke" {
			t.Error("AllNodeVersions includes an underfunded node's build")
		}
	}
	if got := reg.AllOperators(ctx); len(got) != 3 {
		t.Errorf("AllOperators len = %d, want 3 (an underfunded node is still a relay hop)", len(got))
	}
	if got, err := reg.Operators(ctx, "broke-only"); err != nil || len(got) != 1 {
		t.Errorf("Operators(broke-only) = %v, %v; want the node kept so RegistryCount stays accurate", got, err)
	}
}

func TestDynamicRegistry_DiscoveryExcludesUnderfundedSigner(t *testing.T) {
	atFloor, unknown, broke := signerFleet()
	assertSignerGate(t, stagingRegistry(t, false, atFloor, unknown, broke))
}

// The static provider has its own advertisable, so it needs its own pin — see
// TestStaticRegistry_AggregatesExcludeWireIncompatible.
func TestStaticRegistry_DiscoveryExcludesUnderfundedSigner(t *testing.T) {
	atFloor, unknown, broke := signerFleet()
	assertSignerGate(t, staticStaging(t, false, atFloor, unknown, broke))
}

// The WARN is how a payer learns why a model left their catalog, so it must
// fire on the transition in, name the signer, and give way to an Info on the
// way back — and stay quiet while nothing changes.
func TestDynamicRegistry_LogsSignerFundingTransitions(t *testing.T) {
	var buf bytes.Buffer
	reg := stagingRegistry(t, false)
	reg.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo}))

	funded := withSpendable(reachableOp(1, "m"), 20_000_000)
	funded.SigningAddr = "SIGNER1"
	broke := withSpendable(funded, 0)

	snap := func(op Operator) *registrySnapshot {
		s, err := buildSnapshot([]Operator{op})
		if err != nil {
			t.Fatalf("buildSnapshot: %v", err)
		}
		return s
	}

	reg.logTransitions(snap(funded), snap(funded))
	if strings.Contains(buf.String(), "routing floor") || strings.Contains(buf.String(), "topped up") {
		t.Fatalf("logged a funding transition with none: %s", buf.String())
	}

	reg.logTransitions(snap(funded), snap(broke))
	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "below the routing floor") || !strings.Contains(out, "SIGNER1") {
		t.Fatalf("funded→broke log = %q, want a WARN naming the signer", out)
	}

	buf.Reset()
	reg.logTransitions(snap(broke), snap(funded))
	if out := buf.String(); !strings.Contains(out, "level=INFO") || !strings.Contains(out, "topped up") {
		t.Fatalf("broke→funded log = %q, want an INFO recovery line", out)
	}

	// A rotated signer whose first read failed is unknown, not topped up.
	unknown := funded
	unknown.SignerSpendableMicroAlgos = nil
	buf.Reset()
	reg.logTransitions(snap(broke), snap(unknown))
	if out := buf.String(); strings.Contains(out, "topped up") || !strings.Contains(out, "unknown") {
		t.Fatalf("broke→unknown log = %q, want the unknown-balance line, not \"topped up\"", out)
	}

	// A node that appears already broke gets the WARN on arrival.
	newcomer := withSpendable(reachableOp(2, "m"), 0)
	newcomer.SigningAddr = "SIGNER2"
	buf.Reset()
	s, err := buildSnapshot([]Operator{funded, newcomer})
	if err != nil {
		t.Fatalf("buildSnapshot: %v", err)
	}
	reg.logTransitions(snap(funded), s)
	if out := buf.String(); !strings.Contains(out, "below the routing floor") || !strings.Contains(out, "SIGNER2") {
		t.Fatalf("added-broke log = %q, want a WARN naming SIGNER2", out)
	}
}

// Every refresh diffs against the startup seed, so a node broke at boot that
// stays broke never transitions: the constructor must name it.
func TestDynamicRegistry_WarnsUnderfundedInSeed(t *testing.T) {
	var buf bytes.Buffer
	broke := withSpendable(reachableOp(1, "m"), 0)
	broke.SigningAddr = "SEEDSIGNER"
	_, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{broke, reachableOp(2, "m")}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	out := buf.String()
	if strings.Count(out, "below the routing floor") != 1 || !strings.Contains(out, "SEEDSIGNER") {
		t.Errorf("seed log = %q, want exactly one WARN naming SEEDSIGNER", out)
	}
}
