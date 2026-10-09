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

func TestAggregateIdentity(t *testing.T) {
	// Every declaring operator agrees → that value.
	if got := aggregateIdentity([]string{"hf:a/b", "hf:a/b"}); got != "hf:a/b" {
		t.Errorf("agree = %q, want hf:a/b", got)
	}
	// A silent operator (empty) abstains, it does not break consensus.
	if got := aggregateIdentity([]string{"hf:a/b", "", "hf:a/b"}); got != "hf:a/b" {
		t.Errorf("silence should abstain, got %q", got)
	}
	// Disagreement → omit (never pick a side).
	if got := aggregateIdentity([]string{"hf:a/b", "hf:c/d"}); got != "" {
		t.Errorf("disagreement = %q, want empty", got)
	}
	// Nothing declared → empty.
	if got := aggregateIdentity(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}
	if got := aggregateIdentity([]string{"", ""}); got != "" {
		t.Errorf("all empty = %q, want empty", got)
	}
}

func TestAggregateSource(t *testing.T) {
	// Revisions and case are not part of source identity. Preserve the first
	// spelling so the aggregate still carries the operator's usable HF pointer.
	first := "hf:zai-org/GLM-5.2@revA"
	if got := aggregateSource([]string{first, "hf:ZAI-ORG/glm-5.2@revB"}); got != first {
		t.Errorf("normalized agreement = %q, want first spelling %q", got, first)
	}
	// Silence abstains just as it does for canonical consensus.
	if got := aggregateSource([]string{"", "hf:Qwen/Qwen2.5-7B"}); got != "hf:Qwen/Qwen2.5-7B" {
		t.Errorf("silence should abstain, got %q", got)
	}
	// Different repositories remain a real disagreement.
	if got := aggregateSource([]string{"hf:a/one@rev", "hf:a/two@rev"}); got != "" {
		t.Errorf("different repos = %q, want empty", got)
	}
}

func idOp(id uint64, model, source, canonical string) Operator {
	return Operator{
		ID: id, OwnerAddr: "O", BaseURL: "http://x", Reachable: true, ReachableAsOf: time.Now(),
		ProtoVersion:    wire.ProtoVersion,
		Models:          []string{model},
		ModelCapacities: map[string]ModelCapacity{model: {Source: source, CanonicalID: canonical}},
	}
}

// A closed-weights frontier model has no source, so operators serving it carry a
// canonicalId instead — the aggregate must surface it (a consumer groups on it,
// exactly like the client), while source stays empty.
func TestAllModelDetails_CanonicalStatic(t *testing.T) {
	reg, err := NewStaticRegistryProvider([]Operator{
		idOp(1, "grok-4.5", "", "xai/grok-4.5"),
		idOp(2, "grok-4.5", "", "xai/grok-4.5"),
	})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v, want 1 model", out)
	}
	if out[0].CanonicalID != "xai/grok-4.5" {
		t.Errorf("canonical_id = %q, want xai/grok-4.5", out[0].CanonicalID)
	}
	if out[0].Source != "" {
		t.Errorf("source = %q, want empty for a closed frontier model", out[0].Source)
	}
}

// A sourced model surfaces its consensus source; canonical_id stays empty (the
// canonical IS the source repo — mirror the node's per-model rule).
func TestAllModelDetails_SourceStatic(t *testing.T) {
	reg, err := NewStaticRegistryProvider([]Operator{
		idOp(1, "glm-5.2", "hf:zai-org/GLM-5.2", ""),
		idOp(2, "zai-org/GLM-5.2", "hf:zai-org/GLM-5.2", ""),
	})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	byID := map[string]string{}
	for _, m := range out {
		if m.CanonicalID != "" {
			t.Errorf("%s: canonical_id = %q, want empty (sourced model)", m.ID, m.CanonicalID)
		}
		byID[m.ID] = m.Source
	}
	// The aggregate keys per wire id, so each spelling stays its own entry — but
	// both carry the same declared repo, which is what a consumer groups on.
	if byID["glm-5.2"] != "hf:zai-org/GLM-5.2" || byID["zai-org/GLM-5.2"] != "hf:zai-org/GLM-5.2" {
		t.Errorf("sources = %+v, want both hf:zai-org/GLM-5.2", byID)
	}
}

// Source consensus is by normalized repo identity, not the literal pointer:
// operators may honestly pin different revisions or use different case.
func TestAllModelDetails_SourceRevisionCaseConsensus(t *testing.T) {
	first := "hf:zai-org/GLM-5.2@revA"
	reg, err := NewStaticRegistryProvider([]Operator{
		idOp(1, "glm-5.2", first, ""),
		idOp(2, "glm-5.2", "hf:ZAI-ORG/glm-5.2@revB", ""),
	})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v, want 1 model", out)
	}
	if out[0].Source != first {
		t.Errorf("source = %q, want first representative %q", out[0].Source, first)
	}
}

// Operators disagreeing on a model's source withdraw the identity claim — the
// aggregate omits it rather than pick a side (mirrors the weights-digest rule).
func TestAllModelDetails_IdentityDisagreementOmits(t *testing.T) {
	reg, err := NewStaticRegistryProvider([]Operator{
		idOp(1, "m1", "hf:a/one", ""),
		idOp(2, "m1", "hf:b/two", ""),
	})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v, want 1 model", out)
	}
	if out[0].Source != "" {
		t.Errorf("source = %q, want empty on disagreement", out[0].Source)
	}
}

// A consensus source clears any canonical_id, keeping the wire invariant
// "canonical_id present ⇒ source empty" on the aggregate.
func TestAllModelDetails_SourceClearsCanonical(t *testing.T) {
	reg, err := NewStaticRegistryProvider([]Operator{
		idOp(1, "m1", "hf:a/one", ""),
		idOp(2, "m1", "", "a/one"),
	})
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 {
		t.Fatalf("AllModelDetails = %+v, want 1 model", out)
	}
	if out[0].Source != "hf:a/one" {
		t.Errorf("source = %q, want hf:a/one", out[0].Source)
	}
	if out[0].CanonicalID != "" {
		t.Errorf("canonical_id = %q, want empty when a source is present", out[0].CanonicalID)
	}
}

// The dynamic registry must fold identity the same way as the static one.
func TestAllModelDetails_CanonicalDynamic(t *testing.T) {
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{
		idOp(1, "grok-4.5", "", "xai/grok-4.5"),
		idOp(2, "grok-4.5", "", "xai/grok-4.5"),
	}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 || out[0].CanonicalID != "xai/grok-4.5" || out[0].Source != "" {
		t.Fatalf("dynamic AllModelDetails = %+v, want canonical_id xai/grok-4.5, empty source", out)
	}
}

func TestAllModelDetails_SourceRevisionCaseConsensusDynamic(t *testing.T) {
	first := "hf:zai-org/GLM-5.2@revA"
	reg, err := NewDynamicRegistryProvider(&fakeSource{}, []Operator{
		idOp(1, "glm-5.2", first, ""),
		idOp(2, "glm-5.2", "hf:ZAI-ORG/glm-5.2@revB", ""),
	}, DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
	}, discardLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	out := reg.AllModelDetails(context.Background())
	if len(out) != 1 || out[0].Source != first || out[0].CanonicalID != "" {
		t.Fatalf("dynamic AllModelDetails = %+v, want source %q and empty canonical_id", out, first)
	}
}
