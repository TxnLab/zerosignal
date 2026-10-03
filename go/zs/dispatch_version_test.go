/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

// versionOp builds an Operator with a single model and an arbitrary
// advertised ProtoVersion. Mirrors teeOp from the TEE test file but
// omits TEE wiring (the version filter is the focus here).
func versionOp(id uint64, model, protoVer string) Operator {
	return Operator{
		ID:      id,
		BaseURL: "http://op.example",
		Models:  []string{model},
		ModelCapacities: map[string]ModelCapacity{
			model: {ContextWindow: 128_000, MaxOutputTokens: 16_384},
		},
		ProtoVersion: protoVer,
	}
}

func minimalVersionServer(t *testing.T, ops []Operator) *Client {
	t.Helper()
	registry, err := NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Client{
		cfg:              Config{Privacy: PrivacyDirect, Affinity: Affinity{Policy: AffinityNone}},
		log:              log,
		registryProvider: registry,
	}
}

func TestPickCandidates_VersionFilter_KeepsCompatible(t *testing.T) {
	// Mixed fleet: one compatible (same major as wire.ProtoVersion),
	// one same-major-higher-minor (also compatible), one bumped to a
	// future major, and one legacy (missing field → LegacyProtoVersion
	// "1.0", incompatible with the current major).
	srv := minimalVersionServer(t, []Operator{
		versionOp(1, "gpt-4o-mini", wire.ProtoVersion),
		// A minor no build has reached, so this stays a HIGHER minor
		// however far wire.ProtoVersion moves inside major 9. It read
		// "9.5" until that became the current version, at which point
		// the assertion still passed (compatibility is major-only) and
		// the comment was simply wrong.
		versionOp(2, "gpt-4o-mini", "9.999"), // same major (9), higher minor → compatible
		versionOp(3, "gpt-4o-mini", "10.0"),  // future major → incompatible
		versionOp(4, "gpt-4o-mini", ""),      // missing → legacy 1.0 → incompatible with the current major
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini",
		[]byte(`{"model":"gpt-4o-mini"}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if pick.VersionBlocked {
		t.Fatalf("VersionBlocked unexpectedly set; got %d operators", len(pick.Operators))
	}
	got := make([]uint64, len(pick.Operators))
	for i, op := range pick.Operators {
		got[i] = op.ID
	}
	// Op 3 (future major 10) and Op 4 (legacy 1.0) must be filtered out. Ops 1 and 2 must survive.
	if len(got) != 2 || got[0] != 1 || got[1] != 2 {
		t.Fatalf("expected [1 2]; got %v", got)
	}
}

func TestPickCandidates_VersionFilter_AllIncompatibleSetsVersionBlocked(t *testing.T) {
	srv := minimalVersionServer(t, []Operator{
		versionOp(1, "gpt-4o-mini", "10.0"),
		versionOp(2, "gpt-4o-mini", "1.0"),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini",
		[]byte(`{"model":"gpt-4o-mini"}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if !pick.VersionBlocked {
		t.Fatalf("VersionBlocked should be set; got %d operators", len(pick.Operators))
	}
	if len(pick.Operators) != 0 {
		t.Errorf("Operators should be empty; got %d", len(pick.Operators))
	}
}

func TestPickCandidates_VersionFilter_RegistryMissTakesPrecedence(t *testing.T) {
	// Registry empty for the requested model: VersionBlocked must
	// NOT fire — the dispatch caller should see RegistryCount==0 and
	// surface no_operator instead.
	srv := minimalVersionServer(t, nil)

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini",
		[]byte(`{}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 1, MaxOutputTokens: 1}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if pick.VersionBlocked {
		t.Errorf("VersionBlocked should not fire on empty registry")
	}
	if pick.RegistryCount != 0 {
		t.Errorf("RegistryCount = %d, want 0", pick.RegistryCount)
	}
}

// One operator running two nodes: both must surface as independent dispatch
// candidates (all nodes eligible), and a response-id pin must resolve the EXACT
// node it recorded — not a sibling of the same operator.
func TestPickCandidates_MultiNode_AllEligible_And_ExactNodePin(t *testing.T) {
	const model = "gpt-test"
	mkNode := func(node uint64, baseURL string) Operator {
		op := versionOp(7, model, wire.ProtoVersion) // compatible major
		op.NodeID = node
		op.BaseURL = baseURL
		return op
	}
	n1 := mkNode(1, "https://op7-a.example")
	n2 := mkNode(2, "https://op7-b.example")
	srv := minimalVersionServer(t, []Operator{n1, n2})
	sizing := SizingRequest{Model: model, InputTokens: 1, MaxOutputTokens: 1}

	// (a) No affinity → both nodes are candidates, neither collapsed away.
	body := []byte(`{"model":"gpt-test","messages":[]}`)
	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, model,
		body, sizing, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	gotNodes := map[uint64]string{}
	for _, op := range pick.Operators {
		if op.ID != 7 {
			t.Errorf("unexpected operator id %d", op.ID)
		}
		gotNodes[op.NodeID] = op.BaseURL
	}
	if len(gotNodes) != 2 || gotNodes[1] != "https://op7-a.example" || gotNodes[2] != "https://op7-b.example" {
		t.Fatalf("both nodes should be candidates; got %+v", gotNodes)
	}

	// (b) Response-id pin recorded for node 2 → resolves node 2 exactly.
	srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.responseAffinity.Record(7, 2, []string{"rid"})
	pinBody := []byte(`{"model":"gpt-test","previous_response_id":"rid","input":[]}`)
	pick, err = srv.pickCandidates(context.Background(), endpointResponses, model,
		pinBody, sizing, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates (pin): %v", err)
	}
	if pick.AffinityBlocked || pick.VersionBlocked {
		t.Fatalf("pin should resolve cleanly; got %+v", pick)
	}
	if len(pick.Operators) != 1 || pick.Operators[0].NodeID != 2 ||
		pick.Operators[0].BaseURL != "https://op7-b.example" {
		t.Fatalf("pin must resolve the EXACT node 2; got %+v", pick.Operators)
	}
}

func TestPickCandidates_VersionFilter_ResponseIDPin_BlocksIncompatible(t *testing.T) {
	// The /v1/responses session-pin path resolves the operator by id,
	// bypassing the registry-walk version filter. Without an explicit
	// version check on that branch, a long-lived previous_response_id
	// pointing at an operator that has since moved to an incompatible
	// wire major would be re-served — and the resulting sealed request
	// would fail mid-flight at decode time rather than producing the
	// clean no_compatible_operator the rest of the pipeline emits.
	const model = "gpt-test"
	op := versionOp(7, model, "10.0")
	srv := minimalVersionServer(t, []Operator{op})
	srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.responseAffinity.Record(op.ID, op.NodeID, []string{"resp_pinned"})

	body := []byte(`{"model":"gpt-test","previous_response_id":"resp_pinned","input":[]}`)
	pick, err := srv.pickCandidates(context.Background(), endpointResponses, model,
		body, SizingRequest{Model: model, InputTokens: 1, MaxOutputTokens: 1}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if !pick.VersionBlocked {
		t.Fatalf("VersionBlocked should fire on pinned incompatible operator; got %+v", pick)
	}
	if len(pick.Operators) != 0 {
		t.Errorf("Operators should be empty when VersionBlocked; got %d", len(pick.Operators))
	}
	if pick.AffinityBlocked {
		t.Errorf("AffinityBlocked should not fire — the pin resolved fine, version is the actual cause")
	}
}

func TestDispatch_VersionBlocked_NoCompatibleOperator(t *testing.T) {
	// End-to-end: every operator advertises an incompatible major, and the
	// turn must translate VersionBlocked → no_compatible_operator.
	srv := minimalVersionServer(t, []Operator{
		versionOp(1, "gpt-4o-mini", "10.0"),
	})
	srv.tokenizer = testTokenizer()

	ze := turnErr(t, srv, `{"model":"gpt-4o-mini","max_completion_tokens":100}`)
	if ze.Code != "no_compatible_operator" || ze.Kind != KindNoRoute {
		t.Fatalf("error = %s/%s, want no_route/no_compatible_operator", ze.Kind, ze.Code)
	}
}
