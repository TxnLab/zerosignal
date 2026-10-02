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

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

// minimalTEEServer builds a Client with just enough wiring to drive
// pickCandidates and a turn through their TEE-filter branches.
// Skips the wallet / keystore / reserve-client wiring that the full
// admission flow needs — TEE filtering happens before any of that.
func minimalTEEServer(t *testing.T, ops []Operator) *Client {
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

func teeOp(id uint64, model string, tee *TEEStatus) Operator {
	return Operator{
		ID:      id,
		BaseURL: "http://op.example",
		Models:  []string{model},
		ModelCapacities: map[string]ModelCapacity{
			model: {ContextWindow: 128_000, MaxOutputTokens: 16_384},
		},
		TEE:          tee,
		ProtoVersion: wire.ProtoVersion,
	}
}

var attestedTEE = &TEEStatus{
	Mode:       "stub",
	VerifierID: VerifierIDBuiltin,
	Verified:   true,
}

var failedTEE = &TEEStatus{
	Mode:       "stub",
	VerifierID: VerifierIDBuiltin,
	Verified:   false,
	FailureTag: FailureStubNotAllowed,
}

func TestPickCandidates_TEEFilter_KeepsOnlyAttested(t *testing.T) {
	srv := minimalTEEServer(t, []Operator{
		teeOp(1, "gpt-4o-mini", attestedTEE),
		teeOp(2, "gpt-4o-mini", nil),       // doesn't advertise
		teeOp(3, "gpt-4o-mini", failedTEE), // advertised but failed
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}

	if pick.TEEBlocked {
		t.Fatalf("TEEBlocked unexpectedly set; surviving operators: %d", len(pick.Operators))
	}
	if len(pick.Operators) != 1 || pick.Operators[0].ID != 1 {
		ids := make([]uint64, len(pick.Operators))
		for i, op := range pick.Operators {
			ids[i] = op.ID
		}
		t.Fatalf("expected only op 1; got %v", ids)
	}
}

func TestPickCandidates_TEEFilter_AllNonAttestedSetsTEEBlocked(t *testing.T) {
	srv := minimalTEEServer(t, []Operator{
		teeOp(1, "gpt-4o-mini", nil),
		teeOp(2, "gpt-4o-mini", failedTEE),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}

	if !pick.TEEBlocked {
		t.Fatalf("TEEBlocked should be set when no attested operator survives; got %d operators", len(pick.Operators))
	}
	if len(pick.Operators) != 0 {
		t.Errorf("Operators should be empty; got %d", len(pick.Operators))
	}
}

func TestPickCandidates_TEEFilter_NoOpWhenRequireFalse(t *testing.T) {
	// Same registry as the strict test, but requireTEE=false → all
	// three operators survive.
	srv := minimalTEEServer(t, []Operator{
		teeOp(1, "gpt-4o-mini", attestedTEE),
		teeOp(2, "gpt-4o-mini", nil),
		teeOp(3, "gpt-4o-mini", failedTEE),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}

	if pick.TEEBlocked {
		t.Errorf("TEEBlocked set with requireTEE=false")
	}
	if len(pick.Operators) != 3 {
		t.Errorf("got %d operators, want 3", len(pick.Operators))
	}
}

func TestPickCandidates_TEEFilter_RegistryMissTakesPrecedence(t *testing.T) {
	// No operators serve the requested model at all — RegistryCount
	// = 0, no TEE filter even runs. The dispatch caller should see
	// the existing no_operator path, not no_tee_capacity.
	srv := minimalTEEServer(t, nil)

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{}`),
		SizingRequest{Model: "gpt-4o-mini", InputTokens: 1, MaxOutputTokens: 1}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if pick.TEEBlocked {
		t.Errorf("TEEBlocked should not fire when registry is empty for the model")
	}
	if pick.RegistryCount != 0 {
		t.Errorf("RegistryCount = %d, want 0", pick.RegistryCount)
	}
}

func TestDispatchHayai_RequireTEE_TriggersFilter(t *testing.T) {
	// End-to-end: two non-TEE operators and a request that requires TEE →
	// no_tee_capacity from the turn's translation of pickResult.TEEBlocked.
	srv := minimalTEEServer(t, []Operator{
		teeOp(1, "gpt-4o-mini", nil),
		teeOp(2, "gpt-4o-mini", failedTEE),
	})

	// The turn needs the tokenizer to estimate input tokens — without it, the
	// tokenize path would fail before we reach the pickCandidates call.
	srv.tokenizer = testTokenizer()

	ze := requestErr(t, srv, Request{
		Endpoint:   EndpointChatCompletions,
		Body:       []byte(`{"model":"gpt-4o-mini","max_completion_tokens":100}`),
		RequireTEE: true,
	})
	if ze.Code != "no_tee_capacity" || ze.Kind != KindNoRoute {
		t.Fatalf("error = %s/%s, want no_route/no_tee_capacity", ze.Kind, ze.Code)
	}
}

func TestDispatchHayai_RequireForModels_TriggersFilter(t *testing.T) {
	// Same shape as above, but the requirement comes from
	// Config.RequireTEEModels rather than the request. Should produce the
	// same no_tee_capacity.
	srv := minimalTEEServer(t, []Operator{
		teeOp(1, "gpt-4o-mini", nil),
	})
	srv.cfg.RequireTEEModels = []string{"gpt-4o-mini"}
	srv.tokenizer = testTokenizer()

	ze := turnErr(t, srv, `{"model":"gpt-4o-mini","max_completion_tokens":100}`)
	if ze.Code != "no_tee_capacity" || ze.Kind != KindNoRoute {
		t.Fatalf("error = %s/%s, want no_route/no_tee_capacity", ze.Kind, ze.Code)
	}
}
