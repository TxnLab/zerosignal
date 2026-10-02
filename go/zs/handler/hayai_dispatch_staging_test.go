/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// stagingOp builds a model-serving operator with its on-chain NodeRecord.staging
// flag set or clear. Mirrors teeOp (hayai_dispatch_tee_test.go); reuses
// minimalTEEServer from that file since staging filtering, like TEE, happens in
// pickCandidates before any wallet / reserve wiring.
func stagingOp(id uint64, model string, staging bool) hayai.Operator {
	return hayai.Operator{
		ID:      id,
		BaseURL: "http://op.example",
		Models:  []string{model},
		ModelCapacities: map[string]hayai.ModelCapacity{
			model: {ContextWindow: 128_000, MaxOutputTokens: 16_384},
		},
		Staging:      staging,
		ProtoVersion: wire.ProtoVersion,
	}
}

func opIDSet(ops []hayai.Operator) map[uint64]bool {
	m := make(map[uint64]bool, len(ops))
	for _, op := range ops {
		m[op.ID] = true
	}
	return m
}

func TestPickCandidates_StagingFilter_DropsStagingByDefault(t *testing.T) {
	// AllowStaging defaults to false (empty config), so the staging node (op 2)
	// is dropped and the two production nodes survive — model is still served, so
	// StagingBlocked stays clear.
	srv := minimalTEEServer(t, []hayai.Operator{
		stagingOp(1, "gpt-4o-mini", false),
		stagingOp(2, "gpt-4o-mini", true),
		stagingOp(3, "gpt-4o-mini", false),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}

	if pick.StagingBlocked {
		t.Fatalf("StagingBlocked unexpectedly set; survivors: %d", len(pick.Operators))
	}
	ids := opIDSet(pick.Operators)
	if len(pick.Operators) != 2 || !ids[1] || !ids[3] || ids[2] {
		t.Fatalf("got ids %v, want {1,3} with staging op 2 dropped", ids)
	}
}

func TestPickCandidates_StagingFilter_AllStagingSetsStagingBlocked(t *testing.T) {
	// Every node serving the model is staging and the proxy didn't opt in →
	// StagingBlocked with an empty result (distinct from RegistryCount==0: the
	// model IS advertised, just only by held-out nodes).
	srv := minimalTEEServer(t, []hayai.Operator{
		stagingOp(1, "gpt-4o-mini", true),
		stagingOp(2, "gpt-4o-mini", true),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}

	if !pick.StagingBlocked {
		t.Fatalf("StagingBlocked should be set when every node is staging; got %d operators", len(pick.Operators))
	}
	if len(pick.Operators) != 0 {
		t.Errorf("Operators should be empty; got %d", len(pick.Operators))
	}
	// The model is still served (the count is unchanged by the staging filter),
	// so this is not the registry-miss path.
	if pick.RegistryCount == 0 {
		t.Errorf("RegistryCount = 0, want >0 (model is advertised, just only by staging nodes)")
	}
}

func TestPickCandidates_StagingFilter_AllowStagingKeepsStaging(t *testing.T) {
	// hayai.allow_staging on (config / --allow-staging) → staging nodes compete
	// alongside production ones; nothing is dropped and StagingBlocked stays clear.
	srv := minimalTEEServer(t, []hayai.Operator{
		stagingOp(1, "gpt-4o-mini", false),
		stagingOp(2, "gpt-4o-mini", true),
		stagingOp(3, "gpt-4o-mini", false),
	})
	srv.cfg.AllowStaging = true

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}

	if pick.StagingBlocked {
		t.Errorf("StagingBlocked set with AllowStaging=true")
	}
	if len(pick.Operators) != 3 {
		t.Errorf("got %d operators, want 3 (staging kept when allowed)", len(pick.Operators))
	}
}

func TestDispatchHayai_AllStaging_503_NoProductionOperator(t *testing.T) {
	// End-to-end: a model served only by staging nodes, default config (no
	// allow_staging) → 503 no_production_operator from dispatchHayai's
	// translation of pickResult.StagingBlocked.
	srv := minimalTEEServer(t, []hayai.Operator{
		stagingOp(1, "gpt-4o-mini", true),
		stagingOp(2, "gpt-4o-mini", true),
	})
	srv.tokenizer = testTokenizer()

	body := []byte(`{"model":"gpt-4o-mini","max_completion_tokens":100}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	w := httptest.NewRecorder()

	srv.dispatchHayai(w, req, endpointChatCompletions, body, formatChat)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s; want 503", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"no_production_operator"`) {
		t.Errorf("expected no_production_operator in body, got %s", w.Body.String())
	}
}
