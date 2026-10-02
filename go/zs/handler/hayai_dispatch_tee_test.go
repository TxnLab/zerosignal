/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// minimalTEEServer builds a Server with just enough wiring to drive
// pickCandidates and dispatchHayai through their TEE-filter branches.
// Skips the wallet / keystore / reserve-client wiring that the full
// admission flow needs — TEE filtering happens before any of that.
func minimalTEEServer(t *testing.T, ops []hayai.Operator) *Server {
	t.Helper()
	registry, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Server{
		cfg:              &Config{Privacy: hayai.PrivacyDirect, Affinity: hayai.AffinityNone},
		log:              log,
		mux:              http.NewServeMux(),
		registryProvider: registry,
	}
}

func teeOp(id uint64, model string, tee *hayai.TEEStatus) hayai.Operator {
	return hayai.Operator{
		ID:      id,
		BaseURL: "http://op.example",
		Models:  []string{model},
		ModelCapacities: map[string]hayai.ModelCapacity{
			model: {ContextWindow: 128_000, MaxOutputTokens: 16_384},
		},
		TEE:          tee,
		ProtoVersion: wire.ProtoVersion,
	}
}

var attestedTEE = &hayai.TEEStatus{
	Mode:       "stub",
	VerifierID: hayai.VerifierIDBuiltin,
	Verified:   true,
}

var failedTEE = &hayai.TEEStatus{
	Mode:       "stub",
	VerifierID: hayai.VerifierIDBuiltin,
	Verified:   false,
	FailureTag: hayai.FailureStubNotAllowed,
}

func TestPickCandidates_TEEFilter_KeepsOnlyAttested(t *testing.T) {
	srv := minimalTEEServer(t, []hayai.Operator{
		teeOp(1, "gpt-4o-mini", attestedTEE),
		teeOp(2, "gpt-4o-mini", nil),       // doesn't advertise
		teeOp(3, "gpt-4o-mini", failedTEE), // advertised but failed
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
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
	srv := minimalTEEServer(t, []hayai.Operator{
		teeOp(1, "gpt-4o-mini", nil),
		teeOp(2, "gpt-4o-mini", failedTEE),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
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
	srv := minimalTEEServer(t, []hayai.Operator{
		teeOp(1, "gpt-4o-mini", attestedTEE),
		teeOp(2, "gpt-4o-mini", nil),
		teeOp(3, "gpt-4o-mini", failedTEE),
	})

	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, "gpt-4o-mini", []byte(`{"model":"gpt-4o-mini"}`),
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
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
		hayai.SizingRequest{Model: "gpt-4o-mini", InputTokens: 1, MaxOutputTokens: 1}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
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

func TestDispatchHayai_TEEHeader_TriggersFilter_503(t *testing.T) {
	// End-to-end: configure a Server with two non-TEE operators,
	// fire a request with X-Zs-Require-TEE, expect 503
	// no_tee_capacity from dispatchHayai's translation of
	// pickResult.TEEBlocked.
	srv := minimalTEEServer(t, []hayai.Operator{
		teeOp(1, "gpt-4o-mini", nil),
		teeOp(2, "gpt-4o-mini", failedTEE),
	})

	// dispatchHayai needs the tokenizer to estimate input tokens —
	// without it, the tokenize path would fail before we reach the
	// pickCandidates call. Reuse the model-agnostic SafeEstimator.
	srv.tokenizer = testTokenizer()

	body := []byte(`{"model":"gpt-4o-mini","max_completion_tokens":100}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	req.Header.Set("X-Zs-Require-TEE", "nvidia-cc")
	w := httptest.NewRecorder()

	srv.dispatchHayai(w, req, endpointChatCompletions, body, formatChat)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s; want 503", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"no_tee_capacity"`) {
		t.Errorf("expected no_tee_capacity in body, got %s", w.Body.String())
	}
}

func TestDispatchHayai_RequireForModels_TriggersFilter_503(t *testing.T) {
	// Same shape as above, but the requirement comes from
	// Config.TEERequiredModels rather than the request header. Should
	// produce the same 503 no_tee_capacity.
	srv := minimalTEEServer(t, []hayai.Operator{
		teeOp(1, "gpt-4o-mini", nil),
	})
	srv.cfg.TEERequiredModels = []string{"gpt-4o-mini"}
	srv.tokenizer = testTokenizer()

	body := []byte(`{"model":"gpt-4o-mini","max_completion_tokens":100}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(body)))
	w := httptest.NewRecorder()

	srv.dispatchHayai(w, req, endpointChatCompletions, body, formatChat)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s; want 503", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"no_tee_capacity"`) {
		t.Errorf("expected no_tee_capacity, got %s", w.Body.String())
	}
}
