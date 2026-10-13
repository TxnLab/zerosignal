/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs/tee"
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
	Mode:                  "dstack-tdx",
	VerifierID:            tee.VerifierIDDstack,
	Verified:              true,
	OSImageChecked:        true,
	ComposeReleaseChecked: true,
}

// unreleasedTEE passed on a trusted image whose compose matched no published
// release: verified, and still not attested. A pick that read the pass alone
// would keep it.
var unreleasedTEE = &TEEStatus{
	Mode:           "dstack-tdx",
	VerifierID:     tee.VerifierIDDstack,
	Verified:       true,
	OSImageChecked: true,
}

var failedTEE = &TEEStatus{
	Mode:       "stub",
	VerifierID: tee.VerifierIDBuiltin,
	Verified:   false,
	FailureTag: tee.FailureStubNotAllowed,
}

// A strict tool-call pin whose node lost its attestation blocks, and the 503
// names the pin and the prefer escape rather than claiming the pool has no
// attested node: here op 1 is attested and serves the model.
func TestPickCandidates_ToolAffinityStrict_UnattestedNamesThePin(t *testing.T) {
	const model = "gpt-4o-mini"
	pinned := teeOp(7, model, nil)
	pick := func(policy AffinityPolicy) pickResult {
		srv := minimalTEEServer(t, []Operator{teeOp(1, model, attestedTEE), pinned})
		srv.cfg.Affinity.Policy = policy
		srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
		srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})
		res, err := srv.pickCandidates(context.Background(), endpointChatCompletions, model,
			[]byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`),
			SizingRequest{Model: model, InputTokens: 100, MaxOutputTokens: 100}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
		if err != nil {
			t.Fatalf("pickCandidates: %v", err)
		}
		return res
	}

	res := pick(AffinityStrict)
	if !res.TEEBlocked || len(res.Operators) != 0 {
		t.Fatalf("strict: got %+v, want empty + TEEBlocked", res)
	}
	if r := res.TEEBlockedReason; !strings.Contains(r, "operator 7 node") || !strings.Contains(r, "affinity policy to prefer") {
		t.Errorf("reason = %q, want the pinned node and the prefer hint", r)
	}

	res = pick(AffinityPrefer)
	if res.TEEBlocked || res.TEEBlockedReason != "" || len(res.Operators) != 1 || res.Operators[0].ID != 1 {
		t.Fatalf("prefer: got %+v, want only the attested op 1 and no reason", res)
	}
}

// The pin-specific reason is only for a strict pin that lost its attestation.
// When the pool itself has no attested node the pool's message stands: under
// prefer, and under strict when the pin is attested but was dropped earlier.
func TestPickCandidates_TEEBlockedReasonOnlyBlamesAStrictUnattestedPin(t *testing.T) {
	const model = "gpt-4o-mini"
	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)
	cases := []struct {
		name   string
		policy AffinityPolicy
		pinned Operator
	}{
		{"prefer, unattested pin", AffinityPrefer, teeOp(7, model, nil)},
		{"strict, attested pin on another wire generation", AffinityStrict, func() Operator {
			o := teeOp(7, model, attestedTEE)
			o.ProtoVersion = "1.0"
			return o
		}()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := minimalTEEServer(t, []Operator{teeOp(1, model, nil), tc.pinned})
			srv.cfg.Affinity.Policy = tc.policy
			srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
			srv.toolAffinity.Record(tc.pinned.ID, tc.pinned.NodeID, []string{"call_1"})
			res, err := srv.pickCandidates(context.Background(), endpointChatCompletions, model, body,
				SizingRequest{Model: model, InputTokens: 100, MaxOutputTokens: 100}, true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
			if err != nil {
				t.Fatalf("pickCandidates: %v", err)
			}
			if !res.TEEBlocked || res.TEEBlockedReason != "" {
				t.Fatalf("got TEEBlocked=%v reason=%q, want the pool's block with no pin reason", res.TEEBlocked, res.TEEBlockedReason)
			}
		})
	}
}

// End to end: the strict pin's reason is the error the caller sees.
func TestDispatch_StrictUnattestedPinNamesThePin(t *testing.T) {
	const model = "gpt-4o-mini"
	pinned := teeOp(7, model, nil)
	srv := minimalTEEServer(t, []Operator{teeOp(1, model, attestedTEE), pinned})
	srv.tokenizer = testTokenizer()
	srv.cfg.Affinity.Policy = AffinityStrict
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})

	ze := requestErr(t, srv, Request{
		Endpoint:   EndpointChatCompletions,
		Body:       []byte(`{"model":"gpt-4o-mini","max_completion_tokens":100,"messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`),
		RequireTEE: true,
	})
	if ze.Code != "no_tee_capacity" || !strings.Contains(ze.Message, "pinned (strict affinity) to operator 7") {
		t.Fatalf("error = %s: %q, want no_tee_capacity naming the pin", ze.Code, ze.Message)
	}
}

func TestPickCandidates_TEEFilter_KeepsOnlyAttested(t *testing.T) {
	srv := minimalTEEServer(t, []Operator{
		teeOp(1, "gpt-4o-mini", attestedTEE),
		teeOp(2, "gpt-4o-mini", nil),       // doesn't advertise
		teeOp(3, "gpt-4o-mini", failedTEE), // advertised but failed
		teeOp(4, "gpt-4o-mini", unreleasedTEE),
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
		teeOp(3, "gpt-4o-mini", unreleasedTEE),
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

// The previous_response_id pin resolves its operator by id, past the shared
// filter, so it applies the TEE rule itself. A node that passed on no
// published release must still override the pin, and an attested one keeps it.
func TestPickCandidates_TEEFilter_ResponseIDPin(t *testing.T) {
	const model = "gpt-4o-mini"
	body := []byte(`{"model":"gpt-4o-mini","previous_response_id":"rid","input":[]}`)
	sizing := SizingRequest{Model: model, InputTokens: 100, MaxOutputTokens: 100}
	for _, tc := range []struct {
		name        string
		status      *TEEStatus
		wantBlocked bool
	}{
		{"attested keeps the pin", attestedTEE, false},
		{"verified on no published release overrides it", unreleasedTEE, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := minimalTEEServer(t, []Operator{teeOp(1, model, tc.status)})
			srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
			srv.responseAffinity.Record(1, 0, []string{"rid"})
			pick, err := srv.pickCandidates(context.Background(), endpointResponses, model, body, sizing,
				true, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
			if err != nil {
				t.Fatalf("pickCandidates: %v", err)
			}
			if pick.AffinityBlocked {
				t.Fatalf("the pin did not resolve: %s", pick.AffinityBlockReason)
			}
			if pick.TEEBlocked != tc.wantBlocked {
				t.Fatalf("TEEBlocked = %v, want %v", pick.TEEBlocked, tc.wantBlocked)
			}
		})
	}
}

func TestDispatch_RequireTEE_TriggersFilter(t *testing.T) {
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

func TestDispatch_RequireForModels_TriggersFilter(t *testing.T) {
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
