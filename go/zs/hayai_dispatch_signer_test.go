/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
)

// signerOp is a serving node with its signing account's spendable ALGO set, or
// never read when spendable is nil.
func signerOp(id uint64, model string, spendable *uint64) Operator {
	op := stagingNodeOp(id, model, false)
	op.SignerSpendableMicroAlgos = spendable
	return op
}

func micro(v uint64) *uint64 { return &v }

func pickChat(t *testing.T, srv *Client, model string, body []byte) pickResult {
	t.Helper()
	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, model, body,
		SizingRequest{Model: model, InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	return pick
}

func TestPickCandidates_SignerFilter_DropsBelowFloorOnly(t *testing.T) {
	const model = "gpt-4o-mini"
	srv := minimalTEEServer(t, []Operator{
		signerOp(1, model, micro(selection.MinSignerSpendableMicroAlgos)),
		signerOp(2, model, micro(selection.MinSignerSpendableMicroAlgos-1)),
		signerOp(3, model, nil),
	})

	pick := pickChat(t, srv, model, []byte(`{"model":"gpt-4o-mini"}`))
	if pick.SignerUnderfundedBlocked {
		t.Fatal("SignerUnderfundedBlocked set with funded candidates left")
	}
	ids := opIDSet(pick.Operators)
	if len(pick.Operators) != 2 || !ids[1] || !ids[3] || ids[2] {
		t.Fatalf("got ids %v, want {1,3}: at-floor and never-read route, one-short does not", ids)
	}
}

func TestPickCandidates_SignerFilter_AllBelowFloorSetsBlocked(t *testing.T) {
	const model = "gpt-4o-mini"
	srv := minimalTEEServer(t, []Operator{
		signerOp(1, model, micro(0)),
		signerOp(2, model, micro(1_000_000)),
	})

	pick := pickChat(t, srv, model, []byte(`{"model":"gpt-4o-mini"}`))
	if !pick.SignerUnderfundedBlocked || len(pick.Operators) != 0 {
		t.Fatalf("got %+v, want empty + SignerUnderfundedBlocked", pick)
	}
	if pick.RegistryCount != 2 {
		t.Errorf("RegistryCount = %d, want 2 (the model IS served)", pick.RegistryCount)
	}
	if pick.SignerUnderfundedReason != "" {
		t.Errorf("reason = %q, want empty so the model-wide message is used", pick.SignerUnderfundedReason)
	}
}

func TestDispatchHayai_AllUnderfunded_NoFundedOperator(t *testing.T) {
	srv := minimalTEEServer(t, []Operator{
		signerOp(1, "gpt-4o-mini", micro(0)),
	})
	srv.tokenizer = testTokenizer()

	ze := turnErr(t, srv, `{"model":"gpt-4o-mini","max_completion_tokens":100}`)
	if ze.Code != "no_funded_operator" {
		t.Errorf("error = %s/%s, want no_funded_operator", ze.Kind, ze.Code)
	}
}

// The previous_response_id pin resolves one operator straight from the
// registry, bypassing SelectTargets — so it needs its own check, or a drained
// node keeps receiving a conversation's every turn.
func TestPickCandidates_ResponseIDPin_BlocksUnderfunded(t *testing.T) {
	const model = "gpt-4o-mini"
	op := signerOp(7, model, micro(0))
	srv := minimalTEEServer(t, []Operator{op, signerOp(8, model, nil)})
	srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.responseAffinity.Record(op.ID, op.NodeID, []string{"resp_pinned"})

	body := []byte(`{"model":"gpt-4o-mini","previous_response_id":"resp_pinned","input":[]}`)
	pick, err := srv.pickCandidates(context.Background(), endpointResponses, model, body,
		SizingRequest{Model: model, InputTokens: 1, MaxOutputTokens: 1}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if !pick.SignerUnderfundedBlocked || len(pick.Operators) != 0 {
		t.Fatalf("got %+v, want empty + SignerUnderfundedBlocked (never relocate the session to node 8)", pick)
	}
	if pick.AffinityBlocked {
		t.Error("AffinityBlocked set — that reports a sizing conflict, not a drained signer")
	}
	// Node 8 serves the model and is funded, so the model-wide message would be
	// false and would steer the payer off a session that survives a top-up.
	if r := pick.SignerUnderfundedReason; !strings.Contains(r, "resp_pinned") || !strings.Contains(r, "operator 7 node") || strings.Contains(r, "every node") {
		t.Errorf("reason = %q, want the pinned node named, not a model-wide claim", r)
	}
}

// A caller preference that excludes the pinned node is a permanent conflict
// and outranks the drained signer, which a top-up would clear.
func TestPickCandidates_ResponseIDPin_ConflictOutranksUnderfunded(t *testing.T) {
	const model = "gpt-4o-mini"
	op := signerOp(7, model, micro(0))
	srv := minimalTEEServer(t, []Operator{op, signerOp(8, model, nil)})
	srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.responseAffinity.Record(op.ID, op.NodeID, []string{"resp_pinned"})

	body := []byte(`{"model":"gpt-4o-mini","previous_response_id":"resp_pinned","input":[]}`)
	pick, err := srv.pickCandidates(context.Background(), endpointResponses, model, body,
		SizingRequest{Model: model, InputTokens: 1, MaxOutputTokens: 1}, false, selection.ImageToolBudgets{},
		selection.RoutingPreferences{Only: []selection.OperatorRef{allRef(8)}})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if !pick.PinConflict || pick.SignerUnderfundedBlocked {
		t.Fatalf("got PinConflict=%v SignerUnderfundedBlocked=%v, want the conflict alone", pick.PinConflict, pick.SignerUnderfundedBlocked)
	}
}

// Under strict affinity the tool-call pin can't yield, so the 503 must name
// the pinned node and the prefer escape hatch rather than the whole model.
func TestPickCandidates_ToolAffinityStrict_UnderfundedNamesThePin(t *testing.T) {
	const model = "gpt-4o-mini"
	pinned := signerOp(7, model, micro(0))
	srv := minimalTEEServer(t, []Operator{pinned, signerOp(8, model, nil)})
	srv.cfg.Affinity.Policy = AffinityStrict
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)
	pick := pickChat(t, srv, model, body)
	if !pick.SignerUnderfundedBlocked || len(pick.Operators) != 0 {
		t.Fatalf("got %+v, want empty + SignerUnderfundedBlocked", pick)
	}
	if r := pick.SignerUnderfundedReason; !strings.Contains(r, "operator 7 node") || !strings.Contains(r, "affinity_policy") {
		t.Errorf("reason = %q, want the pinned node and the prefer hint", r)
	}
}

// Under the proxy's default prefer policy a tool loop pinned to a node that has
// since drained must yield to a funded peer rather than float it back.
func TestPickCandidates_ToolAffinityPrefer_UnderfundedNotFloated(t *testing.T) {
	const model = "gpt-4o-mini"
	pinned := signerOp(7, model, micro(0))
	peer := signerOp(8, model, nil)
	srv := minimalTEEServer(t, []Operator{pinned, peer})
	srv.cfg.Affinity.Policy = AffinityPrefer
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})

	body := []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`)
	pick := pickChat(t, srv, model, body)
	if len(pick.Operators) != 1 || pick.Operators[0].ID != 8 {
		t.Fatalf("got %v, want only the funded peer 8", opIDSet(pick.Operators))
	}

	// The other arm, so the assertion above can't pass because the pin never
	// resolved: with the pinned node funded, it leads.
	srv2 := minimalTEEServer(t, []Operator{signerOp(7, model, nil), peer})
	srv2.cfg.Affinity.Policy = AffinityPrefer
	srv2.toolAffinity = srv.toolAffinity
	if got := pickChat(t, srv2, model, body); len(got.Operators) != 2 || got.Operators[0].ID != 7 {
		t.Fatalf("funded pin: got order %v, want 7 first", got.Operators)
	}
}
