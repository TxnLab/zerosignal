/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
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

func TestDispatch_AllUnderfunded_NoFundedOperator(t *testing.T) {
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
	if r := pick.SignerUnderfundedReason; !strings.Contains(r, "operator 7 node") || !strings.Contains(r, "affinity policy to prefer") {
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

// A payer short of its rail's coin for the ticket pool is told which coin and
// which pool: a Solana payer funds SOL for ticket rent, with no USDC opt-in to
// make. The default remedies follow the rail too. The texts are the TS twin's.
func TestOpenFailure_NamesTheRailsCoinAndPool(t *testing.T) {
	for _, c := range []struct {
		rail          ticket.Rail
		err           error
		want          string
		recoverTicket string
	}{
		{ticket.RailAlgorand, fmt.Errorf("short: %w", ErrDepositUnaffordable),
			"zerosignal wallet PAYER needs more ALGO (not USDC) to fund the prepaid ticket-MBR pool on  — short: " + ErrDepositUnaffordable.Error() + ". " +
				"To fix it, fund the payer address: ALGO for fees and the ticket pool, and USDC for requests once the address has opted in to the USDC asset.",
			"read its box with escrow.Client.ReadTicketBox and, once the deadline passes, call refundInactive on an open ticket or settleLapsed on an operator's claim"},
		{ticket.RailSolana, fmt.Errorf("short: %w", ErrRentDepositUnaffordable),
			"zerosignal wallet PAYER needs more SOL (not USDC) to fund the prepaid ticket rent pool on  — short: " + ErrRentDepositUnaffordable.Error() + ". " +
				"To fix it, fund the payer address: SOL for fees and the ticket rent pool, and USDC for requests.",
			"read its ticket account from the escrow program and, once the deadline passes, send refund_inactive on an open ticket or settle_lapsed on an operator's claim"},
		{ticket.RailSolana, fmt.Errorf("short: %w", ErrRentDepositBelowTarget),
			"zerosignal wallet PAYER needs more SOL (not USDC) to fund the prepaid ticket rent pool on  — short: " + ErrRentDepositBelowTarget.Error() + ". " +
				"To fix it, fund the payer address: SOL for fees and the ticket rent pool, and USDC for requests.",
			""},
	} {
		s := &Client{wallet: failingOpenWallet{}, deployment: Deployment{Rail: c.rail}}
		ze := s.openFailure(c.err)
		if ze.Code != "mbr_pool_underfunded" || ze.Message != c.want {
			t.Errorf("%s:\n got %s %q\nwant mbr_pool_underfunded %q", RailName(c.rail), ze.Code, ze.Message, c.want)
		}
		if c.recoverTicket != "" {
			if got := (Config{Network: Network{Rail: c.rail}}).withDefaults().Remedies.RecoverTicket; got != c.recoverTicket {
				t.Errorf("%s RecoverTicket:\n got %q\nwant %q", RailName(c.rail), got, c.recoverTicket)
			}
		}
	}
	// A Solana payer built its own wallet from SolanaWalletConfig.
	for rail, want := range map[ticket.Rail]string{
		ticket.RailAlgorand: "raise Config.ConcurrentSlots (WalletConfig.DepositSlots for a Wallet you built) and rebuild the Client; the next request funds the larger pool",
		ticket.RailSolana:   "raise Config.ConcurrentSlots (SolanaWalletConfig.DepositSlots for a SolanaWallet you built) and rebuild the Client; the next request funds the larger pool",
	} {
		if got := (Config{Network: Network{Rail: rail}}).withDefaults().Remedies.RaiseSlots; got != want {
			t.Errorf("%s RaiseSlots:\n got %q\nwant %q", RailName(rail), got, want)
		}
	}
}

// Each no_funded_operator refusal names the floor in the Client's own rail's
// unit: a Solana node's signer pays its fees in lamports, and "5 ALGO" would
// send its operator to fund the wrong chain. The texts are the TS twin's too.
func TestNoFundedOperator_NamesTheRailsFloor(t *testing.T) {
	const model = "gpt-4o-mini"
	for _, c := range []struct {
		rail  ticket.Rail
		floor string
		drain func(*Operator)
	}{
		{ticket.RailAlgorand, "5 ALGO", func(op *Operator) { op.SignerSpendableMicroAlgos = micro(0) }},
		{ticket.RailSolana, "10120 lamports", func(op *Operator) { op.SignerSpendableLamports = micro(0) }},
	} {
		t.Run(RailName(c.rail), func(t *testing.T) {
			drained := func(id uint64) Operator {
				op := signerOp(id, model, nil)
				c.drain(&op)
				return op
			}

			srv := minimalTEEServer(t, []Operator{drained(1)})
			srv.tokenizer = testTokenizer()
			srv.deployment.Rail = c.rail
			ze := turnErr(t, srv, `{"model":"gpt-4o-mini","max_completion_tokens":100}`)
			if want := `every node serving the model "gpt-4o-mini" has less than ` + c.floor +
				` spendable in its signing account to pay network fees; retry later or pick another model`; ze.Message != want {
				t.Errorf("model-wide:\n got %q\nwant %q", ze.Message, want)
			}

			pinned := drained(7)
			srv = minimalTEEServer(t, []Operator{pinned, signerOp(8, model, nil)})
			srv.deployment.Rail = c.rail
			srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
			srv.responseAffinity.Record(pinned.ID, pinned.NodeID, []string{"resp_pinned"})
			pick, err := srv.pickCandidates(context.Background(), endpointResponses, model,
				[]byte(`{"model":"gpt-4o-mini","previous_response_id":"resp_pinned","input":[]}`),
				SizingRequest{Model: model, InputTokens: 1, MaxOutputTokens: 1}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
			if err != nil {
				t.Fatal(err)
			}
			if want := `previous_response_id "resp_pinned" is pinned to operator 7 node 0, whose signing account has less than ` + c.floor +
				` spendable to pay network fees; retry once the operator tops up, or start a new conversation`; pick.SignerUnderfundedReason != want {
				t.Errorf("response pin:\n got %q\nwant %q", pick.SignerUnderfundedReason, want)
			}

			srv = minimalTEEServer(t, []Operator{pinned, signerOp(8, model, nil)})
			srv.deployment.Rail = c.rail
			srv.cfg.Affinity.Policy = AffinityStrict
			srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
			srv.toolAffinity.Record(pinned.ID, pinned.NodeID, []string{"call_1"})
			pick = pickChat(t, srv, model, []byte(`{"model":"gpt-4o-mini","messages":[{"role":"tool","tool_call_id":"call_1","content":"x"}]}`))
			if want := `this tool-call continuation is pinned (strict affinity) to operator 7 node 0, whose signing account has less than ` + c.floor +
				` spendable to pay network fees; retry later, or set the affinity policy to prefer so another node can continue it`; pick.SignerUnderfundedReason != want {
				t.Errorf("tool pin:\n got %q\nwant %q", pick.SignerUnderfundedReason, want)
			}
		})
	}
}
