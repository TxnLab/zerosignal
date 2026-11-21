/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// fakeSettlementHandle implements settlementHandle so runReceiptChecks can be
// driven with a controlled groupRejected result — the real *OpenHandle
// can't (a detached one always returns false, a wired one needs live algod).
type fakeSettlementHandle struct {
	groupRejected bool
	ackCalls      int
	protestCalls  int
}

func (f *fakeSettlementHandle) AckSettle(_ context.Context, _ *ticket.UsageReceipt, _ string) (AckResult, error) {
	f.ackCalls++
	// err=nil, so the dispatcher takes the success branch — the exact path where
	// the Resolve-gate must NOT un-track a rejected-then-standalone settle.
	return AckResult{TxID: "STANDALONE_ACK_TXID", FeeMicroalgos: 5000, GroupRejected: f.groupRejected}, nil
}

func (f *fakeSettlementHandle) Protest(_ context.Context, _ *ticket.UsageReceipt, _ []byte, _ escrow.ProtestReasonCode) (string, uint64, error) {
	f.protestCalls++
	return "", 0, nil
}

// TestRunReceiptChecks_ExcludesNodeOnGroupRejection covers the trigger half of
// the downrank feature end-to-end: a receipt that verifies, an atomic settle
// group present, and AckSettle reporting groupRejected=true → the dispatcher
// hard-excludes the served (operatorId,nodeId). Nothing else exercises this
// seam (every other settlement test uses a detached OpenHandle → groupRejected
// is always false), so without this a revert of the ExcludeNode call — or a
// regression in the Resolve-gate on the same path — would stay green.
func TestRunReceiptChecks_ExcludesNodeOnGroupRejection(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var signAddr types.Address
	copy(signAddr[:], pub)

	op := Operator{ID: 7, NodeID: 3, SigningAddr: signAddr.String(), TicketSigningKey: pub}
	tkt := &ticket.Ticket{
		TicketID:   "dGlja2V0LXhvcnZvenowMA==",
		OperatorID: op.ID,
		NodeID:     op.NodeID,
		MaxPrice:   100_000,
		Deployment: harnessDeployment,
	}

	plaintext := []byte("hello world")
	computed := wire.BodyHashOfBody(plaintext)
	receipt := &ticket.UsageReceipt{
		TicketID:          tkt.TicketID,
		ActualInputCount:  10,
		ActualOutputCount: 5,
		AmountCharged:     50_000, // <= MaxPrice
		Deployment:        harnessDeployment,
	}
	receipt.SetBodyHashBytes(computed)
	if err := receipt.Sign(context.Background(), rawKeyBytesSigner{addr: op.SigningAddr, priv: priv}, op.SigningAddr); err != nil {
		t.Fatalf("sign receipt: %v", err)
	}

	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	source := &ChainOperatorSource{}
	srv := &Client{
		cfg:          Config{Privacy: PrivacyDirect},
		log:          discard,
		refunds:      NewRefundWatchdog(discard),
		nodeExcluder: source,
	}
	handle := &fakeSettlementHandle{groupRejected: true}
	// Non-empty ⇒ the atomic path is attempted; AckSettle rejects it and the
	// dispatcher excludes the node.
	group := testSettleGroup

	check := srv.runReceiptChecks(
		context.Background(), endpointChatCompletions, "test-model",
		tkt, op, handle, receipt, computed, plaintext, group, nil,
	)

	if !check.excluded {
		t.Error("the check does not report the exclusion, so no NodeExcluded event fires")
	}
	if handle.ackCalls != 1 {
		t.Fatalf("AckSettle calls = %d, want 1", handle.ackCalls)
	}
	if !source.NodeExcluded(RefOf(op)) {
		t.Error("served node was not excluded after AckSettle reported a rejected settle group")
	}
	// Sanity: an HONEST settle (groupRejected=false) must NOT exclude the node.
	honestSource := &ChainOperatorSource{}
	honestSrv := &Client{cfg: Config{Privacy: PrivacyDirect}, log: discard, refunds: NewRefundWatchdog(discard), nodeExcluder: honestSource}
	honestHandle := &fakeSettlementHandle{groupRejected: false}
	honest := honestSrv.runReceiptChecks(
		context.Background(), endpointChatCompletions, "test-model",
		tkt, op, honestHandle, receipt, computed, plaintext, group, nil,
	)
	if honest.excluded {
		t.Error("an honest settle reported an exclusion")
	}
	if honestSource.NodeExcluded(RefOf(op)) {
		t.Error("an honest settle wrongly excluded the node")
	}
}

// contains reports whether id is among the operator ids.
func containsID(ids []uint64, id uint64) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// A node proven to have handed a fraudulent settle group is hard-dropped from
// the target candidate set — it never reaches SelectTargets, so it can't be
// picked no matter its price/latency. Its honest siblings/peers are untouched.
func TestPickCandidates_ExcludedNodeDropped(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
		routingOp(3, routingModel, 0, 0),
	})
	source := &ChainOperatorSource{}
	source.ExcludeNode(NodeRef{Op: 2}) // node id defaults to 0 on routingOp
	srv.nodeExcluder = source

	pick := routingPick(t, srv, selection.RoutingPreferences{})
	ids := opIDs(pick)
	if containsID(ids, 2) {
		t.Fatalf("excluded operator 2 still a candidate: %v", ids)
	}
	if !containsID(ids, 1) || !containsID(ids, 3) {
		t.Fatalf("honest peers dropped: got %v, want 1 and 3 present", ids)
	}
	// RegistryCount reflects the post-exclusion pool (filtered before the count),
	// so the empty-candidate diagnostics stay honest.
	if pick.RegistryCount != 2 {
		t.Errorf("RegistryCount = %d, want 2 (3 serving − 1 excluded)", pick.RegistryCount)
	}
}

// The exclusion fires in the settle of a turn whose response id and tool-call
// ids are already recorded, so both continuation pins must honour it too: the
// response-id pin blocks (its session lives only on that node), and the
// tool-call pin is no preference, even under strict, rather than handing
// SelectTargets a node its own filter has just dropped.
func TestPickCandidates_ExcludedNodeOffContinuationPins(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(7, routingModel, 0, 0),
	})
	source := &ChainOperatorSource{}
	source.ExcludeNode(NodeRef{Op: 7})
	srv.nodeExcluder = source
	srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.responseAffinity.Record(7, 0, []string{"rid"})
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(7, 0, []string{"call_1"})
	sizing := SizingRequest{Model: routingModel, InputTokens: 100, MaxOutputTokens: 100}

	// The response pin is a session, so it binds whatever the policy.
	responseBody := []byte(`{"model":"` + routingModel + `","previous_response_id":"rid","input":[]}`)
	const want = `previous_response_id "rid" is pinned to operator 7 node 0, which this payer excluded for handing it a fraudulent settle group; start a new conversation`
	for _, policy := range []AffinityPolicy{AffinityNone, AffinityPrefer, AffinityStrict} {
		srv.cfg.Affinity.Policy = policy
		pick, err := srv.pickCandidates(context.Background(), endpointResponses, routingModel, responseBody,
			sizing, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
		if err != nil {
			t.Fatalf("pickCandidates (%s): %v", policy, err)
		}
		if !pick.AffinityBlocked || len(pick.Operators) != 0 {
			t.Fatalf("response pin to an excluded node under %s: want AffinityBlocked and no operators, got %v blocked=%v", policy, opIDs(pick), pick.AffinityBlocked)
		}
		if pick.AffinityBlockReason != want {
			t.Errorf("reason under %s = %q, want %q", policy, pick.AffinityBlockReason, want)
		}
	}

	toolBody := []byte(`{"model":"` + routingModel + `","messages":[{"role":"tool","tool_call_id":"call_1"}]}`)
	for _, policy := range []AffinityPolicy{AffinityPrefer, AffinityStrict} {
		var logs bytes.Buffer
		srv.log = slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
		srv.cfg.Affinity.Policy = policy
		pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, routingModel, toolBody,
			sizing, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
		if err != nil {
			t.Fatalf("pickCandidates (%s): %v", policy, err)
		}
		if ids := opIDs(pick); pick.AffinityBlocked || len(ids) != 1 || ids[0] != 1 {
			t.Fatalf("tool pin to an excluded node under %s: want [1], got %v blocked=%v", policy, ids, pick.AffinityBlocked)
		}
		if !strings.Contains(logs.String(), `msg="affinity-preferred node is excluded" operator_id=7 node_id=0`) {
			t.Errorf("under %s, no exclusion debug line:\n%s", policy, logs.String())
		}
	}
}

// An excluded node behind the NEWEST pin ends the walk: the older pin behind
// it, to a live node, is not consulted, as for a node gone from the registry.
func TestPickCandidates_ExcludedNewestPinIsNoPreference(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
		routingOp(7, routingModel, 0, 0),
	})
	source := &ChainOperatorSource{}
	source.ExcludeNode(NodeRef{Op: 7})
	srv.nodeExcluder = source
	srv.cfg.Affinity.Policy = AffinityPrefer
	srv.toolAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.toolAffinity.Record(2, 0, []string{"call_old"})
	srv.toolAffinity.Record(7, 0, []string{"call_new"})

	body := []byte(`{"model":"` + routingModel + `","messages":[{"role":"tool","tool_call_id":"call_old"},{"role":"tool","tool_call_id":"call_new"}]}`)
	pick, err := srv.pickCandidates(context.Background(), endpointChatCompletions, routingModel, body,
		SizingRequest{Model: routingModel, InputTokens: 100, MaxOutputTokens: 100}, false, selection.ImageToolBudgets{}, selection.RoutingPreferences{})
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if ids := opIDs(pick); len(ids) != 2 || ids[0] != 1 {
		t.Fatalf("got %v, want the unpinned order with 1 first, not the older pin 2", ids)
	}
}

// The same exclusion drops the node from the relay pool: a node that tried to
// take the payer's account is not trusted to forward traffic either. This is a
// true DROP, distinct from RelayDownranked's soft demote to the fallback tier.
func TestRelayPool_ExcludedNodeDropped(t *testing.T) {
	ops := []Operator{
		relayOp(1, "OWNER_A", "http://a.example"),
		relayOp(2, "OWNER_B", "http://b.example"),
		relayOp(3, "OWNER_C", "http://c.example"),
	}
	srv := relayRepServer(t, true, ops, newFakeRelayRep())
	source := &ChainOperatorSource{}
	source.ExcludeNode(NodeRef{Op: 2})
	srv.nodeExcluder = source

	pool := srv.relayPool(context.Background())
	for _, m := range pool {
		if m.ID == 2 {
			t.Fatalf("excluded node 2 still in the relay pool (%d relays)", len(pool))
		}
	}
	if len(pool) != 2 {
		t.Fatalf("relay pool size = %d, want 2 (3 − 1 excluded)", len(pool))
	}
}
