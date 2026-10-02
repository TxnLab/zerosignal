/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"testing"

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

func (f *fakeSettlementHandle) AckSettle(_ context.Context, _ *ticket.UsageReceipt, _ []types.SignedTxn) (string, uint64, bool, error) {
	f.ackCalls++
	// err=nil, so the dispatcher takes the success branch — the exact path where
	// the Resolve-gate must NOT un-track a rejected-then-standalone settle.
	return "STANDALONE_ACK_TXID", 5000, f.groupRejected, nil
}

func (f *fakeSettlementHandle) Protest(_ context.Context, _ *ticket.UsageReceipt, _ []byte, _ escrow.ProtestReasonCode) (string, error) {
	f.protestCalls++
	return "", nil
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
		TicketID:   "dGlja2V0LXhvcnZvenp6MDA=",
		OperatorID: op.ID,
		NodeID:     op.NodeID,
		MaxPrice:   100_000,
	}

	plaintext := []byte("hello world")
	computed := wire.BodyHashOfBody(plaintext)
	receipt := &ticket.UsageReceipt{
		TicketID:          tkt.TicketID,
		ActualInputCount:  10,
		ActualOutputCount: 5,
		AmountCharged:     50_000, // <= MaxPrice
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
	group := []types.SignedTxn{{}, {}}

	srv.runReceiptChecks(
		context.Background(), endpointChatCompletions, "test-model",
		tkt, op, handle, receipt, computed, plaintext, 0.20, group, nil,
	)

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
	honestSrv.runReceiptChecks(
		context.Background(), endpointChatCompletions, "test-model",
		tkt, op, honestHandle, receipt, computed, plaintext, 0.20, group, nil,
	)
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
