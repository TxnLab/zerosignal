/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

// reserveSigFixture returns a signed reserve request plus everything a Verify
// call needs. The signer is keyed on the payer address, and the target
// (operatorID, nodeID) the signature binds are returned so tests can pass a
// wrong target and confirm rejection.
func reserveSigFixture(t *testing.T) (r *ReserveRequest, pub ed25519.PublicKey, operatorID, nodeID uint64, issuedAt time.Time) {
	t.Helper()
	signer, addr, pub := newFakeSigner(t)
	operatorID, nodeID = 42, 7
	issuedAt = time.Unix(1_700_000_000, 0)
	r = &ReserveRequest{
		Model:          "gpt-4.1-mini",
		InputCount:     1234,
		MaxOutputCount: 512,
		Stream:         true,
		ProxyRecipient: "age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s",
		PayerIssuedAt:  issuedAt.Unix(),
	}
	if err := r.Sign(context.Background(), signer, addr, operatorID, nodeID); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if r.PayerSig == "" {
		t.Fatal("Sign left PayerSig empty")
	}
	if r.PayerAddr != addr {
		t.Fatalf("Sign set PayerAddr=%q, want %q", r.PayerAddr, addr)
	}
	return r, pub, operatorID, nodeID, issuedAt
}

func TestReserveSign_VerifyRoundTrip(t *testing.T) {
	r, pub, op, node, issuedAt := reserveSigFixture(t)
	// A fresh reserve within the window verifies.
	if err := r.Verify(pub, op, node, issuedAt.Add(5*time.Second), DefaultReserveSkew); err != nil {
		t.Fatalf("verify fresh sig: %v", err)
	}
}

func TestReserveVerify_NilSigner(t *testing.T) {
	r := &ReserveRequest{Model: "m"}
	if err := r.Sign(context.Background(), nil, "addr", 1, 1); err == nil {
		t.Fatal("Sign with nil signer should error")
	}
}

// Each signed field, when tampered after signing, must break verification.
func TestReserveVerify_TamperedFieldRejected(t *testing.T) {
	base, pub, op, node, issuedAt := reserveSigFixture(t)
	now := issuedAt.Add(5 * time.Second)

	tampers := map[string]func(r *ReserveRequest){
		"model":            func(r *ReserveRequest) { r.Model = "gpt-4.1" },
		"input_count":      func(r *ReserveRequest) { r.InputCount++ },
		"max_output_count": func(r *ReserveRequest) { r.MaxOutputCount++ },
		"stream":           func(r *ReserveRequest) { r.Stream = !r.Stream },
		"proxy_recipient":  func(r *ReserveRequest) { r.ProxyRecipient = "age1other" },
		"payer_issued_at":  func(r *ReserveRequest) { r.PayerIssuedAt++ },
		"payer_addr":       func(r *ReserveRequest) { r.PayerAddr = EncodeAlgorandAddress(make(ed25519.PublicKey, 32)) },
	}
	for name, mutate := range tampers {
		clone := *base
		mutate(&clone)
		if err := clone.Verify(pub, op, node, now, DefaultReserveSkew); err == nil {
			t.Errorf("tampered %s: Verify accepted a mutated field", name)
		}
	}
}

// A signature bound to one node must not verify at a sibling node (or a
// different operator) — the target-binding property.
func TestReserveVerify_WrongTargetRejected(t *testing.T) {
	r, pub, op, node, issuedAt := reserveSigFixture(t)
	now := issuedAt.Add(5 * time.Second)

	if err := r.Verify(pub, op, node+1, now, DefaultReserveSkew); err == nil {
		t.Error("Verify accepted a signature bound to a different node_id")
	}
	if err := r.Verify(pub, op+1, node, now, DefaultReserveSkew); err == nil {
		t.Error("Verify accepted a signature bound to a different operator_id")
	}
	// The correct target still verifies.
	if err := r.Verify(pub, op, node, now, DefaultReserveSkew); err != nil {
		t.Errorf("correct target failed: %v", err)
	}
}

func TestReserveVerify_WrongKeyRejected(t *testing.T) {
	r, _, op, node, issuedAt := reserveSigFixture(t)
	otherPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(otherPub, op, node, issuedAt.Add(5*time.Second), DefaultReserveSkew); err == nil {
		t.Error("Verify accepted a signature under the wrong key")
	}
}

// Window boundaries: future-dated rejected, just-inside expiry accepted, just
// past expiry surfaces ErrReserveSigExpired.
func TestReserveVerify_WindowBoundaries(t *testing.T) {
	r, pub, op, node, issuedAt := reserveSigFixture(t)
	skew := DefaultReserveSkew

	// Future-dated: verify at a `now` before issuedAt-skew is "not yet valid".
	if err := r.Verify(pub, op, node, issuedAt.Add(-skew-time.Second), skew); err == nil {
		t.Error("Verify accepted a future-dated signature")
	} else if errors.Is(err, ErrReserveSigExpired) {
		t.Error("future-dated should not be reported as expired")
	}

	// Exactly at the not-before edge (now == issuedAt - skew) is accepted.
	if err := r.Verify(pub, op, node, issuedAt.Add(-skew), skew); err != nil {
		t.Errorf("not-before boundary should be accepted: %v", err)
	}

	// Just inside the expiry edge: now == issuedAt + MaxReserveSigAge + skew.
	edge := issuedAt.Add(MaxReserveSigAge).Add(skew)
	if err := r.Verify(pub, op, node, edge, skew); err != nil {
		t.Errorf("expiry boundary should be accepted: %v", err)
	}

	// One second past the edge: expired sentinel.
	if err := r.Verify(pub, op, node, edge.Add(time.Second), skew); !errors.Is(err, ErrReserveSigExpired) {
		t.Errorf("past expiry err = %v, want ErrReserveSigExpired", err)
	}
}

// CanonicalBytes must fold the target ids in — different targets produce
// different bytes even for an otherwise-identical request.
func TestReserveCanonicalBytes_TargetChangesBytes(t *testing.T) {
	r := &ReserveRequest{Model: "m", InputCount: 1, ProxyRecipient: "age1x"}
	a := r.CanonicalBytes(1, 1)
	b := r.CanonicalBytes(1, 2)
	c := r.CanonicalBytes(2, 1)
	if string(a) == string(b) || string(a) == string(c) {
		t.Error("CanonicalBytes did not bind the target (operatorID, nodeID)")
	}
}

// TestReserveRequest_ImageBudgetsRoundTrip confirms the image-tool
// budget fields serialize and parse on the plaintext reserve request, and
// are omitted when zero. They never touch Ticket.CanonicalBytes (the
// signing guarantee is enforced by the cross-impl vectors test), so a node
// on an older build simply ignores them.
func TestReserveRequest_ImageBudgetsRoundTrip(t *testing.T) {
	in := ReserveRequest{
		Model:               "gpt-4o",
		InputCount:          100,
		MaxOutputCount:      500,
		ImageToolBudget:     4,
		ImageEditToolBudget: 2,
	}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out ReserveRequest
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.ImageToolBudget != 4 || out.ImageEditToolBudget != 2 {
		t.Errorf("budgets round-trip = (%d,%d), want (4,2)", out.ImageToolBudget, out.ImageEditToolBudget)
	}
}

func TestReserveRequest_ImageBudgetsOmittedWhenZero(t *testing.T) {
	b, err := json.Marshal(ReserveRequest{Model: "gpt-4o"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := m["image_tool_budget"]; ok {
		t.Error("image_tool_budget should be omitted when zero")
	}
	if _, ok := m["image_edit_tool_budget"]; ok {
		t.Error("image_edit_tool_budget should be omitted when zero")
	}
}
