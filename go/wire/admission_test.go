/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestComputeAdmissionTag_Deterministic(t *testing.T) {
	var k [ResponseKeySize]byte
	if _, err := rand.Read(k[:]); err != nil {
		t.Fatal(err)
	}
	ticketID := "YWJjZGVmZ2hpamtsbW5vcA==" // arbitrary base64
	txID := "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
	body := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`)

	a := ComputeAdmissionTag(k, ticketID, txID, body)
	b := ComputeAdmissionTag(k, ticketID, txID, body)
	if !bytes.Equal(a, b) {
		t.Fatalf("tag differs across calls on identical inputs: %x vs %x", a, b)
	}
	if len(a) != AdmissionTagSize {
		t.Errorf("tag size = %d, want %d", len(a), AdmissionTagSize)
	}
}

// TestComputeAdmissionTag_Differs verifies that perturbing each input
// in isolation produces a different tag. Catches accidental
// no-ops (e.g. forgetting to feed one of the inputs into the HMAC)
// without having to read the implementation.
func TestComputeAdmissionTag_Differs(t *testing.T) {
	var k [ResponseKeySize]byte
	_, _ = rand.Read(k[:])
	ticketID := "dGlja2V0aWRiYXNlNjQhIQ=="
	txID := "TXID0123456789ABCDEFGHIJKLMNOPQR"
	body := []byte("hello")
	base := ComputeAdmissionTag(k, ticketID, txID, body)

	// Different key
	k2 := k
	k2[0] ^= 0x01
	if got := ComputeAdmissionTag(k2, ticketID, txID, body); bytes.Equal(got, base) {
		t.Error("tag unchanged after flipping a bit of K")
	}

	// Different ticket id
	if got := ComputeAdmissionTag(k, ticketID+"x", txID, body); bytes.Equal(got, base) {
		t.Error("tag unchanged after mutating ticket_id")
	}

	// Different tx id
	if got := ComputeAdmissionTag(k, ticketID, txID+"x", body); bytes.Equal(got, base) {
		t.Error("tag unchanged after mutating tx_id")
	}

	// Different body
	body2 := append([]byte(nil), body...)
	body2[0] ^= 0x01
	if got := ComputeAdmissionTag(k, ticketID, txID, body2); bytes.Equal(got, base) {
		t.Error("tag unchanged after flipping a bit of body")
	}

	// Domain separation: moving the boundary between ticket_id and
	// tx_id must change the tag. Without the NUL separators the two
	// concatenations would collide.
	if got := ComputeAdmissionTag(k, ticketID+"A", txID[1:], body); bytes.Equal(got, base) {
		t.Error("tag unchanged after shifting the ticket_id/tx_id boundary — separator missing or weak")
	}
}

// TestDecryptRequest_AdmissionTag_RoundTrip confirms the wire-format
// encode/decode path for AdmissionTag: the 32-byte HMAC a caller
// passes to WrapRequest comes out byte-identical from DecryptRequest.
// Actual verification is the node's job; this test only covers the
// codec.
func TestDecryptRequest_AdmissionTag_RoundTrip(t *testing.T) {
	node := newTestIdentity(t)
	tag := bytes.Repeat([]byte{0x5A}, AdmissionTagSize)

	envJSON, _, err := WrapRequest([]byte("hi"), "TX", "TKT", tag, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptRequest(envJSON, node)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.AdmissionTag, tag) {
		t.Errorf("AdmissionTag mismatch: got %x want %x", got.AdmissionTag, tag)
	}
}

// TestDecryptRequest_AdmissionTag_WrongLength rejects any tag that
// doesn't decode to exactly AdmissionTagSize bytes. Short or long
// values are surely garbage — the HMAC verification would fail
// anyway, but catching it at decode time keeps the error surface
// clean and the node's verify path simple.
func TestDecryptRequest_AdmissionTag_WrongLength(t *testing.T) {
	node := newTestIdentity(t)
	envJSON, _, err := WrapRequest([]byte("hi"), "TX", "TKT", []byte{0x01, 0x02}, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptRequest(envJSON, node); err == nil {
		t.Fatal("want length error, got nil")
	}
}
