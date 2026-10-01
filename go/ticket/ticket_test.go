/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/TxnLab/zerosignal/go/wire"
)

// fakeBytesSigner is the in-memory BytesSigner used by ticket tests so the
// proto package can exercise the signer interface without depending on
// proto/keystore (which would create an import cycle).
type fakeBytesSigner struct {
	keys map[string]ed25519.PrivateKey
}

func (f *fakeBytesSigner) SignBytes(_ context.Context, addr string, msg []byte) ([]byte, error) {
	priv, ok := f.keys[addr]
	if !ok {
		return nil, errors.New("address not in fake keystore")
	}
	return ed25519.Sign(priv, msg), nil
}

func newFakeSigner(t *testing.T) (signer *fakeBytesSigner, addr string, pub ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr = EncodeAlgorandAddress(pub)
	return &fakeBytesSigner{keys: map[string]ed25519.PrivateKey{addr: priv}}, addr, pub
}

// sampleTicket returns a Ticket with deterministic non-zero fields, suitable
// for signing/verification tests. CommitK is base64(sha256(zero key)) — any
// valid base64 value works; we are not testing the commitment property here.
func sampleTicket() *Ticket {
	var k [wire.ResponseKeySize]byte
	commit := CommitResponseKey(k)
	return &Ticket{
		TicketID:       base64.StdEncoding.EncodeToString([]byte("sixteen-byte-id!")),
		OperatorID:     42,
		InputCount:     1234,
		MaxOutputCount: 512,
		InputRate:      2,
		OutputRate:     4,
		MaxPrice:       1234*2 + 512*4,
		MinPrice:       50,
		ExpiresAt:      1_700_000_000,
		Model:          "gpt-4.1-mini",
		Stream:         true,
		CommitK:        base64.StdEncoding.EncodeToString(commit[:]),
	}
}

func TestTicket_SignVerify_RoundTrip(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	tk := sampleTicket()
	if err := tk.Sign(context.Background(), signer, addr); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := tk.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestTicket_Sign_UnknownAddress(t *testing.T) {
	signer, _, _ := newFakeSigner(t)
	tk := sampleTicket()
	err := tk.Sign(context.Background(), signer, "OTHER_ADDR_NOT_IN_KEYSTORE_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
	if err == nil {
		t.Fatal("want error when signing with an unknown address")
	}
}

func TestTicket_Sign_NilSigner(t *testing.T) {
	tk := sampleTicket()
	if err := tk.Sign(context.Background(), nil, "anything"); err == nil {
		t.Fatal("want error on nil signer")
	}
}

func TestTicket_Verify_WrongKey(t *testing.T) {
	signer, addr, _ := newFakeSigner(t)
	otherPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tk := sampleTicket()
	_ = tk.Sign(context.Background(), signer, addr)
	if err := tk.Verify(otherPub); err == nil {
		t.Fatal("want verify error with wrong pubkey")
	}
}

func TestTicket_Verify_TamperedField(t *testing.T) {
	// Flip a field after signing; verification must fail. Try each field.
	cases := []struct {
		name   string
		mutate func(*Ticket)
	}{
		{"ticket_id", func(t *Ticket) { t.TicketID = base64.StdEncoding.EncodeToString([]byte("different-id----")) }},
		{"operator_id", func(t *Ticket) { t.OperatorID++ }},
		{"input_count", func(t *Ticket) { t.InputCount++ }},
		{"max_output_count", func(t *Ticket) { t.MaxOutputCount++ }},
		{"input_rate", func(t *Ticket) { t.InputRate++ }},
		{"output_rate", func(t *Ticket) { t.OutputRate++ }},
		{"max_price", func(t *Ticket) { t.MaxPrice++ }},
		{"min_price", func(t *Ticket) { t.MinPrice++ }},
		{"expires_at", func(t *Ticket) { t.ExpiresAt++ }},
		{"model", func(t *Ticket) { t.Model = "other-model" }},
		{"stream", func(t *Ticket) { t.Stream = !t.Stream }},
		{"commit_k", func(t *Ticket) {
			raw, _ := base64.StdEncoding.DecodeString(t.CommitK)
			raw[0] ^= 0xFF
			t.CommitK = base64.StdEncoding.EncodeToString(raw)
		}},
		{"input_usage_type", func(t *Ticket) { t.InputUsageType++ }},
		{"output_usage_type", func(t *Ticket) { t.OutputUsageType++ }},
		{"cache_read_rate", func(t *Ticket) { t.CacheReadRate++ }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			signer, addr, pub := newFakeSigner(t)
			tk := sampleTicket()
			if err := tk.Sign(context.Background(), signer, addr); err != nil {
				t.Fatal(err)
			}
			c.mutate(tk)
			if err := tk.Verify(pub); err == nil {
				t.Fatalf("tampered %s: verify passed", c.name)
			}
		})
	}
}

func TestTicket_Verify_BadSig(t *testing.T) {
	signer, addr, pub := newFakeSigner(t)
	tk := sampleTicket()
	_ = tk.Sign(context.Background(), signer, addr)
	tk.Sig = "!!!not-base64!!!"
	if err := tk.Verify(pub); err == nil {
		t.Fatal("want error on non-base64 sig")
	}
	tk.Sig = base64.StdEncoding.EncodeToString([]byte("too-short"))
	if err := tk.Verify(pub); err == nil {
		t.Fatal("want error on wrong-length sig")
	}
}

func TestTicket_Verify_WrongPubKeyLength(t *testing.T) {
	signer, addr, _ := newFakeSigner(t)
	tk := sampleTicket()
	_ = tk.Sign(context.Background(), signer, addr)
	if err := tk.Verify(ed25519.PublicKey([]byte{1, 2, 3})); err == nil {
		t.Fatal("want error on short pubkey")
	}
}

func TestTicket_CanonicalBytes_IsDeterministic(t *testing.T) {
	// Same struct → same bytes. This is the property sign/verify depend on.
	a := sampleTicket().CanonicalBytes()
	b := sampleTicket().CanonicalBytes()
	if !bytes.Equal(a, b) {
		t.Fatal("CanonicalBytes not deterministic for identical structs")
	}
}

func TestTicket_CanonicalBytes_ExcludesSig(t *testing.T) {
	// Changing Sig after construction must not change CanonicalBytes — Sig
	// is the output, not an input, so verifier recomputes the same bytes
	// regardless of what Sig was pre-populated with.
	a := sampleTicket()
	before := append([]byte(nil), a.CanonicalBytes()...)
	a.Sig = "anything"
	after := a.CanonicalBytes()
	if !bytes.Equal(before, after) {
		t.Fatal("CanonicalBytes depends on Sig; must not")
	}
}

func TestCommitResponseKey_MatchesSha256(t *testing.T) {
	// Trivial sanity: two equal keys commit equal; different keys commit
	// different.
	var k1 [wire.ResponseKeySize]byte
	var k2 [wire.ResponseKeySize]byte
	k2[0] = 1
	if CommitResponseKey(k1) == CommitResponseKey(k2) {
		t.Fatal("different keys committed to the same value")
	}
	if CommitResponseKey(k1) != CommitResponseKey(k1) {
		t.Fatal("commit not deterministic for same key")
	}
}
