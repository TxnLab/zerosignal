/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/wire"
)

func sampleReceipt() *UsageReceipt {
	r := &UsageReceipt{
		TicketID:          "dGlja2V0LXhvcnZvenp6MDA=",
		ActualInputCount:  42,
		ActualOutputCount: 17,
		AmountCharged:     2_600,
	}
	r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("hello world")))
	return r
}

func TestUsageReceipt_CanonicalBytes_Deterministic(t *testing.T) {
	r := sampleReceipt()
	a := r.CanonicalBytes()
	b := r.CanonicalBytes()
	if !bytes.Equal(a, b) {
		t.Fatal("CanonicalBytes not deterministic")
	}
	if !bytes.HasPrefix(a, []byte(receiptSigningTag)) {
		t.Fatal("CanonicalBytes missing domain prefix")
	}
}

func TestUsageReceipt_SignVerify_RoundTrip(t *testing.T) {
	signingAddr, pub, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	signer := receiptTestSigner{addr: signingAddr, priv: priv}
	if err := r.Sign(context.Background(), signer, signingAddr); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if r.Sig == "" {
		t.Fatal("Sig is empty after Sign")
	}
	if err := r.Verify(pub); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestUsageReceipt_Sign_RejectsNilSigner(t *testing.T) {
	r := sampleReceipt()
	err := r.Sign(context.Background(), nil, "addr")
	if err == nil || !strings.Contains(err.Error(), "signer is nil") {
		t.Fatalf("expected nil-signer error, got %v", err)
	}
}

func TestUsageReceipt_Sign_PropagatesSignerError(t *testing.T) {
	r := sampleReceipt()
	signer := receiptTestSigner{err: errors.New("hsm unreachable")}
	err := r.Sign(context.Background(), signer, "addr")
	if err == nil || !strings.Contains(err.Error(), "hsm unreachable") {
		t.Fatalf("expected signer error to propagate, got %v", err)
	}
}

func TestUsageReceipt_Verify_RejectsShortSig(t *testing.T) {
	r := sampleReceipt()
	r.Sig = base64.StdEncoding.EncodeToString([]byte("too short"))
	_, pub, _, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Verify(pub); err == nil {
		t.Fatal("expected error for short signature")
	}
}

func TestUsageReceipt_Verify_DigestShape_Required(t *testing.T) {
	// UsageReceipt.Verify expects Ed25519 over sha256(CanonicalBytes).
	// Pin both halves: (a) signing the digest directly must verify,
	// and (b) signing the legacy "MX"-prefixed message must NOT
	// verify. The second half catches any reintroduction of the
	// dropped Algorand sign-bytes prefix.
	_, pub, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}

	r := sampleReceipt()
	digest := ReceiptSigDigest(r)
	r.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))
	if err := r.Verify(pub); err != nil {
		t.Fatalf("digest-shaped sig should verify, got %v", err)
	}

	r2 := sampleReceipt()
	legacyMsg := append([]byte("MX"), r2.CanonicalBytes()...)
	r2.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, legacyMsg))
	if err := r2.Verify(pub); err == nil {
		t.Fatal("legacy MX-prefixed sig should fail Verify")
	}
}

// TestUsageReceipt_Verify_FailsOnFieldTamper pins that every signed
// field participates in the signature. If a future refactor drops a
// field from CanonicalBytes, one of these mutations will silently
// keep verifying and the test will fail.
func TestUsageReceipt_Verify_FailsOnFieldTamper(t *testing.T) {
	signingAddr, pub, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signer := receiptTestSigner{addr: signingAddr, priv: priv}

	mutate := map[string]func(*UsageReceipt){
		"ticket_id":             func(r *UsageReceipt) { r.TicketID = "tampered" },
		"actual_input_count":    func(r *UsageReceipt) { r.ActualInputCount++ },
		"actual_output_count":   func(r *UsageReceipt) { r.ActualOutputCount++ },
		"amount_charged":        func(r *UsageReceipt) { r.AmountCharged++ },
		"ttft_ms":               func(r *UsageReceipt) { r.TtftMs++ },
		"decode_ms":             func(r *UsageReceipt) { r.DecodeMs++ },
		"body_hash":             func(r *UsageReceipt) { r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("something else"))) },
		"input_usage_type":      func(r *UsageReceipt) { r.InputUsageType++ },
		"output_usage_type":     func(r *UsageReceipt) { r.OutputUsageType++ },
		"aux_output_usage_type": func(r *UsageReceipt) { r.AuxOutputUsageType++ },
		"aux_output_count":      func(r *UsageReceipt) { r.AuxOutputCount++ },
		"cached_input_count":    func(r *UsageReceipt) { r.CachedInputCount++ },
	}
	for field, tamper := range mutate {
		t.Run(field, func(t *testing.T) {
			r := sampleReceipt()
			if err := r.Sign(context.Background(), signer, signingAddr); err != nil {
				t.Fatalf("Sign: %v", err)
			}
			tamper(r)
			if err := r.Verify(pub); err == nil {
				t.Fatalf("Verify should fail after tampering %s", field)
			}
		})
	}
}

func TestUsageReceipt_HeaderRoundTrip(t *testing.T) {
	signingAddr, _, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	r := sampleReceipt()
	if err := r.Sign(context.Background(), receiptTestSigner{addr: signingAddr, priv: priv}, signingAddr); err != nil {
		t.Fatal(err)
	}
	enc, err := r.EncodeReceiptHeader()
	if err != nil {
		t.Fatalf("EncodeReceiptHeader: %v", err)
	}
	got, err := DecodeReceiptHeader(enc)
	if err != nil {
		t.Fatalf("DecodeReceiptHeader: %v", err)
	}
	if got != *r {
		t.Fatalf("round-trip mismatch:\n got:  %+v\n want: %+v", got, *r)
	}
}

func TestUsageReceipt_BodyHashBytes_RoundTrip(t *testing.T) {
	r := &UsageReceipt{}
	r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("abcdef")))
	got, err := r.BodyHashBytes()
	if err != nil {
		t.Fatal(err)
	}
	want := wire.BodyHashOfBody([]byte("abcdef"))
	if got != want {
		t.Fatalf("hash mismatch")
	}

	r.BodyHash = "not-hex"
	if _, err := r.BodyHashBytes(); err == nil {
		t.Fatal("expected error on short/invalid hex")
	}
	r.BodyHash = strings.Repeat("g", 64) // right length, wrong alphabet
	if _, err := r.BodyHashBytes(); err == nil {
		t.Fatal("expected error on non-hex chars")
	}
}

func TestBodyHashFromFrames(t *testing.T) {
	frames := [][]byte{[]byte("hello "), []byte("world")}
	got := wire.BodyHashFromFrames(frames)
	want := wire.BodyHashOfBody([]byte("hello world"))
	if got != want {
		t.Fatalf("frame concat hash should equal body hash of concatenation")
	}

	// Ordering matters: reversed frames → different hash.
	rev := [][]byte{[]byte("world"), []byte("hello ")}
	if wire.BodyHashFromFrames(rev) == want {
		t.Fatal("hash should depend on frame order")
	}

	// Empty input → sha256 of empty string.
	if wire.BodyHashFromFrames(nil) != wire.BodyHashOfBody(nil) {
		t.Fatal("empty frames should hash like empty body")
	}
}

func TestUsageReceipt_TokensPerSec(t *testing.T) {
	// 900 output tokens over a 3000ms decode window = 300 tok/s.
	r := &UsageReceipt{ActualOutputCount: 900, TtftMs: 120, DecodeMs: 3000}
	if got := r.TokensPerSec(); got != 300 {
		t.Errorf("TokensPerSec() = %d, want 300", got)
	}
	// No decode window (non-stream / no first token) → no throughput signal.
	noDecode := &UsageReceipt{ActualOutputCount: 900, TtftMs: 4200, DecodeMs: 0}
	if got := noDecode.TokensPerSec(); got != 0 {
		t.Errorf("TokensPerSec() with decode=0 = %d, want 0", got)
	}
}

// receiptTestSigner is a BytesSigner backed by a raw ed25519 private
// key. Mirrors the existing Ticket tests' signer pattern.
type receiptTestSigner struct {
	addr string
	priv ed25519.PrivateKey
	err  error
}

func (s receiptTestSigner) SignBytes(_ context.Context, addr string, msg []byte) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	if s.addr != "" && addr != s.addr {
		return nil, errors.New("receiptTestSigner: address mismatch")
	}
	return ed25519.Sign(s.priv, msg), nil
}
