/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	sdktypes "github.com/algorand/go-algorand-sdk/v2/types"
)

func TestGenerateAlgorandKeypair_RoundTrip(t *testing.T) {
	addr, pub, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pub size = %d", len(pub))
	}
	if len(priv) != ed25519.PrivateKeySize {
		t.Fatalf("priv size = %d", len(priv))
	}
	if len(addr) != 58 {
		t.Errorf("addr length = %d, want 58", len(addr))
	}
	// Derived pubkey must match the generated one.
	got, err := DecodeAlgorandAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatal("decoded pubkey differs from generated")
	}
}

func TestEncodeDecodeAlgorandAddress_RoundTrip(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := EncodeAlgorandAddress(pub)
	got, err := DecodeAlgorandAddress(addr)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, pub) {
		t.Fatal("round-tripped pubkey differs")
	}
}

func TestDecodeAlgorandAddress_Errors(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		wantErr string
	}{
		{"empty", "", "length"},
		{"short", "SHORT", "length"},
		{"non-base32", strings.Repeat("!", 58), "decode base32"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := DecodeAlgorandAddress(c.addr)
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("err = %v, want %q", err, c.wantErr)
			}
		})
	}
}

func TestDecodeAlgorandAddress_ChecksumFailure(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	addr := EncodeAlgorandAddress(pub)
	// Tamper a character that isn't the last one — the 58th char carries
	// 2 slack bits (36 bytes = 288 bits, 58 × 5 = 290 bits), so flipping
	// some values there decodes to the same bytes and the checksum still
	// passes. Any interior char has all 5 of its bits in the output.
	tampered := []byte(addr)
	i := len(tampered) / 2
	if tampered[i] != 'A' {
		tampered[i] = 'A'
	} else {
		tampered[i] = 'B'
	}
	if _, err := DecodeAlgorandAddress(string(tampered)); err == nil {
		t.Fatal("tampered address decoded without error")
	}
}

// TestAlgorandAddress_MatchesSDK pins our hand-rolled address codec to
// go-algorand-sdk/v2/types. If this ever drifts (checksum byte order,
// base32 alphabet/padding, hash function) our on-chain identity and
// every wallet that speaks the SDK convention silently disagree, so we
// compare output byte-for-byte against the SDK for both a fixed vector
// (all-zero pubkey) and a batch of random pubkeys.
func TestAlgorandAddress_MatchesSDK(t *testing.T) {
	// Fixed vector: the canonical all-zero address.
	zero := make(ed25519.PublicKey, ed25519.PublicKeySize)
	gotZero := EncodeAlgorandAddress(zero)
	wantZero, err := sdktypes.EncodeAddress(zero)
	if err != nil {
		t.Fatalf("sdk EncodeAddress(zero): %v", err)
	}
	if gotZero != wantZero {
		t.Fatalf("zero-pubkey encoding: got %q, sdk %q", gotZero, wantZero)
	}

	// Randomised: any byte-level divergence (checksum slice, alphabet, padding)
	// trips this.
	for i := 0; i < 64; i++ {
		pub, _, err := ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}

		gotAddr := EncodeAlgorandAddress(pub)
		wantAddr, err := sdktypes.EncodeAddress(pub)
		if err != nil {
			t.Fatalf("sdk EncodeAddress: %v", err)
		}
		if gotAddr != wantAddr {
			t.Fatalf("encode divergence: ours=%q sdk=%q", gotAddr, wantAddr)
		}

		// Decode via us; SDK must accept the same string and return the same pubkey.
		gotPub, err := DecodeAlgorandAddress(gotAddr)
		if err != nil {
			t.Fatalf("DecodeAlgorandAddress(%q): %v", gotAddr, err)
		}
		sdkAddr, err := sdktypes.DecodeAddress(gotAddr)
		if err != nil {
			t.Fatalf("sdk DecodeAddress(%q): %v", gotAddr, err)
		}
		if !bytes.Equal(gotPub, sdkAddr[:]) {
			t.Fatalf("decode divergence: ours=%x sdk=%x", gotPub, sdkAddr[:])
		}
		if !bytes.Equal(gotPub, pub) {
			t.Fatalf("decoded pubkey differs from original")
		}
	}
}

// TestAlgorandAddress_SDKRejectsOurTamperedAddr guards the reverse
// direction: an address our decoder rejects for checksum mismatch must
// also be rejected by the SDK. If one side accepts and the other
// doesn't, an attacker can mint strings that look valid to only one
// participant in the protocol.
func TestAlgorandAddress_SDKRejectsOurTamperedAddr(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	addr := EncodeAlgorandAddress(pub)
	tampered := []byte(addr)
	i := len(tampered) / 2
	if tampered[i] != 'A' {
		tampered[i] = 'A'
	} else {
		tampered[i] = 'B'
	}
	if _, err := DecodeAlgorandAddress(string(tampered)); err == nil {
		t.Fatal("our decoder accepted tampered address")
	}
	if _, err := sdktypes.DecodeAddress(string(tampered)); err == nil {
		t.Fatal("sdk decoder accepted tampered address our decoder rejected")
	}
}

func TestTicketVerify_DigestShape(t *testing.T) {
	// Ticket.Verify expects Ed25519 over sha256(CanonicalBytes). Pin
	// both halves of the invariant: (a) a raw Ed25519 sig produced by
	// signing the digest verbatim must verify, and (b) a sig produced
	// by signing the legacy "MX"-prefixed payload must NOT verify.
	// The second half catches any reintroduction of the dropped
	// Algorand sign-bytes prefix.
	_, pub, priv, err := GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}

	tk := sampleTicket()
	digest := TicketSigDigest(tk)
	tk.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, digest[:]))
	if err := tk.Verify(pub); err != nil {
		t.Fatalf("digest-shaped sig should verify, got %v", err)
	}

	tk2 := sampleTicket()
	legacyMsg := append([]byte("MX"), tk2.CanonicalBytes()...)
	tk2.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, legacyMsg))
	if err := tk2.Verify(pub); err == nil {
		t.Fatal("legacy MX-prefixed sig should fail Verify")
	}
}
