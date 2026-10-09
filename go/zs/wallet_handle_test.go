/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// TestOpenHandle_NilWalletGuard: the detached-handle guard on each
// on-chain method returns a typed error instead of panicking on the
// nil receiver's fields. Tests that construct OpenHandle values
// directly (like the dispatch fakeWallet) rely on this.
func TestOpenHandle_NilWalletGuard(t *testing.T) {
	h := &OpenHandle{TicketID: "dGlja2V0LXhvcnZvenp6MDA="}
	r := &ticket.UsageReceipt{}

	if _, _, _, err := h.AckSettle(context.Background(), r, nil); err == nil || !strings.Contains(err.Error(), "detached") {
		t.Errorf("AckSettle on detached handle: err=%v, want 'detached'", err)
	}
	if _, _, err := h.Protest(context.Background(), r, []byte{}, escrow.ProtestReasonBodyHash); err == nil || !strings.Contains(err.Error(), "detached") {
		t.Errorf("Protest on detached handle: err=%v, want 'detached'", err)
	}
	if _, err := h.RefundInactive(context.Background()); err == nil || !strings.Contains(err.Error(), "detached") {
		t.Errorf("RefundInactive on detached handle: err=%v, want 'detached'", err)
	}
}

// TestReceiptSigDigest_MatchesProto: the digest the proxy submits on
// settle/protest must match sha256(canonical) so the contract's
// ed25519verify_bare check passes. Pin the byte-for-byte equivalence
// against an open-coded reference here so any future change to
// Receipt.CanonicalBytes or to the digest derivation stays in sync.
func TestReceiptSigDigest_MatchesProto(t *testing.T) {
	r := &ticket.UsageReceipt{
		TicketID:          "t-test",
		ActualInputCount:  10,
		ActualOutputCount: 3,
		AmountCharged:     100,
	}
	r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("x")))

	got := ticket.ReceiptSigDigest(r)
	want := wire.BodyHashOfBody(r.CanonicalBytes()) // sha256 — same primitive

	if got != want {
		t.Errorf("digest = %x, want %x", got, want)
	}
}

// TestDecodeTicketID_Boundaries pins the 16-byte round trip that the
// escrow contract's box-key schema demands. A mismatch here would
// silently submit groups with wrong-length ticket ids that the
// contract rejects.
func TestDecodeTicketID_Boundaries(t *testing.T) {
	tests := []struct {
		name string
		in   string
		ok   bool
	}{
		{"valid 16-byte b64", "AAAAAAAAAAAAAAAAAAAAAA==", true}, // 16 bytes of zeros
		{"empty", "", false},
		{"bad base64", "not-base-64!@#", false},
		{"wrong length", "AAAAAA==", false}, // 3 bytes
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := decodeTicketID(tc.in)
			if tc.ok {
				if err != nil {
					t.Fatalf("unexpected err: %v", err)
				}
				if len(raw) != 16 {
					t.Errorf("decoded len = %d, want 16", len(raw))
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error, got raw=%x", raw)
			}
		})
	}
}

// TestDecodeReceiptSig_Boundaries ensures the receipt's base64 Sig
// field converts to exactly 64 raw bytes. Short or malformed sigs
// surface at this boundary instead of reaching the contract's
// ed25519verify_bare call (which would revert with a less readable
// error).
func TestDecodeReceiptSig_Boundaries(t *testing.T) {
	// 64 bytes of zeros, base64-encoded (86 chars + "==" padding = 88 chars).
	valid := base64.StdEncoding.EncodeToString(make([]byte, 64))
	if raw, err := decodeReceiptSig(valid); err != nil || len(raw) != 64 {
		t.Errorf("valid sig: err=%v len=%d", err, len(raw))
	}

	if _, err := decodeReceiptSig("short"); err == nil {
		t.Error("short sig should fail")
	}
	if _, err := decodeReceiptSig("!@#not-base-64"); err == nil {
		t.Error("non-b64 sig should fail")
	}
}
