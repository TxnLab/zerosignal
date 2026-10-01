/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"filippo.io/age"
)

// newSealerOpenerPair builds a sealer and the opener that reads it, over a
// throwaway ephemeral recipient.
func newSealerOpenerPair(t *testing.T, txID, ticketID string) (*ResponseSealer, *ResponseOpener) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate identity: %v", err)
	}
	sealer, err := NewResponseSealer(id.Recipient(), txID, ticketID)
	if err != nil {
		t.Fatalf("NewResponseSealer: %v", err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatalf("UnwrapResponseKey: %v", err)
	}
	opener, err := NewResponseOpener(key, txID, ticketID)
	if err != nil {
		t.Fatalf("NewResponseOpener: %v", err)
	}
	return sealer, opener
}

func TestResponseOpener_BodyRoundTrip(t *testing.T) {
	sealer, opener := newSealerOpenerPair(t, "TX", "TKT")
	sealed, err := sealer.SealBody([]byte(`{"hello":"world"}`))
	if err != nil {
		t.Fatalf("SealBody: %v", err)
	}
	got, err := opener.OpenBody(sealed)
	if err != nil {
		t.Fatalf("OpenBody: %v", err)
	}
	if string(got) != `{"hello":"world"}` {
		t.Fatalf("OpenBody = %q", got)
	}
	if opener.FrameIndex() != 0 {
		t.Errorf("FrameIndex = %d after OpenBody, want 0 — a body is not a frame", opener.FrameIndex())
	}
}

// TestResponseOpener_FramesInOrder is the counter rule from the reading side:
// the sealer advances per SealStreamFrame, so the opener must present the same
// sequence of indices or every frame after the first mismatch fails.
func TestResponseOpener_FramesInOrder(t *testing.T) {
	sealer, opener := newSealerOpenerPair(t, "TX", "TKT")
	want := []string{"a", "bb", "ccc", "dddd"}
	sealed := make([]string, 0, len(want))
	for _, p := range want {
		s, err := sealer.SealStreamFrame([]byte(p))
		if err != nil {
			t.Fatalf("SealStreamFrame: %v", err)
		}
		sealed = append(sealed, s)
	}
	for i, s := range sealed {
		got, err := opener.OpenNextFrame([]byte(s))
		if err != nil {
			t.Fatalf("OpenNextFrame(%d): %v", i, err)
		}
		if string(got) != want[i] {
			t.Errorf("frame %d = %q, want %q", i, got, want[i])
		}
		if opener.FrameIndex() != uint64(i+1) {
			t.Errorf("FrameIndex after frame %d = %d, want %d", i, opener.FrameIndex(), i+1)
		}
	}
}

// TestResponseOpener_HeaderDoesNotAdvance pins the rule that makes OpenHeader
// a separate method: a sealed header (the `zs-settle-group` SSE frame) arrives
// BETWEEN content frames, and consuming an index for it would push every
// following frame — including the receipt — off by one.
func TestResponseOpener_HeaderDoesNotAdvance(t *testing.T) {
	sealer, opener := newSealerOpenerPair(t, "TX", "TKT")

	first, err := sealer.SealStreamFrame([]byte("content"))
	if err != nil {
		t.Fatalf("SealStreamFrame: %v", err)
	}
	header, err := sealer.SealHeader(SealedHeaderSettleGroup, []byte(`{"group":true}`))
	if err != nil {
		t.Fatalf("SealHeader: %v", err)
	}
	receipt, err := sealer.SealStreamFrame([]byte(`{"receipt":true}`))
	if err != nil {
		t.Fatalf("SealStreamFrame: %v", err)
	}

	if _, err := opener.OpenNextFrame([]byte(first)); err != nil {
		t.Fatalf("OpenNextFrame(content): %v", err)
	}
	if _, err := opener.OpenHeader(header, SealedHeaderSettleGroup); err != nil {
		t.Fatalf("OpenHeader: %v", err)
	}
	if opener.FrameIndex() != 1 {
		t.Fatalf("FrameIndex = %d after OpenHeader, want 1 — a sealed header consumes no frame slot", opener.FrameIndex())
	}
	// The receipt frame was sealed at index 1. It only opens if the header
	// left the counter alone.
	got, err := opener.OpenNextFrame([]byte(receipt))
	if err != nil {
		t.Fatalf("OpenNextFrame(receipt): %v — the settle-group header consumed a frame index", err)
	}
	if string(got) != `{"receipt":true}` {
		t.Errorf("receipt = %q", got)
	}
}

// TestResponseOpener_FailedFrameDoesNotAdvance pins the advance-on-success-only
// rule. A failed open means these bytes were not the frame this key and index
// produced; charging a slot for them would desynchronize the opener from the
// sealer and turn one bad frame into a stream of them.
func TestResponseOpener_FailedFrameDoesNotAdvance(t *testing.T) {
	sealer, opener := newSealerOpenerPair(t, "TX", "TKT")
	frame0, err := sealer.SealStreamFrame([]byte("zero"))
	if err != nil {
		t.Fatalf("SealStreamFrame: %v", err)
	}

	for _, bad := range []struct {
		name string
		data string
	}{
		{"bad base64", "!!not b64!!"},
		{"too short", "AAAA"},
		{"not this key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
	} {
		if _, err := opener.OpenNextFrame([]byte(bad.data)); err == nil {
			t.Fatalf("%s: OpenNextFrame succeeded, want error", bad.name)
		}
		if opener.FrameIndex() != 0 {
			t.Fatalf("%s: FrameIndex = %d after a failed open, want 0", bad.name, opener.FrameIndex())
		}
	}

	// Still at index 0, so the genuine frame 0 opens.
	got, err := opener.OpenNextFrame([]byte(frame0))
	if err != nil {
		t.Fatalf("OpenNextFrame after failures: %v — a failed open consumed an index", err)
	}
	if string(got) != "zero" {
		t.Errorf("frame 0 = %q, want %q", got, "zero")
	}
}

// TestResponseOpener_EmptyPayloadIsExactlyMinimumLength pins the length guard's
// boundary. An empty plaintext seals to exactly NonceSize+Overhead bytes, so a
// `<=` where the guard says `<` rejects a legitimately sealed empty frame as
// "too short" — which on a stream aborts the read before the settlement tail.
// Every other short-input test sits far below the boundary and cannot tell the
// two comparisons apart.
func TestResponseOpener_EmptyPayloadIsExactlyMinimumLength(t *testing.T) {
	sealer, opener := newSealerOpenerPair(t, "TX", "TKT")

	frame, err := sealer.SealStreamFrame([]byte{})
	if err != nil {
		t.Fatalf("SealStreamFrame(empty): %v", err)
	}
	got, err := opener.OpenNextFrame([]byte(frame))
	if err != nil {
		t.Fatalf("OpenNextFrame on an empty sealed frame: %v — the minimum-length guard is off by one", err)
	}
	if len(got) != 0 {
		t.Errorf("plaintext = %q, want empty", got)
	}
	if opener.FrameIndex() != 1 {
		t.Errorf("FrameIndex = %d, want 1 — a successfully opened empty frame still consumes a slot", opener.FrameIndex())
	}

	header, err := sealer.SealHeader(SealedHeaderReceipt, []byte{})
	if err != nil {
		t.Fatalf("SealHeader(empty): %v", err)
	}
	if _, err := opener.OpenHeader(header, SealedHeaderReceipt); err != nil {
		t.Fatalf("OpenHeader on an empty sealed header: %v", err)
	}
}

// TestDecryptBody_WrongNonceLengthDoesNotPanic pins the STRICT length check on
// the envelope nonce. env.Nonce is attacker-supplied base64 from the response,
// and chacha20poly1305.Open PANICS rather than erroring on a wrong-length
// nonce — so a `< NonceSize` in place of `!=` turns an over-long nonce into a
// process-killing panic on the payer's own proxy. Existing coverage only ever
// supplies a SHORT nonce, which the two comparisons treat identically.
func TestDecryptBody_WrongNonceLengthDoesNotPanic(t *testing.T) {
	var key [ResponseKeySize]byte
	for _, n := range []int{NonceSize - 1, NonceSize + 1, 2 * NonceSize} {
		env := ResponseEnvelope{
			Nonce:      base64.StdEncoding.EncodeToString(make([]byte, n)),
			Ciphertext: base64.StdEncoding.EncodeToString(make([]byte, 32)),
		}
		raw, err := json.Marshal(env)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := DecryptBody(raw, key, "TX", "TKT"); err == nil {
			t.Errorf("nonce length %d: want an error, got nil", n)
		}
	}
}

// TestResponseOpener_BindingIsNotTransposable: (txID, ticketID) are adjacent
// same-typed strings, so swapping them compiles. It must not verify.
func TestResponseOpener_BindingIsNotTransposable(t *testing.T) {
	sealer, _ := newSealerOpenerPair(t, "TX", "TKT")
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	// Re-seal under a known key so we can build a transposed opener over it.
	sealer, err = NewResponseSealer(id.Recipient(), "TX", "TKT")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := sealer.SealStreamFrame([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	transposed, err := NewResponseOpener(key, "TKT", "TX")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transposed.OpenNextFrame([]byte(frame)); err == nil {
		t.Fatal("a transposed (ticketID, txID) opener verified the frame")
	}

	correct, err := NewResponseOpener(key, "TX", "TKT")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := correct.OpenNextFrame([]byte(frame)); err != nil {
		t.Fatalf("correctly-bound opener failed: %v", err)
	}
}
