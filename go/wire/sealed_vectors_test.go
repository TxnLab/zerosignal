/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire_test

// Cross-impl SEALED-FRAMING fixture. Generates / verifies
// proto/testdata/sealed_vectors.json.
//
// vectors.json already pins the AAD *bytes* for all five variants (body with
// and without a ticket, frame, and the two header names). What it does not pin
// is the FRAMING that carries them: base64(nonce || ciphertext) for stream
// frames and sealed headers, the {nonce, ciphertext} ResponseEnvelope JSON for
// a non-streaming body, and the age-wrapped K_response in X-Zs-Response-Key.
//
// Before this fixture existed, both implementations only ever opened ciphertext
// they had produced themselves — Go's seal_test.go round-trips through Go's own
// ResponseSealer, and proto/ts/test/wire.test.ts feeds every decrypt assertion
// from the TS ResponseSealer. A framing change that is self-consistent within
// one language therefore stayed green while diverging from the other. Swapping
// SealStreamFrame to emit ciphertext||nonce and DecryptSSEDataValue to read it
// back that way passes both suites in full.
//
// This file closes that hole. The artifacts here are sealed ONCE by the real
// ResponseSealer and committed; both languages then verify by OPENING them with
// their real openers and asserting the recovered plaintext. That chains to a
// full cross-language equivalence:
//
//	committed bytes ≡ Go opener ≡ Go sealer     (this file + seal_test.go)
//	committed bytes ≡ TS opener ≡ TS sealer     (sealed-vectors.test.ts + wire.test.ts)
//
// so any framing divergence on either side fails on that side.
//
// WHY A SEPARATE FILE FROM vectors.json: sealing draws a fresh nonce per call
// and age-wrapping is randomized, so these artifacts are not reproducible from
// their inputs. ticket/vectors_test.go asserts whole-file byte equality against
// regenerated output, which such values would break on every run. These are
// CAPTURED vectors, not derived ones: the check is "does it still open", not
// "does it still serialize identically".
//
// To regenerate after an intentional framing change:
//
//	cd proto/go && go test ./wire -run TestSealedVectors -update
//
// Regenerating produces different nonces and a different age wrapping every
// time; that churn is expected and carries no meaning. Do it only when the
// framing genuinely changed, and update proto/SPEC.md § 5 / § 6 in the same
// change.

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"filippo.io/age"

	"github.com/TxnLab/zerosignal/go/wire"
)

// Reuses the package-level -update flag registered by
// stream_terminal_vectors_test.go; a second flag.Bool("update", …) in the same
// test binary would panic with "flag redefined".

const sealedVectorsPath = "../../testdata/sealed_vectors.json"

// sealedVectorsIdentity is a THROWAWAY age identity, generated once via
// `age-keygen`, that exists only so this fixture can pin the age-wrapped
// K_response end to end: the file ships the secret so any implementation can
// unwrap the committed X-Zs-Response-Key value and check it recovers
// response_key_hex. It protects nothing and is not used anywhere outside this
// fixture. Never reuse it for anything real.
const sealedVectorsIdentity = "AGE-SECRET-KEY-1MVRZWHPVANGL5WD7GCJ0V9LUMCPNUMZM2UPPMKCLTZHWW3VNUF3QUTE4EV"

type sealedFrameVector struct {
	Index        uint64 `json:"index"`
	PlaintextHex string `json:"plaintext_hex"`
	// base64(nonce || ciphertext) — the data: value of an `event: zs` frame.
	DataB64 string `json:"data_b64"`
}

type sealedHeaderVector struct {
	// SealedHeaderReceipt / SealedHeaderSettleGroup — bound into the AAD, so a
	// receipt ciphertext cannot be opened as a settle group.
	Name         string `json:"name"`
	PlaintextHex string `json:"plaintext_hex"`
	// base64(nonce || ciphertext) — the X-Zs-Receipt / X-Zs-Settle-Group value.
	ValueB64 string `json:"value_b64"`
}

type sealedVectorsFile struct {
	Version int    `json:"version"`
	Comment string `json:"comment"`

	TxID     string `json:"tx_id"`
	TicketID string `json:"ticket_id"`

	// The symmetric key every artifact below is sealed under. Pinned via
	// NewResponseSealerWithKey so openers need no key exchange.
	ResponseKeyHex string `json:"response_key_hex"`

	// Age identity + the wrapped key it opens. Unwrapping WrappedKeyB64 under
	// AgeIdentity MUST recover exactly ResponseKeyHex — this pins the
	// X-Zs-Response-Key framing (base64 of an age file), which is otherwise
	// only ever produced and consumed by the same implementation.
	AgeIdentity   string `json:"age_identity"`
	AgeRecipient  string `json:"age_recipient"`
	WrappedKeyB64 string `json:"wrapped_key_b64"`

	// Non-streaming path: the marshaled ResponseEnvelope JSON, base64'd so the
	// fixture carries the exact bytes rather than a re-encoding of them.
	BodyPlaintextHex string `json:"body_plaintext_hex"`
	BodyEnvelopeJSON string `json:"body_envelope_json"`

	// Streaming path: consecutive frames from one sealer, so frame_index
	// advancement is pinned alongside the framing.
	Frames []sealedFrameVector `json:"frames"`

	// Sealed metadata. SealHeader deliberately does NOT advance the frame
	// counter, so these are sealed between frames 1 and 2 below to pin that.
	Headers []sealedHeaderVector `json:"headers"`
}

// buildSealedVectors seals a fresh set of artifacts. Only called under -update.
func buildSealedVectors(t *testing.T) *sealedVectorsFile {
	t.Helper()

	const (
		txID     = "TX-SEALED-001"
		ticketID = "TKT-SEALED-001"
	)

	id, err := age.ParseX25519Identity(sealedVectorsIdentity)
	if err != nil {
		t.Fatalf("parse fixture age identity: %v", err)
	}
	recipient := id.Recipient()

	// Distinct from vectors.json's all-zero commit key and its 0,1,2,… k, so a
	// key mix-up between fixtures cannot silently pass.
	var key [wire.ResponseKeySize]byte
	for i := range key {
		key[i] = byte(0xA0 + i)
	}

	sealer, err := wire.NewResponseSealerWithKey(recipient, txID, ticketID, key)
	if err != nil {
		t.Fatalf("new sealer: %v", err)
	}

	bodyPlaintext := []byte(`{"id":"sealed-vector","object":"chat.completion"}`)
	envelope, err := sealer.SealBody(bodyPlaintext)
	if err != nil {
		t.Fatalf("seal body: %v", err)
	}

	// A second sealer for the streaming artifacts: SealBody and
	// SealStreamFrame both start at frame index 0 relative to their own
	// sealer, and mixing them on one instance would leave the frame indices
	// below dependent on whether the body was sealed first.
	streamSealer, err := wire.NewResponseSealerWithKey(recipient, txID, ticketID, key)
	if err != nil {
		t.Fatalf("new stream sealer: %v", err)
	}

	framePlaintexts := [][]byte{
		[]byte(`data: {"choices":[{"delta":{"content":"sealed"}}]}`),
		[]byte(`data: {"choices":[{"delta":{"content":" vector"}}]}`),
		[]byte(`data: [DONE]`),
	}

	frames := make([]sealedFrameVector, 0, len(framePlaintexts))
	headers := make([]sealedHeaderVector, 0, 2)

	for i, pt := range framePlaintexts {
		// Seal the two headers after frame 1 so the committed frame_index of
		// frame 2 proves SealHeader did not advance the counter.
		if i == 2 {
			headerPlaintexts := []struct {
				name string
				pt   []byte
			}{
				{wire.SealedHeaderSettleGroup, []byte(`{"settle_group":"sealed-vector-group"}`)},
				{wire.SealedHeaderReceipt, []byte(`{"ticket_id":"TKT-SEALED-001","amount_charged":4500}`)},
			}
			for _, h := range headerPlaintexts {
				v, err := streamSealer.SealHeader(h.name, h.pt)
				if err != nil {
					t.Fatalf("seal header %s: %v", h.name, err)
				}
				headers = append(headers, sealedHeaderVector{
					Name:         h.name,
					PlaintextHex: hex.EncodeToString(h.pt),
					ValueB64:     v,
				})
			}
		}

		data, err := streamSealer.SealStreamFrame(pt)
		if err != nil {
			t.Fatalf("seal frame %d: %v", i, err)
		}
		frames = append(frames, sealedFrameVector{
			Index:        uint64(i),
			PlaintextHex: hex.EncodeToString(pt),
			DataB64:      data,
		})
	}

	return &sealedVectorsFile{
		Version: 1,
		Comment: "Cross-impl sealed-framing fixture. Captured (not derived): nonces and the " +
			"age wrapping are random, so these bytes are not reproducible from their inputs. " +
			"Every implementation verifies by OPENING each artifact and asserting the recovered " +
			"plaintext equals the committed *_plaintext_hex. Generated by " +
			"proto/go/wire/sealed_vectors_test.go; regenerate with " +
			"`cd proto/go && go test ./wire -run TestSealedVectors -update`.",
		TxID:             txID,
		TicketID:         ticketID,
		ResponseKeyHex:   hex.EncodeToString(key[:]),
		AgeIdentity:      sealedVectorsIdentity,
		AgeRecipient:     recipient.String(),
		WrappedKeyB64:    streamSealer.WrappedKeyHeader(),
		BodyPlaintextHex: hex.EncodeToString(bodyPlaintext),
		BodyEnvelopeJSON: string(envelope),
		Frames:           frames,
		Headers:          headers,
	}
}

// verifySealedVectors opens every committed artifact with the production
// openers. This is the whole point of the file: it asserts that the CURRENT
// code can still read bytes the sealer produced when the fixture was captured,
// which a self-consistent framing change would break.
func verifySealedVectors(t *testing.T, v *sealedVectorsFile) {
	t.Helper()

	keyBytes, err := hex.DecodeString(v.ResponseKeyHex)
	if err != nil {
		t.Fatalf("decode response_key_hex: %v", err)
	}
	if len(keyBytes) != wire.ResponseKeySize {
		t.Fatalf("response_key_hex is %d bytes, want %d", len(keyBytes), wire.ResponseKeySize)
	}
	var key [wire.ResponseKeySize]byte
	copy(key[:], keyBytes)

	t.Run("wrapped_response_key", func(t *testing.T) {
		id, err := age.ParseX25519Identity(v.AgeIdentity)
		if err != nil {
			t.Fatalf("parse age_identity: %v", err)
		}
		got, err := wire.UnwrapResponseKey(v.WrappedKeyB64, id)
		if err != nil {
			t.Fatalf("unwrap committed wrapped key: %v", err)
		}
		if !bytes.Equal(got[:], key[:]) {
			t.Fatalf("unwrapped key = %x, want %x", got, key)
		}
	})

	t.Run("body_envelope", func(t *testing.T) {
		want, err := hex.DecodeString(v.BodyPlaintextHex)
		if err != nil {
			t.Fatalf("decode body_plaintext_hex: %v", err)
		}
		got, err := wire.DecryptBody([]byte(v.BodyEnvelopeJSON), key, v.TxID, v.TicketID)
		if err != nil {
			t.Fatalf("open committed body envelope: %v", err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("body plaintext = %q, want %q", got, want)
		}
	})

	if len(v.Frames) == 0 {
		t.Fatal("fixture carries no frames")
	}
	for _, f := range v.Frames {
		t.Run("frame_"+hex.EncodeToString([]byte{byte(f.Index)}), func(t *testing.T) {
			want, err := hex.DecodeString(f.PlaintextHex)
			if err != nil {
				t.Fatalf("decode plaintext_hex: %v", err)
			}
			got, err := wire.DecryptSSEDataValue([]byte(f.DataB64), key, v.TxID, v.TicketID, f.Index)
			if err != nil {
				t.Fatalf("open committed frame %d: %v", f.Index, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("frame %d plaintext = %q, want %q", f.Index, got, want)
			}

			// The frame index is bound into the AAD, so the same bytes must NOT
			// open at a neighbouring index. Without this, a fixture whose
			// indices were all 0 would still pass above.
			if _, err := wire.DecryptSSEDataValue([]byte(f.DataB64), key, v.TxID, v.TicketID, f.Index+1); err == nil {
				t.Fatalf("frame %d opened at index %d — frame_index is not bound", f.Index, f.Index+1)
			}
		})
	}

	if len(v.Headers) == 0 {
		t.Fatal("fixture carries no sealed headers")
	}
	for _, h := range v.Headers {
		t.Run("header_"+h.Name, func(t *testing.T) {
			want, err := hex.DecodeString(h.PlaintextHex)
			if err != nil {
				t.Fatalf("decode plaintext_hex: %v", err)
			}
			got, err := wire.OpenSealedHeader(h.ValueB64, key, v.TxID, v.TicketID, h.Name)
			if err != nil {
				t.Fatalf("open committed header %s: %v", h.Name, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("header %s plaintext = %q, want %q", h.Name, got, want)
			}

			// The name is bound into the AAD — that is what stops a receipt
			// ciphertext being replayed as a settle group.
			other := wire.SealedHeaderReceipt
			if h.Name == wire.SealedHeaderReceipt {
				other = wire.SealedHeaderSettleGroup
			}
			if _, err := wire.OpenSealedHeader(h.ValueB64, key, v.TxID, v.TicketID, other); err == nil {
				t.Fatalf("header %s opened under name %q — the name is not bound", h.Name, other)
			}
		})
	}
}

func TestSealedVectors(t *testing.T) {
	if *updateStreamVectors {
		v := buildSealedVectors(t)
		// Verify before writing: never commit a fixture the openers can't read.
		verifySealedVectors(t, v)

		out, err := json.MarshalIndent(v, "", "    ")
		if err != nil {
			t.Fatalf("marshal sealed vectors: %v", err)
		}
		out = append(out, '\n')
		if err := os.WriteFile(sealedVectorsPath, out, 0o644); err != nil {
			t.Fatalf("write %s: %v", sealedVectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", sealedVectorsPath, len(out))
		return
	}

	raw, err := os.ReadFile(sealedVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v\n(run `cd proto/go && go test ./wire -run TestSealedVectors -update` to generate)", sealedVectorsPath, err)
	}
	var v sealedVectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse %s: %v", sealedVectorsPath, err)
	}
	verifySealedVectors(t, &v)
}
