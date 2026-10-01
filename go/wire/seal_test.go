/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestDecryptRequest_RoundTrip(t *testing.T) {
	node := newTestIdentity(t)
	plaintext := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)

	envJSON, ephemeral, err := WrapRequest(plaintext, "TXABC", "", nil, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptRequest(envJSON, node)
	if err != nil {
		t.Fatalf("DecryptRequest: %v", err)
	}
	if !bytes.Equal(got.Body, plaintext) {
		t.Errorf("body mismatch: got %q, want %q", got.Body, plaintext)
	}
	if got.AlgorandTxID != "TXABC" {
		t.Errorf("algorand_tx_id = %q, want TXABC", got.AlgorandTxID)
	}
	gotRecipient, ok := got.ReplyToRecipient.(*age.X25519Recipient)
	if !ok {
		t.Fatalf("ReplyToRecipient is %T, want *age.X25519Recipient", got.ReplyToRecipient)
	}
	if gotRecipient.String() != ephemeral.Recipient().String() {
		t.Errorf("reply-to recipient mismatch: got %s, want %s",
			gotRecipient, ephemeral.Recipient())
	}
}

func TestDecryptRequest_TamperedCiphertext(t *testing.T) {
	node := newTestIdentity(t)
	envJSON, _, err := WrapRequest([]byte("hi"), "TX", "", nil, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	var env RequestEnvelope
	if err := json.Unmarshal(envJSON, &env); err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(env.Ciphertext)
	ct[len(ct)-1] ^= 0xFF
	env.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(env)

	if _, err := DecryptRequest(tampered, node); err == nil {
		t.Fatal("want age decrypt error, got nil")
	}
}

func TestDecryptRequest_WrongIdentity(t *testing.T) {
	node := newTestIdentity(t)
	other := newTestIdentity(t)
	envJSON, _, err := WrapRequest([]byte("hi"), "TX", "", nil, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}

	if _, err := DecryptRequest(envJSON, other); err == nil {
		t.Fatal("want error with wrong identity, got nil")
	}
}

func TestDecryptRequest_BadJSON(t *testing.T) {
	node := newTestIdentity(t)
	_, err := DecryptRequest([]byte("{not json"), node)
	if err == nil || !strings.Contains(err.Error(), "parse request envelope") {
		t.Errorf("want parse error, got %v", err)
	}
}

func TestDecryptRequest_MissingCiphertext(t *testing.T) {
	node := newTestIdentity(t)
	bad, _ := json.Marshal(RequestEnvelope{})
	_, err := DecryptRequest(bad, node)
	if err == nil || !strings.Contains(err.Error(), "missing ciphertext") {
		t.Errorf("want missing-ciphertext error, got %v", err)
	}
}

// sealInner builds an envelope around an arbitrary inner plaintext, bypassing
// WrapRequestWithIdentity so a test can seal a malformed frame.
func sealInner(t *testing.T, inner []byte, nodeRecipient age.Recipient) []byte {
	t.Helper()
	ct, err := ageSeal(inner, nodeRecipient)
	if err != nil {
		t.Fatal(err)
	}
	out, err := json.Marshal(RequestEnvelope{Ciphertext: base64.StdEncoding.EncodeToString(ct)})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestDecryptRequest_MissingReplyTo(t *testing.T) {
	node := newTestIdentity(t)
	inner, err := encodeInnerRequest(innerRequestHeader{AlgorandTxID: "TX"}, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecryptRequest(sealInner(t, inner, node.Recipient()), node)
	if err == nil || !strings.Contains(err.Error(), "missing reply_to_public_key") {
		t.Errorf("want missing-reply-to error, got %v", err)
	}
}

// A pre-8.0 caller sealed the bare request body with no inner-request frame.
// It must fail at the framing check, not somewhere downstream in the provider.
func TestDecryptRequest_UnframedInnerRejected(t *testing.T) {
	node := newTestIdentity(t)
	_, err := DecryptRequest(sealInner(t, []byte(`{"model":"gpt-4"}`), node.Recipient()), node)
	if err == nil || !strings.Contains(err.Error(), "bad magic") {
		t.Errorf("want bad-magic error, got %v", err)
	}
}

func TestDecryptRequest_BadBase64(t *testing.T) {
	node := newTestIdentity(t)
	bad, _ := json.Marshal(RequestEnvelope{Ciphertext: "!!!not-base64!!!"})
	_, err := DecryptRequest(bad, node)
	if err == nil || !strings.Contains(err.Error(), "decode ciphertext") {
		t.Errorf("want decode error, got %v", err)
	}
}

func TestSealBody_RoundTrip(t *testing.T) {
	ephemeral := newTestIdentity(t)
	sealer, err := NewResponseSealer(ephemeral.Recipient(), "TX99", "")
	if err != nil {
		t.Fatalf("NewResponseSealer: %v", err)
	}

	plaintext := []byte(`{"id":"chatcmpl-abc","choices":[{"index":0}]}`)
	body, err := sealer.SealBody(plaintext)
	if err != nil {
		t.Fatalf("SealBody: %v", err)
	}

	// Verify via the proxy-side API.
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBody(body, key, "TX99", "")
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("body mismatch: got %q, want %q", got, plaintext)
	}
}

// The relay-metadata-minimization invariant: neither envelope carries a field
// a forwarding relay could read. Asserted on the marshaled JSON keys rather
// than the struct so adding a field to either type fails here.
func TestEnvelopesCarryNothingButCiphertext(t *testing.T) {
	node := newTestIdentity(t)
	reqJSON, ephemeral, err := WrapRequest([]byte("body"), "TX-SECRET", "TICKET-SECRET", make([]byte, AdmissionTagSize), node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := NewResponseSealer(ephemeral.Recipient(), "TX-SECRET", "TICKET-SECRET")
	if err != nil {
		t.Fatal(err)
	}
	respJSON, err := sealer.SealBody([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		json []byte
		want []string
	}{
		{"request", reqJSON, []string{"ciphertext"}},
		{"response", respJSON, []string{"ciphertext", "nonce"}},
	} {
		var fields map[string]any
		if err := json.Unmarshal(tc.json, &fields); err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(fields) != len(tc.want) {
			t.Errorf("%s envelope has fields %v, want exactly %v", tc.name, keysOf(fields), tc.want)
		}
		for _, k := range tc.want {
			if _, ok := fields[k]; !ok {
				t.Errorf("%s envelope missing %q", tc.name, k)
			}
		}
		// Belt and braces: no identifier appears anywhere in the bytes.
		for _, secret := range []string{"TX-SECRET", "TICKET-SECRET"} {
			if strings.Contains(string(tc.json), secret) {
				t.Errorf("%s envelope leaks %q", tc.name, secret)
			}
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func TestSealHeader_RoundTrip(t *testing.T) {
	ephemeral := newTestIdentity(t)
	key := randomKey(t)
	sealer, err := NewResponseSealerWithKey(ephemeral.Recipient(), "TX", "TKT", key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"ticket_id":"abc","amount_charged":42}`)

	b64, err := sealer.SealHeader(SealedHeaderReceipt, plaintext)
	if err != nil {
		t.Fatalf("SealHeader: %v", err)
	}
	if strings.Contains(b64, "ticket_id") {
		t.Fatal("sealed header is not ciphertext")
	}
	got, err := OpenSealedHeader(b64, key, "TX", "TKT", SealedHeaderReceipt)
	if err != nil {
		t.Fatalf("OpenSealedHeader: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("got %q, want %q", got, plaintext)
	}
}

// The name is in the AAD, so a receipt ciphertext cannot be presented as a
// settle group (nor as a body or a stream frame).
func TestSealHeader_NameBoundIntoAAD(t *testing.T) {
	ephemeral := newTestIdentity(t)
	key := randomKey(t)
	sealer, err := NewResponseSealerWithKey(ephemeral.Recipient(), "TX", "TKT", key)
	if err != nil {
		t.Fatal(err)
	}
	b64, err := sealer.SealHeader(SealedHeaderReceipt, []byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenSealedHeader(b64, key, "TX", "TKT", SealedHeaderSettleGroup); err == nil {
		t.Error("receipt opened as a settle group")
	}
	if _, err := DecryptSSEDataValue([]byte(b64), key, "TX", "TKT", 0); err == nil {
		t.Error("sealed header opened as a stream frame")
	}
}

// SealHeader must not consume a frame index — a stream emits sealed content
// frames and a sealed settle-group header in the same response.
func TestSealHeader_DoesNotAdvanceFrameIndex(t *testing.T) {
	ephemeral := newTestIdentity(t)
	key := randomKey(t)
	sealer, err := NewResponseSealerWithKey(ephemeral.Recipient(), "TX", "TKT", key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sealer.SealHeader(SealedHeaderSettleGroup, []byte("group")); err != nil {
		t.Fatal(err)
	}
	frame, err := sealer.SealStreamFrame([]byte("first"))
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSSEDataValue([]byte(frame), key, "TX", "TKT", 0)
	if err != nil {
		t.Fatalf("frame 0 did not open: %v", err)
	}
	if string(got) != "first" {
		t.Errorf("got %q", got)
	}
}

func TestSealBody_UniqueNoncesAcrossCalls(t *testing.T) {
	ephemeral := newTestIdentity(t)
	sealer, err := NewResponseSealer(ephemeral.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	a, err := sealer.SealBody([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}
	b, err := sealer.SealBody([]byte("x"))
	if err != nil {
		t.Fatal(err)
	}

	var envA, envB ResponseEnvelope
	_ = json.Unmarshal(a, &envA)
	_ = json.Unmarshal(b, &envB)
	if envA.Nonce == envB.Nonce {
		t.Error("two SealBody calls produced identical nonces")
	}
}

func TestNewResponseSealer_NilRecipient(t *testing.T) {
	if _, err := NewResponseSealer(nil, "TX", ""); err == nil {
		t.Fatal("want error with nil recipient")
	}
}

func TestSealStreamFrame_RoundTrip(t *testing.T) {
	ephemeral := newTestIdentity(t)
	sealer, err := NewResponseSealer(ephemeral.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	plaintext := []byte(`{"delta":{"content":"Hello"}}`)

	b64, err := sealer.SealStreamFrame(plaintext)
	if err != nil {
		t.Fatalf("SealStreamFrame: %v", err)
	}

	// Verify via the proxy-side API at the expected frame index (0).
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), ephemeral)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptSSEDataValue([]byte(b64), key, "TX", "", 0)
	if err != nil {
		t.Fatalf("DecryptSSEDataValue: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("frame mismatch: got %q, want %q", got, plaintext)
	}
}

func TestSealStreamFrame_FrameIndexAdvances(t *testing.T) {
	// Each sealed frame must authenticate only at its own index; calling
	// the sealer repeatedly must produce ciphertexts that open at 0, 1, 2…
	ephemeral := newTestIdentity(t)
	sealer, err := NewResponseSealer(ephemeral.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), ephemeral)
	if err != nil {
		t.Fatal(err)
	}

	for i := uint64(0); i < 5; i++ {
		b64, err := sealer.SealStreamFrame([]byte("payload"))
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		if _, err := DecryptSSEDataValue([]byte(b64), key, "TX", "", i); err != nil {
			t.Errorf("frame %d: expected open at index %d, got %v", i, i, err)
		}
	}
}

func TestSealStreamFrame_ManyFramesUniqueNonces(t *testing.T) {
	ephemeral := newTestIdentity(t)
	sealer, err := NewResponseSealer(ephemeral.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]struct{}, 1000)
	for i := range 1000 {
		b64, err := sealer.SealStreamFrame([]byte("x"))
		if err != nil {
			t.Fatalf("frame %d: %v", i, err)
		}
		raw, _ := base64.StdEncoding.DecodeString(b64)
		n := string(raw[:NonceSize])
		if _, dup := seen[n]; dup {
			t.Fatalf("nonce repeated within 1000 frames at i=%d", i)
		}
		seen[n] = struct{}{}
	}
}
