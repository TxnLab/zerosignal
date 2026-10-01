/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"filippo.io/age"
)

func TestWrapRequest_RoundTrip(t *testing.T) {
	node := newTestIdentity(t)
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}]}`)

	out, ephemeral, err := WrapRequest(body, "TX123", "", nil, node.Recipient())
	if err != nil {
		t.Fatalf("WrapRequest: %v", err)
	}

	var env RequestEnvelope
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if env.Ciphertext == "" {
		t.Error("envelope missing ciphertext")
	}

	// Round-trip through DecryptRequest to verify the ciphertext is
	// recoverable by the node side, identifiers and all.
	dec, err := DecryptRequest(out, node)
	if err != nil {
		t.Fatalf("DecryptRequest: %v", err)
	}
	if !bytes.Equal(dec.Body, body) {
		t.Errorf("body mismatch: got %q, want %q", dec.Body, body)
	}
	if dec.AlgorandTxID != "TX123" {
		t.Errorf("txid = %q", dec.AlgorandTxID)
	}
	if dec.ReplyToRecipient.(*age.X25519Recipient).String() != ephemeral.Recipient().String() {
		t.Errorf("reply-to recipient mismatch")
	}
}

func TestWrapRequest_GeneratesFreshEphemeral(t *testing.T) {
	node := newTestIdentity(t)
	body := []byte("x")

	_, e1, err := WrapRequest(body, "TX", "", nil, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	_, e2, err := WrapRequest(body, "TX", "", nil, node.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if e1.Recipient().String() == e2.Recipient().String() {
		t.Error("two wraps produced the same ephemeral recipient")
	}
}

func TestWrapRequest_EmptyBody(t *testing.T) {
	node := newTestIdentity(t)
	out, _, err := WrapRequest(nil, "TX", "", nil, node.Recipient())
	if err != nil {
		t.Fatalf("WrapRequest nil body: %v", err)
	}

	dec, err := DecryptRequest(out, node)
	if err != nil {
		t.Fatal(err)
	}
	if len(dec.Body) != 0 {
		t.Errorf("decrypted empty body = %q, want len 0", dec.Body)
	}
}

func TestUnwrapResponseKey_RoundTrip(t *testing.T) {
	// Produce a wrapped-key header by running the node side: NewResponseSealer
	// wraps a fresh key to the ephemeral recipient; WrappedKeyHeader exposes
	// the base64 value that the proxy receives in X-Zs-Response-Key.
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}

	// UnwrapResponseKey just needs to succeed and return a 32-byte key.
	_, err = UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatalf("UnwrapResponseKey: %v", err)
	}
}

func TestUnwrapResponseKey_BadBase64(t *testing.T) {
	id := newTestIdentity(t)
	_, err := UnwrapResponseKey("!!not-b64!!", id)
	if err == nil || !strings.Contains(err.Error(), "decode wrapped key") {
		t.Errorf("want decode error, got %v", err)
	}
}

func TestUnwrapResponseKey_WrongIdentity(t *testing.T) {
	id := newTestIdentity(t)
	other := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}

	_, err = UnwrapResponseKey(sealer.WrappedKeyHeader(), other)
	if err == nil {
		t.Fatal("want decrypt error with wrong identity")
	}
}

func TestUnwrapResponseKey_WrongSize(t *testing.T) {
	id := newTestIdentity(t)

	// Hand-craft a wrapped blob that decrypts to fewer than 32 bytes so the
	// size-check path fires. Can't go through NewResponseSealer for this.
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, id.Recipient())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("only-16-bytes-!!")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())

	_, err = UnwrapResponseKey(b64, id)
	if err == nil || !strings.Contains(err.Error(), "unexpected response key length") {
		t.Errorf("want length error, got %v", err)
	}
}

func TestDecryptBody_RoundTrip(t *testing.T) {
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX42", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(`{"ok":true,"data":"hello"}`)
	env, err := sealer.SealBody(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptBody(env, key, "TX42", "")
	if err != nil {
		t.Fatalf("DecryptBody: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch")
	}
}

func TestDecryptBody_BadJSON(t *testing.T) {
	key := randomKey(t)
	_, err := DecryptBody([]byte("{bad"), key, "TX", "")
	if err == nil || !strings.Contains(err.Error(), "parse response envelope") {
		t.Errorf("want parse error, got %v", err)
	}
}

func TestDecryptBody_BadBase64Nonce(t *testing.T) {
	key := randomKey(t)
	bad, _ := json.Marshal(ResponseEnvelope{Nonce: "!!!", Ciphertext: base64.StdEncoding.EncodeToString([]byte("x"))})
	_, err := DecryptBody(bad, key, "TX", "")
	if err == nil || !strings.Contains(err.Error(), "decode nonce") {
		t.Errorf("want decode nonce error, got %v", err)
	}
}

func TestDecryptBody_BadBase64Ciphertext(t *testing.T) {
	key := randomKey(t)
	bad, _ := json.Marshal(ResponseEnvelope{Nonce: base64.StdEncoding.EncodeToString(make([]byte, NonceSize)), Ciphertext: "!!!"})
	_, err := DecryptBody(bad, key, "TX", "")
	if err == nil || !strings.Contains(err.Error(), "decode ciphertext") {
		t.Errorf("want decode ciphertext error, got %v", err)
	}
}

func TestDecryptBody_BadNonceLength(t *testing.T) {
	key := randomKey(t)
	bad, _ := json.Marshal(ResponseEnvelope{
		Nonce:      base64.StdEncoding.EncodeToString([]byte("short")),
		Ciphertext: base64.StdEncoding.EncodeToString([]byte("xxxx")),
	})
	_, err := DecryptBody(bad, key, "TX", "")
	if err == nil || !strings.Contains(err.Error(), "invalid nonce length") {
		t.Errorf("want nonce length error, got %v", err)
	}
}

func TestDecryptBody_Tampered(t *testing.T) {
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}
	env, err := sealer.SealBody([]byte("hi"))
	if err != nil {
		t.Fatal(err)
	}

	var parsed ResponseEnvelope
	if err := json.Unmarshal(env, &parsed); err != nil {
		t.Fatal(err)
	}
	ct, _ := base64.StdEncoding.DecodeString(parsed.Ciphertext)
	ct[0] ^= 0xFF
	parsed.Ciphertext = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(parsed)

	_, err = DecryptBody(tampered, key, "TX", "")
	if err == nil || !strings.Contains(err.Error(), "aead open") {
		t.Errorf("want aead open error, got %v", err)
	}
}

// The response carries no tx_id, so splice resistance rests entirely on the
// AAD: a response sealed under one request's txID must not open under
// another's. This is the relay splicing request A's response onto request B.
func TestDecryptBody_WrongTxIDBreaksAAD(t *testing.T) {
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX-SEALED", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}
	env, err := sealer.SealBody([]byte("hi"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptBody(env, key, "TX-DIFFERENT", "")
	if err == nil || !strings.Contains(err.Error(), "aead open") {
		t.Errorf("want aead open error from AAD mismatch, got %v", err)
	}
	if _, err := DecryptBody(env, key, "TX-SEALED", ""); err != nil {
		t.Errorf("correct txID must still open: %v", err)
	}
}

func TestDecryptSSEDataValue_RoundTrip(t *testing.T) {
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte(`{"delta":"hello"}`)
	b64, err := sealer.SealStreamFrame(plaintext)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DecryptSSEDataValue([]byte(b64), key, "TX", "", 0)
	if err != nil {
		t.Fatalf("DecryptSSEDataValue: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Errorf("plaintext mismatch: got %q", got)
	}
}

func TestDecryptSSEDataValue_TooShort(t *testing.T) {
	key := randomKey(t)
	tiny := base64.StdEncoding.EncodeToString([]byte("short"))
	_, err := DecryptSSEDataValue([]byte(tiny), key, "TX", "", 0)
	if err == nil || !strings.Contains(err.Error(), "sse frame too short") {
		t.Errorf("want too-short error, got %v", err)
	}
}

func TestDecryptSSEDataValue_BadBase64(t *testing.T) {
	key := randomKey(t)
	_, err := DecryptSSEDataValue([]byte("!!not b64!!"), key, "TX", "", 0)
	if err == nil || !strings.Contains(err.Error(), "decode sse frame") {
		t.Errorf("want decode error, got %v", err)
	}
}

func TestDecryptSSEDataValue_Tampered(t *testing.T) {
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}
	b64, err := sealer.SealStreamFrame([]byte("hi"))
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := base64.StdEncoding.DecodeString(b64)
	raw[NonceSize] ^= 0xFF // flip ciphertext byte
	tampered := base64.StdEncoding.EncodeToString(raw)

	_, err = DecryptSSEDataValue([]byte(tampered), key, "TX", "", 0)
	if err == nil || !strings.Contains(err.Error(), "aead open") {
		t.Errorf("want aead open error, got %v", err)
	}
}

func TestDecryptSSEDataValue_WrongFrameIndex(t *testing.T) {
	// A frame sealed as index 3 must not open as index 2 — reordering and
	// dropping must be detected via AAD. Discard the first three frames
	// from the sealer so we get one sealed at index 3.
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := sealer.SealStreamFrame([]byte("skip")); err != nil {
			t.Fatal(err)
		}
	}
	b64, err := sealer.SealStreamFrame([]byte("frame three"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptSSEDataValue([]byte(b64), key, "TX", "", 2)
	if err == nil || !strings.Contains(err.Error(), "aead open") {
		t.Errorf("want aead open error, got %v", err)
	}
}

func TestDecryptSSEDataValue_WrongTxID(t *testing.T) {
	id := newTestIdentity(t)
	sealer, err := NewResponseSealer(id.Recipient(), "TX-REAL", "")
	if err != nil {
		t.Fatal(err)
	}
	key, err := UnwrapResponseKey(sealer.WrappedKeyHeader(), id)
	if err != nil {
		t.Fatal(err)
	}
	b64, err := sealer.SealStreamFrame([]byte("payload"))
	if err != nil {
		t.Fatal(err)
	}

	_, err = DecryptSSEDataValue([]byte(b64), key, "TX-ATTACKER", "", 0)
	if err == nil || !strings.Contains(err.Error(), "aead open") {
		t.Errorf("want aead open error, got %v", err)
	}
}
