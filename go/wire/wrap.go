/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"filippo.io/age"
)

// WrapRequest generates a fresh ephemeral X25519 identity, age-encrypts body
// to nodeRecipient, and returns the marshaled RequestEnvelope plus the
// ephemeral identity. The caller (proxy) holds the identity in handler
// scope to decrypt the response, then discards it via ZeroEphemeralIdentity.
//
// ticketID is the ID of a Ticket previously obtained from the node's
// /v1/zs/reserve endpoint. It rides inside the sealed inner-request frame
// and is AAD-bound on every sealed response payload.
//
// admissionTag is the proof-of-possession HMAC computed via
// ComputeAdmissionTag (see admission.go). Pass the 32-byte value for any
// ticket-gated request; nil omits the header field, which the node refuses
// with 402 admission_tag_invalid — useful only to the ticket-less tests
// this variant exists for.
//
// TESTS ONLY — a freshly generated identity is by definition NOT the one the
// caller declared as proxy_recipient at reserve, and the node rejects a request
// whose reply_to_public_key differs (reply_to_mismatch). Any real ticket-gated
// flow must use WrapRequestWithIdentity with the reserve-time identity, which
// is also what lets one private key unwrap both the reserve's
// WrappedResponseKey and the response's X-Zs-Response-Key. This variant remains
// only for tests that wrap without a ticket.
func WrapRequest(body []byte, txID, ticketID string, admissionTag []byte, nodeRecipient age.Recipient) ([]byte, *age.X25519Identity, error) {
	ephemeral, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, nil, fmt.Errorf("generate ephemeral identity: %w", err)
	}
	out, err := WrapRequestWithIdentity(body, txID, ticketID, admissionTag, ephemeral, nodeRecipient)
	if err != nil {
		return nil, nil, err
	}
	return out, ephemeral, nil
}

// WrapRequestWithIdentity is like WrapRequest but uses a
// caller-supplied ephemeral identity. Use this when the identity was
// generated earlier in the flow — the proxy's reserve step, for
// instance, needs the identity to unwrap ReserveResponse.WrappedResponseKey,
// then hands it to the request-wrap step so the eventual response's
// X-Zs-Response-Key wraps to the same recipient.
//
// Everything the node needs — reply-to recipient, tx id, ticket id, admission
// tag — is framed with the body into the inner-request plaintext and sealed to
// nodeRecipient, so the marshaled envelope is a single "ciphertext" field.
func WrapRequestWithIdentity(body []byte, txID, ticketID string, admissionTag []byte, ephemeral *age.X25519Identity, nodeRecipient age.Recipient) ([]byte, error) {
	if ephemeral == nil {
		return nil, fmt.Errorf("wrap request: nil ephemeral identity")
	}

	header := innerRequestHeader{
		ReplyToPublicKey: ephemeral.Recipient().String(),
		AlgorandTxID:     txID,
		TicketID:         ticketID,
	}
	if len(admissionTag) > 0 {
		header.AdmissionTag = base64.StdEncoding.EncodeToString(admissionTag)
	}
	inner, err := encodeInnerRequest(header, body)
	if err != nil {
		return nil, err
	}

	ct, err := ageSeal(inner, nodeRecipient)
	if err != nil {
		return nil, fmt.Errorf("seal request: %w", err)
	}
	out, err := json.Marshal(RequestEnvelope{Ciphertext: base64.StdEncoding.EncodeToString(ct)})
	if err != nil {
		return nil, fmt.Errorf("marshal envelope: %w", err)
	}
	return out, nil
}

// UnwrapResponseKey decrypts the X-Zs-Response-Key header value with the
// per-request ephemeral identity and returns the 32-byte symmetric key used
// to AEAD-seal response payloads.
func UnwrapResponseKey(b64Wrapped string, identity age.Identity) ([ResponseKeySize]byte, error) {
	var key [ResponseKeySize]byte

	wrapped, err := base64.StdEncoding.DecodeString(b64Wrapped)
	if err != nil {
		return key, fmt.Errorf("decode wrapped key: %w", err)
	}

	raw, err := ageOpen(wrapped, identity)
	if err != nil {
		return key, fmt.Errorf("open wrapped key: %w", err)
	}
	if len(raw) != ResponseKeySize {
		return key, fmt.Errorf("unexpected response key length %d", len(raw))
	}
	copy(key[:], raw)
	return key, nil
}

// DecryptBody AEAD-opens a non-streaming ResponseEnvelope and returns the
// plaintext response body. txID must be the one the caller sealed into the
// request envelope and ticketID the ticket it was admitted under; both are
// bound into the AAD, so a node that sealed under different values fails the
// open. There is no cleartext echo of either on the response.
// A one-shot convenience over ResponseOpener.OpenBody. Prefer the opener when
// you will also read headers or frames for the same response — it names the
// binding once and builds one AEAD.
func DecryptBody(envelopeJSON []byte, responseKey [ResponseKeySize]byte, txID, ticketID string) ([]byte, error) {
	o, err := NewResponseOpener(responseKey, txID, ticketID)
	if err != nil {
		return nil, err
	}
	return o.OpenBody(envelopeJSON)
}

// OpenSealedHeader AEAD-opens one piece of sealed response metadata — the
// value of the X-Zs-Receipt / X-Zs-Settle-Group header, or the data: field of
// the `zs-settle-group` SSE frame — produced by ResponseSealer.SealHeader.
// name must be the SealedHeader* constant the node sealed under; it is bound
// into the AAD, so a receipt cannot be opened as a settle group.
// A one-shot convenience over ResponseOpener.OpenHeader.
func OpenSealedHeader(b64 string, responseKey [ResponseKeySize]byte, txID, ticketID, name string) ([]byte, error) {
	o, err := NewResponseOpener(responseKey, txID, ticketID)
	if err != nil {
		return nil, err
	}
	return o.OpenHeader(b64, name)
}

// DecryptSSEDataValue parses "base64(nonce || ciphertext)" from the data:
// field of an `event: zs` SSE frame and AEAD-opens it with responseKey.
// txID, ticketID, and frameIndex are bound into AAD; frameIndex must be
// the 0-based position of this encrypted frame within the stream.
// A one-shot convenience over ResponseOpener.OpenNextFrame for a caller that
// already tracks the index itself — chiefly tests, which open a captured
// stream out of order. A consumer reading frames in wire order should hold a
// ResponseOpener instead and let it own the counter: SPEC.md § 5.3's rule for
// which frames consume an index is easy to restate wrongly, and a
// hand-maintained counter has to be right at every branch of the read loop.
func DecryptSSEDataValue(b64 []byte, responseKey [ResponseKeySize]byte, txID, ticketID string, frameIndex uint64) ([]byte, error) {
	o, err := NewResponseOpener(responseKey, txID, ticketID)
	if err != nil {
		return nil, err
	}
	o.frameIndex = frameIndex
	return o.OpenNextFrame(b64)
}
