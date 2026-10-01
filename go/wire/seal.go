/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/age"
	"golang.org/x/crypto/chacha20poly1305"
)

// DecryptedRequest is the output of DecryptRequest.
//
// AdmissionTag is the raw 32-byte HMAC the caller attached to the
// inner-request header; nil when the header carried none. This type only
// decodes the wire bytes — verifying the tag against HMAC(K_response, ...)
// is the node's verifyAdmissionTag step, and a missing tag is refused there
// with 402 admission_tag_invalid, so nil never reaches a served request.
type DecryptedRequest struct {
	Body             []byte
	ReplyToRecipient age.Recipient
	AlgorandTxID     string
	TicketID         string
	AdmissionTag     []byte
}

// DecryptRequest parses a RequestEnvelope, age-decrypts the ciphertext with
// the node's identities, and decodes the inner-request frame inside it: the
// body plus the reply-to recipient, tx id, ticket id, and admission tag that
// were plaintext envelope fields before 8.0. The recipient is used by
// NewResponseSealer to wrap the response symmetric key.
//
// The age-decrypt is the node's forced-work floor either way — the admission
// tag commits to sha256(the plaintext body), so nothing could be admitted
// before this point. Reading the identifiers here rather than off the outer
// JSON costs no extra work and denies them to a relay.
//
// nodeIdentities is variadic: age.Decrypt tries each identity in order
// (current ephemeral, then previous ephemeral during the overlap window,
// then the long-lived on-chain identity as the durable fallback) and the
// first whose stanza opens the file header wins. Passing the long-lived
// identity last means a request sealed to the on-chain key still decrypts
// even when an ephemeral key was advertised — the basis for the
// opportunistic forward-secrecy fallback (SPEC.md § 4, § 8). At least one
// identity must be supplied.
func DecryptRequest(envelopeJSON []byte, nodeIdentities ...age.Identity) (*DecryptedRequest, error) {
	if len(nodeIdentities) == 0 {
		return nil, errors.New("decrypt request: no node identities supplied")
	}
	var env RequestEnvelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse request envelope: %w", err)
	}
	if env.Ciphertext == "" {
		return nil, errors.New("request envelope missing ciphertext")
	}

	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	inner, err := ageOpen(ct, nodeIdentities...)
	if err != nil {
		return nil, fmt.Errorf("open request: %w", err)
	}
	header, body, err := decodeInnerRequest(inner)
	if err != nil {
		return nil, err
	}
	if header.ReplyToPublicKey == "" {
		return nil, errors.New("inner request missing reply_to_public_key")
	}
	recipient, err := age.ParseX25519Recipient(header.ReplyToPublicKey)
	if err != nil {
		return nil, fmt.Errorf("parse reply_to_public_key: %w", err)
	}

	var admissionTag []byte
	if header.AdmissionTag != "" {
		admissionTag, err = base64.StdEncoding.DecodeString(header.AdmissionTag)
		if err != nil {
			return nil, fmt.Errorf("decode admission_tag: %w", err)
		}
		if len(admissionTag) != AdmissionTagSize {
			return nil, fmt.Errorf("admission_tag length %d, want %d", len(admissionTag), AdmissionTagSize)
		}
	}

	return &DecryptedRequest{
		Body:             body,
		ReplyToRecipient: recipient,
		AlgorandTxID:     header.AlgorandTxID,
		TicketID:         header.TicketID,
		AdmissionTag:     admissionTag,
	}, nil
}

// ResponseSealer seals the response payloads for a single request under a
// fresh per-response symmetric key. The key is generated in NewResponseSealer
// and age-wrapped to the proxy's ephemeral recipient; WrappedKeyHeader returns
// the base64 value to place in the X-Zs-Response-Key response header.
//
// Use SealBody once for non-streaming responses or SealStreamFrame repeatedly
// for streaming responses. Nonces are drawn fresh from crypto/rand per call.
// The sealer tracks the AAD frame index internally — callers MUST NOT emit
// plaintext frames via this type; plaintext frames pass through the SSE
// writer without advancing the counter (SPEC.md § 6).
type ResponseSealer struct {
	txID       string
	ticketID   string
	aead       cipher.AEAD
	wrapped    string // base64 of age-encrypted key; cached so callers can read it repeatedly
	frameIndex uint64
}

// NewResponseSealer generates a fresh 32-byte key, wraps it to replyTo, and
// returns a sealer ready to seal response payloads bound to (txID, ticketID).
// ticketID may be empty at this layer, but a prompt-carrying node never seals
// with an empty one — a missing ticket_id is refused at admission with
// 402 ticket_required (SPEC.md § 3a).
func NewResponseSealer(replyTo age.Recipient, txID, ticketID string) (*ResponseSealer, error) {
	var key [ResponseKeySize]byte
	if _, err := rand.Read(key[:]); err != nil {
		return nil, fmt.Errorf("generate response key: %w", err)
	}
	return NewResponseSealerWithKey(replyTo, txID, ticketID, key)
}

// NewResponseSealerWithKey is like NewResponseSealer but uses a caller-supplied
// symmetric key instead of generating one. Used by the ticket-gated admission
// path (SPEC.md § 3a): the node generates K at /v1/zs/reserve time, publishes
// sha256(K) in the ticket's commit_k field, stores K server-side, and then seals
// the eventual response with that exact K so the proxy can verify the operator
// used the pre-committed key.
func NewResponseSealerWithKey(replyTo age.Recipient, txID, ticketID string, key [ResponseKeySize]byte) (*ResponseSealer, error) {
	if replyTo == nil {
		return nil, errors.New("nil reply-to recipient")
	}
	aead, err := chacha20poly1305.New(key[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 init: %w", err)
	}

	wrapped, err := ageSeal(key[:], replyTo)
	if err != nil {
		return nil, fmt.Errorf("wrap response key: %w", err)
	}

	return &ResponseSealer{
		txID:     txID,
		ticketID: ticketID,
		aead:     aead,
		wrapped:  base64.StdEncoding.EncodeToString(wrapped),
	}, nil
}

// WrappedKeyHeader returns the value to place in the X-Zs-Response-Key
// header: base64 of the age-encrypted 32-byte symmetric key.
func (s *ResponseSealer) WrappedKeyHeader() string { return s.wrapped }

// TxID returns the algorand_tx_id this sealer binds into AAD.
func (s *ResponseSealer) TxID() string { return s.txID }

// TicketID returns the ticket_id this sealer binds into AAD.
func (s *ResponseSealer) TicketID() string { return s.ticketID }

// SealBody AEAD-seals plaintext with a fresh nonce bound to
// BuildBodyAAD(txID, ticketID) and returns the marshaled ResponseEnvelope.
func (s *ResponseSealer) SealBody(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	ct := s.aead.Seal(nil, nonce, plaintext, BuildBodyAAD(s.txID, s.ticketID))
	env := ResponseEnvelope{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	out, err := json.Marshal(env)
	if err != nil {
		return nil, fmt.Errorf("marshal response envelope: %w", err)
	}
	return out, nil
}

// SealHeader AEAD-seals one piece of post-response metadata under the name'd
// header AAD and returns the base64(nonce || ciphertext) value for the
// X-Zs-Receipt / X-Zs-Settle-Group response header — or, on a stream, the
// data: field of the `zs-settle-group` SSE frame, which exists because the real
// response headers were written before the receipt was computable.
//
// Unlike SealStreamFrame this does not advance the frame counter: header
// metadata is emitted at most once per name, the name in the AAD already
// separates the two from each other and from body/frame payloads, and the
// `zs-settle-group` frame precedes `zs-receipt`, which must land on the index
// the content frames left off at.
func (s *ResponseSealer) SealHeader(name string, plaintext []byte) (string, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := s.aead.Seal(nil, nonce, plaintext, BuildHeaderAAD(s.txID, s.ticketID, name))
	raw := make([]byte, 0, len(nonce)+len(ct))
	raw = append(raw, nonce...)
	raw = append(raw, ct...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// SealStreamFrame AEAD-seals a single SSE frame payload under the sealer's
// current frame index and returns the base64(nonce || ciphertext) value
// that belongs in the `data:` line of an `event: zs` SSE frame.
// The internal counter is incremented after a successful seal.
func (s *ResponseSealer) SealStreamFrame(plaintext []byte) (string, error) {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	ct := s.aead.Seal(nil, nonce, plaintext, BuildFrameAAD(s.txID, s.ticketID, s.frameIndex))
	s.frameIndex++
	raw := make([]byte, 0, len(nonce)+len(ct))
	raw = append(raw, nonce...)
	raw = append(raw, ct...)
	return base64.StdEncoding.EncodeToString(raw), nil
}
