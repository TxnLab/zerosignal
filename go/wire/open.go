/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// ResponseOpener is the read half of ResponseSealer: it opens the response
// payloads for a single request under the per-response symmetric key the node
// wrapped to the caller's ephemeral recipient.
//
// It exists so SPEC.md § 5.3's frame-counter rule is a property of WHICH
// METHOD YOU CALL, exactly as it is on the seal side — OpenHeader does not
// advance, OpenNextFrame does. As three free functions each re-supplied the
// index positionally, every consumer re-implemented the rule by hand and the
// two reference consumers arrived at structurally different answers.
//
// It also names the binding. (responseKey, txID, ticketID) is a triple with
// two adjacent same-typed strings, so transposing txID and ticketID compiles
// and silently produces a different AAD; here they are supplied once, at
// construction.
//
// One AEAD is built per response rather than per frame, which matters on a
// streaming hot path.
//
// NOT safe for concurrent use: OpenNextFrame mutates the counter, and frames
// have to be opened in wire order anyway.
type ResponseOpener struct {
	txID       string
	ticketID   string
	aead       cipher.AEAD
	frameIndex uint64
}

// NewResponseOpener returns an opener bound to (txID, ticketID) — which MUST
// be the values the caller sealed into the request envelope, since both are
// bound into every AAD and a node that sealed under different ones fails the
// open. responseKey comes from UnwrapResponseKey over the X-Zs-Response-Key
// header.
func NewResponseOpener(responseKey [ResponseKeySize]byte, txID, ticketID string) (*ResponseOpener, error) {
	aead, err := chacha20poly1305.New(responseKey[:])
	if err != nil {
		return nil, fmt.Errorf("chacha20poly1305 init: %w", err)
	}
	return &ResponseOpener{txID: txID, ticketID: ticketID, aead: aead}, nil
}

// TxID returns the algorand_tx_id this opener binds into AAD.
func (o *ResponseOpener) TxID() string { return o.txID }

// TicketID returns the ticket_id this opener binds into AAD.
func (o *ResponseOpener) TicketID() string { return o.ticketID }

// FrameIndex returns the index the NEXT OpenNextFrame call will use — i.e. how
// many encrypted frames have been opened successfully so far.
func (o *ResponseOpener) FrameIndex() uint64 { return o.frameIndex }

// OpenBody opens a non-streaming ResponseEnvelope and returns the plaintext
// response body. Does not touch the frame counter — a non-streaming response
// carries no frames.
func (o *ResponseOpener) OpenBody(envelopeJSON []byte) ([]byte, error) {
	var env ResponseEnvelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse response envelope: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	if len(nonce) != NonceSize {
		return nil, fmt.Errorf("invalid nonce length %d", len(nonce))
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	pt, err := o.aead.Open(nil, nonce, ct, BuildBodyAAD(o.txID, o.ticketID))
	if err != nil {
		return nil, fmt.Errorf("aead open: %w", err)
	}
	return pt, nil
}

// OpenHeader opens one piece of sealed response metadata — the value of the
// X-Zs-Receipt / X-Zs-Settle-Group header, or the data: field of the
// `zs-settle-group` SSE frame. name must be the SealedHeader* constant the
// node sealed under; it is bound into the AAD, so a receipt cannot be opened
// as a settle group.
//
// Does NOT advance the frame counter, mirroring SealHeader. That is the whole
// reason this is a distinct method: a settle-group frame arrives mid-stream
// between content frames, and consuming a frame index for it would push the
// following receipt frame off by one.
func (o *ResponseOpener) OpenHeader(b64 string, name string) ([]byte, error) {
	pt, err := o.openNoncePrefixed([]byte(b64), BuildHeaderAAD(o.txID, o.ticketID, name), "sealed "+name)
	if err != nil {
		return nil, err
	}
	return pt, nil
}

// OpenNextFrame opens the next encrypted `event: zs` SSE frame — the data:
// field, "base64(nonce || ciphertext)" — at the current frame index, and
// advances the counter ON SUCCESS ONLY.
//
// Success-only is the pinned rule (SPEC.md § 5.3). A failed open means these
// bytes were not a frame this key and index produced, so charging a slot for
// them would desynchronize every subsequent frame from the sealer, turning one
// bad frame into a stream of them. It also matches SealStreamFrame, which
// advances only after a successful seal.
//
// Plaintext frames MUST NOT be routed through here — they pass through the SSE
// reader without advancing the counter (SPEC.md § 6).
func (o *ResponseOpener) OpenNextFrame(b64 []byte) ([]byte, error) {
	pt, err := o.openNoncePrefixed(b64, BuildFrameAAD(o.txID, o.ticketID, o.frameIndex), "sse frame")
	if err != nil {
		return nil, err
	}
	o.frameIndex++
	return pt, nil
}

// openNoncePrefixed decodes "base64(nonce || ciphertext)" and AEAD-opens it
// under aad. what names the payload in error text. This is the one routine
// behind both OpenHeader and OpenNextFrame — they differ only in the AAD
// builder and in whether the counter moves afterwards.
func (o *ResponseOpener) openNoncePrefixed(b64 []byte, aad []byte, what string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", what, err)
	}
	if len(raw) < NonceSize+chacha20poly1305.Overhead {
		return nil, fmt.Errorf("%s too short (%d bytes)", what, len(raw))
	}
	pt, err := o.aead.Open(nil, raw[:NonceSize], raw[NonceSize:], aad)
	if err != nil {
		return nil, fmt.Errorf("aead open %s: %w", what, err)
	}
	return pt, nil
}
