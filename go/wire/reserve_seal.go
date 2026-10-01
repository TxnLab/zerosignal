/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"filippo.io/age"
)

// SealedReserveContentType is the Content-Type for a confidentiality-only
// sealed POST /v1/zs/reserve request body (SPEC.md § 3a, § 3f). It is
// deliberately distinct from EncryptedContentType
// ("application/vnd.zs+json") so a node — and a byte-transparent relay —
// can tell a sealed reserve from a sealed inference envelope by content-type
// alone, without parsing the body.
//
// Reserve is sealed (not plaintext) at protocol 3.0: with single-hop relaying
// live, a plaintext reserve would expose the caller's payer_addr (a stable
// on-chain address) to the relay operator, who could then link client IP →
// payer_addr. Sealing the body to the *target* operator's recipient closes
// that link while the relay still forwards the opaque bytes.
const SealedReserveContentType = "application/vnd.zs-reserve+json"

// SealedReserveResponseContentType is the Content-Type for a sealed
// 200 POST /v1/zs/reserve *response* body — the whole ticket.ReserveResponse
// age-sealed to the caller's proxy_recipient (SPEC.md § 3a, § 3f).
//
// Sealing the response at protocol 8.0 closes the last direct payer read on
// the reserve leg: presigned_open_txn is a signed 2-tx group naming the payer
// as gtxn[0]'s sender and again as open()'s payerAddr ABI arg, so a relay
// forwarding a plaintext reserve response could decode the payer address
// outright — no chain lookup — and bind it to the client IP it already holds.
//
// Error responses (4xx/5xx) stay plaintext OpenAI-shaped JSON: they carry no
// ticket and no payer, and a caller that cannot parse them cannot report why
// its reserve failed.
const SealedReserveResponseContentType = "application/vnd.zs-reserve-response+json"

// SealedReserveEnvelope is the JSON body carrying an age-sealed
// ticket.ReserveRequest or ticket.ReserveResponse. Like RequestEnvelope since
// 8.0 it carries nothing but ciphertext; it stays a distinct type because the
// reserve leg has no ticket to bind and no inner-request frame — its plaintext
// is the bare marshaled request or response.
type SealedReserveEnvelope struct {
	Ciphertext string `json:"ciphertext"`
}

// SealReserveRequest age-encrypts a marshaled ticket.ReserveRequest to the
// target operator's long-lived recipient and returns the marshaled
// SealedReserveEnvelope. age is itself authenticated encryption to the
// recipient, so there is no admission tag or AAD here — the reserve carries
// no ticket to bind. No ephemeral identity is returned: the reply path is
// unchanged (the node wraps K_response to the proxy_recipient carried inside
// the inner plaintext). Mirrors the age pattern in WrapRequestWithIdentity.
func SealReserveRequest(body []byte, operatorRecipient age.Recipient) ([]byte, error) {
	if operatorRecipient == nil {
		return nil, errors.New("seal reserve request: nil operator recipient")
	}
	return sealReserveEnvelope(body, operatorRecipient)
}

// SealReserveResponse age-encrypts a marshaled ticket.ReserveResponse to the
// caller's proxy_recipient — the ephemeral X25519 recipient it declared inside
// the sealed reserve request, which a relay therefore never saw — and returns
// the marshaled SealedReserveEnvelope.
//
// The caller already holds this private key (it is the same identity that
// unwraps wrapped_response_key and, later, X-Zs-Response-Key), so opening the
// response costs it nothing. There is no admission ordering to preserve on a
// response, and non-privacy direct callers are unaffected: they seal to
// themselves and decrypt their own response.
func SealReserveResponse(body []byte, proxyRecipient age.Recipient) ([]byte, error) {
	if proxyRecipient == nil {
		return nil, errors.New("seal reserve response: nil proxy recipient")
	}
	return sealReserveEnvelope(body, proxyRecipient)
}

func sealReserveEnvelope(body []byte, recipient age.Recipient) ([]byte, error) {
	ct, err := ageSeal(body, recipient)
	if err != nil {
		return nil, err
	}
	out, err := json.Marshal(SealedReserveEnvelope{
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	})
	if err != nil {
		return nil, fmt.Errorf("marshal sealed reserve envelope: %w", err)
	}
	return out, nil
}

// OpenReserveRequest is the node-side inverse of SealReserveRequest: it
// parses a SealedReserveEnvelope, age-decrypts the ciphertext with the node's
// identities, and returns the inner plaintext (a marshaled
// ticket.ReserveRequest the caller then json.Unmarshals). It is the
// confidentiality-only analogue of DecryptRequest — no reply-to recipient,
// tx_id, or admission tag to resolve.
//
// nodeIdentities is variadic with the same semantics as DecryptRequest:
// age.Decrypt tries each identity in order (current ephemeral, then previous
// ephemeral during the overlap window, then the long-lived on-chain identity)
// and the first to open the header wins. The long-lived identity passed last
// is the durable fallback so a reserve sealed to the on-chain key still opens.
// At least one identity must be supplied.
func OpenReserveRequest(envelopeJSON []byte, nodeIdentities ...age.Identity) ([]byte, error) {
	if len(nodeIdentities) == 0 {
		return nil, errors.New("open reserve request: no node identities supplied")
	}
	return openReserveEnvelope(envelopeJSON, nodeIdentities...)
}

// OpenReserveResponse is the caller-side inverse of SealReserveResponse: it
// parses a SealedReserveEnvelope and age-decrypts it with the ephemeral
// identity whose recipient the caller sent as proxy_recipient, returning the
// marshaled ticket.ReserveResponse.
func OpenReserveResponse(envelopeJSON []byte, identity age.Identity) ([]byte, error) {
	if identity == nil {
		return nil, errors.New("open reserve response: nil identity")
	}
	return openReserveEnvelope(envelopeJSON, identity)
}

func openReserveEnvelope(envelopeJSON []byte, identities ...age.Identity) ([]byte, error) {
	var env SealedReserveEnvelope
	if err := json.Unmarshal(envelopeJSON, &env); err != nil {
		return nil, fmt.Errorf("parse sealed reserve envelope: %w", err)
	}
	if env.Ciphertext == "" {
		return nil, errors.New("sealed reserve envelope missing ciphertext")
	}
	ct, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decode ciphertext: %w", err)
	}
	body, err := ageOpen(ct, identities...)
	if err != nil {
		return nil, fmt.Errorf("open sealed reserve envelope: %w", err)
	}
	return body, nil
}
