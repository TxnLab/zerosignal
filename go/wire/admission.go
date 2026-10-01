/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"crypto/hmac"
	"crypto/sha256"
)

// AdmissionTagDomain is the domain-separation prefix for the admission
// HMAC. Versioned ("v1") so a future tag formula can be rolled out
// without colliding with the current one. The trailing NUL keeps the
// tag self-terminating in any concatenation, matching the
// ticketSigningTag convention in ticket.go.
const AdmissionTagDomain = "zs-admission-v1\x00"

// AdmissionTagSize is the wire size of an admission tag (HMAC-SHA256
// output). Exposed so callers can size buffers and so the wire decoder
// can validate the post-base64-decode length without re-deriving from
// the hash function.
const AdmissionTagSize = sha256.Size // 32

// ComputeAdmissionTag returns HMAC-SHA256(K, domain || ticket_id ||
// NUL || tx_id || NUL || sha256(body)) — the proof-of-possession tag
// the proxy attaches to every encrypted request and the node verifies
// after peeking the ticket (before committing to Consume — a forged
// tag must not burn the ticket).
//
// Inputs:
//   - k: K_response, the 32-byte key the node generated at reserve
//     time and the proxy obtained by unwrapping
//     ReserveResponse.WrappedResponseKey.
//   - ticketID: the envelope's ticket_id as-is (base64 wire form).
//     Fed into HMAC as raw string bytes — no decode required, just
//     "byte-for-byte identical on both sides" matters for HMAC.
//   - txID: the envelope's algorand_tx_id as-is (base32 wire form).
//     Same raw-string rule.
//   - body: the plaintext request body bytes (the value that goes
//     into RequestEnvelope.Ciphertext BEFORE age-encryption). The
//     body is hashed inside the tag so a captured tag cannot be
//     replayed against a different body.
//
// NUL separators between ticket_id and tx_id prevent cross-field
// boundary confusion (the same concatenation-collision concern the
// existing aadProtocolTag/aadBodyDomain AAD layout addresses).
//
// Both sides MUST call this with identical inputs; the verification
// is a constant-time hmac.Equal in the node's verifyAdmissionTag.
//
// Why HMAC of K_response (not a separate admission key): K_response is
// already a per-ticket random secret known only to the legit proxy
// (delivered wrapped at reserve time) and the node (stored
// server-side). HMAC's domain separation primitive — the AdmissionTagDomain
// prefix — keeps this MAC distinct from any other use of K_response,
// so reusing the key is cryptographically sound and avoids doubling
// the per-ticket random state.
func ComputeAdmissionTag(k [ResponseKeySize]byte, ticketID, txID string, body []byte) []byte {
	bodyHash := sha256.Sum256(body)
	mac := hmac.New(sha256.New, k[:])
	_, _ = mac.Write([]byte(AdmissionTagDomain))
	_, _ = mac.Write([]byte(ticketID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write([]byte(txID))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(bodyHash[:])
	return mac.Sum(nil)
}
