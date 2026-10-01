/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"
)

// EphemeralAdvertisement is the operator's signed advertisement of a
// short-lived age recipient, served in GET /v1/zs/details (SPEC.md § 3c) —
// the ONLY encryption recipient (mandatory forward secrecy; there is no
// long-lived on-chain anchor). Sealing parties verify it and seal to it, or
// refuse the operator — there is no fallback. Forward secrecy is by
// key-erasure: the node rotates the underlying X25519 identity in memory and
// never persists it, so a later compromise of the node's on-disk secrets
// cannot decrypt traffic that was sealed to a since-zeroed ephemeral key. See
// SPEC.md § 8 (forward secrecy).
//
// The advertisement is signed by the operator's on-chain Ed25519 *signing*
// key — the same key that signs Ticket / UsageReceipt — not by the X25519
// age identity, so the anchor for trust is the on-chain operator record. A
// verifier recovers the signing pubkey from the operator's SigningAddr via
// DecodeAlgorandAddress.
//
// The target binding — (operatorID, nodeID) — is deliberately NOT part of this
// struct: both are already top-level /v1/zs/details fields, and passing them
// to CanonicalBytes / Sign / Verify as parameters (rather than trusting them
// from the wire, or carrying them in a field a caller may forget to set) means
// a relay or substituting node cannot re-point a captured-and-resigned-looking
// block at a different operator — or at a different node of the SAME operator.
// The node_id binding matters even though each node is supposed to hold its
// own signing key: nothing enforces per-node key distinctness, so without it
// an operator that reuses one signing key across sibling nodes would let node
// A's advertisement validate as node B's (sealing traffic to a key node B
// cannot decrypt). The verifier always supplies the chain-resolved
// (operator_id, node_id) pair, so the signature only validates when the
// advertised recipient was signed for that exact node. Mirrors
// ReserveRequest.CanonicalBytes, whose binding is threaded the same way.
type EphemeralAdvertisement struct {
	AgePubkey string `json:"ephemeral_age_pubkey"` // age1… recipient
	Expiry    int64  `json:"ephemeral_expiry"`     // unix seconds — end of the validity window
	IssuedAt  int64  `json:"ephemeral_issued_at"`  // unix seconds — start of the window (key mint/rotation time); signed, so [IssuedAt, Expiry] is tamper-evident
	Sig       string `json:"ephemeral_sig"`        // base64(Ed25519 over EphemeralSigDigest)
}

// ephemeralSigningTag domain-separates EphemeralAdvertisement signatures
// from Ticket / UsageReceipt signatures and any other Ed25519 the system may
// introduce. The trailing NUL matches ticketSigningTag / receiptSigningTag —
// keeps the tag self-terminating in any concatenation.
//
// The tag has stayed at v1 through both canonical-layout changes (IssuedAt
// joining the signed bytes, then NodeID at the proto-6.0 major). It did not
// need to move: changing the layout already makes the old and new digests
// disjoint, so signatures across the cutover cannot cross-validate — the hard
// break was carried by wire.ProtoVersion, not by this string. SPEC.md says v1
// and so does this constant. If prose here ever claims a v2 or v3, the prose
// is what is wrong: editing the constant to match it would silently cut
// proxy and node over to different signatures.
const ephemeralSigningTag = "zs-ephemeral-v1\x00"

// DefaultEphemeralSkew is the clock-skew tolerance a verifier applies to the
// advertised expiry: a block is treated as live until now > Expiry + skew.
// 60s matches the node's rotation invariant (advertised_expiry + skew ≤
// key-drop-time) so a key is never accepted past the point the node can
// still decrypt envelopes sealed to it.
const DefaultEphemeralSkew = 60 * time.Second

// MaxEphemeralLifetime caps the signed validity window Expiry-IssuedAt and is
// a HARD check in Verify. The node's advertised TTL is 25m; 40m (≈1.5× advTTL)
// clears an honest current key with margin while rejecting a malicious node
// that advertises a long-lived "ephemeral" (e.g. expiry years out) so it can
// secretly retain the private half and defeat forward secrecy. This is the
// genuinely new guarantee IssuedAt buys: it bounds the blast radius of a
// key-retaining node regardless of honest in-memory zeroing. Re-derive if the
// node-side rotation timing (node/internal/server/ephemeral.go) is retuned.
const MaxEphemeralLifetime = 40 * time.Minute

// FreshnessTarget is the SOFT relay-staleness threshold on now-IssuedAt,
// consumed by Stale (NOT by Verify). A hard-valid block older than this that
// arrived via a relay means the relay is serving a staler key than the node
// should have — prefer a fresher path and downrank the relay, but still use
// the block (it's decryptable and forward-secret). ≈ rotationPeriod (20m) +
// skew (60s). Not a hard gate: an honest current key late in its rotation
// window legitimately ages up to advTTL, so this can only attribute relay
// behavior, never reject. See node-side timing in ephemeral.go.
const FreshnessTarget = 21 * time.Minute

// ErrEphemeralExpired is returned by Verify when the signature is valid but
// the advertisement is past Expiry + skew. It is a sentinel so callers can
// distinguish a stale-but-genuine block (fall back to the on-chain key
// silently) from a forged or substituted one (log the substitution attempt).
var ErrEphemeralExpired = errors.New("ephemeral advertisement expired")

// ErrEphemeralLifetimeTooLong is returned by Verify when the signature is
// valid but the signed window Expiry-IssuedAt exceeds MaxEphemeralLifetime —
// an authentic-but-over-long advertisement, i.e. a node trying to pin a
// long-lived key it could retain to defeat forward secrecy. Distinct from
// ErrEphemeralExpired (genuine-but-stale) so callers treat it as a policy
// rejection, not a silent staleness fallback.
var ErrEphemeralLifetimeTooLong = errors.New("ephemeral advertisement lifetime exceeds policy")

// CanonicalBytes returns the unambiguous byte sequence Ed25519 signs (and
// verifies). It follows the same encoding rules as Ticket.CanonicalBytes /
// UsageReceipt.CanonicalBytes: a domain tag, then length-prefixed strings
// and fixed-width big-endian numbers, independent of any JSON encoder so a
// non-Go reimplementation can reproduce the exact bytes.
//
// LOCKED layout (any change requires a vectors regeneration and the matching
// TS edit): ephemeralSigningTag ‖ u64(operatorID) ‖ u64(nodeID) ‖
// lenStr(AgePubkey) ‖ i64(Expiry) ‖ i64(IssuedAt). operatorID and nodeID lead
// even though neither is on the wire here — both are the caller-supplied
// target binding (nodeID immediately after operatorID, mirroring the ticket
// canonical order). AgePubkey is the age1… string, treated as opaque
// length-prefixed bytes so ticket keeps no dependency on the age package.
// IssuedAt is appended at the tail so the signed window [IssuedAt, Expiry] is
// tamper-evident. Sig is excluded (that's what we're computing).
func (a *EphemeralAdvertisement) CanonicalBytes(operatorID, nodeID uint64) []byte {
	b := make([]byte, 0, 128)
	b = append(b, ephemeralSigningTag...)
	b = appendU64(b, operatorID)
	b = appendU64(b, nodeID)
	b = appendLenStr(b, a.AgePubkey)
	b = appendI64(b, a.Expiry)
	b = appendI64(b, a.IssuedAt)
	return b
}

// EphemeralSigDigest returns sha256(CanonicalBytes(operatorID, nodeID)) — the
// 32-byte value both Sign and Verify feed to ed25519. CanonicalBytes already
// includes the "zs-ephemeral-v1\x00" domain tag so the digest is
// cross-protocol safe. Exposed (like TicketSigDigest / ReceiptSigDigest) so
// the signing payload stays single-source.
func EphemeralSigDigest(a *EphemeralAdvertisement, operatorID, nodeID uint64) [sha256.Size]byte {
	return sha256.Sum256(a.CanonicalBytes(operatorID, nodeID))
}

// Sign populates a.Sig with an Ed25519 signature over the 32-byte digest
// EphemeralSigDigest(a) = sha256(CanonicalBytes()). CanonicalBytes() already
// prepends the ephemeral-specific tag ("zs-ephemeral-v1\x00") so the
// digest binds that tag plus the operator id, node id, recipient, expiry, and
// issued-at — cross-protocol / replay reuse cannot produce a valid signature.
//
// The caller is responsible for setting a.AgePubkey, a.Expiry and a.IssuedAt
// before signing; the signature commits to those three plus the target
// (operatorID, nodeID), which are this node's OWN identity — the node it is
// advertising itself as. Passing them rather than reading them off the struct
// is what stops an unset binding from silently signing for (0, 0). The signing
// key is whatever signer holds for signingAddr (the operator's on-chain
// signing account, the same key that signs Ticket / UsageReceipt). Routing
// through BytesSigner lets the actual key live in a mnemonic-backed
// keystore, an HSM, or any other custody backend. Mirrors Ticket.Sign /
// ReserveRequest.Sign.
func (a *EphemeralAdvertisement) Sign(ctx context.Context, signer BytesSigner, signingAddr string, operatorID, nodeID uint64) error {
	if signer == nil {
		return errors.New("ephemeral sign: signer is nil")
	}
	digest := EphemeralSigDigest(a, operatorID, nodeID)
	sig, err := signer.SignBytes(ctx, signingAddr, digest[:])
	if err != nil {
		return fmt.Errorf("ephemeral sign: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("ephemeral sign: signer returned %d-byte signature, want %d", len(sig), ed25519.SignatureSize)
	}
	a.Sig = base64.StdEncoding.EncodeToString(sig)
	return nil
}

// Verify checks that a.Sig is a valid Ed25519 signature of
// EphemeralSigDigest(a) under pub for the given (operatorID, nodeID), and
// that the advertisement has not expired (now ≤ Expiry + skew).
//
// operatorID and nodeID are inputs, never trusted from the wire: they enter
// the recomputed digest directly and are never written back onto a, so the
// signature only validates when the recipient was signed for that exact
// (chain-resolved) node, and Verify leaves the object it verified unmodified.
// A relay or substituting node cannot re-point a block at a different operator
// — or a sibling node of the same operator (relevant when an operator reuses
// one signing key across its nodes) — without re-signing under that node's
// key.
//
// Verify performs the HARD (fail-closed) checks only; the SOFT relay-staleness
// signal is Stale, called separately after Verify returns nil. Order is
// deliberate: (1) signature, so a forged block fails generically (a caller can
// log it as a substitution attempt) and the timestamps below are authentic
// before any policy keys off them; (2) not-before + lifetime cap on the
// now-trusted window; (3) the expiry sentinel last so a genuine-but-stale block
// surfaces ErrEphemeralExpired and callers fall back silently rather than
// logging a stale-but-genuine advertisement as an attack. Pass
// DefaultEphemeralSkew for skew; now is injected so callers can test boundaries
// deterministically.
func (a *EphemeralAdvertisement) Verify(pub ed25519.PublicKey, now time.Time, operatorID, nodeID uint64, skew time.Duration) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid ed25519 public key length %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(a.Sig)
	if err != nil {
		return fmt.Errorf("decode ephemeral sig: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid ed25519 signature length %d", len(sig))
	}
	// The chain-resolved (operator_id, node_id) enters the digest here, so a
	// substituted id — cross-operator or sibling-node — can never validate.
	digest := EphemeralSigDigest(a, operatorID, nodeID)
	if !ed25519.Verify(pub, digest[:], sig) {
		return errors.New("ephemeral signature verification failed")
	}

	// Signed values are now authentic — enforce policy on the validity window.
	// Future-dated block: reject (a node cannot pre-issue a key it has not
	// minted yet).
	issuedAt := time.Unix(a.IssuedAt, 0)
	if issuedAt.After(now.Add(skew)) {
		return fmt.Errorf("ephemeral advertisement not yet valid: issued_at %d is in the future", a.IssuedAt)
	}
	// Lifetime cap: a long-lived "ephemeral" is a node trying to retain a key
	// to defeat forward secrecy. Bounds the blast radius regardless of honest
	// zeroing — the genuinely new guarantee IssuedAt buys.
	if lifetime := time.Unix(a.Expiry, 0).Sub(issuedAt); lifetime < 0 || lifetime > MaxEphemeralLifetime {
		return ErrEphemeralLifetimeTooLong
	}

	// Expiry last: signature is valid, so a stale block is genuine — surface
	// the sentinel so callers fall back silently.
	if now.After(time.Unix(a.Expiry, 0).Add(skew)) {
		return ErrEphemeralExpired
	}
	return nil
}

// Stale is the SOFT relay-attribution signal: true when the block's age
// (now - IssuedAt) exceeds FreshnessTarget. Call it ONLY after Verify returns
// nil (it trusts IssuedAt is authentic). A stale block fetched via a relay
// means the relay served an older key than the node should have — prefer a
// fresher path and downrank the relay — but the block is still usable
// (decryptable and forward-secret), so this never rejects, only attributes.
func (a *EphemeralAdvertisement) Stale(now time.Time) bool {
	return now.Sub(time.Unix(a.IssuedAt, 0)) > FreshnessTarget
}
