/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// EphemeralAdvertisement — the operator's signed advertisement of a short-lived
// age recipient, served in GET /v1/zs/details (SPEC.md § 3c) — the ONLY
// encryption recipient (mandatory forward secrecy; there is no long-lived
// on-chain anchor). Mirrors proto/go/ticket/ephemeral.go byte-for-byte.
//
// Sealing parties verify it and seal to it, or refuse the operator — there is no
// fallback. Forward secrecy is by key-erasure: the node rotates the underlying
// X25519 identity in memory and never persists it, so a later compromise of the
// node's on-disk secrets cannot decrypt traffic that was sealed to a
// since-zeroed ephemeral key. See SPEC.md § 8 (forward secrecy).
//
// The advertisement is signed by the operator's on-chain Ed25519 *signing*
// key — the same key that signs Ticket / UsageReceipt — not by the X25519
// age identity, so the anchor for trust is the on-chain operator record. A
// verifier recovers the signing pubkey from the operator's SigningAddr via
// decodeAlgorandAddress.
//
// operatorId and nodeId are deliberately NOT serialized in this block: both
// are already top-level /v1/zs/details fields, and binding them at
// sign/verify time (rather than trusting them from the wire) means a relay or
// substituting node cannot re-point a captured block at a different operator —
// or at a different node of the SAME operator (relevant when an operator
// reuses one signing key across sibling nodes). The verifier always supplies
// the chain-resolved (operatorId, nodeId) pair (leading arguments, mirroring
// Go's json:"-" fields + explicit Sign/Verify args), so the signature only
// validates when the advertised recipient was signed for that exact node.

import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'

import { ed25519 } from '../util/ed25519.js'
import { CanonicalWriter } from '../util/canonical.js'
import type { BytesSigner } from './signing.js'

export interface EphemeralAdvertisement {
    // age1… recipient.
    ephemeral_age_pubkey: string
    // unix seconds — end of the validity window.
    ephemeral_expiry: number
    // unix seconds — start of the window (key mint/rotation time); signed, so
    // [issued_at, expiry] is tamper-evident. Required to recompute the
    // canonical bytes.
    ephemeral_issued_at: number
    // base64(Ed25519 signature over ephemeralSigDigest). Filled by
    // signEphemeral; verifyEphemeral reads it.
    ephemeral_sig?: string
}

// EPHEMERAL_SIGNING_TAG domain-separates EphemeralAdvertisement signatures
// from Ticket / UsageReceipt signatures and any other Ed25519 the system may
// introduce. The trailing NUL matches TICKET_SIGNING_TAG / RECEIPT_SIGNING_TAG —
// keeps the tag self-terminating in any concatenation.
//
// The tag has stayed at v1 through both canonical-layout changes
// (ephemeral_issued_at joining the signed bytes, then nodeId at the proto-6.0
// major). It did not need to move: changing the layout already makes the old
// and new digests disjoint, so signatures across the cutover cannot
// cross-validate — the hard break was carried by PROTO_VERSION, not by this
// string. SPEC.md says v1 and so does this constant. If prose here ever claims
// a v2 or v3, the prose is what is wrong: editing the constant to match it
// would silently cut client and node over to different signatures. Mirrors
// proto/go/ticket/ephemeral.go ephemeralSigningTag.
export const EPHEMERAL_SIGNING_TAG = 'zs-ephemeral-v1\x00'

// DEFAULT_EPHEMERAL_SKEW_SEC is the clock-skew tolerance (seconds) a verifier
// applies to the advertised expiry: a block is treated as live until
// now > ephemeral_expiry + skew. 60s matches the node's rotation invariant
// (advertised_expiry + skew ≤ key-drop-time) so a key is never accepted past
// the point the node can still decrypt envelopes sealed to it.
export const DEFAULT_EPHEMERAL_SKEW_SEC = 60

// MAX_EPHEMERAL_LIFETIME_SEC caps the signed window ephemeral_expiry -
// ephemeral_issued_at and is a HARD check in verifyEphemeral. The node's
// advertised TTL is 25m; 40m (≈1.5× advTTL) clears an honest current key with
// margin while rejecting a node that advertises a long-lived "ephemeral" so it
// can secretly retain the private half and defeat forward secrecy. Mirrors
// proto/go/ticket/ephemeral.go MaxEphemeralLifetime.
export const MAX_EPHEMERAL_LIFETIME_SEC = 40 * 60

// FRESHNESS_TARGET_SEC is the SOFT relay-staleness threshold on
// now - ephemeral_issued_at, consumed by ephemeralStale (NOT by
// verifyEphemeral). ≈ rotationPeriod (20m) + skew (60s). Mirrors
// proto/go/ticket/ephemeral.go FreshnessTarget.
export const FRESHNESS_TARGET_SEC = 21 * 60

// EphemeralExpiredError is thrown by verifyEphemeral when the signature is
// valid but the advertisement is past ephemeral_expiry + skew. It is a
// distinguishable class so callers can tell a stale-but-genuine block (fall
// back to the on-chain key silently) from a forged or substituted one (log
// the substitution attempt).
export class EphemeralExpiredError extends Error {
    constructor(message = 'ephemeral advertisement expired') {
        super(message)
        this.name = 'EphemeralExpiredError'
    }
}

// EphemeralLifetimeError is thrown by verifyEphemeral when the signature is
// valid but the signed window exceeds MAX_EPHEMERAL_LIFETIME_SEC — an
// authentic-but-over-long advertisement (a node trying to pin a long-lived key
// it could retain to defeat forward secrecy). Distinct from
// EphemeralExpiredError so callers treat it as a policy rejection, not a silent
// staleness fallback. Mirrors Go's ErrEphemeralLifetimeTooLong.
export class EphemeralLifetimeError extends Error {
    constructor(message = 'ephemeral advertisement lifetime exceeds policy') {
        super(message)
        this.name = 'EphemeralLifetimeError'
    }
}

// ephemeralCanonicalBytes returns the unambiguous byte sequence Ed25519 signs
// (and verifies). It follows the same encoding rules as ticketCanonicalBytes /
// receiptCanonicalBytes: a domain tag, then length-prefixed strings and
// fixed-width big-endian numbers, independent of any JSON encoder so a non-TS
// reimplementation can reproduce the exact bytes.
//
// LOCKED layout (any change requires a vectors regeneration and the matching
// Go edit): EPHEMERAL_SIGNING_TAG ‖ u64(operatorId) ‖ u64(nodeId) ‖
// lenStr(ephemeral_age_pubkey) ‖ i64(ephemeral_expiry) ‖ i64(ephemeral_issued_at).
// operatorId and nodeId lead even though neither is on the wire here — both
// are bound at sign/verify time (nodeId immediately after operatorId,
// mirroring the ticket canonical order). ephemeral_age_pubkey is the age1…
// string, treated as opaque length-prefixed bytes. ephemeral_issued_at is
// appended at the tail so the signed window [issued_at, expiry] is
// tamper-evident. ephemeral_sig is excluded (that's what we're computing).
// Matches proto/go/ticket/ephemeral.go::EphemeralAdvertisement.CanonicalBytes
// byte-for-byte.
export function ephemeralCanonicalBytes(
    operatorId: number | bigint,
    nodeId: number | bigint,
    a: EphemeralAdvertisement,
): Uint8Array {
    return new CanonicalWriter()
        .str(EPHEMERAL_SIGNING_TAG)
        .u64(operatorId)
        .u64(nodeId)
        .lenStr(a.ephemeral_age_pubkey)
        .i64(a.ephemeral_expiry)
        .i64(a.ephemeral_issued_at)
        .finish()
}

// ephemeralSigDigest returns sha256(ephemeralCanonicalBytes(operatorId,
// nodeId, a)) — the 32-byte value both signEphemeral and verifyEphemeral feed
// to ed25519. ephemeralCanonicalBytes already includes the
// "zs-ephemeral-v1\x00" domain tag so the digest is cross-protocol safe.
export function ephemeralSigDigest(
    operatorId: number | bigint,
    nodeId: number | bigint,
    a: EphemeralAdvertisement,
): Uint8Array {
    return sha256(ephemeralCanonicalBytes(operatorId, nodeId, a))
}

// signEphemeral populates a.ephemeral_sig with an Ed25519 signature over the
// 32-byte digest ephemeralSigDigest(operatorId, a). The digest binds the
// ephemeral-specific tag plus the operator id, recipient, and expiry —
// cross-protocol / replay reuse cannot produce a valid signature.
//
// The caller is responsible for setting a.ephemeral_age_pubkey,
// a.ephemeral_expiry, and a.ephemeral_issued_at (and supplying operatorId +
// nodeId) before signing; the signature commits to all five. The signing key
// is whatever signer holds for signingAddr (the node's on-chain signing
// account, the same key that signs Ticket / UsageReceipt). Mirrors signTicket.
export async function signEphemeral(
    operatorId: number | bigint,
    nodeId: number | bigint,
    a: EphemeralAdvertisement,
    signer: BytesSigner,
    signingAddr: string,
): Promise<void> {
    if (!signer) throw new Error('ephemeral sign: signer is nil')
    const digest = ephemeralSigDigest(operatorId, nodeId, a)
    const sig = await signer.signBytes(signingAddr, digest)
    if (sig.length !== 64) {
        throw new Error(`ephemeral sign: signer returned ${sig.length}-byte signature, want 64`)
    }
    a.ephemeral_sig = base64.encode(sig)
}

// verifyEphemeral checks that a.ephemeral_sig is a valid Ed25519 signature of
// ephemeralSigDigest(operatorId, nodeId, a) under pub for the given
// (operatorId, nodeId), and that the advertisement has not expired
// (now ≤ ephemeral_expiry + skew).
//
// operatorId and nodeId are inputs, never trusted from the wire: both are
// bound into the digest, so the signature only validates when the recipient
// was signed for that exact (chain-resolved) node. A relay or substituting
// node cannot re-point a block at a different operator — or a sibling node of
// the same operator (relevant when an operator reuses one signing key across
// its nodes) — without re-signing under that node's key.
//
// verifyEphemeral performs the HARD (fail-closed) checks only; the SOFT
// relay-staleness signal is ephemeralStale, called separately after this
// returns. Order is deliberate: (1) signature, so a forged block throws a
// generic verification Error (a caller can log it as a substitution attempt)
// and the timestamps below are authentic before any policy keys off them;
// (2) not-before + lifetime cap on the now-trusted window; (3) the expiry
// sentinel last so a genuine-but-stale block throws EphemeralExpiredError and
// callers fall back silently rather than logging a stale-but-genuine
// advertisement as an attack. Pass DEFAULT_EPHEMERAL_SKEW_SEC for skewSec;
// nowUnixSec is injected so callers can test boundaries deterministically.
export function verifyEphemeral(
    operatorId: number | bigint,
    nodeId: number | bigint,
    a: EphemeralAdvertisement,
    pub: Uint8Array,
    nowUnixSec: number,
    skewSec: number,
): void {
    if (pub.length !== 32) {
        throw new Error(`invalid ed25519 public key length ${pub.length}`)
    }
    if (!a.ephemeral_sig) throw new Error('ephemeral signature missing')
    let sig: Uint8Array
    try {
        sig = base64.decode(a.ephemeral_sig)
    } catch (err) {
        throw new Error(`decode ephemeral sig: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (sig.length !== 64) {
        throw new Error(`invalid ed25519 signature length ${sig.length}`)
    }
    const digest = ephemeralSigDigest(operatorId, nodeId, a)
    if (!ed25519.verify(sig, digest, pub)) {
        throw new Error('ephemeral signature verification failed')
    }

    // Signed values are now authentic — enforce policy on the validity window.
    // Future-dated block: reject (a node cannot pre-issue a key it has not
    // minted yet).
    if (a.ephemeral_issued_at > nowUnixSec + skewSec) {
        throw new Error(
            `ephemeral advertisement not yet valid: issued_at ${a.ephemeral_issued_at} is in the future`,
        )
    }
    // Lifetime cap: a long-lived "ephemeral" is a node trying to retain a key
    // to defeat forward secrecy.
    const lifetime = a.ephemeral_expiry - a.ephemeral_issued_at
    if (lifetime < 0 || lifetime > MAX_EPHEMERAL_LIFETIME_SEC) {
        throw new EphemeralLifetimeError()
    }

    // Expiry last: signature is valid, so a stale block is genuine — throw the
    // sentinel so callers fall back silently.
    if (nowUnixSec > a.ephemeral_expiry + skewSec) {
        throw new EphemeralExpiredError()
    }
}

// ephemeralStale is the SOFT relay-attribution signal: true when the block's
// age (nowUnixSec - ephemeral_issued_at) exceeds FRESHNESS_TARGET_SEC. Call it
// ONLY after verifyEphemeral succeeds (it trusts ephemeral_issued_at is
// authentic). A stale block fetched via a relay means the relay served an older
// key than the node should have — prefer a fresher path and downrank the relay
// — but the block is still usable, so this never rejects, only attributes.
// Mirrors proto/go/ticket/ephemeral.go::EphemeralAdvertisement.Stale.
export function ephemeralStale(a: EphemeralAdvertisement, nowUnixSec: number): boolean {
    return nowUnixSec - a.ephemeral_issued_at > FRESHNESS_TARGET_SEC
}
