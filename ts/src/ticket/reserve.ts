/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Reserve request/response shapes. Mirrors proto/go/ticket/reserve.go.
//
// Both bodies of a successful reserve are age-sealed and the shapes below are
// the inner plaintexts. The request is sealed to the target under
// SEALED_RESERVE_CONTENT_TYPE (protocol 3.0) so a single-hop relay can't read
// the caller's payer_addr; the 200 response is sealed to the caller's
// proxy_recipient under SEALED_RESERVE_RESPONSE_CONTENT_TYPE (8.0) because
// presigned_open_txn names the payer address outright. See SPEC.md § 3a, § 3f.

import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'

import { ed25519 } from '../util/ed25519.js'
import { CanonicalWriter } from '../util/canonical.js'
import type { BytesSigner } from './signing.js'
import type { Ticket } from './ticket.js'

// Content-Type for a POST /v1/zs/reserve *error* response — plaintext
// OpenAI-shaped JSON, carrying no ticket and no payer. A successful response
// uses SEALED_RESERVE_RESPONSE_CONTENT_TYPE; the request body uses
// SEALED_RESERVE_CONTENT_TYPE.
export const RESERVE_CONTENT_TYPE = 'application/json'

export interface ReserveRequest {
    model: string
    // Conservative upper bound (not a tokenizer output).
    input_count: number
    // Exact value, read from the request or a per-model default.
    max_output_count: number
    stream: boolean
    // age recipient ("age1...") the node wraps K_response to.
    // Required — the node refuses an empty one with 400 invalid_reserve.
    // Also signed context in the reserve's canonical bytes (where it
    // doubles as the replay nonce) and the value admission compares the
    // request's reply_to_public_key against.
    proxy_recipient?: string
    // 58-char Algorand address that funds and signs the open() group's
    // usdcPayment (gtxn[0]); it must also hold a prepaid ticket-MBR pool
    // that open() draws box-MBR from (there is no per-turn feePayment leg).
    // Required in the consensus-verified open() design.
    payer_addr?: string
    // Per-request ceilings on how many images the zs_image_generation /
    // zs_image_edit built-in tools may produce over the whole
    // /v1/responses tool loop. The proxy/client sizes
    // max_price additively (max_n × per-image cap); the synthetic-token
    // factor and passes the raw counts here so the node can enforce per-tool
    // consumption in-loop. These ride the plaintext reserve request only —
    // they are NOT part of Ticket.CanonicalBytes, so they add no wire-format
    // change (the AmountCharged ≤ MaxPrice clamp on the signed ticket still
    // bounds the downside). Zero / omitted ⇒ the tool is unusable for this
    // request even if the model decides to call it.
    image_tool_budget?: number
    image_edit_tool_budget?: number
    // Dedicated-route image request (/v1/images/{generations,edits}) priced by
    // the parameter-deterministic microUSDC model. When image_n > 0 and the
    // model advertises a per-image microUSDC rate, the node sizes
    // MaxPrice = imageprice.costMicroUSDC(rate, image_n, image_size,
    // image_quality) directly (input_count / max_output_count unused for
    // sizing). Plaintext reserve only — not part of Ticket canonical bytes.
    image_n?: number
    image_size?: string
    image_quality?: string
    // Selects the edit route (image_edit_rate) over generation (image_rate)
    // when sizing a dedicated image reserve. Ignored unless image_n > 0.
    image_edit?: boolean
    // payer_sig / payer_issued_at authenticate payer_addr (protocol 8.1,
    // additive). payer_sig is base64(Ed25519 over reserveSigDigest) produced by
    // the key underneath payer_addr; payer_issued_at is the unix-second start of
    // the [issued_at, issued_at+MAX_RESERVE_SIG_AGE_SEC] window the signature
    // commits to. Sealing buys confidentiality, not authentication — so without
    // this the node's per-account limiter keys on a spoofable claim. The
    // signature additionally binds the target (operator_id, node_id) and
    // proxy_recipient as *unsent* signed context (see reserveCanonicalBytes).
    // Ride the sealed reserve request only — NOT part of Ticket canonical bytes.
    // See SPEC.md § 3a "Reserve-request signature".
    payer_sig?: string
    payer_issued_at?: number
    // input_bound_version names the tokenize bound the caller used to compute
    // input_count, so the node enforces the inference-time input budget with the
    // SAME function. Omitted / 0 means version 1.
    //
    // Explicit rather than inferred, because bound v2 is not uniformly smaller
    // than v1: it is tighter on prose, tool schemas and images, but deliberately
    // LARGER on the classes v1 under-counts (base64, hex, UUID-dense text,
    // emoji, embedded JSON). A node that simply measured with its newest bound
    // would reject a correctly-sized v1 caller whose body happens to be CJK or
    // base64 — an outage caused purely by upgrading.
    //
    // Rides the sealed reserve request only — NOT part of the ticket's canonical
    // bytes, so it is additive and changes no signature. Only set after
    // usesTightInputBound confirms the target advertises >= 9.2.
    input_bound_version?: number
}

export interface ReserveResponse {
    ticket: Ticket
    // base64(age_encrypt(K_response, proxy_recipient)). Empty when the
    // request carried no proxy_recipient. Same primitive as
    // X-Zs-Response-Key, just delivered at reserve time.
    wrapped_response_key?: string
    // ALGO/USD exchange rate at reserve time. Display-only (let UI
    // express ALGO network fees in USD) — NOT used in pricing.
    algo_usd_price?: number
    // base64(msgpack(SignedTxn)) — the node's pre-signed gtxn[1] (the
    // open() AppCall) of the 2-tx open group [usdcPayment, open()].
    presigned_open_txn?: string
}

// RESERVE_SIGNING_TAG domain-separates the reserve-request payer signature from
// Ticket / UsageReceipt / EphemeralAdvertisement signatures. The trailing NUL
// matches the whole family (must equal proto/go/ticket/reserve.go
// reserveSigningTag). New independent domain — no suffix bump on the others.
export const RESERVE_SIGNING_TAG = 'zs-reserve-v1\x00'

// MAX_RESERVE_SIG_AGE_SEC is the short validity window a verifier enforces on a
// payer signature. A reserve is immediate and per-request, so the window is
// deliberately tight. Mirrors proto/go/ticket/reserve.go MaxReserveSigAge.
export const MAX_RESERVE_SIG_AGE_SEC = 60

// DEFAULT_RESERVE_SKEW_SEC is the clock-skew tolerance applied to both window
// edges. issued_at is stamped on consumer devices, so some slack is mandatory.
// Mirrors proto/go/ticket/reserve.go DefaultReserveSkew.
export const DEFAULT_RESERVE_SKEW_SEC = 30

// ReserveSigExpiredError is thrown by verifyReserveRequest when the signature is
// valid but the [issued_at, issued_at+MAX_RESERVE_SIG_AGE_SEC] window has passed
// (within skew). A distinguishable class so a caller can tell a stale-but-genuine
// signature (client clock lagging) from a forgery. Mirrors Go's
// ErrReserveSigExpired.
export class ReserveSigExpiredError extends Error {
    constructor(message = 'reserve signature expired') {
        super(message)
        this.name = 'ReserveSigExpiredError'
    }
}

// reserveCanonicalBytes returns the unambiguous byte sequence the payer
// signature covers — the *signed subset* of the reserve, plus the target
// (operatorId, nodeId) as signed context. Matches proto/go/ticket/reserve.go
// ReserveRequest.CanonicalBytes byte-for-byte.
//
// LOCKED layout (any change requires a vectors regeneration + the matching Go
// edit): RESERVE_SIGNING_TAG ‖ lenStr(payer_addr) ‖ u64(operatorId) ‖
// u64(nodeId) ‖ lenStr(model) ‖ u64(input_count) ‖ u64(max_output_count) ‖
// bool(stream) ‖ lenStr(proxy_recipient) ‖ i64(payer_issued_at).
//
// operatorId / nodeId are NOT wire fields — both ends know them out of band
// (target binding, see the Go doc), so they enter as parameters. proxy_recipient
// is a per-request fresh recipient, so it doubles as the replay nonce.
// Undefined optional fields encode as their zero value (lenStr('') / i64(0)),
// exactly as the Go empty-string/zero would.
export function reserveCanonicalBytes(
    operatorId: number | bigint,
    nodeId: number | bigint,
    r: ReserveRequest,
): Uint8Array {
    return new CanonicalWriter()
        .str(RESERVE_SIGNING_TAG)
        .lenStr(r.payer_addr ?? '')
        .u64(operatorId)
        .u64(nodeId)
        .lenStr(r.model)
        .u64(r.input_count)
        .u64(r.max_output_count)
        .bool(r.stream)
        .lenStr(r.proxy_recipient ?? '')
        .i64(r.payer_issued_at ?? 0)
        .finish()
}

// reserveSigDigest returns sha256(reserveCanonicalBytes(operatorId, nodeId, r))
// — the 32-byte value both signReserveRequest and verifyReserveRequest feed to
// ed25519. reserveCanonicalBytes already prepends the "zs-reserve-v1\x00" domain
// tag so the digest is cross-protocol safe.
export function reserveSigDigest(
    operatorId: number | bigint,
    nodeId: number | bigint,
    r: ReserveRequest,
): Uint8Array {
    return sha256(reserveCanonicalBytes(operatorId, nodeId, r))
}

// signReserveRequest populates r.payer_sig with an Ed25519 signature over
// reserveSigDigest(operatorId, nodeId, r), produced by the key underneath
// payerAddr. It sets r.payer_addr = payerAddr first so the signed identity can
// never diverge from the signing key's address. The caller must have already
// set r.model / r.input_count / r.max_output_count / r.stream / r.proxy_recipient
// and r.payer_issued_at — the signature commits to all of them plus the target
// (operatorId, nodeId), which are the node this reserve is sent to. Mirrors
// signTicket / signEphemeral.
export async function signReserveRequest(
    operatorId: number | bigint,
    nodeId: number | bigint,
    r: ReserveRequest,
    signer: BytesSigner,
    payerAddr: string,
): Promise<void> {
    if (!signer) throw new Error('reserve sign: signer is nil')
    r.payer_addr = payerAddr
    const digest = reserveSigDigest(operatorId, nodeId, r)
    const sig = await signer.signBytes(payerAddr, digest)
    if (sig.length !== 64) {
        throw new Error(`reserve sign: signer returned ${sig.length}-byte signature, want 64`)
    }
    r.payer_sig = base64.encode(sig)
}

// verifyReserveRequest checks that r.payer_sig is a valid Ed25519 signature of
// reserveSigDigest(operatorId, nodeId, r) under pub, and that the signed window
// is live within skew. pub is recovered by the caller from r.payer_addr
// (decodeAlgorandAddress); operatorId / nodeId are the verifying node's OWN
// identity, never trusted from the wire. Ordering mirrors verifyEphemeral:
// (1) signature; (2) not-before; (3) the short window last, throwing
// ReserveSigExpiredError so a stale-but-genuine signature is distinguishable.
// nowUnixSec is injected so callers can test boundaries deterministically.
export function verifyReserveRequest(
    operatorId: number | bigint,
    nodeId: number | bigint,
    r: ReserveRequest,
    pub: Uint8Array,
    nowUnixSec: number,
    skewSec: number,
): void {
    if (pub.length !== 32) {
        throw new Error(`invalid ed25519 public key length ${pub.length}`)
    }
    if (!r.payer_sig) throw new Error('reserve signature missing')
    let sig: Uint8Array
    try {
        sig = base64.decode(r.payer_sig)
    } catch (err) {
        throw new Error(`decode reserve sig: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (sig.length !== 64) {
        throw new Error(`invalid ed25519 signature length ${sig.length}`)
    }
    const digest = reserveSigDigest(operatorId, nodeId, r)
    if (!ed25519.verify(sig, digest, pub)) {
        throw new Error('reserve signature verification failed')
    }

    // Signed values are now authentic — enforce the window.
    const issuedAt = r.payer_issued_at ?? 0
    if (issuedAt > nowUnixSec + skewSec) {
        throw new Error(`reserve signature not yet valid: issued_at ${issuedAt} is in the future`)
    }
    if (nowUnixSec > issuedAt + MAX_RESERVE_SIG_AGE_SEC + skewSec) {
        throw new ReserveSigExpiredError()
    }
}
