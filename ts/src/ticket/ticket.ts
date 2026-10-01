/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Ticket — signed admission credential issued by a node's reserve
// endpoint. Mirrors proto/go/ticket/ticket.go.
//
// Integer fields are microUSDC (price/rates) or unix seconds
// (expires_at). USDC has 6 decimals and is dollar-pegged, so 1 USDC =
// 1,000,000 microUSDC and rates convert from operator USD/1M config by a
// straight 1e6 scale at reserve time (no oracle in the pricing path).
//
// All numeric fields are uint64 / int64 in Go. We type them as `number`
// since real values stay well within JS's safe-integer range (token
// counts, microUSDC totals); the canonical-bytes encoder coerces to
// BigInt before writing the 8-byte big-endian form, so values up to
// 2^53-1 are safe.

import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'

import { ed25519 } from '../util/ed25519.js'
import { CanonicalWriter } from '../util/canonical.js'
import type { BytesSigner } from './signing.js'
import type { UsageType } from './usagetype.js'

export interface Ticket {
    // base64(16 bytes) — opaque to the proxy; node maps to K_response.
    ticket_id: string
    // sequential operator id assigned by ZeroSignalEscrow.createOperator;
    // contract resolves the owner (payout) address from the operator box.
    operator_id: number
    // node id within operator_id that issued this ticket; the contract's
    // open() snapshots (operator_id, node_id) and resolves the node's
    // signing key. Verifiers check sig against that node's signing address.
    node_id: number
    // exact count the proxy committed to at reserve time.
    input_count: number
    // ceiling; actual drives settlement refund.
    max_output_count: number
    // microUSDC per 1,000,000 input tokens.
    input_rate: number
    // microUSDC per 1,000,000 output tokens.
    output_rate: number
    // microUSDC; computed by the issuing node per SPEC §3a — the exact
    // rate-based ceiling ceil(input_count*input_rate/1e6) +
    // ceil(max_output_count*output_rate/1e6), bumped up to min_price
    // when that floor is larger (tiny paid requests). Immutable for the
    // life of the ticket; the contract's open() locks exactly this many
    // microUSDC into escrow. Invariant: max_price >= min_price.
    max_price: number
    // microUSDC; per-request minimum amount_charged on non-zero usage
    // (see SPEC §3a "Minimum charge"). max(token component =
    // ceil(min_charge.output_tokens*output_rate/1e6), µALGO component =
    // ceil(min_charge.algo_txns*1000*algo_usd)). 0 only when both
    // components are 0 — i.e. a free model, OR (token component off:
    // hayai.min_charge.output_tokens=0 or output_rate=0) AND (µALGO
    // component off: hayai.min_charge.algo_txns=0 — the default — or
    // oracle unavailable at reserve). With stock config a paid model's
    // ticket has a non-zero min_price. The (0,0) inference-failure path
    // still charges 0 regardless.
    min_price: number
    // unix seconds.
    expires_at: number
    // requested model id.
    model: string
    // whether the sealed request will stream.
    stream: boolean
    // base64(sha256(K_response)) — binds payment to this specific
    // response key.
    commit_k: string
    // input_usage_type / output_usage_type (v2) discriminate the unit each
    // direction is priced in (see UsageType). Chat is Tokens/Tokens; a
    // dedicated image route is None-or-Tokens/Images. One byte each at the
    // tail of the canonical bytes. Default 0 (UsageType.None).
    input_usage_type: UsageType
    output_usage_type: UsageType
    // cache_read_rate (v2) — microUSDC per 1,000,000 cached-read input tokens
    // (the prompt subset an upstream served from cache, reported as
    // cached_input_count on the receipt). Always <= input_rate; 0 = free cached
    // reads. When the operator leaves it unset the issuing node resolves it to
    // input_rate, so a v1-era flat charge is reproduced exactly. One uint64 at
    // the tail of the canonical bytes.
    cache_read_rate: number
    // base64(Ed25519 signature over ticketSigDigest). Filled by
    // signTicket; verifyTicket reads it.
    sig?: string
}

// Domain prefix for ticket signatures — distinguishes ticket sigs from
// receipt sigs (and any other ed25519 use). Trailing NUL keeps the tag
// self-terminating in concatenations. v1 covered the base ticket + the later
// UsageType-discriminator append; bumped v1 → v2 when cache_read_rate was
// appended (must match proto/go/ticket/ticket.go::ticketSigningTag).
const TICKET_SIGNING_TAG = 'zs-ticket-v2\x00'

// ticketCanonicalBytes returns the unambiguous byte sequence Ed25519
// signs (and verifies). Strings → uint32-BE length + raw bytes; numeric
// fields → fixed-width big-endian; bool → single byte (0 or 1). Matches
// proto/go/ticket/ticket.go::Ticket.CanonicalBytes byte-for-byte. Sig
// is excluded — that's what we're computing.
export function ticketCanonicalBytes(t: Ticket): Uint8Array {
    return new CanonicalWriter()
        .str(TICKET_SIGNING_TAG)
        .lenStr(t.ticket_id)
        .u64(t.operator_id)
        .u64(t.node_id)
        .u64(t.input_count)
        .u64(t.max_output_count)
        .u64(t.input_rate)
        .u64(t.output_rate)
        .u64(t.max_price)
        .u64(t.min_price)
        .i64(t.expires_at)
        .lenStr(t.model)
        .bool(t.stream)
        .lenStr(t.commit_k)
        // usage-type discriminators (one byte each).
        .u8(t.input_usage_type)
        .u8(t.output_usage_type)
        // v2: cached-read rate at the tail.
        .u64(t.cache_read_rate)
        .finish()
}

// ticketSigDigest returns sha256(canonicalBytes(t)) — the 32-byte
// value both signTicket and the escrow contract's
// op.ed25519verifyBare feed to ed25519. canonicalBytes already
// prepends the "zs-ticket-v2\x00" domain tag; signing the digest
// (not the raw message) keeps on-chain verify cost constant.
export function ticketSigDigest(t: Ticket): Uint8Array {
    return sha256(ticketCanonicalBytes(t))
}

// signTicket populates t.sig with Ed25519(priv, ticketSigDigest(t)).
// The signing key is whatever signer holds for signingAddr (the
// operator's signing address — distinct from the payment address; see
// SPEC §3 / §3a). Routing through BytesSigner keeps the actual key in
// a wallet / HSM / keystore without proto/ts needing to know.
export async function signTicket(
    t: Ticket,
    signer: BytesSigner,
    signingAddr: string,
): Promise<void> {
    if (!signer) throw new Error('ticket sign: signer is nil')
    const digest = ticketSigDigest(t)
    const sig = await signer.signBytes(signingAddr, digest)
    if (sig.length !== 64) {
        throw new Error(`ticket sign: signer returned ${sig.length}-byte signature, want 64`)
    }
    t.sig = base64.encode(sig)
}

// verifyTicket throws if t.sig is not a valid Ed25519 signature of
// ticketSigDigest(t) under pub. Callers typically recover pub from an
// Algorand address via decodeAlgorandAddress.
export function verifyTicket(t: Ticket, pub: Uint8Array): void {
    if (pub.length !== 32) {
        throw new Error(`invalid ed25519 public key length ${pub.length}`)
    }
    if (!t.sig) throw new Error('ticket signature missing')
    let sig: Uint8Array
    try {
        sig = base64.decode(t.sig)
    } catch (err) {
        throw new Error(`decode ticket sig: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (sig.length !== 64) {
        throw new Error(`invalid ed25519 signature length ${sig.length}`)
    }
    const digest = ticketSigDigest(t)
    if (!ed25519.verify(sig, digest, pub)) {
        throw new Error('ticket signature verification failed')
    }
}

// commitResponseKey returns sha256(K) — the commitment a node places
// in Ticket.commit_k at reserve time. The proxy recovers K via
// unwrapResponseKey and recomputes this to verify the operator sealed
// the response with the pre-committed key.
export function commitResponseKey(k: Uint8Array): Uint8Array {
    return sha256(k)
}
