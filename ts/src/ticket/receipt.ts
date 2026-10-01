/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// UsageReceipt — signed post-response artifact that drives escrow
// settlement. Mirrors proto/go/ticket/receipt.go.
//
// The escrow contract's settle method receives a digest + sig and
// disburses amount_charged to the operator owner address, refunding
// the remainder plus the ticket's box MBR to the payer. The proxy /
// browser independently verifies:
//   - sig is valid under the operator's signing pubkey
//   - amount_charged ≤ Ticket.max_price
//   - body_hash equals sha256 of the reconstructed plaintext
//     (non-stream body bytes, or plaintext frames concatenated in
//     index order)
//
// body_hash is hex (lower-case, length 64). sig is base64.

import { sha256 } from '@noble/hashes/sha2.js'
import { base64 } from '@scure/base'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import { ed25519 } from '../util/ed25519.js'
import { CanonicalWriter } from '../util/canonical.js'
import type { BytesSigner } from './signing.js'
import type { UsageType } from './usagetype.js'

export interface UsageReceipt {
    ticket_id: string // base64(16 bytes) — same form as Ticket.ticket_id
    actual_input_count: number
    actual_output_count: number
    amount_charged: number // microUSDC; clamped to Ticket.max_price
    // ttft_ms and decode_ms are the operator-measured timings carried as
    // two separate fields (previously a single packed processing_time_ms).
    // ttft_ms is time-to-first-token; decode_ms is the decode window, which
    // opens at the upstream's FIRST FRAME of any kind rather than at the first
    // output frame, so that thinking a provider never streamed is still
    // covered by the window its tokens are divided by (SPEC.md "Where the
    // decode window starts"). A non-stream / no-first-token receipt sets
    // ttft_ms = total service time and decode_ms = 0. Derive throughput
    // with tokensPerSec(). Both are committed inside the receipt digest and
    // passed verbatim as the `ttftMs` / `decodeMs` ABI args on settle(); the
    // contract's match check freezes the ticket if the first-half and
    // second-half values disagree. On chain ttft_ms drives the per-operator
    // TTFT latency metric and decode_ms + output tokens drive the
    // throughput EWMA.
    ttft_ms: number
    decode_ms: number
    body_hash: string // hex sha256(plaintext); always 64 chars
    // input_usage_type / output_usage_type (v2) discriminate the unit each
    // direction was metered in; aux_output_usage_type / aux_output_count carry
    // the one inline secondary modality a response can mix (tool-produced
    // images alongside chat tokens), recorded in metrics without a co-signed
    // billing tuple. Three bytes + one uint64 at the tail of the canonical
    // bytes. Default 0 (UsageType.None) describes a plain token receipt.
    input_usage_type: UsageType
    output_usage_type: UsageType
    aux_output_usage_type: UsageType
    aux_output_count: number
    // cached_input_count (v2) — subset of actual_input_count the upstream served
    // from a prefix/prompt cache (invariant: <= actual_input_count). Billed at
    // the ticket's cache_read_rate instead of input_rate. 0 on image routes and
    // whenever the upstream reports no cached count. One uint64 at the tail of
    // the canonical bytes.
    cached_input_count: number
    sig?: string // base64(Ed25519 over receiptSigDigest)
}

// v1 covered the base receipt + the later UsageType-discriminator / aux-output
// append; bumped v1 → v2 when cached_input_count was appended (must match
// proto/go/ticket/receipt.go::receiptSigningTag).
const RECEIPT_SIGNING_TAG = 'zs-receipt-v2\x00'

export function receiptCanonicalBytes(r: UsageReceipt): Uint8Array {
    return new CanonicalWriter()
        .str(RECEIPT_SIGNING_TAG)
        .lenStr(r.ticket_id)
        .u64(r.actual_input_count)
        .u64(r.actual_output_count)
        .u64(r.amount_charged)
        // ttft_ms then decode_ms join after amount_charged so the digest
        // commits to both (must match the Go-side ordering in
        // proto/go/ticket/receipt.go::CanonicalBytes).
        .u64(r.ttft_ms)
        .u64(r.decode_ms)
        .lenStr(r.body_hash)
        // usage-type discriminators + aux output slot (three bytes then the
        // aux count).
        .u8(r.input_usage_type)
        .u8(r.output_usage_type)
        .u8(r.aux_output_usage_type)
        .u64(r.aux_output_count)
        // v2: cached-read count at the tail.
        .u64(r.cached_input_count)
        .finish()
}

// receiptSigDigest returns sha256(canonicalBytes(r)). canonicalBytes
// already prepends the "zs-receipt-v2\x00" domain tag.
export function receiptSigDigest(r: UsageReceipt): Uint8Array {
    return sha256(receiptCanonicalBytes(r))
}

// tokensPerSec derives generation throughput (output tokens / sec) from the
// decode window. Returns 0 when there's no decode window (decode_ms === 0),
// matching the contract's throughput-EWMA exclusion so callers can treat 0
// as "no throughput signal".
export function tokensPerSec(r: UsageReceipt): number {
    if (r.decode_ms === 0) return 0
    return Math.floor((r.actual_output_count * 1000) / r.decode_ms)
}

export async function signReceipt(
    r: UsageReceipt,
    signer: BytesSigner,
    signingAddr: string,
): Promise<void> {
    if (!signer) throw new Error('receipt sign: signer is nil')
    const digest = receiptSigDigest(r)
    const sig = await signer.signBytes(signingAddr, digest)
    if (sig.length !== 64) {
        throw new Error(`receipt sign: signer returned ${sig.length}-byte signature, want 64`)
    }
    r.sig = base64.encode(sig)
}

export function verifyReceipt(r: UsageReceipt, pub: Uint8Array): void {
    if (pub.length !== 32) {
        throw new Error(`invalid ed25519 public key length ${pub.length}`)
    }
    if (!r.sig) throw new Error('receipt signature missing')
    let sig: Uint8Array
    try {
        sig = base64.decode(r.sig)
    } catch (err) {
        throw new Error(`decode receipt sig: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (sig.length !== 64) {
        throw new Error(`invalid ed25519 signature length ${sig.length}`)
    }
    const digest = receiptSigDigest(r)
    if (!ed25519.verify(sig, digest, pub)) {
        throw new Error('receipt signature verification failed')
    }
}

// encodeReceiptHeader returns the base64(JSON) form the node writes to
// the X-Zs-Receipt header. Inverse of decodeReceiptHeader.
export function encodeReceiptHeader(r: UsageReceipt): string {
    return base64.encode(new TextEncoder().encode(JSON.stringify(r)))
}

// decodeReceiptHeader parses the base64(JSON) shape the node writes to
// X-Zs-Receipt. Use before verifyReceipt.
export function decodeReceiptHeader(value: string): UsageReceipt {
    let raw: Uint8Array
    try {
        raw = base64.decode(value)
    } catch (err) {
        throw new Error(`decode receipt header base64: ${err instanceof Error ? err.message : String(err)}`)
    }
    try {
        return JSON.parse(new TextDecoder().decode(raw)) as UsageReceipt
    } catch (err) {
        throw new Error(`decode receipt header json: ${err instanceof Error ? err.message : String(err)}`)
    }
}

// setBodyHashBytes sets r.body_hash from raw sha256 output (32 bytes).
// Matches what bodyHashOfBody / bodyHashFromFrames return.
export function setBodyHashBytes(r: UsageReceipt, sum: Uint8Array): void {
    if (sum.length !== 32) throw new Error(`body_hash bytes length ${sum.length}, want 32`)
    r.body_hash = bytesToHex(sum)
}

// bodyHashBytes returns the 32-byte sha256 represented by r.body_hash,
// throwing when the field isn't a valid 64-char hex string.
export function bodyHashBytes(r: UsageReceipt): Uint8Array {
    if (r.body_hash.length !== 64) {
        throw new Error(`body_hash must be 64 hex chars, got ${r.body_hash.length}`)
    }
    try {
        return hexToBytes(r.body_hash)
    } catch (err) {
        throw new Error(`decode body_hash hex: ${err instanceof Error ? err.message : String(err)}`)
    }
}
