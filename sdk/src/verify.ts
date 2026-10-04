/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's checks on what a node signs: the ticket at reserve and the usage
// receipt at the end of a turn. They mirror proto/go/zs's reserve checks and
// VerifyReceipt; the canonical bytes and signatures are @txnlab/zs-proto's.

import {
    type Ticket,
    type UsageReceipt,
    bodyHashBytes,
    commitResponseKey,
    verifyReceipt as verifyReceiptSig,
    verifyTicket,
} from '@txnlab/zs-proto/ticket'

const ED25519_PUBKEY_LEN = 32
const RESPONSE_KEY_LEN = 32

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}

/** Thrown when a ticket's signature does not verify under the node's signing key. */
export class TicketSignatureInvalidError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'TicketSignatureInvalidError'
    }
}

/** Thrown when sha256(K_response) is not the commit_k the node signed into the ticket. */
export class CommitKMismatchError extends Error {
    constructor(message: string) {
        super(message)
        this.name = 'CommitKMismatchError'
    }
}

/** verifyTicketSignature throws TicketSignatureInvalidError unless the node signed t under signingKey. */
export function verifyTicketSignature(t: Ticket, signingKey: Uint8Array): void {
    if (signingKey.length !== ED25519_PUBKEY_LEN) {
        throw new TicketSignatureInvalidError(`invalid ed25519 public key length ${signingKey.length}`)
    }
    try {
        verifyTicket(t, signingKey)
    } catch (err) {
        throw new TicketSignatureInvalidError(message(err))
    }
}

/**
 * verifyCommitK throws CommitKMismatchError unless base64(sha256(responseKey))
 * is the ticket's commit_k. That binds the key the node wrapped for this turn to
 * the ticket the payer escrows against. The comparison is on the encoded
 * string, as Go's, so a non-canonical commit_k fails too.
 */
export function verifyCommitK(t: Ticket, responseKey: Uint8Array): void {
    if (responseKey.length !== RESPONSE_KEY_LEN) {
        throw new CommitKMismatchError(`K_response must be ${RESPONSE_KEY_LEN} bytes, got ${responseKey.length}`)
    }
    if (base64(commitResponseKey(responseKey)) !== t.commit_k) {
        throw new CommitKMismatchError('commit_k does not match sha256(K_response)')
    }
}

/**
 * ReceiptViolation classifies a rejected receipt, as Go's ReceiptViolation and
 * the receipt.violated event's `violation`.
 */
export type ReceiptViolation = 'sig' | 'amount' | 'body_hash'

/** ReceiptError is a receipt verifyReceipt rejected, mirroring Go's ReceiptError. */
export class ReceiptError extends Error {
    readonly violation: ReceiptViolation
    constructor(violation: ReceiptViolation, message: string, cause?: unknown) {
        super(message, cause === undefined ? undefined : { cause })
        this.name = 'ReceiptError'
        this.violation = violation
    }
}

/** Every ReceiptViolation, in Go's order; pinned against Go by the vocabulary vectors. */
export const receiptViolations = ['sig', 'amount', 'body_hash'] as const satisfies readonly ReceiptViolation[]

/**
 * verifyReceipt runs Go's checks in Go's order and throws a ReceiptError on the
 * first that fails: the signature under signingKey; amount_charged at most the
 * ticket's max_price and cached_input_count at most actual_input_count; then
 * body_hash against computedHash, the sha256 of the body or the concatenated
 * stream frames.
 *
 * A charge below min_price is accepted. The floor is the node's to apply in
 * its own favour (SPEC §3a); a lower charge costs only the node.
 */
export function verifyReceipt(r: UsageReceipt, t: Ticket, signingKey: Uint8Array, computedHash: Uint8Array): void {
    try {
        verifyReceiptSig(r, signingKey)
    } catch (err) {
        throw new ReceiptError('sig', `receipt signature verify: ${message(err)}`, err)
    }
    if (r.amount_charged > t.max_price) {
        throw new ReceiptError(
            'amount',
            `receipt amount_charged ${r.amount_charged} exceeds ticket max_price ${t.max_price}`,
        )
    }
    // A signed but self-inconsistent count is the node's misbehaviour; the
    // cached reads are a subset of the input (SPEC §3a).
    if (r.cached_input_count > r.actual_input_count) {
        throw new ReceiptError(
            'amount',
            `receipt cached_input_count ${r.cached_input_count} exceeds actual_input_count ${r.actual_input_count}`,
        )
    }
    let claimed: Uint8Array
    try {
        claimed = bodyHashBytes(r)
    } catch (err) {
        throw new ReceiptError('body_hash', `receipt body_hash malformed: ${message(err)}`, err)
    }
    if (computedHash.length !== claimed.length || claimed.some((b, i) => b !== computedHash[i])) {
        throw new ReceiptError('body_hash', `receipt body_hash mismatch (got ${r.body_hash} want ${hex(computedHash)})`)
    }
}

/**
 * The receipt decoders verifyReceipt needs ahead of it: the stream's receipt
 * frame and the buffered response's X-Zs-Receipt header. Both are zs-proto's,
 * and refuse a value that doesn't fit its Go type; a lax decode would let a
 * node sign 2^64-1 and send -1 past the amount check.
 */
export { decodeReceiptHeader, parseReceiptJSON } from '@txnlab/zs-proto/ticket'

function base64(b: Uint8Array): string {
    let s = ''
    for (const x of b) s += String.fromCharCode(x)
    return btoa(s)
}

function hex(b: Uint8Array): string {
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}
