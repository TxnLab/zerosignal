/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's checks on what a node signs: the ticket at reserve and the usage
// receipt at the end of a turn. They mirror proto/go/zs's reserve checks and
// VerifyReceipt; the canonical bytes and signatures are @txnlab/zs-proto's.

import { base64 as scureBase64 } from '@scure/base'
import {
    type Ticket,
    type UsageReceipt,
    bodyHashBytes,
    commitResponseKey,
    decodeDeploymentId,
    verifyReceiptFor,
    verifyTicketFor,
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

/**
 * verifyTicketSignature throws TicketSignatureInvalidError unless the node
 * signed t under signingKey, bound to deployment, or unbound while
 * allowLegacy. Go's reserve passes allowLegacy only when the reserve named no
 * deployment. With no deployment, only an unbound ticket passes.
 */
export function verifyTicketSignature(
    t: Ticket,
    signingKey: Uint8Array,
    deployment?: Uint8Array,
    allowLegacy = true,
): void {
    if (signingKey.length !== ED25519_PUBKEY_LEN) {
        throw new TicketSignatureInvalidError(`invalid ed25519 public key length ${signingKey.length}`)
    }
    try {
        verifyTicketFor(t, signingKey, deployment, allowLegacy)
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
 * first that fails: the signature under signingKey, and the receipt naming the
 * ticket; amount_charged at most the ticket's max_price and cached_input_count
 * at most actual_input_count; then body_hash against computedHash, the sha256
 * of the body or the concatenated stream frames.
 *
 * A charge below min_price is accepted. The floor is the node's to apply in
 * its own favour (SPEC §3a); a lower charge costs only the node.
 */
export function verifyReceipt(r: UsageReceipt, t: Ticket, signingKey: Uint8Array, computedHash: Uint8Array): void {
    try {
        // A receipt is bound exactly when its ticket is, and to the same
        // deployment; the ticket's binding was checked at reserve.
        const want = t.deployment ? decodeDeploymentId(t.deployment) : undefined
        verifyReceiptFor(r, signingKey, want, want === undefined)
    } catch (err) {
        throw new ReceiptError('sig', `receipt signature verify: ${message(err)}`, err)
    }
    // The signature holds for whichever ticket the receipt names, so a node can
    // hand over one it signed for another ticket. Classed with the signature,
    // as the node signed nothing for this ticket: none of the receipt's figures
    // is pinned or journaled, and no protest goes out. Solana's program refuses
    // a protest over another ticket's receipt; Algorand's refuses it against a
    // pending claim with another digest, and otherwise freezes this ticket on
    // evidence about another. Ahead of the amount and body_hash checks, which
    // would otherwise pin the figure or protest. The mismatch itself, unlike
    // the rest of the sig class, bars the node (ReceiptForAnotherTicketError).
    const mismatch = receiptTicketMismatch(r.ticket_id, t.ticket_id)
    if (mismatch !== undefined) throw new ReceiptError('sig', mismatch.message, mismatch)
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

const TICKET_ID_LEN = 16

/**
 * ReceiptForAnotherTicketError is the cause of the one sig ReceiptError that
 * is evidence against the node, Go's errReceiptNamesOtherTicket: the signature
 * verified under the node's key over a receipt naming another ticket. The
 * receipt check bars the node for it. A bad signature proves nothing about who
 * produced the receipt, and a non-canonical ticket id is the payer's own
 * input, so neither carries it.
 */
export class ReceiptForAnotherTicketError extends Error {
    constructor(receiptId: string, want: string) {
        super(`the receipt names another ticket: ${JSON.stringify(receiptId)}, not the payer's ${JSON.stringify(want)}`)
        this.name = 'ReceiptForAnotherTicketError'
    }
}

/**
 * Why the receipt doesn't name the payer's ticket, or undefined when it does:
 * Go's receiptNamesTicket. The receipt's id is compared as the string the node
 * signed against the canonical spelling of the bytes the payer opened, as the
 * open offer's fold compares, so no decoder's leniency makes two spellings of
 * one id agree. The ticket's own id must be that spelling too: Go's decoder
 * takes non-zero padding bits and this one doesn't, so without it the two SDKs
 * would accept different receipts for one ticket. This decoder already refuses
 * every other spelling, so the ticket comparison below can't fail today; it
 * stays so the check holds should the decoder ever loosen. Only the receipt's
 * mismatch is a ReceiptForAnotherTicketError; the checks of the payer's id
 * come first, so a ticket the payer holds in another spelling never bars the
 * node.
 */
function receiptTicketMismatch(receiptId: string, ticketId: string): Error | undefined {
    let raw: Uint8Array
    try {
        raw = scureBase64.decode(ticketId)
    } catch (err) {
        return new Error(`the payer's ticket id: ${message(err)}`)
    }
    if (raw.length !== TICKET_ID_LEN) return new Error(`the payer's ticket id decodes to ${raw.length} bytes, want ${TICKET_ID_LEN}`)
    const want = scureBase64.encode(raw)
    if (ticketId !== want) return new Error(`the payer's ticket id ${JSON.stringify(ticketId)} is not the canonical spelling ${JSON.stringify(want)}`)
    if (receiptId !== want) return new ReceiptForAnotherTicketError(receiptId, want)
    return undefined
}

function base64(b: Uint8Array): string {
    let s = ''
    for (const x of b) s += String.fromCharCode(x)
    return btoa(s)
}

function hex(b: Uint8Array): string {
    return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}
