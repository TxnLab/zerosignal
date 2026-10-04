/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's checks on a 200 reserve response, mirroring the tail of
// proto/go/zs's Reserve: everything between the sealed body arriving and the
// open being composed, short of the ticket's signature and price.

import { type Ticket, parseReserveResponseJSON } from '@txnlab/zs-proto/ticket'
import { type EphemeralIdentity, openReserveResponse, unwrapResponseKey } from '@txnlab/zs-proto/wire'

import { verifyCommitK } from './verify.js'

/** ReserveTerms is what the payer asked the node for. */
export interface ReserveTerms {
    model: string
    maxOutputCount: number
    stream: boolean
    /**
     * The node the reserve was sent to. open() snapshots the pair and settles
     * against that node's signing key, and an operator's nodes can share one,
     * so the signature alone doesn't catch a ticket for a sibling node.
     */
    operatorId: number | bigint
    nodeId: number | bigint
}

/** ReserveResponseError is a 200 reserve response the payer refuses to escrow against. */
export class ReserveResponseError extends Error {
    constructor(message: string, cause?: unknown) {
        super(message, cause === undefined ? undefined : { cause })
        this.name = 'ReserveResponseError'
    }
}

export interface OpenReserveOptions {
    nowMs: number
    /** See checkTicketTerms. */
    minTtlSeconds?: number
    /** The reserve named a payer, so the node owes a presigned open group. */
    requirePresignedOpen?: boolean
}

export interface ReservedTicket {
    ticket: Ticket & { sig: string }
    /** K_response. The caller zeroes it when the turn ends. */
    responseKey: Uint8Array
    /** ALGO/USD at reserve, for display; 0 when the node sent none. */
    algoUsdPrice: number
    /** base64 msgpack of the presigned open group; '' when the node sent none. */
    presignedOpenTxn: string
}

/**
 * openReserve opens a sealed 200 reserve response with the identity whose
 * recipient the reserve declared, and runs Go's checks: a strict parse, the
 * ticket's terms against the request, then the wrapped K_response, which must
 * hash to the ticket's commit_k. Every failure is a ReserveResponseError except
 * the last, a CommitKMismatchError. Go has no requirePresignedOpen; it composes
 * the open only when a group came back.
 *
 * Two checks are the caller's before it escrows: the ticket's signature, with
 * verifyTicketSignature, since the node's signing key comes from the chain;
 * and its price, with zs-proto's verifyTicketPrice against what the node
 * advertised, which is also what bounds the input_count checkTicketTerms
 * leaves alone.
 */
export async function openReserve(
    sealed: Uint8Array,
    identity: EphemeralIdentity,
    terms: ReserveTerms,
    opts: OpenReserveOptions,
): Promise<ReservedTicket> {
    let plaintext: Uint8Array
    try {
        plaintext = await openReserveResponse(sealed, identity)
    } catch (err) {
        throw new ReserveResponseError(`open reserve response: ${message(err)}`, err)
    }
    let parsed
    try {
        parsed = parseReserveResponseJSON(plaintext)
    } catch (err) {
        throw new ReserveResponseError(`parse reserve response: ${message(err)}`, err)
    }
    const { ticket } = parsed
    if (!ticket.sig) throw new ReserveResponseError('reserve ticket is unsigned')
    checkTicketTerms(ticket, terms, opts.nowMs, opts.minTtlSeconds)
    if (!parsed.wrapped_response_key) {
        throw new ReserveResponseError('reserve response missing wrapped_response_key')
    }
    if (opts.requirePresignedOpen && !parsed.presigned_open_txn) {
        throw new ReserveResponseError('reserve response missing presigned_open_txn')
    }
    let responseKey: Uint8Array
    try {
        responseKey = await unwrapResponseKey(parsed.wrapped_response_key, identity)
    } catch (err) {
        throw new ReserveResponseError(`unwrap response key: ${message(err)}`, err)
    }
    // Before the open: a node that committed to one K and wrapped another
    // would have the payer escrow for a response its admission then refuses.
    try {
        verifyCommitK(ticket, responseKey)
    } catch (err) {
        responseKey.fill(0)
        throw err
    }
    return {
        ticket: ticket as Ticket & { sig: string },
        responseKey,
        algoUsdPrice: parsed.algo_usd_price ?? 0,
        presignedOpenTxn: parsed.presigned_open_txn ?? '',
    }
}

/**
 * checkTicketTerms throws a ReserveResponseError unless a ticket reflects the
 * request it answers. A valid signature over other terms (a cheaper model, a
 * different node, a stale ticket) is still no ticket to escrow against.
 *
 * input_count is deliberately not compared: the node clamps it to
 * [min_input_count, context_window − max_output_count] (SPEC §3a), so an
 * honest ticket can differ from the request. verifyTicketPrice's
 * input_count_bound is what stops a node inflating it. That bound allows the
 * payer's own count plus 10%, and min_input_count isn't advertised, so it
 * still refuses a short request from a node whose floor is above the payer's.
 *
 * The ticket must have at least minTtlSeconds left at nowMs, default and
 * minimum 1: Go's "not yet expired". A caller with a slow path from here to
 * the node's admission asks for more, or the ticket lapses between the open
 * and the request it pays for.
 */
export function checkTicketTerms(t: Ticket, terms: ReserveTerms, nowMs: number, minTtlSeconds = 1): void {
    if (BigInt(t.operator_id) !== id('operatorId', terms.operatorId)) {
        throw new ReserveResponseError(`ticket operator id ${t.operator_id} != requested ${terms.operatorId}`)
    }
    if (BigInt(t.node_id) !== id('nodeId', terms.nodeId)) {
        throw new ReserveResponseError(`ticket node id ${t.node_id} != requested ${terms.nodeId}`)
    }
    if (t.model !== terms.model) {
        throw new ReserveResponseError(`ticket model ${JSON.stringify(t.model)} != requested ${JSON.stringify(terms.model)}`)
    }
    if (t.max_output_count !== terms.maxOutputCount) {
        throw new ReserveResponseError(`ticket max_output_count ${t.max_output_count} != requested ${terms.maxOutputCount}`)
    }
    if (t.stream !== terms.stream) {
        throw new ReserveResponseError(`ticket stream ${t.stream} != requested ${terms.stream}`)
    }
    // A NaN either side would make the comparison below false and pass the
    // ticket, and a minimum under 1 would pass one already expired.
    if (!Number.isFinite(nowMs) || !Number.isFinite(minTtlSeconds) || minTtlSeconds < 1) {
        throw new ReserveResponseError(`cannot check expiry: now ${nowMs}ms, minimum TTL ${minTtlSeconds}s`)
    }
    const now = Math.floor(nowMs / 1000)
    if (t.expires_at - now < minTtlSeconds) {
        throw new ReserveResponseError(
            `ticket expires_at ${t.expires_at} leaves under ${minTtlSeconds}s (now ${now})`,
        )
    }
    if (!t.ticket_id) throw new ReserveResponseError('ticket_id is empty')
    if (!t.commit_k) throw new ReserveResponseError('commit_k is empty')
    // The node bumps max_price up to min_price for a tiny paid request, so a
    // ticket that breaks this would underfund escrow or marks a misbehaving
    // node.
    if (t.min_price > t.max_price) {
        throw new ReserveResponseError(`ticket min_price ${t.min_price} > max_price ${t.max_price}`)
    }
}

// A caller's id that isn't an integer would throw a bare RangeError from BigInt.
function id(name: string, v: number | bigint): bigint {
    if (typeof v === 'number' && !Number.isSafeInteger(v)) {
        throw new ReserveResponseError(`requested ${name} ${v} is not an integer`)
    }
    return BigInt(v)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
