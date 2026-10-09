/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The inference leg's crypto: sealing the request to the node, and opening
// the key its response is sealed under. Mirrors the seal and unwrap steps of
// proto/go/zs's runSealed and its responders; the primitives are zs-proto's
// wire, as Go's are its wire package.

import type { Ticket } from '@txnlab/zs-proto/ticket'
import { type EphemeralIdentity, computeAdmissionTag, unwrapResponseKey, wrapRequest } from '@txnlab/zs-proto/wire'

import { verifyCommitK } from './verify.js'

const RESPONSE_KEY_LEN = 32

/** Thrown when the response's X-Zs-Response-Key does not open under the reserve's identity. */
export class ResponseKeyUnwrapError extends Error {
    constructor(message: string, options?: ErrorOptions) {
        super(message, options)
        this.name = 'ResponseKeyUnwrapError'
    }
}

export interface SealRequestArgs {
    /** The plaintext request body: the bytes the node forwards upstream. */
    body: Uint8Array
    /** The open() app call's txid. */
    txId: string
    ticketId: string
    /** K_response, unwrapped at reserve. It keys the admission tag. */
    responseKey: Uint8Array
    /** The node's sealing recipient pinned at reserve, which the node committed K_response against. */
    nodeRecipient: string
    /** The reserve's ephemeral identity, reused as reply-to so it opens the response too. */
    ephemeral: EphemeralIdentity
}

/**
 * sealRequest is the request envelope: the body sealed to the node with its
 * identifiers and the admission tag, which proves to the node that the sender
 * holds K_response before it consumes the ticket.
 */
export async function sealRequest(a: SealRequestArgs): Promise<Uint8Array> {
    // Go's key is a [32]byte; a TypeScript caller can pass any length.
    if (a.responseKey.length !== RESPONSE_KEY_LEN) {
        throw new Error(`K_response must be ${RESPONSE_KEY_LEN} bytes, got ${a.responseKey.length}`)
    }
    const admissionTag = computeAdmissionTag(a.responseKey, a.ticketId, a.txId, a.body)
    const { envelope } = await wrapRequest({
        body: a.body,
        txID: a.txId,
        ticketID: a.ticketId,
        admissionTag,
        nodeRecipient: a.nodeRecipient,
        ephemeral: a.ephemeral,
    })
    return envelope
}

/**
 * openResponseKey unwraps the response's X-Zs-Response-Key and checks it
 * against the ticket's commit_k, before any of the response is opened. It
 * throws ResponseKeyUnwrapError when the key won't unwrap and
 * CommitKMismatchError when the node sealed under a key it didn't commit to.
 */
export async function openResponseKey(wrappedB64: string, ephemeral: EphemeralIdentity, t: Ticket): Promise<Uint8Array> {
    let key: Uint8Array
    try {
        key = await unwrapResponseKey(wrappedB64, ephemeral)
    } catch (err) {
        throw new ResponseKeyUnwrapError(err instanceof Error ? err.message : String(err), { cause: err })
    }
    try {
        verifyCommitK(t, key)
    } catch (err) {
        key.fill(0)
        throw err
    }
    return key
}
