/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The error a Client call rejects with, mirroring proto/go/zs Error and Kind
// (names pinned by testdata/sdk_vocabulary_vectors.json). The low-level checks
// a Client is built from throw their own classified errors (ReceiptError,
// TicketSignatureInvalidError, …), which the Client wraps.

import type { Ticket } from './types.js'

/**
 * Kind tells the caller what to do about a ZsError. It is the stable
 * contract: codes may be added under a kind without breaking callers, so
 * branch on kind and treat code as diagnostic.
 */
export type Kind =
    | 'invalid_request'
    | 'context_exceeded'
    | 'no_route'
    | 'busy'
    | 'unreachable'
    | 'price_rejected'
    | 'funds'
    | 'spend_cap'
    | 'operator_fault'
    | 'upstream'
    | 'interrupted'
    | 'internal'

// as const, not Kind[]: the vocabulary test checks this list covers Kind, which
// a list typed as Kind[] always would.
export const kinds = [
    'invalid_request',
    'context_exceeded',
    'no_route',
    'busy',
    'unreachable',
    'price_rejected',
    'funds',
    'spend_cap',
    'operator_fault',
    'upstream',
    'interrupted',
    'internal',
] as const satisfies readonly Kind[]

export interface ZsErrorInit {
    kind: Kind
    /** The wire or SDK code that produced it, e.g. "no_capacity". */
    code: string
    message: string
    retryable?: boolean
    retryAfter?: number
    paid?: boolean
    ticket?: Ticket
    cause?: unknown
}

export class ZsError extends Error {
    readonly kind: Kind
    readonly code: string
    /**
     * Whether the same request, sent again as a new turn, could plausibly
     * succeed: the failure was capacity, transport or the provider's, not
     * something the caller must change first. False when the caller's own
     * abort ended the turn. A new turn is a new payment, so a caller weighing
     * a retry reads paid too; the SDK never resends after paid.
     */
    readonly retryable: boolean
    /** Milliseconds to wait before retrying, when the node named one. */
    readonly retryAfter?: number
    /**
     * Whether escrow was opened for this turn: the SDK submitted the open. A
     * node saying the open never confirmed doesn't clear it, since that is the
     * node's unverified claim.
     */
    readonly paid: boolean
    /**
     * The handle that can still move this turn's money, when paid. The SDK
     * keeps driving it to settle, protest or refund.
     */
    readonly ticket?: Ticket

    constructor(init: ZsErrorInit) {
        super(init.message, init.cause === undefined ? undefined : { cause: init.cause })
        this.name = 'ZsError'
        this.kind = init.kind
        this.code = init.code
        this.retryable = init.retryable ?? false
        this.paid = init.paid ?? false
        if (init.retryAfter !== undefined) this.retryAfter = init.retryAfter
        if (init.ticket !== undefined) this.ticket = init.ticket
    }
}

export function isZsError(err: unknown): err is ZsError {
    return err instanceof ZsError
}

/**
 * findError is Go's errors.As: the first error of type T in err's tree,
 * walking each cause and every error an AggregateError holds, in Go's order:
 * depth first, an AggregateError's errors left to right as a multi-%w wrap's,
 * so the first wrapped error's whole chain comes before the second. Bounded,
 * so a cyclic cause chain ends.
 */
export function findError<T extends Error>(err: unknown, type: abstract new (...args: never[]) => T): T | undefined {
    const seen = new Set<unknown>()
    const stack: unknown[] = [err]
    while (stack.length > 0 && seen.size < 64) {
        const e = stack.pop()
        if (!(e instanceof Error) || seen.has(e)) continue
        seen.add(e)
        if (e instanceof type) return e
        const next = e instanceof AggregateError ? [...(e.errors as unknown[]), e.cause] : [e.cause]
        for (let i = next.length - 1; i >= 0; i--) stack.push(next[i])
    }
    return undefined
}

/** configError is a ZsError for a Config the SDK cannot run with. */
export function configError(message: string): ZsError {
    return new ZsError({ kind: 'invalid_request', code: 'invalid_config', message })
}

/**
 * ProviderError is the cause of an upstream ZsError: the failure the node
 * reported inside its response, for the provider behind it. code is the node's,
 * not one of the SDK's; like message, which is the node's text verbatim and
 * empty when it gave none, it is the node's claim, for display and logs.
 */
export class ProviderError extends Error {
    readonly code: string
    /**
     * The HTTP status of the single-body reply that carried it, or 0 for a
     * stream frame. Not readonly: the body is decoded before the reply's
     * status is read.
     */
    status: number
    constructor(code: string, message: string, status = 0) {
        super(message)
        this.name = 'ProviderError'
        this.code = code
        this.status = status
    }
}

/**
 * NodeReply is a failed reply from the node, as the cause of a ZsError, so an
 * adapter can answer its caller with the node's status and body rather than
 * one of its own. header omits the node's X-Zs-* fields.
 */
export class NodeReply extends Error {
    readonly status: number
    readonly header: Headers
    readonly body: Uint8Array
    /** Replaces the node's when body is one the SDK wrote in place of one it could not parse; else ''. */
    readonly contentType: string
    constructor(status: number, reply: { header?: Headers; body?: Uint8Array; contentType?: string } = {}) {
        super(`operator returned HTTP ${status}`)
        this.name = 'NodeReply'
        this.status = status
        this.header = reply.header ?? new Headers()
        this.body = reply.body ?? new Uint8Array()
        this.contentType = reply.contentType ?? ''
    }
}
