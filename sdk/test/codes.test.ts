/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The code table and retry rule, checked against
// testdata/error_retry_vectors.json, which Go generates from its own errorKinds
// and retryable.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { errorKinds, markRetryable, newError, retryable } from '../src/codes.js'
import { type Kind, NodeReply, ProviderError, ZsError } from '../src/errors.js'

interface RetryCase {
    kind: Kind
    code: string
    provider_code?: string
    node_status?: number
    retryable: boolean
}

const cases: RetryCase[] = JSON.parse(
    readFileSync(new URL('../../testdata/error_retry_vectors.json', import.meta.url), 'utf8'),
)

// As Go's runRetryVector: a provider code makes the cause a ProviderError
// carried by a reply of node_status; node_status alone, a NodeReply.
function errorOf(c: RetryCase): ZsError {
    let cause: unknown
    if (c.provider_code !== undefined) cause = new ProviderError(c.provider_code, '', c.node_status ?? 0)
    else if (c.node_status !== undefined) cause = new NodeReply(c.node_status)
    return new ZsError({ kind: c.kind, code: c.code, message: '', cause })
}

describe('errorKinds', () => {
    // Go writes one causeless row per code it lists, and no other.
    it('lists exactly the codes Go does, under the same kinds', () => {
        const goTable = cases
            .filter((c) => c.provider_code === undefined && c.node_status === undefined)
            .map((c) => [c.code, c.kind])
        expect([...errorKinds].sort(([a], [b]) => (a < b ? -1 : 1))).toEqual(goTable)
    })
})

describe('retryable', () => {
    it.each(cases.map((c) => [c.kind, c.code, c.provider_code, c.node_status, c.retryable, c] as const))(
        '%s %s (provider %j, status %j) → %s',
        (_kind, _code, _pc, _ns, want, c) => {
            expect(retryable(errorOf(c))).toBe(want)
        },
    )
})

describe('newError', () => {
    it('takes the kind from the table and leaves retryable to delivery', () => {
        const e = newError('operators_busy', 'all busy', { retryAfter: 2000 })
        expect(e).toBeInstanceOf(ZsError)
        expect([e.kind, e.code, e.message, e.retryable, e.retryAfter, e.paid]).toEqual([
            'busy',
            'operators_busy',
            'all busy',
            false,
            2000,
            false,
        ])
    })

    it('makes an unlisted code internal, including an Object.prototype name', () => {
        expect(newError('no_such_code', 'm').kind).toBe('internal')
        expect(newError('toString', 'm').kind).toBe('internal')
        expect(newError('constructor', 'm').kind).toBe('internal')
    })

    it('carries paid, the ticket and the cause', () => {
        const ticket = { id: 't', signed: {} as never, target: { op: 1, node: 2 } }
        const cause = new NodeReply(502)
        const e = newError('stream_interrupted', 'm', { paid: true, ticket, cause })
        expect([e.paid, e.ticket, e.cause]).toEqual([true, ticket, cause])
    })
})

describe('markRetryable', () => {
    it('applies the rule', () => {
        const busy = newError('operators_busy', 'm')
        markRetryable(busy, false)
        expect(busy.retryable).toBe(true)
        const ctx = newError('context_length_exceeded', 'm')
        markRetryable(ctx, false)
        expect(ctx.retryable).toBe(false)
    })

    // The caller ended the turn: nothing is waiting for a resend.
    it('is never retryable when the caller aborted', () => {
        const e = newError('operators_busy', 'm')
        markRetryable(e, true)
        expect(e.retryable).toBe(false)
        // Even an error already marked retryable.
        const marked = newError('operators_busy', 'm')
        markRetryable(marked, false)
        markRetryable(marked, true)
        expect(marked.retryable).toBe(false)
    })

    // A refusal under the node's own code is built directly, not through the
    // table, and the delivery rule still reads it.
    it('decides a node refusal built outside the table', () => {
        const e = new ZsError({ kind: 'interrupted', code: 'ticket_invalid', message: 'm', cause: new NodeReply(402) })
        markRetryable(e, false)
        expect(e.retryable).toBe(true)
    })

    // The decoder builds the provider failure before the reply's status is
    // known; the verdict must read the status set afterwards.
    it('reads a status the cause learned after the error was built', () => {
        const pe = new ProviderError('', 'm')
        const e = newError('upstream_error', 'm', { cause: pe })
        pe.status = 503
        markRetryable(e, false)
        expect(e.retryable).toBe(true)
    })
})

describe('ProviderError', () => {
    it("keeps the node's message verbatim, empty when it gave none", () => {
        expect(new ProviderError('provider_error', '').message).toBe('')
        expect(new ProviderError('', 'provider error').message).toBe('provider error')
        expect(new ProviderError('x', 'm').name).toBe('ProviderError')
    })

    // A stream frame carries no reply status, and a codeless failure in one is
    // not one the node retried.
    it('defaults to status 0, which is not retryable', () => {
        const pe = new ProviderError('', 'm')
        expect(pe.status).toBe(0)
        expect(retryable(newError('upstream_error', 'm', { cause: pe }))).toBe(false)
    })
})

describe('NodeReply', () => {
    it("names the status as Go's does", () => {
        const r = new NodeReply(502)
        expect([r.status, r.message, r.name]).toEqual([502, 'operator returned HTTP 502', 'NodeReply'])
    })
})
