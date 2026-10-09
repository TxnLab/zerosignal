/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The ZsError a caller reads, not just the init it is built from: the
// vocabulary test pins ZsErrorInit's names, and these pin that each reaches
// the error under the same name.

import { describe, expect, it } from 'vitest'

import { type ZsErrorInit, ZsError, configError, findError, isZsError } from '../src/index.js'

describe('ZsError', () => {
    it('carries every init field under its own name', () => {
        const init = {
            kind: 'busy',
            code: 'no_capacity',
            message: 'm',
            retryable: true,
            retryAfter: 1500,
            paid: true,
            ticket: { id: 't', signed: {} as never, target: { op: 3, node: 7 } },
            cause: new Error('under'),
        } satisfies Required<ZsErrorInit>
        const e = new ZsError(init)
        for (const f of Object.keys(init) as (keyof typeof init)[]) {
            expect(e[f], f).toBe(init[f])
        }
        expect(e.name).toBe('ZsError')
        expect(isZsError(e)).toBe(true)
    })

    // A caller branching on .kind after this guard must not get a plain error.
    it('is told apart from other errors and lookalikes', () => {
        expect(isZsError(new Error('x'))).toBe(false)
        expect(isZsError({ kind: 'busy', code: 'x', message: 'm' })).toBe(false)
    })

    // paid true would tell the caller escrow was opened.
    it('defaults to not retryable and not paid, with no cause', () => {
        const e = new ZsError({ kind: 'busy', code: 'x', message: 'm' })
        expect([e.retryable, e.paid]).toEqual([false, false])
        expect('cause' in e).toBe(false)
        expect([e.retryAfter, e.ticket]).toEqual([undefined, undefined])
    })

    it('reports a bad Config as invalid_config, nothing paid', () => {
        const e = configError('no')
        expect([e.kind, e.code, e.message, e.paid, e.retryable]).toEqual(['invalid_request', 'invalid_config', 'no', false, false])
    })
})

describe('findError', () => {
    class A extends Error {}
    class B extends Error {}

    it('finds a type through the cause chain', () => {
        const a = new A('a')
        expect(findError(new Error('x', { cause: new Error('y', { cause: a }) }), A)).toBe(a)
        expect(findError(new Error('x', { cause: a }), B)).toBeUndefined()
        expect(findError(a, A)).toBe(a)
    })

    // Go's errors.As walks every %w of a multi-wrap.
    it('finds a type in any error an AggregateError holds, and under it', () => {
        const a = new A('a')
        const b = new B('b')
        const agg = new AggregateError([a, new Error('z', { cause: b })], 'both', { cause: a })
        const top = new Error('top', { cause: agg })
        expect(findError(top, A)).toBe(a)
        expect(findError(top, B)).toBe(b)
        expect(findError(top, AggregateError)).toBe(agg)
    })

    // Go's errors.As finishes the first %w's chain before the second's.
    it("walks depth first, the first held error's chain before the next", () => {
        const deep = new A('deep')
        const shallow = new A('shallow')
        expect(findError(new AggregateError([new Error('x', { cause: deep }), shallow], ''), A)).toBe(deep)
    })

    it('ends on a cyclic chain and ignores non-errors', () => {
        const x = new Error('x')
        const y = new Error('y', { cause: x })
        Object.defineProperty(x, 'cause', { value: y })
        expect(findError(x, A)).toBeUndefined()
        expect(findError('a string', Error)).toBeUndefined()
        expect(findError(undefined, Error)).toBeUndefined()
    })
})
