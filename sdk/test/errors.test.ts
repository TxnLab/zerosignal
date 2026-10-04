/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The ZsError a caller reads, not just the init it is built from: the
// vocabulary test pins ZsErrorInit's names, and these pin that each reaches
// the error under the same name.

import { describe, expect, it } from 'vitest'

import { type ZsErrorInit, ZsError, configError, isZsError } from '../src/index.js'

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
