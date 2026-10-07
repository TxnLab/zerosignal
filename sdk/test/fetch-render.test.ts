/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The OpenAI-compatible rendering of errors and receipts, against
// testdata/http_render_vectors.json, which Go's zs/handler generates, and
// porting handler/errors_shape_test.go, should_retry_test.go,
// headers_test.go and usage_test.go.

import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import { errorKinds } from '../src/codes.js'
import { type Kind, ZsError, kinds } from '../src/errors.js'
import type { ReceiptVerified } from '../src/events.js'
import {
    SHOULD_RETRY_HEADER,
    errorResponse,
    errorShapes,
    kindShapes,
    openAIErrorResponse,
    setRetryAfter,
} from '../src/fetch/errors.js'
import { copyResponseHeaders, snapshotZsHeaders, stripNodeZsHeaders, stripZsHeaders } from '../src/fetch/headers.js'
import { USAGE_FRAME_EVENT, USAGE_FRAME_HEADER, dollars, feeBreakdownFor, plainFloat, setUsageHeaders, usageFrame } from '../src/fetch/usage.js'

interface ErrorCase {
    kind: Kind
    code: string
    message: string
    retryable: boolean
    paid: boolean
    retry_after_ms: number
    status: number
    headers: Record<string, string>
    body: string
}

interface UsageCase {
    name: string
    ticket_id: string
    amount_charged: number
    actual_input_count: number
    actual_output_count: number
    max_price: number
    min_price: number
    op: number
    node: number
    owner_addr: string
    open_fees: number
    settle_fees: number
    algo_usd: number
    fee_bps: number
    fee_bps_known: boolean
    headers: Record<string, string>
    frame_event: string
    frame_data: string
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/http_render_vectors.json', import.meta.url), 'utf8')) as {
    errors: ErrorCase[]
    usage: UsageCase[]
}

function headersOf(h: Headers): Record<string, string> {
    const out: Record<string, string> = {}
    h.forEach((v, k) => {
        out[k] = v
    })
    return out
}

function receiptOf(c: UsageCase): ReceiptVerified {
    return {
        type: 'receipt.verified',
        receipt: {
            ticket_id: c.ticket_id,
            amount_charged: c.amount_charged,
            actual_input_count: c.actual_input_count,
            actual_output_count: c.actual_output_count,
        },
        ticket: { max_price: c.max_price, min_price: c.min_price },
        target: { op: c.op, node: c.node },
        ownerAddr: c.owner_addr,
        openFeesMicroAlgos: c.open_fees,
        settleFeesMicroAlgos: c.settle_fees,
        algoUsd: c.algo_usd,
        feeBps: c.fee_bps,
        feeBpsKnown: c.fee_bps_known,
    } as unknown as ReceiptVerified
}

describe('the error rendering vectors', () => {
    const cases = vectors.errors

    it('cover every code Go renders, and every kind', () => {
        const goCodes = new Set(vectors.errors.filter((c) => !c.code.startsWith('unlisted_') && c.code !== '').map((c) => c.code))
        // The extra rows reuse a listed code.
        expect([...errorShapes.keys()].sort()).toEqual([...goCodes].sort())
        expect(new Set(vectors.errors.filter((c) => c.code.startsWith('unlisted_')).map((c) => c.kind))).toEqual(new Set(kinds))
    })

    it.each(cases.map((c) => [`${c.code || '(no code)'} ${c.kind}`, c] as const))('render %s as Go does', async (_name, c) => {
        const r = errorResponse(
            new Headers(),
            new ZsError({
                kind: c.kind,
                code: c.code,
                message: c.message,
                retryable: c.retryable,
                paid: c.paid,
                ...(c.retry_after_ms > 0 ? { retryAfter: c.retry_after_ms } : {}),
            }),
        )
        expect(r.status).toBe(c.status)
        expect(headersOf(r.headers)).toEqual(c.headers)
        expect(await r.text()).toBe(c.body)
    })
})

describe('errorShapes', () => {
    // Every code a turn reports has a shape: an unlisted one falls back to
    // its kind's, which for several kinds is a different status.
    it('cover every code the SDK reports', () => {
        for (const code of errorKinds.keys()) expect(errorShapes.has(code), code).toBe(true)
    })

    it('cover every kind', () => {
        for (const k of kinds) expect(kindShapes.get(k), k).toBeDefined()
    })
})

describe('errorResponse', () => {
    // OpenAI's SDKs resend a 5xx on their own unless told not to, so every
    // error says whether to, and never yes once the turn is paid.
    it('advises a resend only for a retryable error that isn’t paid', () => {
        for (const code of errorShapes.keys()) {
            for (const retryable of [false, true]) {
                for (const paid of [false, true]) {
                    const r = errorResponse(new Headers(), new ZsError({ kind: 'internal', code, message: '', retryable, paid }))
                    expect(r.headers.get(SHOULD_RETRY_HEADER), `${code} ${retryable} ${paid}`).toBe(String(retryable && !paid))
                }
            }
        }
    })

    it('replaces retry advice already on the headers', () => {
        const h = new Headers({ [SHOULD_RETRY_HEADER]: 'true', 'Retry-After': '30' })
        const r = errorResponse(h, new ZsError({ kind: 'busy', code: 'operators_busy', message: '' }))
        expect(r.headers.get(SHOULD_RETRY_HEADER)).toBe('false')
        expect(r.headers.get('Retry-After')).toBeNull()
    })
})

describe('openAIErrorResponse', () => {
    // An error written outside a turn (a bad body, an unknown model) is never
    // advised as a resend.
    it('defaults to no resend, keeping advice already set', async () => {
        const r = openAIErrorResponse(new Headers(), 500, 'proxy_error', 'panic', 'x')
        expect(r.headers.get(SHOULD_RETRY_HEADER)).toBe('false')
        expect(r.headers.get('Content-Type')).toBe('application/json')
        expect(await r.json()).toEqual({ error: { message: 'x', type: 'proxy_error', code: 'panic' } })
        const kept = openAIErrorResponse(new Headers({ [SHOULD_RETRY_HEADER]: 'true' }), 503, 't', 'c', 'm')
        expect(kept.headers.get(SHOULD_RETRY_HEADER)).toBe('true')
        // Go reads an empty value as none.
        const empty = openAIErrorResponse(new Headers({ [SHOULD_RETRY_HEADER]: '' }), 503, 't', 'c', 'm')
        expect(empty.headers.get(SHOULD_RETRY_HEADER)).toBe('false')
    })

    it('leaves an empty code out of the body', async () => {
        const r = openAIErrorResponse(new Headers(), 500, 'proxy_error', '', 'boom')
        expect(await r.json()).toEqual({ error: { message: 'boom', type: 'proxy_error' } })
    })
})

describe('setRetryAfter', () => {
    it('writes whole seconds and removes a wait of none', () => {
        const h = new Headers({ 'Retry-After': '9' })
        setRetryAfter(h, 2999)
        expect(h.get('Retry-After')).toBe('2')
        setRetryAfter(h, 0)
        expect(h.get('Retry-After')).toBeNull()
        h.set('Retry-After', '9')
        setRetryAfter(h, undefined)
        expect(h.get('Retry-After')).toBeNull()
        setRetryAfter(h, 500)
        expect(h.get('Retry-After')).toBe('0')
        setRetryAfter(h, Infinity)
        expect(h.get('Retry-After')).toBeNull()
        h.set('Retry-After', '9')
        setRetryAfter(h, NaN)
        expect(h.get('Retry-After')).toBeNull()
        h.set('Retry-After', '9')
        setRetryAfter(h, -1500)
        expect(h.get('Retry-After')).toBeNull()
    })
})

describe('the response headers', () => {
    it('copy everything but the hop-by-hop and CORS headers, each replacing the caller’s', () => {
        const src = new Headers({
            Connection: 'keep-alive',
            'Transfer-Encoding': 'chunked',
            'Keep-Alive': 'timeout=5',
            Upgrade: 'h2c',
            'Proxy-Authenticate': 'Basic',
            'Proxy-Authorization': 'Basic eA==',
            TE: 'trailers',
            Trailers: 'X-Sum',
            'Access-Control-Allow-Origin': '*',
            'Content-Type': 'application/json',
            'X-Cool': 'yes',
        })
        const dst = new Headers({ 'X-Cool': 'no', 'Access-Control-Allow-Origin': 'https://app' })
        copyResponseHeaders(dst, src)
        expect(headersOf(dst)).toEqual({ 'access-control-allow-origin': 'https://app', 'content-type': 'application/json', 'x-cool': 'yes' })
    })

    it('copy every value of a repeated header', () => {
        const src = new Headers()
        src.append('Set-Cookie', 'a=1')
        src.append('Set-Cookie', 'b=2')
        const dst = new Headers()
        copyResponseHeaders(dst, src)
        expect(dst.getSetCookie()).toEqual(['a=1', 'b=2'])
    })

    // The node's X-Zs-* never reach the caller; the SDK's own, set before the
    // node answered, survive the node sending the same name.
    it('drop the node’s X-Zs-* and keep the SDK’s own', () => {
        const h = new Headers({ 'X-Zs-Max-Output-Clamped': '512' })
        const saved = snapshotZsHeaders(h)
        copyResponseHeaders(h, new Headers({ 'X-Zs-Max-Output-Clamped': '1', 'X-Zs-Receipt': 'r', 'x-zs-evil': 'e', 'X-Request-Id': 'q', 'X-Zsfoo': 'f' }))
        stripNodeZsHeaders(h, saved)
        expect(headersOf(h)).toEqual({ 'x-request-id': 'q', 'x-zs-max-output-clamped': '512', 'x-zsfoo': 'f' })
        stripZsHeaders(h)
        expect(headersOf(h)).toEqual({ 'x-request-id': 'q', 'x-zsfoo': 'f' })
    })
})

describe('the usage rendering vectors', () => {
    it.each(vectors.usage.map((c) => [c.name, c] as const))('render %s as Go does', (_name, c) => {
        const h = new Headers()
        setUsageHeaders(h, receiptOf(c))
        expect(headersOf(h)).toEqual(c.headers)
        const f = usageFrame(receiptOf(c))
        expect(f.event).toBe(c.frame_event)
        expect(new TextDecoder().decode(f.data)).toBe(c.frame_data)
        expect(f.sealed).toBe(false)
    })
})

describe('feeBreakdownFor', () => {
    // A rate that wasn't read is no breakdown at all; a genuine 0 rate is one.
    it('tells an unknown rate from a 0 fee', () => {
        expect(feeBreakdownFor(1_000_000, 1_100_000, 1000, false)).toBeUndefined()
        expect(feeBreakdownFor(1_000_000, 1_100_000, 1000, true)).toEqual({
            fee_bps: 1000,
            discount_bps: 0,
            platform_fee_microusdc: 100_000,
            refund_microusdc: 0,
            total_debit_microusdc: 1_100_000,
            total_debit_usd: 1.1,
        })
        expect(feeBreakdownFor(200_000, 500_000, 0, true)).toMatchObject({ platform_fee_microusdc: 0, refund_microusdc: 300_000 })
    })

    it('leaves out a total of nothing in dollars', () => {
        expect(feeBreakdownFor(0, 500, 100, true)).not.toHaveProperty('total_debit_usd')
    })
})

describe('the usage frame', () => {
    it('is the zs.usage event, without the fee object when the rate is unknown', () => {
        const c = vectors.usage.find((u) => !u.fee_bps_known)!
        const f = usageFrame(receiptOf(c))
        expect(f.event).toBe(USAGE_FRAME_EVENT)
        // The header a caller opts in with; Go's usageFrameHeader.
        expect(USAGE_FRAME_HEADER).toBe('X-Zs-Usage-Frame')
        expect(new TextDecoder().decode(f.data)).not.toContain('"fee"')
    })
})

describe('dollars', () => {
    // Go's %.6f rounds an exact half to even and never uses an exponent.
    it.each([
        [0.0078125, '$0.007812'],
        [0.0234375, '$0.023438'],
        [10.2265625, '$10.226562'],
        [186.6953125, '$186.695312'],
        [0.0000005, '$0.000000'],
        [0.0000015, '$0.000002'],
        [1.1, '$1.100000'],
        [0, '$0.000000'],
        [-0, '$-0.000000'],
        [-0.0078125, '$-0.007812'],
        [1e21, '$1000000000000000000000.000000'],
        [1.7365584472313273e22, '$17365584472313272729600.000000'],
        [Infinity, '$+Inf'],
        [-Infinity, '$-Inf'],
        [NaN, '$NaN'],
    ])('writes %s as %s', (x, want) => {
        expect(dollars(x)).toBe(want)
    })
})

describe('the usage frame’s JSON', () => {
    it('escapes as Go’s does', () => {
        const c = vectors.usage[0]!
        const f = usageFrame(receiptOf({ ...c, ticket_id: 'a<b>&c', owner_addr: `x${String.fromCharCode(0x2029)}y` }))
        const text = new TextDecoder().decode(f.data)
        expect(text).toContain('"ticket_id":"a\\u003cb\\u003e\\u0026c"')
        expect(text).toContain('"operator_owner_addr":"x\\u2029y"')
    })
})

describe('plainFloat', () => {
    it.each([
        [0.2134, '0.2134'],
        [0.0000001234, '0.0000001234'],
        [1e-7, '0.0000001'],
        [-2.5e-8, '-0.000000025'],
        [12345678.9, '12345678.9'],
        [1e21, '1000000000000000000000'],
        [1.5e22, '15000000000000000000000'],
        [1, '1'],
    ])('writes %s as %s', (x, want) => {
        expect(plainFloat(x)).toBe(want)
    })
})
