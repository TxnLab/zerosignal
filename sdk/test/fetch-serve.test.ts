/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// zs.fetch, porting go/zs handler/emit_test.go and the POST routes of
// handlers_test.go and server_test.go, plus what a fetch function adds: the
// caller's abort and a cancelled body ending the turn.

import { describe, expect, it, vi } from 'vitest'

import { ZsError, NodeReply } from '../src/errors.js'
import type { Event, ReceiptVerified } from '../src/events.js'
import { type FetchTarget, MAX_CLIENT_BODY_BYTES, type ServeOptions, goBlank, openAIFetch, serveTurn } from '../src/fetch/serve.js'
import type { Request as TurnRequest, Stream } from '../src/turn.js'
import { recLogger } from './turn-fixtures.js'

const enc = new TextEncoder()
const dec = new TextDecoder()
const CHAT_URL = 'https://zerosignal.invalid/v1/chat/completions'

// script is a turn's events as a fixed sequence, ended by err when given.
// stoppedAt is how many events were taken before the reader stopped, or -1
// when it read to the end.
function script(events: Event[], err?: unknown) {
    const s = { stoppedAt: -1 }
    async function* run(): AsyncGenerator<Event> {
        let taken = 0
        let ended = false
        try {
            for (const ev of events) {
                taken++
                yield ev
            }
            ended = true
            if (err !== undefined) throw err
        } finally {
            if (!ended) s.stoppedAt = taken
        }
    }
    return Object.assign(s, { events: run() })
}

const started = (status: number, streaming: boolean, header = new Headers()): Event => ({ type: 'response.started', status, header, streaming })
const frame = (data: string, sealed = true): Event => ({ type: 'frame', event: '', id: '', data: enc.encode(data), comment: '', retry: 0, sealed })
const done: Event = { type: 'done', finishReason: '', incompleteReason: '', empty: false }
const receipt = (): ReceiptVerified =>
    ({
        type: 'receipt.verified',
        receipt: { ticket_id: 'tid', amount_charged: 0, actual_input_count: 0, actual_output_count: 0 },
        ticket: { max_price: 0, min_price: 0 },
        target: { op: 0, node: 0 },
        ownerAddr: '',
        openFeesMicroAlgos: 0,
        settleFeesMicroAlgos: 0,
        algoUsd: 0,
        feeBps: 0,
        feeBpsKnown: false,
    }) as unknown as ReceiptVerified

const opts = (o: Partial<ServeOptions> = {}): ServeOptions => ({ legacy: false, usageFrame: false, fundingHint: 'Or use the web app.', ...o })

const sse = (data: string) => `data: ${data}\n\n`

describe('serveTurn', () => {
    // A sealed reply passes the node's headers through too, but not its
    // Retry-After uncapped. A value that reads as no hint, an HTTP-date or
    // zero, is removed rather than copied, since a client would still honour it.
    for (const status of [200, 400, 503]) {
        it.each([
            { node: '86400', want: '300' },
            { node: '7', want: '7' },
            { node: '', want: null },
            { node: '0', want: null },
            { node: 'Wed, 21 Oct 2099 07:28:00 GMT', want: null },
        ])(`caps a ${status} reply's Retry-After $node`, async ({ node, want }) => {
            const h = new Headers({ 'X-Should-Retry': 'true' })
            if (node !== '') h.set('Retry-After', node)
            const res = await serveTurn(script([started(status, false, h), frame('{}'), done]).events, opts())
            expect(res.headers.get('Retry-After')).toBe(want)
            // An error reply comes after the open, so resending it pays again.
            expect(res.headers.get('X-Should-Retry')).toBe(status >= 400 ? 'false' : 'true')
        })
    }

    // An operator's own error passes through with its status and body, and the
    // SDK's X-Zs-* headers survive the strip while the node's do not.
    it('passes an operator’s error through', async () => {
        const body = enc.encode('{"error":{"message":"m","type":"invalid_request_error","code":"ticket_invalid"}}')
        const node = new Headers({
            'Content-Type': 'application/json; charset=utf-8',
            'Content-Length': '5',
            'Retry-After': '86400',
            'X-Zs-Max-Output-Clamped': '999',
            'X-Zs-Future-Field': 'leak-me',
        })
        const err = new ZsError({
            kind: 'interrupted',
            code: 'ticket_invalid',
            message: '',
            retryAfter: 300_000,
            cause: new NodeReply(402, { header: node, body }),
        })
        const res = await serveTurn(script([{ type: 'max_output.clamped', ceiling: 100 }], err).events, opts())
        expect(res.status).toBe(402)
        expect(new Uint8Array(await res.arrayBuffer())).toEqual(body)
        expect(res.headers.get('X-Zs-Max-Output-Clamped')).toBe('100')
        expect(res.headers.get('X-Zs-Future-Field')).toBeNull()
        expect(res.headers.get('Retry-After')).toBe('300')
        expect(res.headers.get('Content-Type')).toBe('application/json; charset=utf-8')
        expect(res.headers.get('X-Should-Retry')).toBe('false')
    })

    // A body the SDK wrote in place of one it could not parse is JSON
    // whatever the operator labelled its page; and an error with no hint
    // sends none, even where the node's page had one.
    it('labels a replaced body JSON and sends only the error’s hint', async () => {
        const html = new ZsError({
            kind: 'interrupted',
            code: '',
            message: '',
            cause: new NodeReply(504, { header: new Headers({ 'Content-Type': 'text/html' }), body: enc.encode('{}\n'), contentType: 'application/json' }),
        })
        let res = await serveTurn(script([], html).events, opts())
        expect(res.headers.get('Content-Type')).toBe('application/json')
        const day = new ZsError({
            kind: 'interrupted',
            code: '',
            message: '',
            cause: new NodeReply(503, { header: new Headers({ 'Retry-After': '86400' }), body: enc.encode('{}') }),
        })
        res = await serveTurn(script([], day).events, opts())
        expect(res.headers.get('Retry-After')).toBeNull()
    })

    // An SDK error is shaped by its code, and wallet_unfunded is completed with
    // what the payer can do about it.
    it('shapes an error and hints at funding', async () => {
        const res = await serveTurn(script([], new ZsError({ kind: 'funds', code: 'wallet_unfunded', message: 'payer has no USDC.' })).events, opts())
        expect(res.status).toBe(402)
        expect(await res.text()).toContain('payer has no USDC. Or use the web app.')
        const plain = await serveTurn(script([], new Error('boom')).events, opts())
        expect(plain.status).toBe(500)
        expect(await plain.text()).toBe('{"error":{"message":"boom","type":"proxy_error"}}\n')
    })

    it('starts a stream with the node’s status, as SSE that is never resent', async () => {
        const res = await serveTurn(script([{ type: 'max_output.clamped', ceiling: 64 }, started(202, true)]).events, opts())
        expect(res.status).toBe(202)
        const got: Record<string, string> = {}
        res.headers.forEach((v, k) => (got[k] = v))
        expect(got).toEqual({
            'cache-control': 'no-cache',
            connection: 'keep-alive',
            'content-type': 'text/event-stream',
            'x-accel-buffering': 'no',
            'x-should-retry': 'false',
            'x-zs-max-output-clamped': '64',
        })
    })

    // A /v1/completions caller gets its content in text-completion shape, but
    // a frame the node did not seal reaches it unchanged, and a chat caller's
    // content is never reshaped.
    it('reshapes only a legacy caller’s sealed content', async () => {
        const chunk = '{"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hi"},"finish_reason":null}]}'
        let res = await serveTurn(
            script([started(200, true), frame(chunk), frame(chunk, false), receipt()]).events,
            opts({ legacy: true, usageFrame: true }),
        )
        const got = (await res.text()).trim().split('\n\n')
        expect(got).toHaveLength(3)
        expect(got[0]).toBe('data: {"choices":[{"finish_reason":null,"index":0,"logprobs":null,"text":"Hi"}],"id":"c","object":"text_completion"}')
        expect(got[1]).toBe(`data: ${chunk}`)
        expect(got[2]).toMatch(/^event: zs\.usage\n/)

        res = await serveTurn(script([started(200, true), frame(chunk)]).events, opts())
        expect(await res.text()).toBe(sse(chunk))

        res = await serveTurn(
            script([
                started(200, false),
                frame('{"id":"c","object":"chat.completion","choices":[{"index":0,"message":{"role":"assistant","content":"Hi"},"finish_reason":"stop"}]}'),
                done,
            ]).events,
            opts({ legacy: true }),
        )
        expect(await res.text()).toBe('{"choices":[{"finish_reason":"stop","index":0,"logprobs":null,"text":"Hi"}],"id":"c","object":"text_completion"}')
    })

    it('sends the usage frame only to a caller who asked', async () => {
        const res = await serveTurn(script([started(200, true), receipt()]).events, opts())
        expect(await res.text()).toBe('')
    })

    // A whole reply is held until done, so its usage headers precede the
    // body, and the node's own X-Zs-* headers are dropped.
    it('puts a whole reply’s usage in its headers', async () => {
        const node = new Headers({ 'X-Zs-Future-Field': 'leak-me', 'X-Request-Id': 'r1', 'Content-Length': '3' })
        const res = await serveTurn(script([started(200, false, node), frame('{"ok":true}'), receipt(), done]).events, opts())
        expect(res.status).toBe(200)
        expect(await res.text()).toBe('{"ok":true}')
        expect(res.headers.get('X-Zs-Ticket-Id')).toBe('tid')
        expect(res.headers.get('X-Zs-Future-Field')).toBeNull()
        expect(res.headers.get('X-Request-Id')).toBe('r1')
        expect(res.headers.get('Content-Type')).toBe('application/json')
    })

    // A frame's bytes reach the caller as the node sent them.
    it('writes a frame’s bytes unchanged', async () => {
        const raw = Uint8Array.of(0x7b, 0xff, 0x7d)
        const ev: Event = { type: 'frame', event: 'e', id: 'i', data: raw, comment: 'c', retry: 5, sealed: true }
        const res = await serveTurn(script([started(200, true), ev]).events, opts())
        const want = new Uint8Array([...enc.encode(': c\nevent: e\nid: i\nretry: 5\ndata: '), ...raw, ...enc.encode('\n\n')])
        expect(new Uint8Array(await res.arrayBuffer())).toEqual(want)
        const whole = await serveTurn(script([started(200, false), { ...ev, event: '', id: '', comment: '', retry: 0 }, done]).events, opts())
        expect(new Uint8Array(await whole.arrayBuffer())).toEqual(raw)
    })

    // A turn that breaks after the stream opened ends in an SSE error frame,
    // not a status the caller can no longer receive.
    it('ends a stream that broke with an error frame and [DONE]', async () => {
        const res = await serveTurn(
            script([started(200, true), frame('a')], new ZsError({ kind: 'interrupted', code: 'stream_interrupted', message: '' })).events,
            opts(),
        )
        expect(res.status).toBe(200)
        expect(await res.text()).toBe(sse('a') + sse('{"error":{"message":"stream interrupted","type":"proxy_error","code":"stream_error"}}') + sse('[DONE]'))
    })

    it('answers a turn with no response as an empty 200', async () => {
        const res = await serveTurn(script([{ type: 'max_output.clamped', ceiling: 1 }, done]).events, opts())
        expect(res.status).toBe(200)
        expect(await res.text()).toBe('')
        expect(res.headers.get('X-Zs-Max-Output-Clamped')).toBe('1')
    })

    // A caller who stops reading the body has left: the turn is stopped.
    it('stops the turn when the caller cancels the body', async () => {
        const stop = vi.fn()
        const s = script([started(200, true), frame('one'), frame('two'), frame('three')])
        const res = await serveTurn(s.events, opts({ stop }))
        const reader = res.body!.getReader()
        expect(dec.decode((await reader.read()).value)).toBe(sse('one'))
        await reader.cancel()
        expect(stop).toHaveBeenCalledTimes(1)
        await vi.waitFor(() => expect(s.stoppedAt).toBe(2))
    })

    it('rejects with the caller’s reason when it aborts before the response', async () => {
        const stop = vi.fn()
        const caller = new AbortController()
        let release!: () => void
        const held = new Promise<void>((r) => (release = r))
        const s = { stoppedAt: -1 }
        async function* events(): AsyncGenerator<Event> {
            try {
                yield started(200, false)
                await held
                yield done
            } finally {
                s.stoppedAt = 1
            }
        }
        const p = serveTurn(events(), opts({ stop, caller: caller.signal }))
        const reason = new Error('gone')
        setTimeout(() => caller.abort(reason), 5)
        await expect(p).rejects.toBe(reason)
        expect(stop).toHaveBeenCalledTimes(1)
        release()
        await vi.waitFor(() => expect(s.stoppedAt).toBe(1))
    })

    it('errors the body with the caller’s reason when it aborts mid-stream', async () => {
        const stop = vi.fn()
        const caller = new AbortController()
        const s = script([started(200, true), frame('one'), frame('two')])
        const res = await serveTurn(s.events, opts({ stop, caller: caller.signal }))
        const reader = res.body!.getReader()
        await reader.read()
        const reason = new Error('gone')
        caller.abort(reason)
        await expect(reader.read()).rejects.toBe(reason)
        expect(stop).toHaveBeenCalledTimes(1)
    })

    // A status that can't carry a body: the reply's is dropped, and a stream
    // under one can deliver nothing, so its turn is stopped.
    it('drops the body under a status that can’t carry one', async () => {
        const reply = await serveTurn(script([started(204, false), frame('{"a":1}'), done]).events, opts())
        expect(reply.status).toBe(204)
        expect(reply.body).toBeNull()
        const stop = vi.fn()
        const s = script([started(204, true), frame('x')])
        const res = await serveTurn(s.events, opts({ stop }))
        expect(res.status).toBe(204)
        expect(res.body).toBeNull()
        expect(stop).toHaveBeenCalledTimes(1)
        await vi.waitFor(() => expect(s.stoppedAt).toBe(1))
    })
})

describe('serveTurn, the node’s headers', () => {
    // The fetch that read the node's answer decoded a gzip or br body but kept
    // the header, and a whole reply's body is the opened plaintext anyway. A
    // stale length or coding would make a re-served response unreadable.
    it('drops the node’s length and coding from a whole reply', async () => {
        const node = new Headers({ 'Content-Length': '3', 'Content-Encoding': 'zstd', 'X-Zs-Max-Output-Clamped': '999' })
        const res = await serveTurn(
            script([{ type: 'max_output.clamped', ceiling: 100 }, started(200, false, node), frame('{"ok":true}'), done]).events,
            opts(),
        )
        expect(res.headers.get('Content-Length')).toBeNull()
        expect(res.headers.get('Content-Encoding')).toBeNull()
        // The SDK's clamp marker, not the node's.
        expect(res.headers.get('X-Zs-Max-Output-Clamped')).toBe('100')
        expect(await res.text()).toBe('{"ok":true}')
    })

    it.each([
        { coding: 'gzip', kept: null },
        { coding: 'GZIP, br', kept: null },
        { coding: 'deflate', kept: null },
        { coding: 'zstd', kept: 'zstd' },
        { coding: 'gzip, zstd', kept: 'gzip, zstd' },
    ])('drops a passed-through error’s $coding coding only when fetch decoded it', async ({ coding, kept }) => {
        const node = new Headers({ 'Content-Length': '2', 'Content-Encoding': coding })
        const err = new ZsError({ kind: 'interrupted', code: '', message: '', cause: new NodeReply(500, { header: node, body: enc.encode('{}') }) })
        const res = await serveTurn(script([], err).events, opts())
        expect(res.headers.get('Content-Encoding')).toBe(kept)
        expect(res.headers.get('Content-Length')).toBeNull()
    })

    it('passes the error’s retry advice on with a node’s error', async () => {
        const err = new ZsError({
            kind: 'busy',
            code: 'operators_busy',
            message: '',
            retryable: true,
            cause: new NodeReply(503, { header: new Headers({ 'X-Should-Retry': 'false' }), body: enc.encode('{}') }),
        })
        const res = await serveTurn(script([], err).events, opts())
        expect(res.headers.get('X-Should-Retry')).toBe('true')
    })

    // A Response takes 200 to 599; a node status outside that is a bad gateway.
    it.each([600, 999, 0])('answers a node status of %i as 502', async (status) => {
        const reply = await serveTurn(script([started(status, false), frame('{"a":1}'), done]).events, opts())
        expect(reply.status).toBe(502)
        expect(await reply.text()).toBe('{"a":1}')
        const stream = await serveTurn(script([started(status, true), frame('x')]).events, opts())
        expect(stream.status).toBe(502)
        expect(await stream.text()).toBe(sse('x'))
    })

    it('ends the stream and the turn when rendering a frame throws', async () => {
        const stop = vi.fn()
        const broken = {
            type: 'frame',
            event: '',
            id: '',
            get data(): Uint8Array {
                throw new Error('unreadable')
            },
            comment: '',
            retry: 0,
            sealed: true,
        } as Event
        const res = await serveTurn(script([started(200, true), broken]).events, opts({ stop }))
        await expect(res.text()).rejects.toThrow('unreadable')
        expect(stop).toHaveBeenCalledTimes(1)
    })
})

describe('goBlank', () => {
    // Go reads a header's bytes as UTF-8, so a lone 0xA0 is an invalid byte,
    // not a space, while the UTF-8 for U+00A0 is one.
    it.each([
        [null, true],
        ['', true],
        ['\t\v\f \r\n', true],
        ['Â ', true],
        ['â\u0080\u0083', true],
        [' ', false],
        ['\u0085', false],
        ['﻿', false],
        ['1', false],
        [' x ', false],
    ])('%j is blank: %s', (v, want) => {
        expect(goBlank(v)).toBe(want)
    })
})

interface Recorded {
    req: TurnRequest
    signal: AbortSignal | undefined
}

// target answers every turn with events, recording what it was asked.
function target(events: () => AsyncIterable<Event> = () => script([started(200, false), frame('{"ok":true}'), done]).events) {
    const calls: Recorded[] = []
    return {
        calls,
        stream(req: TurnRequest, signal?: AbortSignal): Stream {
            calls.push({ req, signal })
            return { events } as unknown as Stream
        },
    }
}

describe('openAIFetch', () => {
    it('answers an unrouted path or method as Go’s mux does', async () => {
        const t = target()
        const f = openAIFetch(t)
        let res = await f('https://zerosignal.invalid/v1/embeddings', { method: 'POST', body: '{}' })
        expect(res.status).toBe(404)
        expect(await res.text()).toBe('404 page not found\n')
        expect(res.headers.get('Content-Type')).toBe('text/plain; charset=utf-8')
        res = await f(CHAT_URL)
        expect(res.status).toBe(405)
        expect(res.headers.get('Allow')).toBe('POST')
        expect(await res.text()).toBe('Method Not Allowed\n')
        res = await f('https://zerosignal.invalid/chat/completions', { method: 'POST', body: '{}' })
        expect(res.status).toBe(404)
        expect(t.calls).toEqual([])
    })

    it('hands the turn the body and the headers it honours', async () => {
        const t = target()
        const f = openAIFetch(t)
        const res = await f(new URL(CHAT_URL), {
            method: 'POST',
            body: '{"model":"m"}',
            headers: { 'Content-Type': 'application/json', 'X-Zs-Require-TEE': 'yes', 'X-Zs-Relay': 'off', Authorization: 'Bearer sk' },
        })
        expect(await res.text()).toBe('{"ok":true}')
        expect(t.calls).toHaveLength(1)
        const { req, signal } = t.calls[0]!
        expect(req).toEqual({
            endpoint: '/v1/chat/completions',
            body: enc.encode('{"model":"m"}'),
            contentType: 'application/json',
            requireTee: true,
            relay: 'off',
            framesOnly: true,
        })
        expect(signal).toBeInstanceOf(AbortSignal)
        await f(new Request('https://zerosignal.invalid/v1/responses', { method: 'POST', body: '{}', headers: { 'X-Zs-Require-TEE': '' } }))
        expect(t.calls[1]!.req).toMatchObject({ endpoint: '/v1/responses', requireTee: false, relay: '', contentType: 'text/plain;charset=UTF-8' })
    })

    it.each(['/v1/images/generations', '/v1/images/edits'])('routes %s', async (path) => {
        const t = target()
        await openAIFetch(t)(`https://zerosignal.invalid${path}`, { method: 'POST', body: '{}' })
        expect(t.calls[0]!.req.endpoint).toBe(path)
    })

    it('passes a multipart body and its boundary through', async () => {
        const t = target()
        const form = new FormData()
        form.set('prompt', 'p')
        await openAIFetch(t)('https://zerosignal.invalid/v1/images/edits', { method: 'POST', body: form })
        const { req } = t.calls[0]!
        expect(req.contentType).toMatch(/^multipart\/form-data; boundary=/)
        expect(dec.decode(req.body as Uint8Array)).toContain('name="prompt"')
    })

    it('opts a stream into the usage frame on the caller’s header', async () => {
        const events = () => script([started(200, true), receipt()]).events
        const f = openAIFetch(target(events))
        expect(await (await f(CHAT_URL, { method: 'POST', body: '{}' })).text()).toBe('')
        const res = await f(CHAT_URL, { method: 'POST', body: '{}', headers: { 'X-Zs-Usage-Frame': '1' } })
        expect(await res.text()).toMatch(/^event: zs\.usage\ndata: \{"type":"zs\.usage","ticket_id":"tid"/)
    })

    it('takes a body at the cap and refuses one past it', async () => {
        const t = target()
        const f = openAIFetch(t)
        let res = await f(CHAT_URL, { method: 'POST', body: new Uint8Array(MAX_CLIENT_BODY_BYTES) })
        expect(res.status).toBe(200)
        expect((t.calls[0]!.req.body as Uint8Array).length).toBe(MAX_CLIENT_BODY_BYTES)
        res = await f(CHAT_URL, { method: 'POST', body: new Uint8Array(MAX_CLIENT_BODY_BYTES + 1) })
        expect(res.status).toBe(413)
        expect(await res.text()).toBe('{"error":{"message":"request body exceeds proxy limit","type":"invalid_request_error","code":"body_too_large"}}\n')
        expect(res.headers.get('X-Should-Retry')).toBe('false')
        expect(t.calls).toHaveLength(1)
    })

    it('answers a body that fails to read with 400 read_body', async () => {
        const t = target()
        const body = new ReadableStream<Uint8Array>({
            pull(ctl) {
                ctl.error(new Error('reset'))
            },
        })
        const res = await openAIFetch(t)(CHAT_URL, { method: 'POST', body, duplex: 'half' } as RequestInit)
        expect(res.status).toBe(400)
        expect(await res.text()).toContain('"code":"read_body"')
        expect(t.calls).toEqual([])
    })

    it('rejects a request whose signal already aborted, starting no turn', async () => {
        const t = target()
        const reason = new Error('gone')
        await expect(openAIFetch(t)(CHAT_URL, { method: 'POST', body: '{}', signal: AbortSignal.abort(reason) })).rejects.toBe(reason)
        expect(t.calls).toEqual([])
    })

    // The caller's abort and a cancelled body both reach the turn's signal,
    // which is how the forwarder learns the caller left.
    it('ends the turn’s signal when the caller cancels the body', async () => {
        const t = target(() => script([started(200, true), frame('a'), frame('b')]).events)
        const res = await openAIFetch(t)(CHAT_URL, { method: 'POST', body: '{}' })
        const signal = t.calls[0]!.signal!
        expect(signal.aborted).toBe(false)
        await res.body!.cancel()
        expect(signal.aborted).toBe(true)
    })

    it('ends the turn’s signal when the caller aborts', async () => {
        const t = target(() => script([started(200, true), frame('a'), frame('b')]).events)
        const caller = new AbortController()
        const res = await openAIFetch(t)(CHAT_URL, { method: 'POST', body: '{}', signal: caller.signal })
        const signal = t.calls[0]!.signal!
        caller.abort(new Error('gone'))
        expect(signal.aborted).toBe(true)
        await expect(res.text()).rejects.toThrow('gone')
    })

    it('rewrites a /v1/completions request into chat, and refuses one it can’t', async () => {
        const t = target(() =>
            script([
                started(200, false),
                frame('{"object":"chat.completion","choices":[{"index":0,"message":{"content":"Hi"},"finish_reason":"stop"}]}'),
                done,
            ]).events,
        )
        const f = openAIFetch(t)
        const res = await f('https://zerosignal.invalid/v1/completions', { method: 'POST', body: '{"model":"m","prompt":"p","echo":true}' })
        expect(await res.text()).toBe('{"choices":[{"finish_reason":"stop","index":0,"logprobs":null,"text":"Hi"}],"object":"text_completion"}')
        expect(t.calls[0]!.req.endpoint).toBe('/v1/chat/completions')
        expect(dec.decode(t.calls[0]!.req.body as Uint8Array)).toBe('{"messages":[{"content":"p","role":"user"}],"model":"m"}')

        const bad = await f('https://zerosignal.invalid/v1/completions', { method: 'POST', body: '{"prompt":[1,2]}' })
        expect(bad.status).toBe(400)
        expect(await bad.text()).toContain('"code":"unsupported_prompt"')
        expect(t.calls).toHaveLength(1)
    })

    // Go's recoverer: whatever breaks, the caller gets a 500 and the turn is
    // not left running.
    it('answers a broken handler with 500 and ends the turn', async () => {
        const logger = recLogger()
        let signal: AbortSignal | undefined
        const f = openAIFetch(
            {
                stream(_req, s) {
                    signal = s
                    return {
                        events: () => {
                            throw new Error('broken')
                        },
                    } as unknown as Stream
                },
            },
            { logger },
        )
        const res = await f(CHAT_URL, { method: 'POST', body: '{}' })
        expect(res.status).toBe(500)
        expect(await res.text()).toBe('{"error":{"message":"internal server error","type":"proxy_error","code":"panic"}}\n')
        expect(signal!.aborted).toBe(true)
        expect(logger.logged.map((l) => l.msg)).toContain('panic in handler')
    })

    it('logs a broken handler to the Client’s logger when the options leave it out', async () => {
        const logger = recLogger()
        const broken = {
            stream: () => ({ events: () => { throw new Error('broken') } }) as unknown as Stream,
            config: { network: { network: 'testnet' }, logger },
        }
        const res = await openAIFetch(broken)(CHAT_URL, { method: 'POST', body: '{}' })
        expect(res.status).toBe(500)
        expect(logger.logged.map((l) => l.msg)).toContain('panic in handler')
    })

    // Go's mux matches the unescaped path; a path that doesn't unescape never
    // reaches it.
    it('routes the unescaped path', async () => {
        const t = target()
        const f = openAIFetch(t)
        expect((await f('https://zerosignal.invalid/v1/chat/complet%69ons', { method: 'POST', body: '{}' })).status).toBe(200)
        expect(t.calls[0]!.req.endpoint).toBe('/v1/chat/completions')
        const bad = await f('https://zerosignal.invalid/v1/chat/%E0%A4%A', { method: 'POST', body: '{}' })
        expect(bad.status).toBe(400)
        expect(t.calls).toHaveLength(1)
    })

    // Headers joins repeated lines, where Go reads the first: joined, two
    // `required` lines would read as no preference.
    it('reads a repeated relay header’s first value', async () => {
        const t = target()
        const headers = new Headers()
        headers.append('X-Zs-Relay', 'required')
        headers.append('X-Zs-Relay', 'auto')
        await openAIFetch(t)(CHAT_URL, { method: 'POST', body: '{}', headers })
        expect(t.calls[0]!.req.relay).toBe('required')
    })

    it('hints at funding only on mainnet with a URL', async () => {
        const unfunded = () => script([], new ZsError({ kind: 'funds', code: 'wallet_unfunded', message: 'm.' })).events
        const body = async (o: Parameters<typeof openAIFetch>[1]) => (await openAIFetch(target(unfunded), o)(CHAT_URL, { method: 'POST', body: '{}' })).text()
        expect(await body({ network: 'mainnet', fundingUrl: 'https://app' })).toContain(
            'm. If this is your web account, you can add funds in the web app instead (https://app).',
        )
        expect(await body({ network: 'testnet', fundingUrl: 'https://app' })).toContain('"message":"m."')
        expect(await body({ network: 'mainnet' })).toContain('"message":"m."')
        // Only a wallet that needs funds is pointed at funding.
        const busy = () => script([], new ZsError({ kind: 'busy', code: 'operators_busy', message: 'm.' })).events
        const res = await openAIFetch(target(busy), { network: 'mainnet', fundingUrl: 'https://app' })(CHAT_URL, { method: 'POST', body: '{}' })
        expect(await res.text()).toContain('"message":"m."')
    })

    it('reads the network off the Client when the options leave it out, as Go’s handler does', async () => {
        const unfunded = () => script([], new ZsError({ kind: 'funds', code: 'wallet_unfunded', message: 'm.' })).events
        const onNet = (network: string) => ({ ...target(unfunded), config: { network: { network } } })
        const body = async (t: FetchTarget, o: Parameters<typeof openAIFetch>[1]) =>
            (await openAIFetch(t, o)(CHAT_URL, { method: 'POST', body: '{}' })).text()
        expect(await body(onNet('mainnet'), { fundingUrl: 'https://app' })).toContain('(https://app).')
        expect(await body(onNet('testnet'), { fundingUrl: 'https://app' })).toContain('"message":"m."')
        // An explicit network still outranks the Client's.
        expect(await body(onNet('mainnet'), { network: 'testnet', fundingUrl: 'https://app' })).toContain('"message":"m."')
    })
})
