/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A streamed turn's answer, porting go/zs sse_test.go, sse_tally_race_test.go,
// emit_test.go's tail-drain forward, forward_relay_attribution_test.go's
// streaming seam, and the stream cases of go/zs/handler dispatch_test.go and
// relay_truncation_test.go (the frame factory's opens, receipt and settle).

import { describe, expect, it, vi } from 'vitest'

import type { UsageReceipt } from '@txnlab/zs-proto/ticket'
import {
    PROTO_VERSION,
    RESPONSE_KEY_HEADER,
    ResponseSealer,
    SEALED_HEADER_SETTLE_GROUP,
    bodyHashFromFrames,
    generateEphemeralIdentity,
} from '@txnlab/zs-proto/wire'

import { IDAffinity } from '../src/affinity.js'
import type { SpendGuard } from '../src/config.js'
import type { ZsError } from '../src/errors.js'
import { withHeaderBackstop } from '../src/header-backstop.js'
import { IdleWatchdog, StreamIdleTimeoutError } from '../src/idle.js'
import type { Fetch } from '../src/ports.js'
import { ProtestReason, type Reserved } from '../src/parts.js'
import { DISPUTE_EXCERPT_CAP, SettleSlot } from '../src/receipt-check.js'
import { DRAIN_TAIL_TIMEOUT_MS } from '../src/response.js'
import type { RelayHop } from '../src/routing/relay.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import type { SealedCall } from '../src/sealed.js'
import {
    type FrameDeps,
    type FrameTransform,
    type GenComplete,
    type OutFrame,
    type StreamFrame,
    StreamTally,
    emptyFrame,
    forwardStream,
    frameFactory,
    frameSSE,
    pumpSSE,
} from '../src/stream.js'
import { TICKET_ID, VALID_GROUP, fixture, handleOf, recLogger } from './turn-fixtures.js'

const enc = new TextEncoder()
const dec = new TextDecoder()

/** A body that arrives in chunks of size bytes. */
function bodyOf(text: string | Uint8Array, size = 1 << 20): ReadableStream<Uint8Array> {
    const bytes = typeof text === 'string' ? enc.encode(text) : text
    let at = 0
    return new ReadableStream({
        pull(c) {
            if (at >= bytes.length) {
                c.close()
                return
            }
            c.enqueue(bytes.slice(at, at + size))
            at += size
        },
    })
}

/** A body the test writes to as it goes; it errors when signal aborts, as a fetch body does. */
function source(signal?: AbortSignal) {
    let ctrl!: ReadableStreamDefaultController<Uint8Array>
    const stream = new ReadableStream<Uint8Array>({
        start(c) {
            ctrl = c
        },
    })
    const s = {
        stream,
        push(text: string) {
            ctrl.enqueue(enc.encode(text))
        },
        close() {
            ctrl.close()
        },
        watch(sig: AbortSignal) {
            sig.addEventListener('abort', () => {
                try {
                    ctrl.error(sig.reason)
                } catch {
                    // already closed
                }
            })
        },
    }
    if (signal) s.watch(signal)
    return s
}

/** What pumpSSE emits, as SSE text, and how many frames. */
function sink() {
    const outs: OutFrame[] = []
    let text = ''
    return {
        outs,
        get text() {
            return text
        },
        emit(o: OutFrame): number {
            outs.push(o)
            if (o.frame === undefined) return 0
            const b = frameSSE(o.frame)
            text += dec.decode(b)
            return b.length
        },
    }
}

const identity: FrameTransform = async (f) => ({ frame: f })

async function pump(text: string | Uint8Array, frameFn: FrameTransform = identity, chunk?: number) {
    const s = sink()
    const tally = new StreamTally()
    await pumpSSE(new AbortController().signal, (o) => s.emit(o), bodyOf(text, chunk), frameFn, tally)
    return { s, tally }
}

const frameOf = (over: Partial<StreamFrame>): StreamFrame => ({ ...emptyFrame(), ...over })

describe('frameSSE', () => {
    it('writes one data line per line of data, then the blank line', () => {
        expect(dec.decode(frameSSE(frameOf({ data: enc.encode('hi') })))).toBe('data: hi\n\n')
        expect(dec.decode(frameSSE(frameOf({ data: enc.encode('line1\nline2') })))).toBe('data: line1\ndata: line2\n\n')
    })

    it('writes the comment, event, id and a positive retry, in Go’s order', () => {
        const f = frameOf({ comment: 'hb', event: 'message', id: '42', retry: 1000, data: enc.encode('payload') })
        expect(dec.decode(frameSSE(f))).toBe(': hb\nevent: message\nid: 42\nretry: 1000\ndata: payload\n\n')
        expect(dec.decode(frameSSE(frameOf({ retry: -1, event: 'e' })))).toBe('event: e\n\n')
    })
})

describe('pumpSSE', () => {
    it('passes each frame on', async () => {
        const { s } = await pump('data: one\n\ndata: two\n\ndata: three\n\n')
        expect(s.text).toBe('data: one\n\ndata: two\n\ndata: three\n\n')
        expect(s.outs).toHaveLength(3)
    })

    it('joins data lines, and reads event, id, retry and a comment', async () => {
        const { s } = await pump('event: msg\nid: 7\nretry: 300\n: keepalive\ndata: l1\ndata: l2\n\n')
        expect(s.outs[0]!.frame).toEqual(frameOf({ event: 'msg', id: '7', retry: 300, comment: 'keepalive', data: enc.encode('l1\nl2') }))
    })

    it('passes a lone comment on, as a keepalive', async () => {
        const { s } = await pump(': keepalive\n\ndata: hi\n\n')
        expect(s.text).toBe(': keepalive\n\ndata: hi\n\n')
    })

    // Each as Go's trimLineEnd and splitSSEField read it.
    it.each([
        ['CRLF line ends', 'data: hi\r\n\r\n', 'hi'],
        ['no space after the colon', 'data:hi\n\n', 'hi'],
        ['only one space dropped', 'data:  hi\n\n', ' hi'],
        ['a lone CR stays in the value', 'data: a\rb\n\n', 'a\rb'],
        ['a field with no colon has no value', 'data\ndata: x\n\n', 'x'],
        // Go's buffer adds the joining newline only once it holds something.
        ['a leading empty data line adds nothing', 'data:\ndata: x\n\n', 'x'],
        ['an empty data line between two joins twice', 'data: a\ndata:\ndata: b\n\n', 'a\n\nb'],
    ])('reads %s', async (_name, text, data) => {
        const { s } = await pump(text)
        expect(dec.decode(s.outs.at(-1)!.frame!.data)).toBe(data)
    })

    it('drops a frame that has nothing, and an unknown field', async () => {
        const { s } = await pump('\n\nfoo: bar\n\ndata: x\n\n')
        expect(s.outs).toHaveLength(1)
    })

    // strconv.Atoi: a sign and digits, within int64.
    it.each([
        ['5', 5],
        ['+5', 5],
        ['007', 7],
        [' 5', 0],
        ['5s', 0],
        ['', 0],
        ['9223372036854775808', 0],
    ])('reads retry %j as %i', async (v, want) => {
        const { s } = await pump(`retry: ${v}\ndata: x\n\n`)
        expect(s.outs[0]!.frame!.retry).toBe(want)
    })

    // Go's string(bytes) keeps a BOM, so a BOM-led field name is no field.
    it('reads a BOM-led field name as no field', async () => {
        const raw = new Uint8Array([0xef, 0xbb, 0xbf, ...enc.encode('event: zs\ndata: x\n\n')])
        const { s } = await pump(raw)
        expect(s.outs[0]!.frame).toEqual(frameOf({ data: enc.encode('x') }))
    })

    it('keeps the last comment of a frame', async () => {
        const { s } = await pump(': a\n: b\ndata: x\n\n')
        expect(s.outs[0]!.frame!.comment).toBe('b')
    })

    it('reads a frame far past any line cap, and lines split across chunks', async () => {
        const big = 'x'.repeat(128 * 1024)
        const { s } = await pump(`data: ${big}\r\n\r\ndata: tail\n\n`, identity, 7)
        expect(s.outs.map((o) => dec.decode(o.frame!.data))).toEqual([big, 'tail'])
    })

    it('keeps bytes that aren’t valid UTF-8', async () => {
        const raw = new Uint8Array([...enc.encode('data: '), 0xff, 0xfe, 0x0a, 0x0a])
        const { s } = await pump(raw, identity, 1)
        expect(s.outs[0]!.frame!.data).toEqual(new Uint8Array([0xff, 0xfe]))
    })

    it('flushes a last frame that has no blank line', async () => {
        const { s } = await pump('data: trailing')
        expect(s.text).toBe('data: trailing\n\n')
    })

    it('drops what the transform empties, and doesn’t count a usage report', async () => {
        const usage = { fake: true } as never
        const { s, tally } = await pump('data: one\n\ndata: drop-me\n\ndata: usage\n\ndata: three\n\n', async (f) => {
            const d = dec.decode(f.data)
            if (d === 'drop-me') return {}
            if (d === 'usage') return { usage }
            return { frame: f }
        })
        expect(s.text).toBe('data: one\n\ndata: three\n\n')
        expect(s.outs).toHaveLength(3)
        expect(tally.frames).toBe(2)
        expect(tally.bytes).toBe(enc.encode('data: one\n\ndata: three\n\n').length)
    })

    it('fails on a transform error, naming it', async () => {
        await expect(
            pump('data: one\n\n', async () => {
                throw new Error('transform boom')
            }),
        ).rejects.toThrow('transform stream chunk: transform boom')
    })

    it('stops on an aborted signal', async () => {
        const ac = new AbortController()
        ac.abort(new Error('caller gone'))
        const s = sink()
        await expect(pumpSSE(ac.signal, (o) => s.emit(o), bodyOf('data: one\n\n'), identity, new StreamTally())).rejects.toThrow('caller gone')
        expect(s.outs).toEqual([])
    })

    it('stops between lines of one chunk once the signal aborts', async () => {
        const ac = new AbortController()
        const s = sink()
        const p = pumpSSE(
            ac.signal,
            (o) => {
                ac.abort(new Error('stop'))
                return s.emit(o)
            },
            bodyOf('data: one\n\ndata: two\n\n'),
            identity,
            new StreamTally(),
        )
        await expect(p).rejects.toThrow('stop')
        expect(s.outs).toHaveLength(1)
    })

    it('reads a missing body as an empty stream', async () => {
        const s = sink()
        await pumpSSE(new AbortController().signal, (o) => s.emit(o), null, identity, new StreamTally())
        expect(s.outs).toEqual([])
    })
})

describe('StreamTally', () => {
    function clocked() {
        let now = 1000
        return {
            clock: () => now,
            at(t: number) {
                now = t
            },
        }
    }

    it('counts what was forwarded and the largest gap between frames', () => {
        const c = clocked()
        const t = new StreamTally(c.clock)
        c.at(1100)
        t.record(10)
        c.at(1150)
        t.record(20)
        c.at(1400)
        t.record(5)
        c.at(1420)
        t.record(5)
        c.at(1500)
        expect(t.attrs(1000)).toEqual({
            frames: 4,
            bytes: 40,
            elapsed_ms: 500,
            ttfb_ms: 100,
            max_inter_frame_gap_ms: 250,
            silence_before_cut_ms: 80,
        })
    })

    // The silence before the cut is the gap maxGap can't see: a stream that
    // stalled, recovered and then went quiet.
    it('reports the silence before the cut apart from the worst earlier gap', () => {
        const c = clocked()
        const t = new StreamTally(c.clock)
        c.at(1000)
        t.record(1)
        c.at(1100)
        t.record(1)
        c.at(4100)
        expect(t.attrs(1000)).toMatchObject({ max_inter_frame_gap_ms: 100, silence_before_cut_ms: 3000 })
    })

    it('reports zero ttfb and silence with no frames', () => {
        const c = clocked()
        const t = new StreamTally(c.clock)
        c.at(1700)
        expect(t.attrs(1000)).toEqual({
            frames: 0,
            bytes: 0,
            elapsed_ms: 700,
            ttfb_ms: 0,
            max_inter_frame_gap_ms: 0,
            silence_before_cut_ms: 0,
        })
    })
})

/** An emitter that records the stream it is given. */
class StreamRecorder {
    failed?: ZsError
    opened: [number, Headers][] = []
    outs: OutFrame[] = []
    interrupted = 0
    openResult = true
    onFrame?: (o: OutFrame) => void
    note() {}
    clamped() {}
    reserved() {}
    committed() {}
    fail(err: ZsError) {
        if (this.failed) throw new Error(`failed twice: ${this.failed.code}, then ${err.code}`)
        this.failed = err
    }
    reply() {
        throw new Error('a stream test never replies')
    }
    open(status: number, header: Headers): boolean {
        this.opened.push([status, header])
        return this.openResult
    }
    frame(o: OutFrame): number {
        this.outs.push(o)
        this.onFrame?.(o)
        return o.frame === undefined ? 0 : frameSSE(o.frame).length
    }
    causes: unknown[] = []
    interrupt(cause?: unknown) {
        this.interrupted++
        this.causes.push(cause)
    }
    get data(): string[] {
        return this.outs.flatMap((o) => (o.frame ? [dec.decode(o.frame.data)] : []))
    }
}

const hopOf = (over: Partial<RelayHop> = {}): RelayHop => ({
    baseUrl: 'https://relay.example.com',
    targetId: 9,
    targetNodeId: 1,
    relayId: 5,
    relayNodeId: 0,
    relayProtoVersion: PROTO_VERSION,
    ...over,
})

const SSE = { 'Content-Type': 'text/event-stream' }

describe('forwardStream', () => {
    const out = { url: 'https://node.example.com/v1/chat/completions', body: enc.encode('{}'), headers: { 'Content-Type': 'x', accept: 'application/json' } }
    const call = (signal?: AbortSignal, hop: RelayHop | null = null) => ({ endpoint: '/v1/chat/completions' as const, hop, signal })
    const noFallback = async () => {
        throw new Error('no fallback expected')
    }

    function setup(respond: (init: RequestInit) => Promise<Response> | Response) {
        const logger = recLogger()
        const fetches: [string, RequestInit][] = []
        const deps = {
            logger,
            fetch: vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
                fetches.push([String(url), init!])
                return respond(init!)
            }),
            drainTailTimeoutMs: 50,
        }
        return { deps, logger, fetches, em: new StreamRecorder() }
    }

    it('posts with Accept text/event-stream in place of any other, on a signal of its own', async () => {
        const caller = new AbortController()
        const t = setup(() => new Response(bodyOf('data: x\n\n'), { headers: SSE }))
        await forwardStream(t.deps, t.em as never, out, call(caller.signal), async () => identity, noFallback, { value: false })
        const [url, init] = t.fetches[0]!
        expect(url).toBe(out.url)
        expect(init.method).toBe('POST')
        expect(init.body).toBe(out.body)
        expect(init.headers).toEqual({ 'Content-Type': 'x', Accept: 'text/event-stream' })
        expect(init.signal).not.toBe(caller.signal)
        // Released once the stream is done.
        expect(init.signal!.aborted).toBe(true)
        expect(t.em.opened).toHaveLength(1)
        expect(t.em.data).toEqual(['x'])
    })

    it('refuses a URL that won’t parse before any request', async () => {
        const t = setup(() => {
            throw new Error('no fetch expected')
        })
        await forwardStream(t.deps, t.em as never, { ...out, url: 'not a url' }, call(), async () => identity, noFallback, { value: false })
        expect(t.em.failed?.code).toBe('build_request')
        expect(t.fetches).toEqual([])
    })

    // The request rides its own signal, so a caller who already left can't
    // excuse a relay whose dial failed.
    it('charges an unreachable relay even when the caller has left', async () => {
        const rep = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const outcome = vi.spyOn(rep, 'recordRelayOutcome')
        const t = setup(() => {
            throw new TypeError('fetch failed')
        })
        const caller = new AbortController()
        caller.abort()
        const hop = hopOf()
        await forwardStream({ ...t.deps, relayReputation: rep }, t.em as never, out, call(caller.signal, hop), async () => identity, noFallback, {
            value: false,
        })
        expect(outcome).toHaveBeenCalledWith({ op: 5, node: 0 }, false)
        expect(t.em.failed).toMatchObject({ code: 'upstream_unreachable', message: 'fetch failed' })
        expect(t.logger.logged).toContainEqual({
            level: 'error',
            msg: 'upstream request failed',
            attrs: { endpoint: '/v1/chat/completions', relay_operator_id: 5, relay_node_id: 0, err: 'fetch failed' },
        })
    })

    // The residue Go's relayEvidence names: its backstop fires on a context
    // the caller didn't end, so the relay is charged.
    it('charges the relay when the header backstop gives up', async () => {
        const rep = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const outcome = vi.spyOn(rep, 'recordRelayOutcome')
        const t = setup((init) => new Promise((_, reject) => init.signal!.addEventListener('abort', () => reject(init.signal!.reason), { once: true })))
        const deps = { ...t.deps, fetch: withHeaderBackstop(t.deps.fetch as Fetch, 10), relayReputation: rep }
        await forwardStream(deps, t.em as never, out, call(new AbortController().signal, hopOf()), async () => identity, noFallback, { value: false })
        expect(outcome).toHaveBeenCalledWith({ op: 5, node: 0 }, false)
        expect(t.em.failed).toMatchObject({ code: 'upstream_unreachable', message: 'timeout awaiting response headers' })
    })

    it('credits the relay that forwarded an event stream', async () => {
        const rep = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const outcome = vi.spyOn(rep, 'recordRelayOutcome')
        const t = setup(() => new Response(bodyOf(''), { status: 200, headers: SSE }))
        await forwardStream({ ...t.deps, relayReputation: rep }, t.em as never, out, call(undefined, hopOf()), async () => identity, noFallback, {
            value: false,
        })
        expect(outcome.mock.calls).toEqual([[{ op: 5, node: 0 }, true]])
    })

    it('hands a plain body to the buffered responder, attributing it to the relay', async () => {
        const rep = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        const upstream = vi.spyOn(rep, 'recordRelayUpstreamUnreachable')
        const body = '{"error":{"message":"down","code":"relay_upstream_unreachable"}}'
        const t = setup(() => new Response(body, { status: 502, headers: { 'Content-Type': 'application/json' } }))
        const seen: [number, string][] = []
        await forwardStream(
            { ...t.deps, relayReputation: rep },
            t.em as never,
            out,
            call(undefined, hopOf()),
            async () => {
                throw new Error('no stream expected')
            },
            async (_em, resp, b) => {
                seen.push([resp.status, dec.decode(b)])
            },
            { value: false },
        )
        expect(seen).toEqual([[502, body]])
        expect(upstream).toHaveBeenCalledOnce()
        expect(t.em.opened).toEqual([])
    })

    it('reports a buffered responder that throws, and a body that won’t read', async () => {
        let t = setup(() => new Response('{}', { headers: { 'Content-Type': 'application/json' } }))
        await forwardStream(t.deps, t.em as never, out, call(), async () => identity, async () => {
            throw new Error('boom')
        }, { value: false })
        expect(t.em.failed).toMatchObject({ code: 'response_handler', message: 'upstream response could not be processed' })
        expect(t.logger.logged).toContainEqual({ level: 'error', msg: 'non-stream fallback failed', attrs: { endpoint: '/v1/chat/completions', err: 'boom' } })

        const broken = new ReadableStream<Uint8Array>({
            pull(c) {
                c.error(new Error('reset'))
            },
        })
        t = setup(() => new Response(broken, { headers: { 'Content-Type': 'application/json' } }))
        await forwardStream(t.deps, t.em as never, out, call(), async () => identity, noFallback, { value: false })
        expect(t.em.failed?.code).toBe('read_upstream')
    })

    it('fails a stream it can’t open, without starting it', async () => {
        const t = setup(() => new Response(bodyOf('data: x\n\n'), { headers: SSE }))
        await forwardStream(
            t.deps,
            t.em as never,
            out,
            call(),
            async () => {
                throw new Error('no key')
            },
            noFallback,
            { value: false },
        )
        expect(t.em.failed).toMatchObject({ code: 'stream_setup', message: 'stream could not be initialized' })
        expect(t.em.opened).toEqual([])
        expect(t.logger.logged).toContainEqual({ level: 'error', msg: 'frame transform setup failed', attrs: { endpoint: '/v1/chat/completions', err: 'no key' } })
    })

    it('reads nothing once the emitter couldn’t start the stream', async () => {
        const t = setup(() => new Response(bodyOf('data: x\n\n'), { headers: SSE }))
        t.em.openResult = false
        await forwardStream(t.deps, t.em as never, out, call(), async () => identity, noFallback, { value: false })
        expect(t.em.outs).toEqual([])
    })

    // The hook's close wipes the response key, so it runs only once nothing
    // more will be opened, and on every path that built the hook.
    it('closes the frame hook once the stream has been read, and not before', async () => {
        for (const openResult of [true, false]) {
            const t = setup(() => new Response(bodyOf('data: a\n\ndata: b\n\n'), { headers: SSE }))
            t.em.openResult = openResult
            const seen: string[] = []
            const hook = Object.assign(async (f: StreamFrame) => (seen.push('frame'), { frame: f }), { close: () => seen.push('close') })
            await forwardStream(t.deps, t.em as never, out, call(), async () => hook, noFallback, { value: false })
            expect(seen).toEqual(openResult ? ['frame', 'frame', 'close'] : ['close'])
        }
    })

    it('logs a clean stream’s profile at debug', async () => {
        const t = setup(() => new Response(bodyOf('data: a\n\ndata: b\n\n'), { status: 201, headers: SSE }))
        await forwardStream(t.deps, t.em as never, out, call(), async () => identity, noFallback, { value: false })
        expect(t.em.opened[0]![0]).toBe(201)
        const done = t.logger.logged.find((l) => l.msg === 'stream complete')!
        expect(done.level).toBe('debug')
        expect(done.attrs).toMatchObject({ endpoint: '/v1/chat/completions', frames: 2 })
        expect(t.em.interrupted).toBe(0)
    })

    it('interrupts a stream that breaks while the caller is still there', async () => {
        const t = setup(() => new Response(bodyOf('data: a\n\n'), { headers: SSE }))
        await forwardStream(
            t.deps,
            t.em as never,
            out,
            call(new AbortController().signal),
            async () => async () => {
                throw new Error('bad frame')
            },
            noFallback,
            { value: false },
        )
        expect(t.em.interrupted).toBe(1)
        expect(t.logger.logged).toContainEqual({
            level: 'warn',
            msg: 'sse pump ended with error',
            attrs: { endpoint: '/v1/chat/completions', err: 'transform stream chunk: bad frame' },
        })
    })

    // A caller who leaves after the node finished still has the tail read, so
    // the receipt settles: the operator is paid for what it delivered.
    it('drains the tail when the caller leaves after the generation completed', async () => {
        const caller = new AbortController()
        let src!: ReturnType<typeof source>
        const t = setup((init) => {
            src = source(init.signal!)
            src.push('data: done\n\n')
            return new Response(src.stream, { headers: SSE })
        })
        const gen: GenComplete = { value: false }
        const seen: string[] = []
        await forwardStream(
            t.deps,
            t.em as never,
            out,
            call(caller.signal),
            async () => async (f) => {
                const d = dec.decode(f.data)
                seen.push(d)
                if (d === 'done') {
                    gen.value = true
                    caller.abort()
                    src.push('data: after\n\ndata: tail\n\n')
                    src.close()
                }
                return { frame: f }
            },
            noFallback,
            gen,
        )
        expect(seen).toEqual(['done', 'after', 'tail'])
        expect(t.em.interrupted).toBe(0)
        expect(t.logger.logged.map((l) => l.msg)).toContain('client disconnected after generation complete; draining receipt tail')
    })

    it('cancels the node when the caller leaves before the generation completed', async () => {
        const caller = new AbortController()
        let upstream!: AbortSignal
        const t = setup((init) => {
            upstream = init.signal!
            const src = source(upstream)
            src.push('data: first\n\n')
            return new Response(src.stream, { headers: SSE })
        })
        await forwardStream(
            t.deps,
            t.em as never,
            out,
            call(caller.signal),
            async () => async (f) => {
                caller.abort()
                return { frame: f }
            },
            noFallback,
            { value: false },
        )
        expect(upstream.aborted).toBe(true)
        // Nobody is left to tell.
        expect(t.em.interrupted).toBe(0)
        const line = t.logger.logged.find((l) => l.msg === 'client disconnected before generation complete; upstream cancelled')!
        expect(line.level).toBe('info')
        expect(line.attrs).toMatchObject({ endpoint: '/v1/chat/completions', frames: 1 })
    })

    it('cancels at once for a caller who left before the stream opened', async () => {
        const caller = new AbortController()
        caller.abort()
        const t = setup((init) => {
            const src = source(init.signal!)
            return new Response(src.stream, { headers: SSE })
        })
        await forwardStream(t.deps, t.em as never, out, call(caller.signal), async () => identity, noFallback, { value: false })
        expect(t.logger.logged.find((l) => l.msg === 'client disconnected before generation complete; upstream cancelled')?.attrs).toMatchObject({
            frames: 0,
        })
    })

    it('stops draining a tail that never comes', async () => {
        const caller = new AbortController()
        let upstream!: AbortSignal
        const t = setup((init) => {
            upstream = init.signal!
            const src = source(upstream)
            src.push('data: done\n\n')
            return new Response(src.stream, { headers: SSE })
        })
        const gen: GenComplete = { value: false }
        const started = Date.now()
        await forwardStream(
            t.deps,
            t.em as never,
            out,
            call(caller.signal),
            async () => async (f) => {
                gen.value = true
                caller.abort()
                return { frame: f }
            },
            noFallback,
            gen,
        )
        expect(Date.now() - started).toBeGreaterThanOrEqual(40)
        expect(upstream.aborted).toBe(true)
        expect(t.logger.logged).toContainEqual({
            level: 'warn',
            msg: 'receipt tail drain timed out; cancelling upstream',
            attrs: { endpoint: '/v1/chat/completions' },
        })
        expect(t.em.interrupted).toBe(0)
    })

    // Go's drainTailTimeout.
    it('drains for 10s by default', async () => {
        expect(DRAIN_TAIL_TIMEOUT_MS).toBe(10_000)
        const timers = vi.spyOn(globalThis, 'setTimeout')
        try {
            const caller = new AbortController()
            let src!: ReturnType<typeof source>
            const t = setup((init) => {
                src = source(init.signal!)
                src.push('data: done\n\n')
                return new Response(src.stream, { headers: SSE })
            })
            const gen: GenComplete = { value: false }
            await forwardStream(
                { logger: t.deps.logger, fetch: t.deps.fetch },
                t.em as never,
                out,
                call(caller.signal),
                async () => async (f) => {
                    if (!gen.value) {
                        gen.value = true
                        caller.abort()
                        src.close()
                    }
                    return { frame: f }
                },
                noFallback,
                gen,
            )
            expect(timers.mock.calls.map((c) => c[1])).toContain(10_000)
        } finally {
            timers.mockRestore()
        }
    })

    it('leaves no drain timer behind a stream that ends in time', async () => {
        const caller = new AbortController()
        const t = setup(() => new Response(bodyOf('data: done\n\n'), { headers: SSE }))
        t.deps.drainTailTimeoutMs = 10
        const gen: GenComplete = { value: false }
        await forwardStream(
            t.deps,
            t.em as never,
            out,
            call(caller.signal),
            async () => async (f) => {
                gen.value = true
                caller.abort()
                return { frame: f }
            },
            noFallback,
            gen,
        )
        await new Promise((r) => setTimeout(r, 30))
        expect(t.logger.logged.map((l) => l.msg)).not.toContain('receipt tail drain timed out; cancelling upstream')
    })

    describe('with an idle watchdog', () => {
        const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms))

        it('cancels a node that goes silent, and interrupts the turn with why', async () => {
            let upstream!: AbortSignal
            const t = setup((init) => {
                upstream = init.signal!
                const src = source(upstream)
                src.push('data: a\n\n')
                return new Response(src.stream, { headers: SSE })
            })
            const idle = new IdleWatchdog({ preStream: 1000, midStream: 20, toolActive: 1000 })
            await forwardStream(t.deps, t.em as never, out, call(new AbortController().signal), async () => identity, noFallback, { value: false }, idle)
            expect(t.em.data).toEqual(['a'])
            expect(upstream.aborted).toBe(true)
            expect(t.em.interrupted).toBe(1)
            const cause = t.em.causes[0] as StreamIdleTimeoutError
            expect(cause).toBeInstanceOf(StreamIdleTimeoutError)
            expect([cause.phase, cause.timeoutMs]).toEqual(['mid-stream', 20])
            expect(t.logger.logged).toContainEqual({
                level: 'warn',
                msg: 'upstream stream idle; cancelling upstream',
                attrs: { endpoint: '/v1/chat/completions', phase: 'mid-stream', timeout_ms: 20 },
            })
        })

        it('bounds the wait for the first byte by the pre-stream budget', async () => {
            const t = setup((init) => new Response(source(init.signal!).stream, { headers: SSE }))
            const idle = new IdleWatchdog({ preStream: 20, midStream: 1000, toolActive: 1000 })
            await forwardStream(t.deps, t.em as never, out, call(), async () => identity, noFallback, { value: false }, idle)
            expect((t.em.causes[0] as StreamIdleTimeoutError).phase).toBe('pre-stream')
        })

        it('counts a keepalive comment as the node being alive', async () => {
            let src!: ReturnType<typeof source>
            const t = setup((init) => {
                src = source(init.signal!)
                return new Response(src.stream, { headers: SSE })
            })
            const idle = new IdleWatchdog({ preStream: 60, midStream: 60, toolActive: 60 })
            const run = forwardStream(t.deps, t.em as never, out, call(), async () => identity, noFallback, { value: false }, idle)
            for (let i = 0; i < 5; i++) {
                await sleep(20)
                src.push(': zs-keepalive\n\n')
            }
            src.push('data: end\n\n')
            src.close()
            await run
            expect(t.em.interrupted).toBe(0)
            expect(t.em.data.at(-1)).toBe('end')
        })

        it('bounds a receipt-tail drain, telling nobody', async () => {
            const caller = new AbortController()
            let upstream!: AbortSignal
            const t = setup((init) => {
                upstream = init.signal!
                const src = source(upstream)
                src.push('data: done\n\n')
                return new Response(src.stream, { headers: SSE })
            })
            t.deps.drainTailTimeoutMs = 60_000
            const gen: GenComplete = { value: false }
            const idle = new IdleWatchdog({ preStream: 1000, midStream: 20, toolActive: 1000 })
            const started = Date.now()
            await forwardStream(
                t.deps,
                t.em as never,
                out,
                call(caller.signal),
                async () => async (f) => {
                    gen.value = true
                    caller.abort()
                    return { frame: f }
                },
                noFallback,
                gen,
                idle,
            )
            expect(Date.now() - started).toBeLessThan(5000)
            expect(upstream.aborted).toBe(true)
            expect(t.em.interrupted).toBe(0)
            expect(t.logger.logged.map((l) => l.msg)).toContain('upstream stream idle; cancelling upstream')
        })

        // A receipt's settle runs inline and reads nothing; that wait is the
        // SDK's, not the node's.
        it('doesn’t count the frame hook’s own time as silence', async () => {
            const t = setup(() => new Response(bodyOf('data: a\n\ndata: b\n\n'), { headers: SSE }))
            const idle = new IdleWatchdog({ preStream: 1000, midStream: 20, toolActive: 1000 })
            await forwardStream(
                t.deps,
                t.em as never,
                out,
                call(),
                async () => async (f) => {
                    await sleep(60)
                    return { frame: f }
                },
                noFallback,
                { value: false },
                idle,
            )
            expect(t.em.interrupted).toBe(0)
            expect(t.em.data).toEqual(['a', 'b'])
        })

        it('disarms when the stream ends', async () => {
            const t = setup(() => new Response(bodyOf('data: done\n\n'), { headers: SSE }))
            const idle = new IdleWatchdog({ preStream: 10, midStream: 10, toolActive: 10 })
            await forwardStream(t.deps, t.em as never, out, call(), async () => identity, noFallback, { value: false }, idle)
            await sleep(30)
            expect(t.em.interrupted).toBe(0)
            expect(t.logger.logged.map((l) => l.msg)).not.toContain('upstream stream idle; cancelling upstream')
        })

        it('arms nothing for a reply that isn’t a stream', async () => {
            const t = setup(() => new Response('{}', { headers: { 'Content-Type': 'application/json' } }))
            const idle = new IdleWatchdog({ preStream: 10, midStream: 10, toolActive: 10 })
            let replied = false
            await forwardStream(
                t.deps,
                t.em as never,
                out,
                call(),
                async () => identity,
                async () => {
                    await sleep(30)
                    replied = true
                },
                { value: false },
                idle,
            )
            expect(replied).toBe(true)
            expect(t.logger.logged.map((l) => l.msg)).not.toContain('upstream stream idle; cancelling upstream')
        })
    })
})

describe('frameFactory', () => {
    const CONTENT = ['{"choices":[{"delta":{"content":"A"}}]}', '{"choices":[{"delta":{},"finish_reason":"stop"}]}']

    async function setup(o: { endpoint?: SealedCall['endpoint']; frames?: string[]; receipt?: Partial<UsageReceipt>; matching?: boolean } = {}) {
        const frames = (o.frames ?? CONTENT).map((s) => enc.encode(s))
        const hash = o.matching === false ? bodyHashFromFrames([enc.encode('other')]) : bodyHashFromFrames(frames)
        const f = await fixture(o.receipt, enc.encode(''), hash)
        const identity = await generateEphemeralIdentity()
        const sealer = await ResponseSealer.create({ replyTo: identity.recipient, txID: 'APPCALL', ticketID: TICKET_ID, key: f.responseKey })
        const handle = handleOf({ txid: 'ACK', fee: 1000 })
        const reserved = { ticket: f.ticket, identity, responseKey: f.responseKey, algoUsdPrice: 0.2 } as unknown as Reserved
        const call: SealedCall = { endpoint: o.endpoint ?? '/v1/chat/completions', model: 'm', op: f.op, reserved, handle, txId: 'APPCALL', hop: null }
        const logger = recLogger()
        const responseAffinity = new IDAffinity(16, 60_000)
        const resolved: string[] = []
        const deps: FrameDeps = { logger, responseAffinity, feeRate: () => 150, resolveRefund: (id) => resolved.push(id) }
        const gen: GenComplete = { value: false }
        return { f, frames, sealer, handle, call, logger, deps, gen, responseAffinity, resolved }
    }

    type Setup = Awaited<ReturnType<typeof setup>>

    const zs = (s: Setup, pt: Uint8Array) => frameOf({ event: 'zs', data: enc.encode(s.sealer.sealStreamFrame(pt)) })
    const receiptFrame = (s: Setup, r: UsageReceipt = s.f.receipt) => frameOf({ event: 'zs-receipt', data: enc.encode(s.sealer.sealStreamFrame(enc.encode(JSON.stringify(r)))) })
    const groupFrame = (s: Setup, g: string) => frameOf({ event: 'zs-settle-group', data: enc.encode(s.sealer.sealHeader(SEALED_HEADER_SETTLE_GROUP, enc.encode(g))) })
    const keyed = (s: Setup, key = s.sealer.wrappedKeyHeader()) => new Response(null, { headers: { [RESPONSE_KEY_HEADER]: key } })

    async function transform(s: Setup, slot?: SettleSlot) {
        return frameFactory(s.deps, s.call, s.gen, slot)(keyed(s))
    }

    it('opens the content, settles inline on the receipt with the node’s group, and reports it', async () => {
        const s = await setup()
        const slot = new SettleSlot()
        const fn = await transform(s, slot)
        const outs: OutFrame[] = []
        for (const pt of s.frames) outs.push(await fn(zs(s, pt)))
        outs.push(await fn(groupFrame(s, VALID_GROUP)))
        outs.push(await fn(receiptFrame(s)))
        expect(outs.slice(0, 2).map((o) => o.frame)).toEqual(s.frames.map((pt) => frameOf({ data: pt, sealed: true })))
        expect(outs[2]).toEqual({})
        // The ack ran before the usage was handed on.
        expect(s.handle.acks.map((a) => a[1])).toEqual([VALID_GROUP])
        expect(outs[3]!.usage).toMatchObject({
            receipt: s.f.receipt,
            ticket: s.f.ticket,
            op: s.f.op,
            openFees: 2000,
            // What the scripted ack reported paying.
            settleFees: 1000,
            algoUsdPrice: 0.2,
            feeBps: 150,
            haveFee: true,
            check: { violation: '', excluded: false, settled: { ticketId: TICKET_ID, kind: 'atomic', txId: 'ACK', feesMicroAlgos: 1000 } },
        })
        expect((await slot.done).settlement.txId).toBe('ACK')
        expect(s.resolved).toEqual([TICKET_ID])
    })

    it('reports the payer’s fee for a standalone ack', async () => {
        const s = await setup()
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        const out = await fn(receiptFrame(s))
        expect(s.handle.acks[0]![1]).toBeNull()
        expect(out.usage).toMatchObject({ settleFees: 1000, check: { settled: { kind: 'payer_ack', feesMicroAlgos: 1000 } } })
    })

    it('shows the idle watchdog each opened content frame, and nothing else', async () => {
        const opening = '{"type":"response.zs_tool_call.in_progress","item_id":"t1","tool":"zs_image_generation"}'
        const s = await setup({ frames: [opening] })
        const idle = new IdleWatchdog({ preStream: 1000, midStream: 1000, toolActive: 1000 })
        const seen: [string, string][] = []
        vi.spyOn(idle, 'frame').mockImplementation((text, raw) => {
            seen.push([text(), dec.decode(raw)])
        })
        const fn = await frameFactory(s.deps, s.call, s.gen, undefined, idle)(keyed(s))
        await fn(zs(s, s.frames[0]!))
        await fn(groupFrame(s, VALID_GROUP))
        await fn(receiptFrame(s))
        expect(seen).toEqual([[opening, opening]])
    })

    it('marks the generation complete on a terminal frame, and only then', async () => {
        const s = await setup()
        const fn = await transform(s)
        await fn(zs(s, s.frames[0]!))
        expect(s.gen.value).toBe(false)
        await fn(zs(s, s.frames[1]!))
        expect(s.gen.value).toBe(true)
    })

    it('marks an error frame complete too, and logs it', async () => {
        const s = await setup({ frames: ['{"error":{"message":"provider down"}}'] })
        const fn = await transform(s)
        await fn(zs(s, s.frames[0]!))
        expect(s.gen.value).toBe(true)
        expect(s.logger.logged).toContainEqual({
            level: 'warn',
            msg: 'operator returned stream error',
            attrs: { operator_id: 7, node_id: 3, ticket_id: TICKET_ID, error: 'provider down' },
        })
    })

    it('records the response id once, and only on /v1/responses', async () => {
        const frames = ['{"type":"response.created","response":{"id":"resp_1"}}', '{"type":"response.completed","response":{"id":"resp_2"}}']
        for (const endpoint of ['/v1/chat/completions', '/v1/responses'] as const) {
            const s = await setup({ endpoint, frames })
            const record = vi.spyOn(s.responseAffinity, 'record')
            const fn = await transform(s)
            for (const pt of s.frames) await fn(zs(s, pt))
            expect(record.mock.calls).toEqual(endpoint === '/v1/responses' ? [[{ op: 7, node: 3 }, ['resp_1']]] : [])
        }
    })

    // A streamed tool call pins the continuation as a buffered one does.
    it('records each tool call’s id as its first chunk arrives, on any endpoint', async () => {
        const frames = [
            '{"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call_1","function":{"name":"f","arguments":""}}]}}]}',
            '{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{}"}}]}}]}',
            '{"choices":[{"delta":{"tool_calls":[{"index":1,"id":"call_2","function":{"name":"g","arguments":""}}]}}]}',
            '{"choices":[{"delta":{},"finish_reason":"tool_calls"}]}',
        ]
        const s = await setup({ frames })
        const toolAffinity = new IDAffinity(16, 60_000)
        const record = vi.spyOn(toolAffinity, 'record')
        s.deps.toolAffinity = toolAffinity
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        expect(record.mock.calls).toEqual([
            [{ op: 7, node: 3 }, ['call_1']],
            [{ op: 7, node: 3 }, ['call_2']],
        ])
        expect(toolAffinity.lookup('call_2')).toEqual({ op: 7, node: 3 })
    })

    // Go replaces each invalid byte, as the next turn's request is read.
    it('reads an id’s invalid bytes as Go does', async () => {
        const head = enc.encode('{"choices":[{"delta":{"tool_calls":[{"id":"call_')
        const frame = new Uint8Array([...head, 0xe2, 0x82, ...enc.encode('"}]}}]}')])
        const s = await setup({ frames: [] })
        s.frames.push(frame)
        const toolAffinity = new IDAffinity(16, 60_000)
        s.deps.toolAffinity = toolAffinity
        const fn = await transform(s)
        await fn(zs(s, frame))
        expect(toolAffinity.lookup('call_��')).toEqual({ op: 7, node: 3 })
    })

    it('passes an unsealed frame on as sent', async () => {
        const s = await setup()
        const fn = await transform(s)
        const done = frameOf({ data: enc.encode('[DONE]'), comment: 'c', id: '1' })
        expect(await fn(done)).toEqual({ frame: done })
    })

    it('fails on a content frame that won’t open, and opens the rest in order', async () => {
        const s = await setup()
        const fn = await transform(s)
        const first = zs(s, s.frames[0]!)
        const second = zs(s, s.frames[1]!)
        // Out of order: the second is sealed at index 1.
        await expect(fn(second)).rejects.toThrow(/^decrypt sse frame: /)
        expect((await fn(first)).frame?.data).toEqual(s.frames[0])
        expect((await fn(second)).frame?.data).toEqual(s.frames[1])
    })

    // A relay that drops a content frame desyncs the index: the receipt won't
    // open, and an honest node isn't protested for the relay's fault.
    it('discards a receipt that won’t open, without settling, and takes a later one at the same index', async () => {
        const s = await setup()
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        expect(await fn(frameOf({ event: 'zs-receipt', data: enc.encode('AAAA') }))).toEqual({})
        expect(s.logger.logged.map((l) => l.msg)).toContain('decrypt receipt frame failed')
        expect(s.handle.acks).toEqual([])
        // The failed open took no index.
        expect((await fn(receiptFrame(s))).usage).toBeDefined()
        expect(s.handle.acks).toHaveLength(1)
    })

    it('discards a receipt that won’t parse, and settles on a good one after it', async () => {
        const s = await setup()
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        const bad = frameOf({ event: 'zs-receipt', data: enc.encode(s.sealer.sealStreamFrame(enc.encode('{"amount_charged":-1}'))) })
        expect(await fn(bad)).toEqual({})
        expect(s.logger.logged.map((l) => l.msg)).toContain('parse receipt frame failed')
        expect(s.handle.acks).toEqual([])
        // It opened, so it took its index; the next receipt is sealed at the one after.
        expect((await fn(receiptFrame(s))).usage?.check.violation).toBe('')
        expect(s.handle.acks).toHaveLength(1)
    })

    // Go drops the submit's error: a delivered answer still reports its usage.
    it('reports the usage when the settle submit throws', async () => {
        const s = await setup()
        s.call = { ...s.call, handle: handleOf({ throws: new Error('wallet down') }) }
        const slot = new SettleSlot()
        const fn = await transform(s, slot)
        for (const pt of s.frames) await fn(zs(s, pt))
        const out = await fn(receiptFrame(s))
        expect(out.usage?.check.violation).toBe('')
        expect((await slot.done).err).toEqual(new Error('wallet down'))
        expect(s.logger.logged).toContainEqual({ level: 'error', msg: 'escrow settle submit failed', attrs: { ticket_id: TICKET_ID, err: 'wallet down' } })
    })

    // A second receipt could steer the spend guard and the ack down
    // different branches.
    it('settles on the first receipt only', async () => {
        const s = await setup()
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        await fn(receiptFrame(s))
        expect(await fn(receiptFrame(s))).toEqual({})
        expect(s.handle.acks).toHaveLength(1)
        expect(s.logger.logged.map((l) => l.msg)).toContain('operator emitted more than one zs-receipt frame; ignoring the extra')
    })

    // SPEC § 3: no per-request key outlives the response.
    it('wipes the response key on close, after which nothing opens', async () => {
        const s = await setup()
        const fn = await transform(s)
        await fn(zs(s, s.frames[0]!))
        fn.close?.()
        await expect(fn(zs(s, s.frames[1]!))).rejects.toThrow(/^decrypt sse frame: /)
    })

    // SPEC § 5.3: the receipt hashes the frames before it, so content after
    // the tail opens was never priced. An honest node writes upstream frames
    // that follow [DONE] there, so the turn stands.
    it('drops content after the receipt, having settled on what came before', async () => {
        const s = await setup({ frames: [CONTENT[0]!] })
        const fn = await transform(s)
        await fn(zs(s, s.frames[0]!))
        expect((await fn(receiptFrame(s))).usage?.check.violation).toBe('')
        expect(await fn(zs(s, enc.encode('{"delta":"late"}')))).toEqual({})
        expect(s.logger.logged.map((l) => l.msg)).toContain('frame after the settlement tail dropped')
        expect(s.handle.acks).toHaveLength(1)
    })

    it('drops content after the settle group', async () => {
        const s = await setup()
        const fn = await transform(s)
        await fn(groupFrame(s, VALID_GROUP))
        expect(await fn(zs(s, s.frames[0]!))).toEqual({})
    })

    // A frame that won't open could be a relay's; it doesn't end the content.
    it('takes content after a settle group that won’t open', async () => {
        const s = await setup()
        const fn = await transform(s)
        expect(await fn(frameOf({ event: 'zs-settle-group', data: enc.encode('AAAA') }))).toEqual({})
        expect((await fn(zs(s, s.frames[0]!))).frame?.data).toEqual(s.frames[0])
    })

    it('opens the settle group without taking an index, the last one sent winning', async () => {
        const s = await setup()
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        await fn(groupFrame(s, VALID_GROUP))
        await fn(groupFrame(s, 'bm90IGEgZ3JvdXA='))
        await fn(receiptFrame(s))
        // The malformed later group replaced the good one: a standalone ack.
        expect(s.handle.acks[0]![1]).toBeNull()
        expect(s.logger.logged.map((l) => l.msg)).toContain('settle-group header malformed; falling back to standalone ack')
    })

    it('protests a hash mismatch inline with the frames as the excerpt, and releases the spend', async () => {
        // The excerpt spans both frames and stops at the cap.
        const big = 'x'.repeat(DISPUTE_EXCERPT_CAP - 3)
        const s = await setup({ frames: [big, 'tail'], matching: false })
        const released: string[] = []
        s.deps.spendGuard = { admit() {}, reserve() {}, settle() {}, release: (id) => released.push(id) } satisfies SpendGuard
        const fn = await transform(s)
        for (const pt of s.frames) await fn(zs(s, pt))
        const out = await fn(receiptFrame(s))
        const [, excerpt, reason] = s.handle.protests[0]!
        expect(dec.decode(excerpt)).toBe(`${big}tai`)
        expect(reason).toBe(ProtestReason.bodyHash)
        expect(released).toEqual([TICKET_ID])
        expect(out.usage!.check).toMatchObject({ violation: 'body_hash', settled: { kind: 'protest', txId: 'ACK' } })
    })

    it('refuses a stream the node didn’t seal', async () => {
        const s = await setup()
        await expect(frameFactory(s.deps, s.call, s.gen)(new Response(null))).rejects.toThrow('operator did not seal the SSE stream')
        expect(s.logger.logged).toContainEqual({
            level: 'warn',
            msg: 'operator opened SSE stream without sealed key — protocol violation',
            attrs: { operator_id: 7, node_id: 3 },
        })
    })

    it('refuses a key the ticket didn’t commit to, and one that won’t unwrap', async () => {
        const s = await setup()
        const other = await ResponseSealer.create({ replyTo: (s.call.reserved as Reserved).identity.recipient, txID: 'APPCALL', ticketID: TICKET_ID })
        await expect(frameFactory(s.deps, s.call, s.gen)(keyed(s, other.wrappedKeyHeader()))).rejects.toThrow(/commit_k/)
        await expect(frameFactory(s.deps, s.call, s.gen)(keyed(s, 'AAAA'))).rejects.toThrow(/^unwrap response key: /)
    })
})

describe('a streamed turn end to end', () => {
    // A caller who closes on the last content frame still has the receipt
    // verified and the ack submitted.
    it('settles after a caller who left on the terminal frame', async () => {
        const frames = ['{"choices":[{"delta":{"content":"A"}}]}', '{"choices":[{"delta":{},"finish_reason":"stop"}]}'].map((t) => enc.encode(t))
        const f = await fixture({}, enc.encode(''), bodyHashFromFrames(frames))
        const identity = await generateEphemeralIdentity()
        const sealer = await ResponseSealer.create({ replyTo: identity.recipient, txID: 'APPCALL', ticketID: TICKET_ID, key: f.responseKey })
        const handle = handleOf({ txid: 'ACK' })
        const reserved = { ticket: f.ticket, identity, responseKey: f.responseKey, algoUsdPrice: 0 } as unknown as Reserved
        const caller = new AbortController()
        const call: SealedCall = { endpoint: '/v1/chat/completions', model: 'm', op: f.op, reserved, handle, txId: 'APPCALL', hop: null, signal: caller.signal }
        let src!: ReturnType<typeof source>
        const deps = {
            logger: recLogger(),
            fetch: async (_u: string | URL | Request, init?: RequestInit) => {
                src = source(init!.signal!)
                for (const pt of frames) src.push(`event: zs\ndata: ${sealer.sealStreamFrame(pt)}\n\n`)
                return new Response(src.stream, { headers: { ...SSE, [RESPONSE_KEY_HEADER]: sealer.wrappedKeyHeader() } })
            },
        }
        const em = new StreamRecorder()
        // The caller leaves as the terminal frame reaches it; the node sends its tail after.
        em.onFrame = (o) => {
            if (o.frame && dec.decode(o.frame.data).includes('finish_reason')) {
                caller.abort()
                src.push(`event: zs-receipt\ndata: ${sealer.sealStreamFrame(enc.encode(JSON.stringify(f.receipt)))}\n\n`)
                src.push('data: [DONE]\n\n')
                src.close()
            }
            // An emitter may reshape what it's handed; the hash keeps its own copy.
            if (o.frame?.sealed) o.frame.data.fill(0x20)
        }
        const gen: GenComplete = { value: false }
        await forwardStream(
            deps,
            em as never,
            { url: 'https://node.example.com/v1/chat/completions', body: new Uint8Array(), headers: {} },
            call,
            frameFactory({ logger: deps.logger, feeRate: () => null }, call, gen),
            async () => {
                throw new Error('no fallback expected')
            },
            gen,
        )
        expect(handle.acks).toHaveLength(1)
        expect(em.outs.find((o) => o.usage)?.usage).toMatchObject({ check: { violation: '' }, feeBps: 0, haveFee: false })
        expect(em.data.at(-1)).toBe('[DONE]')
        expect(em.interrupted).toBe(0)
    })
})
