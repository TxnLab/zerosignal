/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest'

import {
    bodyHashFromFrames,
    generateEphemeralIdentity,
    ResponseOpener,
    ResponseSealer,
    SEALED_HEADER_RECEIPT,
    SEALED_HEADER_SETTLE_GROUP,
} from '@txnlab/zs-proto/wire'

import {
    FrameOpenError,
    MissingReceiptError,
    type ResponseChunk,
    type SealedStreamOptions,
    type SseEvent,
    SseBufferOverflowError,
    SseNotEventStreamError,
    type StreamReceipt,
    openSealedStream,
    sseEvents,
} from '../src/response.js'

const enc = new TextEncoder()
const dec = new TextDecoder()

async function collect<T>(s: ReadableStream<T>): Promise<T[]> {
    const out: T[] = []
    const r = s.getReader()
    for (;;) {
        const { done, value } = await r.read()
        if (done) return out
        out.push(value)
    }
}

function textSource(chunks: string[]): ReadableStream<string> {
    return new ReadableStream({
        start(c) {
            for (const ch of chunks) c.enqueue(ch)
            c.close()
        },
    })
}

const parse = (chunks: string[], max?: number): Promise<SseEvent[]> =>
    collect(textSource(chunks).pipeThrough(max === undefined ? sseEvents() : sseEvents(max)))

describe('sseEvents', () => {
    it('ends events at a blank line, CRLF or LF, as Go reads them', async () => {
        expect(await parse(['data: a\r\n\r\ndata: b\n\n'])).toEqual([{ data: 'a' }, { data: 'b' }])
    })

    it('keeps the event name and joins data lines with a newline', async () => {
        expect(await parse(['event: zs\ndata: one\ndata: two\n\n'])).toEqual([{ event: 'zs', data: 'one\ntwo' }])
    })

    it('drops one space after the colon, not two', async () => {
        expect(await parse(['data:  x\n\ndata:y\n\n'])).toEqual([{ data: ' x' }, { data: 'y' }])
    })

    // A prose delta like "The " must keep the space that separates it from the next.
    it('keeps trailing spaces, and a payload that is only a space', async () => {
        expect(await parse(['data: The \n\ndata:  \n\n'])).toEqual([{ data: 'The ' }, { data: ' ' }])
    })

    it('reads an event far larger than one chunk, as an inline image frame is', async () => {
        const big = 'A'.repeat(20 * 1024 * 1024)
        const chunks = ['event: zs\n', 'data: ']
        for (let i = 0; i < big.length; i += 1024 * 1024) chunks.push(big.slice(i, i + 1024 * 1024))
        chunks.push('\n\n')
        const got = await parse(chunks)
        expect(got).toHaveLength(1)
        expect(got[0]!.event).toBe('zs')
        expect(got[0]!.data === big).toBe(true)
    })

    it('accepts a stream that opens with a blank line and a comment', async () => {
        expect(await parse(['\n: keep-alive\n\nevent: zs\ndata: ok\n\n'])).toEqual([{ event: 'zs', data: 'ok' }])
    })

    it('skips comments and an event with neither name nor data', async () => {
        expect(await parse([': zs-keepalive\n\nid: 1\nretry: 5\n\ndata: z\n\n'])).toEqual([{ data: 'z' }])
    })

    // As Go keeps it: a sealed frame with no data must reach the opener and fail
    // there, not vanish.
    it('keeps a named event that has no data line, with empty data', async () => {
        expect(await parse(['event: zs\n\ndata: z\n\n'])).toEqual([{ event: 'zs', data: '' }, { data: 'z' }])
    })

    // Go reads an empty name as no name, so `[DONE]` still ends the stream.
    it('reads an empty event name as no name', async () => {
        expect(await parse(['event:\ndata: [DONE]\n\n'])).toEqual([{ data: '[DONE]' }])
    })

    it('reads a field with no colon as an empty value', async () => {
        expect(await parse(['data: a\n\ndata\n\n'])).toEqual([{ data: 'a' }, { data: '' }])
    })

    it('reassembles events split anywhere across chunks', async () => {
        const text = 'event: zs\r\ndata: hello\r\n\r\ndata: [DONE]\n\n'
        expect(await parse([...text])).toEqual([{ event: 'zs', data: 'hello' }, { data: '[DONE]' }])
    })

    it('flushes a last event that has no blank line', async () => {
        expect(await parse(['data: a\n\ndata: tail'])).toEqual([{ data: 'a' }, { data: 'tail' }])
    })

    it('strips a leading byte-order mark', async () => {
        expect(await parse([String.fromCharCode(0xfeff) + 'data: a\n\n'])).toEqual([{ data: 'a' }])
    })

    it('fails at the first line on a body that is not SSE', async () => {
        await expect(parse(['<html><body>502</body></html>'])).rejects.toBeInstanceOf(SseNotEventStreamError)
        await expect(parse(['{"error":{"message":"x"}}\n'])).rejects.toBeInstanceOf(SseNotEventStreamError)
    })

    // Once judged SSE, a last line cut off mid-field is an unknown field, as in Go.
    it('ignores a well-framed body cut off mid-field', async () => {
        expect(await parse(['data: a\n', 'dat'])).toEqual([{ data: 'a' }])
    })

    it('judges a body too short to judge early once it ends', async () => {
        await expect(parse(['<b>'])).rejects.toBeInstanceOf(SseNotEventStreamError)
        expect(await parse(['data:'])).toEqual([{ data: '' }])
    })

    // Leading newlines are dropped as they arrive, so a body of nothing else
    // holds nothing while it waits to be judged.
    it('holds nothing for a body of leading newlines', async () => {
        expect(await parse(Array.from({ length: 250 }, () => '\r\n'), 10)).toEqual([])
        expect(await parse([...Array.from({ length: 250 }, () => '\n'), 'data: x\n\n'], 10)).toEqual([{ data: 'x' }])
    })

    it('counts empty data lines toward the ceiling', async () => {
        await expect(parse([`${'data:\n'.repeat(20)}`], 10)).rejects.toBeInstanceOf(SseBufferOverflowError)
    })

    it('waits for a field name split across chunks before judging', async () => {
        expect(await parse(['da', 'ta: x\n\n'])).toEqual([{ data: 'x' }])
        expect(await parse(['\n\n', 're', 'try: 1\ndata: y\n\n'])).toEqual([{ data: 'y' }])
    })

    it('fails on an event that outgrows the ceiling, counting its finished data lines', async () => {
        await expect(parse(['data: 0123456789'], 10)).rejects.toBeInstanceOf(SseBufferOverflowError)
        // Each line is short; the event they add up to is not.
        await expect(parse(['data: 123\ndata: 456\ndata: 789\ndata: 01\n'], 10)).rejects.toBeInstanceOf(
            SseBufferOverflowError,
        )
    })

    // Split so the check runs while the event is still open: two lines of 5,
    // each counted with the newline join adds, hold 12.
    it('allows an event exactly at the ceiling, and frees it once the event ends', async () => {
        const open = ['data: 12345\ndata: 67890\n', '\n']
        expect(await parse(open, 12)).toEqual([{ data: '12345\n67890' }])
        await expect(parse(open, 11)).rejects.toBeInstanceOf(SseBufferOverflowError)
        expect(await parse(['data: 1234567890\n', '\n', 'data: 1234567890\n', '\n'], 11)).toHaveLength(2)
    })
})

const TX = 'TX-ID'
const TICKET = 'AQIDBAUGBwgJCgsMDQ4PEA=='

interface Wire {
    sealer: ResponseSealer
    key: Uint8Array
}

async function wire(): Promise<Wire> {
    const id = await generateEphemeralIdentity()
    const key = new Uint8Array(32).fill(7)
    const sealer = await ResponseSealer.create({ replyTo: id.recipient, txID: TX, ticketID: TICKET, key })
    return { sealer, key }
}

const receiptJSON = (amount: number) =>
    enc.encode(JSON.stringify({ ticket_id: TICKET, amount_charged: amount, body_hash: '00'.repeat(32) }))

const chat = (s: string) => enc.encode(JSON.stringify({ choices: [{ delta: { content: s } }] }))
const stop = enc.encode(JSON.stringify({ choices: [{ delta: {}, finish_reason: 'stop' }] }))

const ev = (event: string, data: string) => `event: ${event}\ndata: ${data}\n\n`
const plain = (data: string) => `data: ${data}\n\n`

/** A byte source a test controls: what was sent, whether it was cancelled. */
function source(parts: string[], opts: { hold?: boolean } = {}) {
    let cancelled = false
    let controller!: ReadableStreamDefaultController<Uint8Array>
    const stream = new ReadableStream<Uint8Array>({
        start(c) {
            controller = c
            for (const p of parts) c.enqueue(enc.encode(p))
            if (!opts.hold) c.close()
        },
        cancel() {
            cancelled = true
        },
    })
    return {
        stream,
        push: (p: string) => controller.enqueue(enc.encode(p)),
        close: () => controller.close(),
        cancelled: () => cancelled,
    }
}

function run(w: Wire, src: ReadableStream<Uint8Array>, extra: Partial<SealedStreamOptions> = {}) {
    const receipts: StreamReceipt[] = []
    const closed = vi.fn()
    const stream = openSealedStream({
        source: src,
        opener: new ResponseOpener(w.key, TX, TICKET),
        api: 'chat',
        onReceipt: (r) => receipts.push(r),
        onClosed: closed,
        ...extra,
    })
    return { stream, receipts, closed }
}

const texts = (chunks: ResponseChunk[]) =>
    chunks.map((c) => (c.kind === 'content' ? `c:${dec.decode(c.bytes)}` : `p:${c.data}`))

describe('openSealedStream', () => {
    it('opens content in order, hands over the receipt, and ends at [DONE]', async () => {
        const w = await wire()
        const a = chat('a')
        const sg = w.sealer.sealHeader(SEALED_HEADER_SETTLE_GROUP, enc.encode('GROUP-B64'))
        const body = [
            ev('zs', w.sealer.sealStreamFrame(a)),
            ev('zs', w.sealer.sealStreamFrame(stop)),
            ev('zs-settle-group', sg),
            ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(5))),
            plain('[DONE]'),
            plain('after-done'),
        ]
        const { stream, receipts, closed } = run(w, source(body).stream)
        const out = await collect(stream)
        expect(texts(out)).toEqual([`c:${dec.decode(a)}`, `c:${dec.decode(stop)}`])
        expect(receipts).toHaveLength(1)
        expect(receipts[0]!.receipt.amount_charged).toBe(5)
        expect(receipts[0]!.settleGroup).toBe('GROUP-B64')
        expect(receipts[0]!.bodyHash).toEqual(bodyHashFromFrames([a, stop]))
        expect(receipts[0]!.contentFrames).toEqual([a, stop])
        await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
    })

    // SPEC § 5.3: anything but a sealed frame is passed on with the counter
    // unchanged, and body_hash covers the content frames alone.
    it('passes unsealed data through without hashing it or moving the counter', async () => {
        const w = await wire()
        const a = chat('a')
        const body = [
            plain('{"plain":1}'),
            ev('zs', w.sealer.sealStreamFrame(a)),
            ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(1))),
        ]
        const { stream, receipts } = run(w, source(body).stream)
        expect(texts(await collect(stream))).toEqual(['p:{"plain":1}', `c:${dec.decode(a)}`])
        expect(receipts[0]!.bodyHash).toEqual(bodyHashFromFrames([a]))
    })

    it('hands a named unsealed event to onEvent, not to the reader', async () => {
        const w = await wire()
        const onEvent = vi.fn()
        const { stream } = run(w, source([ev('zs-notice', '{"n":1}'), plain('x')]).stream, { onEvent })
        expect(texts(await collect(stream))).toEqual(['p:x'])
        expect(onEvent).toHaveBeenCalledWith('zs-notice', '{"n":1}')
    })

    it('keeps no settle group that fails to open, and still opens the receipt', async () => {
        const w = await wire()
        // Sealed under the receipt's header name, so it can't open as a settle group.
        const wrong = w.sealer.sealHeader(SEALED_HEADER_RECEIPT, enc.encode('GROUP'))
        const body = [ev('zs-settle-group', wrong), ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(2)))]
        const { stream, receipts } = run(w, source(body).stream)
        await collect(stream)
        expect(receipts).toHaveLength(1)
        expect(receipts[0]!.settleGroup).toBeNull()
    })

    it('errors on a content frame that does not open, naming its index', async () => {
        const w = await wire()
        const body = [ev('zs', w.sealer.sealStreamFrame(chat('a'))), ev('zs', 'AAAA' + w.sealer.sealStreamFrame(chat('b')))]
        const { stream, closed } = run(w, source(body).stream)
        const err = await collect(stream).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(FrameOpenError)
        expect((err as FrameOpenError).frameIndex).toBe(1)
        await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
    })

    it('discards a receipt that does not open, and leaves the stream whole', async () => {
        const w = await wire()
        const a = chat('a')
        const frame0 = w.sealer.sealStreamFrame(a)
        w.sealer.sealStreamFrame(enc.encode('never sent')) // so the receipt lands one index ahead
        const body = [ev('zs', frame0), ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(3))), plain('x')]
        const { stream, receipts } = run(w, source(body).stream)
        expect(texts(await collect(stream))).toEqual([`c:${dec.decode(a)}`, 'p:x'])
        expect(receipts).toHaveLength(0)
    })

    it('errors at the end without a receipt when one is required', async () => {
        // Both ways a stream ends: at [DONE], and at the end of the body.
        for (const tail of [[plain('[DONE]')], []]) {
            const w = await wire()
            const body = [ev('zs', w.sealer.sealStreamFrame(chat('a'))), ...tail]
            const required = run(w, source(body).stream, { requireReceipt: true })
            await expect(collect(required.stream)).rejects.toBeInstanceOf(MissingReceiptError)

            const w2 = await wire()
            const body2 = [ev('zs', w2.sealer.sealStreamFrame(chat('a'))), ...tail]
            expect(await collect(run(w2, source(body2).stream).stream)).toHaveLength(1)
        }
    })

    // SPEC § 5.3: content after the tail opens is outside the receipt's
    // body_hash, so it never reaches the reader, and the stream stands.
    it('drops content after the receipt or an opened settle group', async () => {
        for (const tailEvent of ['zs-settle-group', 'zs-receipt'] as const) {
            const w = await wire()
            const a = chat('a')
            const frame0 = w.sealer.sealStreamFrame(a)
            const tail =
                tailEvent === 'zs-settle-group'
                    ? ev('zs-settle-group', w.sealer.sealHeader(SEALED_HEADER_SETTLE_GROUP, enc.encode('G')))
                    : ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(1)))
            const body = [ev('zs', frame0), tail, ev('zs', w.sealer.sealStreamFrame(chat('late'))), plain('[DONE]')]
            const { stream } = run(w, source(body).stream)
            expect(texts(await collect(stream))).toEqual([`c:${dec.decode(a)}`])
        }
    })

    it('settles on the first receipt only', async () => {
        const w = await wire()
        const body = [
            ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(1))),
            ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(9))),
        ]
        const { stream, receipts } = run(w, source(body).stream)
        await collect(stream)
        expect(receipts.map((r) => r.receipt.amount_charged)).toEqual([1])
    })

    // As in Go: a receipt that opens but doesn't parse took its index, and
    // doesn't count as the stream's receipt.
    it('takes the next receipt after one that opens but does not parse', async () => {
        const w = await wire()
        const body = [
            ev('zs-receipt', w.sealer.sealStreamFrame(enc.encode('not json'))),
            ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(4))),
        ]
        const { stream, receipts } = run(w, source(body).stream)
        await collect(stream)
        expect(receipts.map((r) => r.receipt.amount_charged)).toEqual([4])
    })

    it('reports the time spent opening each sealed frame', async () => {
        const w = await wire()
        const onOpenSample = vi.fn()
        const body = [
            ev('zs', w.sealer.sealStreamFrame(chat('a'))),
            ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(1))),
            plain('x'),
        ]
        await collect(run(w, source(body).stream, { onOpenSample }).stream)
        expect(onOpenSample).toHaveBeenCalledTimes(2)
    })

    describe('when the reader leaves', () => {
        it('cancels the node at once before the generation finished', async () => {
            const w = await wire()
            const src = source([ev('zs', w.sealer.sealStreamFrame(chat('a')))], { hold: true })
            const { stream, receipts, closed } = run(w, src.stream)
            const reader = stream.getReader()
            await reader.read()
            await reader.cancel('gone')
            await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
            expect(src.cancelled()).toBe(true)
            expect(receipts).toHaveLength(0)
        })

        it('drains the tail after a terminal frame, so the receipt is still handled', async () => {
            const w = await wire()
            const src = source([ev('zs', w.sealer.sealStreamFrame(stop))], { hold: true })
            const order: string[] = []
            const { stream } = run(w, src.stream, {
                onReceipt: (r) => order.push(`receipt:${r.receipt.amount_charged}`),
                onClosed: () => order.push('closed'),
            })
            const reader = stream.getReader()
            await reader.read()
            await reader.cancel('gone')
            expect(src.cancelled()).toBe(false)
            src.push(ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(6))))
            src.push(plain('[DONE]'))
            // Closed only after the receipt: the key is zeroed in onClosed.
            await vi.waitFor(() => expect(order).toEqual(['receipt:6', 'closed']))
        })

        // A node sends the settle group only after its last content frame, so it
        // arms the drain even when no frame read as terminal.
        it('drains after a settle group though no frame read as terminal', async () => {
            const w = await wire()
            const sg = w.sealer.sealHeader(SEALED_HEADER_SETTLE_GROUP, enc.encode('G'))
            const src = source(
                [ev('zs', w.sealer.sealStreamFrame(chat('a'))), ev('zs-settle-group', sg), plain('marker')],
                { hold: true },
            )
            const { stream, receipts, closed } = run(w, src.stream)
            const reader = stream.getReader()
            await reader.read()
            // Reading the marker means the settle group before it was taken.
            expect((await reader.read()).value).toEqual({ kind: 'plain', data: 'marker' })
            await reader.cancel('gone')
            src.push(ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(8))))
            src.close()
            await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
            expect(src.cancelled()).toBe(false)
            expect(receipts.map((r) => [r.receipt.amount_charged, r.settleGroup])).toEqual([[8, 'G']])
        })

        it('gives the tail drainTimeoutMs, then cancels the node', async () => {
            const w = await wire()
            const src = source([ev('zs', w.sealer.sealStreamFrame(stop))], { hold: true })
            const { stream, closed } = run(w, src.stream, { drainTimeoutMs: 100 })
            const reader = stream.getReader()
            await reader.read()
            await reader.cancel('gone')
            const t0 = Date.now()
            // Still draining part way through the window...
            await new Promise((r) => setTimeout(r, 30))
            expect(src.cancelled()).toBe(false)
            expect(closed).not.toHaveBeenCalled()
            // ...and cancelled once it ends.
            await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
            expect(src.cancelled()).toBe(true)
            expect(Date.now() - t0).toBeGreaterThanOrEqual(90)
        })

        // The vocabulary is the caller's: on the Responses API, response.completed
        // is the terminal frame that arms the drain.
        it('drains after a Responses API completion', async () => {
            const w = await wire()
            const done = enc.encode(JSON.stringify({ type: 'response.completed', response: { id: 'r' } }))
            const src = source([ev('zs', w.sealer.sealStreamFrame(done))], { hold: true })
            const { stream, receipts, closed } = run(w, src.stream, { api: 'responses' })
            const reader = stream.getReader()
            await reader.read()
            await reader.cancel('gone')
            src.push(ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(2))))
            src.close()
            await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
            expect(src.cancelled()).toBe(false)
            expect(receipts.map((r) => r.receipt.amount_charged)).toEqual([2])
        })

        it('drains for ten seconds by default', async () => {
            const w = await wire()
            const src = source([ev('zs', w.sealer.sealStreamFrame(stop))], { hold: true })
            vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] })
            try {
                const { stream, receipts, closed } = run(w, src.stream)
                const reader = stream.getReader()
                await reader.read()
                await reader.cancel('gone')
                await vi.advanceTimersByTimeAsync(9_000)
                expect(src.cancelled()).toBe(false)
                src.push(ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(4))))
                await vi.advanceTimersByTimeAsync(10)
                expect(receipts.map((r) => r.receipt.amount_charged)).toEqual([4])
                await vi.advanceTimersByTimeAsync(1_000)
                await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
                expect(src.cancelled()).toBe(true)
            } finally {
                vi.useRealTimers()
            }
        })

        it('stops promptly when the reader breaks out of a for-await before the end', async () => {
            const w = await wire()
            const src = source([ev('zs', w.sealer.sealStreamFrame(chat('a')))], { hold: true })
            const { stream, closed } = run(w, src.stream)
            for await (const _ of stream as unknown as AsyncIterable<ResponseChunk>) break
            await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
            expect(src.cancelled()).toBe(true)
        })
    })

    // Go copies before keeping. Without the copy, a reader that reuses or
    // transfers the bytes it was given would change the hash, and an honest
    // node would be protested.
    it('hashes its own copy of each frame, not the bytes the reader holds', async () => {
        const w = await wire()
        const a = chat('a')
        const body = [ev('zs', w.sealer.sealStreamFrame(a)), plain('marker')]
        const src = source(body, { hold: true })
        const { stream, receipts } = run(w, src.stream)
        const reader = stream.getReader()
        const first = (await reader.read()).value as ResponseChunk & { kind: 'content' }
        first.bytes.fill(0)
        await reader.read()
        src.push(ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(1))))
        src.close()
        while (!(await reader.read()).done) {
            // drain
        }
        expect(receipts[0]!.bodyHash).toEqual(bodyHashFromFrames([a]))
        expect(receipts[0]!.contentFrames).toEqual([a])
    })

    // The receipt that failed to open took no index, so the next one opens there.
    it('opens the next receipt at the index a failed one left', async () => {
        const w = await wire()
        const a = chat('a')
        const body = [
            ev('zs', w.sealer.sealStreamFrame(a)),
            ev('zs-receipt', 'AAAA' + w.sealer.sealStreamFrame(receiptJSON(3)).slice(4)),
        ]
        // The good receipt is sealed at index 1, the same index the bad one tried.
        const w2 = await wire()
        w2.sealer.sealStreamFrame(a)
        body.push(ev('zs-receipt', w2.sealer.sealStreamFrame(receiptJSON(7))))
        const { stream, receipts } = run(w, source(body).stream)
        await collect(stream)
        expect(receipts.map((r) => r.receipt.amount_charged)).toEqual([7])
    })

    it('errors on a sealed frame with no data, as Go fails to open it', async () => {
        const w = await wire()
        const { stream } = run(w, source(['event: zs\n\n']).stream)
        await expect(collect(stream)).rejects.toBeInstanceOf(FrameOpenError)
    })

    it('passes a source error to the reader, and still closes', async () => {
        const w = await wire()
        const failing = new ReadableStream<Uint8Array>({
            start(c) {
                c.enqueue(enc.encode(ev('zs', w.sealer.sealStreamFrame(chat('a')))))
                c.error(new Error('connection reset'))
            },
        })
        const { stream, closed } = run(w, failing)
        await expect(collect(stream)).rejects.toThrow('connection reset')
        await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
    })

    it('keeps the stream whole when onReceipt or onClosed throws', async () => {
        const w = await wire()
        const a = chat('a')
        const errors: string[] = []
        const logger = { debug() {}, info() {}, warn() {}, error: (m: string) => errors.push(m) }
        const body = [ev('zs', w.sealer.sealStreamFrame(a)), ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(1)))]
        const { stream } = run(w, source(body).stream, {
            onReceipt: () => {
                throw new Error('handler')
            },
            onClosed: () => {
                throw new Error('closer')
            },
            logger,
        })
        expect(texts(await collect(stream))).toEqual([`c:${dec.decode(a)}`])
        await vi.waitFor(() => expect(errors).toEqual(['onReceipt threw', 'onClosed threw']))
    })

    it('logs an error frame from the node, and treats it as terminal', async () => {
        const w = await wire()
        const warns: Array<[string, unknown]> = []
        const logger = { debug() {}, info() {}, warn: (m: string, a?: unknown) => warns.push([m, a]), error() {} }
        const errFrame = enc.encode(JSON.stringify({ error: { message: 'upstream down' } }))
        const src = source([ev('zs', w.sealer.sealStreamFrame(errFrame))], { hold: true })
        const { stream, closed } = run(w, src.stream, { logger })
        const reader = stream.getReader()
        await reader.read()
        expect(warns).toEqual([['operator returned stream error', { ticket_id: TICKET, error: 'upstream down' }]])
        await reader.cancel('gone')
        // Terminal, so the tail is drained rather than cancelled.
        src.push(ev('zs-receipt', w.sealer.sealStreamFrame(receiptJSON(0))))
        src.close()
        await vi.waitFor(() => expect(closed).toHaveBeenCalledOnce())
        expect(src.cancelled()).toBe(false)
    })
})
