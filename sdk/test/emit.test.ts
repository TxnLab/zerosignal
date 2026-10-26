/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The emitter behind Stream.events and the Stream itself, porting go/zs
// emit_test.go's streamEmitter cases, stream_test.go and settle_test.go's
// Wait cases.

import { getEventListeners } from 'node:events'

import { describe, expect, it } from 'vitest'

import { newError, retryable } from '../src/codes.js'
import { StreamDecoder } from '../src/decode.js'
import { type Delivery, StreamEmitter } from '../src/emit.js'
import { NodeReply, ProviderError, ZsError } from '../src/errors.js'
import type { Event } from '../src/events.js'
import { type FeeUnit, feeUnitOf } from '../src/network.js'
import type { Reserved } from '../src/parts.js'
import { type SettleResult, SettleSlot } from '../src/receipt-check.js'
import type { UsageReport } from '../src/responder.js'
import { MAX_NODE_RETRY_HINT_MS } from '../src/routing/verdict.js'
import { type StreamFrame, emptyFrame, frameSSE } from '../src/stream.js'
import { type Emitter, type Request, type TurnRunner, TurnStream } from '../src/turn.js'
import { testOperator } from './fixtures.js'
import { ALGO_FEES, recLogger } from './turn-fixtures.js'

const enc = new TextEncoder()
const frameOf = (data: string, sealed = true, over: Partial<StreamFrame> = {}): StreamFrame => ({
    ...emptyFrame(),
    data: enc.encode(data),
    sealed,
    ...over,
})

const answerFrame = frameOf('{"choices":[{"index":0,"delta":{"content":"hi"}}]}')
const finishedFrame = frameOf('{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}')
const errorFrame = frameOf('{"error":{"message":"rate limited","code":"rate_limit_exceeded"}}')
const sentinelFrame = frameOf('[DONE]', false)

const CHAT = '/v1/chat/completions'

/** An emitter recording what it delivers; keepReading false makes the caller leave at once. */
function recording(o: { dec?: boolean; caller?: AbortSignal; feeUnit?: FeeUnit } = {}) {
    const events: Event[] = []
    const errors: ZsError[] = []
    let cancels = 0
    const em = new StreamEmitter(
        (d: Delivery) => {
            if ('error' in d) errors.push(d.error)
            else events.push(d.event)
        },
        () => {
            cancels++
        },
        o.caller,
        o.dec === false ? null : new StreamDecoder(CHAT),
        o.feeUnit ?? ALGO_FEES,
    )
    return {
        em,
        events,
        errors,
        get cancels() {
            return cancels
        },
    }
}

const reservedOf = (ticketId: string, maxPrice = 0): Reserved =>
    ({ ticket: { ticket_id: ticketId, max_price: maxPrice, expires_at: 2_000_000_000 } }) as unknown as Reserved

const op34 = testOperator({ id: 3, nodeId: 4 })

const usageOf = (): UsageReport =>
    ({
        receipt: {},
        ticket: { ticket_id: 'tid' },
        op: op34,
        openFees: 0,
        settleFees: 0,
        algoUsdPrice: 0,
        feeUnit: { currency: 'ALGO', decimals: 6 },
        feeBps: 0,
        haveFee: false,
        check: { violation: '', excluded: false, settled: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 } },
    }) as unknown as UsageReport

// Runs frames through a chat emitter, then ends the stream as the Stream does
// once the forwarder returns, and checks the one ending.
function ended(...frames: StreamFrame[]) {
    const r = recording()
    for (const f of frames) r.em.frame({ frame: f })
    r.em.finish()
    r.em.finish()
    r.em.interrupt()
    expect(r.errors.length).toBeLessThanOrEqual(1)
    if (r.errors.length === 1) expect(r.em.err).toBe(r.errors[0])
    return { events: r.events, err: r.errors[0] }
}

describe('StreamEmitter', () => {
    // A caller that stops reading has left: the emitter cancels the turn, so
    // the forwarder treats it as a disconnect, and nothing more is delivered.
    it('cancels on stop and drops everything after', () => {
        const r = recording()
        r.em.frame({ frame: frameOf('one') })
        r.em.stop()
        r.em.stop()
        expect(r.cancels).toBe(1)
        r.em.frame({ frame: frameOf('two') })
        r.em.fail(newError('no_operator', 'x'))
        expect(r.events.map((e) => e.type)).toEqual(['frame'])
        expect(r.errors).toEqual([])
        // The error is still the turn's, for err.
        expect(r.em.err?.code).toBe('no_operator')
    })

    // Every terminal error is judged retryable as it is delivered, except one
    // the caller's own signal ended. Paid or not is a separate answer.
    it.each([
        { name: 'transport loss', aborted: false, code: 'read_upstream', paid: false, want: true },
        { name: 'transport loss after payment', aborted: false, code: 'read_upstream', paid: true, want: true },
        { name: 'caller aborted', aborted: true, code: 'read_upstream', paid: false, want: false },
        { name: 'caller must fix it', aborted: false, code: 'missing_model', paid: false, want: false },
    ])('decides retryable at the end: $name', ({ aborted, code, paid, want }) => {
        const ac = new AbortController()
        if (aborted) ac.abort()
        const r = recording({ caller: ac.signal })
        if (paid) r.em.committed('tid', 'txid', 1000)
        r.em.fail(newError(code, 'x'))
        expect(r.errors).toHaveLength(1)
        expect(r.errors[0]).toMatchObject({ retryable: want, paid })
    })

    it('never advises a retry the caller’s abort ended, whatever the kind', () => {
        const ac = new AbortController()
        ac.abort()
        const busy = newError('operators_busy', 'm')
        expect(retryable(busy)).toBe(true)
        const r = recording({ caller: ac.signal })
        r.em.fail(busy)
        expect(busy.retryable).toBe(false)
    })

    // After the escrow open a failure is paid and names the ticket, because
    // nothing is resent after the open.
    it('marks a failure after the open paid, naming the ticket', () => {
        const r = recording()
        r.em.reserved(reservedOf('tid', 7), op34)
        r.em.committed('tid', 'txid', 1000)
        r.em.interrupt()
        const err = r.errors[0]!
        expect(err).toBeInstanceOf(ZsError)
        expect(err).toMatchObject({ paid: true, kind: 'interrupted', code: 'stream_interrupted' })
        expect(err.ticket).toMatchObject({ id: 'tid', target: { op: 3, node: 4 } })
        expect(err.ticket!.signed.max_price).toBe(7)
    })

    it('keeps a ticket the error already names', () => {
        const r = recording()
        r.em.reserved(reservedOf('tid'), op34)
        r.em.committed('tid', 'txid', 1000)
        const own = { id: 'other', signed: {}, target: { op: 1, node: 1 } } as never
        r.em.fail(newError('read_upstream', 'x', { ticket: own }))
        expect(r.errors[0]!.ticket).toBe(own)
    })

    // A free Solana turn commits with no open: nothing is locked, so a failure
    // after it is unpaid and names no ticket, and its resend costs nothing.
    it('leaves a failure after a free turn’s commit unpaid, with no ticket', () => {
        const r = recording({ feeUnit: feeUnitOf('solana') })
        r.em.reserved(reservedOf('tid', 0), op34)
        r.em.committed('tid', '', 0)
        r.em.interrupt()
        expect(r.events).toContainEqual({ type: 'payment.committed', ticketId: 'tid', openTxId: '', feesMicroAlgos: 0, networkFees: 0 })
        expect(r.errors[0]).toMatchObject({ paid: false, code: 'stream_interrupted', retryable: true })
        expect(r.errors[0]!.ticket).toBeUndefined()
    })

    it('leaves a failure before the open unpaid, with no ticket', () => {
        const r = recording()
        r.em.reserved(reservedOf('tid'), op34)
        r.em.fail(newError('wallet_open', 'x'))
        expect(r.errors[0]).toMatchObject({ paid: false })
        expect(r.errors[0]!.ticket).toBeUndefined()
    })

    it('reports the milestones as events', () => {
        const r = recording()
        r.em.clamped(512)
        r.em.reserved(reservedOf('tid', 9), op34)
        r.em.committed('tid', 'OPEN', 2000)
        r.em.note({ type: 'max_output.clamped', ceiling: 1 })
        expect(r.events).toEqual([
            { type: 'max_output.clamped', ceiling: 512 },
            { type: 'reserve.succeeded', ticketId: 'tid', target: { op: 3, node: 4 }, maxPrice: 9, expiresAt: new Date(2_000_000_000_000) },
            { type: 'payment.committed', ticketId: 'tid', openTxId: 'OPEN', feesMicroAlgos: 2000, networkFees: 2000 },
            { type: 'max_output.clamped', ceiling: 1 },
        ])
    })

    it('reports an open paid in another coin under networkFees alone', () => {
        const r = recording({ feeUnit: feeUnitOf('solana') })
        r.em.committed('tid', 'OPEN', 5000)
        expect(r.events).toEqual([{ type: 'payment.committed', ticketId: 'tid', openTxId: 'OPEN', feesMicroAlgos: 0, networkFees: 5000 }])
    })

    // The turn's one ending is decided from the node's sealed frames once the
    // stream is over. The plaintext [DONE] decides nothing.
    it.each([
        { name: 'finished', frames: [answerFrame, finishedFrame, sentinelFrame], err: '', empty: false },
        { name: 'finished without the sentinel', frames: [answerFrame, finishedFrame], err: '', empty: false },
        { name: 'sentinel added early', frames: [answerFrame, sentinelFrame, finishedFrame, sentinelFrame], err: '', empty: false },
        { name: 'cut before the finish', frames: [answerFrame, sentinelFrame], err: 'stream_interrupted', empty: false },
        { name: 'nothing', frames: [sentinelFrame], err: 'stream_interrupted', empty: false },
        { name: 'finished with no answer', frames: [finishedFrame, sentinelFrame], err: '', empty: true },
        { name: 'node error', frames: [answerFrame, errorFrame, sentinelFrame, finishedFrame], err: 'upstream_error', empty: false },
        { name: 'sealed [DONE] is content', frames: [frameOf('[DONE]'), answerFrame], err: 'stream_interrupted', empty: false },
        { name: 'plaintext finish is not evidence', frames: [answerFrame, frameOf(new TextDecoder().decode(finishedFrame.data), false)], err: 'stream_interrupted', empty: false },
    ])('ends on sealed evidence: $name', ({ frames, err, empty }) => {
        const out = ended(...frames)
        const dones = out.events.filter((e) => e.type === 'done')
        if (err !== '') {
            expect(out.err?.code).toBe(err)
            expect(dones).toEqual([])
            return
        }
        expect(out.err).toBeUndefined()
        expect(dones).toEqual([{ type: 'done', finishReason: 'stop', incompleteReason: '', empty }])
        expect(out.events.at(-1)).toBe(dones[0])
    })

    // A plaintext frame is passed on but never decoded: a relay can write one.
    it('passes a plaintext frame on undecoded', () => {
        const out = ended(frameOf(new TextDecoder().decode(answerFrame.data), false))
        expect(out.events.map((e) => e.type)).toEqual(['frame'])
    })

    it('passes a sealed frame on, then what it decodes to', () => {
        const r = recording()
        r.em.frame({ frame: answerFrame })
        expect(r.events).toEqual([
            { type: 'frame', event: '', id: '', data: answerFrame.data, comment: '', retry: 0, sealed: true },
            expect.objectContaining({ type: 'delta.text', delta: 'hi' }),
        ])
    })

    // An adapter re-emits a frame's data, so it must be the node's bytes:
    // decoded text would put U+FFFD for an invalid byte and drop a leading BOM.
    it('passes a frame’s bytes on as the node sent them', () => {
        const raw = Uint8Array.of(0xef, 0xbb, 0xbf, 0x22, 0xff, 0xc3, 0x22)
        const r = recording()
        r.em.frame({ frame: { ...emptyFrame(), data: raw, sealed: true } })
        r.em.reply(200, new Headers(), raw, null)
        const frames = r.events.filter((e) => e.type === 'frame')
        expect(frames).toHaveLength(2)
        for (const f of frames) expect(f.data).toEqual(raw)
    })

    // A stream that broke keeps the node's own account of why, when it gave one.
    it('prefers the node’s failure to an interruption', () => {
        const r = recording()
        r.em.frame({ frame: errorFrame })
        r.em.interrupt()
        expect(r.errors[0]?.code).toBe('upstream_error')
        expect(r.errors[0]?.message).toBe('rate limited')
    })

    it('ends a broken stream interrupted when the node said nothing', () => {
        const r = recording()
        r.em.frame({ frame: answerFrame })
        r.em.interrupt()
        expect(r.errors[0]).toMatchObject({ code: 'stream_interrupted', message: 'the stream broke before its end' })
    })

    // A single-body reply ends in done too, and one with no answer says so.
    it.each([
        { body: '', empty: true },
        { body: '{"choices":[{"index":0,"message":{"content":"hi"},"finish_reason":"stop"}]}', empty: false },
        { body: '{"choices":[{"index":0,"message":{"content":"","reasoning":"hmm"},"finish_reason":"stop"}]}', empty: true },
    ])('ends a whole reply in done: $body', ({ body, empty }) => {
        const r = recording()
        r.em.reply(200, new Headers(), enc.encode(body), null)
        expect(r.events.at(-1)).toMatchObject({ type: 'done', empty })
        expect(r.errors).toEqual([])
    })

    it('reports a whole reply as started, one sealed frame, its content, its usage, then done', () => {
        const r = recording()
        const body = '{"choices":[{"index":0,"message":{"content":"hi"},"finish_reason":"stop"}]}'
        r.em.reply(200, new Headers({ 'X-Request-Id': 'r' }), enc.encode(body), usageOf())
        expect(r.events.map((e) => e.type)).toEqual(['response.started', 'frame', 'delta.text', 'receipt.verified', 'done'])
        expect(r.events[0]).toMatchObject({ type: 'response.started', status: 200, streaming: false })
        expect(r.events[1]).toEqual({ type: 'frame', event: '', id: '', data: enc.encode(body), comment: '', retry: 0, sealed: true })
    })

    it('stops a reply once the caller leaves', () => {
        const events: Event[] = []
        let em!: StreamEmitter
        em = new StreamEmitter(
            (d) => {
                if ('event' in d) events.push(d.event)
                em.stop()
            },
            () => {},
            undefined,
            new StreamDecoder(CHAT),
            ALGO_FEES,
        )
        em.reply(200, new Headers(), enc.encode('{"choices":[{"index":0,"message":{"content":"hi"},"finish_reason":"stop"}]}'), usageOf())
        expect(events.map((e) => e.type)).toEqual(['response.started'])
    })

    // A reader who leaves mid-reply ends nothing: the failed reply is not
    // finished for it, so err stays empty and nothing more is delivered.
    it.each([
        { name: 'on the reply’s content', leaveOn: 'delta.text', body: '{"choices":[{"index":0,"message":{"content":"hi"},"finish_reason":"stop"}]}', usage: false },
        { name: 'on the reply’s usage', leaveOn: 'receipt.verified', body: '{"error":{"message":"overloaded"}}', usage: true },
    ])('stops a failed reply the reader left $name', ({ leaveOn, body, usage }) => {
        const events: Event[] = []
        let em!: StreamEmitter
        em = new StreamEmitter(
            (d) => {
                if (!('event' in d)) throw new Error('an error was delivered after the reader left')
                events.push(d.event)
                if (d.event.type === leaveOn) em.stop()
            },
            () => {},
            undefined,
            new StreamDecoder(CHAT),
            ALGO_FEES,
        )
        em.reply(503, new Headers(), enc.encode(body), usage ? usageOf() : null)
        expect(events.at(-1)!.type).toBe(leaveOn)
        expect(em.err).toBeUndefined()
    })

    // One node may ask for a day; the caller is told at most the cap.
    it('caps a failed reply’s Retry-After', () => {
        const r = recording()
        r.em.reply(503, new Headers({ 'Retry-After': '86400' }), enc.encode('{"detail":"x"}'), null)
        expect(r.errors[0]!.retryAfter).toBe(MAX_NODE_RETRY_HINT_MS)
    })

    // A sealed reply the node marked failed is not an answer, whether or not
    // its body says why, and its Retry-After is kept. Its status is what
    // judges a retry when the body names no code.
    it.each([
        { name: 'unexplained', body: '{"detail":"x"}', msg: 'the node answered HTTP 503', status: 503, nodeReply: true, retry: true },
        { name: 'not json', body: '<html>503</html>', msg: 'the node answered HTTP 503', status: 503, nodeReply: true, retry: true },
        { name: 'explained', body: '{"error":{"message":"overloaded","code":"provider_overloaded"}}', msg: 'overloaded', status: 503, nodeReply: false, retry: true },
        { name: 'explained without a code', body: '{"error":{"message":"overloaded"}}', msg: 'overloaded', status: 503, nodeReply: false, retry: true },
        { name: 'the lowest failed status', body: '{"detail":"x"}', msg: 'the node answered HTTP 400', status: 400, nodeReply: true, retry: false },
    ])('fails a reply the node marked failed: $name', ({ body, msg, status, nodeReply, retry }) => {
        const r = recording()
        const header = new Headers({ 'Retry-After': '7', 'X-Zs-Receipt': 'sealed', 'X-Request-Id': 'req-1' })
        r.em.reply(status, header, enc.encode(body), null)
        expect(r.events.some((e) => e.type === 'done')).toBe(false)
        const err = r.errors[0]!
        expect(err).toMatchObject({ kind: 'upstream', message: msg, retryAfter: 7000, retryable: retry })
        expect(err.cause instanceof NodeReply).toBe(nodeReply)
        if (err.cause instanceof NodeReply) {
            expect(err.cause.status).toBe(status)
            expect(err.cause.body).toEqual(enc.encode(body))
            expect(err.cause.header.get('X-Zs-Receipt')).toBeNull()
            expect(err.cause.header.get('X-Request-Id')).toBe('req-1')
        }
        if (err.cause instanceof ProviderError) expect(err.cause.status).toBe(status)
    })

    it('leaves a failed reply’s retry unhinted when the node named none', () => {
        const r = recording()
        r.em.reply(503, new Headers(), enc.encode('{"detail":"x"}'), null)
        expect(r.errors[0]!.retryAfter).toBeUndefined()
    })

    // framesOnly yields the node's frames and nothing decoded from them, an
    // error frame included, and a done with no fields once the stream is over.
    it('passes frames alone with framesOnly, ending in an empty done', () => {
        const r = recording({ dec: false })
        r.em.frame({ frame: answerFrame })
        r.em.frame({ frame: errorFrame })
        r.em.frame({ frame: sentinelFrame })
        r.em.finish()
        expect(r.errors).toEqual([])
        expect(r.events.map((e) => e.type)).toEqual(['frame', 'frame', 'frame', 'done'])
        expect(r.events[3]).toEqual({ type: 'done', finishReason: '', incompleteReason: '', empty: false })
    })

    // reply finishes the turn itself, and the Stream finishes it again once
    // the run returns; only one done may come of the two.
    it('ends a framesOnly whole reply in one done, however often it is finished', () => {
        const r = recording({ dec: false })
        r.em.reply(200, new Headers(), enc.encode('{}'), null)
        r.em.finish()
        expect(r.events.map((e) => e.type)).toEqual(['response.started', 'frame', 'done'])
    })

    it('passes a failed whole reply as a frame with framesOnly', () => {
        const r = recording({ dec: false })
        r.em.reply(503, new Headers(), enc.encode('{"detail":"x"}'), null)
        expect(r.errors).toEqual([])
        expect(r.events.map((e) => e.type)).toEqual(['response.started', 'frame', 'done'])
    })

    // An error the node reports inside its response ends the turn as paid and
    // upstream, after the receipt, in place of done.
    it('ends an error frame in a paid upstream error, after the receipt', () => {
        const r = recording()
        r.em.reserved(reservedOf('tid'), op34)
        r.em.committed('tid', 'txid', 1000)
        r.em.frame({ frame: errorFrame })
        r.em.frame({ usage: usageOf() })
        r.em.frame({ frame: sentinelFrame })
        r.em.finish()
        const err = r.errors[0]!
        expect(err).toMatchObject({ kind: 'upstream', code: 'upstream_error', message: 'rate limited', paid: true })
        expect(err.cause).toBeInstanceOf(ProviderError)
        expect(err.cause).toMatchObject({ code: 'rate_limit_exceeded', message: 'rate limited' })
        expect(err.ticket?.id).toBe('tid')
        expect(r.events.some((e) => e.type === 'done')).toBe(false)
        expect(r.events.some((e) => e.type === 'receipt.verified')).toBe(true)
    })

    // A node cutting the stream because the payer's open dropped unconfirmed
    // says so only in its own frame: the turn stays paid, and is retryable.
    it('keeps an unconfirmed open paid and retryable', () => {
        const r = recording()
        r.em.reserved(reservedOf('tid'), op34)
        r.em.committed('tid', 'txid', 1000)
        r.em.frame({ frame: frameOf('{"error":{"message":"open_unconfirmed: open txn dropped from pool","code":"payment_verification_failed"}}') })
        r.em.frame({ frame: sentinelFrame })
        r.em.finish()
        expect(r.errors[0]).toMatchObject({ kind: 'upstream', retryable: true, paid: true })
        expect(r.errors[0]!.ticket?.id).toBe('tid')
    })

    // The stream tally counts what a frame costs on the wire; a usage report
    // counts nothing.
    it('sizes a frame by its SSE encoding and a usage report at 0', () => {
        const r = recording({ dec: false })
        const f = frameOf('{"x":1}', true, { event: 'message' })
        expect(r.em.frame({ frame: f })).toBe(frameSSE(f).length)
        expect(r.em.frame({ usage: usageOf() })).toBe(0)
        expect(r.em.frame({})).toBe(0)
        expect(r.events.map((e) => e.type)).toEqual(['frame', 'receipt.verified'])
        expect(r.events[0]).toMatchObject({ event: 'message', data: enc.encode('{"x":1}') })
    })

    // response.started hands the caller the node's headers, never its
    // protocol fields, for a whole reply and a stream alike.
    it.each([false, true])('strips the protocol headers from response.started (streaming %s)', (streaming) => {
        const r = recording()
        const h = new Headers({ 'X-Zs-Settle-Group': 'pre-signed', 'X-Zs-Receipt': 'receipt', 'X-Zs-Evil': 'x', 'X-Request-Id': 'req-1' })
        if (streaming) expect(r.em.open(200, h)).toBe(true)
        else r.em.reply(200, h, enc.encode('{}'), null)
        const started = r.events.find((e) => e.type === 'response.started')
        expect(started).toMatchObject({ status: 200, streaming })
        const got = (started as { header: Headers }).header
        const names: string[] = []
        got.forEach((_v, k) => names.push(k))
        expect(names).toEqual(['x-request-id'])
        // The node's own set is left as it came.
        expect(h.get('X-Zs-Receipt')).toBe('receipt')
    })
})

const REQ: Request = { endpoint: CHAT, body: '{}' }

/** A Stream over run, recording each run's signal. */
function streamOf(run: (em: Emitter, slot: SettleSlot, signal: AbortSignal) => Promise<void>, req: Request = REQ, signal?: AbortSignal) {
    let runs = 0
    const signals: AbortSignal[] = []
    const runner: TurnRunner = (em, slot, s) => {
        runs++
        signals.push(s)
        return run(em, slot, s)
    }
    const st = new TurnStream(runner, req, ALGO_FEES, signal)
    return {
        st,
        signals,
        get runs() {
            return runs
        },
    }
}

const finishedRun = async (em: Emitter) => {
    em.open(200, new Headers())
    em.frame({ frame: answerFrame })
    em.frame({ frame: finishedFrame })
}

async function read(it: AsyncIterable<Event>): Promise<{ events: Event[]; err: unknown }> {
    const events: Event[] = []
    try {
        for await (const ev of it) events.push(ev)
    } catch (err) {
        return { events, err }
    }
    return { events, err: undefined }
}

describe('SettleSlot', () => {
    // Only the first outcome counts, for result and done alike.
    it('keeps the first finish', async () => {
        const slot = new SettleSlot()
        const a: SettleResult = { settlement: { ticketId: 'A', kind: 'atomic', txId: 'TA', feesMicroAlgos: 0, networkFees: 0 } }
        const b: SettleResult = { settlement: { ticketId: 'B', kind: 'payer_ack', txId: 'TB', feesMicroAlgos: 0, networkFees: 0 } }
        expect(slot.result).toBeUndefined()
        slot.finish(a)
        slot.finish(b)
        expect(slot.result).toBe(a)
        expect(await slot.done).toBe(a)
    })
})

describe('Stream', () => {
    it('runs nothing until its events are read', async () => {
        const s = streamOf(finishedRun)
        await Promise.resolve()
        expect(s.runs).toBe(0)
        const it = s.st.events()
        expect(s.runs).toBe(0)
        await read(it)
        expect(s.runs).toBe(1)
    })

    it('yields the turn’s events in order and ends in done', async () => {
        const s = streamOf(finishedRun)
        const out = await read(s.st.events())
        expect(out.err).toBeUndefined()
        expect(out.events.map((e) => e.type)).toEqual(['response.started', 'frame', 'delta.text', 'frame', 'done'])
        expect(out.events.at(-1)).toMatchObject({ type: 'done', finishReason: 'stop' })
        expect(s.st.err).toBeUndefined()
    })

    // A Stream runs its turn once: a second run reserves and pays a second time.
    it('runs its turn once, refusing a second read', async () => {
        const s = streamOf(finishedRun)
        await read(s.st.events())
        const again = await read(s.st.events())
        expect(again.events).toEqual([])
        expect(String(again.err)).toContain('can be read only once')
        expect(s.runs).toBe(1)
    })

    it('refuses a second read while the first is running', async () => {
        let release!: () => void
        const s = streamOf(async (em) => {
            em.open(200, new Headers())
            await new Promise<void>((r) => (release = r))
        })
        const first = s.st.events()[Symbol.asyncIterator]()
        await first.next()
        const again = await read(s.st.events())
        expect(String(again.err)).toContain('only once')
        release()
        await first.return?.()
        expect(s.runs).toBe(1)
    })

    it('throws the turn’s error after the events before it, once the run returns, and reports it as err', async () => {
        let returned = false
        const s = streamOf(async (em) => {
            em.open(200, new Headers())
            em.frame({ frame: answerFrame })
            em.interrupt()
            await new Promise((r) => setTimeout(r, 5))
            returned = true
        })
        const out = await read(s.st.events())
        expect(returned).toBe(true)
        expect(out.events.map((e) => e.type)).toContain('delta.text')
        expect(out.err).toBeInstanceOf(ZsError)
        expect(out.err).toMatchObject({ code: 'stream_interrupted' })
        expect(s.st.err).toBe(out.err)
    })

    it('ends a run that returns undecided by its decoder, before the read ends', async () => {
        const s = streamOf(async (em) => {
            em.open(200, new Headers())
            em.frame({ frame: answerFrame })
        })
        const out = await read(s.st.events())
        expect(out.err).toMatchObject({ code: 'stream_interrupted', message: 'the stream ended before the node said generation finished' })
    })

    it('passes the run’s own throw to the reader', async () => {
        const boom = new Error('boom')
        const s = streamOf(async () => {
            throw boom
        })
        const out = await read(s.st.events())
        expect(out.err).toBe(boom)
        // The slot still finishes, so wait doesn't hang.
        expect(await s.st.wait()).toEqual({ settlement: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 } })
    })

    // A loop that stops reading early is a caller who left: the turn is
    // cancelled, and the loop's exit waits for the run, as Go's range does.
    it('cancels the turn when the reader leaves, and its exit waits for the run', async () => {
        let returned = false
        const s = streamOf(async (e, _slot, signal) => {
            e.open(200, new Headers())
            e.frame({ frame: answerFrame })
            await new Promise<void>((r) => signal.addEventListener('abort', () => r(), { once: true }))
            // A tail drained after the caller left still runs.
            e.frame({ frame: finishedFrame })
            await new Promise((r) => setTimeout(r, 5))
            returned = true
        })
        const seen: string[] = []
        for await (const ev of s.st.events()) {
            seen.push(ev.type)
            if (ev.type === 'frame') break
        }
        expect(returned).toBe(true)
        expect(s.signals[0]!.aborted).toBe(true)
        expect(seen).toEqual(['response.started', 'frame'])
        // A turn the reader left isn't finished for it: the stream decided no ending.
        expect(s.st.err).toBeUndefined()
    })

    it('hands a run’s throw to a reader busy in its loop body, unhandled nowhere', async () => {
        const unhandled: unknown[] = []
        const onUnhandled = (err: unknown) => unhandled.push(err)
        process.on('unhandledRejection', onUnhandled)
        try {
            const boom = new Error('boom')
            const s = streamOf(async (em) => {
                em.open(200, new Headers())
                await new Promise((r) => setTimeout(r, 5))
                throw boom
            })
            let err: unknown
            try {
                for await (const _ of s.st.events()) await new Promise((r) => setTimeout(r, 30))
            } catch (e) {
                err = e
            }
            expect(err).toBe(boom)
            await new Promise((r) => setTimeout(r, 10))
            expect(unhandled).toEqual([])
        } finally {
            process.off('unhandledRejection', onUnhandled)
        }
    })

    // The reader already holds the turn's ending; a throw after it is logged,
    // and the reader and err agree on the ending.
    it('keeps the delivered error when the run throws after it', async () => {
        const logger = recLogger()
        const st = new TurnStream(
            async (em) => {
                em.fail(newError('no_operator', 'x'))
                throw new Error('late boom')
            },
            REQ,
            ALGO_FEES,
            undefined,
            logger,
        )
        const out = await read(st.events())
        expect(out.err).toMatchObject({ code: 'no_operator' })
        expect(st.err).toBe(out.err)
        expect(logger.logged).toEqual([{ level: 'error', msg: 'turn run failed after its ending', attrs: { err: 'late boom' } }])
    })

    it('cancels the turn when a reader with its own signal leaves', async () => {
        const caller = new AbortController()
        const s = streamOf(
            async (em, _slot, signal) => {
                em.open(200, new Headers())
                // Bounded, so a turn never told to stop fails the assertion, not the timeout.
                await new Promise<void>((r) => {
                    signal.addEventListener('abort', () => r(), { once: true })
                    setTimeout(r, 200)
                })
            },
            REQ,
            caller.signal,
        )
        for await (const _ of s.st.events()) break
        expect(s.signals[0]!.aborted).toBe(true)
        expect(caller.signal.aborted).toBe(false)
    })

    it('keeps the error a run decides after the reader left', async () => {
        const s = streamOf(async (em, _slot, signal) => {
            em.open(200, new Headers())
            await new Promise<void>((r) => signal.addEventListener('abort', () => r(), { once: true }))
            em.fail(newError('read_upstream', 'x'))
        })
        for await (const _ of s.st.events()) break
        expect(s.st.err).toMatchObject({ code: 'read_upstream' })
    })

    it('doesn’t cancel a turn whose error the reader was handed', async () => {
        const s = streamOf(async (em) => {
            em.fail(newError('no_operator', 'x'))
        })
        await read(s.st.events())
        expect(s.signals[0]!.aborted).toBe(false)
    })

    it('runs under the caller’s signal, and judges the turn by it', async () => {
        const caller = new AbortController()
        const s = streamOf(
            async (em, _slot, signal) => {
                caller.abort()
                expect(signal.aborted).toBe(true)
                em.fail(newError('operators_busy', 'm'))
            },
            REQ,
            caller.signal,
        )
        const out = await read(s.st.events())
        expect(out.err).toMatchObject({ code: 'operators_busy', retryable: false })
    })

    it('decodes nothing with framesOnly', async () => {
        const s = streamOf(finishedRun, { ...REQ, framesOnly: true })
        const out = await read(s.st.events())
        expect(out.events.map((e) => e.type)).toEqual(['response.started', 'frame', 'frame', 'done'])
    })

    it('decodes in the request’s endpoint dialect', async () => {
        const s = streamOf(
            async (em) => {
                em.reply(200, new Headers(), enc.encode('{"object":"response","status":"completed","output":[{"type":"message","id":"m1","content":[{"type":"output_text","text":"yo"}]}]}'), null)
            },
            { endpoint: '/v1/responses', body: '{}' },
        )
        expect(await s.st.text()).toBe('yo')
    })

    describe('text', () => {
        it('joins the answer’s text deltas', async () => {
            const s = streamOf(async (em) => {
                em.open(200, new Headers())
                em.frame({ frame: answerFrame })
                em.frame({ frame: answerFrame })
                em.frame({ frame: finishedFrame })
            })
            expect(await s.st.text()).toBe('hihi')
        })

        it('throws the turn’s error', async () => {
            const s = streamOf(async (em) => {
                em.fail(newError('no_operator', 'x'))
            })
            await expect(s.st.text()).rejects.toMatchObject({ code: 'no_operator' })
        })

        it('is empty with framesOnly', async () => {
            const s = streamOf(finishedRun, { ...REQ, framesOnly: true })
            expect(await s.st.text()).toBe('')
        })
    })

    describe('wait', () => {
        const settled: SettleResult = { settlement: { ticketId: 'T', kind: 'atomic', txId: 'TX', feesMicroAlgos: 0, networkFees: 0 } }

        it('refuses before the events are read', async () => {
            const s = streamOf(finishedRun)
            await expect(s.st.wait()).rejects.toThrow('wait called before')
        })

        it('resolves with the submit the turn reported', async () => {
            const s = streamOf(async (em, slot) => {
                slot.expected = true
                await finishedRun(em)
                setTimeout(() => slot.finish(settled), 5)
            })
            await read(s.st.events())
            expect(await s.st.wait()).toBe(settled)
        })

        it('rejects with the signal’s reason on an unfinished submit, and resolves once it finishes', async () => {
            let slot!: SettleSlot
            const s = streamOf(async (em, sl) => {
                slot = sl
                sl.expected = true
                await finishedRun(em)
            })
            await read(s.st.events())
            const ac = new AbortController()
            ac.abort(new Error('gone'))
            await expect(s.st.wait(ac.signal)).rejects.toThrow('gone')
            const live = new AbortController()
            const waiting = s.st.wait(live.signal)
            const later = new AbortController()
            const pending = s.st.wait(later.signal)
            later.abort(new Error('later'))
            await expect(pending).rejects.toThrow('later')
            slot.finish(settled)
            expect(await waiting).toBe(settled)
        })

        // A finished submit wins over an aborted signal: a handler waiting on
        // its request's signal after the client hung up still learns the txid.
        it('prefers a finished submit to an aborted signal', async () => {
            const s = streamOf(async (em, slot) => {
                slot.expected = true
                slot.finish(settled)
                await finishedRun(em)
            })
            await read(s.st.events())
            const ac = new AbortController()
            ac.abort()
            for (let i = 0; i < 50; i++) expect(await s.st.wait(ac.signal)).toBe(settled)
        })

        // A turn that fails before any escrow resolves with kind ''.
        it('resolves at once for a turn without a submit', async () => {
            const s = streamOf(async (em) => {
                em.fail(newError('no_operator', 'x'))
            })
            await read(s.st.events())
            expect(await s.st.wait()).toEqual({ settlement: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 } })
        })

        it('lets go of the signal once it resolves', async () => {
            let slot!: SettleSlot
            const s = streamOf(async (em, sl) => {
                slot = sl
                sl.expected = true
                await finishedRun(em)
            })
            await read(s.st.events())
            const ac = new AbortController()
            const waiting = s.st.wait(ac.signal)
            expect(getEventListeners(ac.signal, 'abort')).toHaveLength(1)
            slot.finish(settled)
            await waiting
            expect(getEventListeners(ac.signal, 'abort')).toHaveLength(0)
        })

        it('gives each turn without a submit its own result', async () => {
            const a = streamOf(finishedRun)
            const b = streamOf(finishedRun)
            await read(a.st.events())
            await read(b.st.events())
            const ra = await a.st.wait()
            ra.settlement.txId = 'MUTATED'
            expect((await b.st.wait()).settlement.txId).toBe('')
        })

        // A loop body that throws skips the rest of events; a caller that
        // catches it can still wait.
        it('resolves after a loop body that threw', async () => {
            const s = streamOf(finishedRun)
            await expect(
                (async () => {
                    for await (const _ of s.st.events()) throw new Error('caller bug')
                })(),
            ).rejects.toThrow('caller bug')
            expect(await s.st.wait()).toEqual({ settlement: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 } })
        })

        it('waits on a submit the turn built', async () => {
            let slot!: SettleSlot
            const s = streamOf(async (em, sl) => {
                slot = sl
                sl.expected = true
                await finishedRun(em)
            })
            await read(s.st.events())
            let done = false
            const waiting = s.st.wait().then((r) => {
                done = true
                return r
            })
            await new Promise((r) => setTimeout(r, 5))
            expect(done).toBe(false)
            slot.finish(settled)
            expect(await waiting).toBe(settled)
        })
    })
})
