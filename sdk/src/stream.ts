/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A streamed turn's answer, mirroring proto/go/zs sse.go's forwardRawStream
// and pumpSSE and dispatch.go's buildFrameFactory: send the sealed request,
// read the node's SSE frames line by line, open the sealed ones, and settle on
// the receipt frame inline. A caller who leaves after the generation finished
// still has the receipt tail drained, so the node is paid for what it
// delivered; one who leaves before cancels the node at once.
//
// response.ts's openSealedStream is the standalone primitive; this is the
// Client's, and keeps Go's choices where that one departs (it reads past
// [DONE] to the end, passes every unsealed frame on, and only a terminal
// frame arms the drain).

import { parseReceiptJSON } from '@txnlab/zs-proto/ticket'
import { extractResponseIDFromFrame, extractStreamToolCallIDs } from '@txnlab/zs-proto/selection'
import { TRANSPORT_FAILURE_STATUS } from '@txnlab/zs-proto/transient'
import {
    RESPONSE_KEY_HEADER,
    ResponseOpener,
    SEALED_HEADER_SETTLE_GROUP,
    STREAM_EVENT_MARKER,
    STREAM_EVENT_RECEIPT,
    STREAM_EVENT_SETTLE_GROUP,
    type StreamApi,
    bodyHashFromFrames,
    classifyStreamFrame,
} from '@txnlab/zs-proto/wire'

import { newError } from './codes.js'
import { goDecodeUTF8 } from './gotext.js'
import type { IdleWatchdog, StreamIdleTimeoutError } from './idle.js'
import { type Operator, refOf } from './operator.js'
import type { Clock, LogAttrs } from './ports.js'
import { type ReceiptCheckDeps, type SettleSlot, checkTurnReceipt } from './receipt-check.js'
import { type ResponderDeps, type UsageReport, openCommittedKey, openSealedResponseMeta, settleGroupOf } from './responder.js'
import { DRAIN_TAIL_TIMEOUT_MS } from './response.js'
import { type RelayHop, relayRef } from './routing/relay.js'
import { type BufferedResponder, type Outbound, type SealedCall, type SealedDeps, attributeRelayHop } from './sealed.js'
import type { Emitter } from './turn.js'
import type { Endpoint } from './types.js'

/** One Server-Sent Event as the pump reads it, Go's Frame. data is the joined data lines, as bytes. */
export interface StreamFrame {
    event: string
    id: string
    data: Uint8Array
    comment: string
    retry: number
    /** Set when data was opened from the node's sealed stream. */
    sealed: boolean
}

/**
 * OutFrame is what one upstream frame becomes for the caller: a frame to pass
 * on, or the verified usage the receipt frame carried, or neither.
 */
export interface OutFrame {
    frame?: StreamFrame
    usage?: UsageReport
}

/** The per-frame hook: opens the node's sealed frames and settles on its receipt. */
export type FrameTransform = (f: StreamFrame) => Promise<OutFrame>

/**
 * Builds the hook from the node's response headers, which carry the key the
 * frames are sealed under. It throws when the stream can't be opened at all.
 */
export type FrameTransformFactory = (resp: Response) => Promise<FrameTransform>

/**
 * Set by the frame hook once the node's generation has ended (a terminal or
 * error frame), so a caller leaving after it drains the receipt tail.
 */
export interface GenComplete {
    value: boolean
}

export function emptyFrame(): StreamFrame {
    return { event: '', id: '', data: new Uint8Array(), comment: '', retry: 0, sealed: false }
}

export function isEmptyFrame(f: StreamFrame): boolean {
    return f.data.length === 0 && f.event === '' && f.id === '' && f.retry === 0 && f.comment === ''
}

function isEmptyOut(o: OutFrame): boolean {
    return (o.frame === undefined || isEmptyFrame(o.frame)) && o.usage === undefined
}

const enc = new TextEncoder()
// ignoreBOM: Go's string(bytes) keeps a leading BOM, so a BOM-led field name
// matches nothing, as it doesn't in Go.
const dec = new TextDecoder('utf-8', { ignoreBOM: true })

/**
 * frameSSE is f in Server-Sent Events wire form, ending in its blank line, as
 * an OpenAI-compatible endpoint would write it: Go's Frame.SSE.
 */
export function frameSSE(f: StreamFrame): Uint8Array {
    const parts: Uint8Array[] = []
    const text = (s: string) => parts.push(enc.encode(s))
    if (f.comment !== '') text(`: ${f.comment}\n`)
    if (f.event !== '') text(`event: ${f.event}\n`)
    if (f.id !== '') text(`id: ${f.id}\n`)
    if (f.retry > 0) text(`retry: ${f.retry}\n`)
    if (f.data.length > 0) {
        // One data line per line of data.
        let start = 0
        for (;;) {
            const nl = f.data.indexOf(0x0a, start)
            text('data: ')
            parts.push(f.data.subarray(start, nl === -1 ? f.data.length : nl))
            text('\n')
            if (nl === -1) break
            start = nl + 1
        }
    }
    text('\n')
    return concat(parts)
}

function concat(parts: readonly Uint8Array[]): Uint8Array {
    let n = 0
    for (const p of parts) n += p.length
    const out = new Uint8Array(n)
    let at = 0
    for (const p of parts) {
        out.set(p, at)
        at += p.length
    }
    return out
}

/**
 * StreamTally counts what a forward forwarded, never what the frames held: a
 * frame written after the caller left still counts. Its gap timings tell a
 * caller's total-elapsed deadline (frames flowing until the cut) from an idle
 * timeout (a silence before the cut), which take maxGap and silenceBeforeCut
 * together: maxGap spans frame to frame and can't see the last silence.
 */
export class StreamTally {
    frames = 0
    bytes = 0
    #firstAt: number | undefined
    #lastAt: number | undefined
    maxGap = 0
    readonly #clock: Clock

    constructor(clock: Clock = Date.now) {
        this.#clock = clock
    }

    /** Notes one frame written toward the caller. */
    record(n: number): void {
        const now = this.#clock()
        this.frames++
        this.bytes += n
        if (this.#firstAt === undefined) this.#firstAt = now
        else if (now - this.#lastAt! > this.maxGap) this.maxGap = now - this.#lastAt!
        this.#lastAt = now
    }

    /**
     * attrs renders the tally for a log line. start is when the node's headers
     * arrived, so ttfb is headers to first frame: the node's admission and
     * prefill, not the caller's whole wait. Durations are milliseconds.
     */
    attrs(start: number): LogAttrs {
        const now = this.#clock()
        return {
            frames: this.frames,
            bytes: this.bytes,
            elapsed_ms: now - start,
            ttfb_ms: this.#firstAt === undefined ? 0 : this.#firstAt - start,
            max_inter_frame_gap_ms: this.maxGap,
            // 0 with no frames: there was never a frame for the silence to follow.
            silence_before_cut_ms: this.#lastAt === undefined ? 0 : now - this.#lastAt,
        }
    }
}

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err))

const opAttrs = (op: Operator): LogAttrs => ({ operator_id: op.id, node_id: op.nodeId })

const relayAttrs = (hop: RelayHop | null): LogAttrs =>
    hop === null ? {} : { relay_operator_id: hop.relayId, relay_node_id: hop.relayNodeId }

function abortError(signal: AbortSignal): unknown {
    return signal.reason ?? new Error('aborted')
}

// strconv.Atoi: an optional sign and digits, within int64.
function goAtoi(s: string): number | null {
    if (!/^[+-]?[0-9]+$/.test(s)) return null
    const n = BigInt(s)
    if (n < -(1n << 63n) || n > (1n << 63n) - 1n) return null
    return Number(n)
}

// trimLineEnd drops one LF, then one CR.
function trimLineEnd(b: Uint8Array): Uint8Array {
    let n = b.length
    if (n > 0 && b[n - 1] === 0x0a) n--
    if (n > 0 && b[n - 1] === 0x0d) n--
    return b.subarray(0, n)
}

/**
 * pumpSSE reads SSE frames from body, passes each through frameFn, and hands
 * the result to emit, Go's pumpSSE. Lines end at LF with one trailing CR
 * dropped, of any length; a blank line ends a frame, and a last frame without
 * one still counts. It resolves at the body's end and throws on anything else,
 * signal's abort included.
 */
export async function pumpSSE(
    signal: AbortSignal,
    emit: (out: OutFrame) => number,
    body: ReadableStream<Uint8Array> | null,
    frameFn: FrameTransform,
    tally: StreamTally,
    /** Called for each chunk of body read, before any of it is parsed. */
    onChunk?: () => void,
): Promise<void> {
    let frame = emptyFrame()
    let data: Uint8Array[] = []
    let dataLen = 0

    const flushFrame = async () => {
        if (dataLen > 0) {
            frame.data = concat(data)
            data = []
            dataLen = 0
        }
        if (isEmptyFrame(frame)) {
            frame = emptyFrame()
            return
        }
        let out: OutFrame
        try {
            out = await frameFn(frame)
        } catch (err) {
            throw new Error(`transform stream chunk: ${errText(err)}`, { cause: err })
        } finally {
            frame = emptyFrame()
        }
        if (isEmptyOut(out)) return
        const n = emit(out)
        // A report rather than a frame (the verified usage) isn't forwarded bytes.
        if (n > 0) tally.record(n)
    }

    const line = async (raw: Uint8Array) => {
        const l = trimLineEnd(raw)
        if (l.length === 0) {
            await flushFrame()
            return
        }
        if (l[0] === 0x3a) {
            // A comment; the frame keeps the last one.
            let c = l.subarray(1)
            if (c.length > 0 && c[0] === 0x20) c = c.subarray(1)
            frame.comment = dec.decode(c)
            return
        }
        const colon = l.indexOf(0x3a)
        const field = dec.decode(colon === -1 ? l : l.subarray(0, colon))
        let value = colon === -1 ? new Uint8Array() : l.subarray(colon + 1)
        if (value.length > 0 && value[0] === 0x20) value = value.subarray(1)
        switch (field) {
            case 'event':
                frame.event = dec.decode(value)
                break
            case 'data':
                // A newline between lines only once something is held, as Go's
                // buffer does: a leading empty data line adds nothing.
                if (dataLen > 0) {
                    data.push(new Uint8Array([0x0a]))
                    dataLen++
                }
                data.push(value.slice())
                dataLen += value.length
                break
            case 'id':
                frame.id = dec.decode(value)
                break
            case 'retry': {
                const n = goAtoi(dec.decode(value))
                if (n !== null) frame.retry = n
                break
            }
        }
    }

    if (body === null) {
        await flushFrame()
        return
    }
    const reader = body.getReader()
    // The bytes of a line not yet ended.
    let held: Uint8Array[] = []
    try {
        for (;;) {
            if (signal.aborted) throw abortError(signal)
            const { done, value } = await reader.read()
            if (done) break
            onChunk?.()
            let start = 0
            for (let nl = value.indexOf(0x0a); nl !== -1; nl = value.indexOf(0x0a, start)) {
                if (signal.aborted) throw abortError(signal)
                held.push(value.subarray(start, nl + 1))
                const whole = held.length === 1 ? held[0]! : concat(held)
                held = []
                await line(whole)
                start = nl + 1
            }
            if (start < value.length) held.push(value.slice(start))
        }
        if (held.length > 0) await line(concat(held))
        await flushFrame()
    } finally {
        reader.releaseLock()
    }
}

/** What forwardStream reads off the Client. */
export type StreamForwardDeps = Pick<SealedDeps, 'fetch' | 'relayReputation' | 'logger'> & {
    clock?: Clock | undefined
    /** Overrides DRAIN_TAIL_TIMEOUT_MS. */
    drainTailTimeoutMs?: number | undefined
}

// withHeader sets name on h, replacing any spelling of it.
function withHeader(h: Record<string, string>, name: string, value: string): Record<string, string> {
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(h)) if (k.toLowerCase() !== name.toLowerCase()) out[k] = v
    out[name] = value
    return out
}

/**
 * forwardStream sends out and pumps the node's SSE answer through the frame
 * hook to em, Go's forwardRawStream. A node that answers with a plain body
 * goes to fallback instead.
 *
 * The node's read is detached from call.signal. A caller who leaves after the
 * generation completed (genComplete) has the receipt tail drained for up to
 * the drain timeout, so the operator is paid for what it delivered and the
 * payer still checks the receipt; one who leaves before cancels the node at
 * once, which settles nothing.
 *
 * idle bounds the silences of the node's body, the drain included: a silence
 * past its budget cancels the node, and the turn ends stream_interrupted with
 * the StreamIdleTimeoutError as its cause.
 */
export async function forwardStream(
    deps: StreamForwardDeps,
    em: Emitter,
    out: Outbound,
    call: Pick<SealedCall, 'endpoint' | 'hop' | 'signal'>,
    factory: FrameTransformFactory,
    fallback: BufferedResponder,
    genComplete: GenComplete,
    idle?: IdleWatchdog,
): Promise<void> {
    const log = deps.logger
    const clock = deps.clock ?? Date.now
    const { endpoint, hop, signal } = call
    const upstream = new AbortController()
    try {
        try {
            new URL(out.url)
        } catch (err) {
            em.fail(newError('build_request', errText(err)))
            return
        }
        let resp: Response
        try {
            resp = await deps.fetch(out.url, {
                method: 'POST',
                headers: withHeader(out.headers, 'Accept', 'text/event-stream'),
                body: out.body,
                signal: upstream.signal,
            })
        } catch (err) {
            // The request rode the detached signal, which a caller leaving
            // can't reach before the response, so this is the hop's failure.
            attributeRelayHop(deps.relayReputation, hop, upstream.signal, TRANSPORT_FAILURE_STATUS, null, null)
            log.error('upstream request failed', { endpoint, ...relayAttrs(hop), err: errText(err) })
            em.fail(newError('upstream_unreachable', errText(err)))
            return
        }

        const ct = resp.headers.get('Content-Type') ?? ''
        if (!ct.startsWith('text/event-stream')) {
            let body: Uint8Array
            try {
                body = new Uint8Array(await resp.arrayBuffer())
            } catch (err) {
                em.fail(newError('read_upstream', errText(err)))
                return
            }
            attributeRelayHop(deps.relayReputation, hop, upstream.signal, resp.status, resp.headers, body)
            try {
                await fallback(em, resp, body)
            } catch (err) {
                log.error('non-stream fallback failed', { endpoint, err: errText(err) })
                em.fail(newError('response_handler', 'upstream response could not be processed'))
            }
            return
        }

        // A forwarded event stream is the relay doing its job. A drop after
        // this point isn't cleanly the relay's, so nothing later charges it.
        if (hop !== null) deps.relayReputation?.recordRelayOutcome(relayRef(hop), true)

        let frameFn: FrameTransform
        try {
            frameFn = await factory(resp)
        } catch (err) {
            log.error('frame transform setup failed', { endpoint, err: errText(err) })
            em.fail(newError('stream_setup', 'stream could not be initialized'))
            return
        }

        if (!em.open(resp.status, resp.headers)) return

        // Read only once the pump has stopped, so it is complete.
        const tally = new StreamTally(clock)
        let abandonedPreGen = false
        const forwardStart = clock()
        let drainTimer: ReturnType<typeof setTimeout> | undefined
        const onLeave = () => {
            if (genComplete.value) {
                // The node has finished: read on to the receipt so it is paid.
                log.debug('client disconnected after generation complete; draining receipt tail', { endpoint, ...relayAttrs(hop) })
                drainTimer = setTimeout(() => {
                    log.warn('receipt tail drain timed out; cancelling upstream', { endpoint, ...relayAttrs(hop) })
                    upstream.abort()
                }, deps.drainTailTimeoutMs ?? DRAIN_TAIL_TIMEOUT_MS)
            } else {
                // Left before the node finished: stop it. Nothing was
                // delivered whole, so a $0 settle is right.
                abandonedPreGen = true
                upstream.abort()
            }
        }
        if (signal?.aborted) onLeave()
        else signal?.addEventListener('abort', onLeave, { once: true })

        let idleErr: StreamIdleTimeoutError | undefined
        idle?.start((err) => {
            idleErr = err
            log.warn('upstream stream idle; cancelling upstream', {
                endpoint,
                ...relayAttrs(hop),
                phase: err.phase,
                timeout_ms: err.timeoutMs,
            })
            upstream.abort(err)
        })
        // The hook settles a receipt inline, reading nothing meanwhile.
        const timedFn: FrameTransform =
            idle === undefined
                ? frameFn
                : async (f) => {
                      idle.pause()
                      try {
                          return await frameFn(f)
                      } finally {
                          idle.resume()
                      }
                  }
        let pumpErr: unknown
        let failed = false
        try {
            await pumpSSE(upstream.signal, (o) => em.frame(o), resp.body, timedFn, tally, idle && (() => idle.chunk()))
        } catch (err) {
            failed = true
            pumpErr = err
        } finally {
            idle?.stop()
            signal?.removeEventListener('abort', onLeave)
            if (drainTimer !== undefined) clearTimeout(drainTimer)
        }
        if (abandonedPreGen) {
            // Info: escrow is open, so the payer committed money to a request
            // that delivered nothing whole.
            log.info('client disconnected before generation complete; upstream cancelled', {
                endpoint,
                ...relayAttrs(hop),
                ...tally.attrs(forwardStart),
            })
        } else if (!failed) {
            log.debug('stream complete', { endpoint, ...relayAttrs(hop), ...tally.attrs(forwardStart) })
        }
        if (failed) {
            log.warn('sse pump ended with error', { endpoint, err: errText(pumpErr) })
            // A drain the caller ended has nobody to tell.
            if (!signal?.aborted) em.interrupt(idleErr)
        }
    } finally {
        upstream.abort()
    }
}

/** What the frame hook reads off the Client. */
export type FrameDeps = ReceiptCheckDeps & Pick<ResponderDeps, 'toolAffinity' | 'responseAffinity' | 'feeRate'>

/** streamApiFor is the event vocabulary an endpoint's frames use, for classifyStreamFrame. */
export function streamApiFor(endpoint: Endpoint): StreamApi {
    return endpoint === '/v1/responses' ? 'responses' : 'chat'
}

/**
 * frameFactory builds the frame hook for call, Go's buildFrameFactory. The
 * hook opens `zs` frames in order and keeps them for the receipt's body hash,
 * opens the settle group without taking an index, and settles on the first
 * receipt that opens and parses, inline, before the usage reaches the caller.
 * A node controls how many receipts it sends; only the first is acted on, so
 * it can't steer the spend guard and the ack down different branches.
 */
export function frameFactory(
    deps: FrameDeps,
    call: SealedCall,
    genComplete: GenComplete,
    slot?: SettleSlot,
    idle?: IdleWatchdog,
): FrameTransformFactory {
    const log = deps.logger
    const { endpoint, model, op, reserved, handle, txId, hop } = call
    const ticket = reserved.ticket
    const ticketId = ticket.ticket_id
    return async (resp) => {
        const wrappedKey = resp.headers.get(RESPONSE_KEY_HEADER) ?? ''
        if (wrappedKey === '') {
            // Plaintext through an admitted ticket: there is no such path.
            log.warn('operator opened SSE stream without sealed key — protocol violation', { ...opAttrs(op), ...relayAttrs(hop) })
            throw new Error('operator did not seal the SSE stream')
        }
        // A key that doesn't match commit_k would open the frames fine: the
        // check is what makes key substitution visible on a stream.
        const responseKey = await openCommittedKey(wrappedKey, reserved)
        // One opener owns the frame counter: openNextFrame advances it,
        // openHeader doesn't, and a failed open doesn't.
        const opener = new ResponseOpener(responseKey, txId, ticketId)
        const meta = { ticket, op, hop, log }
        const api = streamApiFor(endpoint)
        // The node sends its settle group before the receipt.
        let settleGroup: string | null = null
        const contentFrames: Uint8Array[] = []
        const recordResponseId = deps.responseAffinity !== undefined && endpoint === '/v1/responses'
        let recordedResponseId = false
        let receiptSeen = false

        return async (f) => {
            switch (f.event) {
                case STREAM_EVENT_MARKER: {
                    let pt: Uint8Array
                    try {
                        pt = opener.openNextFrame(dec.decode(f.data))
                    } catch (err) {
                        throw new Error(`decrypt sse frame: ${errText(err)}`, { cause: err })
                    }
                    const verdict = classifyStreamFrame(pt, api)
                    if (verdict.error) {
                        log.warn('operator returned stream error', {
                            ...opAttrs(op),
                            ...relayAttrs(hop),
                            ticket_id: ticketId,
                            error: verdict.message,
                        })
                    }
                    // Set before the receipt arrives: a caller who closes on the
                    // last content (or on an error event) must still have the
                    // tail drained. On an error frame that protects the payer,
                    // whose zero-cost receipt and ack come after it.
                    if (verdict.terminal && !genComplete.value) genComplete.value = true
                    // So the next turn of a tool-calling conversation routes back
                    // here, as a buffered reply's tool calls do. Each id rides its
                    // call's first chunk only, so ids are recorded as they arrive.
                    // Decoded as Go reads bytes, each invalid byte its own
                    // U+FFFD, which is how the next turn's ids are read too.
                    let text: string | undefined
                    const textOf = () => (text ??= goDecodeUTF8(pt))
                    // An image tool's round is silent while it runs.
                    idle?.frame(textOf, pt)
                    if (deps.toolAffinity) {
                        const ids = extractStreamToolCallIDs(textOf())
                        if (ids.length > 0) deps.toolAffinity.record(refOf(op), ids)
                    }
                    if (recordResponseId && !recordedResponseId) {
                        const id = extractResponseIDFromFrame(textOf())
                        if (id !== '') {
                            deps.responseAffinity!.record(refOf(op), [id])
                            recordedResponseId = true
                        }
                    }
                    // The hash keeps its own copy of the node's original bytes:
                    // an emitter's reshape of the frame must not reach it.
                    contentFrames.push(pt.slice())
                    return { frame: { ...emptyFrame(), data: pt, sealed: true } }
                }

                case STREAM_EVENT_SETTLE_GROUP: {
                    // Sealed as a header, so it takes no frame index.
                    const sg = openSealedResponseMeta(meta, opener, dec.decode(f.data), SEALED_HEADER_SETTLE_GROUP)
                    settleGroup = settleGroupOf(meta, sg)
                    return {}
                }

                case STREAM_EVENT_RECEIPT: {
                    let pt: Uint8Array
                    try {
                        pt = opener.openNextFrame(dec.decode(f.data))
                    } catch (err) {
                        log.warn('decrypt receipt frame failed', {
                            ...opAttrs(op),
                            ...relayAttrs(hop),
                            ticket_id: ticketId,
                            err: errText(err),
                        })
                        return {}
                    }
                    let receipt
                    try {
                        receipt = parseReceiptJSON(pt)
                    } catch (err) {
                        log.warn('parse receipt frame failed', {
                            ...opAttrs(op),
                            ...relayAttrs(hop),
                            ticket_id: ticketId,
                            err: errText(err),
                        })
                        return {}
                    }
                    if (receiptSeen) {
                        log.warn('operator emitted more than one zs-receipt frame; ignoring the extra', {
                            ...opAttrs(op),
                            ...relayAttrs(hop),
                            ticket_id: ticketId,
                        })
                        return {}
                    }
                    receiptSeen = true
                    const { submit, check } = await checkTurnReceipt(deps, {
                        endpoint,
                        model,
                        ticket,
                        op,
                        handle,
                        receipt,
                        computedHash: bodyHashFromFrames(contentFrames),
                        // The excerpt a protest carries: the frames the hash covers, in order.
                        plaintext: concat(contentFrames),
                        algoUsdPrice: reserved.algoUsdPrice,
                        settleGroup,
                        hop,
                        slot,
                    })
                    // Inline, unlike a buffered reply: the usage that follows
                    // reports the settle, and the stream is still open.
                    // A submit that throws has already told the slot; like Go,
                    // which drops the submit's error, the stream goes on to
                    // report the usage and read the tail.
                    if (submit !== null) {
                        try {
                            await submit()
                        } catch (err) {
                            log.error('escrow settle submit failed', { ticket_id: ticketId, err: errText(err) })
                        }
                    }
                    const feeBps = deps.feeRate()
                    return {
                        usage: {
                            receipt,
                            ticket,
                            op,
                            openFees: handle.openFeesMicroalgos,
                            settleFees: check.settled.feesMicroAlgos,
                            algoUsdPrice: reserved.algoUsdPrice,
                            feeBps: feeBps ?? 0,
                            haveFee: feeBps !== null,
                            check,
                        },
                    }
                }

                default:
                    // Unsealed (the [DONE] sentinel, keepalives): passed through.
                    return { frame: f }
            }
        }
    }
}
