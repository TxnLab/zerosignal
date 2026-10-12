/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Reading a node's sealed SSE response: the TypeScript side of Go's
// pumpSSE + buildFrameFactory + forwardRawStream (proto/go/zs/sse.go,
// dispatch.go). What to do with a receipt once it arrives (verify, then
// settle or protest) is the caller's, through onReceipt.

import {
    bodyHashFromFrames,
    classifyStreamFrame,
    ResponseOpener,
    SEALED_HEADER_SETTLE_GROUP,
    STREAM_EVENT_MARKER,
    STREAM_EVENT_RECEIPT,
    STREAM_EVENT_SETTLE_GROUP,
    type StreamApi,
} from '@txnlab/zs-proto/wire'
import { parseReceiptJSON, type UsageReceipt } from '@txnlab/zs-proto/ticket'

import { discardLogger, type Logger } from './ports.js'

/** One server-sent event: its `event:` name, if any, and its joined `data:` lines. */
export interface SseEvent {
    event?: string
    data: string
}

/**
 * The response did not begin like text/event-stream: its first line is
 * neither an SSE field nor a comment. That is an HTML error page or a JSON
 * error body under a streaming content type, caught at the first chunk rather
 * than buffered toward the overflow ceiling.
 */
export class SseNotEventStreamError extends Error {
    constructor(headSample: string) {
        super(`response is not well-framed text/event-stream (body starts with: ${JSON.stringify(headSample)})`)
        this.name = 'SseNotEventStreamError'
    }
}

/**
 * One event grew past the buffer ceiling without ending. Real events can be
 * large (an inline 4K image is ~64 Mi chars of base64), so the ceiling sits at
 * twice that; crossing it means an event that never ends, which in a browser
 * would otherwise exhaust the heap below the JS layer.
 */
export class SseBufferOverflowError extends Error {
    constructor(bufferLength: number, maxChars: number) {
        super(
            `SSE buffer reached ${bufferLength} chars without an event boundary ` +
                `(max ${maxChars}) — response is not well-framed text/event-stream`,
        )
        this.name = 'SseBufferOverflowError'
    }
}

/**
 * A sealed content frame did not open. The counter is shared by every sealed
 * frame, so a dropped, reordered or duplicated frame shows up here on the next
 * one, not necessarily the one tampered with (SPEC § 5.3).
 */
export class FrameOpenError extends Error {
    readonly frameIndex: number
    constructor(message: string, frameIndex: number) {
        super(message)
        this.name = 'FrameOpenError'
        this.frameIndex = frameIndex
    }
}

/** The stream ended without a receipt that opened and parsed, and the caller asked for one. */
export class MissingReceiptError extends Error {
    constructor() {
        super('operator closed the stream without a usable zs-receipt frame — cannot verify the charge')
        this.name = 'MissingReceiptError'
    }
}

/** 128 Mi chars: twice the largest real event (an inline 4K image, ~64 Mi of base64), far under a browser heap. */
export const MAX_SSE_BUFFER_CHARS = 128 * 1024 * 1024

const BOM = String.fromCharCode(0xfeff)

/** How long a consumer keeps reading the settlement tail after its own caller left: Go's drainTailTimeout. */
export const DRAIN_TAIL_TIMEOUT_MS = 10_000

// A well-framed stream begins with a field or a comment, after an optional BOM
// and blank lines.
const SSE_FIELD_PREFIX = /^(?:event|data|id|retry):|^:/

/**
 * sseEvents splits decoded text into events, line by line as Go's pumpSSE
 * does: a line ends at LF with one trailing CR dropped, a blank line ends the
 * event, `:` lines are comments, and one space after a field's colon is
 * dropped. Only `event` and `data` are kept. An event with a name but no data
 * line is kept with empty data, as Go keeps it; one with neither is dropped,
 * and an empty name is no name. A body that is not SSE fails at its first line.
 */
export function sseEvents(maxBufferChars = MAX_SSE_BUFFER_CHARS): TransformStream<string, SseEvent> {
    let partial = ''
    let sniffed = false
    let event: string | undefined
    let data: string[] | null = null
    let held = 0

    const dispatch = (controller: TransformStreamDefaultController<SseEvent>) => {
        if (data !== null || event !== undefined) {
            const joined = data?.join('\n') ?? ''
            controller.enqueue(event === undefined ? { data: joined } : { event, data: joined })
        }
        event = undefined
        data = null
        held = 0
    }

    const line = (raw: string, controller: TransformStreamDefaultController<SseEvent>) => {
        const l = raw.endsWith('\r') ? raw.slice(0, -1) : raw
        if (l === '') {
            dispatch(controller)
            return
        }
        if (l.startsWith(':')) return
        const sep = l.indexOf(':')
        const field = sep === -1 ? l : l.slice(0, sep)
        const value = sep === -1 ? '' : l.slice(sep + 1).replace(/^ /, '')
        if (field === 'event') {
            event = value === '' ? undefined : value
        } else if (field === 'data') {
            ;(data ??= []).push(value)
            // +1 for the newline join adds, so empty data lines count too.
            held += value.length + 1
        }
    }

    const notSse = (controller: TransformStreamDefaultController<SseEvent>) =>
        controller.error(new SseNotEventStreamError(partial.slice(0, 80)))

    return new TransformStream({
        transform(chunk, controller) {
            let scanFrom = partial.length
            partial += chunk
            if (!sniffed) {
                // Leading blank lines and a BOM end no event, so they can go
                // before the check; that also keeps what waits for it short.
                let i = 0
                while (i < partial.length && (partial[i] === '\n' || partial[i] === '\r' || partial[i] === BOM)) i++
                partial = partial.slice(i)
                // Wait until the longest field name (`retry:`) or a whole line is in.
                if (partial.length < 6 && !partial.includes('\n')) return
                sniffed = true
                if (!SSE_FIELD_PREFIX.test(partial)) {
                    notSse(controller)
                    return
                }
                scanFrom = 0
            }
            let start = 0
            for (let nl = partial.indexOf('\n', scanFrom); nl !== -1; nl = partial.indexOf('\n', start)) {
                line(partial.slice(start, nl), controller)
                start = nl + 1
            }
            partial = partial.slice(start)
            if (partial.length + held > maxBufferChars) {
                controller.error(new SseBufferOverflowError(partial.length + held, maxBufferChars))
            }
        },
        flush(controller) {
            // A body too short to have been judged is judged now.
            if (!sniffed && partial !== '' && !SSE_FIELD_PREFIX.test(partial)) {
                notSse(controller)
                return
            }
            // A last event without its blank line still counts, as in Go.
            if (partial !== '') line(partial, controller)
            dispatch(controller)
        },
    })
}

/** The receipt a sealed stream ended with, and what the caller needs to check it. */
export interface StreamReceipt {
    receipt: UsageReceipt
    /** sha256 over the opened content frames in order: what receipt.body_hash must equal. */
    bodyHash: Uint8Array
    /** The opened content frames, for a dispute excerpt. Held in memory only. */
    contentFrames: readonly Uint8Array[]
    /** The opened `zs-settle-group` value, or null when the node sent none or it didn't open. */
    settleGroup: string | null
}

/** What a sealed stream yields to its reader. The settlement tail never reaches it. */
export type ResponseChunk =
    /** An opened `event: zs` frame. */
    | { kind: 'content'; bytes: Uint8Array }
    /** An unsealed, unnamed data line other than `[DONE]`, passed through as sent and not hashed. */
    | { kind: 'plain'; data: string }

export interface SealedStreamOptions {
    /** The response body, after the caller checked commit_k against the key behind opener. */
    source: ReadableStream<Uint8Array>
    opener: ResponseOpener
    /** Which event vocabulary marks the end of generation. */
    api: StreamApi
    /**
     * Called once, with the first receipt that opens and parses. It runs inside
     * the stream, so it also fires during a settlement-tail drain after the
     * reader has gone; that is the point of the drain. It must not throw.
     */
    onReceipt: (r: StreamReceipt) => void
    /** Unsealed named events (anything but `zs`, `zs-receipt`, `zs-settle-group`). Dropped without it. */
    onEvent?: (event: string, data: string) => void
    /** Error the stream if it ends without a receipt. Go tolerates that; the default does too. */
    requireReceipt?: boolean
    /** Milliseconds spent opening each sealed frame. */
    onOpenSample?: (ms: number) => void
    /** Runs once the stream is fully done with the opener, after any drain: where to zero the key. */
    onClosed?: () => void
    drainTimeoutMs?: number
    logger?: Logger
}

/**
 * openSealedStream reads a sealed SSE response (SPEC § 5.3) and yields its
 * opened content. It mirrors Go's frame factory:
 * - `zs` frames open at the next index and are hashed; one that fails to open
 *   errors the stream.
 * - `zs-settle-group` opens as a header, taking no index, and is kept for the
 *   receipt.
 * - `zs-receipt` opens at the next index. One that fails to open or parse is
 *   discarded, and only the first good one reaches onReceipt.
 * - `[DONE]` ends the stream; other events pass through unhashed.
 *
 * Where it differs from Go: `[DONE]` ends the read, where Go reads on to EOF,
 * so a receipt sent after it (out of SPEC order) is not seen. And the settle
 * group arms the drain, which Go arms on a terminal frame only.
 *
 * When the reader cancels after the generation finished (a terminal frame, or
 * the settle group, which a node sends only after the last content frame), the
 * rest of the stream is drained for up to drainTimeoutMs, so the receipt is
 * still verified. Before that, a cancel stops the node promptly. A reader that
 * stops reading without cancelling holds everything back, the receipt
 * included, so a reader that is done must cancel.
 */
export function openSealedStream(opts: SealedStreamOptions): ReadableStream<ResponseChunk> {
    const log = opts.logger ?? discardLogger
    const { opener } = opts
    const frames: Uint8Array[] = []
    let settleGroup: string | null = null
    let receiptSeen = false
    let tailPending = false
    // Set once a settle group or receipt has opened: content after it is
    // outside the receipt's body_hash, so it is dropped (SPEC § 5.3).
    let tailOpened = false

    const open = (data: string): Uint8Array => {
        const t0 = performance.now()
        const pt = opener.openNextFrame(data)
        opts.onOpenSample?.(performance.now() - t0)
        return pt
    }

    const read = new TransformStream<SseEvent, ResponseChunk>({
        transform(ev, controller) {
            switch (ev.event) {
                case STREAM_EVENT_MARKER: {
                    if (tailOpened) {
                        log.debug('frame after the settlement tail dropped', { ticket_id: opener.ticketId })
                        return
                    }
                    const index = opener.frameIndex
                    let pt: Uint8Array
                    try {
                        pt = open(ev.data)
                    } catch (err) {
                        throw new FrameOpenError(
                            `open frame ${index}: ${err instanceof Error ? err.message : String(err)}`,
                            index,
                        )
                    }
                    // The hash keeps its own copy: the reader owns pt and may change or
                    // transfer it before the receipt arrives, and a hash over the
                    // changed bytes would protest an honest node.
                    frames.push(pt.slice())
                    const verdict = classifyStreamFrame(pt, opts.api)
                    if (verdict.error) {
                        log.warn('operator returned stream error', { ticket_id: opener.ticketId, error: verdict.message })
                    }
                    if (verdict.terminal) tailPending = true
                    controller.enqueue({ kind: 'content', bytes: pt })
                    return
                }
                case STREAM_EVENT_SETTLE_GROUP:
                    tailPending = true
                    try {
                        settleGroup = new TextDecoder().decode(opener.openHeader(ev.data, SEALED_HEADER_SETTLE_GROUP))
                        tailOpened = true
                    } catch (err) {
                        log.warn('sealed settle group failed to open', { ticket_id: opener.ticketId, err: String(err) })
                        settleGroup = null
                    }
                    return
                case STREAM_EVENT_RECEIPT: {
                    let receipt: UsageReceipt
                    try {
                        receipt = parseReceiptJSON(open(ev.data))
                    } catch (err) {
                        log.warn('receipt frame discarded', { ticket_id: opener.ticketId, err: String(err) })
                        return
                    }
                    tailOpened = true
                    if (receiptSeen) {
                        // Settlement is irreversible and has run; a second receipt
                        // must not get a second, different verdict.
                        log.warn('operator emitted more than one zs-receipt frame; ignoring the extra', {
                            ticket_id: opener.ticketId,
                        })
                        return
                    }
                    receiptSeen = true
                    try {
                        opts.onReceipt({
                            receipt,
                            bodyHash: bodyHashFromFrames(frames),
                            contentFrames: frames.slice(),
                            settleGroup,
                        })
                    } catch (err) {
                        // The reader's content is already delivered; a failing
                        // handler must not take it down.
                        log.error('onReceipt threw', { ticket_id: opener.ticketId, err: String(err) })
                    }
                    return
                }
                case undefined:
                    if (ev.data === '[DONE]') {
                        // terminate() skips flush, so the receipt check runs here too.
                        if (opts.requireReceipt && !receiptSeen) throw new MissingReceiptError()
                        controller.terminate()
                        return
                    }
                    controller.enqueue({ kind: 'plain', data: ev.data })
                    return
                default:
                    opts.onEvent?.(ev.event, ev.data)
            }
        },
        flush() {
            if (opts.requireReceipt && !receiptSeen) throw new MissingReceiptError()
        },
    })

    const pipeline = opts.source
        // TextDecoderStream's writable is typed BufferSource; a Uint8Array is one.
        .pipeThrough(new TextDecoderStream() as unknown as TransformStream<Uint8Array, string>)
        .pipeThrough(sseEvents())
        .pipeThrough(read)

    const out = new TransformStream<ResponseChunk, ResponseChunk>()
    void (async () => {
        try {
            // preventCancel: whether a reader leaving cancels the node or drains
            // the tail is a settlement decision, made below, not by the reader.
            await pipeline.pipeTo(out.writable, { preventCancel: true })
        } catch (err) {
            try {
                await out.writable.abort(err)
            } catch {
                // already aborted
            }
            if (tailPending) {
                await drainSettlementTail(pipeline, opts.drainTimeoutMs ?? DRAIN_TAIL_TIMEOUT_MS)
            } else {
                try {
                    await pipeline.cancel(err)
                } catch {
                    // already errored or closed
                }
            }
        } finally {
            // After any drain: the tail opens under the same key.
            try {
                opts.onClosed?.()
            } catch (err) {
                log.error('onClosed threw', { ticket_id: opener.ticketId, err: String(err) })
            }
        }
    })()
    return out.readable
}

/**
 * drainSettlementTail reads stream to its end, or for timeoutMs, discarding
 * what comes out. Reading is what moves the transforms upstream along, so the
 * receipt frame still reaches its handler after the reader has gone. It never
 * throws: a node that fails mid-tail leaves nothing to settle from.
 */
export async function drainSettlementTail(stream: ReadableStream<unknown>, timeoutMs = DRAIN_TAIL_TIMEOUT_MS): Promise<void> {
    const reader = stream.getReader()
    let timer: ReturnType<typeof setTimeout> | undefined
    const deadline = new Promise<void>((resolve) => {
        timer = setTimeout(resolve, timeoutMs)
    })
    const pump = (async () => {
        for (;;) {
            const { done } = await reader.read()
            if (done) return
        }
    })()
    // Attached before the race, so a rejection after the deadline isn't unhandled.
    pump.catch(() => {})
    try {
        await Promise.race([pump, deadline])
    } catch {
        // the source errored mid-tail
    } finally {
        if (timer !== undefined) clearTimeout(timer)
        try {
            await reader.cancel()
        } catch {
            // already closed or errored
        }
    }
}
