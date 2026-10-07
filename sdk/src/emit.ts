/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Internal: the emitter behind Stream.events, mirroring proto/go/zs
// streamEmitter.

import { markRetryable, newError } from './codes.js'
import type { StreamDecoder } from './decode.js'
import { NodeReply, ZsError } from './errors.js'
import type { Event } from './events.js'
import type { Operator } from './operator.js'
import { refOf } from './operator.js'
import type { Reserved } from './parts.js'
import { type UsageReport, nodeRetryAfter, usageEvents } from './responder.js'
import { nodeHeader } from './sealed.js'
import { type OutFrame, type StreamFrame, frameSSE } from './stream.js'
import type { Emitter } from './turn.js'
import type { Ticket } from './types.js'

const text = new TextDecoder()

/** One thing the emitter hands the caller: an event, or the turn's terminal error. */
export type Delivery = { event: Event } | { error: ZsError }

/**
 * StreamEmitter turns a turn's milestones into events for deliver. A caller
 * who stops reading is one who left: stop cancels the turn, which the
 * forwarder already reads as a disconnect (drain the receipt tail if
 * generation completed, cancel the upstream if not), and from then on events
 * are dropped.
 */
export class StreamEmitter implements Emitter {
    readonly #deliver: (d: Delivery) => void
    readonly #cancel: () => void
    // The caller's own signal: a turn it ended is not one to retry.
    readonly #caller: AbortSignal | undefined
    // Decodes sealed frames into content events; null for framesOnly.
    readonly #dec: StreamDecoder | null

    #stopped = false
    // Set once the turn's one ending, done or an error, is decided; nothing
    // later can change it.
    #ended = false
    #ticket: Ticket | undefined
    #paid = false
    #err: ZsError | undefined

    constructor(deliver: (d: Delivery) => void, cancel: () => void, caller: AbortSignal | undefined, dec: StreamDecoder | null) {
        this.#deliver = deliver
        this.#cancel = cancel
        this.#caller = caller
        this.#dec = dec
    }

    /** Whether the caller left or the turn's error was delivered. */
    get stopped(): boolean {
        return this.#stopped
    }

    /** The turn's terminal error, once decided. */
    get err(): ZsError | undefined {
        return this.#err
    }

    /** The caller stopped reading. */
    stop(): void {
        if (this.#stopped) return
        this.#stopped = true
        this.#cancel()
    }

    #emit(ev: Event): boolean {
        if (this.#stopped) return false
        this.#deliver({ event: ev })
        // As Go's yield answers: false once the caller has left, even on the
        // event that saw it go.
        return !this.#stopped
    }

    #emitAll(evs: Event[]): boolean {
        for (const ev of evs) if (!this.#emit(ev)) return false
        return true
    }

    // end delivers the terminal error, and decides whether it is retryable
    // here, once, for every way a turn can fail. Once the request is paid,
    // the error says so and names the ticket, because nothing is resent after
    // the open.
    #end(err: ZsError): void {
        if (this.#ended) return
        this.#ended = true
        markRetryable(err, this.#caller?.aborted ?? false)
        if (this.#paid) {
            const w = err as { paid: boolean; ticket?: Ticket }
            w.paid = true
            if (w.ticket === undefined && this.#ticket !== undefined) w.ticket = this.#ticket
        }
        this.#err = err
        if (!this.#stopped) {
            this.#stopped = true
            this.#deliver({ error: err })
        }
    }

    note(ev: Event): void {
        this.#emit(ev)
    }

    clamped(ceiling: number): void {
        this.#emit({ type: 'max_output.clamped', ceiling })
    }

    reserved(r: Reserved, op: Operator): void {
        const t = r.ticket
        this.#ticket = { id: t.ticket_id, signed: t, target: refOf(op) }
        this.#emit({
            type: 'reserve.succeeded',
            ticketId: t.ticket_id,
            target: refOf(op),
            maxPrice: t.max_price,
            expiresAt: new Date(t.expires_at * 1000),
        })
    }

    committed(ticketId: string, openTxId: string, feesMicroAlgos: number): void {
        this.#paid = true
        this.#emit({ type: 'payment.committed', ticketId, openTxId, feesMicroAlgos })
    }

    fail(err: ZsError): void {
        this.#end(err)
    }

    reply(status: number, header: Headers, body: Uint8Array, usage: UsageReport | null): void {
        const h = nodeHeader(header)
        if (!this.#emit({ type: 'response.started', status, header: h, streaming: false })) return
        if (!this.#emit({ type: 'frame', event: '', id: '', data: body, comment: '', retry: 0, sealed: true })) return
        const dec = this.#dec
        if (dec !== null && !this.#emitAll(dec.body(text.decode(body)))) return
        if (usage !== null && !this.#emitAll(usageEvents(usage))) return
        if (dec !== null && status >= 400) {
            dec.replyStatus(new NodeReply(status, { header: h, body }), nodeRetryAfter(header))
        }
        this.finish()
    }

    /**
     * finish ends a response that is over: a whole reply, or a stream once
     * the forwarder returns. The receipt has been handled by then, so a failed
     * turn is still settled at what the node charged. The decoder decides
     * between done and an error from the node's sealed frames alone.
     */
    finish(): void {
        if (this.#ended) return
        const dec = this.#dec
        if (dec === null) {
            this.#ended = true
            this.#emit({ type: 'done', finishReason: '', incompleteReason: '', empty: false })
            return
        }
        const out = dec.outcome()
        if (out instanceof ZsError) {
            this.#end(out)
            return
        }
        this.#ended = true
        this.#emit(out)
    }

    open(status: number, header: Headers): boolean {
        this.#emit({ type: 'response.started', status, header: nodeHeader(header), streaming: true })
        return true
    }

    frame(out: OutFrame): number {
        if (out.usage !== undefined) {
            this.#emitAll(usageEvents(out.usage))
            return 0
        }
        const f = out.frame
        if (f === undefined) return 0
        const n = frameSSE(f).length
        if (this.#emit(frameEvent(f)) && f.sealed && this.#dec !== null) this.#emitAll(this.#dec.frame(text.decode(f.data)))
        return n
    }

    /** Ends a stream that broke. A failure the node already reported is the better account of why, so it wins. */
    interrupt(): void {
        const reported = this.#dec?.reportedFailure() ?? null
        this.#end(reported ?? newError('stream_interrupted', 'the stream broke before its end'))
    }
}

function frameEvent(f: StreamFrame): Event {
    return { type: 'frame', event: f.event, id: f.id, data: f.data, comment: f.comment, retry: f.retry, sealed: f.sealed }
}
