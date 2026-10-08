/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// One turn as the caller asks for it and as dispatch sees it, and the emitter
// dispatch reports through, mirroring proto/go/zs Request, turn and emitter.

import { normalizeRelay } from '@txnlab/zs-proto/selection'

import { StreamDecoder } from './decode.js'
import { type Delivery, StreamEmitter } from './emit.js'
import type { ZsError } from './errors.js'
import type { Event } from './events.js'
import type { Operator } from './operator.js'
import type { Logger } from './ports.js'
import type { Reserved } from './parts.js'
import { type SettleResult, SettleSlot } from './receipt-check.js'
import type { UsageReport } from './responder.js'
import type { OutFrame } from './stream.js'
import type { Endpoint } from './types.js'

/**
 * Request is one turn: an OpenAI-shaped body for one endpoint, plus the
 * routing preferences that don't travel in it. Those that do (the body's
 * `provider` object) are read from body and stripped before it is sealed.
 */
export interface Request {
    endpoint: Endpoint
    body: Uint8Array | string
    /** body's media type. Only an image edit, which is multipart, needs it. */
    contentType?: string
    /** Routes only to attested nodes, on top of Config.requireTeeModels. */
    requireTee?: boolean
    /**
     * Refuses a node before anything is sealed to it, for content that needs
     * more of a node than requireTee checks. It is asked about each candidate
     * before its reserve, again on each re-sweep, and about a node the
     * ephemeral self-heal refreshed, since the new key is what the request
     * would then be sealed to. op is a frozen copy, and the reserve seals to
     * the key it shows. A refused node is skipped, as is one whose check
     * throws, like a node pick filtered out; the turn fails no_tee_capacity
     * only when it refused every candidate. Go has no counterpart.
     */
    admitNode?: (op: Readonly<Operator>, signal?: AbortSignal) => boolean | Promise<boolean>
    /**
     * "auto", "off" or "required"; absent or anything else defers to
     * Config.privacy. A `provider.relay` in body outranks it. "off" takes
     * effect only with Config.allowPrivacyOverride.
     */
    relay?: string
    /**
     * Skips decoding, for a caller that re-emits the node's bytes: the turn
     * yields each frame but no content events, an error the node reports
     * inside its response passes as a frame, and done's fields are zero.
     */
    framesOnly?: boolean
}

/** Turn is one request as dispatch sees it. */
export interface Turn {
    endpoint: Endpoint
    body: Uint8Array | string
    contentType: string
    requireTee: boolean
    admitNode: Request['admitNode']
    /** The caller's normalized relay preference; the body's outranks it. */
    relay: string
}

export function turnOf(r: Request): Turn {
    return {
        endpoint: r.endpoint,
        body: r.body,
        contentType: r.contentType ?? '',
        requireTee: r.requireTee ?? false,
        admitNode: r.admitNode,
        relay: normalizeRelay(r.relay),
    }
}

/**
 * Stream is one turn. It runs when events is first read, so building one
 * costs nothing and sends nothing.
 */
export interface Stream {
    /**
     * Runs the turn and yields its events in order, then throws the turn's
     * error, if any; err reports it too. A loop that stops reading early is
     * treated as a caller who left: before generation completes the node is
     * told to stop; after it the receipt is still collected and the ticket
     * settled, and the loop's exit waits for that. Readable once.
     */
    events(): AsyncIterable<Event>
    /** The terminal error of a turn whose events loop has finished, or undefined. */
    readonly err: ZsError | undefined
    /**
     * Runs the turn and returns its answer text, ignoring every other event,
     * or throws the turn's error. With framesOnly there is no decoded text,
     * so it returns ''.
     */
    text(): Promise<string>
    /**
     * Resolves once this turn's escrow submit has returned, with what it did,
     * or rejects with signal's reason if that comes first. With an err, the
     * settlement is the submit that was attempted, not one that took effect.
     * It does not wait for confirmation: a submitted transaction can still
     * fail to land, which the refund watchdog and the journal cover. Call it
     * once the events loop has started; a turn with no submit resolves with
     * kind '' once its run returns.
     */
    wait(signal?: AbortSignal): Promise<SettleResult>
}

/** Runs a turn through em with slot for its submit, as Client.stream binds it. */
export type TurnRunner = (em: Emitter, slot: SettleSlot, signal: AbortSignal) => Promise<void>

// A fresh one per turn: the caller owns what wait returns.
const noSettlement = (): SettleResult => ({ settlement: { ticketId: '', kind: '', txId: '', feesMicroAlgos: 0 } })

/** TurnStream is the Stream Client.stream returns. */
export class TurnStream implements Stream {
    readonly #run: TurnRunner
    readonly #endpoint: Endpoint
    readonly #framesOnly: boolean
    readonly #signal: AbortSignal | undefined
    readonly #logger: Logger | undefined
    readonly #slot = new SettleSlot()
    #started = false
    #err: ZsError | undefined

    constructor(run: TurnRunner, req: Request, signal?: AbortSignal, logger?: Logger) {
        this.#run = run
        this.#endpoint = req.endpoint
        this.#framesOnly = req.framesOnly ?? false
        this.#signal = signal
        this.#logger = logger
    }

    get err(): ZsError | undefined {
        return this.#err
    }

    async *events(): AsyncGenerator<Event, void, undefined> {
        if (this.#started) throw new Error("zs: a Stream's events can be read only once")
        this.#started = true
        const leave = new AbortController()
        const signal = this.#signal ? AbortSignal.any([this.#signal, leave.signal]) : leave.signal
        const queue = new DeliveryQueue()
        const em = new StreamEmitter(
            (d) => queue.push(d),
            () => leave.abort(),
            this.#signal,
            this.#framesOnly ? null : new StreamDecoder(this.#endpoint),
        )
        const slot = this.#slot
        const done = (async () => {
            try {
                await this.#run(em, slot, signal)
                // A stream ends here, once the forwarder has read it all: only
                // then is there no sealed frame left to change the outcome.
                if (!em.stopped) em.finish()
            } finally {
                // Every submit is built before the run returns, so a turn
                // without one has nothing for wait to wait on.
                if (!slot.expected) slot.finish(noSettlement())
                queue.close()
            }
        })()
        // Awaited in the finally below; a rejection while the reader sits in
        // its loop body would otherwise be unhandled until then.
        done.catch(() => {})
        try {
            for (;;) {
                const d = await queue.next()
                if (d === null) break
                if ('error' in d) throw d.error
                yield d.event
            }
        } finally {
            // Ends the turn's signal, as Go's deferred cancel does: the caller
            // left, or the turn is over.
            if (!em.stopped) em.stop()
            try {
                await done
            } catch (err) {
                // A run that throws after the turn's ending was decided can't
                // change it: the reader holds that error, and err reports it.
                if (em.err === undefined) throw err
                this.#logger?.error('turn run failed after its ending', { err: err instanceof Error ? err.message : String(err) })
            } finally {
                this.#err = em.err
            }
        }
    }

    async text(): Promise<string> {
        let s = ''
        for await (const ev of this.events()) if (ev.type === 'delta.text') s += ev.delta
        return s
    }

    async wait(signal?: AbortSignal): Promise<SettleResult> {
        if (!this.#started) throw new Error("zs: wait called before the Stream's events were read")
        // A submit that already returned wins over a signal already aborted.
        const ready = this.#slot.result
        if (ready !== undefined) return ready
        if (!signal) return this.#slot.done
        signal.throwIfAborted()
        return new Promise<SettleResult>((resolve, reject) => {
            const onAbort = () => reject(signal.reason)
            signal.addEventListener('abort', onAbort, { once: true })
            void this.#slot.done.then((r) => {
                signal.removeEventListener('abort', onAbort)
                resolve(r)
            })
        })
    }
}

// DeliveryQueue hands the emitter's deliveries to the events loop in order.
// The emitter can't wait on the loop, so a slow reader buffers.
class DeliveryQueue {
    readonly #items: Delivery[] = []
    #closed = false
    #wake: (() => void) | undefined

    push(d: Delivery): void {
        this.#items.push(d)
        this.#wake?.()
    }

    close(): void {
        this.#closed = true
        this.#wake?.()
    }

    async next(): Promise<Delivery | null> {
        for (;;) {
            const d = this.#items.shift()
            if (d !== undefined) return d
            if (this.#closed) return null
            await new Promise<void>((resolve) => {
                this.#wake = resolve
            })
            this.#wake = undefined
        }
    }
}

/**
 * Emitter receives what a turn produces: dispatch and the sealed run decide
 * what happened, and the emitter turns it into the caller's view. A request
 * ends in fail or reply (or, streamed, the calls the streamed run adds); note,
 * clamped, reserved and committed may precede either.
 */
export interface Emitter {
    /** A routing milestone. It never ends the request. */
    note(ev: Event): void
    /** The request's max_output was lowered to ceiling. */
    clamped(ceiling: number): void
    /** The ticket a node signed. */
    reserved(r: Reserved, op: Operator): void
    /** The escrow open; nothing is resent after it. */
    committed(ticketId: string, openTxId: string, feesMicroAlgos: number): void
    /** Ends the request with err before any response has started. */
    fail(err: ZsError): void
    /**
     * Delivers a whole response: header is the node's own, X-Zs-* fields
     * included, for the emitter to strip; body is opened; usage is null when
     * the node sent no readable receipt. It must not throw: the forwarder
     * reads a throw as the response failing and would end the turn twice.
     */
    reply(status: number, header: Headers, body: Uint8Array, usage: UsageReport | null): void
    /**
     * Starts a stream; header is the node's own, as for reply. False means it
     * could not start and the caller has already been told.
     */
    open(status: number, header: Headers): boolean
    /**
     * Delivers one stream frame, or the usage its receipt carried, and returns
     * the frame's size on the wire for the stream tally; a usage report counts
     * 0. Frames that arrive after the caller left are dropped, not refused, so
     * a tail drain still reaches the receipt.
     */
    frame(out: OutFrame): number
    /** Ends an open stream that broke before its end, for cause when the SDK knows why. */
    interrupt(cause?: unknown): void
}
