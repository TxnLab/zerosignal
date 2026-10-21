/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The confirmation watch: signatureSubscribe over one WebSocket, the twin of
// go/solana/rpc pubsub.go. A push, not a getSignatureStatuses poll, because
// the public endpoints answer a poll with 429 after about ten calls while a
// subscription stays within their limits. A dropped socket ends every watch on
// it with PubSubClosedError, and the caller polls from there. Nothing here
// notices an upstream that keeps the socket open and stops sending, so a watch
// can stay pending: the caller bounds it, by the blockhash's
// lastValidBlockHeight or a timer, and polls once that passes.
//
// Differences from Go:
//   - The socket is the platform's WebSocket (browsers, Node 22), or the one
//     the host passes. A browser's sets no headers, so a provider's API key
//     rides in the URL; Go takes a header, TLS config and dialer.
//   - Neither side pings; a browser can't. The socket is the caller's to
//     redial after an idle proxy drops it.
//   - Frames are not size-capped, and a fragmented message is reassembled:
//     the platform's WebSocket reads each message whole.
//   - A subscription id or slot past 2^53 is refused, where Go reads any u64.

import { type Commitment, SolanaRpcError } from './rpc.js'

/** The part of the WHATWG WebSocket this client uses. */
export interface WebSocketLike {
    send(data: string): void
    close(): void
    addEventListener(type: 'open' | 'close' | 'error', listener: () => void): void
    addEventListener(type: 'message', listener: (ev: { data: unknown }) => void): void
}

export type WebSocketConstructor = new (url: string) => WebSocketLike

/** Ends every subscription on a socket that closed, and every later subscribe on it. */
export class PubSubClosedError extends Error {
    constructor(detail: string) {
        super(`solana rpc: pubsub socket closed: ${detail}`)
        this.name = 'PubSubClosedError'
    }
}

/** Ends a subscription its caller cancelled. */
export class UnsubscribedError extends Error {
    constructor() {
        super('solana rpc: unsubscribed')
        this.name = 'UnsubscribedError'
    }
}

/** A watched transaction's outcome at the commitment watched for. */
export interface SignatureResult {
    slot: bigint
    /** The TransactionError it landed with, null for a success (see txErrorName). */
    err: unknown
}

interface Pending {
    sub: SignatureSubscription
    armed: (err: Error | undefined) => void
    abandoned: boolean
}

/** One signatureSubscribe. The RPC sends one notification and drops the subscription itself. */
export class SignatureSubscription {
    /** The notification, or the error that ended the subscription without one. */
    readonly result: Promise<SignatureResult>
    #settle!: (r: SignatureResult | Error) => void
    #settled = false
    /** Set once the RPC arms it. */
    id = -1

    constructor(private readonly pubsub: SolanaPubSub) {
        this.result = new Promise<SignatureResult>((resolve, reject) => {
            this.#settle = (r) => (r instanceof Error ? reject(r) : resolve(r))
        })
        // A caller that never reads the result must not see an unhandled rejection.
        this.result.catch(() => {})
    }

    /** Ends the subscription with UnsubscribedError, unless it has already ended. */
    unsubscribe(): void {
        this.pubsub.drop(this)
    }

    /** @internal */
    finish(r: SignatureResult | Error): void {
        if (this.#settled) return
        this.#settled = true
        this.#settle(r)
    }
}

/** One WebSocket to an RPC's pubsub endpoint, carrying any number of subscriptions. */
export class SolanaPubSub {
    readonly #ws: WebSocketLike
    #nextId = 0
    readonly #pending = new Map<number, Pending>()
    readonly #subs = new Map<number, SignatureSubscription>()
    #err: PubSubClosedError | undefined
    readonly #closed: Promise<PubSubClosedError>
    #onClosed!: (e: PubSubClosedError) => void

    private constructor(ws: WebSocketLike) {
        this.#ws = ws
        this.#closed = new Promise((resolve) => (this.#onClosed = resolve))
        ws.addEventListener('message', (ev) => {
            if (typeof ev.data === 'string') this.#read(ev.data)
        })
        ws.addEventListener('close', () => this.#fail('the RPC closed it'))
        ws.addEventListener('error', () => this.#fail('socket error'))
    }

    /**
     * connect opens a socket to endpoint, a ws or wss URL. signal bounds the
     * opening only.
     */
    static connect(endpoint: string, o: { webSocket?: WebSocketConstructor | undefined; signal?: AbortSignal | undefined } = {}): Promise<SolanaPubSub> {
        // No error spells the endpoint: a provider's API key often rides in its query.
        let u: URL
        try {
            u = new URL(endpoint)
        } catch {
            return Promise.reject(new Error('solana rpc: pubsub endpoint is not a URL'))
        }
        if (u.protocol !== 'ws:' && u.protocol !== 'wss:') return Promise.reject(new Error('solana rpc: pubsub endpoint is not ws or wss'))
        if (u.username !== '' || u.password !== '') return Promise.reject(new Error('solana rpc: pubsub endpoint carries credentials'))
        const WS = o.webSocket ?? (globalThis as { WebSocket?: WebSocketConstructor }).WebSocket
        if (WS === undefined) return Promise.reject(new Error('solana rpc: no WebSocket in this runtime; pass one'))
        const signal = o.signal
        if (signal?.aborted) return Promise.reject(signal.reason)
        let ws: WebSocketLike
        try {
            ws = new WS(endpoint)
        } catch {
            // A browser's SyntaxError or SecurityError quotes the URL.
            return Promise.reject(new Error('solana rpc: pubsub dial failed'))
        }
        return new Promise((resolve, reject) => {
            let done = false
            const onAbort = () => {
                if (done) return
                done = true
                ws.close()
                reject(signal!.reason)
            }
            signal?.addEventListener('abort', onAbort, { once: true })
            ws.addEventListener('open', () => {
                if (done) return
                done = true
                signal?.removeEventListener('abort', onAbort)
                resolve(new SolanaPubSub(ws))
            })
            const failed = () => {
                if (done) return
                done = true
                signal?.removeEventListener('abort', onAbort)
                // The event says nothing of the endpoint, which may hold an API key.
                reject(new Error('solana rpc: pubsub dial failed'))
            }
            ws.addEventListener('error', failed)
            ws.addEventListener('close', failed)
        })
    }

    /** Resolves once the socket has ended, with why. */
    get closed(): Promise<PubSubClosedError> {
        return this.#closed
    }

    /** Why the socket ended, or undefined while it is open. */
    get error(): PubSubClosedError | undefined {
        return this.#err
    }

    /** Closes the socket, ending every subscription on it. */
    close(): void {
        this.#fail('closed')
        this.#ws.close()
    }

    /**
     * signatureSubscribe watches signature until it reaches commitment,
     * resolving once the RPC has armed the watch. signal bounds that wait only;
     * the watch then lasts until it notifies, unsubscribe, or the socket ends.
     */
    signatureSubscribe(
        signature: string,
        o: { commitment?: Commitment | undefined; signal?: AbortSignal | undefined } = {},
    ): Promise<SignatureSubscription> {
        if (this.#err !== undefined) return Promise.reject(this.#err)
        const signal = o.signal
        if (signal?.aborted) return Promise.reject(signal.reason)
        const sub = new SignatureSubscription(this)
        const reqId = ++this.#nextId
        return new Promise<SignatureSubscription>((resolve, reject) => {
            // Fires only while the subscribe waits: arming removes it. The
            // answer may still come; #answer then drops what it arms.
            const onAbort = () => {
                const p = this.#pending.get(reqId)
                if (p !== undefined) p.abandoned = true
                reject(signal!.reason)
            }
            const pending: Pending = {
                sub,
                abandoned: false,
                armed: (err) => {
                    signal?.removeEventListener('abort', onAbort)
                    if (err !== undefined) reject(err)
                    else resolve(sub)
                },
            }
            this.#pending.set(reqId, pending)
            signal?.addEventListener('abort', onAbort, { once: true })
            try {
                this.#send(reqId, 'signatureSubscribe', [signature, o.commitment === undefined ? {} : { commitment: o.commitment }])
            } catch (e) {
                this.#pending.delete(reqId)
                pending.armed(e instanceof Error ? e : new Error(String(e)))
            }
        })
    }

    /** @internal */
    drop(sub: SignatureSubscription): void {
        if (this.#subs.get(sub.id) !== sub) return
        this.#subs.delete(sub.id)
        this.#unsubscribe(sub.id)
        sub.finish(new UnsubscribedError())
    }

    #send(id: number, method: string, params: unknown[]): void {
        this.#ws.send(JSON.stringify({ jsonrpc: '2.0', id, method, params }))
    }

    #unsubscribe(subId: number): void {
        if (this.#err !== undefined) return
        try {
            this.#send(++this.#nextId, 'signatureUnsubscribe', [subId])
        } catch {}
    }

    #read(frame: string): void {
        let m: unknown
        try {
            m = JSON.parse(frame)
        } catch {
            return
        }
        if (typeof m !== 'object' || m === null) return
        const msg = m as Record<string, unknown>
        if (typeof msg.id === 'number') this.#answer(msg.id, msg)
        else if (msg.method === 'signatureNotification') this.#notify(msg.params)
    }

    #answer(reqId: number, m: Record<string, unknown>): void {
        const p = this.#pending.get(reqId)
        // An unsubscribe's answer.
        if (p === undefined) return
        this.#pending.delete(reqId)
        const e = m.error
        if (e !== undefined && e !== null) {
            const err = typeof e === 'object' && !Array.isArray(e) ? (e as Record<string, unknown>) : undefined
            if (
                err === undefined ||
                typeof err.code !== 'number' ||
                !Number.isInteger(err.code) ||
                (err.message !== undefined && typeof err.message !== 'string')
            ) {
                p.armed(new Error('solana rpc signatureSubscribe: malformed error'))
                return
            }
            p.armed(new SolanaRpcError('signatureSubscribe', err.code, (err.message as string | undefined) ?? '', err.data))
            return
        }
        const subId = m.result
        if (typeof subId !== 'number' || !Number.isSafeInteger(subId) || subId < 0) {
            p.armed(new Error('solana rpc signatureSubscribe: subscription id is not a u64 below 2^53'))
            return
        }
        if (p.abandoned) {
            this.#unsubscribe(subId)
            return
        }
        // A repeated id would overwrite the first watch, which then outlives
        // even the socket. Not unsubscribed, since the first watch holds it.
        if (this.#subs.has(subId)) {
            p.armed(new Error(`solana rpc signatureSubscribe: subscription id ${subId} is already in use`))
            return
        }
        p.sub.id = subId
        this.#subs.set(subId, p.sub)
        p.armed(undefined)
    }

    #notify(params: unknown): void {
        if (typeof params !== 'object' || params === null) return
        const { result, subscription } = params as Record<string, unknown>
        if (typeof subscription !== 'number' || typeof result !== 'object' || result === null) return
        const { context, value } = result as Record<string, unknown>
        // A value that is not an object is the "receivedSignature" notice, sent
        // only to a subscription that asked for it; this one never does.
        if (typeof value !== 'object' || value === null) return
        const slot = (typeof context === 'object' && context !== null ? (context as Record<string, unknown>).slot : undefined) ?? 0
        if (typeof slot !== 'number' || !Number.isSafeInteger(slot) || slot < 0) return
        const sub = this.#subs.get(subscription)
        if (sub === undefined) return
        this.#subs.delete(subscription)
        sub.finish({ slot: BigInt(slot), err: (value as Record<string, unknown>).err ?? null })
    }

    #fail(detail: string): void {
        if (this.#err !== undefined) return
        const err = new PubSubClosedError(detail)
        this.#err = err
        for (const p of this.#pending.values()) p.armed(err)
        this.#pending.clear()
        for (const s of this.#subs.values()) s.finish(err)
        this.#subs.clear()
        this.#onClosed(err)
    }
}
