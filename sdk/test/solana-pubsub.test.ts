/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The signatureSubscribe watch against an injected WebSocket, ported from
// go/solana/rpc pubsub_test.go.

import { encodeBase58 } from '@txnlab/zs-proto/solana'
import { describe, expect, it } from 'vitest'

import { PubSubClosedError, SolanaPubSub, UnsubscribedError, type WebSocketLike } from '../src/solana/pubsub.js'
import { SolanaRpcError, txErrorName } from '../src/solana/rpc.js'

const SIG = encodeBase58(new Uint8Array(64).fill(0x11))

type Listener = (ev: { data: unknown }) => void

/** A WebSocket the test drives: it records what the client sends and delivers what the test pushes. */
class FakeSocket implements WebSocketLike {
    static last: FakeSocket | undefined
    readonly sent: { id: number; method: string; params: unknown }[] = []
    readonly #listeners = new Map<string, Listener[]>()
    closedByClient = false
    /** Set, send throws as a socket that cannot take the frame. */
    refuseSends = false

    constructor(readonly url: string) {
        FakeSocket.last = this
    }

    addEventListener(type: string, listener: Listener): void {
        this.#listeners.set(type, [...(this.#listeners.get(type) ?? []), listener])
    }

    send(data: string): void {
        if (this.refuseSends) throw new DOMException('Still in CONNECTING state.', 'InvalidStateError')
        this.sent.push(JSON.parse(data) as { id: number; method: string; params: unknown })
    }

    close(): void {
        this.closedByClient = true
        this.emit('close')
    }

    emit(type: string, data?: unknown): void {
        for (const l of this.#listeners.get(type) ?? []) l({ data })
    }

    push(msg: unknown): void {
        this.emit('message', JSON.stringify(msg))
    }
}

async function connect(): Promise<{ p: SolanaPubSub; ws: FakeSocket }> {
    const pending = SolanaPubSub.connect('wss://rpc.example/ws?api-key=secret', { webSocket: FakeSocket })
    const ws = FakeSocket.last!
    ws.emit('open')
    return { p: await pending, ws }
}

/** Arms a watch, answering the subscribe with subId. */
async function subscribe(p: SolanaPubSub, ws: FakeSocket, subId: number, commitment?: 'finalized') {
    const pending = p.signatureSubscribe(SIG, { commitment })
    const call = ws.sent.at(-1)!
    ws.push({ jsonrpc: '2.0', result: subId, id: call.id })
    return { sub: await pending, call }
}

const notification = (subscription: number, slot: number, value: unknown) => ({
    jsonrpc: '2.0',
    method: 'signatureNotification',
    params: { result: { context: { slot }, value }, subscription },
})

describe('SolanaPubSub', () => {
    it('notifies each watch with its outcome', async () => {
        const { p, ws } = await connect()
        expect(ws.url).toBe('wss://rpc.example/ws?api-key=secret')
        const ok = await subscribe(p, ws, 7, 'finalized')
        expect(ok.call).toMatchObject({ method: 'signatureSubscribe', params: [SIG, { commitment: 'finalized' }] })
        const failed = await subscribe(p, ws, 8)
        expect(failed.call.params).toEqual([SIG, {}])

        // The received notice is for a subscription that asked for it; this
        // one is still waiting after it.
        ws.push(notification(8, 5, 'receivedSignature'))
        ws.push(notification(8, 9, { err: { InstructionError: [1, { Custom: 6001 }] } }))
        ws.push(notification(7, 11, { err: null }))

        expect(await ok.sub.result).toEqual({ slot: 11n, err: null })
        const r = await failed.sub.result
        expect(r.slot).toBe(9n)
        expect(txErrorName(r.err)).toBe('InstructionError')
    })

    it('rejects a subscribe the RPC refuses', async () => {
        const { p, ws } = await connect()
        const pending = p.signatureSubscribe(SIG, { commitment: 'finalized' })
        ws.push({ jsonrpc: '2.0', error: { code: -32602, message: 'Invalid params' }, id: ws.sent.at(-1)!.id })
        const err = await pending.catch((e: unknown) => e)
        expect(err).toBeInstanceOf(SolanaRpcError)
        expect((err as SolanaRpcError).code).toBe(-32602)
    })

    it('ends every watch when the socket drops, and refuses later subscribes', async () => {
        const { p, ws } = await connect()
        const { sub } = await subscribe(p, ws, 3, 'finalized')
        ws.emit('close')
        await expect(sub.result).rejects.toBeInstanceOf(PubSubClosedError)
        expect(await p.closed).toBeInstanceOf(PubSubClosedError)
        expect(p.error).toBeInstanceOf(PubSubClosedError)
        await expect(p.signatureSubscribe(SIG)).rejects.toBeInstanceOf(PubSubClosedError)
    })

    it('ends a subscribe still waiting when the socket drops', async () => {
        const { p, ws } = await connect()
        const pending = p.signatureSubscribe(SIG)
        ws.emit('error')
        await expect(pending).rejects.toBeInstanceOf(PubSubClosedError)
    })

    // A socket that cannot take a frame ends as a drop does, so the caller
    // redials rather than each later subscribe failing alone.
    it('ends every watch when a subscribe cannot be sent, and refuses later subscribes', async () => {
        const { p, ws } = await connect()
        const { sub } = await subscribe(p, ws, 3)
        ws.refuseSends = true
        const err = await p.signatureSubscribe(SIG).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(PubSubClosedError)
        expect((err as Error).message).toContain('send failed')
        await expect(sub.result).rejects.toBeInstanceOf(PubSubClosedError)
        expect(await p.closed).toBe(err)
        expect(p.error).toBe(err)
        expect(ws.closedByClient).toBe(true)
        ws.refuseSends = false
        await expect(p.signatureSubscribe(SIG)).rejects.toBe(err)
        expect(ws.sent.filter((s) => s.method === 'signatureSubscribe')).toHaveLength(1)
    })

    it('ends every watch when an unsubscribe cannot be sent', async () => {
        const { p, ws } = await connect()
        const gone = await subscribe(p, ws, 3)
        const other = await subscribe(p, ws, 4)
        ws.refuseSends = true
        gone.sub.unsubscribe()
        await expect(gone.sub.result).rejects.toBeInstanceOf(UnsubscribedError)
        await expect(other.sub.result).rejects.toBeInstanceOf(PubSubClosedError)
        expect(p.error).toBeInstanceOf(PubSubClosedError)
    })

    it('ends every watch on close', async () => {
        const { p, ws } = await connect()
        const { sub } = await subscribe(p, ws, 3)
        p.close()
        expect(ws.closedByClient).toBe(true)
        await expect(sub.result).rejects.toBeInstanceOf(PubSubClosedError)
    })

    it('unsubscribes', async () => {
        const { p, ws } = await connect()
        const { sub } = await subscribe(p, ws, 41)
        sub.unsubscribe()
        await expect(sub.result).rejects.toBeInstanceOf(UnsubscribedError)
        expect(ws.sent.at(-1)).toMatchObject({ method: 'signatureUnsubscribe', params: [41] })
        // A second unsubscribe sends nothing.
        sub.unsubscribe()
        expect(ws.sent.filter((s) => s.method === 'signatureUnsubscribe')).toHaveLength(1)
    })

    // The RPC reuses an id once its watch has notified. A handle to the watch
    // that ended must not end the one that now holds the id.
    it('leaves a reused id to its new watch when a stale handle unsubscribes', async () => {
        const { p, ws } = await connect()
        const first = await subscribe(p, ws, 7)
        ws.push(notification(7, 3, { err: null }))
        expect(await first.sub.result).toEqual({ slot: 3n, err: null })
        const second = await subscribe(p, ws, 7)

        first.sub.unsubscribe()
        expect(ws.sent.filter((s) => s.method === 'signatureUnsubscribe')).toEqual([])
        ws.push(notification(7, 4, { err: null }))
        expect(await second.sub.result).toEqual({ slot: 4n, err: null })
        expect(await first.sub.result).toEqual({ slot: 3n, err: null })
    })

    // The RPC answering two subscribes with one id would strand the first
    // watch past the socket's end; the second is refused instead.
    it('refuses a repeated subscription id', async () => {
        const { p, ws } = await connect()
        const first = await subscribe(p, ws, 5)
        const pending = p.signatureSubscribe(SIG)
        ws.push({ jsonrpc: '2.0', result: 5, id: ws.sent.at(-1)!.id })
        await expect(pending).rejects.toThrow('already in use')
        ws.emit('close')
        await expect(first.sub.result).rejects.toBeInstanceOf(PubSubClosedError)
    })

    it('answers a subscribe whose error is malformed', async () => {
        const { p, ws } = await connect()
        const pending = p.signatureSubscribe(SIG)
        ws.push({ jsonrpc: '2.0', error: { code: 'x', message: 'bad' }, id: ws.sent.at(-1)!.id })
        await expect(pending).rejects.toThrow('malformed error')
    })

    // A subscribe its caller gave up on before the RPC armed it would otherwise
    // hold a server-side subscription for the socket's life.
    it('drops a subscribe abandoned before the RPC armed it', async () => {
        const { p, ws } = await connect()
        const ac = new AbortController()
        const pending = p.signatureSubscribe(SIG, { signal: ac.signal })
        const call = ws.sent.at(-1)!
        ac.abort(new Error('caller left'))
        await expect(pending).rejects.toThrow('caller left')
        ws.push({ jsonrpc: '2.0', result: 99, id: call.id })
        expect(ws.sent.at(-1)).toMatchObject({ method: 'signatureUnsubscribe', params: [99] })
    })

    it('fails a dial the socket refuses', async () => {
        const pending = SolanaPubSub.connect('wss://rpc.example/ws?api-key=secret', { webSocket: FakeSocket })
        FakeSocket.last!.emit('error')
        await expect(pending).rejects.toThrow('pubsub dial failed')
    })

    // A browser's constructor error quotes the URL, API key and all.
    it('keeps the endpoint out of a constructor error', async () => {
        class Refusing extends FakeSocket {
            constructor(url: string) {
                super(url)
                throw new DOMException(`The URL '${url}' is invalid.`, 'SyntaxError')
            }
        }
        const err = await SolanaPubSub.connect('wss://rpc.example/ws?api-key=secret', { webSocket: Refusing }).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect((err as Error).message).not.toContain('secret')
    })

    it.each(['https://rpc.example/?api-key=secret', 'rpc.example/?api-key=secret', 'wss://user:secret@rpc.example/'])(
        'refuses the endpoint %s without spelling it',
        async (endpoint) => {
            const err = await SolanaPubSub.connect(endpoint, { webSocket: FakeSocket }).catch((e: unknown) => e)
            expect(err).toBeInstanceOf(Error)
            expect((err as Error).message).not.toContain('secret')
        },
    )

    // Each half of the userinfo is refused on its own, before any socket: a
    // dial would fail with another message.
    it.each(['wss://:secret@rpc.example/', 'wss://secret@rpc.example/'])('refuses the credentials in %s without spelling them', async (endpoint) => {
        class Unreachable extends FakeSocket {
            constructor(url: string) {
                super(url)
                throw new Error('dialed')
            }
        }
        const err = await SolanaPubSub.connect(endpoint, { webSocket: Unreachable }).catch((e: unknown) => e)
        expect(err).toBeInstanceOf(Error)
        expect((err as Error).message).toContain('carries credentials')
        expect((err as Error).message).not.toContain('secret')
    })

    it('stops a dial on its signal', async () => {
        const ac = new AbortController()
        const pending = SolanaPubSub.connect('wss://rpc.example/ws', { webSocket: FakeSocket, signal: ac.signal })
        ac.abort(new Error('gone'))
        await expect(pending).rejects.toThrow('gone')
        expect(FakeSocket.last!.closedByClient).toBe(true)
    })
})
