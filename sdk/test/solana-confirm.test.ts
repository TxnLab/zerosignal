/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// confirmSignature against a scripted chain, ported from go/solana/rpc
// confirm_test.go.

import { encodeBase58 } from '@txnlab/zs-proto/solana'
import { describe, expect, it } from 'vitest'

import { confirmSignature, reached, TransactionExpiredError } from '../src/solana/confirm.js'
import { SolanaPubSub, type WebSocketLike } from '../src/solana/pubsub.js'
import { type Commitment, type SignatureStatus, type SolanaRpc, txErrorName } from '../src/solana/rpc.js'

const SIG = encodeBase58(new Uint8Array(64).fill(0x11))

const at = (slot: bigint, c: Commitment, err: unknown = null): SignatureStatus => ({ slot, confirmations: null, err, confirmationStatus: c })

/** Answers the two reads from scripts, the last entry of each repeating, and counts them. */
function chain(statuses: (SignatureStatus | null)[], heights: bigint[]) {
    const n = { status: 0, height: 0 }
    // Each height read's commitment.
    const heightAt: (Commitment | undefined)[] = []
    const unused = () => {
        throw new Error('unused')
    }
    const rpc: SolanaRpc = {
        getSignatureStatuses: async () => [statuses[Math.min(n.status++, statuses.length - 1)]!],
        getBlockHeight: async (o) => (heightAt.push(o?.commitment), heights[Math.min(n.height++, heights.length - 1)]!),
        getAccountInfo: unused,
        getProgramAccounts: unused,
        getBalance: unused,
        getLatestBlockhash: unused,
        getGenesisHash: unused,
        getMinimumBalanceForRentExemption: unused,
        sendTransaction: unused,
    }
    return { rpc, n, heightAt }
}

const fast = { pollMs: 1, heightCheckMs: 1 }

describe('confirmSignature', () => {
    it('waits for the commitment', async () => {
        const { rpc, n } = chain([null, at(7n, 'processed'), at(7n, 'confirmed')], [90n])
        await expect(confirmSignature(rpc, SIG, 100n, 'confirmed', fast)).resolves.toEqual({ slot: 7n, err: null })
        // The processed status is a landed transaction: no height is read for it.
        expect(n).toEqual({ status: 3, height: 1 })
    })

    it('returns a failed landing', async () => {
        const { rpc } = chain([at(9n, 'finalized', { InstructionError: [2, { Custom: 6054 }] })], [0n])
        const r = await confirmSignature(rpc, SIG, 100n, undefined, fast)
        expect(r.slot).toBe(9n)
        expect(txErrorName(r.err)).toBe('InstructionError')
    })

    it('expires only past the height with no status', async () => {
        const { rpc, n, heightAt } = chain([null], [99n, 100n, 101n])
        await expect(confirmSignature(rpc, SIG, 100n, 'confirmed', fast)).rejects.toBeInstanceOf(TransactionExpiredError)
        // At the height itself the transaction can still land.
        expect(n.height).toBe(3)
        // The confirmed height, not the finalized one, which lags and would declare the expiry late.
        expect(heightAt).toEqual(['confirmed', 'confirmed', 'confirmed'])
    })

    it('reads the status once more past the height', async () => {
        // The transaction landed between the status read and the height read.
        const { rpc } = chain([null, at(100n, 'finalized')], [101n])
        await expect(confirmSignature(rpc, SIG, 100n, 'finalized', fast)).resolves.toEqual({ slot: 100n, err: null })
    })

    it('waits on a landing past the height', async () => {
        // Landed but short of the commitment when the height passed: not expired.
        const { rpc } = chain([null, at(100n, 'processed'), at(100n, 'confirmed')], [101n])
        await expect(confirmSignature(rpc, SIG, 100n, 'confirmed', fast)).resolves.toEqual({ slot: 100n, err: null })
    })

    it('ends with the signal', async () => {
        const { rpc } = chain([null], [1n])
        const signal = AbortSignal.timeout(20)
        await expect(confirmSignature(rpc, SIG, 100n, 'confirmed', { ...fast, signal })).rejects.toMatchObject({ name: 'TimeoutError' })
    })
})

describe('reached', () => {
    it.each([
        [{ confirmationStatus: 'processed' }, 'processed', true],
        [{ confirmationStatus: 'processed' }, 'confirmed', false],
        [{ confirmationStatus: 'confirmed' }, 'confirmed', true],
        [{ confirmationStatus: 'confirmed' }, 'finalized', false],
        [{ confirmationStatus: 'finalized' }, 'confirmed', true],
        [{ confirmations: 2n }, 'processed', true],
        [{ confirmations: 2n }, 'confirmed', false],
        [{}, 'finalized', true],
    ] as const)('reads an older RPC status %o at %s', (s, c, want) => {
        const status: SignatureStatus = { slot: 0n, confirmations: null, err: null, confirmationStatus: undefined, ...s }
        expect(reached(status, c)).toBe(want)
    })
})

type Listener = (ev: { data: unknown }) => void

class FakeSocket implements WebSocketLike {
    static last: FakeSocket | undefined
    readonly sent: { id: number; method: string; params: unknown }[] = []
    readonly #listeners = new Map<string, Listener[]>()

    constructor(readonly url: string) {
        FakeSocket.last = this
    }
    addEventListener(type: string, listener: Listener): void {
        this.#listeners.set(type, [...(this.#listeners.get(type) ?? []), listener])
    }
    send(data: string): void {
        this.sent.push(JSON.parse(data) as { id: number; method: string; params: unknown })
    }
    close(): void {
        this.emit('close')
    }
    emit(type: string, data?: unknown): void {
        for (const l of this.#listeners.get(type) ?? []) l({ data })
    }
    push(msg: unknown): void {
        this.emit('message', JSON.stringify(msg))
    }
}

async function connect(): Promise<{ pubsub: SolanaPubSub; ws: FakeSocket }> {
    const pending = SolanaPubSub.connect('wss://rpc.example/ws', { webSocket: FakeSocket })
    const ws = FakeSocket.last!
    ws.emit('open')
    return { pubsub: await pending, ws }
}

// The height check for a test whose watch must arm. confirmSignature gives
// the subscribe one height check to be answered, and a millisecond can pass
// before the test answers it: the subscribe then times out and it polls, as it
// should. Go's armWindow.
const ARM_WINDOW_MS = 100

async function until(f: () => boolean): Promise<void> {
    while (!f()) await new Promise((r) => setTimeout(r, 1))
}

describe('confirmSignature with a watch', () => {
    it("takes the watch's answer", async () => {
        const { pubsub, ws } = await connect()
        // The status stays unknown and the height low, so only the watch can end it.
        const { rpc, n } = chain([null], [1n])
        const done = confirmSignature(rpc, SIG, 100n, 'confirmed', { pubsub, pollMs: 1, heightCheckMs: 3_600_000 })
        await until(() => ws.sent.length > 0)
        const call = ws.sent[0]!
        expect(call.method).toBe('signatureSubscribe')
        expect(call.params).toEqual([SIG, { commitment: 'confirmed' }])
        ws.push({ jsonrpc: '2.0', result: 4, id: call.id })
        await until(() => n.status >= 1)
        ws.push({
            jsonrpc: '2.0',
            method: 'signatureNotification',
            params: { result: { context: { slot: 12 }, value: { err: null } }, subscription: 4 },
        })
        await expect(done).resolves.toEqual({ slot: 12n, err: null })
        // One status read while arming, then nothing polled.
        expect(n.status).toBe(1)
    })

    it('takes a landing found past the height', async () => {
        // With a watch armed the ticks read only the height, so the read past it is the one that finds the landing.
        const { pubsub, ws } = await connect()
        const { rpc, n } = chain([null, at(100n, 'confirmed')], [90n, 101n])
        const done = confirmSignature(rpc, SIG, 100n, 'confirmed', { pubsub, pollMs: 3_600_000, heightCheckMs: ARM_WINDOW_MS })
        await until(() => ws.sent.length > 0)
        ws.push({ jsonrpc: '2.0', result: 4, id: ws.sent[0]!.id })
        await expect(done).resolves.toEqual({ slot: 100n, err: null })
        expect(n.status).toBe(2)
    })

    it('reads only the height while a watch is armed', async () => {
        const { pubsub, ws } = await connect()
        const { rpc, n } = chain([null], [1n])
        const ctl = new AbortController()
        const done = confirmSignature(rpc, SIG, 100n, 'confirmed', { pubsub, pollMs: 1, heightCheckMs: ARM_WINDOW_MS, signal: ctl.signal })
        await until(() => ws.sent.length > 0)
        ws.push({ jsonrpc: '2.0', result: 4, id: ws.sent[0]!.id })
        await until(() => n.height >= 3)
        ctl.abort()
        await done.catch(() => {})
        // The status was read once, while arming: the watch is what saves the polls.
        expect(n.status).toBe(1)
    })

    it('polls when the subscribe goes unanswered', async () => {
        const { pubsub, ws } = await connect()
        const { rpc, n } = chain([null, at(5n, 'confirmed')], [1n])
        const done = confirmSignature(rpc, SIG, 100n, 'confirmed', { pubsub, pollMs: 1, heightCheckMs: 20 })
        await until(() => ws.sent.length > 0)
        await expect(done).resolves.toEqual({ slot: 5n, err: null })
        expect(n.status).toBe(2)
    })

    it('polls when the subscribe fails', async () => {
        const { pubsub, ws } = await connect()
        ws.close()
        const { rpc } = chain([null, at(5n, 'confirmed')], [1n])
        await expect(confirmSignature(rpc, SIG, 100n, 'confirmed', { pubsub, pollMs: 1, heightCheckMs: 3_600_000 })).resolves.toEqual({
            slot: 5n,
            err: null,
        })
    })

    it('polls once the watch drops', async () => {
        const { pubsub, ws } = await connect()
        // pollMs is an hour, so only a status read at the drop itself ends it.
        const { rpc, n } = chain([null, at(5n, 'confirmed')], [1n])
        const done = confirmSignature(rpc, SIG, 100n, 'confirmed', { pubsub, pollMs: 3_600_000, heightCheckMs: 3_600_000 })
        await until(() => ws.sent.length > 0)
        ws.push({ jsonrpc: '2.0', result: 4, id: ws.sent[0]!.id })
        await until(() => n.status >= 1)
        ws.close()
        await expect(done).resolves.toEqual({ slot: 5n, err: null })
        expect(n.status).toBe(2)
    })
})
