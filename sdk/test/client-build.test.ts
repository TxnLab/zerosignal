/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Client.create building the SDK's own wallet, over a stand-in chain: the
// wiring from Config to the chain, the startup read's bound, and the journal
// the built wallet claims.

import { afterEach, describe, expect, it, vi } from 'vitest'

import { base64 } from '@scure/base'
import { algorandDeploymentId, encodeDeploymentId } from '@txnlab/zs-proto/ticket'
import { DEPLOYMENT_BINDING_MIN_VERSION } from '@txnlab/zs-proto/wire'

import type { AlgodEscrowChainOptions } from '../src/escrow/algod.js'
import type { ReserveCall } from '../src/reserve.js'

const GENESIS = new Uint8Array(32).fill(7)

const h = vi.hoisted(() => ({
    built: [] as { opts: AlgodEscrowChainOptions; signal: AbortSignal | undefined }[],
    refresh: (_signal: AbortSignal | undefined): Promise<void> => Promise.resolve(),
    // The genesis read Client.create makes after the wallet's; a stand-in so
    // no test reaches a real algod.
    params: (): Promise<unknown> => Promise.resolve({ genesisHash: new Uint8Array(32).fill(7) }),
    reserveCalls: [] as ReserveCall[],
}))

vi.mock('../src/reserve.js', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../src/reserve.js')>()),
    reserve: (call: ReserveCall) => {
        h.reserveCalls.push(call)
        return Promise.reject(new Error('captured'))
    },
}))

vi.mock('../src/escrow/algod.js', async (importOriginal) => {
    const real = await importOriginal<typeof import('../src/escrow/algod.js')>()
    class StandInChain {
        readonly #entry: (typeof h.built)[number]
        constructor(opts: AlgodEscrowChainOptions) {
            this.#entry = { opts, signal: undefined }
            h.built.push(this.#entry)
        }
        refreshConfig(signal?: AbortSignal): Promise<void> {
            this.#entry.signal = signal
            return h.refresh(signal)
        }
        protocolFeeBps(): Promise<number> {
            return Promise.resolve(30)
        }
    }
    return { ...real, AlgodEscrowChain: StandInChain, suggestedParams: () => h.params() }
})

// Only Algorand resolves until a Solana host is wired, so a Solana network
// stands on Algorand's here: enough for Client.create to build for its rail.
vi.mock('../src/network.js', async (importOriginal) => {
    const m = await importOriginal<typeof import('../src/network.js')>()
    return {
        ...m,
        resolveNetwork: (n: Parameters<typeof m.resolveNetwork>[0]) =>
            n?.rail === 'solana' ? { ...m.resolveNetwork({ ...n, rail: 'algorand' }), rail: 'solana' as const } : m.resolveNetwork(n),
    }
})

const { Client, ESCROW_CONFIG_TIMEOUT_MS, Wallet, isMemoryJournal, resolveNetwork, testnet } = await import('../src/index.js')
const { partsOf } = await import('../src/client-parts.js')
const { testOperator } = await import('./fixtures.js')
type Config = import('../src/index.js').Config

const signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }
const registry = {
    operators: async () => [],
    resolve: async () => undefined,
    allOperators: async () => [],
    reprobeEphemeral: async () => null,
    recordModelDemand: () => {},
}
const base: Config = { signer, network: testnet(), registry }

const flush = () => new Promise((r) => setTimeout(r, 0))

// A read that ends only when its signal aborts, as a stalled algod's would.
const stalls = (signal: AbortSignal | undefined) =>
    new Promise<void>((_, reject) => signal?.addEventListener('abort', () => reject(signal.reason), { once: true }))

afterEach(() => {
    h.built.length = 0
    h.refresh = () => Promise.resolve()
    h.params = () => Promise.resolve({ genesisHash: GENESIS })
    h.reserveCalls.length = 0
    vi.restoreAllMocks()
})

describe('Client.create building the wallet', () => {
    it('builds the Wallet over the configured escrow and claims a memory journal for it', async () => {
        const c = await Client.create(base)
        expect(h.built).toHaveLength(1)
        const { opts } = h.built[0]!
        expect(opts.appId).toBe(resolveNetwork(testnet()).escrowAppId)
        expect(opts.signer).toBe(signer)
        expect(c.config.wallet).toBeInstanceOf(Wallet)
        expect(c.config.wallet!.payerAddr()).toBe('PAYER')
        const journal = c.config.stores.journal!
        expect(isMemoryJournal(journal)).toBe(true)
        expect(c.journalDurable).toBe(false)
        await expect(Client.create({ ...base, stores: { journal } })).rejects.toMatchObject({ code: 'invalid_config' })
        await flush()
        expect(c.feeRate()).toBe(30)
        c.close()
    })

    it('bounds the escrow config read at ESCROW_CONFIG_TIMEOUT_MS, with or without a live caller signal', async () => {
        for (const caller of [undefined, new AbortController().signal]) {
            const timeouts: [number, AbortController][] = []
            vi.spyOn(AbortSignal, 'timeout').mockImplementation((ms) => {
                const ctl = new AbortController()
                timeouts.push([ms, ctl])
                return ctl.signal
            })
            h.refresh = stalls
            const p = Client.create(base, caller)
            await flush()
            const bound = timeouts.find(([ms]) => ms === ESCROW_CONFIG_TIMEOUT_MS)
            expect(bound).toBeDefined()
            bound![1].abort(new Error('timed out'))
            await expect(p).rejects.toThrow(/^read escrow config: timed out$/)
            vi.restoreAllMocks()
        }
    })

    it("stops the escrow config read on the caller's signal", async () => {
        h.refresh = stalls
        const ctrl = new AbortController()
        const p = Client.create(base, ctrl.signal)
        await flush()
        ctrl.abort(new Error('caller left'))
        await expect(p).rejects.toThrow('read escrow config: caller left')
    })

    // The wallet just read the chain, so algod is up: a failed genesis read
    // is not a blip to start unbound for.
    it('fails when the genesis read fails after building the wallet', async () => {
        h.params = () => Promise.reject(new Error('genesis down'))
        await expect(Client.create(base)).rejects.toThrow('genesis down')
    })

    // The reserve client it builds names the genesis-derived deployment to a
    // node that binds.
    it('hands the deployment to the reserve client it builds', async () => {
        const c = await Client.create(base)
        const op = testOperator({
            ephemeralRecipient: 'age1live',
            ephemeralExpiry: Math.floor(Date.now() / 1000) + 3600,
            protoVersion: DEPLOYMENT_BINDING_MIN_VERSION,
        })
        await expect(
            partsOf.get(c)!.reserveClient.reserve(op, { model: 'm', input_count: 1, max_output_count: 1 } as never, null),
        ).rejects.toThrow('captured')
        const want = encodeDeploymentId(algorandDeploymentId(GENESIS, resolveNetwork(testnet()).escrowAppId))
        expect(h.reserveCalls[0]!.request.deployment).toBe(want)
        c.close()
    })

    // A reserve client built without the rail would let a Solana payer's node
    // choose its ticket ids.
    it('hands the rail to the reserve client it builds', async () => {
        const c = await Client.create({ ...base, network: { ...testnet(), rail: 'solana' } })
        const op = testOperator({ ephemeralRecipient: 'age1live', ephemeralExpiry: Math.floor(Date.now() / 1000) + 3600 })
        await expect(
            partsOf.get(c)!.reserveClient.reserve(op, { model: 'm', input_count: 1, max_output_count: 1 } as never, null),
        ).rejects.toThrow('captured')
        expect(base64.decode(h.reserveCalls[0]!.request.ticket_id ?? '')).toHaveLength(16)
        c.close()
    })
})
