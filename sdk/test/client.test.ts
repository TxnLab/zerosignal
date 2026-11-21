/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Client shell and its per-process state, porting go/zs affinity_test.go,
// fee_rate_test.go and the construction cases of zs_test.go.

import algosdk from 'algosdk'
import { describe, expect, it, vi } from 'vitest'

import {
    Client,
    type Config,
    DuplicateTicketError,
    type EscrowChain,
    FEE_RATE_CACHE_TTL_MS,
    FEE_RATE_REFRESH_TIMEOUT_MS,
    IDAffinity,
    type RegistryProvider,
    type Signer,
    type TicketJournal,
    Wallet,
    type WalletOpener,
    findError,
    isMemoryJournal,
    memoryJournal,
    resolveConfig,
    testnet,
} from '../src/index.js'
import { FeeRateCache } from '../src/fee-rate.js'
import type { Watchdog } from '../src/refund-watchdog.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import { PENDING_BY_OPERATOR, STATUS_PENDING_SETTLE } from '@txnlab/zs-proto/escrow'
import { partsOf } from '../src/client-parts.js'
import { turnOf } from '../src/turn.js'

const signer: Signer = {
    address: 'PAYER',
    signBytes: async () => new Uint8Array(),
    signTransactions: async () => [],
}

const registry: RegistryProvider = {
    operators: async () => [],
    resolve: async () => undefined,
    allOperators: async () => [],
    reprobeEphemeral: async () => null,
    recordModelDemand: () => {},
}

const callerWallet = (over: Partial<WalletOpener> = {}): WalletOpener => ({
    open: () => Promise.reject(new Error('unused')),
    payerAddr: () => 'PAYER',
    ...over,
})

// With the wallet, registry and reserve client all supplied, create reads no
// chain: a built reserve client would need the deployment read from algod.
const standInReserveClient = { reserve: () => Promise.reject(new Error('unused')) }
const base: Config = { signer, network: testnet(), registry, wallet: callerWallet(), reserveClient: standInReserveClient }

// Lets the cache's background refresh settle.
const flush = () => new Promise((r) => setTimeout(r, 0))

describe('IDAffinity', () => {
    it('pins each id to the node that issued it, the latest record winning', () => {
        const a = new IDAffinity(10, 1000)
        a.record({ op: 1, node: 2 }, ['call_a', '', 'call_b'])
        expect(a.lookup('call_a')).toEqual({ op: 1, node: 2 })
        expect(a.lookup('call_b')).toEqual({ op: 1, node: 2 })
        expect(a.size).toBe(2)
        a.record({ op: 3, node: 4 }, ['call_a'])
        expect(a.lookup('call_a')).toEqual({ op: 3, node: 4 })
        expect(a.lookup('')).toBeUndefined()
        expect(a.lookup('nope')).toBeUndefined()
    })

    it('ignores operator 0 and an empty id list', () => {
        const a = new IDAffinity(10, 1000)
        a.record({ op: 0, node: 5 }, ['x'])
        a.record({ op: 1, node: 5 }, [])
        expect(a.size).toBe(0)
    })

    it('keeps a pin live through its expiry instant and sweeps it after', () => {
        let now = 1_000
        const a = new IDAffinity(10, 500, () => now)
        a.record({ op: 1, node: 1 }, ['x'])
        now = 1_500
        expect(a.lookup('x')).toEqual({ op: 1, node: 1 })
        now = 1_501
        expect(a.lookup('x')).toBeUndefined()
        expect(a.size).toBe(0)
    })

    it('a re-record extends the pin from its own time', () => {
        let now = 0
        const a = new IDAffinity(10, 500, () => now)
        a.record({ op: 1, node: 1 }, ['x'])
        now = 400
        a.record({ op: 1, node: 1 }, ['x'])
        now = 900
        expect(a.lookup('x')).toEqual({ op: 1, node: 1 })
    })

    it('evicts the least recently used past max, a lookup counting as use', () => {
        const a = new IDAffinity(2, 1000)
        a.record({ op: 1, node: 1 }, ['a'])
        a.record({ op: 1, node: 1 }, ['b'])
        a.lookup('a')
        a.record({ op: 1, node: 1 }, ['c'])
        expect(a.size).toBe(2)
        expect(a.lookup('b')).toBeUndefined()
        expect(a.lookup('a')).toBeDefined()
        expect(a.lookup('c')).toBeDefined()
    })

    it('a re-record counts as use', () => {
        const a = new IDAffinity(2, 1000)
        a.record({ op: 1, node: 1 }, ['a'])
        a.record({ op: 1, node: 1 }, ['b'])
        a.record({ op: 2, node: 2 }, ['a'])
        a.record({ op: 1, node: 1 }, ['c'])
        expect(a.lookup('b')).toBeUndefined()
        expect(a.lookup('a')).toEqual({ op: 2, node: 2 })
    })

    it('reads a max of 0 or less as 1024', () => {
        for (const max of [0, -1]) {
            const a = new IDAffinity(max, 1000)
            a.record({ op: 1, node: 1 }, Array.from({ length: 1025 }, (_, i) => `id${i}`))
            expect(a.size).toBe(1024)
            expect(a.lookup('id0')).toBeUndefined()
            expect(a.lookup('id1')).toBeDefined()
        }
    })

    it('keeps a max of 1 as given', () => {
        const a = new IDAffinity(1, 1000)
        a.record({ op: 1, node: 1 }, ['a', 'b'])
        expect(a.size).toBe(1)
        expect(a.lookup('a')).toBeUndefined()
        expect(a.lookup('b')).toBeDefined()
    })

    it('hands out copies, so a caller cannot move a pin', () => {
        const a = new IDAffinity(10, 1000)
        const ref = { op: 1, node: 1 }
        a.record(ref, ['x'])
        ref.op = 9
        const got = a.lookup('x')!
        got.node = 9
        expect(a.lookup('x')).toEqual({ op: 1, node: 1 })
    })
})

describe('FeeRateCache', () => {
    it('answers null cold and starts one refresh however many read', async () => {
        const c = new FeeRateCache()
        let resolve!: (v: number) => void
        const fetch = vi.fn(() => new Promise<number>((r) => (resolve = r)))
        expect(c.get(fetch)).toBeNull()
        expect(c.get(fetch)).toBeNull()
        expect(fetch).toHaveBeenCalledTimes(1)
        resolve(25)
        await flush()
        expect(c.get(fetch)).toBe(25)
        expect(fetch).toHaveBeenCalledTimes(1)
    })

    it('serves a stale rate while one refresh replaces it', async () => {
        let now = 0
        const c = new FeeRateCache(() => now)
        const fetch = vi.fn().mockResolvedValueOnce(25).mockResolvedValueOnce(40)
        c.get(fetch)
        await flush()
        now = FEE_RATE_CACHE_TTL_MS
        expect(c.get(fetch)).toBe(25)
        expect(fetch).toHaveBeenCalledTimes(1)
        now = FEE_RATE_CACHE_TTL_MS + 1
        expect(c.get(fetch)).toBe(25)
        expect(c.get(fetch)).toBe(25)
        expect(fetch).toHaveBeenCalledTimes(2)
        await flush()
        expect(c.get(fetch)).toBe(40)
    })

    it('keeps what it had on a failed read, and the next read retries', async () => {
        let now = 0
        const c = new FeeRateCache(() => now)
        const fetch = vi.fn().mockRejectedValueOnce(new Error('algod down')).mockResolvedValueOnce(25)
        c.get(fetch)
        await flush()
        expect(c.get(fetch)).toBeNull()
        await flush()
        expect(c.get(fetch)).toBe(25)
        now = FEE_RATE_CACHE_TTL_MS + 1
        fetch.mockRejectedValueOnce(new Error('algod down'))
        c.get(fetch)
        await flush()
        expect(c.get(fetch)).toBe(25)
    })

    it('survives a fetch that throws before returning a promise', async () => {
        const c = new FeeRateCache()
        const fetch = vi.fn((): Promise<number> => {
            throw new Error('boom')
        })
        expect(c.get(fetch)).toBeNull()
        await flush()
        expect(c.get(fetch)).toBeNull()
        expect(fetch).toHaveBeenCalledTimes(2)
    })

    it('bounds the read at FEE_RATE_REFRESH_TIMEOUT_MS', async () => {
        const timeout = new AbortController()
        const spy = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(timeout.signal)
        try {
            const c = new FeeRateCache()
            let got: AbortSignal | undefined
            c.get(async (signal) => {
                got = signal
                return 1
            })
            await flush()
            expect(spy).toHaveBeenCalledWith(FEE_RATE_REFRESH_TIMEOUT_MS)
            expect(got).toBe(timeout.signal)
        } finally {
            spy.mockRestore()
        }
    })
})

describe('DuplicateTicketError', () => {
    it('is found through a cause chain, and only by class', () => {
        const wrapped = new Error('guard refused', { cause: new DuplicateTicketError() })
        expect(findError(wrapped, DuplicateTicketError)).toBeInstanceOf(DuplicateTicketError)
        expect(findError(new Error('ticket id already has an open reservation'), DuplicateTicketError)).toBeUndefined()
        expect(new DuplicateTicketError().name).toBe('DuplicateTicketError')
    })
})

describe('turnOf', () => {
    it('normalizes the relay preference and fills the defaults', () => {
        expect(turnOf({ endpoint: '/v1/responses', body: '{}', relay: ' Required ' })).toEqual({
            endpoint: '/v1/responses',
            body: '{}',
            contentType: '',
            requireTee: false,
            relay: 'required',
        })
        expect(turnOf({ endpoint: '/v1/responses', body: '{}', relay: 'sometimes' }).relay).toBe('')
        expect(turnOf({ endpoint: '/v1/images/edits', body: 'x', contentType: 'multipart/form-data; boundary=b', requireTee: true })).toMatchObject({
            contentType: 'multipart/form-data; boundary=b',
            requireTee: true,
            relay: '',
        })
    })
})

describe('Client.create', () => {
    it('rejects a Config resolveConfig rejects', async () => {
        await expect(Client.create({ ...base, privacy: 'loud' as never })).rejects.toMatchObject({ code: 'invalid_config' })
    })

    it('logs the configuration warnings', async () => {
        const warn = vi.fn()
        const c = await Client.create({ ...base, maxOutputCeiling: 100, logger: { debug() {}, info() {}, warn, error() {} } })
        expect(warn).toHaveBeenCalledWith(expect.stringContaining('maxOutputCeiling 100'))
        c.close()
    })

    it('exposes the resolved config with the parts it built, and the registry', async () => {
        const c = await Client.create(base)
        expect(c.registry).toBe(registry)
        expect(c.config.registry).toBe(registry)
        expect(c.config.affinity).toEqual({ policy: 'prefer', ttl: 600_000, max: 1024 })
        expect(c.config.wallet).toBe(base.wallet)
        expect(c.config.reserveClient).toBeDefined()
        expect(c.config.stores.toolAffinity).toBeInstanceOf(IDAffinity)
        expect(c.config.stores.responseAffinity).toBeInstanceOf(IDAffinity)
        expect(c.config.stores.toolAffinity).not.toBe(c.config.stores.responseAffinity)
        expect(c.config.stores.journal).toBeUndefined()
        c.close()

        const tool = new IDAffinity(1, 1)
        const d = await Client.create({ ...base, stores: { toolAffinity: tool } })
        expect(d.config.stores.toolAffinity).toBe(tool)
        expect(d.config.stores.responseAffinity).not.toBe(tool)
        d.close()
        const resp = new IDAffinity(1, 1)
        const e = await Client.create({ ...base, stores: { responseAffinity: resp } })
        expect(e.config.stores.responseAffinity).toBe(resp)
        expect(e.config.stores.toolAffinity).not.toBe(resp)
        e.close()
    })

    it('builds both affinity stores from Config.affinity and its clock', async () => {
        let now = 0
        const c = await Client.create({ ...base, affinity: { ttl: 500, max: 1 }, clock: () => now })
        for (const store of [c.config.stores.toolAffinity!, c.config.stores.responseAffinity!]) {
            now = 0
            store.record({ op: 1, node: 1 }, ['a', 'b'])
            expect(store.lookup('a')).toBeUndefined()
            now = 500
            expect(store.lookup('b')).toEqual({ op: 1, node: 1 })
            now = 501
            expect(store.lookup('b')).toBeUndefined()
        }
        c.close()
    })

    it('warms the fee rate from create and serves it once read', async () => {
        const protocolFeeBps = vi.fn(async () => 30)
        const c = await Client.create({ ...base, wallet: callerWallet({ protocolFeeBps }) })
        expect(protocolFeeBps).toHaveBeenCalledTimes(1)
        await flush()
        expect(c.feeRate()).toBe(30)
        expect(protocolFeeBps).toHaveBeenCalledTimes(1)
        c.close()
    })

    it('has no fee rate when the wallet cannot read one', async () => {
        const c = await Client.create(base)
        expect(c.feeRate()).toBeNull()
        c.close()
    })

    // Go's New: the watchdog logs the Remedies.RecoverTicket in force, and its
    // refunds free the SpendGuard's reservation.
    // Go's New: the watchdog times deadlines on the wall clock, whatever
    // Config.clock says, logs the Remedies.RecoverTicket in force, and its
    // refunds free the SpendGuard's reservation.
    it('runs a refund watchdog on the wall clock, with the configured logger, remedy and spend guard', async () => {
        const released: string[] = []
        const logged: { msg: string; attrs: Record<string, unknown> | undefined }[] = []
        const at = (msg: string, attrs?: Record<string, unknown>) => void logged.push({ msg, attrs })
        const make = (over: Partial<Config>) =>
            Client.create({
                ...base,
                // Decades ahead: read off it, an hour-away deadline is long past.
                clock: () => 4_000_000_000_000,
                logger: { debug: at, info: at, warn: at, error: at },
                spendGuard: { admit() {}, reserve() {}, settle() {}, release: (id) => void released.push(id) },
                ...over,
            })
        const due = async () => ({ exists: true, verdict: 'refundInactive' as const, deadlineMs: 0 })
        const giveUps = () => logged.filter((l) => l.msg.includes('giving up')).map((l) => l.attrs?.remedy)

        const c = await make({ remedies: { recoverTicket: 'ask the operator' } })
        const rw = c.refunds as Watchdog
        rw.retryDelayMs = 1
        let early = 0
        rw.arm('EARLY', Date.now() + 3_600_000, due, async () => (early++, 'TX'), async () => '')
        rw.arm('T1', Date.now(), due, async () => 'TX', async () => '')
        rw.arm('T2', Date.now(), due, () => Promise.reject(new Error('algod down')), async () => '')
        await vi.waitFor(() => expect(giveUps()).toEqual(['ask the operator']))
        expect(released).toEqual(['T1'])
        expect(early).toBe(0)
        rw.resolve('EARLY')
        c.close()

        const d = await make({})
        ;(d.refunds as Watchdog).retryDelayMs = 1
        ;(d.refunds as Watchdog).arm('T3', Date.now(), due, () => Promise.reject(new Error('algod down')), async () => '')
        await vi.waitFor(() => expect(giveUps()).toHaveLength(2))
        expect(giveUps()[1]).toEqual(expect.stringContaining('call refundInactive on an open ticket'))
        d.close()
    })

    it("starts no journal for a caller's wallet", async () => {
        const c = await Client.create(base)
        expect(c.journalDurable).toBe(false)
        c.close()
        const d = await Client.create({ ...base, stores: { journal: memoryJournal() } })
        expect(d.journalDurable).toBe(false)
        d.close()
        const durable: TicketJournal = { put: async () => {}, delete: async () => {}, list: async () => [] }
        expect(isMemoryJournal(durable)).toBe(false)
        const e = await Client.create({ ...base, stores: { journal: durable } })
        expect(e.journalDurable).toBe(true)
        expect(e.config.stores.journal).toBe(durable)
        // Only the SDK's own wallet runs the sweep.
        expect(partsOf.get(e)!.reconciler).toBeUndefined()
        e.close()
    })

    describe("with the SDK's Wallet", () => {
        const chain = { protocolFeeBps: async () => 0 } as unknown as EscrowChain
        const sdkWallet = () => new Wallet({ chain, signer })

        it('journals in memory by default and says so', async () => {
            const info = vi.fn()
            const c = await Client.create({ ...base, wallet: sdkWallet(), logger: { debug() {}, info, warn() {}, error() {} } })
            expect(c.journalDurable).toBe(false)
            expect(isMemoryJournal(c.config.stores.journal!)).toBe(true)
            expect(info).toHaveBeenCalledWith(expect.stringContaining('journaled in memory'))
            c.close()
        })

        it('refuses a journal another Client sweeps, until that one closes', async () => {
            const journal = memoryJournal()
            const a = await Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })
            await expect(Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })).rejects.toMatchObject({
                code: 'invalid_config',
                message: expect.stringContaining('already swept by another Client'),
            })
            // The claim is held until the sweep has stopped.
            const closing = a.close()
            await expect(Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })).rejects.toMatchObject({
                code: 'invalid_config',
            })
            await closing
            await a.close()
            const b = await Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })
            expect(b.config.stores.journal).toBe(journal)
            // A's late second close must not free the claim b now holds.
            await a.close()
            await expect(Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })).rejects.toMatchObject({
                code: 'invalid_config',
            })
            await b.close()
        })

        // A restart's leftovers are found by the first sweep, which create
        // starts at once, acting as this payer on this deployment.
        it('sweeps its journal from create', async () => {
            const refunds: unknown[] = []
            const sweepChain = {
                protocolFeeBps: async () => 0,
                readTicketBox: async () => ({ status: 1, pendingBy: 0, expiresAt: 1n, settlementGraceSeconds: 0n }),
                refundInactive: async (c: unknown) => (refunds.push(c), 'TX'),
            } as unknown as EscrowChain
            const journal = memoryJournal()
            const row = {
                ticketId: 'NkImzFiSJz3WK6cx7PFU1Q==',
                openTxId: '',
                escrowAppId: resolveConfig(base).network.escrowAppId,
                target: { op: 3, node: 4 },
                payer: 'PAYER',
                maxPrice: 1n,
                expiresAt: 0,
                status: 'open' as const,
                createdAt: 0,
                updatedAt: 0,
            }
            await journal.put(row)
            await journal.put({ ...row, ticketId: 'AAAAAAAAAAAAAAAAAAAAAA==', escrowAppId: 1n })
            const c = await Client.create({ ...base, wallet: new Wallet({ chain: sweepChain, signer }), stores: { journal } })
            await vi.waitFor(() => expect(refunds).toHaveLength(1))
            expect(refunds[0]).toMatchObject({ operatorId: 3n, nodeId: 4n, payer: 'PAYER' })
            await c.close()
        })

        // Go's TestNew_WiresTheSpendGuardToTheTicketOutcomes: the first sweep
        // already tells the guard, it decides deadlines on the wall clock, and
        // it gives up naming the configured remedy.
        it('sweeps with the spend guard, the remedy and the wall clock', async () => {
            const CLOSED = 'NkImzFiSJz3WK6cx7PFU1Q=='
            const released: string[] = []
            const refunds: unknown[] = []
            const inAnHour = BigInt(Math.floor(Date.now() / 1000) + 3600)
            const sweepChain = {
                protocolFeeBps: async () => 0,
                // CLOSED's box is gone; the other's deadline is an hour off.
                readTicketBox: async (raw: Uint8Array) =>
                    raw[0] === 0x36 ? null : { status: 1, pendingBy: 0, expiresAt: inAnHour, settlementGraceSeconds: 0n },
                refundInactive: async (c: unknown) => (refunds.push(c), 'TX'),
            } as unknown as EscrowChain
            const journal = memoryJournal()
            const row = {
                openTxId: '',
                escrowAppId: resolveConfig(base).network.escrowAppId,
                target: { op: 3, node: 4 },
                payer: 'PAYER',
                maxPrice: 1n,
                expiresAt: 0,
                createdAt: 0,
                updatedAt: 0,
            }
            const settle = {
                amountCharged: 1n,
                receiptDigest: new Uint8Array(32),
                ttftMs: 0n,
                decodeMs: 0n,
                inputTokens: 0n,
                outputTokens: 0n,
                outputUsageType: 0,
                auxOutputUsageType: 0,
                auxOutputCount: 0n,
            }
            await journal.put({ ...row, ticketId: CLOSED, status: 'settle_pending', settle })
            await journal.put({ ...row, ticketId: 'AAAAAAAAAAAAAAAAAAAAAA==', status: 'open' })
            const c = await Client.create({
                ...base,
                clock: () => 4_000_000_000_000,
                wallet: new Wallet({ chain: sweepChain, signer }),
                stores: { journal },
                remedies: { recoverTicket: 'ask the operator' },
                spendGuard: { admit() {}, reserve() {}, settle() {}, release: (id) => void released.push(id) },
            })
            await vi.waitFor(() => expect(released).toEqual([CLOSED]))
            expect(refunds).toEqual([])
            expect(partsOf.get(c)!.reconciler!.remedy).toBe('ask the operator')
            await c.close()
        })

        // Go's TestNew_BackgroundDriversBarAnOverclaimingNode: the sweep and
        // the watchdog bar an over-claiming node in the Client's own
        // exclusion store, the one routing reads.
        it('bars an over-claiming node from the sweep and the watchdog', async () => {
            const nodeExclusions = new NodeExclusionStore()
            const inAnHour = BigInt(Math.floor(Date.now() / 1000) + 3600)
            const sweepChain = {
                protocolFeeBps: async () => 0,
                config: async () => ({ resolvesFrozen: true }),
                readTicketBox: async () => ({
                    status: STATUS_PENDING_SETTLE,
                    pendingBy: PENDING_BY_OPERATOR,
                    expiresAt: inAnHour,
                    settlementGraceSeconds: 0n,
                    pendingAmount: 100n,
                    pendingDigest: new Uint8Array(32),
                }),
                settleStandalone: async () => ({ txid: 'FREEZETX', payerFeeMicroalgos: 1000n }),
            } as unknown as EscrowChain
            const journal = memoryJournal()
            await journal.put({
                ticketId: 'NkImzFiSJz3WK6cx7PFU1Q==',
                openTxId: '',
                escrowAppId: resolveConfig(base).network.escrowAppId,
                target: { op: 3, node: 4 },
                payer: 'PAYER',
                maxPrice: 200n,
                expiresAt: 0,
                status: 'settle_pending',
                settle: {
                    amountCharged: 1n,
                    receiptDigest: new Uint8Array(32),
                    ttftMs: 0n,
                    decodeMs: 0n,
                    inputTokens: 0n,
                    outputTokens: 0n,
                    outputUsageType: 0,
                    auxOutputUsageType: 0,
                    auxOutputCount: 0n,
                },
                createdAt: 0,
                updatedAt: 0,
            })
            const c = await Client.create({ ...base, wallet: new Wallet({ chain: sweepChain, signer }), stores: { journal, nodeExclusions } })
            await vi.waitFor(() => expect(nodeExclusions.nodeExcluded({ op: 3, node: 4 })).toBe(true))

            const rw = c.refunds as Watchdog
            rw.lapseFallbackMs = 1
            const claim = async () => ({ exists: true, verdict: 'settleLapsed' as const, deadlineMs: 0, pendingAmount: 101n })
            rw.arm('W', Date.now() + 20, claim, async () => '', async () => 'TX')
            rw.recordReceipt('W', { op: 5, node: 6 }, 100n)
            await vi.waitFor(() => expect(nodeExclusions.nodeExcluded({ op: 5, node: 6 })).toBe(true))
            await c.close()
        })

        // A live ticket has one driver: the sweep leaves the ones this
        // Client's watchdog holds, or both would send the same refund.
        it("leaves the tickets its own watchdog drives to it", async () => {
            const WATCHED = 'NkImzFiSJz3WK6cx7PFU1Q=='
            const refunded: number[] = []
            const sweepChain = {
                protocolFeeBps: async () => 0,
                readTicketBox: async () => ({ status: 1, pendingBy: 0, expiresAt: 1n, settlementGraceSeconds: 0n }),
                refundInactive: async (c: { ticketIdRaw: Uint8Array }) => (refunded.push(c.ticketIdRaw[0]!), 'TX'),
            } as unknown as EscrowChain
            const row = {
                openTxId: '',
                escrowAppId: resolveConfig(base).network.escrowAppId,
                target: { op: 3, node: 4 },
                payer: 'PAYER',
                maxPrice: 1n,
                expiresAt: 0,
                status: 'open' as const,
                createdAt: 0,
                updatedAt: 0,
            }
            const journal = memoryJournal()
            await journal.put({ ...row, ticketId: WATCHED })
            await journal.put({ ...row, ticketId: 'AAAAAAAAAAAAAAAAAAAAAA==' })
            // Held until the watchdog is armed, as a live turn arms it.
            let open!: () => void
            const gate = new Promise<void>((r) => (open = r))
            const list = journal.list.bind(journal)
            journal.list = async (...a) => (await gate, list(...a))
            const c = await Client.create({ ...base, wallet: new Wallet({ chain: sweepChain, signer }), stores: { journal } })
            const p = partsOf.get(c)!
            const never = async () => ''
            p.refunds.arm(WATCHED, Date.now() + 3_600_000, async () => ({ exists: false, verdict: 'unknown', deadlineMs: 0 }), never, never)
            open()
            await vi.waitFor(() => expect(refunded).toEqual([0]))
            p.refunds.resolve(WATCHED)
            await c.close()
        })

        // The claim goes back last: once released, the next Client may sweep
        // the same rows, and anything of this one's still driving them would
        // submit the same refund or lapse. A journal the caller supplied, a
        // memoryJournal too, can pass to the next Client, and a refund already
        // sent is waited for.
        for (const [kind, journal] of [
            ['durable', (): TicketJournal => ({ put: async () => {}, delete: async () => {}, list: async () => [] })],
            ['memoryJournal', () => memoryJournal()],
        ] as const) {
            it(`hands the watchdog off, waiting out a sent refund, before releasing a supplied ${kind} journal`, async () => {
                const j = journal()
                const c = await Client.create({ ...base, wallet: sdkWallet(), stores: { journal: j } })
                const p = partsOf.get(c)!
                const never = async () => ''
                const due = async () => ({ exists: true, verdict: 'refundInactive' as const, deadlineMs: 0 })
                p.refunds.arm('LIVE', Date.now() + 3_600_000, due, never, never)
                let sending!: () => void
                const sent = new Promise<void>((r) => (sending = r))
                let finish!: () => void
                const gate = new Promise<void>((r) => (finish = r))
                p.refunds.arm('SENDING', Date.now(), due, async () => (sending(), await gate, 'TX'), never)
                await sent
                const release = p.reconciler!.release!
                const atRelease: boolean[] = []
                p.reconciler!.release = () => {
                    atRelease.push(p.refunds.watching('LIVE'))
                    release()
                }
                const closed = c.close()
                await new Promise((r) => setTimeout(r, 20))
                expect(atRelease, 'released while a refund was in flight').toEqual([])
                finish()
                await closed
                expect(atRelease).toEqual([false])
                const next = await Client.create({ ...base, wallet: sdkWallet(), stores: { journal: j } })
                await next.close()
            })
        }

        // Go's Close calls endLife first: a settle watch ends before the
        // reconciler hands off, not after.
        it('ends settle watches before handing the watchdog off', async () => {
            const c = await Client.create({ ...base, wallet: sdkWallet(), stores: { journal: memoryJournal() } })
            const p = partsOf.get(c)!
            let finish!: () => void
            const gate = new Promise<void>((r) => (finish = r))
            const handOff = p.refunds.handOff.bind(p.refunds)
            p.refunds.handOff = async () => {
                await gate
                await handOff()
            }
            const pending = { settleOutcome: async () => 'pending' as const } as unknown as Parameters<typeof p.settles.confirmSettled>[2]
            p.settles.confirmSettled('WATCHED', 'TX', pending)
            const closed = c.close()
            const ended = await Promise.race([
                p.settles.wait().then(() => true),
                new Promise<boolean>((r) => setTimeout(() => r(false), 2000)),
            ])
            expect(ended, 'the watch outlived the hand-off').toBe(true)
            finish()
            await closed
        })

        // The default journal dies with the Client, so its watchdog stays the
        // only thing that finishes its tickets.
        it('keeps the watchdog running past close over its own memory journal', async () => {
            const c = await Client.create({ ...base, wallet: sdkWallet() })
            const p = partsOf.get(c)!
            const never = async () => ''
            p.refunds.arm('LIVE', Date.now() + 3_600_000, async () => ({ exists: false, verdict: 'unknown', deadlineMs: 0 }), never, never)
            await c.close()
            expect(p.refunds.watching('LIVE')).toBe(true)
            p.refunds.resolve('LIVE')
        })

        it("reads the fee rate through the SDK's Wallet", async () => {
            const feeChain = { protocolFeeBps: async () => 30 } as unknown as EscrowChain
            const c = await Client.create({ ...base, wallet: new Wallet({ chain: feeChain, signer }) })
            await flush()
            expect(c.feeRate()).toBe(30)
            c.close()
        })

        it("lets a caller's wallet share a journal: it runs no sweep, and its close frees nothing", async () => {
            const journal = memoryJournal()
            const a = await Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })
            const b = await Client.create({ ...base, stores: { journal } })
            b.close()
            await expect(Client.create({ ...base, wallet: sdkWallet(), stores: { journal } })).rejects.toMatchObject({
                code: 'invalid_config',
            })
            a.close()
        })
    })

    it('fails when the escrow config read for a built wallet fails', async () => {
        const addr = algosdk.generateAccount().addr.toString()
        const { wallet: _, ...noWallet } = base
        // A refusal, which the algod transport does not retry.
        const algod = vi.fn(async () => new Response(JSON.stringify({ message: 'no such app' }), { status: 404 }))
        vi.stubGlobal('fetch', algod)
        try {
            const p = Client.create({
                ...noWallet,
                signer: { ...signer, address: addr },
                network: { network: 'testnet', algodEndpoint: 'http://127.0.0.1:1' },
            })
            await expect(p).rejects.toThrow(/^read escrow config: .*no such app/)
            expect(algod).toHaveBeenCalled()
            expect(String((algod.mock.calls[0] as unknown[])[0])).toMatch(/^http:\/\/127\.0\.0\.1:1\//)
        } finally {
            vi.unstubAllGlobals()
        }
    })

    it('stops retrying the escrow config reads once create gives up', async () => {
        const addr = algosdk.generateAccount().addr.toString()
        const { wallet: _, ...noWallet } = base
        const algod = vi.fn(async () => new Response('', { status: 503 }))
        vi.stubGlobal('fetch', algod)
        try {
            const ac = new AbortController()
            const p = Client.create({ ...noWallet, signer: { ...signer, address: addr } }, ac.signal)
            await vi.waitFor(() => expect(algod).toHaveBeenCalled())
            ac.abort(new Error('caller left'))
            await expect(p).rejects.toThrow('read escrow config: caller left')
            const calls = algod.mock.calls.length
            // Past the transport's first one-second wait.
            await new Promise((r) => setTimeout(r, 1_500))
            expect(algod.mock.calls.length).toBe(calls)
        } finally {
            vi.unstubAllGlobals()
        }
    })

    it("stops the escrow config read on create's signal", async () => {
        const addr = algosdk.generateAccount().addr.toString()
        const { wallet: _, ...noWallet } = base
        const p = Client.create({ ...noWallet, signer: { ...signer, address: addr } }, AbortSignal.abort(new Error('caller left')))
        await expect(p).rejects.toThrow('read escrow config: caller left')
    })
})
