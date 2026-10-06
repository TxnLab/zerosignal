/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest'

import {
    type Config,
    type RegistryProvider,
    type ReserveClient,
    type Signer,
    type SpendGuard,
    type Stores,
    type WalletOpener,
    ZsError,
    consoleLogger,
    defaults,
    discardLogger,
    memoryCache,
    memoryJournal,
    memoryStorage,
    resolveConfig,
    testnet,
} from '../src/index.js'
import { TargetBackoffStore } from '../src/routing/backoff.js'
import { defaultFetch as browserDefaultFetch } from '../src/default-fetch.js'

const signer: Signer = {
    address: 'PAYER',
    signBytes: async () => new Uint8Array(),
    signTransactions: async () => [],
}

const base: Config = { signer, network: testnet() }

describe('resolveConfig', () => {
    it('requires a signer with an address', () => {
        expect(() => resolveConfig({} as Config)).toThrow(ZsError)
        expect(() => resolveConfig({ signer: { ...signer, address: '' } })).toThrow(ZsError)
    })

    it('fills every default', () => {
        const c = resolveConfig(base)
        expect(c.privacy).toBe('relay_required')
        expect(c.affinity).toEqual(defaults.affinity)
        expect(c.discovery).toEqual(defaults.discovery)
        expect(c.concurrentSlots).toBe(defaults.concurrentSlots)
        expect(c.reserveTimeout).toBe(defaults.reserveTimeout)
        expect(c.retryBudget).toBe(defaults.retryBudget)
        expect(c.maxOutputCeiling).toBe(defaults.maxOutputCeiling)
        expect(c.logger).toBe(discardLogger)
        expect(c.warnings).toEqual([])
        expect(c.remedies.fund).not.toBe('')
        // The Client builds these, so they stay unset here.
        expect(c.stores).toEqual({})
        expect([c.sweepDelay, c.registry, c.reserveClient, c.wallet]).toEqual([undefined, undefined, undefined, undefined])
        // Each of these widens what the SDK will do when on.
        expect([c.allowPrivacyOverride, c.allowStaging, c.allowPrivateHosts, c.disableTee, c.requireMaxOutput]).toEqual(
            [false, false, false, false, false],
        )
    })

    // The build of #default-fetch outside Node; these tests run the Node one,
    // whose behaviour node-fetch.test.ts covers.
    describe('outside Node', () => {
        it('binds the global fetch, which a browser refuses to call unbound', async () => {
            const f = vi.fn(function (this: unknown) {
                expect(this).toBe(globalThis)
                return Promise.resolve(new Response())
            })
            vi.stubGlobal('fetch', f)
            try {
                await browserDefaultFetch(false)!('http://x.example')
                expect(f).toHaveBeenCalledOnce()
            } finally {
                vi.unstubAllGlobals()
            }
        })

        it('has none in a runtime with no fetch', () => {
            vi.stubGlobal('fetch', undefined)
            try {
                expect(browserDefaultFetch(false)).toBeUndefined()
            } finally {
                vi.unstubAllGlobals()
            }
        })
    })

    it('refuses a runtime with no default fetch unless one is given', async () => {
        vi.resetModules()
        vi.doMock('#default-fetch', () => ({ defaultFetch: () => undefined }))
        try {
            // Fresh modules, so the error class is the one this config throws.
            const [{ resolveConfig: resolve }, { ZsError: Err }] = await Promise.all([
                import('../src/config.js'),
                import('../src/errors.js'),
            ])
            expect(() => resolve(base)).toThrow(Err)
            const mine = vi.fn()
            expect(resolve({ ...base, fetch: mine }).fetch).toBe(mine)
        } finally {
            vi.doUnmock('#default-fetch')
            vi.resetModules()
        }
    })

    it('gives the default cache the injected clock', async () => {
        let t = 0
        const c = resolveConfig({ ...base, clock: () => t })
        await c.cache.fetch(['k'], async () => 'old', { staleTimeMs: 10 })
        t = 10
        expect(await c.cache.fetch(['k'], async () => 'new', { staleTimeMs: 10 })).toBe('new')
    })

    // Every setting a caller gives comes back, each in its own field: a
    // dropped one fails open (requireTeeModels, spendGuard) or is silently
    // ignored, and two cross-wired ones read as plausible values.
    it('returns every value the caller set, each in its own field', () => {
        const spendGuard: SpendGuard = { admit() {}, reserve() {}, settle() {}, release() {} }
        const storage = memoryStorage()
        const cache = memoryCache()
        const logger = consoleLogger()
        const clock = () => 1
        const fetch = vi.fn()
        const discovery = {
            refreshInterval: 1,
            refreshTimeout: 2,
            probeBudget: 3,
            targetTopK: 4,
            maxCacheAge: 5,
            maxCarryAge: 6,
            latencyStateMax: 7,
            detailsTimeout: 8,
            detailsConcurrency: 9,
            operatorIds: [3, 5],
        }
        const remedies = { fund: 'f', raiseSlots: 's', raiseSpendCap: 'c', recoverTicket: 'r' }
        const sweepDelay = () => 16
        const stores: Stores = { journal: memoryJournal(), targetBackoff: new TargetBackoffStore(clock) }
        const registry = {} as RegistryProvider
        const reserveClient = {} as ReserveClient
        const wallet = {} as WalletOpener
        const c = resolveConfig({
            signer,
            network: testnet(),
            privacy: 'direct',
            allowPrivacyOverride: true,
            requireTeeModels: ['m'],
            affinity: { policy: 'none', ttl: 11, max: 12 },
            maxOutputCeiling: 4096,
            maxOutputByModel: { m: 7 },
            requireMaxOutput: true,
            concurrentSlots: 13,
            discovery,
            reserveTimeout: 14,
            retryBudget: 15,
            sweepDelay,
            allowStaging: true,
            allowPrivateHosts: true,
            spendGuard,
            remedies,
            stores,
            registry,
            reserveClient,
            wallet,
            storage,
            cache,
            logger,
            clock,
            fetch,
        })
        expect(c).toMatchObject({
            privacy: 'direct',
            allowPrivacyOverride: true,
            requireTeeModels: ['m'],
            disableTee: false,
            affinity: { policy: 'none', ttl: 11, max: 12 },
            maxOutputCeiling: 4096,
            maxOutputByModel: { m: 7 },
            requireMaxOutput: true,
            concurrentSlots: 13,
            reserveTimeout: 14,
            retryBudget: 15,
            allowStaging: true,
            allowPrivateHosts: true,
            remedies,
        })
        expect(c.discovery).toEqual(discovery)
        expect(c.signer).toBe(signer)
        expect(c.spendGuard).toBe(spendGuard)
        expect([c.storage, c.cache, c.logger, c.clock, c.fetch]).toEqual([storage, cache, logger, clock, fetch])
        expect(c.sweepDelay).toBe(sweepDelay)
        expect(c.registry).toBe(registry)
        expect(c.reserveClient).toBe(reserveClient)
        expect(c.wallet).toBe(wallet)
        expect(c.stores).toEqual(stores)
        expect(c.stores.journal).toBe(stores.journal)
        expect(c.stores.targetBackoff).toBe(stores.targetBackoff)
        // A copy: the Client fills defaults in without touching the caller's.
        expect(c.stores).not.toBe(stores)
        expect(c.network.network).toBe('testnet')
    })

    // Go reads an empty list as no limit; a set but empty one would discover nothing.
    it('reads an empty operatorIds as unset', () => {
        expect(resolveConfig({ ...base, discovery: { operatorIds: [] } }).discovery.operatorIds).toBeUndefined()
    })

    // Go's cmp.Or: an empty remedy is unset, or an error would end with nothing.
    it('fills an empty remedy with the default', () => {
        const d = resolveConfig(base).remedies
        expect(resolveConfig({ ...base, remedies: { fund: '', raiseSlots: '', raiseSpendCap: '', recoverTicket: '' } }).remedies).toEqual(d)
    })

    it('treats a non-positive or non-finite number as unset', () => {
        const c = resolveConfig({
            ...base,
            concurrentSlots: 0,
            reserveTimeout: -1,
            retryBudget: Infinity,
            discovery: { probeBudget: -5, refreshInterval: NaN },
        })
        expect(c.concurrentSlots).toBe(defaults.concurrentSlots)
        expect(c.reserveTimeout).toBe(defaults.reserveTimeout)
        expect(c.retryBudget).toBe(defaults.retryBudget)
        expect(c.discovery.probeBudget).toBe(defaults.discovery.probeBudget)
        expect(c.discovery.refreshInterval).toBe(defaults.discovery.refreshInterval)
    })

    // Go's zero value for these is the empty string, which means the default.
    it('treats an empty privacy or affinity policy as unset', () => {
        const c = resolveConfig({ ...base, privacy: '' as 'direct', affinity: { policy: '' as 'strict' } })
        expect([c.privacy, c.affinity.policy]).toEqual(['relay_required', 'prefer'])
    })

    it('keeps what the caller set', () => {
        const c = resolveConfig({
            ...base,
            privacy: 'direct',
            affinity: { policy: 'strict', ttl: 5 },
            discovery: { operatorIds: [3, 5] },
            remedies: { fund: 'open Settings > Funding' },
        })
        expect(c.privacy).toBe('direct')
        expect(c.affinity).toEqual({ policy: 'strict', ttl: 5, max: defaults.affinity.max })
        expect(c.discovery.operatorIds).toEqual([3, 5])
        expect(c.remedies.fund).toBe('open Settings > Funding')
    })

    it('refuses an unknown privacy or affinity policy', () => {
        expect(() => resolveConfig({ ...base, privacy: 'off' as 'direct' })).toThrow(ZsError)
        expect(() => resolveConfig({ ...base, affinity: { policy: 'sticky' as 'strict' } })).toThrow(ZsError)
    })

    it('warns about settings that work but are probably mistakes', () => {
        expect(resolveConfig({ ...base, maxOutputCeiling: 4096 }).warnings).toHaveLength(1)
        expect(resolveConfig({ ...base, maxOutputCeiling: 4096, requireMaxOutput: true }).warnings).toEqual([])
        expect(resolveConfig({ ...base, disableTee: true, requireTeeModels: ['m'] }).warnings).toHaveLength(1)
        expect(resolveConfig({ ...base, disableTee: true }).warnings).toEqual([])
        expect(resolveConfig({ ...base, requireTeeModels: ['m'] }).warnings).toEqual([])
    })
})
