/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest'

import { type Signer, SignerAddressError, memoryCache, memoryStorage, payerBytesSigner } from '../src/index.js'

const PAYER = 'PAYER'

function stubSigner(): Signer & { signed: string[]; msgs: Uint8Array[] } {
    const signed: string[] = []
    const msgs: Uint8Array[] = []
    return {
        address: PAYER,
        signed,
        msgs,
        signBytes: async (address, msg) => {
            signed.push(address)
            msgs.push(msg)
            return new Uint8Array([1])
        },
        signTransactions: async () => [],
    }
}

describe('payerBytesSigner', () => {
    // Verbatim: a prefix (go-algorand-sdk's "MX") would sign another message.
    it("signs the bytes it is given, verbatim, for the signer's own address", async () => {
        const s = stubSigner()
        const digest = new Uint8Array(32).fill(7)
        await expect(payerBytesSigner(s).signBytes(PAYER, digest)).resolves.toEqual(new Uint8Array([1]))
        expect(s.signed).toEqual([PAYER])
        expect(s.msgs).toEqual([digest])
        expect(s.msgs[0]).toBe(digest)
    })

    it('refuses any other address without reaching the signer', async () => {
        const s = stubSigner()
        await expect(payerBytesSigner(s).signBytes('OTHER', new Uint8Array(32))).rejects.toMatchObject({
            constructor: SignerAddressError,
            want: PAYER,
            got: 'OTHER',
        })
        expect(s.signed).toEqual([])
    })
})

describe('memoryCache', () => {
    function clock() {
        let now = 1_000
        return { now: () => now, advance: (ms: number) => (now += ms) }
    }

    it('serves a fresh value and refetches a stale one', async () => {
        const c = clock()
        const cache = memoryCache(c.now)
        const load = vi.fn().mockResolvedValueOnce('a').mockResolvedValueOnce('b')
        expect(await cache.fetch(['k'], load, { staleTimeMs: 100 })).toBe('a')
        c.advance(99)
        expect(await cache.fetch(['k'], load, { staleTimeMs: 100 })).toBe('a')
        c.advance(1)
        expect(await cache.fetch(['k'], load, { staleTimeMs: 100 })).toBe('b')
        expect(load).toHaveBeenCalledTimes(2)
    })

    // Fresh from when the value arrived, not from when the load started, or a
    // load slower than staleTimeMs is stale on arrival and every caller reloads.
    it('dates a value from when its load finished', async () => {
        const c = clock()
        const cache = memoryCache(c.now)
        const load = vi.fn(async () => {
            c.advance(150)
            return 'v'
        })
        await cache.fetch(['k'], load, { staleTimeMs: 100 })
        expect(await cache.fetch(['k'], load, { staleTimeMs: 100 })).toBe('v')
        expect(load).toHaveBeenCalledOnce()
    })

    it('shares one load between concurrent callers', async () => {
        const cache = memoryCache()
        let resolve!: (v: string) => void
        const load = vi.fn(() => new Promise<string>((r) => (resolve = r)))
        const a = cache.fetch(['k'], load, { staleTimeMs: 1000 })
        const b = cache.fetch(['k'], load, { staleTimeMs: 1000 })
        resolve('v')
        expect(await Promise.all([a, b])).toEqual(['v', 'v'])
        expect(load).toHaveBeenCalledTimes(1)
    })

    it('caches nothing from a load that throws', async () => {
        const cache = memoryCache()
        const load = vi.fn().mockRejectedValueOnce(new Error('down')).mockResolvedValueOnce('ok')
        await expect(cache.fetch(['k'], load, { staleTimeMs: 1000 })).rejects.toThrow('down')
        expect(cache.peek(['k'])).toBeUndefined()
        expect(await cache.fetch(['k'], load, { staleTimeMs: 1000 })).toBe('ok')
    })

    it('caches nothing from a load that throws before returning a promise', async () => {
        const cache = memoryCache()
        const opts = { staleTimeMs: 1000 }
        await expect(
            cache.fetch(
                ['k'],
                () => {
                    throw new Error('sync')
                },
                opts,
            ),
        ).rejects.toThrow('sync')
        expect(await cache.fetch(['k'], async () => 'ok', opts)).toBe('ok')
    })

    it('takes bigint keys and tells undefined from null', async () => {
        const cache = memoryCache()
        const opts = { staleTimeMs: 1000 }
        await cache.fetch(['app', 765860477n], async () => 'big', opts)
        await cache.fetch(['app', '765860477'], async () => 'str', opts)
        await cache.fetch([undefined], async () => 'u', opts)
        await cache.fetch([null], async () => 'n', opts)
        expect(cache.peek(['app', 765860477n])).toBe('big')
        expect(cache.peek(['app', '765860477'])).toBe('str')
        expect(cache.peek([undefined])).toBe('u')
        expect(cache.peek([null])).toBe('n')
    })

    it('peeks a value of any age', async () => {
        const c = clock()
        const cache = memoryCache(c.now)
        await cache.fetch(['k'], async () => 'v', { staleTimeMs: 1 })
        c.advance(10_000)
        expect(cache.peek(['k'])).toBe('v')
    })

    it('invalidates by prefix and nothing else', async () => {
        const cache = memoryCache()
        const opts = { staleTimeMs: 1000 }
        await cache.fetch(['details', 'a'], async () => 1, opts)
        await cache.fetch(['details', 'b'], async () => 2, opts)
        await cache.fetch(['detailsX'], async () => 3, opts)
        await cache.fetch(['other'], async () => 4, opts)
        cache.invalidate(['details'])
        expect(cache.peek(['details', 'a'])).toBeUndefined()
        expect(cache.peek(['details', 'b'])).toBeUndefined()
        expect(cache.peek(['detailsX'])).toBe(3)
        expect(cache.peek(['other'])).toBe(4)
    })

    it('does not cache a load that an invalidate overtook', async () => {
        const cache = memoryCache()
        let resolveOld!: (v: string) => void
        const old = cache.fetch(['k'], () => new Promise<string>((r) => (resolveOld = r)), { staleTimeMs: 1000 })
        cache.invalidate(['k'])
        // A fetch after the invalidate starts its own load rather than joining
        // the one that predates it.
        const fresh = cache.fetch(['k'], async () => 'new', { staleTimeMs: 1000 })
        expect(await fresh).toBe('new')
        resolveOld('old')
        expect(await old).toBe('old')
        expect(cache.peek(['k'])).toBe('new')
    })

    // The overtaken load finishing first must not clear the newer load's
    // in-flight entry, or that value is never cached and every caller after
    // starts its own load.
    it('keeps the newer load in flight when an overtaken one finishes first', async () => {
        const cache = memoryCache()
        const opts = { staleTimeMs: 1000 }
        let resolveOld!: (v: string) => void
        let resolveNew!: (v: string) => void
        const load = vi
            .fn<() => Promise<string>>()
            .mockImplementationOnce(() => new Promise((r) => (resolveOld = r)))
            .mockImplementationOnce(() => new Promise((r) => (resolveNew = r)))
            .mockImplementation(async () => 'third')
        const old = cache.fetch(['k'], load, opts)
        cache.invalidate(['k'])
        const fresh = cache.fetch(['k'], load, opts)
        resolveOld('old')
        await old
        const joined = cache.fetch(['k'], load, opts)
        resolveNew('new')
        expect(await Promise.all([fresh, joined])).toEqual(['new', 'new'])
        expect(load).toHaveBeenCalledTimes(2)
        expect(cache.peek(['k'])).toBe('new')
    })
})

describe('memoryStorage', () => {
    it('round-trips and deletes', async () => {
        const s = memoryStorage()
        expect(await s.get('k')).toBeUndefined()
        await s.set('k', 'v')
        expect(await s.get('k')).toBe('v')
        await s.delete('k')
        expect(await s.get('k')).toBeUndefined()
    })
})
