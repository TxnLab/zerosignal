/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The rules of proto/go/zs Config.validate's network half. The presets
// themselves are pinned in vocabulary.test.ts.

import { describe, expect, it } from 'vitest'

import { ZsError, localnet, mainnet, resolveNetwork, testnet } from '../src/index.js'

function configErr(fn: () => unknown): ZsError {
    try {
        fn()
    } catch (err) {
        expect(err).toBeInstanceOf(ZsError)
        const z = err as ZsError
        expect([z.kind, z.code]).toEqual(['invalid_request', 'invalid_config'])
        return z
    }
    throw new Error('did not throw')
}

describe('resolveNetwork', () => {
    it('is mainnet only when wholly unset', () => {
        expect(resolveNetwork().network).toBe('mainnet')
        expect(resolveNetwork({}).escrowAppId).toBe(resolveNetwork(mainnet()).escrowAppId)
    })

    it('refuses a token or an app id that names no chain', () => {
        configErr(() => resolveNetwork({ algodToken: 't' }))
        configErr(() => resolveNetwork({ escrowAppId: 5n }))
    })

    it('needs an app id where none is embedded', () => {
        configErr(() => resolveNetwork(localnet()))
        configErr(() => resolveNetwork({ algodEndpoint: 'http://algod.example' }))
        const n = resolveNetwork({ algodEndpoint: 'http://algod.example/', escrowAppId: 9n })
        expect(n).toMatchObject({ network: '', algodEndpoint: 'http://algod.example', escrowAppId: 9n, feeSink: '' })
        expect(n.warnings).toEqual([])
    })

    it('takes the name case-insensitively and refuses an unknown one', () => {
        expect(resolveNetwork({ network: 'TestNet' as 'testnet' }).network).toBe('testnet')
        configErr(() => resolveNetwork({ network: 'betanet' as 'testnet' }))
    })

    // Go lowercases without trimming, so these are unknown names there. A
    // blank one read as unset would pay on mainnet.
    it('refuses a name with surrounding or only spaces', () => {
        configErr(() => resolveNetwork({ network: ' testnet' as 'testnet' }))
        configErr(() => resolveNetwork({ network: '   ' as 'testnet' }))
    })

    it('refuses an inherited property name as a network', () => {
        configErr(() => resolveNetwork({ network: 'constructor' as 'testnet', escrowAppId: 1n }))
        configErr(() => resolveNetwork({ network: '__proto__' as 'testnet', escrowAppId: 1n }))
    })

    // Go's zero values: an explicit 0n or '' is unset, not a value.
    it('reads a zero app id or empty token as unset', () => {
        expect(resolveNetwork({ escrowAppId: 0n, algodToken: '' }).network).toBe('mainnet')
        expect(resolveNetwork({ ...testnet(), escrowAppId: 0n }).escrowAppId).toBe(765860477n)
        expect(resolveNetwork({ ...localnet(), escrowAppId: 1n, algodToken: '' }).algodToken).toBe('a'.repeat(64))
    })

    it('reads an empty endpoint as unset, and trims every trailing slash', () => {
        expect(resolveNetwork({ algodEndpoint: '' }).network).toBe('mainnet')
        expect(resolveNetwork({ algodEndpoint: 'http://a.example//', escrowAppId: 9n }).algodEndpoint).toBe(
            'http://a.example',
        )
    })

    // The fee sink is the chain's, not the endpoint's: Go keys it on the
    // resolved network, so a custom algod for testnet still simulates from it.
    it("keeps the preset's fee sink behind an overriding endpoint", () => {
        expect(resolveNetwork({ ...testnet(), algodEndpoint: 'https://x.example' }).feeSink).toBe(
            resolveNetwork(testnet()).feeSink,
        )
        expect(resolveNetwork(testnet()).feeSink).not.toBe('')
    })

    it('takes the largest uint64 app id', () => {
        const max = (1n << 64n) - 1n
        expect(resolveNetwork({ ...testnet(), escrowAppId: max }).escrowAppId).toBe(max)
    })

    it('refuses an app id that is not a uint64 bigint', () => {
        configErr(() => resolveNetwork({ ...testnet(), escrowAppId: -5n }))
        configErr(() => resolveNetwork({ ...testnet(), escrowAppId: 1n << 64n }))
        configErr(() => resolveNetwork({ ...testnet(), escrowAppId: 0 as unknown as bigint }))
    })

    it("warns when an endpoint overrides a preset but keeps the preset's app id", () => {
        const n = resolveNetwork({ ...testnet(), algodEndpoint: 'https://my-algod.example' })
        expect(n.algodEndpoint).toBe('https://my-algod.example')
        expect(n.escrowAppId).toBe(resolveNetwork(testnet()).escrowAppId)
        expect(n.warnings).toHaveLength(1)
        expect(resolveNetwork({ ...testnet(), algodEndpoint: 'https://x', escrowAppId: 7n }).warnings).toEqual([])
    })

    it('keeps an explicit app id and token over the preset', () => {
        const n = resolveNetwork({ ...testnet(), escrowAppId: 42n, algodToken: 'tok' })
        expect([n.escrowAppId, n.algodToken]).toEqual([42n, 'tok'])
    })
})
