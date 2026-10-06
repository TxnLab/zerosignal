/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { describe, expect, it, vi } from 'vitest'

// Its own file: the BIP-39 seed is captured by mocking @scure/bip39 for every
// test here.
const seeds: Uint8Array[] = []
vi.mock('@scure/bip39', async (importOriginal) => {
    const real = await importOriginal<typeof import('@scure/bip39')>()
    return {
        ...real,
        mnemonicToSeedSync: (...args: Parameters<typeof real.mnemonicToSeedSync>) => {
            const seed = real.mnemonicToSeedSync(...args)
            seeds.push(seed)
            return seed
        },
    }
})

const { xhdRootFromPhrase } = await import('../src/accounts/xhd.js')

const { cases } = JSON.parse(readFileSync(new URL('../../testdata/account_vectors.json', import.meta.url), 'utf8')) as {
    cases: { phrase: string; kind?: string; address?: string }[]
}

describe('xhdRootFromPhrase', () => {
    // The seed derives the whole tree; once the root key exists it is wiped,
    // and only after use (the address still matches Go's).
    it('zeroes the BIP-39 seed once the root key is derived', async () => {
        const c = cases.find((x) => x.kind === 'xhd-24')!
        const root = await xhdRootFromPhrase(c.phrase)
        expect(root.address).toBe(c.address)
        expect(seeds).toHaveLength(1)
        expect(seeds[0]).toHaveLength(64)
        expect(seeds[0]!.every((b) => b === 0)).toBe(true)
    })
})
