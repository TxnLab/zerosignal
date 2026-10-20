/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { hex } from '@scure/base'
import { entropyToMnemonic } from '@scure/bip39'
import { wordlist } from '@scure/bip39/wordlists/english.js'
import { describe, expect, it } from 'vitest'

import { SOLANA_PATH, slip10Ed25519, solanaKeyFromEntropy, solanaKeyFromPhrase, solanaSigner } from '../src/accounts/solana.js'
import { SignerAddressError } from '../src/ports.js'
import { ZsError } from '../src/index.js'

interface Slip10Case {
    seed: string
    path: number[] | null
    chain_code: string
    private: string
}

interface SolanaCase {
    name: string
    phrase: string
    refused: boolean
    seed?: string
    address?: string
    signatures?: { msg: string; sig: string }[]
}

const { slip10, solana } = JSON.parse(readFileSync(new URL('../../testdata/account_vectors.json', import.meta.url), 'utf8')) as {
    slip10: Slip10Case[]
    solana: SolanaCase[]
}

describe('slip10Ed25519, against SLIP-0010', () => {
    it.each(slip10.map((c) => [`${c.seed.slice(0, 8)} m/${(c.path ?? []).join("'/")}`, c] as const))('%s', (_, c) => {
        const { key, chainCode } = slip10Ed25519(hex.decode(c.seed), c.path ?? [])
        expect(hex.encode(key)).toBe(c.private)
        expect(hex.encode(chainCode)).toBe(c.chain_code)
    })
})

describe('solanaKeyFromPhrase, as Go loads a phrase', () => {
    const loaded = solana.filter((c) => !c.refused)
    const refused = solana.filter((c) => c.refused)

    it('has vectors of both outcomes, solana-keygen among them', () => {
        expect(loaded.length).toBeGreaterThanOrEqual(4)
        expect(refused.length).toBeGreaterThanOrEqual(6)
        expect(loaded.filter((c) => c.name.startsWith('solana-keygen')).length).toBe(2)
    })

    it.each(loaded.map((c) => [c.name, c] as const))('%s', async (_, c) => {
        const k = solanaKeyFromPhrase(c.phrase)
        expect(hex.encode(k.seed)).toBe(c.seed)
        expect(k.address).toBe(c.address)
        const signer = solanaSigner(k)
        expect(signer.address).toBe(c.address)
        for (const { msg, sig } of c.signatures!) {
            expect(hex.encode(await signer.signBytes(c.address!, hex.decode(msg)))).toBe(sig)
        }
    })

    it.each(refused.map((c) => [c.name, c] as const))('%s is refused without quoting it', (_, c) => {
        let err: unknown
        try {
            solanaKeyFromPhrase(c.phrase)
        } catch (e) {
            err = e
        }
        expect(err).toBeInstanceOf(ZsError)
        const first = c.phrase.split(/\s+/).find((w) => w !== '')
        if (first) expect(String((err as Error).message)).not.toContain(first)
    })

    it('derives from entropy the account of its 24-word phrase', () => {
        const entropy = new Uint8Array(32).map((_, i) => i + 1)
        expect(solanaKeyFromEntropy(entropy).address).toBe(solanaKeyFromPhrase(entropyToMnemonic(entropy, wordlist)).address)
        expect(() => solanaKeyFromEntropy(new Uint8Array(16))).toThrow(ZsError)
    })
})

describe('solanaSigner', () => {
    const c = solana.find((v) => v.name === 'solana-keygen 12 words')!

    it('refuses another address, and outlives a wiped key', async () => {
        const k = solanaKeyFromPhrase(c.phrase)
        const signer = solanaSigner(k)
        await expect(signer.signBytes(solana.find((v) => v.name === 'client vector')!.address!, new Uint8Array(32))).rejects.toThrow(SignerAddressError)
        k.seed.fill(0)
        const { msg, sig } = c.signatures![0]!
        expect(hex.encode(await signer.signBytes(c.address!, hex.decode(msg)))).toBe(sig)
    })

    it("refuses a key whose address isn't its seed's", () => {
        const k = solanaKeyFromPhrase(c.phrase)
        const other = solana.find((v) => v.name === 'client vector')!.address!
        expect(() => solanaSigner({ ...k, address: other })).toThrow(ZsError)
    })
})

describe('slip10Ed25519 indices', () => {
    it('refuses an index that is not a uint32', () => {
        for (const bad of [-1, 2 ** 32, 1.5, Number.NaN]) {
            expect(() => slip10Ed25519(new Uint8Array(16), [bad])).toThrow(ZsError)
        }
    })

    it('keeps the Solana path fixed', () => {
        expect(Object.isFrozen(SOLANA_PATH)).toBe(true)
    })
})
