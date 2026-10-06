/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { base64, hex } from '@scure/base'
import { decodeUnsignedTransaction } from 'algosdk'
import { describe, expect, it } from 'vitest'

import { xhdRootFromEntropy, xhdRootFromPhrase, xhdSigner } from '../src/accounts/xhd.js'
import { SignerAddressError, ZsError } from '../src/index.js'

interface Case {
    name: string
    phrase: string
    entropy?: string
    refused: boolean
    address?: string
    kind?: string
    signatures?: { msg: string; sig: string }[]
    txn?: { txn: string; signed: string; txid: string }
}

const { cases } = JSON.parse(readFileSync(new URL('../../testdata/account_vectors.json', import.meta.url), 'utf8')) as {
    cases: Case[]
}
const xhd24 = cases.filter((c) => c.kind === 'xhd-24')
const notXhd = cases.filter((c) => c.kind !== 'xhd-24')

describe('xhdRootFromPhrase, as Go loads a phrase', () => {
    it('has vectors of every outcome', () => {
        expect(xhd24.length).toBeGreaterThanOrEqual(6)
        expect(xhd24.some((c) => c.entropy)).toBe(true)
        expect(cases.some((c) => c.refused && c.name.startsWith('xhd-24'))).toBe(true)
    })

    it.each(xhd24.map((c) => [c.name, c] as const))('%s', async (_, c) => {
        const root = await xhdRootFromPhrase(c.phrase)
        expect(root.address).toBe(c.address)
        const s = xhdSigner(root)
        for (const { msg, sig } of c.signatures!) {
            expect(hex.encode(await s.signBytes(s.address, hex.decode(msg)))).toBe(sig)
        }
        const txn = decodeUnsignedTransaction(base64.decode(c.txn!.txn))
        expect(txn.txID()).toBe(c.txn!.txid)
        const [signed] = await s.signTransactions([txn], [0])
        expect(base64.encode(signed!)).toBe(c.txn!.signed)
    })

    it.each(notXhd.map((c) => [c.name, c] as const))('%s is not loaded', async (_, c) => {
        await expect(xhdRootFromPhrase(c.phrase)).rejects.toBeInstanceOf(ZsError)
    })

    it('points a 25-word phrase at the mnemonic subpath', async () => {
        const algo = cases.find((c) => c.kind === 'algorand-25')!
        await expect(xhdRootFromPhrase(algo.phrase)).rejects.toThrow('accounts/mnemonic')
    })

    it('quotes no word of a refused phrase', async () => {
        const bad = cases.find((c) => c.name === 'xhd-24 bad checksum')!
        await expect(xhdRootFromPhrase(bad.phrase)).rejects.toThrow(
            /^xhd: invalid 24-word BIP-39 phrase \(bad word or checksum\)$/,
        )
    })
})

describe('xhdRootFromEntropy', () => {
    // The entropy is the phrase: the same bytes load the same account either way.
    it.each(xhd24.filter((c) => c.entropy).map((c) => [c.name, c] as const))('%s', async (_, c) => {
        const root = await xhdRootFromEntropy(hex.decode(c.entropy!))
        expect(root.address).toBe(c.address)
        expect(root.publicKey).toHaveLength(32)
        const s = xhdSigner(root)
        for (const { msg, sig } of c.signatures!) {
            expect(hex.encode(await s.signBytes(s.address, hex.decode(msg)))).toBe(sig)
        }
    })

    it.each([16, 31, 33])('refuses %i bytes', async (n) => {
        await expect(xhdRootFromEntropy(new Uint8Array(n))).rejects.toBeInstanceOf(ZsError)
    })
})

describe('xhdSigner', () => {
    it('refuses to sign for another address', async () => {
        const [a, b] = xhd24
        const s = xhdSigner(await xhdRootFromPhrase(a!.phrase))
        await expect(s.signBytes(b!.address!, new Uint8Array(32))).rejects.toBeInstanceOf(SignerAddressError)
    })

    // A digest that starts with an Algorand domain tag ("TX", "MX", ...) is
    // still signed verbatim, as Go's key does; the library's signData would
    // refuse it.
    it('signs a message that begins with a domain tag', async () => {
        const s = xhdSigner(await xhdRootFromPhrase(xhd24[0]!.phrase))
        expect(await s.signBytes(s.address, new TextEncoder().encode('MX looks tagged'))).toHaveLength(64)
    })

    // Under Node the library returns a view into Buffer's shared pool, next to
    // copies of the key; a signature handed out must own just its 64 bytes.
    it('returns a signature that owns its memory', async () => {
        const s = xhdSigner(await xhdRootFromPhrase(xhd24[0]!.phrase))
        const sig = await s.signBytes(s.address, new Uint8Array(32))
        expect(sig.buffer.byteLength).toBe(64)
        expect(sig.byteOffset).toBe(0)
    })

    it('keeps signing after the caller wipes the root it was built from', async () => {
        const c = xhd24[0]!
        const root = await xhdRootFromPhrase(c.phrase)
        const s = xhdSigner(root)
        root.rootKey.fill(0)
        const { msg, sig } = c.signatures![0]!
        expect(hex.encode(await s.signBytes(s.address, hex.decode(msg)))).toBe(sig)
    })
})
