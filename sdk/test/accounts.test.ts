/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { base64, hex } from '@scure/base'
import { decodeUnsignedTransaction, generateAccount } from 'algosdk'
import { describe, expect, it } from 'vitest'

import { algosdkSigner } from '../src/accounts/algosdk.js'
import { mnemonicSigner, phraseWords } from '../src/accounts/mnemonic.js'
import { SignerAddressError, ZsError } from '../src/index.js'

interface Case {
    name: string
    phrase: string
    refused: boolean
    address?: string
    kind?: string
    signatures?: { msg: string; sig: string }[]
    txn?: { txn: string; signed: string; txid: string }
}

const { cases } = JSON.parse(readFileSync(new URL('../../testdata/account_vectors.json', import.meta.url), 'utf8')) as {
    cases: Case[]
}
const algo25 = cases.filter((c) => c.kind === 'algorand-25')
const notAlgo25 = cases.filter((c) => c.kind !== 'algorand-25')

describe('mnemonicSigner, as Go loads a phrase', () => {
    it('has vectors of every outcome', () => {
        expect(algo25.length).toBeGreaterThanOrEqual(6)
        expect(cases.some((c) => c.refused)).toBe(true)
        expect(cases.some((c) => c.kind === 'xhd-24')).toBe(true)
    })

    it.each(algo25.map((c) => [c.name, c] as const))('%s', async (_, c) => {
        const s = mnemonicSigner(c.phrase)
        expect(s.address).toBe(c.address)
        for (const { msg, sig } of c.signatures!) {
            expect(hex.encode(await s.signBytes(s.address, hex.decode(msg)))).toBe(sig)
        }
        const txn = decodeUnsignedTransaction(base64.decode(c.txn!.txn))
        expect(txn.txID()).toBe(c.txn!.txid)
        const [signed] = await s.signTransactions([txn], [0])
        expect(base64.encode(signed!)).toBe(c.txn!.signed)
    })

    // Go refuses these, or loads them as xHD accounts, which this subpath
    // doesn't: neither may come back as some 25-word account.
    it.each(notAlgo25.map((c) => [c.name, c] as const))('%s is not loaded', (_, c) => {
        expect(() => mnemonicSigner(c.phrase)).toThrow(ZsError)
    })

    it('points a 24-word phrase at the xHD subpath', () => {
        const xhd = cases.find((c) => c.kind === 'xhd-24')!
        expect(() => mnemonicSigner(xhd.phrase)).toThrow('accounts/xhd')
    })

    // The phrase is a secret: an error that quoted a mistyped word would put
    // part of it in a log.
    it('quotes no word of a refused phrase', () => {
        const bad = cases.find((c) => c.name === 'algorand-25 unknown word')!
        const err = (() => {
            try {
                mnemonicSigner(bad.phrase)
            } catch (e) {
                return e as Error
            }
        })()
        expect(err?.message).toBe('mnemonic: invalid 25-word Algorand mnemonic (bad word or checksum)')
    })
})

describe('phraseWords', () => {
    // Go's unicode.IsSpace, not JS's \s.
    it('splits on NEL and keeps a byte-order mark', () => {
        const bom = String.fromCharCode(0xfeff)
        expect(phraseWords('a\x85b\xa0c')).toEqual(['a', 'b', 'c'])
        expect(phraseWords(`${bom}a b`)).toEqual([`${bom}a`, 'b'])
    })

    it('splits on the Unicode space separators Go does', () => {
        const seps = [0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1680, 0x2000, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000].map((c) =>
            String.fromCharCode(c),
        )
        for (const sep of seps) expect(phraseWords(`a${sep}b`)).toEqual(['a', 'b'])
        // A zero-width space, just past the U+2000-U+200A range, is not one.
        expect(phraseWords(`a${String.fromCharCode(0x200b)}b`)).toHaveLength(1)
    })
})

describe('algosdkSigner', () => {
    it('signs as its own account and refuses any other', async () => {
        const a = generateAccount()
        const s = algosdkSigner(a)
        expect(s.address).toBe(a.addr.toString())
        const other = generateAccount().addr.toString()
        await expect(s.signBytes(other, new Uint8Array(32))).rejects.toBeInstanceOf(SignerAddressError)
        expect(await s.signBytes(s.address, new Uint8Array(32))).toHaveLength(64)
    })
})
