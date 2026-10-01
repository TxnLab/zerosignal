/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import { ed25519 } from '../src/util/ed25519.js'

import {
    decodeAlgorandAddress,
    encodeAlgorandAddress,
    generateAlgorandKeypair,
} from '../src/ticket/signing.js'

describe('Algorand address codec', () => {
    it('encode/decode round-trips a real keypair', () => {
        const kp = generateAlgorandKeypair()
        expect(kp.address.length).toBe(58)
        expect(decodeAlgorandAddress(kp.address)).toEqual(kp.publicKey)
        expect(encodeAlgorandAddress(kp.publicKey)).toBe(kp.address)
    })

    it('encode returns "" for wrong-length pubkey', () => {
        expect(encodeAlgorandAddress(new Uint8Array(16))).toBe('')
    })

    it('decode rejects wrong length', () => {
        expect(() => decodeAlgorandAddress('SHORT')).toThrow(/algorand address length/)
    })

    it('decode rejects checksum mismatch', () => {
        const kp = generateAlgorandKeypair()
        // Tamper an *interior* character, never the last one: the 58th char
        // carries 2 slack bits (36 bytes = 288 bits, 58 × 5 = 290), so flipping
        // it can change only those padding bits — which @scure/base's strict
        // base32nopad decoder rejects with a padding error before checksum logic
        // (and which Go's lenient decoder would decode to the same bytes, leaving
        // the checksum passing), making a last-char tamper a flaky checksum test.
        // An interior char has all 5 of its bits in the output, so flipping it
        // changes the public key and the recomputed checksum no longer matches.
        // Mirrors proto/go/ticket/signing_test.go::TestDecodeAlgorandAddress_ChecksumFailure.
        const chars = kp.address.split('')
        const i = Math.floor(chars.length / 2)
        chars[i] = chars[i] === 'A' ? 'B' : 'A'
        const broken = chars.join('')
        expect(() => decodeAlgorandAddress(broken)).toThrow(/checksum mismatch/)
    })

    it('decoded pubkey is independent from the original (defensive copy)', () => {
        const kp = generateAlgorandKeypair()
        const decoded = decodeAlgorandAddress(kp.address)
        decoded[0] = (decoded[0]! ^ 0xff) & 0xff
        // Original buffer should not have been mutated.
        expect(kp.publicKey[0]).not.toBe(decoded[0])
    })

    it('a freshly-generated address verifies a signature it produced', () => {
        const kp = generateAlgorandKeypair()
        const msg = new TextEncoder().encode('hello-algorand')
        const sig = ed25519.sign(msg, kp.privateKey)
        const recovered = decodeAlgorandAddress(kp.address)
        expect(ed25519.verify(sig, msg, recovered)).toBe(true)
    })
})
