/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'
import { bytesToHex } from '@noble/hashes/utils.js'

import {
    bodyHashBytes,
    decodeReceiptHeader,
    encodeReceiptHeader,
    receiptCanonicalBytes,
    setBodyHashBytes,
    signReceipt,
    tokensPerSec,
    verifyReceipt,
    type UsageReceipt,
} from '../src/ticket/receipt.js'
import { UsageType } from '../src/ticket/usagetype.js'
import { newFakeSigner } from './helpers.js'

function sampleReceipt(): UsageReceipt {
    return {
        ticket_id: base64.encode(new TextEncoder().encode('sixteen-byte-id!')),
        actual_input_count: 1234,
        actual_output_count: 256,
        amount_charged: 4500,
        ttft_ms: 0,
        decode_ms: 1500,
        body_hash: 'a'.repeat(64),
        input_usage_type: UsageType.Tokens,
        output_usage_type: UsageType.Tokens,
        aux_output_usage_type: UsageType.None,
        aux_output_count: 0,
        cached_input_count: 700,
    }
}

describe('UsageReceipt sign / verify', () => {
    it('round-trips through Sign + Verify', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const r = sampleReceipt()
        await signReceipt(r, signer, address)
        expect(() => verifyReceipt(r, publicKey)).not.toThrow()
    })

    it('Verify fails when amount_charged is mutated after signing', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const r = sampleReceipt()
        await signReceipt(r, signer, address)
        r.amount_charged += 1
        expect(() => verifyReceipt(r, publicKey)).toThrow()
    })

    it('Verify fails when body_hash is mutated after signing', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const r = sampleReceipt()
        await signReceipt(r, signer, address)
        r.body_hash = 'b'.repeat(64)
        expect(() => verifyReceipt(r, publicKey)).toThrow()
    })

    it('Verify fails for a missing signature', () => {
        const { publicKey } = newFakeSigner()
        const r = sampleReceipt()
        expect(() => verifyReceipt(r, publicKey)).toThrow(/signature missing/)
    })
})

describe('UsageReceipt canonicalBytes', () => {
    it('starts with the receipt signing tag', () => {
        const bytes = receiptCanonicalBytes(sampleReceipt())
        const expected = new TextEncoder().encode('zs-receipt-v2\x00')
        expect(bytes.subarray(0, expected.length)).toEqual(expected)
    })

    it('is deterministic for identical structs', () => {
        expect(receiptCanonicalBytes(sampleReceipt())).toEqual(receiptCanonicalBytes(sampleReceipt()))
    })
})

describe('header codec', () => {
    it('round-trips through encode/decode', async () => {
        const { signer, address } = newFakeSigner()
        const r = sampleReceipt()
        await signReceipt(r, signer, address)
        const header = encodeReceiptHeader(r)
        const back = decodeReceiptHeader(header)
        expect(back).toEqual(r)
    })

    it('decode rejects non-base64 input', () => {
        expect(() => decodeReceiptHeader('!!')).toThrow(/decode receipt header base64/)
    })

    it('decode rejects non-json payload', () => {
        const garbage = base64.encode(new TextEncoder().encode('{not'))
        expect(() => decodeReceiptHeader(garbage)).toThrow(/decode receipt header json/)
    })
})

describe('body_hash hex codec', () => {
    it('setBodyHashBytes / bodyHashBytes round-trip', () => {
        const r = sampleReceipt()
        const sum = new Uint8Array(32).fill(0x33)
        setBodyHashBytes(r, sum)
        expect(r.body_hash).toBe(bytesToHex(sum))
        expect(bodyHashBytes(r)).toEqual(sum)
    })

    it('setBodyHashBytes rejects non-32-byte input', () => {
        expect(() => setBodyHashBytes(sampleReceipt(), new Uint8Array(16))).toThrow(/length 16/)
    })

    it('bodyHashBytes rejects wrong-length hex', () => {
        const r = sampleReceipt()
        r.body_hash = 'abcd'
        expect(() => bodyHashBytes(r)).toThrow(/64 hex chars/)
    })
})

describe('receipt timing', () => {
    it('tokensPerSec derives throughput, 0 when no decode window', () => {
        const streamed = { ...sampleReceipt(), actual_output_count: 900, ttft_ms: 120, decode_ms: 3000 }
        expect(tokensPerSec(streamed)).toBe(300) // 900 * 1000 / 3000
        const nonStream = { ...sampleReceipt(), actual_output_count: 900, ttft_ms: 4200, decode_ms: 0 }
        expect(tokensPerSec(nonStream)).toBe(0)
    })
})
