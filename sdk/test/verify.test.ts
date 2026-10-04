/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { createHash, generateKeyPairSync, sign } from 'node:crypto'
import { describe, expect, it } from 'vitest'

import { type BytesSigner, type Ticket, type UsageReceipt, signReceipt, signTicket } from '@txnlab/zs-proto/ticket'

import {
    CommitKMismatchError,
    ReceiptError,
    TicketSignatureInvalidError,
    parseReceiptJSON,
    verifyCommitK,
    verifyReceipt,
    verifyTicketSignature,
} from '../src/index.js'

function keypair(): { pub: Uint8Array; signer: BytesSigner } {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519')
    const jwk = publicKey.export({ format: 'jwk' })
    return {
        pub: new Uint8Array(Buffer.from(jwk.x!, 'base64url')),
        signer: { signBytes: async (_addr, msg) => new Uint8Array(sign(null, msg, privateKey)) },
    }
}

const sha256 = (b: Uint8Array) => new Uint8Array(createHash('sha256').update(b).digest())
const b64 = (b: Uint8Array) => Buffer.from(b).toString('base64')
const hello = new TextEncoder().encode('hello world')
const key = new Uint8Array(32).map((_, i) => (i * 13 + 5) & 0xff)

const TICKET: Ticket = {
    ticket_id: 'c2l4dGVlbi1ieXRlLWlkIQ==',
    operator_id: 42,
    node_id: 7,
    input_count: 100,
    max_output_count: 100,
    input_rate: 1,
    output_rate: 1,
    cache_read_rate: 1,
    max_price: 5000,
    min_price: 100,
    expires_at: 1_700_000_000,
    model: 'm',
    stream: true,
    commit_k: b64(sha256(key)),
    input_usage_type: 1,
    output_usage_type: 1,
}

const RECEIPT: UsageReceipt = {
    ticket_id: TICKET.ticket_id,
    actual_input_count: 42,
    actual_output_count: 17,
    amount_charged: 2600,
    ttft_ms: 0,
    decode_ms: 0,
    body_hash: Buffer.from(sha256(hello)).toString('hex'),
    input_usage_type: 1,
    output_usage_type: 1,
    aux_output_usage_type: 0,
    aux_output_count: 0,
    cached_input_count: 0,
}

async function signed<T extends Ticket | UsageReceipt>(base: T, kind: 'ticket' | 'receipt') {
    const k = keypair()
    const v = { ...base }
    if (kind === 'ticket') await signTicket(v as Ticket, k.signer, 'ADDR')
    else await signReceipt(v as UsageReceipt, k.signer, 'ADDR')
    return { v, pub: k.pub }
}

function flipSig<T extends { sig?: string }>(v: T): T {
    const b = Buffer.from(v.sig!, 'base64')
    b[0]! ^= 1
    return { ...v, sig: b.toString('base64') }
}

function violation(f: () => void): string | undefined {
    try {
        f()
    } catch (err) {
        expect(err).toBeInstanceOf(ReceiptError)
        return (err as ReceiptError).violation
    }
    return undefined
}

describe('verifyTicketSignature', () => {
    it('accepts the signing node and nothing else', async () => {
        const { v, pub } = await signed(TICKET, 'ticket')
        expect(() => verifyTicketSignature(v, pub)).not.toThrow()
        expect(() => verifyTicketSignature(flipSig(v), pub)).toThrow(TicketSignatureInvalidError)
        expect(() => verifyTicketSignature({ ...v, max_price: 5001 }, pub)).toThrow(TicketSignatureInvalidError)
        expect(() => verifyTicketSignature(v, keypair().pub)).toThrow(TicketSignatureInvalidError)
        expect(() => verifyTicketSignature(v, pub.slice(1))).toThrow(TicketSignatureInvalidError)
        expect(() => verifyTicketSignature({ ...v, sig: b64(new Uint8Array(63)) }, pub)).toThrow(
            TicketSignatureInvalidError,
        )
    })
})

describe('verifyCommitK', () => {
    it('accepts the committed key', () => {
        expect(() => verifyCommitK(TICKET, key)).not.toThrow()
    })

    it('refuses another key, a short key, a short commitment, and a non-canonical spelling', () => {
        expect(() => verifyCommitK(TICKET, key.map((x) => x ^ 1))).toThrow(CommitKMismatchError)
        expect(() => verifyCommitK(TICKET, key.slice(1))).toThrow(CommitKMismatchError)
        expect(() => verifyCommitK({ ...TICKET, commit_k: b64(new Uint8Array(31)) }, key)).toThrow(CommitKMismatchError)
        // Go compares the encoded string, so the same bytes unpadded fail.
        expect(() => verifyCommitK({ ...TICKET, commit_k: TICKET.commit_k.replace(/=+$/, '') }, key)).toThrow(
            CommitKMismatchError,
        )
    })
})

describe('verifyReceipt', () => {
    it('accepts a receipt that passes every check', async () => {
        const { v, pub } = await signed(RECEIPT, 'receipt')
        expect(violation(() => verifyReceipt(v, TICKET, pub, sha256(hello)))).toBeUndefined()
    })

    it('classifies a bad signature, a key of the wrong length, or another key as sig', async () => {
        const { v, pub } = await signed(RECEIPT, 'receipt')
        expect(violation(() => verifyReceipt(flipSig(v), TICKET, pub, sha256(hello)))).toBe('sig')
        expect(violation(() => verifyReceipt({ ...v, amount_charged: 2601 }, TICKET, pub, sha256(hello)))).toBe('sig')
        expect(violation(() => verifyReceipt(v, TICKET, pub.slice(1), sha256(hello)))).toBe('sig')
        expect(violation(() => verifyReceipt(v, TICKET, keypair().pub, sha256(hello)))).toBe('sig')
    })

    it('classifies a charge over max_price as amount, and accepts exactly max_price', async () => {
        const over = await signed({ ...RECEIPT, amount_charged: 5001 }, 'receipt')
        expect(violation(() => verifyReceipt(over.v, TICKET, over.pub, sha256(hello)))).toBe('amount')
        const at = await signed({ ...RECEIPT, amount_charged: 5000 }, 'receipt')
        expect(violation(() => verifyReceipt(at.v, TICKET, at.pub, sha256(hello)))).toBeUndefined()
    })

    // SPEC §3a: the floor is the node's to apply; a lower charge costs only it.
    it('accepts a charge below min_price on non-zero usage', async () => {
        const { v, pub } = await signed({ ...RECEIPT, amount_charged: 50 }, 'receipt')
        expect(violation(() => verifyReceipt(v, TICKET, pub, sha256(hello)))).toBeUndefined()
    })

    it('classifies more cached input than input as amount, and accepts equal', async () => {
        const over = await signed({ ...RECEIPT, cached_input_count: 43 }, 'receipt')
        expect(violation(() => verifyReceipt(over.v, TICKET, over.pub, sha256(hello)))).toBe('amount')
        const eq = await signed({ ...RECEIPT, cached_input_count: 42 }, 'receipt')
        expect(violation(() => verifyReceipt(eq.v, TICKET, eq.pub, sha256(hello)))).toBeUndefined()
    })

    it('classifies a body mismatch, a malformed hash, or a computed hash of the wrong length as body_hash', async () => {
        const { v, pub } = await signed(RECEIPT, 'receipt')
        expect(violation(() => verifyReceipt(v, TICKET, pub, sha256(new Uint8Array(1))))).toBe('body_hash')
        expect(violation(() => verifyReceipt(v, TICKET, pub, sha256(hello).slice(1)))).toBe('body_hash')
        // A prefix match must not pass: the first 32 bytes are right.
        const long = new Uint8Array([...sha256(hello), 0])
        expect(violation(() => verifyReceipt(v, TICKET, pub, long))).toBe('body_hash')
        const bad = await signed({ ...RECEIPT, body_hash: 'not-hex!' }, 'receipt')
        expect(violation(() => verifyReceipt(bad.v, TICKET, bad.pub, sha256(hello)))).toBe('body_hash')
        const nonHex = await signed({ ...RECEIPT, body_hash: 'zz'.repeat(32) }, 'receipt')
        expect(violation(() => verifyReceipt(nonHex.v, TICKET, nonHex.pub, sha256(hello)))).toBe('body_hash')
    })

    it('classifies an unsigned receipt as sig, keeping the cause', async () => {
        const { v, pub } = await signed(RECEIPT, 'receipt')
        const { sig: _, ...unsigned } = v
        try {
            verifyReceipt(unsigned, TICKET, pub, sha256(hello))
            expect.unreachable()
        } catch (err) {
            expect(err).toMatchObject({ violation: 'sig' })
            expect((err as Error).cause).toBeInstanceOf(Error)
        }
    })

    it('checks in Go order: sig, then amount, then body_hash', async () => {
        const both = await signed({ ...RECEIPT, amount_charged: 9999 }, 'receipt')
        expect(violation(() => verifyReceipt(flipSig(both.v), TICKET, both.pub, new Uint8Array(32)))).toBe('sig')
        expect(violation(() => verifyReceipt(both.v, TICKET, both.pub, new Uint8Array(32)))).toBe('amount')
    })
})

describe('parseReceiptJSON', () => {
    // Every signed field must survive, or the recomputed digest desyncs from
    // the node's signature.
    it('round-trips every signed field, so the signature still verifies', async () => {
        const { v, pub } = await signed(
            { ...RECEIPT, cached_input_count: 25, aux_output_usage_type: 2, aux_output_count: 3, ttft_ms: 9, decode_ms: 11 },
            'receipt',
        )
        const parsed = parseReceiptJSON(new TextEncoder().encode(JSON.stringify(v)))
        expect(parsed).toEqual(v)
        expect(violation(() => verifyReceipt(parsed, TICKET, pub, sha256(hello)))).toBeUndefined()
    })

    it('reads an omitted or null field as zero', () => {
        const parsed = parseReceiptJSON(new TextEncoder().encode('{"ticket_id":"t","decode_ms":null,"sig":null}'))
        expect(parsed).toMatchObject({ ticket_id: 't', decode_ms: 0, cached_input_count: 0, body_hash: '', sig: '' })
    })

    // The canonical bytes write a uint64, so -1 signs as 2^64-1: accepted, it
    // would verify and pass amount_charged ≤ max_price.
    it.each([
        ['amount_charged', -1],
        ['amount_charged', 1.5],
        ['amount_charged', '5'],
        ['amount_charged', 2 ** 53],
        ['actual_input_count', true],
        ['input_usage_type', 256],
        ['aux_output_usage_type', -1],
        ['ticket_id', 5],
        ['body_hash', {}],
    ])('refuses %s = %j, as Go would', (field, value) => {
        const json = JSON.stringify({ ...RECEIPT, [field]: value })
        expect(() => parseReceiptJSON(new TextEncoder().encode(json))).toThrow(new RegExp(`decode receipt json: ${field}`))
    })

    it('throws on malformed JSON or a non-object', () => {
        for (const s of ['not json', '1', 'null', '[]']) {
            expect(() => parseReceiptJSON(new TextEncoder().encode(s))).toThrow(/decode receipt json/)
        }
    })
})
