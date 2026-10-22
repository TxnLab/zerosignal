/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Solana values of the open and ack wire fields, replaying the
// Go-generated solana_wire_vectors.json (go/solana/zsescrow
// wire_vectors_test.go).

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { base64, hex } from '@scure/base'
import { describe, expect, it } from 'vitest'

import { encodeBase58 } from '../src/solana/index.js'
import {
    AckRejectedError,
    Deployment,
    decodeAckSignature,
    decodeOpenOffer,
    decodeOpenPayment,
    encodeOpenPayment,
    formatOpenSeq,
    parseOpenSeq,
    signReceiptAck,
} from '../src/solana/zsescrow/index.js'
import { parseReceiptJSON } from '../src/ticket/receipt.js'
import type { BytesSigner } from '../src/ticket/signing.js'
import { ed25519 } from '../src/util/ed25519.js'

type Json = Record<string, any> // eslint-disable-line @typescript-eslint/no-explicit-any

const here = path.dirname(fileURLToPath(import.meta.url))
const load = (name: string): Json => JSON.parse(fs.readFileSync(path.resolve(here, '..', '..', 'testdata', name), 'utf8')) as Json

const v = load('solana_wire_vectors.json')
const txs = load('solana_tx_vectors.json')

const d = new Deployment(v.program_id, v.usdc_mint)
const genesis = encodeBase58(hex.decode(v.genesis_hash))
const secrets = new Map<string, Uint8Array>(Object.entries(txs.context.keys as Record<string, Json>).map(([name, k]) => [name, new Uint8Array(32).fill(k.seed)]))
const addressOf = (name: string) => encodeBase58(ed25519.getPublicKey(secrets.get(name)!))

/** Signs digests as the fixture keys, by address. */
const fixtureSigner: BytesSigner = {
    signBytes(address, msg) {
        for (const s of secrets.values()) if (encodeBase58(ed25519.getPublicKey(s)) === address) return Promise.resolve(ed25519.sign(msg, s))
        return Promise.reject(new Error(`no key for ${address}`))
    },
}

const receiptOf = (r: Json | null) => (r === null ? undefined : parseReceiptJSON(new TextEncoder().encode(JSON.stringify(r))))

describe('solana_wire_vectors.json', () => {
    it('has every block', () => {
        for (const k of ['opens', 'open_refusals', 'offer_refusals', 'encode_refusals', 'open_seqs', 'acks', 'settle_refusals']) expect(v[k].length, k).toBeGreaterThan(0)
    })

    it.each((v.opens as Json[]).map((c) => [c.name, c] as const))('writes and reads the open %s as Go does', (_, c) => {
        expect(base64.encode(decodeOpenOffer(c.presigned_open_txn))).toBe(c.presigned_open_txn)
        expect(encodeOpenPayment(base64.decode(c.payment_open))).toEqual({ paymentOpen: c.payment_open, paymentRef: c.payment_ref })
        expect(encodeBase58(decodeOpenPayment(c.payment_open, c.payment_ref).signatures[0]!)).toBe(c.payment_ref)
    })

    it.each((v.open_refusals as Json[]).map((c) => [c.name, c] as const))('refuses the open %s as Go does', (_, c) => {
        expect(() => decodeOpenPayment(c.payment_open, c.payment_ref)).toThrow()
    })

    it.each((v.offer_refusals as Json[]).map((c) => [c.name, c] as const))('refuses the offer %s as Go does', (_, c) => {
        expect(() => decodeOpenOffer(c.presigned_open_txn)).toThrow()
    })

    it.each((v.encode_refusals as Json[]).map((c) => [c.name, c] as const))('refuses to write the open %s as Go does', (_, c) => {
        expect(() => encodeOpenPayment(base64.decode(c.completed_base64))).toThrow(/signature/)
    })

    it.each((v.open_seqs as Json[]).map((c) => [JSON.stringify(c.slot), c] as const))('reads the open_seq slot %s as Go does', (_, c) => {
        if (!c.ok) {
            expect(() => parseOpenSeq(c.slot)).toThrow()
            return
        }
        expect(parseOpenSeq(c.slot)).toBe(BigInt(c.value))
        expect(formatOpenSeq(BigInt(c.value))).toBe(c.slot)
    })

    it.each((v.acks as Json[]).map((c) => [c.name, c] as const))('signs the ack %s as Go does', async (_, c) => {
        const sign = signReceiptAck(
            fixtureSigner,
            addressOf(c.signer),
            d,
            genesis,
            BigInt(c.operator_id),
            BigInt(c.node_id),
            hex.decode(c.ticket_id),
            BigInt(c.open_seq),
            receiptOf(c.receipt),
        )
        if (c.verdict !== 'ok') {
            await expect(sign).rejects.toMatchObject({ field: c.verdict })
            await expect(sign).rejects.toBeInstanceOf(AckRejectedError)
            return
        }
        const sig = await sign
        expect(sig).toBe(c.payment_settle)
        expect(base64.encode(decodeAckSignature(sig))).toBe(sig)
    })

    it.each((v.settle_refusals as Json[]).map((c) => [c.name, c] as const))('refuses the payment_settle %s as Go does', (_, c) => {
        expect(() => decodeAckSignature(c.payment_settle)).toThrow()
    })
})

describe('signReceiptAck', () => {
    const c = (v.acks as Json[]).find((x) => x.name === 'receipt_claim')!
    const sign = (s: BytesSigner) =>
        signReceiptAck(s, addressOf('payer'), d, genesis, BigInt(c.operator_id), BigInt(c.node_id), hex.decode(c.ticket_id), 7n, receiptOf(c.receipt))
    const payerSecret = secrets.get('payer')!

    it('refuses a signature that does not verify as the payer', async () => {
        const bad: Record<string, (msg: Uint8Array) => Uint8Array> = {
            'another key': (msg) => ed25519.sign(msg, secrets.get('attacker')!),
            short: (msg) => ed25519.sign(msg, payerSecret).subarray(0, 63),
            long: (msg) => new Uint8Array([...ed25519.sign(msg, payerSecret), 0]),
            'other bytes': (msg) => ed25519.sign(new Uint8Array([0, ...msg]), payerSecret),
        }
        for (const [name, f] of Object.entries(bad)) {
            await expect(sign({ signBytes: (_, msg) => Promise.resolve(f(msg)) }), name).rejects.toThrow(/does not verify/)
        }
    })

    it('asks to sign as the payer', async () => {
        const asked: string[] = []
        await sign({ signBytes: (address, msg) => (asked.push(address), Promise.resolve(ed25519.sign(msg, payerSecret))) })
        expect(asked).toEqual([addressOf('payer')])
    })

    it('carries a signer failure as its cause', async () => {
        const cause = new Error('locked')
        await expect(sign({ signBytes: () => Promise.reject(cause) })).rejects.toMatchObject({ cause })
    })
})

describe('formatOpenSeq', () => {
    it('refuses what is not a u64', () => {
        expect(() => formatOpenSeq(-1n)).toThrow(RangeError)
        expect(() => formatOpenSeq(1n << 64n)).toThrow(RangeError)
    })
})
