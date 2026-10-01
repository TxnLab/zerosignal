/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'

import {
    commitResponseKey,
    signTicket,
    ticketCanonicalBytes,
    verifyTicket,
    type Ticket,
} from '../src/ticket/ticket.js'
import { UsageType } from '../src/ticket/usagetype.js'
import { RESPONSE_KEY_SIZE } from '../src/wire/constants.js'
import { newFakeSigner } from './helpers.js'
import { ed25519 } from '../src/util/ed25519.js'

function sampleTicket(): Ticket {
    const k = new Uint8Array(RESPONSE_KEY_SIZE)
    const commit = commitResponseKey(k)
    return {
        ticket_id: base64.encode(new TextEncoder().encode('sixteen-byte-id!')),
        operator_id: 42,
        node_id: 7,
        input_count: 1234,
        max_output_count: 512,
        input_rate: 2,
        output_rate: 4,
        max_price: 1234 * 2 + 512 * 4,
        min_price: 50,
        expires_at: 1_700_000_000,
        model: 'gpt-4.1-mini',
        stream: true,
        commit_k: base64.encode(commit),
        input_usage_type: UsageType.Tokens,
        output_usage_type: UsageType.Tokens,
        cache_read_rate: 1,
    }
}

describe('Ticket sign / verify', () => {
    it('round-trips through Sign + Verify', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const t = sampleTicket()
        await signTicket(t, signer, address)
        expect(() => verifyTicket(t, publicKey)).not.toThrow()
    })

    it('Sign fails for an unknown address', async () => {
        const { signer } = newFakeSigner()
        const t = sampleTicket()
        await expect(
            signTicket(t, signer, 'OTHER_ADDR_NOT_IN_SIGNER_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'),
        ).rejects.toThrow()
    })

    it('Sign fails on a nil signer', async () => {
        const t = sampleTicket()
        await expect(signTicket(t, null as never, 'anything')).rejects.toThrow(/signer is nil/)
    })

    it('Verify fails under a different pubkey', async () => {
        const { signer, address } = newFakeSigner()
        const otherPub = ed25519.getPublicKey(ed25519.utils.randomPrivateKey())
        const t = sampleTicket()
        await signTicket(t, signer, address)
        expect(() => verifyTicket(t, otherPub)).toThrow(/verification failed/)
    })

    it('Verify fails when any signed field is mutated after signing', async () => {
        const cases: Array<{ name: string; mutate: (t: Ticket) => void }> = [
            { name: 'ticket_id', mutate: (t) => (t.ticket_id = base64.encode(new TextEncoder().encode('different-id----'))) },
            { name: 'operator_id', mutate: (t) => (t.operator_id += 1) },
            { name: 'input_count', mutate: (t) => (t.input_count += 1) },
            { name: 'max_output_count', mutate: (t) => (t.max_output_count += 1) },
            { name: 'input_rate', mutate: (t) => (t.input_rate += 1) },
            { name: 'output_rate', mutate: (t) => (t.output_rate += 1) },
            { name: 'max_price', mutate: (t) => (t.max_price += 1) },
            { name: 'min_price', mutate: (t) => (t.min_price += 1) },
            { name: 'expires_at', mutate: (t) => (t.expires_at += 1) },
            { name: 'model', mutate: (t) => (t.model = 'other-model') },
            { name: 'stream', mutate: (t) => (t.stream = !t.stream) },
            {
                name: 'commit_k',
                mutate: (t) => {
                    const raw = base64.decode(t.commit_k)
                    raw[0] = (raw[0]! ^ 0xff) & 0xff
                    t.commit_k = base64.encode(raw)
                },
            },
            { name: 'input_usage_type', mutate: (t) => (t.input_usage_type += 1) },
            { name: 'output_usage_type', mutate: (t) => (t.output_usage_type += 1) },
            { name: 'cache_read_rate', mutate: (t) => (t.cache_read_rate += 1) },
        ]
        for (const c of cases) {
            const { signer, address, publicKey } = newFakeSigner()
            const t = sampleTicket()
            await signTicket(t, signer, address)
            c.mutate(t)
            expect(() => verifyTicket(t, publicKey), `tampered ${c.name}`).toThrow()
        }
    })

    it('Verify rejects a malformed sig', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const t = sampleTicket()
        await signTicket(t, signer, address)
        t.sig = '!!!not-base64!!!'
        expect(() => verifyTicket(t, publicKey)).toThrow()
        t.sig = base64.encode(new TextEncoder().encode('too-short'))
        expect(() => verifyTicket(t, publicKey)).toThrow(/invalid ed25519 signature length/)
    })

    it('Verify rejects a wrong-length pubkey', async () => {
        const { signer, address } = newFakeSigner()
        const t = sampleTicket()
        await signTicket(t, signer, address)
        expect(() => verifyTicket(t, new Uint8Array([1, 2, 3]))).toThrow(/invalid ed25519 public key length/)
    })
})

describe('Ticket canonicalBytes', () => {
    it('is deterministic for identical structs', () => {
        expect(ticketCanonicalBytes(sampleTicket())).toEqual(ticketCanonicalBytes(sampleTicket()))
    })

    it('does not depend on sig', () => {
        const a = sampleTicket()
        const before = ticketCanonicalBytes(a)
        a.sig = 'anything'
        const after = ticketCanonicalBytes(a)
        expect(after).toEqual(before)
    })

    it('starts with the ticket signing tag', () => {
        const bytes = ticketCanonicalBytes(sampleTicket())
        const expected = new TextEncoder().encode('zs-ticket-v2\x00')
        expect(bytes.subarray(0, expected.length)).toEqual(expected)
    })

    // Locked byte vector — any algorithm change must update this.
    // Encodes sampleTicket() through the canonical-bytes formula.
    it('matches a fixed byte vector', () => {
        const got = ticketCanonicalBytes(sampleTicket())
        // Manually rebuild the expected layout to be self-documenting.
        const enc = new TextEncoder()
        const parts: number[] = []
        const push = (b: Uint8Array) => parts.push(...b)
        const u32be = (n: number) => new Uint8Array([(n >>> 24) & 0xff, (n >>> 16) & 0xff, (n >>> 8) & 0xff, n & 0xff])
        const u64be = (v: bigint) => {
            const buf = new Uint8Array(8)
            new DataView(buf.buffer).setBigUint64(0, v, false)
            return buf
        }
        const lenStr = (s: string) => {
            const body = enc.encode(s)
            push(u32be(body.length))
            push(body)
        }
        push(enc.encode('zs-ticket-v2\x00'))
        const t = sampleTicket()
        lenStr(t.ticket_id)
        push(u64be(BigInt(t.operator_id)))
        push(u64be(BigInt(t.node_id)))
        push(u64be(BigInt(t.input_count)))
        push(u64be(BigInt(t.max_output_count)))
        push(u64be(BigInt(t.input_rate)))
        push(u64be(BigInt(t.output_rate)))
        push(u64be(BigInt(t.max_price)))
        push(u64be(BigInt(t.min_price)))
        push(u64be(BigInt.asUintN(64, BigInt(t.expires_at))))
        lenStr(t.model)
        parts.push(t.stream ? 1 : 0)
        lenStr(t.commit_k)
        // usage-type discriminators (one byte each).
        parts.push(t.input_usage_type)
        parts.push(t.output_usage_type)
        // v2: cached-read rate at the tail.
        push(u64be(BigInt(t.cache_read_rate)))
        expect(got).toEqual(new Uint8Array(parts))
    })
})

describe('commitResponseKey', () => {
    it('is deterministic and discriminates between distinct keys', () => {
        const k1 = new Uint8Array(RESPONSE_KEY_SIZE)
        const k2 = new Uint8Array(RESPONSE_KEY_SIZE)
        k2[0] = 1
        expect(commitResponseKey(k1)).toEqual(commitResponseKey(k1))
        expect(commitResponseKey(k1)).not.toEqual(commitResponseKey(k2))
    })
})
