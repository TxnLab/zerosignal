/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'

import {
    commitResponseKey,
    parseTicketJSON,
    signTicket,
    ticketCanonicalBytes,
    verifyTicketFor,
    type Ticket,
} from '../src/ticket/ticket.js'
import { encodeDeploymentId } from '../src/ticket/deployment.js'
import { parseReserveResponseJSON } from '../src/ticket/reserve.js'
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

// Verifiers accept only bound tickets, so the sign / verify cases sign one.
const DEP = new Uint8Array(32).fill(7)
const boundTicket = (): Ticket => ({ ...sampleTicket(), deployment: encodeDeploymentId(DEP) })
const verifyTicket = (t: Ticket, pub: Uint8Array) => verifyTicketFor(t, pub, DEP)

describe('Ticket sign / verify', () => {
    it('round-trips through Sign + Verify', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const t = boundTicket()
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
        const t = boundTicket()
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
            const t = boundTicket()
            await signTicket(t, signer, address)
            c.mutate(t)
            expect(() => verifyTicket(t, publicKey), `tampered ${c.name}`).toThrow()
        }
    })

    it('Verify rejects a malformed sig', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const t = boundTicket()
        await signTicket(t, signer, address)
        t.sig = '!!!not-base64!!!'
        expect(() => verifyTicket(t, publicKey)).toThrow()
        t.sig = base64.encode(new TextEncoder().encode('too-short'))
        expect(() => verifyTicket(t, publicKey)).toThrow(/invalid ed25519 signature length/)
    })

    it('Verify rejects a wrong-length pubkey', async () => {
        const { signer, address } = newFakeSigner()
        const t = boundTicket()
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

const enc = (v: unknown) => new TextEncoder().encode(JSON.stringify(v))

describe('parseTicketJSON', () => {
    // Distinct values, so a field read from its neighbour can't pass.
    it('round-trips every signed field', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const t = {
            ...boundTicket(),
            input_usage_type: UsageType.None,
            output_usage_type: UsageType.Images,
            cache_read_rate: 3,
        }
        await signTicket(t, signer, address)
        const got = parseTicketJSON(enc(t))
        expect(got).toEqual(t)
        expect(() => verifyTicket(got, publicKey)).not.toThrow()
    })

    it('accepts each bound itself, and a negative expires_at', () => {
        const t = {
            ...sampleTicket(),
            max_price: Number.MAX_SAFE_INTEGER,
            output_usage_type: 255 as UsageType,
            expires_at: Number.MIN_SAFE_INTEGER,
        }
        expect(parseTicketJSON(enc(t))).toMatchObject({
            max_price: Number.MAX_SAFE_INTEGER,
            output_usage_type: 255,
            expires_at: Number.MIN_SAFE_INTEGER,
        })
    })

    it('reads an absent or null field as zero and leaves sig off', () => {
        const got = parseTicketJSON(enc({ ticket_id: 't', max_price: null, stream: null, sig: null }))
        expect(got).toMatchObject({ ticket_id: 't', max_price: 0, stream: false, model: '', expires_at: 0 })
        expect('sig' in got).toBe(false)
    })

    // The canonical bytes write a uint64, so -1 signs as 2^64-1 and would pass
    // any ceiling the payer holds max_price to; 256 masks to 0 in a usage byte.
    it.each([
        ['max_price', -1],
        ['min_price', 1.5],
        ['input_count', '5'],
        ['max_output_count', 2 ** 53],
        ['operator_id', true],
        ['node_id', -1],
        ['input_rate', -1],
        ['output_rate', -1],
        ['cache_read_rate', -1],
        ['expires_at', 2 ** 53],
        ['expires_at', 1.5],
        ['input_usage_type', 256],
        ['output_usage_type', -1],
        ['stream', 'true'],
        ['stream', 1],
        ['model', 5],
        ['commit_k', {}],
        ['ticket_id', []],
        ['sig', 5],
    ])('refuses %s = %j', (field, value) => {
        expect(() => parseTicketJSON(enc({ ...sampleTicket(), [field]: value }))).toThrow(
            new RegExp(`decode ticket json: ${field}`),
        )
    })

    it('refuses malformed JSON or a non-object', () => {
        for (const s of ['not json', '1', 'null', '[]', '"x"']) {
            expect(() => parseTicketJSON(new TextEncoder().encode(s))).toThrow(/decode ticket json/)
        }
    })
})

describe('parseReserveResponseJSON', () => {
    it('round-trips a full response', async () => {
        const { signer, address } = newFakeSigner()
        const ticket = sampleTicket()
        await signTicket(ticket, signer, address)
        const r = { ticket, wrapped_response_key: 'wk', algo_usd_price: 0.25, sol_usd_price: 142.5, presigned_open_txn: 'pg' }
        expect(parseReserveResponseJSON(enc(r))).toEqual(r)
    })

    it('leaves zero-valued optional fields off, as Go omitempty does', () => {
        const got = parseReserveResponseJSON(
            enc({ ticket: sampleTicket(), wrapped_response_key: '', algo_usd_price: 0, sol_usd_price: 0, presigned_open_txn: null }),
        )
        expect(got).toEqual({ ticket: sampleTicket() })
    })

    it('reads an absent ticket as the zero ticket', () => {
        expect(parseReserveResponseJSON(enc({})).ticket).toMatchObject({ ticket_id: '', max_price: 0 })
    })

    it('reads the ticket as strictly as parseTicketJSON', () => {
        expect(() => parseReserveResponseJSON(enc({ ticket: { ...sampleTicket(), max_price: -1 } }))).toThrow(
            /decode reserve response json: ticket: max_price/,
        )
    })

    it('refuses an algo_usd_price that overflows a float64', () => {
        const raw = new TextEncoder().encode('{"ticket":{},"algo_usd_price":1e400}')
        expect(() => parseReserveResponseJSON(raw)).toThrow(/algo_usd_price Infinity is not a finite number/)
    })

    it.each([
        ['ticket', 'x'],
        ['ticket', []],
        ['wrapped_response_key', 5],
        ['algo_usd_price', '0.25'],
        ['sol_usd_price', '142.5'],
        ['presigned_open_txn', {}],
    ])('refuses %s = %j', (field, value) => {
        expect(() => parseReserveResponseJSON(enc({ ticket: sampleTicket(), [field]: value }))).toThrow(
            new RegExp(`decode reserve response json: ${field}`),
        )
    })
})
