/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest'

import { type Ticket, commitResponseKey } from '@txnlab/zs-proto/ticket'

// Every key openReserve unwraps, so a test can see what it left in the buffer.
const { unwrapped } = vi.hoisted(() => ({ unwrapped: [] as Uint8Array[] }))
vi.mock('@txnlab/zs-proto/wire', async (importOriginal) => {
    const wire = await importOriginal<typeof import('@txnlab/zs-proto/wire')>()
    return {
        ...wire,
        unwrapResponseKey: async (...args: Parameters<typeof wire.unwrapResponseKey>) => {
            const k = await wire.unwrapResponseKey(...args)
            unwrapped.push(k)
            return k
        },
    }
})
import { type EphemeralIdentity, generateEphemeralIdentity, sealReserveResponse } from '@txnlab/zs-proto/wire'

import {
    CommitKMismatchError,
    ReserveResponseError,
    type ReserveTerms,
    checkTicketTerms,
    openReserve,
} from '../src/index.js'

const NOW_MS = 1_700_000_000_500
const NOW = 1_700_000_000

const key = new Uint8Array(32).fill(7)

function b64(b: Uint8Array): string {
    return Buffer.from(b).toString('base64')
}

function ticket(over: Partial<Ticket> = {}): Ticket {
    return {
        ticket_id: 'dGlja2V0LWlkLTE2Ynl0ZQ==',
        operator_id: 3,
        node_id: 9,
        input_count: 300,
        max_output_count: 512,
        input_rate: 2,
        output_rate: 4,
        max_price: 3000,
        min_price: 50,
        expires_at: NOW + 600,
        model: 'm',
        stream: true,
        commit_k: b64(commitResponseKey(key)),
        input_usage_type: 2,
        output_usage_type: 2,
        cache_read_rate: 1,
        sig: 'c2ln',
        ...over,
    }
}

const terms: ReserveTerms = { model: 'm', maxOutputCount: 512, stream: true, operatorId: 3, nodeId: 9 }

// age-wraps k to recipient. The reserve seal is age under a JSON envelope, so
// its ciphertext is exactly what a node puts in wrapped_response_key.
async function wrap(k: Uint8Array, recipient: string): Promise<string> {
    const env = JSON.parse(new TextDecoder().decode(await sealReserveResponse(k, recipient)))
    return env.ciphertext
}

async function sealed(id: EphemeralIdentity, body: unknown): Promise<Uint8Array> {
    return sealReserveResponse(new TextEncoder().encode(JSON.stringify(body)), id.recipient)
}

async function response(id: EphemeralIdentity, over: Record<string, unknown> = {}) {
    return sealed(id, {
        ticket: ticket(),
        wrapped_response_key: await wrap(key, id.recipient),
        algo_usd_price: 0.2,
        presigned_open_txn: 'cGc=',
        ...over,
    })
}

describe('openReserve', () => {
    it('returns the ticket, the unwrapped key and the extras', async () => {
        const id = await generateEphemeralIdentity()
        const got = await openReserve(await response(id), id, terms, { nowMs: NOW_MS, requirePresignedOpen: true })
        expect(got.ticket).toEqual(ticket())
        expect(got.responseKey).toEqual(key)
        expect(got.algoUsdPrice).toBe(0.2)
        expect(got.presignedOpenTxn).toBe('cGc=')
    })

    it('reads absent extras as zero', async () => {
        const id = await generateEphemeralIdentity()
        const got = await openReserve(
            await response(id, { algo_usd_price: undefined, presigned_open_txn: undefined }),
            id,
            terms,
            { nowMs: NOW_MS },
        )
        expect(got.algoUsdPrice).toBe(0)
        expect(got.presignedOpenTxn).toBe('')
    })

    it('refuses a body sealed to another identity', async () => {
        const id = await generateEphemeralIdentity()
        const other = await generateEphemeralIdentity()
        await expect(openReserve(await response(other), id, terms, { nowMs: NOW_MS })).rejects.toThrow(
            /^open reserve response/,
        )
    })

    // A lax parse would read -1 as a number that passes min_price ≤ max_price
    // while the signature covers 2^64-1.
    it('parses strictly', async () => {
        const id = await generateEphemeralIdentity()
        const err = await openReserve(await response(id, { ticket: ticket({ max_price: -1 }) }), id, terms, {
            nowMs: NOW_MS,
        }).catch((e) => e)
        expect(err).toBeInstanceOf(ReserveResponseError)
        expect(err.message).toMatch(/^parse reserve response: .*max_price/)
    })

    it('refuses an unsigned ticket', async () => {
        const id = await generateEphemeralIdentity()
        await expect(
            openReserve(await response(id, { ticket: ticket({ sig: '' }) }), id, terms, { nowMs: NOW_MS }),
        ).rejects.toThrow(/unsigned/)
    })

    it('checks the terms', async () => {
        const id = await generateEphemeralIdentity()
        await expect(
            openReserve(await response(id, { ticket: ticket({ model: 'cheap' }) }), id, terms, { nowMs: NOW_MS }),
        ).rejects.toThrow(/ticket model/)
    })

    it('passes minTtlSeconds through', async () => {
        const id = await generateEphemeralIdentity()
        const body = await response(id, { ticket: ticket({ expires_at: NOW + 10 }) })
        await expect(openReserve(body, id, terms, { nowMs: NOW_MS })).resolves.toBeDefined()
        await expect(openReserve(body, id, terms, { nowMs: NOW_MS, minTtlSeconds: 15 })).rejects.toThrow(
            /leaves under 15s/,
        )
    })

    it('refuses a missing wrapped key', async () => {
        const id = await generateEphemeralIdentity()
        await expect(
            openReserve(await response(id, { wrapped_response_key: '' }), id, terms, { nowMs: NOW_MS }),
        ).rejects.toThrow(/missing wrapped_response_key/)
    })

    it('refuses a missing presigned group only when one is owed', async () => {
        const id = await generateEphemeralIdentity()
        const body = await response(id, { presigned_open_txn: undefined })
        await expect(openReserve(body, id, terms, { nowMs: NOW_MS })).resolves.toBeDefined()
        await expect(openReserve(body, id, terms, { nowMs: NOW_MS, requirePresignedOpen: true })).rejects.toThrow(
            /missing presigned_open_txn/,
        )
    })

    it('refuses a key wrapped to another identity', async () => {
        const id = await generateEphemeralIdentity()
        const other = await generateEphemeralIdentity()
        const err = await openReserve(
            await response(id, { wrapped_response_key: await wrap(key, other.recipient) }),
            id,
            terms,
            { nowMs: NOW_MS },
        ).catch((e) => e)
        expect(err).toBeInstanceOf(ReserveResponseError)
        expect(err.message).toMatch(/^unwrap response key/)
    })

    it('refuses a key that is not the committed one, and zeroes it', async () => {
        const id = await generateEphemeralIdentity()
        unwrapped.length = 0
        const err = await openReserve(
            await response(id, { wrapped_response_key: await wrap(new Uint8Array(32).fill(8), id.recipient) }),
            id,
            terms,
            { nowMs: NOW_MS },
        ).catch((e) => e)
        expect(err).toBeInstanceOf(CommitKMismatchError)
        expect(unwrapped).toHaveLength(1)
        expect(unwrapped[0]).toEqual(new Uint8Array(32))
    })

    // Which check refuses a response with several faults is the order Go
    // runs them in: terms before the wrapped key.
    it('checks the terms before the wrapped key', async () => {
        const id = await generateEphemeralIdentity()
        await expect(
            openReserve(
                await response(id, { ticket: ticket({ model: 'cheap' }), wrapped_response_key: '' }),
                id,
                terms,
                { nowMs: NOW_MS },
            ),
        ).rejects.toThrow(/ticket model/)
    })
})

describe('checkTicketTerms', () => {
    const ok = (t: Ticket, want: ReserveTerms = terms, nowMs = NOW_MS, ttl?: number) => () =>
        checkTicketTerms(t, want, nowMs, ttl)

    it('accepts a ticket that matches', () => {
        expect(ok(ticket())).not.toThrow()
    })

    // SPEC §3a: the node clamps input_count, so it differs from the request.
    it('does not compare input_count', () => {
        expect(ok(ticket({ input_count: 256 }))).not.toThrow()
        expect(ok(ticket({ input_count: 1 }))).not.toThrow()
    })

    it.each<[string, Partial<Ticket>, RegExp]>([
        ['operator', { operator_id: 4 }, /operator id 4 != requested 3/],
        ['node', { node_id: 8 }, /node id 8 != requested 9/],
        ['model', { model: 'n' }, /ticket model "n" != requested "m"/],
        ['max_output_count', { max_output_count: 511 }, /max_output_count 511 != requested 512/],
        ['stream', { stream: false }, /stream false != requested true/],
        ['ticket_id', { ticket_id: '' }, /ticket_id is empty/],
        ['commit_k', { commit_k: '' }, /commit_k is empty/],
        ['min > max', { min_price: 3001 }, /min_price 3001 > max_price 3000/],
    ])('refuses a different %s', (_, over, msg) => {
        expect(ok(ticket(over))).toThrow(ReserveResponseError)
        expect(ok(ticket(over))).toThrow(msg)
    })

    it('accepts min_price equal to max_price', () => {
        expect(ok(ticket({ min_price: 3000 }))).not.toThrow()
    })

    it('compares ids given as bigint', () => {
        expect(ok(ticket(), { ...terms, operatorId: 3n, nodeId: 9n })).not.toThrow()
        expect(ok(ticket(), { ...terms, operatorId: 4n })).toThrow(/operator id/)
    })

    it.each([1.5, NaN])('refuses a requested id of %s as a ReserveResponseError', (bad) => {
        expect(ok(ticket(), { ...terms, operatorId: bad })).toThrow(ReserveResponseError)
        expect(ok(ticket(), { ...terms, nodeId: bad })).toThrow(/requested nodeId .* is not an integer/)
    })

    // Go refuses expires_at <= now; the default minimum of 1s is the same rule.
    it('refuses an expired ticket at the default minimum', () => {
        expect(ok(ticket({ expires_at: NOW + 1 }))).not.toThrow()
        expect(ok(ticket({ expires_at: NOW }))).toThrow(/leaves under 1s/)
    })

    it('holds the ticket to minTtlSeconds, inclusive', () => {
        expect(ok(ticket({ expires_at: NOW + 15 }), terms, NOW_MS, 15)).not.toThrow()
        expect(ok(ticket({ expires_at: NOW + 14 }), terms, NOW_MS, 15)).toThrow(/leaves under 15s/)
    })

    // The ms within the second don't count toward the TTL.
    it('floors the clock to the second', () => {
        expect(ok(ticket({ expires_at: NOW + 1 }), terms, NOW * 1000 + 999)).not.toThrow()
        expect(ok(ticket({ expires_at: NOW + 1 }), terms, (NOW + 1) * 1000)).toThrow(/leaves under/)
    })

    it.each([NaN, Infinity, -Infinity])('refuses a clock reading %s', (now) => {
        expect(ok(ticket(), terms, now)).toThrow(/cannot check expiry/)
    })

    // Under 1, a ticket already expired would pass; -Infinity and NaN make the
    // comparison false outright.
    it.each([NaN, -Infinity, 0, -100, 0.5])('refuses a minimum TTL of %s', (ttl) => {
        expect(ok(ticket({ expires_at: NOW - 99 }), terms, NOW_MS, ttl)).toThrow(/cannot check expiry/)
    })
})
