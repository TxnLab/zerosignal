/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { encodeDeploymentId } from '@txnlab/zs-proto/ticket'
import { DEPLOYMENT_BINDING_MIN_VERSION } from '@txnlab/zs-proto/wire'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { ReserveCall } from '../src/reserve.js'

const groups = JSON.parse(readFileSync(new URL('../../testdata/escrow_group_vectors.json', import.meta.url), 'utf8')) as {
    open: { cases: { name: string; group_b64: string }[] }
}
const openGroup = (name: string) => groups.open.cases.find((c) => c.name === name)!.group_b64

const reserveCalls: ReserveCall[] = []
let reserved: { ticket: { id: string }; presignedOpenTxn: string }
let onReserve = () => {}
vi.mock('../src/reserve.js', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../src/reserve.js')>()),
    reserve: (call: ReserveCall) => {
        reserveCalls.push(call)
        onReserve()
        return Promise.resolve(reserved)
    },
}))
const verifyTicketSignature = vi.fn()
vi.mock('../src/verify.js', async (importOriginal) => ({
    ...(await importOriginal<typeof import('../src/verify.js')>()),
    verifyTicketSignature: (...args: unknown[]) => verifyTicketSignature(...args),
}))

const { NoEphemeralError, ProtestReason, TicketSignatureInvalidError, httpReserveClient, memoryJournal, resolveNetwork } =
    await import('../src/index.js')
type TicketRecord = import('../src/index.js').TicketRecord
const app1 = resolveNetwork({ network: 'localnet', escrowAppId: 1n })

const { testOperator } = await import('./fixtures.js')

function record(over: Partial<TicketRecord> = {}): TicketRecord {
    return {
        ticketId: 't1',
        openTxId: 'TX',
        escrowAppId: 1n,
        target: { op: 7, node: 2 },
        payer: 'PAYER',
        maxPrice: 100n,
        expiresAt: 0,
        status: 'open',
        createdAt: 10,
        updatedAt: 10,
        ...over,
    }
}

describe('memoryJournal', () => {
    it('lists only the payer and escrow app asked for, oldest first', async () => {
        const j = memoryJournal()
        await j.put(record({ ticketId: 'b', createdAt: 20 }))
        await j.put(record({ ticketId: 'c', createdAt: 10 }))
        await j.put(record({ ticketId: 'a', createdAt: 20 }))
        await j.put(record({ ticketId: 'other-payer', payer: 'SOMEONE' }))
        await j.put(record({ ticketId: 'other-app', escrowAppId: 2n }))
        await j.put(record({ ticketId: 'named', deployment: app1.key, createdAt: 30 }))
        await j.put(record({ ticketId: 'named-elsewhere', deployment: 'algorand-custom-1' }))
        expect((await j.list('PAYER', app1)).map((r) => r.ticketId)).toEqual(['c', 'a', 'b', 'named'])
    })

    it('replaces by ticket id and deletes, an unknown id included', async () => {
        const j = memoryJournal()
        await j.put(record())
        await j.put(record({ status: 'settle_pending', updatedAt: 30 }))
        expect(await j.list('PAYER', app1)).toEqual([record({ status: 'settle_pending', updatedAt: 30 })])
        await j.delete('t1')
        await j.delete('never')
        expect(await j.list('PAYER', app1)).toEqual([])
    })

    // Go's journal holds values: a caller editing a record it put or listed
    // must not rewrite the journal's copy.
    it('copies records in and out', async () => {
        const j = memoryJournal()
        const digest = new Uint8Array(32).fill(1)
        const rec = record({
            settle: {
                amountCharged: 5n,
                receiptDigest: digest,
                ttftMs: 0n,
                decodeMs: 0n,
                inputTokens: 0n,
                outputTokens: 0n,
                outputUsageType: 0,
                auxOutputUsageType: 0,
                auxOutputCount: 0n,
            },
        })
        await j.put(rec)
        rec.status = 'settle_pending'
        rec.target.node = 9
        digest.fill(2)
        const [listed] = await j.list('PAYER', app1)
        expect(listed!.status).toBe('open')
        expect(listed!.target.node).toBe(2)
        expect(listed!.settle!.receiptDigest).toEqual(new Uint8Array(32).fill(1))
        listed!.target.node = 9
        listed!.settle!.receiptDigest.fill(3)
        const [again] = await j.list('PAYER', app1)
        expect(again!.target.node).toBe(2)
        expect(again!.settle!.receiptDigest).toEqual(new Uint8Array(32).fill(1))
    })
})

describe('httpReserveClient', () => {
    beforeEach(() => {
        reserveCalls.length = 0
        onReserve = () => {}
        reserved = { ticket: { id: 'T' }, presignedOpenTxn: '' }
        verifyTicketSignature.mockReset()
    })
    const fetch = vi.fn()
    const signer = { signBytes: vi.fn() }
    const op = testOperator({ ephemeralRecipient: 'age1live', ephemeralExpiry: 2_000 })
    const request = { model: 'm' } as ReserveCall['request']

    it('reserves on the operator, sealed to its live recipient', async () => {
        const signal = new AbortController().signal
        const c = httpReserveClient({ fetch, signer, timeoutMs: 1234, clock: () => 1_000_000 })
        await expect(c.reserve(op, request, null, signal)).resolves.toEqual({ ...reserved, sealRecipient: 'age1live' })
        expect(reserveCalls).toHaveLength(1)
        const call = reserveCalls[0]!
        expect(call.target).toEqual({ operatorId: 7, nodeId: 2, baseUrl: op.baseUrl, sealRecipient: 'age1live' })
        expect(call.request).toBe(request)
        expect(call.hop).toBeNull()
        expect(call.fetch).toBe(fetch)
        expect(call.signer).toBe(signer)
        expect(call.timeoutMs).toBe(1234)
        expect(call.signal).toBe(signal)
        expect(call.clock!()).toBe(1_000_000)
    })

    it('leaves unset what the caller did not set', async () => {
        await httpReserveClient({ fetch, clock: () => 0 }).reserve(op, request, null)
        const call = reserveCalls[0]!
        expect('signer' in call).toBe(false)
        expect('timeoutMs' in call).toBe(false)
        expect('signal' in call).toBe(false)
    })

    // reserve() would abort at once on 0; the default applies instead.
    it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('reads a timeout of %s as unset', async (timeoutMs) => {
        await httpReserveClient({ fetch, timeoutMs, clock: () => 0 }).reserve(op, request, null)
        expect('timeoutMs' in reserveCalls[0]!).toBe(false)
    })

    it('rejects an operator whose recipient expired, before any request', async () => {
        const c = httpReserveClient({ fetch, clock: () => 2_000_000 })
        await expect(c.reserve(op, request, null)).rejects.toThrow(NoEphemeralError)
        expect(reserveCalls).toHaveLength(0)
    })

    // Inference seals to what reserve sealed to, even if the operator's
    // recipient rotates while the reserve is in flight.
    it('returns the recipient the reserve was sealed to', async () => {
        const live = { ...op }
        onReserve = () => {
            live.ephemeralRecipient = 'age1rotated'
        }
        const r = await httpReserveClient({ fetch, clock: () => 0 }).reserve(live, request, null)
        expect(r.sealRecipient).toBe('age1live')
    })

    it("verifies the ticket's signature under the operator's key", async () => {
        const key = new Uint8Array(32).fill(9)
        await httpReserveClient({ fetch, clock: () => 0 }).reserve({ ...op, ticketSigningKey: key }, request, null)
        expect(verifyTicketSignature).toHaveBeenCalledExactlyOnceWith(reserved.ticket, key, undefined, true)
    })

    const deployment = new Uint8Array(32).fill(5)

    // A node new enough is asked for a bound ticket, and must give one.
    it('names the deployment to a node that binds, and demands a bound ticket', async () => {
        const key = new Uint8Array(32).fill(9)
        const newer = { ...op, ticketSigningKey: key, protoVersion: DEPLOYMENT_BINDING_MIN_VERSION }
        await httpReserveClient({ fetch, clock: () => 0, deployment }).reserve(newer, request, null)
        expect(reserveCalls[0]!.request).toEqual({ ...request, deployment: encodeDeploymentId(deployment) })
        expect(request).not.toHaveProperty('deployment')
        expect(verifyTicketSignature).toHaveBeenCalledExactlyOnceWith(reserved.ticket, key, deployment, false)
    })

    it.each(['9.12', '', 'junk'])('keeps the legacy layout with a node advertising %j', async (protoVersion) => {
        const older = { ...op, protoVersion }
        await httpReserveClient({ fetch, clock: () => 0, deployment }).reserve(older, { ...request, deployment: 'stale' }, null)
        expect(reserveCalls[0]!.request).toEqual(request)
        expect(verifyTicketSignature).toHaveBeenCalledExactlyOnceWith(reserved.ticket, op.ticketSigningKey, deployment, true)
    })

    it('names nothing without a deployment of its own', async () => {
        const newer = { ...op, protoVersion: DEPLOYMENT_BINDING_MIN_VERSION }
        await httpReserveClient({ fetch, clock: () => 0 }).reserve(newer, request, null)
        expect(reserveCalls[0]!.request).toBe(request)
    })

    it('rejects a ticket whose signature does not verify', async () => {
        verifyTicketSignature.mockImplementation(() => {
            throw new TicketSignatureInvalidError('bad')
        })
        await expect(httpReserveClient({ fetch, clock: () => 0 }).reserve(op, request, null)).rejects.toThrow(
            TicketSignatureInvalidError,
        )
    })

    // Go decodes the group inside Reserve, so a bad one fails the reserve and
    // dispatch moves on rather than ending the request at open.
    it('rejects a presigned open group that does not decode', async () => {
        reserved.presignedOpenTxn = openGroup('size_one')
        await expect(httpReserveClient({ fetch, clock: () => 0 }).reserve(op, request, null)).rejects.toThrow(
            /decode presigned open group: .*want 2/,
        )
    })

    it('passes a presigned open group that decodes', async () => {
        reserved.presignedOpenTxn = openGroup('valid')
        const r = await httpReserveClient({ fetch, clock: () => 0 }).reserve(op, request, null)
        expect(r.presignedOpenTxn).toBe(openGroup('valid'))
    })
})

// Go's escrow.ProtestReasonCode values; the contract reads the number.
describe('ProtestReason', () => {
    it('numbers the reasons as the contract does', () => {
        expect(ProtestReason).toEqual({
            unspecified: 0,
            bodyHash: 1,
            receiptSig: 2,
            amount: 3,
            sealing: 4,
            receiptMissing: 5,
        })
    })
})
