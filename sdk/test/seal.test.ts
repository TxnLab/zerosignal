/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// sealRequest and openResponseKey, against the node's side of zs-proto's wire.

import { describe, expect, it, vi } from 'vitest'

// Every key the SDK unwraps, so a test can check a refused one was zeroed.
const { unwrapped } = vi.hoisted(() => ({ unwrapped: [] as Uint8Array[] }))
vi.mock('@txnlab/zs-proto/wire', async (importOriginal) => {
    const actual = await importOriginal<typeof import('@txnlab/zs-proto/wire')>()
    return {
        ...actual,
        unwrapResponseKey: async (...args: Parameters<typeof actual.unwrapResponseKey>) => {
            const key = await actual.unwrapResponseKey(...args)
            unwrapped.push(key)
            return key
        },
    }
})

import { type Ticket, commitResponseKey } from '@txnlab/zs-proto/ticket'
import {
    ResponseSealer,
    computeAdmissionTag,
    decryptRequest,
    generateEphemeralIdentity,
    unwrapResponseKey,
} from '@txnlab/zs-proto/wire'

import { CommitKMismatchError, ResponseKeyUnwrapError, openResponseKey, sealRequest } from '../src/index.js'

const body = new TextEncoder().encode('{"model":"m"}')
const K = new Uint8Array(32).fill(7)

describe('sealRequest', () => {
    it('seals the body to the node with its identifiers and the admission tag', async () => {
        const node = await generateEphemeralIdentity()
        const ephemeral = await generateEphemeralIdentity()
        const envelope = await sealRequest({
            body,
            txId: 'TX1',
            ticketId: 'TKT1',
            responseKey: K,
            nodeRecipient: node.recipient,
            ephemeral,
        })
        const dec = await decryptRequest(envelope, node.secret)
        expect(dec.body).toEqual(body)
        expect(dec.algorandTxID).toBe('TX1')
        expect(dec.ticketID).toBe('TKT1')
        expect(dec.replyToRecipient).toBe(ephemeral.recipient)
        expect(dec.admissionTag).toEqual(computeAdmissionTag(K, 'TKT1', 'TX1', body))
    })

    it.each([31, 33])('refuses a K_response of %i bytes', async (n) => {
        const node = await generateEphemeralIdentity()
        await expect(
            sealRequest({
                body,
                txId: 'TX1',
                ticketId: 'TKT1',
                responseKey: new Uint8Array(n),
                nodeRecipient: node.recipient,
                ephemeral: await generateEphemeralIdentity(),
            }),
        ).rejects.toThrow(/32 bytes/)
    })
})

describe('openResponseKey', () => {
    async function sealed() {
        const ephemeral = await generateEphemeralIdentity()
        const sealer = await ResponseSealer.create({ replyTo: ephemeral.recipient, txID: 'TX', ticketID: '' })
        return { ephemeral, wrapped: sealer.wrappedKeyHeader() }
    }

    it('returns the key the ticket committed to', async () => {
        const { ephemeral, wrapped } = await sealed()
        const k = await unwrapResponseKey(wrapped, ephemeral)
        const t = { commit_k: Buffer.from(commitResponseKey(k)).toString('base64') } as Ticket
        expect(await openResponseKey(wrapped, ephemeral, t)).toEqual(k)
    })

    it('throws CommitKMismatchError for a key the ticket did not commit to', async () => {
        const { ephemeral, wrapped } = await sealed()
        const t = { commit_k: Buffer.from(commitResponseKey(K)).toString('base64') } as Ticket
        unwrapped.length = 0
        await expect(openResponseKey(wrapped, ephemeral, t)).rejects.toBeInstanceOf(CommitKMismatchError)
        // The refused key is zeroed, not left for the caller to forget.
        expect(unwrapped).toHaveLength(1)
        expect(unwrapped[0]).toEqual(new Uint8Array(32))
    })

    it('throws ResponseKeyUnwrapError under the wrong identity', async () => {
        const { wrapped } = await sealed()
        const other = await generateEphemeralIdentity()
        await expect(openResponseKey(wrapped, other, { commit_k: '' } as Ticket)).rejects.toBeInstanceOf(
            ResponseKeyUnwrapError,
        )
    })

    it('throws ResponseKeyUnwrapError on a header that is not base64', async () => {
        const ephemeral = await generateEphemeralIdentity()
        await expect(openResponseKey('!!', ephemeral, { commit_k: '' } as Ticket)).rejects.toBeInstanceOf(
            ResponseKeyUnwrapError,
        )
    })
})
