/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import * as age from 'age-encryption'

import {
    SEALED_RESERVE_CONTENT_TYPE,
    SEALED_RESERVE_RESPONSE_CONTENT_TYPE,
    openReserveResponse,
    sealReserveRequest,
    sealReserveResponse,
    type EphemeralIdentity,
    type SealedReserveEnvelope,
} from '../src/wire/index.js'
import { ENCRYPTED_CONTENT_TYPE } from '../src/wire/constants.js'
import { newTestNode } from './helpers.js'

describe('sealReserveRequest', () => {
    it('round-trips through age to the operator identity', async () => {
        const op = await newTestNode()
        const plaintext = new TextEncoder().encode(
            JSON.stringify({
                model: 'gpt-4',
                input_count: 1024,
                max_output_count: 256,
                stream: true,
                payer_addr: 'AAAA',
            }),
        )

        const sealed = await sealReserveRequest(plaintext, op.recipient)

        const env = JSON.parse(new TextDecoder().decode(sealed)) as SealedReserveEnvelope
        expect(Object.keys(env)).toEqual(['ciphertext'])

        // payer_addr must not survive in the clear inside the sealed bytes.
        const sealedText = new TextDecoder().decode(sealed)
        expect(sealedText).not.toContain('payer_addr')
        expect(sealedText).not.toContain('AAAA')

        const d = new age.Decrypter()
        d.addIdentity(op.secret)
        const ciphertext = base64ToBytes(env.ciphertext)
        const recovered = await d.decrypt(ciphertext)
        expect(recovered).toEqual(plaintext)
    })

    it('does not decrypt with a different identity', async () => {
        const op = await newTestNode()
        const other = await newTestNode()
        const sealed = await sealReserveRequest(new TextEncoder().encode('{"model":"m"}'), op.recipient)
        const env = JSON.parse(new TextDecoder().decode(sealed)) as SealedReserveEnvelope
        const d = new age.Decrypter()
        d.addIdentity(other.secret)
        await expect(d.decrypt(base64ToBytes(env.ciphertext))).rejects.toBeDefined()
    })

    it('content-type differs from the inference envelope content-type', () => {
        expect(SEALED_RESERVE_CONTENT_TYPE).toBe('application/vnd.zs-reserve+json')
        expect(SEALED_RESERVE_CONTENT_TYPE).not.toBe(ENCRYPTED_CONTENT_TYPE)
    })
})

function base64ToBytes(b64: string): Uint8Array {
    const bin = atob(b64)
    const out = new Uint8Array(bin.length)
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
    return out
}

describe('sealReserveResponse / openReserveResponse', () => {
    it('round-trips to the caller ephemeral identity', async () => {
        const proxy = (await newTestNode()) as EphemeralIdentity
        const body = new TextEncoder().encode(
            '{"ticket":{"ticket_id":"abc"},"presigned_open_txn":"PAYERADDR"}',
        )

        const sealed = await sealReserveResponse(body, proxy.recipient)
        expect(new TextDecoder().decode(sealed)).not.toContain('PAYERADDR')

        const got = await openReserveResponse(sealed, proxy)
        expect(got).toEqual(body)
    })

    it('rejects the wrong identity', async () => {
        const proxy = (await newTestNode()) as EphemeralIdentity
        const other = (await newTestNode()) as EphemeralIdentity
        const sealed = await sealReserveResponse(new TextEncoder().encode('{}'), proxy.recipient)
        await expect(openReserveResponse(sealed, other)).rejects.toThrow()
    })

    it('rejects a missing ciphertext', async () => {
        const proxy = (await newTestNode()) as EphemeralIdentity
        await expect(
            openReserveResponse(new TextEncoder().encode('{}'), proxy),
        ).rejects.toThrow(/missing ciphertext/)
    })

    it('response content type is distinct from the request and inference ones', () => {
        expect(SEALED_RESERVE_RESPONSE_CONTENT_TYPE).not.toBe(SEALED_RESERVE_CONTENT_TYPE)
        expect(SEALED_RESERVE_RESPONSE_CONTENT_TYPE).not.toBe(ENCRYPTED_CONTENT_TYPE)
    })
})
