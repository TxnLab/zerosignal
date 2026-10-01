/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'

import {
    ADMISSION_TAG_SIZE,
    NONCE_SIZE,
    RESPONSE_KEY_SIZE,
    SEALED_HEADER_RECEIPT,
    SEALED_HEADER_SETTLE_GROUP,
    buildBodyAAD,
    buildFrameAAD,
    bodyHashFromFrames,
    bodyHashOfBody,
    computeAdmissionTag,
    decryptBody,
    decryptRequest,
    decryptSSEDataValue,
    openSealedHeader,
    ResponseSealer,
    unwrapResponseKey,
    wrapRequest,
    type EphemeralIdentity,
} from '../src/wire/index.js'
import { newTestNode, randomBytes } from './helpers.js'

describe('AAD layout', () => {
    it('body AAD has the expected hayai\\0body\\0txID\\0ticketID shape', () => {
        const aad = buildBodyAAD('TX1', 'TKT1')
        const expected = new Uint8Array([
            ...new TextEncoder().encode('zs'),
            0,
            ...new TextEncoder().encode('body'),
            0,
            ...new TextEncoder().encode('TX1'),
            0,
            ...new TextEncoder().encode('TKT1'),
        ])
        expect(aad).toEqual(expected)
    })

    it('body AAD with empty ticketID still has trailing separator (no ticket bytes)', () => {
        const aad = buildBodyAAD('TX1', '')
        const expected = new Uint8Array([
            ...new TextEncoder().encode('zs'),
            0,
            ...new TextEncoder().encode('body'),
            0,
            ...new TextEncoder().encode('TX1'),
            0,
        ])
        expect(aad).toEqual(expected)
    })

    it('frame AAD includes 8-byte big-endian frame index', () => {
        const aad = buildFrameAAD('TX1', 'TKT1', 1)
        const idx = new Uint8Array([0, 0, 0, 0, 0, 0, 0, 1])
        const expected = new Uint8Array([
            ...new TextEncoder().encode('zs'),
            0,
            ...new TextEncoder().encode('frame'),
            0,
            ...new TextEncoder().encode('TX1'),
            0,
            ...new TextEncoder().encode('TKT1'),
            0,
            ...idx,
        ])
        expect(aad).toEqual(expected)
    })

    it('body and frame AAD differ at the same txID/ticketID', () => {
        const body = buildBodyAAD('TX', 'TKT')
        const frame = buildFrameAAD('TX', 'TKT', 0)
        expect(Array.from(body)).not.toEqual(Array.from(frame))
    })
})

describe('admission tag', () => {
    it('is deterministic on identical inputs', () => {
        const k = randomBytes(RESPONSE_KEY_SIZE)
        const a = computeAdmissionTag(k, 'TKT', 'TX', new TextEncoder().encode('hello'))
        const b = computeAdmissionTag(k, 'TKT', 'TX', new TextEncoder().encode('hello'))
        expect(a).toEqual(b)
        expect(a.length).toBe(ADMISSION_TAG_SIZE)
    })

    it('changes when any input is perturbed', () => {
        const k = new Uint8Array(RESPONSE_KEY_SIZE).fill(0x11)
        const ticket = 'dGlja2V0aWRiYXNlNjQhIQ=='
        const tx = 'TXID0123456789ABCDEFGHIJKLMNOPQR'
        const body = new TextEncoder().encode('hello')
        const base = computeAdmissionTag(k, ticket, tx, body)

        const k2 = new Uint8Array(k)
        k2[0] = (k2[0]! ^ 0x01) & 0xff
        expect(computeAdmissionTag(k2, ticket, tx, body)).not.toEqual(base)

        expect(computeAdmissionTag(k, ticket + 'x', tx, body)).not.toEqual(base)
        expect(computeAdmissionTag(k, ticket, tx + 'x', body)).not.toEqual(base)

        const body2 = new Uint8Array(body)
        body2[0] = (body2[0]! ^ 0x01) & 0xff
        expect(computeAdmissionTag(k, ticket, tx, body2)).not.toEqual(base)

        // Boundary shift: moving a char from ticket→tx must change the
        // tag (NUL separator does its job).
        expect(computeAdmissionTag(k, ticket + 'A', tx.slice(1), body)).not.toEqual(base)
    })
})

describe('body hash', () => {
    it('computes sha256 over a single non-streaming body', () => {
        const out = bodyHashOfBody(new TextEncoder().encode('hello'))
        expect(out.length).toBe(32)
        // Identical inputs → identical output.
        expect(bodyHashOfBody(new TextEncoder().encode('hello'))).toEqual(out)
    })

    it('streaming hash matches sha256 of concatenated frames', () => {
        const frames = [new TextEncoder().encode('a'), new TextEncoder().encode('bc'), new TextEncoder().encode('def')]
        const concat = new TextEncoder().encode('abcdef')
        expect(bodyHashFromFrames(frames)).toEqual(bodyHashOfBody(concat))
    })

    it('is order-sensitive', () => {
        const a = bodyHashFromFrames([new TextEncoder().encode('x'), new TextEncoder().encode('y')])
        const b = bodyHashFromFrames([new TextEncoder().encode('y'), new TextEncoder().encode('x')])
        expect(a).not.toEqual(b)
    })
})

describe('wrap / decrypt request round-trip', () => {
    it('age-decrypts back to the original body', async () => {
        const node = await newTestNode()
        const body = new TextEncoder().encode('{"model":"gpt-4"}')

        const { envelope, ephemeral } = await wrapRequest({
            body,
            txID: 'TX123',
            ticketID: '',
            nodeRecipient: node.recipient,
        })

        // The envelope carries nothing but ciphertext — the identifiers ride
        // inside the seal, where a forwarding relay cannot read them.
        const parsed = JSON.parse(new TextDecoder().decode(envelope))
        expect(Object.keys(parsed)).toEqual(['ciphertext'])
        expect(new TextDecoder().decode(envelope)).not.toContain('TX123')

        const dec = await decryptRequest(envelope, node.secret)
        expect(dec.body).toEqual(body)
        expect(dec.algorandTxID).toBe('TX123')
        expect(dec.replyToRecipient).toBe(ephemeral.recipient)
    })

    it('produces a fresh ephemeral on every call', async () => {
        const node = await newTestNode()
        const body = new TextEncoder().encode('x')
        const a = await wrapRequest({ body, txID: 'TX', ticketID: '', nodeRecipient: node.recipient })
        const b = await wrapRequest({ body, txID: 'TX', ticketID: '', nodeRecipient: node.recipient })
        expect(a.ephemeral.recipient).not.toBe(b.ephemeral.recipient)
    })

    it('round-trips an empty body', async () => {
        const node = await newTestNode()
        const { envelope } = await wrapRequest({
            body: new Uint8Array(0),
            txID: 'TX',
            ticketID: '',
            nodeRecipient: node.recipient,
        })
        const dec = await decryptRequest(envelope, node.secret)
        expect(dec.body.length).toBe(0)
    })

    it('round-trips a 32-byte admission tag', async () => {
        const node = await newTestNode()
        const tag = new Uint8Array(ADMISSION_TAG_SIZE).fill(0x5a)
        const { envelope } = await wrapRequest({
            body: new TextEncoder().encode('hi'),
            txID: 'TX',
            ticketID: 'TKT',
            admissionTag: tag,
            nodeRecipient: node.recipient,
        })
        const dec = await decryptRequest(envelope, node.secret)
        expect(dec.admissionTag).toEqual(tag)
    })

    it('rejects an admission tag of the wrong length', async () => {
        const node = await newTestNode()
        const { envelope } = await wrapRequest({
            body: new TextEncoder().encode('hi'),
            txID: 'TX',
            ticketID: 'TKT',
            admissionTag: new Uint8Array([0x01, 0x02]),
            nodeRecipient: node.recipient,
        })
        await expect(decryptRequest(envelope, node.secret)).rejects.toThrow(/admission_tag length/)
    })
})

describe('response sealer / unwrap+decrypt', () => {
    async function setup(): Promise<{
        ephemeral: EphemeralIdentity
        sealer: ResponseSealer
        responseKey: Uint8Array
    }> {
        const ephemeral = (await newTestNode()) as EphemeralIdentity
        const sealer = await ResponseSealer.create({
            replyTo: ephemeral.recipient,
            txID: 'TX',
            ticketID: '',
        })
        const responseKey = await unwrapResponseKey(sealer.wrappedKeyHeader(), ephemeral)
        expect(responseKey.length).toBe(RESPONSE_KEY_SIZE)
        return { ephemeral, sealer, responseKey }
    }

    it('unwrapResponseKey returns a 32-byte key under the right identity', async () => {
        const { responseKey } = await setup()
        expect(responseKey.length).toBe(RESPONSE_KEY_SIZE)
    })

    it('unwrapResponseKey fails on non-base64 input', async () => {
        const ephemeral = (await newTestNode()) as EphemeralIdentity
        await expect(unwrapResponseKey('!!not-b64!!', ephemeral)).rejects.toThrow(/decode wrapped key/)
    })

    it('unwrapResponseKey fails under a different identity', async () => {
        const e1 = (await newTestNode()) as EphemeralIdentity
        const e2 = (await newTestNode()) as EphemeralIdentity
        const sealer = await ResponseSealer.create({ replyTo: e1.recipient, txID: 'TX', ticketID: '' })
        await expect(unwrapResponseKey(sealer.wrappedKeyHeader(), e2)).rejects.toBeTruthy()
    })

    it('decryptBody round-trips a sealed body', async () => {
        const { sealer, responseKey } = await setup()
        const plaintext = new TextEncoder().encode('{"ok":true}')
        const env = sealer.sealBody(plaintext)
        const got = decryptBody(env, responseKey, 'TX', '')
        expect(got).toEqual(plaintext)
    })

    it('decryptBody rejects bad json', async () => {
        const k = randomBytes(RESPONSE_KEY_SIZE)
        expect(() => decryptBody(new TextEncoder().encode('{bad'), k, 'TX', '')).toThrow(/parse response envelope/)
    })

    it('decryptBody rejects bad nonce length', async () => {
        const k = randomBytes(RESPONSE_KEY_SIZE)
        const env = new TextEncoder().encode(
            JSON.stringify({
                nonce: base64.encode(new TextEncoder().encode('short')),
                ciphertext: base64.encode(new TextEncoder().encode('xxxx')),
                algorand_tx_id: 'TX',
            }),
        )
        expect(() => decryptBody(env, k, 'TX', '')).toThrow(/invalid nonce length/)
    })

    it('decryptBody rejects a tampered ciphertext byte', async () => {
        const { sealer, responseKey } = await setup()
        const env = sealer.sealBody(new TextEncoder().encode('hi'))
        const parsed = JSON.parse(new TextDecoder().decode(env))
        const ct = base64.decode(parsed.ciphertext)
        ct[0] = (ct[0]! ^ 0xff) & 0xff
        parsed.ciphertext = base64.encode(ct)
        const tampered = new TextEncoder().encode(JSON.stringify(parsed))
        expect(() => decryptBody(tampered, responseKey, 'TX', '')).toThrow(/aead open/)
    })

    it('decryptBody rejects a response sealed under a different tx_id', async () => {
        const ephemeral = (await newTestNode()) as EphemeralIdentity
        const sealer = await ResponseSealer.create({ replyTo: ephemeral.recipient, txID: 'TX-REAL', ticketID: '' })
        const responseKey = await unwrapResponseKey(sealer.wrappedKeyHeader(), ephemeral)
        const env = sealer.sealBody(new TextEncoder().encode('hi'))
        // No tx_id echo to check any more — splice resistance is the AAD's job.
        expect(() => decryptBody(env, responseKey, 'TX-DIFFERENT', '')).toThrow(/aead open/)
    })

    it('decryptBody rejects splicing under a different txID (AAD mismatch)', async () => {
        // Attacker rewrites the echo to the txID the proxy will check
        // against, but the ciphertext was sealed under TX-SEALED. AAD
        // mismatch must break authentication.
        const ephemeral = (await newTestNode()) as EphemeralIdentity
        const sealer = await ResponseSealer.create({ replyTo: ephemeral.recipient, txID: 'TX-SEALED', ticketID: '' })
        const responseKey = await unwrapResponseKey(sealer.wrappedKeyHeader(), ephemeral)
        const env = sealer.sealBody(new TextEncoder().encode('hi'))
        const parsed = JSON.parse(new TextDecoder().decode(env))
        parsed.algorand_tx_id = 'TX-ATTACKER'
        const swapped = new TextEncoder().encode(JSON.stringify(parsed))
        expect(() => decryptBody(swapped, responseKey, 'TX-ATTACKER', '')).toThrow(/aead open/)
    })

    it('decryptSSEDataValue round-trips a sealed frame at the matching index', async () => {
        const { sealer, responseKey } = await setup()
        const b64 = sealer.sealStreamFrame(new TextEncoder().encode('frame0'))
        const got = decryptSSEDataValue(b64, responseKey, 'TX', '', 0)
        expect(got).toEqual(new TextEncoder().encode('frame0'))
    })

    it('decryptSSEDataValue fails when the frame index is wrong', async () => {
        // A frame sealed at index 3 must not open as index 2.
        const { sealer, responseKey } = await setup()
        for (let i = 0; i < 3; i++) sealer.sealStreamFrame(new TextEncoder().encode('skip'))
        const b64 = sealer.sealStreamFrame(new TextEncoder().encode('three'))
        expect(() => decryptSSEDataValue(b64, responseKey, 'TX', '', 2)).toThrow(/aead open/)
    })

    it('decryptSSEDataValue fails on too-short input', async () => {
        const k = randomBytes(RESPONSE_KEY_SIZE)
        const tiny = base64.encode(new TextEncoder().encode('short'))
        expect(() => decryptSSEDataValue(tiny, k, 'TX', '', 0)).toThrow(/sse frame too short/)
    })

    it('decryptSSEDataValue fails on a tampered ciphertext byte', async () => {
        const { sealer, responseKey } = await setup()
        const b64 = sealer.sealStreamFrame(new TextEncoder().encode('hi'))
        const raw = base64.decode(b64)
        raw[NONCE_SIZE] = (raw[NONCE_SIZE]! ^ 0xff) & 0xff
        const tampered = base64.encode(raw)
        expect(() => decryptSSEDataValue(tampered, responseKey, 'TX', '', 0)).toThrow(/aead open/)
    })
})

describe('sealed response metadata (X-Zs-Receipt / X-Zs-Settle-Group)', () => {
    const newSealer = async () => {
        const ephemeral = (await newTestNode()) as EphemeralIdentity
        const sealer = await ResponseSealer.create({ replyTo: ephemeral.recipient, txID: 'TX', ticketID: 'TKT' })
        const responseKey = await unwrapResponseKey(sealer.wrappedKeyHeader(), ephemeral)
        return { sealer, responseKey }
    }

    it('round-trips a sealed header', async () => {
        const { sealer, responseKey } = await newSealer()
        const plaintext = new TextEncoder().encode('{"ticket_id":"abc","amount_charged":42}')

        const value = sealer.sealHeader(SEALED_HEADER_RECEIPT, plaintext)
        expect(value).not.toContain('ticket_id')

        const got = openSealedHeader(value, responseKey, 'TX', 'TKT', SEALED_HEADER_RECEIPT)
        expect(got).toEqual(plaintext)
    })

    // The name is in the AAD, so a receipt cannot be presented as a settle
    // group (nor as a body or a stream frame).
    it('binds the metadata name into the AAD', async () => {
        const { sealer, responseKey } = await newSealer()
        const value = sealer.sealHeader(SEALED_HEADER_RECEIPT, new TextEncoder().encode('hi'))

        expect(() => openSealedHeader(value, responseKey, 'TX', 'TKT', SEALED_HEADER_SETTLE_GROUP)).toThrow(/aead open/)
        expect(() => decryptSSEDataValue(value, responseKey, 'TX', 'TKT', 0)).toThrow(/aead open/)
    })

    // A stream emits sealed content frames and a sealed settle-group header in
    // the same response, so sealHeader must not consume a frame index.
    it('does not advance the frame index', async () => {
        const { sealer, responseKey } = await newSealer()
        sealer.sealHeader(SEALED_HEADER_SETTLE_GROUP, new TextEncoder().encode('group'))

        const frame = sealer.sealStreamFrame(new TextEncoder().encode('first'))
        expect(decryptSSEDataValue(frame, responseKey, 'TX', 'TKT', 0)).toEqual(new TextEncoder().encode('first'))
    })
})
