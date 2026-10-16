/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl SEALED-FRAMING fixture, TS → Go direction. Generates
// proto/testdata/ts_sealed_vectors.json; proto/go/wire/ts_sealed_vectors_test.go
// opens every artifact in it with the production Go openers.
//
// sealed_vectors.json pins Go-sealed bytes that TS opens. Nothing pinned the
// reverse, which is the direction that carries money in production: the chat
// client seals every inference request (wrapRequest) and reserve request
// (sealReserveRequest) in TS, and only a Go node ever opens them. Each suite
// round-trips its own sealer, so a framing change made consistently inside TS —
// say, a renamed inner-header key in encodeInnerRequest and decodeInnerRequest —
// stays green here while every node refuses the requests.
//
// Like sealed_vectors.json these are CAPTURED, not derived: age wrapping and
// AEAD nonces are random, so regenerating churns every byte. Do it only when
// the framing changed deliberately, and update proto/SPEC.md § 5 / § 6 in the
// same change:
//
//   cd proto && make update-ts-sealed-vectors
//
// Every run, update mode included, then checks the committed artifacts open with
// the TS openers, so a broken fixture fails on both sides rather than only Go's.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import * as age from 'age-encryption'
import { base64, hex } from '@scure/base'

import {
    decryptBody,
    decryptRequest,
    decryptSSEDataValue,
    encodeInnerRequest,
    generateEphemeralIdentity,
    openSealedHeader,
    ResponseSealer,
    openSettleAck,
    sealReserveRequest,
    sealSettleAck,
    SEALED_HEADER_RECEIPT,
    SEALED_HEADER_SETTLE_GROUP,
    unwrapResponseKey,
    wrapRequest,
} from '../src/wire/index.js'

interface SealedRequest {
    name: string
    body_hex: string
    admission_tag_hex: string
    // The inner header's open_group; '' when the payer submitted the open.
    open_group: string
    // Sealed under the rail-neutral names (payment_ref, payment_open).
    neutral_names: boolean
    envelope_json: string
}

// An artifact both openers must refuse: it names one payment value under the
// legacy and the rail-neutral name, differently.
interface RefusedArtifact {
    name: string
    envelope_json: string
}

interface SealedFrame {
    index: number
    plaintext_hex: string
    data_b64: string
}

interface SealedHeader {
    name: string
    plaintext_hex: string
    value_b64: string
}

interface TSSealedVectorsFile {
    version: number
    comment: string
    tx_id: string
    ticket_id: string
    // Throwaway identities generated for this fixture alone; they protect
    // nothing. The node identity opens requests; the reply identity is the
    // payer's ephemeral, named inside each request and used to wrap K_response.
    node_age_identity: string
    node_age_recipient: string
    reply_age_identity: string
    reply_age_recipient: string
    requests: SealedRequest[]
    reserve_request_body_hex: string
    reserve_request_envelope_json: string
    // A sealed settle ack, opened by Go's OpenSettleAck.
    settle_ack_ticket_id: string
    settle_ack_group: string
    settle_ack_envelope_json: string
    // The same ack sealed under the rail-neutral name (payment_settle).
    settle_ack_neutral_envelope_json: string
    refused_requests: RefusedArtifact[]
    refused_settle_acks: RefusedArtifact[]
    response_key_hex: string
    wrapped_key_b64: string
    body_plaintext_hex: string
    body_envelope_json: string
    frames: SealedFrame[]
    headers: SealedHeader[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsFile = path.resolve(here, '..', '..', 'testdata', 'ts_sealed_vectors.json')
const UPDATE = process.env.ZS_UPDATE_TS_SEALED_VECTORS === '1'

const enc = new TextEncoder()
const dec = new TextDecoder()

async function build(): Promise<TSSealedVectorsFile> {
    const txID = 'TX-TS-SEALED-001'
    const ticketID = 'TKT-TS-SEALED-001'
    const node = await generateEphemeralIdentity()
    const reply = await generateEphemeralIdentity()

    // Distinct from sealed_vectors.json's 0xA0.. key and vectors.json's keys,
    // so a fixture mix-up cannot pass.
    const key = Uint8Array.from({ length: 32 }, (_, i) => 0xc0 + i)
    const tag = Uint8Array.from({ length: 32 }, (_, i) => 0x10 + i)

    const requestBody = enc.encode('{"model":"ts-sealed-vector","messages":[{"role":"user","content":"hi"}]}')
    const requests: SealedRequest[] = []
    for (const [name, admissionTag, openGroup, neutralNames] of [
        ['with_admission_tag', tag, '', false],
        ['without_admission_tag', undefined, '', false],
        ['with_open_group', tag, 'kgEC-ts-sealed-open-group', false],
        ['with_neutral_names', tag, 'kgEC-ts-sealed-open-group', true],
    ] as const) {
        const { envelope } = await wrapRequest({
            body: requestBody,
            txID,
            ticketID,
            admissionTag,
            nodeRecipient: node.recipient,
            ephemeral: reply,
            ...(openGroup ? { openGroup } : {}),
            neutralNames,
        })
        requests.push({
            name,
            body_hex: hex.encode(requestBody),
            admission_tag_hex: admissionTag ? hex.encode(admissionTag) : '',
            open_group: openGroup,
            neutral_names: neutralNames,
            envelope_json: dec.decode(envelope),
        })
    }

    const reserveBody = enc.encode('{"model":"ts-sealed-vector","payer_addr":"TS-SEALED-PAYER"}')
    const reserveEnvelope = await sealReserveRequest(reserveBody, node.recipient)
    const settleAck = { ticket_id: ticketID, settle_group: 'kgEC-ts-sealed-settle-group' }
    const settleAckEnvelope = await sealSettleAck(settleAck, node.recipient)
    const settleAckNeutralEnvelope = await sealSettleAck(settleAck, node.recipient, true)

    // wrapRequest and sealSettleAck can't write a disagreeing pair, so these
    // are framed and sealed by hand.
    const refusedRequests: RefusedArtifact[] = []
    for (const [name, fields] of [
        ['refs_disagree', { algorand_tx_id: txID, payment_ref: 'TX-TS-SEALED-OTHER' }],
        ['opens_disagree', { payment_ref: txID, open_group: 'kgEC-a', payment_open: 'kgEC-b' }],
    ] as const) {
        const e = new age.Encrypter()
        e.addRecipient(node.recipient)
        const inner = encodeInnerRequest({ reply_to_public_key: reply.recipient, ticket_id: ticketID, ...fields }, requestBody)
        const env = { ciphertext: base64.encode(await e.encrypt(inner)) }
        refusedRequests.push({ name, envelope_json: JSON.stringify(env) })
    }
    const refusedSettleAcks: RefusedArtifact[] = [
        {
            name: 'groups_disagree',
            envelope_json: dec.decode(
                await sealReserveRequest(
                    enc.encode(JSON.stringify({ ticket_id: ticketID, settle_group: 'kgEC-a', payment_settle: 'kgEC-b' })),
                    node.recipient,
                ),
            ),
        },
    ]

    const bodySealer = await ResponseSealer.create({ replyTo: reply.recipient, txID, ticketID, key })
    const bodyPlaintext = enc.encode('{"id":"ts-sealed-vector","object":"chat.completion"}')
    const bodyEnvelope = bodySealer.sealBody(bodyPlaintext)

    // A second sealer for the stream so frame indices don't depend on whether
    // the body was sealed first; headers go between frames 1 and 2 to pin that
    // sealHeader does not advance the counter.
    const streamSealer = await ResponseSealer.create({ replyTo: reply.recipient, txID, ticketID, key })
    const framePlaintexts = [
        'data: {"choices":[{"delta":{"content":"ts sealed"}}]}',
        'data: {"choices":[{"delta":{"content":" vector"}}]}',
        'data: [DONE]',
    ].map((s) => enc.encode(s))
    const frames: SealedFrame[] = []
    const headers: SealedHeader[] = []
    framePlaintexts.forEach((pt, i) => {
        if (i === 2) {
            for (const [name, text] of [
                [SEALED_HEADER_SETTLE_GROUP, '{"settle_group":"ts-sealed-vector-group"}'],
                [SEALED_HEADER_RECEIPT, '{"ticket_id":"TKT-TS-SEALED-001","amount_charged":4500}'],
            ] as const) {
                const p = enc.encode(text)
                headers.push({ name, plaintext_hex: hex.encode(p), value_b64: streamSealer.sealHeader(name, p) })
            }
        }
        frames.push({ index: i, plaintext_hex: hex.encode(pt), data_b64: streamSealer.sealStreamFrame(pt) })
    })

    return {
        version: 1,
        comment:
            'Cross-impl sealed-framing fixture, TS -> Go. Captured (not derived): age wrapping and ' +
            'nonces are random. Every implementation verifies by OPENING each artifact. Generated by ' +
            'proto/ts/test/ts-sealed-vectors.test.ts; regenerate with `cd proto && make update-ts-sealed-vectors`.',
        tx_id: txID,
        ticket_id: ticketID,
        node_age_identity: node.secret,
        node_age_recipient: node.recipient,
        reply_age_identity: reply.secret,
        reply_age_recipient: reply.recipient,
        requests,
        reserve_request_body_hex: hex.encode(reserveBody),
        reserve_request_envelope_json: dec.decode(reserveEnvelope),
        settle_ack_ticket_id: settleAck.ticket_id,
        settle_ack_group: settleAck.settle_group,
        settle_ack_envelope_json: dec.decode(settleAckEnvelope),
        settle_ack_neutral_envelope_json: dec.decode(settleAckNeutralEnvelope),
        refused_requests: refusedRequests,
        refused_settle_acks: refusedSettleAcks,
        response_key_hex: hex.encode(key),
        wrapped_key_b64: streamSealer.wrappedKeyHeader(),
        body_plaintext_hex: hex.encode(bodyPlaintext),
        body_envelope_json: dec.decode(bodyEnvelope),
        frames,
        headers,
    }
}

if (UPDATE) {
    const v = await build()
    fs.writeFileSync(vectorsFile, JSON.stringify(v, null, 4) + '\n')
}

const v = JSON.parse(fs.readFileSync(vectorsFile, 'utf8')) as TSSealedVectorsFile
const key = hex.decode(v.response_key_hex)

describe('ts_sealed_vectors.json opens with the TS openers', () => {
    it('is the schema this test expects', () => {
        expect(v.version).toBe(1)
        expect(v.requests.map((r) => r.name)).toEqual([
            'with_admission_tag',
            'without_admission_tag',
            'with_open_group',
            'with_neutral_names',
        ])
        expect(v.frames.length).toBeGreaterThan(0)
        expect(v.headers.length).toBe(2)
    })

    for (const r of v.requests) {
        it(`decrypts the ${r.name} request envelope`, async () => {
            const got = await decryptRequest(enc.encode(r.envelope_json), v.node_age_identity)
            expect(got.body).toEqual(hex.decode(r.body_hex))
            expect(got.replyToRecipient).toBe(v.reply_age_recipient)
            expect(got.algorandTxID).toBe(v.tx_id)
            expect(got.ticketID).toBe(v.ticket_id)
            expect(got.admissionTag ? hex.encode(got.admissionTag) : '').toBe(r.admission_tag_hex)
            expect(got.openGroup).toBe(r.open_group)
            expect(got.neutralNames).toBe(r.neutral_names)
        })
    }

    for (const [name, json, neutralNames] of [
        ['settle_group', v.settle_ack_envelope_json, false],
        ['payment_settle', v.settle_ack_neutral_envelope_json, true],
    ] as const) {
        it(`opens the settle ack sent as ${name}`, async () => {
            expect(await openSettleAck(enc.encode(json), v.node_age_identity)).toEqual({
                ticket_id: v.settle_ack_ticket_id,
                settle_group: v.settle_ack_group,
                neutralNames,
            })
        })
    }

    it('carries the artifacts that must be refused', () => {
        expect(v.refused_requests.map((r) => r.name)).toEqual(['refs_disagree', 'opens_disagree'])
        expect(v.refused_settle_acks.map((r) => r.name)).toEqual(['groups_disagree'])
    })

    for (const r of v.refused_requests) {
        it(`refuses the ${r.name} request`, async () => {
            await expect(decryptRequest(enc.encode(r.envelope_json), v.node_age_identity)).rejects.toThrow(/disagree/)
        })
    }

    for (const r of v.refused_settle_acks) {
        it(`refuses the ${r.name} settle ack`, async () => {
            await expect(openSettleAck(enc.encode(r.envelope_json), v.node_age_identity)).rejects.toThrow(/disagree/)
        })
    }

    it('unwraps the wrapped response key', async () => {
        const got = await unwrapResponseKey(v.wrapped_key_b64, {
            secret: v.reply_age_identity,
            recipient: v.reply_age_recipient,
        })
        expect(got).toEqual(key)
    })

    it('opens the body envelope', () => {
        expect(decryptBody(enc.encode(v.body_envelope_json), key, v.tx_id, v.ticket_id)).toEqual(
            hex.decode(v.body_plaintext_hex),
        )
    })

    for (const f of v.frames) {
        it(`opens frame ${f.index}`, () => {
            expect(decryptSSEDataValue(f.data_b64, key, v.tx_id, v.ticket_id, f.index)).toEqual(
                hex.decode(f.plaintext_hex),
            )
        })
    }

    for (const h of v.headers) {
        it(`opens the ${h.name} header`, () => {
            expect(openSealedHeader(h.value_b64, key, v.tx_id, v.ticket_id, h.name)).toEqual(
                hex.decode(h.plaintext_hex),
            )
        })
    }
})
