/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity test for the RESPONSE-SEALING FRAMING. Loads
// proto/testdata/sealed_vectors.json (produced by
// proto/go/wire/sealed_vectors_test.go) and asserts the TypeScript openers can
// read bytes the Go sealer produced.
//
// Why this file exists: vectors.json pins the AAD *bytes* for all five
// variants, but nothing pinned the framing that carries them —
// base64(nonce || ciphertext) for stream frames and sealed headers, the
// {nonce, ciphertext} ResponseEnvelope JSON for a non-streaming body, and the
// age-wrapped K_response in X-Zs-Response-Key. Every decrypt assertion in
// wire.test.ts is fed by the TS ResponseSealer, so both halves of the round
// trip move together: swapping seal.ts to emit ciphertext||nonce and wrap.ts to
// read it back that way passes the entire suite while diverging from Go.
//
// Opening Go-produced bytes closes that loop. Combined with wire.test.ts
// (TS sealer ≡ TS opener), this gives Go format ≡ TS opener ≡ TS sealer.
//
// If this fails, the two implementations have drifted on response framing.
// Fix the divergence — do NOT regenerate the fixture to make it pass unless the
// framing changed deliberately, in which case update proto/SPEC.md § 5 / § 6
// and both implementations in the same change.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { hex } from '@scure/base'

import {
    decryptBody,
    decryptSSEDataValue,
    openSealedHeader,
    unwrapResponseKey,
    RESPONSE_KEY_SIZE,
} from '../src/wire/index.js'

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

interface SealedVectorsFile {
    version: number
    comment: string
    tx_id: string
    ticket_id: string
    response_key_hex: string
    age_identity: string
    age_recipient: string
    wrapped_key_b64: string
    body_plaintext_hex: string
    body_envelope_json: string
    frames: SealedFrame[]
    headers: SealedHeader[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsFile = path.resolve(here, '..', '..', 'testdata', 'sealed_vectors.json')
const v = JSON.parse(fs.readFileSync(vectorsFile, 'utf8')) as SealedVectorsFile

const key = hex.decode(v.response_key_hex)
const enc = new TextEncoder()

describe('sealed_vectors.json', () => {
    it('is the schema this test expects', () => {
        expect(v.version).toBe(1)
        expect(key.length).toBe(RESPONSE_KEY_SIZE)
        expect(v.frames.length).toBeGreaterThan(0)
        expect(v.headers.length).toBeGreaterThan(0)
    })

    it('unwraps the age-wrapped response key the Go sealer produced', async () => {
        const got = await unwrapResponseKey(v.wrapped_key_b64, {
            secret: v.age_identity,
            recipient: v.age_recipient,
        })
        expect(got).toEqual(key)
    })

    it('opens the non-streaming body envelope the Go sealer produced', () => {
        const got = decryptBody(enc.encode(v.body_envelope_json), key, v.tx_id, v.ticket_id)
        expect(got).toEqual(hex.decode(v.body_plaintext_hex))
    })

    describe('stream frames', () => {
        for (const f of v.frames) {
            it(`opens frame ${f.index} at its committed index`, () => {
                const got = decryptSSEDataValue(f.data_b64, key, v.tx_id, v.ticket_id, f.index)
                expect(got).toEqual(hex.decode(f.plaintext_hex))
            })

            // The frame index is AAD-bound, so the same bytes must not open at a
            // neighbouring index. Without this a fixture whose indices were all
            // 0 would still pass above.
            it(`refuses frame ${f.index} at index ${f.index + 1}`, () => {
                expect(() =>
                    decryptSSEDataValue(f.data_b64, key, v.tx_id, v.ticket_id, f.index + 1),
                ).toThrow(/aead open/)
            })
        }
    })

    describe('sealed headers', () => {
        for (const h of v.headers) {
            it(`opens the ${h.name} header the Go sealer produced`, () => {
                const got = openSealedHeader(h.value_b64, key, v.tx_id, v.ticket_id, h.name)
                expect(got).toEqual(hex.decode(h.plaintext_hex))
            })

            // The name is AAD-bound — that is what stops a receipt ciphertext
            // being replayed as a settle group.
            it(`refuses the ${h.name} header under the other name`, () => {
                const other = v.headers.find((o) => o.name !== h.name)
                expect(other).toBeDefined()
                expect(() =>
                    openSealedHeader(h.value_b64, key, v.tx_id, v.ticket_id, other!.name),
                ).toThrow(/aead open/)
            })
        }
    })
})
