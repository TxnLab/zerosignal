/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl byte-parity test. Loads proto/testdata/vectors.json (the
// fixture produced by proto/go/ticket/vectors_test.go) and asserts
// every primitive — AAD, admission tag, body hash, canonical bytes,
// sig digests, address codec — produces byte-identical output to the
// Go reference. If this fails, the TS port has drifted from the Go
// source; update only after intentionally syncing both sides.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

import {
    bodyHashFromFrames,
    bodyHashOfBody,
    buildBodyAAD,
    buildFrameAAD,
    buildHeaderAAD,
    computeAdmissionTag,
} from '../src/wire/index.js'
import {
    commitResponseKey,
    ticketCanonicalBytes,
    ticketSigDigest,
    type Ticket,
} from '../src/ticket/ticket.js'
import {
    receiptCanonicalBytes,
    receiptSigDigest,
    type UsageReceipt,
} from '../src/ticket/receipt.js'
import {
    ephemeralCanonicalBytes,
    ephemeralSigDigest,
    type EphemeralAdvertisement,
} from '../src/ticket/ephemeral.js'
import {
    reserveCanonicalBytes,
    reserveSigDigest,
    type ReserveRequest,
} from '../src/ticket/reserve.js'
import { encodeAlgorandAddress } from '../src/ticket/signing.js'

interface VectorsFile {
    version: number
    comment: string
    aad_body_with_ticket: { tx_id: string; ticket_id: string; expected_hex: string }
    aad_body_no_ticket: { tx_id: string; ticket_id: string; expected_hex: string }
    aad_frame: { tx_id: string; ticket_id: string; frame_index: number; expected_hex: string }
    aad_header_receipt: { tx_id: string; ticket_id: string; name: string; expected_hex: string }
    aad_header_settle_group: { tx_id: string; ticket_id: string; name: string; expected_hex: string }
    admission_tag: {
        k_hex: string
        ticket_id: string
        tx_id: string
        body_hex: string
        expected_hex: string
    }
    body_hash_single: { body_hex: string; expected_hex: string }
    body_hash_frames: { frames_hex: string[]; expected_hex: string }
    commit_response_key: { k_hex: string; expected_hex: string }
    ticket: { value: Ticket; canonical_bytes_hex: string; sig_digest_hex: string }
    receipt: { value: UsageReceipt; canonical_bytes_hex: string; sig_digest_hex: string }
    ephemeral_advertisement: {
        operator_id: number
        node_id: number
        value: EphemeralAdvertisement
        canonical_bytes_hex: string
        sig_digest_hex: string
    }
    reserve_request: {
        operator_id: number
        node_id: number
        value: ReserveRequest
        canonical_bytes_hex: string
        sig_digest_hex: string
    }
    algorand_address: { pubkey_hex: string; expected_address: string }
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'vectors.json')
const raw = fs.readFileSync(vectorsPath, 'utf-8')
const vectors = JSON.parse(raw) as VectorsFile

describe('cross-impl golden vectors (proto/testdata/vectors.json)', () => {
    it('vectors file is current schema', () => {
        expect(vectors.version).toBe(6)
    })

    it('AAD body (with ticket)', () => {
        const v = vectors.aad_body_with_ticket
        expect(bytesToHex(buildBodyAAD(v.tx_id, v.ticket_id))).toBe(v.expected_hex)
    })

    it('AAD body (empty ticket)', () => {
        const v = vectors.aad_body_no_ticket
        expect(bytesToHex(buildBodyAAD(v.tx_id, v.ticket_id))).toBe(v.expected_hex)
    })

    it('AAD frame (with frame index)', () => {
        const v = vectors.aad_frame
        expect(bytesToHex(buildFrameAAD(v.tx_id, v.ticket_id, v.frame_index))).toBe(v.expected_hex)
    })

    it('AAD header (receipt)', () => {
        const v = vectors.aad_header_receipt
        expect(bytesToHex(buildHeaderAAD(v.tx_id, v.ticket_id, v.name))).toBe(v.expected_hex)
    })

    it('AAD header (settle group)', () => {
        const v = vectors.aad_header_settle_group
        expect(bytesToHex(buildHeaderAAD(v.tx_id, v.ticket_id, v.name))).toBe(v.expected_hex)
    })

    it('admission tag HMAC', () => {
        const v = vectors.admission_tag
        const tag = computeAdmissionTag(
            hexToBytes(v.k_hex),
            v.ticket_id,
            v.tx_id,
            hexToBytes(v.body_hex),
        )
        expect(bytesToHex(tag)).toBe(v.expected_hex)
    })

    it('body hash (single body)', () => {
        const v = vectors.body_hash_single
        expect(bytesToHex(bodyHashOfBody(hexToBytes(v.body_hex)))).toBe(v.expected_hex)
    })

    it('body hash (concatenated frames)', () => {
        const v = vectors.body_hash_frames
        const frames = v.frames_hex.map(hexToBytes)
        expect(bytesToHex(bodyHashFromFrames(frames))).toBe(v.expected_hex)
    })

    it('commitResponseKey = sha256(K)', () => {
        const v = vectors.commit_response_key
        expect(bytesToHex(commitResponseKey(hexToBytes(v.k_hex)))).toBe(v.expected_hex)
    })

    it('ticket canonicalBytes', () => {
        const v = vectors.ticket
        expect(bytesToHex(ticketCanonicalBytes(v.value))).toBe(v.canonical_bytes_hex)
    })

    it('ticket sig digest = sha256(canonical)', () => {
        const v = vectors.ticket
        expect(bytesToHex(ticketSigDigest(v.value))).toBe(v.sig_digest_hex)
    })

    it('receipt canonicalBytes', () => {
        const v = vectors.receipt
        expect(bytesToHex(receiptCanonicalBytes(v.value))).toBe(v.canonical_bytes_hex)
    })

    it('receipt sig digest = sha256(canonical)', () => {
        const v = vectors.receipt
        expect(bytesToHex(receiptSigDigest(v.value))).toBe(v.sig_digest_hex)
    })

    it('ephemeral advertisement canonicalBytes', () => {
        const v = vectors.ephemeral_advertisement
        expect(bytesToHex(ephemeralCanonicalBytes(v.operator_id, v.node_id, v.value))).toBe(
            v.canonical_bytes_hex,
        )
    })

    it('ephemeral advertisement sig digest = sha256(canonical)', () => {
        const v = vectors.ephemeral_advertisement
        expect(bytesToHex(ephemeralSigDigest(v.operator_id, v.node_id, v.value))).toBe(v.sig_digest_hex)
    })

    it('reserve request canonicalBytes', () => {
        const v = vectors.reserve_request
        expect(bytesToHex(reserveCanonicalBytes(v.operator_id, v.node_id, v.value))).toBe(
            v.canonical_bytes_hex,
        )
    })

    it('reserve request sig digest = sha256(canonical)', () => {
        const v = vectors.reserve_request
        expect(bytesToHex(reserveSigDigest(v.operator_id, v.node_id, v.value))).toBe(v.sig_digest_hex)
    })

    it('Algorand address encode (pubkey → 58-char base32)', () => {
        const v = vectors.algorand_address
        expect(encodeAlgorandAddress(hexToBytes(v.pubkey_hex))).toBe(v.expected_address)
    })
})
