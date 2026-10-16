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
    parseTicketJSON,
    ticketCanonicalBytes,
    ticketSigDigest,
    type Ticket,
} from '../src/ticket/ticket.js'
import {
    parseReceiptJSON,
    receiptCanonicalBytes,
    receiptSigDigest,
    type UsageReceipt,
} from '../src/ticket/receipt.js'
import {
    ephemeralCanonicalBytes,
    ephemeralCanonicalBytesV2,
    ephemeralSigDigest,
    ephemeralSigDigestV2,
    type EphemeralAdvertisement,
} from '../src/ticket/ephemeral.js'
import {
    RAIL_ALGORAND,
    RAIL_SOLANA,
    algorandDeploymentId,
    decodeDeploymentId,
    encodeDeploymentId,
    newDeploymentId,
    solanaDeploymentId,
} from '../src/ticket/deployment.js'
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
    ticket_edge: { value: Ticket; canonical_bytes_hex: string; sig_digest_hex: string }
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
    deployment_algorand: DeploymentVector
    deployment_solana: DeploymentVector
    ticket_v3: { value: Ticket; canonical_bytes_hex: string; sig_digest_hex: string }
    receipt_v3: { value: UsageReceipt; canonical_bytes_hex: string; sig_digest_hex: string }
    reserve_request_v2: {
        operator_id: number
        node_id: number
        value: ReserveRequest
        canonical_bytes_hex: string
        sig_digest_hex: string
    }
    ephemeral_advertisement_v2: {
        operator_id: number
        node_id: number
        value: EphemeralAdvertisement
        canonical_bytes_hex: string
        sig_digest_hex: string
    }
    deployment_malformed: string[]
}

interface DeploymentVector {
    rail: number
    genesis_hash_hex: string
    escrow_hex: string
    expected_hex: string
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'vectors.json')
const raw = fs.readFileSync(vectorsPath, 'utf-8')
const vectors = JSON.parse(raw) as VectorsFile

describe('cross-impl golden vectors (proto/testdata/vectors.json)', () => {
    it('vectors file is current schema', () => {
        expect(vectors.version).toBe(7)
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

    // stream false, empty strings and a negative expires_at.
    it('edge ticket canonicalBytes and sig digest', () => {
        const v = vectors.ticket_edge
        expect([v.value.stream, v.value.model, v.value.expires_at]).toEqual([false, '', -1])
        expect(bytesToHex(ticketCanonicalBytes(v.value))).toBe(v.canonical_bytes_hex)
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

    it('deployment ids (Algorand and Solana)', () => {
        const a = vectors.deployment_algorand
        expect(a.rail).toBe(RAIL_ALGORAND)
        expect(bytesToHex(algorandDeploymentId(hexToBytes(a.genesis_hash_hex), BigInt('0x' + a.escrow_hex)))).toBe(
            a.expected_hex,
        )
        expect(bytesToHex(newDeploymentId(a.rail, hexToBytes(a.genesis_hash_hex), hexToBytes(a.escrow_hex)))).toBe(
            a.expected_hex,
        )
        const s = vectors.deployment_solana
        expect(s.rail).toBe(RAIL_SOLANA)
        expect(bytesToHex(solanaDeploymentId(hexToBytes(s.genesis_hash_hex), hexToBytes(s.escrow_hex)))).toBe(
            s.expected_hex,
        )
    })

    // The bound values are the unbound ones plus the Algorand deployment id.
    it('bound layouts carry the vector deployment id', () => {
        const id = encodeDeploymentId(hexToBytes(vectors.deployment_algorand.expected_hex))
        expect(vectors.ticket_v3.value.deployment).toBe(id)
        expect(vectors.receipt_v3.value.deployment).toBe(id)
        expect(vectors.reserve_request_v2.value.deployment).toBe(id)
        expect(vectors.ephemeral_advertisement_v2.value.ephemeral_deployment).toBe(id)
    })

    // Go refuses each of these in the JSON decode; so must the strict readers,
    // the empty string included.
    it('malformed deployment ids are refused', () => {
        expect(vectors.deployment_malformed).toContain('')
        const enc = new TextEncoder()
        for (const v of vectors.deployment_malformed) {
            expect(() => decodeDeploymentId(v), JSON.stringify(v)).toThrow()
            const ticket = enc.encode(JSON.stringify({ ...vectors.ticket.value, deployment: v }))
            expect(() => parseTicketJSON(ticket), `ticket ${JSON.stringify(v)}`).toThrow()
            const receipt = enc.encode(JSON.stringify({ ...vectors.receipt.value, deployment: v }))
            expect(() => parseReceiptJSON(receipt), `receipt ${JSON.stringify(v)}`).toThrow()
        }
    })

    it('ticket v3 canonicalBytes and sig digest', () => {
        const v = vectors.ticket_v3
        expect(bytesToHex(ticketCanonicalBytes(v.value))).toBe(v.canonical_bytes_hex)
        expect(bytesToHex(ticketSigDigest(v.value))).toBe(v.sig_digest_hex)
    })

    it('receipt v3 canonicalBytes and sig digest', () => {
        const v = vectors.receipt_v3
        expect(bytesToHex(receiptCanonicalBytes(v.value))).toBe(v.canonical_bytes_hex)
        expect(bytesToHex(receiptSigDigest(v.value))).toBe(v.sig_digest_hex)
    })

    it('reserve request v2 canonicalBytes and sig digest', () => {
        const v = vectors.reserve_request_v2
        expect(bytesToHex(reserveCanonicalBytes(v.operator_id, v.node_id, v.value))).toBe(v.canonical_bytes_hex)
        expect(bytesToHex(reserveSigDigest(v.operator_id, v.node_id, v.value))).toBe(v.sig_digest_hex)
    })

    it('ephemeral advertisement v2 canonicalBytes and sig digest', () => {
        const v = vectors.ephemeral_advertisement_v2
        expect(bytesToHex(ephemeralCanonicalBytesV2(v.operator_id, v.node_id, v.value))).toBe(v.canonical_bytes_hex)
        expect(bytesToHex(ephemeralSigDigestV2(v.operator_id, v.node_id, v.value))).toBe(v.sig_digest_hex)
        // The legacy layout ignores the binding.
        expect(bytesToHex(ephemeralCanonicalBytes(v.operator_id, v.node_id, v.value))).toBe(
            vectors.ephemeral_advertisement.canonical_bytes_hex,
        )
    })
})
