/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The deployment-binding verify rules. Mirrors proto/go/ticket/deployment_test.go;
// the byte layouts themselves are pinned by vectors.json.

import { describe, it, expect } from 'vitest'
import { base64 } from '@scure/base'

import {
    DeploymentMismatchError,
    LegacySignatureError,
    algorandDeploymentId,
    decodeDeploymentId,
    encodeDeploymentId,
    knownDeployment,
} from '../src/ticket/deployment.js'
import { parseTicketJSON, signTicket, verifyTicket, verifyTicketFor, type Ticket } from '../src/ticket/ticket.js'
import { parseReceiptJSON, signReceipt, verifyReceiptFor, type UsageReceipt } from '../src/ticket/receipt.js'
import { signReserveRequest, verifyReserveRequestFor, type ReserveRequest } from '../src/ticket/reserve.js'
import {
    DEFAULT_EPHEMERAL_SKEW_SEC,
    EphemeralExpiredError,
    signEphemeral,
    verifyEphemeral,
    verifyEphemeralFor,
    type EphemeralAdvertisement,
} from '../src/ticket/ephemeral.js'
import { UsageType } from '../src/ticket/usagetype.js'
import { newFakeSigner } from './helpers.js'

const genesis = (fill: number) => new Uint8Array(32).fill(fill)
const MINE = algorandDeploymentId(genesis(1), 100)
const OTHER = algorandDeploymentId(genesis(2), 100)
const MINE_S = encodeDeploymentId(MINE)

function ticket(deployment?: string): Ticket {
    return {
        ticket_id: base64.encode(new TextEncoder().encode('sixteen-byte-id!')),
        operator_id: 42,
        node_id: 7,
        input_count: 10,
        max_output_count: 20,
        input_rate: 2,
        output_rate: 4,
        max_price: 100,
        min_price: 1,
        expires_at: 1_700_000_000,
        model: 'm',
        stream: true,
        commit_k: base64.encode(new Uint8Array(32)),
        input_usage_type: UsageType.Tokens,
        output_usage_type: UsageType.Tokens,
        cache_read_rate: 1,
        ...(deployment ? { deployment } : {}),
    }
}

function receipt(deployment?: string): UsageReceipt {
    return {
        ticket_id: 'tid',
        actual_input_count: 10,
        actual_output_count: 5,
        amount_charged: 40,
        ttft_ms: 100,
        decode_ms: 200,
        body_hash: 'a'.repeat(64),
        input_usage_type: UsageType.Tokens,
        output_usage_type: UsageType.Tokens,
        aux_output_usage_type: UsageType.None,
        aux_output_count: 0,
        cached_input_count: 0,
        ...(deployment ? { deployment } : {}),
    }
}

describe('deployment id wire form', () => {
    it('refuses a short id and the all-zero id', () => {
        expect(() => decodeDeploymentId('AAAA')).toThrow()
        expect(() => decodeDeploymentId(base64.encode(new Uint8Array(32)))).toThrow()
        expect(decodeDeploymentId(MINE_S)).toEqual(MINE)
    })

    it('parseTicketJSON refuses a malformed deployment and keeps a good one', () => {
        const enc = (o: object) => new TextEncoder().encode(JSON.stringify(o))
        expect(() => parseTicketJSON(enc({ ...ticket(), deployment: 'AAAA' }))).toThrow()
        expect(parseTicketJSON(enc(ticket(MINE_S))).deployment).toBe(MINE_S)
        expect('deployment' in parseTicketJSON(enc(ticket()))).toBe(false)
        expect(() => parseReceiptJSON(enc({ ...receipt(), deployment: 'AAAA' }))).toThrow()
        expect(parseReceiptJSON(enc(receipt(MINE_S))).deployment).toBe(MINE_S)
        // null reads as absent, as Go's decode skips a TextUnmarshaler on null.
        expect('deployment' in parseTicketJSON(enc({ ...ticket(), deployment: null }))).toBe(false)
    })

    // Go's zero DeploymentID means unknown; a zero id named on the wire is malformed.
    it('knownDeployment treats the all-zero id as unknown', () => {
        expect(knownDeployment(undefined)).toBeUndefined()
        expect(knownDeployment(new Uint8Array(32))).toBeUndefined()
        expect(knownDeployment(MINE)).toBe(MINE)
        expect(() => knownDeployment(new Uint8Array(31))).toThrow()
    })
})

describe('verifyTicketFor', () => {
    it('applies the binding rule and the signature', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const bound = ticket(MINE_S)
        await signTicket(bound, signer, address)
        const legacy = ticket()
        await signTicket(legacy, signer, address)

        expect(() => verifyTicketFor(bound, publicKey, MINE, false)).not.toThrow()
        expect(() => verifyTicketFor(bound, publicKey, OTHER, true)).toThrow(DeploymentMismatchError)
        expect(() => verifyTicketFor(bound, publicKey, undefined, true)).toThrow(DeploymentMismatchError)
        expect(() => verifyTicket(bound, publicKey)).toThrow(DeploymentMismatchError)
        expect(() => verifyTicketFor(legacy, publicKey, MINE, true)).not.toThrow()
        expect(() => verifyTicketFor(legacy, publicKey, MINE, false)).toThrow(LegacySignatureError)

        // Relabelling or stripping breaks the signature.
        const relabelled = { ...bound, deployment: encodeDeploymentId(OTHER) }
        expect(() => verifyTicketFor(relabelled, publicKey, OTHER, false)).toThrow(/verification failed/)
        const { deployment: _, ...stripped } = bound
        expect(() => verifyTicketFor(stripped, publicKey, MINE, true)).toThrow(/verification failed/)
    })
})

describe('verifyReceiptFor', () => {
    it('applies the binding rule and the signature', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const bound = receipt(MINE_S)
        await signReceipt(bound, signer, address)
        expect(() => verifyReceiptFor(bound, publicKey, MINE, false)).not.toThrow()
        expect(() => verifyReceiptFor(bound, publicKey, OTHER, true)).toThrow(DeploymentMismatchError)
        const legacy = receipt()
        await signReceipt(legacy, signer, address)
        expect(() => verifyReceiptFor(legacy, publicKey, MINE, false)).toThrow(LegacySignatureError)
        expect(() => verifyReceiptFor(legacy, publicKey, MINE, true)).not.toThrow()
    })
})

describe('verifyReserveRequestFor', () => {
    it('checks the deployment before the window', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const issuedAt = 1_700_000_000
        const r: ReserveRequest = {
            model: 'm',
            input_count: 1,
            max_output_count: 1,
            stream: false,
            proxy_recipient: 'age1x',
            payer_issued_at: issuedAt,
            deployment: MINE_S,
        }
        await signReserveRequest(42, 7, r, signer, address)
        expect(() => verifyReserveRequestFor(42, 7, r, publicKey, issuedAt + 5, 30, MINE, false)).not.toThrow()
        expect(() => verifyReserveRequestFor(42, 7, r, publicKey, issuedAt + 3600, 30, OTHER, true)).toThrow(
            DeploymentMismatchError,
        )
        const legacy: ReserveRequest = { ...r }
        delete legacy.deployment
        await signReserveRequest(42, 7, legacy, signer, address)
        expect(() => verifyReserveRequestFor(42, 7, legacy, publicKey, issuedAt + 5, 30, MINE, false)).toThrow(
            LegacySignatureError,
        )
        expect(() => verifyReserveRequestFor(42, 7, legacy, publicKey, issuedAt + 5, 30, MINE, true)).not.toThrow()
    })
})

describe('ephemeral dual signature', () => {
    const now = 1_700_000_000 - 60
    const adv = (): EphemeralAdvertisement => ({
        ephemeral_age_pubkey: 'age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s',
        ephemeral_expiry: 1_700_000_000,
        ephemeral_issued_at: 1_700_000_000 - 1500,
    })

    it('signs both, and a bound advertisement is judged by the v2 signature', async () => {
        const { signer, address, publicKey } = newFakeSigner()
        const a = { ...adv(), ephemeral_deployment: MINE_S }
        await signEphemeral(42, 7, a, signer, address)
        expect(a.ephemeral_sig).toBeTruthy()
        expect(a.ephemeral_sig_v2).toBeTruthy()
        expect(a.ephemeral_sig).not.toBe(a.ephemeral_sig_v2)

        expect(() => verifyEphemeral(42, 7, a, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC)).not.toThrow()
        expect(() => verifyEphemeralFor(42, 7, a, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC, MINE, false)).not.toThrow()
        expect(() => verifyEphemeralFor(42, 7, a, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC, OTHER, true)).toThrow(
            DeploymentMismatchError,
        )
        const forged = { ...a, ephemeral_sig_v2: a.ephemeral_sig }
        expect(() => verifyEphemeralFor(42, 7, forged, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC, MINE, true)).toThrow()
        expect(() => verifyEphemeralFor(42, 8, a, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC, MINE, false)).toThrow()

        const { ephemeral_deployment: _d, ephemeral_sig_v2: _s, ...stripped } = a
        expect(() =>
            verifyEphemeralFor(42, 7, stripped, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC, MINE, false),
        ).toThrow(LegacySignatureError)
        expect(() =>
            verifyEphemeralFor(42, 7, stripped, publicKey, now, DEFAULT_EPHEMERAL_SKEW_SEC, MINE, true),
        ).not.toThrow()

        expect(() =>
            verifyEphemeralFor(42, 7, a, publicKey, a.ephemeral_expiry + 600, DEFAULT_EPHEMERAL_SKEW_SEC, MINE, false),
        ).toThrow(EphemeralExpiredError)
    })

    it('re-signing unbound drops a stale v2 signature', async () => {
        const { signer, address } = newFakeSigner()
        const a: EphemeralAdvertisement = { ...adv(), ephemeral_deployment: MINE_S }
        await signEphemeral(42, 7, a, signer, address)
        delete a.ephemeral_deployment
        await signEphemeral(42, 7, a, signer, address)
        expect(a.ephemeral_sig_v2).toBeUndefined()
    })
})
