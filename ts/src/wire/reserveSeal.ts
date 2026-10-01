/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Confidentiality-only reserve seal, both legs. Mirror of
// proto/go/wire/reserve_seal.go. A browser/proxy seals the request and opens
// the response; openReserveRequest (the node role) stays Go-only.
//
// The reserve request is sealed at protocol 3.0 and the reserve response at
// 8.0. With single-hop relaying live, either one in plaintext hands the relay
// operator the caller's payer_addr — a stable on-chain address it can bind to
// the client IP it already holds. The request carries payer_addr directly; the
// response carries presigned_open_txn, a signed transaction group naming the
// payer as gtxn[0]'s sender and again as open()'s payerAddr ABI arg. Sealing
// each to the party that needs it closes both reads while the relay still
// forwards the opaque bytes. See SPEC.md § 3a, § 3f.

import * as age from 'age-encryption'
import { base64 } from '@scure/base'

import type { EphemeralIdentity } from './identity.js'

// Content-Type for a sealed POST /v1/zs/reserve request body. Deliberately
// distinct from the inference EncryptedContentType ("application/vnd.zs+json")
// so a node — and a byte-transparent relay — can tell a sealed reserve from a
// sealed inference envelope by content-type alone, without parsing.
export const SEALED_RESERVE_CONTENT_TYPE = 'application/vnd.zs-reserve+json'

// Content-Type for a sealed 200 POST /v1/zs/reserve *response* body — the whole
// ticket.ReserveResponse age-sealed to the caller's proxy_recipient. Error
// responses stay plaintext OpenAI-shaped JSON (application/json): they carry
// no ticket and no payer, and a caller that cannot parse them cannot report
// why its reserve failed.
export const SEALED_RESERVE_RESPONSE_CONTENT_TYPE = 'application/vnd.zs-reserve-response+json'

// JSON body carrying an age-sealed ticket.ReserveRequest or
// ticket.ReserveResponse. Like RequestEnvelope since 8.0 it carries nothing but
// ciphertext; it stays a distinct type because the reserve leg has no ticket to
// bind and no inner-request frame — its plaintext is the bare marshaled request
// or response.
export interface SealedReserveEnvelope {
    ciphertext: string
}

// sealReserveRequest age-encrypts a marshaled ticket.ReserveRequest to the
// target operator's long-lived recipient ("age1...") and returns the RFC8259
// JSON encoding of SealedReserveEnvelope. Send it as the request body with
// Content-Type: SEALED_RESERVE_CONTENT_TYPE. age is itself authenticated
// encryption to the recipient, so there is no admission tag or AAD — the
// reserve carries no ticket to bind, and the reply path is unchanged.
export async function sealReserveRequest(
    body: Uint8Array,
    operatorRecipient: string,
): Promise<Uint8Array> {
    return sealReserveEnvelope(body, operatorRecipient)
}

// sealReserveResponse age-encrypts a marshaled ticket.ReserveResponse to the
// caller's proxy_recipient — the ephemeral recipient it declared inside the
// sealed reserve request, which a relay therefore never saw. This is the node
// role; it lives here so a TS peer can play the node side and so round-trip
// tests need no Go.
export async function sealReserveResponse(
    body: Uint8Array,
    proxyRecipient: string,
): Promise<Uint8Array> {
    return sealReserveEnvelope(body, proxyRecipient)
}

// openReserveResponse age-decrypts a sealed reserve response with the ephemeral
// identity whose recipient the caller sent as proxy_recipient, returning the
// marshaled ticket.ReserveResponse. This is the same identity that unwraps
// wrapped_response_key and, later, X-Zs-Response-Key — so the caller already
// holds the key and opening costs it nothing.
export async function openReserveResponse(
    envelopeJSON: Uint8Array,
    identity: EphemeralIdentity,
): Promise<Uint8Array> {
    let env: SealedReserveEnvelope
    try {
        env = JSON.parse(new TextDecoder().decode(envelopeJSON)) as SealedReserveEnvelope
    } catch (err) {
        throw new Error(`parse sealed reserve envelope: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (!env.ciphertext) throw new Error('sealed reserve envelope missing ciphertext')

    let ct: Uint8Array
    try {
        ct = base64.decode(env.ciphertext)
    } catch (err) {
        throw new Error(`decode ciphertext: ${err instanceof Error ? err.message : String(err)}`)
    }

    const d = new age.Decrypter()
    d.addIdentity(identity.secret)
    try {
        return await d.decrypt(ct)
    } catch (err) {
        throw new Error(`open sealed reserve envelope: ${err instanceof Error ? err.message : String(err)}`)
    }
}

async function sealReserveEnvelope(body: Uint8Array, recipient: string): Promise<Uint8Array> {
    const e = new age.Encrypter()
    e.addRecipient(recipient)
    const ciphertext = await e.encrypt(body)

    const env: SealedReserveEnvelope = {
        ciphertext: base64.encode(ciphertext),
    }
    return new TextEncoder().encode(JSON.stringify(env))
}
