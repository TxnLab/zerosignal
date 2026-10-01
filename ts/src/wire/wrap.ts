/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Proxy-side wire operations. Mirrors proto/go/wire/wrap.go.
//
// Lifecycle (browser-as-proxy):
//   1. generateEphemeralIdentity() — fresh per request.
//   2. wrapRequest(...)            — age-encrypt body, build envelope.
//   3. unwrapResponseKey(...)      — recover K_response from
//                                    X-Zs-Response-Key (or the
//                                    reserve-time wrapped_response_key).
//   4. decryptBody(...)            — non-streaming response.
//      decryptSSEDataValue(...)    — once per `event: zs` SSE frame.
//
// All four steps share the same per-request ephemeral identity. After
// the response is fully consumed, drop the identity reference (JS GC
// will eventually collect it; in-memory wiping is not reliable for
// strings — see README "Secret-key lifetime").

import * as age from 'age-encryption'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { base64 } from '@scure/base'

import { buildBodyAAD, buildFrameAAD, buildHeaderAAD } from './aad.js'
import { NONCE_SIZE, POLY1305_TAG_SIZE, RESPONSE_KEY_SIZE } from './constants.js'
import type { EphemeralIdentity } from './identity.js'
import { generateEphemeralIdentity } from './identity.js'
import type { RequestEnvelope, ResponseEnvelope } from './envelope.js'
import type { InnerRequestHeader } from './inner.js'
import { encodeInnerRequest } from './inner.js'

export interface WrapRequestArgs {
    body: Uint8Array
    txID: string
    ticketID: string
    // Pre-computed admission tag (32-byte HMAC). Required for any
    // ticket-gated request; undefined omits the header field, which a node
    // refuses with 402 admission_tag_invalid.
    admissionTag?: Uint8Array
    // age recipient string ("age1...") for the node we're addressing.
    nodeRecipient: string
    // Pre-generated ephemeral identity. Required when the caller already
    // generated one (e.g. to unwrap reserve-time wrapped_response_key
    // before computing the admission tag). Omit to have wrapRequest
    // generate one internally.
    ephemeral?: EphemeralIdentity
}

export interface WrapRequestResult {
    // RFC8259 JSON encoding of RequestEnvelope. Send as the request body
    // with Content-Type: application/vnd.zs+json.
    envelope: Uint8Array
    // The ephemeral identity used. Caller MUST hold this until the
    // response is decrypted, then drop the reference.
    ephemeral: EphemeralIdentity
}

// wrapRequest frames the body with the request's reply-to recipient, tx id,
// ticket id, and admission tag, age-encrypts the whole frame to nodeRecipient,
// and returns the marshaled RequestEnvelope (a lone ciphertext field) plus the
// ephemeral identity used.
export async function wrapRequest(args: WrapRequestArgs): Promise<WrapRequestResult> {
    const ephemeral = args.ephemeral ?? (await generateEphemeralIdentity())

    const header: InnerRequestHeader = {
        reply_to_public_key: ephemeral.recipient,
        algorand_tx_id: args.txID,
        ticket_id: args.ticketID,
    }
    if (args.admissionTag && args.admissionTag.length > 0) {
        header.admission_tag = base64.encode(args.admissionTag)
    }

    const e = new age.Encrypter()
    e.addRecipient(args.nodeRecipient)
    const ciphertext = await e.encrypt(encodeInnerRequest(header, args.body))

    const env: RequestEnvelope = { ciphertext: base64.encode(ciphertext) }
    const envelope = new TextEncoder().encode(JSON.stringify(env))
    return { envelope, ephemeral }
}

// unwrapResponseKey age-decrypts the X-Zs-Response-Key header value
// (or the reserve-time wrapped_response_key) and returns the 32-byte
// symmetric key used to AEAD-seal response payloads.
export async function unwrapResponseKey(
    b64Wrapped: string,
    identity: EphemeralIdentity,
): Promise<Uint8Array> {
    let wrapped: Uint8Array
    try {
        wrapped = base64.decode(b64Wrapped)
    } catch (err) {
        throw new Error(`decode wrapped key: ${err instanceof Error ? err.message : String(err)}`)
    }

    const d = new age.Decrypter()
    d.addIdentity(identity.secret)
    const raw = await d.decrypt(wrapped)
    if (raw.length !== RESPONSE_KEY_SIZE) {
        throw new Error(`unexpected response key length ${raw.length}`)
    }
    return raw
}

// decryptBody AEAD-opens a non-streaming ResponseEnvelope and returns
// the plaintext response body. txID must be the one wrapRequest sealed and
// ticketID the ticket it was admitted under; both are bound into the AAD, so
// a response sealed under different values fails the open. Neither is echoed
// on the response.
export function decryptBody(
    envelopeJSON: Uint8Array,
    responseKey: Uint8Array,
    txID: string,
    ticketID: string,
): Uint8Array {
    let env: ResponseEnvelope
    try {
        env = JSON.parse(new TextDecoder().decode(envelopeJSON)) as ResponseEnvelope
    } catch (err) {
        throw new Error(`parse response envelope: ${err instanceof Error ? err.message : String(err)}`)
    }

    let nonce: Uint8Array
    try {
        nonce = base64.decode(env.nonce)
    } catch (err) {
        throw new Error(`decode nonce: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (nonce.length !== NONCE_SIZE) {
        throw new Error(`invalid nonce length ${nonce.length}`)
    }

    let ct: Uint8Array
    try {
        ct = base64.decode(env.ciphertext)
    } catch (err) {
        throw new Error(`decode ciphertext: ${err instanceof Error ? err.message : String(err)}`)
    }

    try {
        return chacha20poly1305(responseKey, nonce, buildBodyAAD(txID, ticketID)).decrypt(ct)
    } catch (err) {
        throw new Error(`aead open: ${err instanceof Error ? err.message : String(err)}`)
    }
}

// decryptSSEDataValue parses "base64(nonce || ciphertext)" from the
// data: field of an `event: zs` SSE frame and AEAD-opens it with
// responseKey. txID, ticketID, and frameIndex are bound into AAD;
// frameIndex must be the 0-based position of this encrypted frame
// within the stream. Plaintext frames don't go through this — they
// pass through the SSE stream unwrapped (SPEC.md §6).
export function decryptSSEDataValue(
    b64: string,
    responseKey: Uint8Array,
    txID: string,
    ticketID: string,
    frameIndex: number | bigint,
): Uint8Array {
    let raw: Uint8Array
    try {
        raw = base64.decode(b64)
    } catch (err) {
        throw new Error(`decode sse frame: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (raw.length < NONCE_SIZE + POLY1305_TAG_SIZE) {
        throw new Error(`sse frame too short (${raw.length} bytes)`)
    }
    const nonce = raw.subarray(0, NONCE_SIZE)
    const ct = raw.subarray(NONCE_SIZE)
    try {
        return chacha20poly1305(responseKey, nonce, buildFrameAAD(txID, ticketID, frameIndex)).decrypt(ct)
    } catch (err) {
        throw new Error(`aead open: ${err instanceof Error ? err.message : String(err)}`)
    }
}

// openSealedHeader AEAD-opens one piece of sealed response metadata — the
// value of the X-Zs-Receipt / X-Zs-Settle-Group header, or the data: field of
// the `zs-settle-group` SSE frame. name must be the SEALED_HEADER_* constant
// the node sealed under; it is bound into the AAD, so a receipt cannot be
// opened as a settle group. Mirrors proto/go/wire/wrap.go::OpenSealedHeader.
export function openSealedHeader(
    b64: string,
    responseKey: Uint8Array,
    txID: string,
    ticketID: string,
    name: string,
): Uint8Array {
    let raw: Uint8Array
    try {
        raw = base64.decode(b64)
    } catch (err) {
        throw new Error(`decode sealed ${name}: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (raw.length < NONCE_SIZE + POLY1305_TAG_SIZE) {
        throw new Error(`sealed ${name} too short (${raw.length} bytes)`)
    }
    const nonce = raw.subarray(0, NONCE_SIZE)
    const ct = raw.subarray(NONCE_SIZE)
    try {
        return chacha20poly1305(responseKey, nonce, buildHeaderAAD(txID, ticketID, name)).decrypt(ct)
    } catch (err) {
        throw new Error(`aead open sealed ${name}: ${err instanceof Error ? err.message : String(err)}`)
    }
}
