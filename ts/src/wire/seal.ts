/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Node-side wire operations. Mirrors proto/go/wire/seal.go.
//
// A browser playing the proxy role doesn't need decryptRequest /
// ResponseSealer, but porting them keeps the TS package symmetric with
// the Go side and makes round-trip tests trivial. They also unlock
// browser-as-node experiments (e.g. an in-browser test harness that
// terminates an envelope without needing a real node).

import * as age from 'age-encryption'
import { chacha20poly1305 } from '@noble/ciphers/chacha.js'
import { base64 } from '@scure/base'

import { buildBodyAAD, buildFrameAAD, buildHeaderAAD } from './aad.js'
import { NONCE_SIZE, RESPONSE_KEY_SIZE } from './constants.js'
import type { RequestEnvelope, ResponseEnvelope } from './envelope.js'
import { decodeInnerRequest } from './inner.js'
import { ADMISSION_TAG_SIZE } from './admission.js'

export interface DecryptedRequest {
    body: Uint8Array
    // age recipient string the proxy supplied as reply_to_public_key.
    // Used by ResponseSealer to wrap the response symmetric key.
    replyToRecipient: string
    algorandTxID: string
    ticketID: string
    // 32-byte HMAC the proxy attached to the envelope, or undefined
    // when omitted. Verifying the tag against HMAC(K_response, ...) is
    // the node's job — this type just decodes the wire bytes.
    admissionTag?: Uint8Array
}

// decryptRequest parses a RequestEnvelope, age-decrypts the ciphertext
// with nodeIdentity (AGE-SECRET-KEY-1...), and decodes the inner-request
// frame inside it: the body plus the reply-to recipient, tx id, ticket id,
// and admission tag that were plaintext envelope fields before 8.0.
export async function decryptRequest(
    envelopeJSON: Uint8Array,
    nodeIdentity: string,
): Promise<DecryptedRequest> {
    let env: RequestEnvelope
    try {
        env = JSON.parse(new TextDecoder().decode(envelopeJSON)) as RequestEnvelope
    } catch (err) {
        throw new Error(`parse request envelope: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (!env.ciphertext) throw new Error('request envelope missing ciphertext')

    let ct: Uint8Array
    try {
        ct = base64.decode(env.ciphertext)
    } catch (err) {
        throw new Error(`decode ciphertext: ${err instanceof Error ? err.message : String(err)}`)
    }

    const d = new age.Decrypter()
    d.addIdentity(nodeIdentity)
    const { header, body } = decodeInnerRequest(await d.decrypt(ct))
    if (!header.reply_to_public_key) throw new Error('inner request missing reply_to_public_key')

    let admissionTag: Uint8Array | undefined
    if (header.admission_tag) {
        try {
            admissionTag = base64.decode(header.admission_tag)
        } catch (err) {
            throw new Error(`decode admission_tag: ${err instanceof Error ? err.message : String(err)}`)
        }
        if (admissionTag.length !== ADMISSION_TAG_SIZE) {
            throw new Error(`admission_tag length ${admissionTag.length}, want ${ADMISSION_TAG_SIZE}`)
        }
    }

    return {
        body,
        replyToRecipient: header.reply_to_public_key,
        algorandTxID: header.algorand_tx_id,
        ticketID: header.ticket_id ?? '',
        admissionTag,
    }
}

export interface ResponseSealerInit {
    // age recipient string ("age1...") of the proxy's ephemeral.
    replyTo: string
    txID: string
    ticketID: string
    // Optional caller-supplied symmetric key — used by the ticket-gated
    // admission path so the reserve-time commit_k matches the actual
    // sealing key. When omitted, a fresh 32-byte key is generated.
    key?: Uint8Array
}

// ResponseSealer seals response payloads under a single per-request
// symmetric key, age-wrapped to the proxy's ephemeral recipient.
//
// Use sealBody once for non-streaming responses or sealStreamFrame
// repeatedly for streaming. Nonces are drawn fresh per call. The
// sealer tracks the AAD frame index internally — callers MUST NOT
// emit plaintext frames via this type; plaintext frames pass through
// the SSE writer without advancing the counter.
export class ResponseSealer {
    readonly txID: string
    readonly ticketID: string
    private readonly key: Uint8Array
    private readonly wrapped: string
    private frameIndex = 0n

    private constructor(txID: string, ticketID: string, key: Uint8Array, wrapped: string) {
        this.txID = txID
        this.ticketID = ticketID
        this.key = key
        this.wrapped = wrapped
    }

    static async create(init: ResponseSealerInit): Promise<ResponseSealer> {
        if (!init.replyTo) throw new Error('nil reply-to recipient')

        let key: Uint8Array
        if (init.key) {
            if (init.key.length !== RESPONSE_KEY_SIZE) {
                throw new Error(`response key length ${init.key.length}, want ${RESPONSE_KEY_SIZE}`)
            }
            key = init.key
        } else {
            key = new Uint8Array(RESPONSE_KEY_SIZE)
            crypto.getRandomValues(key)
        }

        const e = new age.Encrypter()
        e.addRecipient(init.replyTo)
        const wrappedRaw = await e.encrypt(key)
        const wrapped = base64.encode(wrappedRaw)

        return new ResponseSealer(init.txID, init.ticketID, key, wrapped)
    }

    // wrappedKeyHeader returns the value to place in the
    // X-Zs-Response-Key header: base64 of the age-encrypted
    // 32-byte symmetric key.
    wrappedKeyHeader(): string {
        return this.wrapped
    }

    // sealBody AEAD-seals plaintext with a fresh nonce bound to
    // buildBodyAAD(txID, ticketID) and returns the marshaled
    // ResponseEnvelope JSON.
    sealBody(plaintext: Uint8Array): Uint8Array {
        const nonce = new Uint8Array(NONCE_SIZE)
        crypto.getRandomValues(nonce)
        const ct = chacha20poly1305(this.key, nonce, buildBodyAAD(this.txID, this.ticketID)).encrypt(plaintext)
        const env: ResponseEnvelope = {
            nonce: base64.encode(nonce),
            ciphertext: base64.encode(ct),
        }
        return new TextEncoder().encode(JSON.stringify(env))
    }

    // sealHeader AEAD-seals one piece of post-response metadata under the
    // name'd header AAD and returns the base64(nonce || ciphertext) value for
    // the X-Zs-Receipt / X-Zs-Settle-Group response header — or, on a stream,
    // the data: field of the `zs-settle-group` SSE frame.
    //
    // Unlike sealStreamFrame this does not advance the frame counter: header
    // metadata is emitted at most once per name, the name in the AAD already
    // separates the two from each other and from body/frame payloads, and the
    // `zs-settle-group` frame precedes `zs-receipt`, which must land on the
    // index the content frames left off at.
    sealHeader(name: string, plaintext: Uint8Array): string {
        const nonce = new Uint8Array(NONCE_SIZE)
        crypto.getRandomValues(nonce)
        const ct = chacha20poly1305(this.key, nonce, buildHeaderAAD(this.txID, this.ticketID, name)).encrypt(plaintext)
        const raw = new Uint8Array(nonce.length + ct.length)
        raw.set(nonce, 0)
        raw.set(ct, nonce.length)
        return base64.encode(raw)
    }

    // sealStreamFrame AEAD-seals a single SSE frame payload under the
    // sealer's current frame index and returns the
    // base64(nonce || ciphertext) value that belongs in the data: line
    // of an `event: zs` SSE frame. The internal counter is
    // incremented after a successful seal.
    sealStreamFrame(plaintext: Uint8Array): string {
        const nonce = new Uint8Array(NONCE_SIZE)
        crypto.getRandomValues(nonce)
        const ct = chacha20poly1305(this.key, nonce, buildFrameAAD(this.txID, this.ticketID, this.frameIndex)).encrypt(plaintext)
        this.frameIndex += 1n
        const raw = new Uint8Array(nonce.length + ct.length)
        raw.set(nonce, 0)
        raw.set(ct, nonce.length)
        return base64.encode(raw)
    }
}
