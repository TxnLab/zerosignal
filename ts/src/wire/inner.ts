/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The inner-request frame: the plaintext sealed into RequestEnvelope.ciphertext.
// Mirrors proto/go/wire/inner.go.
//
//   "zsrq" || uint8(version) || uint32_be(headerLen) || headerJSON || body
//
// Framing rather than a JSON wrapper because the body must survive
// byte-for-byte: the admission tag and the receipt's body_hash both commit to
// sha256(body), and re-serializing arbitrary caller JSON does not round-trip
// its bytes. Length-prefixing the header keeps the body a raw suffix — no
// escaping, no base64 inflation on multi-megabyte image-edit bodies.
//
// Only the node (Go) decodes this frame, so the header JSON's key order does
// not have to match Go's — a JSON object is order-insensitive. What must match
// is the framing: magic, version, and the big-endian length.

import { concatBytes, utf8 } from '../util/bytes.js'

const INNER_REQUEST_VERSION = 1
const INNER_REQUEST_MAGIC = utf8('zsrq')
const INNER_PREFIX_LEN = INNER_REQUEST_MAGIC.length + 1 + 4

// Bounds the declared header length so a corrupt frame cannot drive a huge
// allocation before the JSON parse fails.
const INNER_HEADER_MAX_LEN = 64 << 10

// innerRequestHeader is the metadata half of the frame. These were the
// plaintext outer RequestEnvelope fields before 8.0; they moved inside so a
// relay cannot read ticket_id / algorand_tx_id and resolve the payer on chain.
export interface InnerRequestHeader {
    reply_to_public_key: string
    algorand_tx_id: string
    ticket_id?: string
    admission_tag?: string
}

export function encodeInnerRequest(header: InnerRequestHeader, body: Uint8Array): Uint8Array {
    const headerJSON = utf8(JSON.stringify(header))
    if (headerJSON.length > INNER_HEADER_MAX_LEN) {
        throw new Error(`inner request header ${headerJSON.length} bytes exceeds max ${INNER_HEADER_MAX_LEN}`)
    }
    const prefix = new Uint8Array(1 + 4)
    prefix[0] = INNER_REQUEST_VERSION
    new DataView(prefix.buffer).setUint32(1, headerJSON.length, false)
    return concatBytes(INNER_REQUEST_MAGIC, prefix, headerJSON, body)
}

// decodeInnerRequest is the node-role inverse, exported for tests and for any
// TS peer that plays the node side. The returned body is a view into raw.
export function decodeInnerRequest(raw: Uint8Array): { header: InnerRequestHeader; body: Uint8Array } {
    if (raw.length < INNER_PREFIX_LEN) {
        throw new Error('inner request frame truncated')
    }
    for (let i = 0; i < INNER_REQUEST_MAGIC.length; i++) {
        if (raw[i] !== INNER_REQUEST_MAGIC[i]) {
            throw new Error('inner request frame bad magic')
        }
    }
    const version = raw[INNER_REQUEST_MAGIC.length]
    if (version !== INNER_REQUEST_VERSION) {
        throw new Error(`inner request frame version ${version}, want ${INNER_REQUEST_VERSION}`)
    }
    const view = new DataView(raw.buffer, raw.byteOffset, raw.byteLength)
    const headerLen = view.getUint32(INNER_REQUEST_MAGIC.length + 1, false)
    if (headerLen > INNER_HEADER_MAX_LEN) {
        throw new Error(`inner request header ${headerLen} bytes exceeds max ${INNER_HEADER_MAX_LEN}`)
    }
    const end = INNER_PREFIX_LEN + headerLen
    if (end > raw.length) {
        throw new Error('inner request header length past end of frame')
    }
    let header: InnerRequestHeader
    try {
        header = JSON.parse(new TextDecoder().decode(raw.subarray(INNER_PREFIX_LEN, end))) as InnerRequestHeader
    } catch (err) {
        throw new Error(`parse inner request header: ${err instanceof Error ? err.message : String(err)}`)
    }
    return { header, body: raw.subarray(end) }
}
