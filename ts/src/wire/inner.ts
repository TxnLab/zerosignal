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
    // algorand_tx_id and payment_ref are one value under two names: a payer
    // writes payment_ref only to a node that reads it (usesRailNeutralNames),
    // since an older node would see no tx id at all.
    algorand_tx_id?: string
    payment_ref?: string
    ticket_id?: string
    admission_tag?: string
    // The payer-completed open() group for a node that submits it itself
    // (submitsOpen), as open_group or, under the neutral names, payment_open.
    // Mirrors Go's innerRequestHeader.OpenGroup.
    open_group?: string
    payment_open?: string
}

/**
 * paymentFields returns the header's payment reference and open, whichever
 * names carried them, as Go's innerRequestHeader.paymentFields does. Two
 * different values under the two names are refused, so the header has exactly
 * one reading for the admission tag, the payment check and anything else that
 * reads it.
 */
export function paymentFields(h: InnerRequestHeader): { ref: string; open: string } {
    try {
        return {
            ref: pickPaymentField('algorand_tx_id', h.algorand_tx_id, 'payment_ref', h.payment_ref),
            open: pickPaymentField('open_group', h.open_group, 'payment_open', h.payment_open),
        }
    } catch (err) {
        throw new Error(`inner request header: ${err instanceof Error ? err.message : String(err)}`)
    }
}

/**
 * pickPaymentField returns whichever of a legacy and a rail-neutral field is
 * set, and refuses two different values. Mirrors Go's wire.oneOf.
 */
export function pickPaymentField(legacyName: string, legacy: unknown, neutralName: string, neutral: unknown): string {
    const l = stringOrEmpty(legacyName, legacy)
    const n = stringOrEmpty(neutralName, neutral)
    if (l !== '' && n !== '' && l !== n) throw new Error(`${legacyName} and ${neutralName} disagree`)
    return n !== '' ? n : l
}

// Go's json.Unmarshal leaves a string field empty for null or an absent key
// and refuses any other non-string, so a TS peer must refuse it too.
function stringOrEmpty(name: string, v: unknown): string {
    if (v === undefined || v === null) return ''
    if (typeof v !== 'string') throw new Error(`${name} is not a string`)
    return v
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
    // Go decodes null as the zero header, which then fails its first required field.
    if (header === null) header = {} as InnerRequestHeader
    return { header, body: raw.subarray(end) }
}
