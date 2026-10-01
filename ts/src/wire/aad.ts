/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// AEAD associated-data layout. Each sealed payload (non-streaming body,
// streaming frame, or a named piece of response metadata) is bound to
// (txID, ticketID) via chacha20poly1305's AAD. A domain tag distinguishes
// the three so one ciphertext cannot be replayed as another; the frame AAD
// additionally carries a monotonic 64-bit index so reordering, dropping, or
// duplicating frames within a stream breaks authentication, and the header
// AAD carries the metadata name so a receipt cannot be replayed as a settle
// group. See proto/SPEC.md §6.
//
// Format (no length prefixes — concat with NUL separators):
//   body   AAD: "zs" \0 "body"  \0 txID \0 ticketID
//   frame  AAD: "zs" \0 "frame" \0 txID \0 ticketID \0 frameIndex_BE_uint64
//   header AAD: "zs" \0 "hdr"   \0 txID \0 ticketID \0 name
//
// Mirrors proto/go/wire/envelope.go::BuildBodyAAD / BuildFrameAAD /
// BuildHeaderAAD. Byte-for-byte identical output is required — the node and
// the browser must agree on AAD or AEAD opens fail. Golden-vectored in
// proto/testdata/vectors.json.

import { concatBytes, utf8 } from '../util/bytes.js'

const PROTOCOL_TAG = utf8('zs')
const BODY_DOMAIN = utf8('body')
const FRAME_DOMAIN = utf8('frame')
const HEADER_DOMAIN = utf8('hdr')
const NUL = new Uint8Array([0])

export function buildBodyAAD(txID: string, ticketID: string): Uint8Array {
    return concatBytes(PROTOCOL_TAG, NUL, BODY_DOMAIN, NUL, utf8(txID), NUL, utf8(ticketID))
}

export function buildFrameAAD(txID: string, ticketID: string, frameIndex: number | bigint): Uint8Array {
    const idx = new Uint8Array(8)
    new DataView(idx.buffer).setBigUint64(0, BigInt(frameIndex), false)
    return concatBytes(PROTOCOL_TAG, NUL, FRAME_DOMAIN, NUL, utf8(txID), NUL, utf8(ticketID), NUL, idx)
}

export function buildHeaderAAD(txID: string, ticketID: string, name: string): Uint8Array {
    return concatBytes(PROTOCOL_TAG, NUL, HEADER_DOMAIN, NUL, utf8(txID), NUL, utf8(ticketID), NUL, utf8(name))
}
