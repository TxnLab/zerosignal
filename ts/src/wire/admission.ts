/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Admission tag — proof-of-possession HMAC the proxy attaches to every
// encrypted request. Verified by the node before it commits the ticket
// to "consumed" so a forged tag can't burn somebody else's ticket. See
// proto/docs/admission-tag.md and proto/SPEC.md §3a.
//
// Mirrors proto/go/wire/admission.go::ComputeAdmissionTag.
//
//   tag = HMAC-SHA256(
//       K_response,
//       AdmissionTagDomain || ticket_id || \0 || tx_id || \0 || sha256(body)
//   )
//
// The trailing-NUL convention matches ticketSigningTag — keeps the
// domain prefix self-terminating in any concatenation. ticket_id and
// tx_id are fed in as raw wire-form strings (base64 / base32
// respectively), not decoded — only "byte-for-byte identical on both
// sides" matters for HMAC.

import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'

import { concatBytes, utf8 } from '../util/bytes.js'

export const ADMISSION_TAG_DOMAIN = 'zs-admission-v1\x00'
export const ADMISSION_TAG_SIZE = 32 // sha256 output

export function computeAdmissionTag(
    k: Uint8Array,
    ticketID: string,
    txID: string,
    body: Uint8Array,
): Uint8Array {
    const bodyDigest = sha256(body)
    const message = concatBytes(
        utf8(ADMISSION_TAG_DOMAIN),
        utf8(ticketID),
        new Uint8Array([0]),
        utf8(txID),
        new Uint8Array([0]),
        bodyDigest,
    )
    return hmac(sha256, k, message)
}
