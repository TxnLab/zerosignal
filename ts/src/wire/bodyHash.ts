/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Body-hash helpers — sha256 over the plaintext response, in two shapes:
//   - non-streaming: a single sha256 over the full body bytes.
//   - streaming: sha256 of the concatenation (in index order) of every
//     plaintext frame the node sealed. Frames carry no separator —
//     ordering is already authenticated via FrameAAD's monotonic index.
//
// The node computes one of these and signs the resulting digest into the
// UsageReceipt's body_hash field; the proxy / browser recomputes from
// the plaintext it observed and compares. A mismatch is evidence the
// operator signed a receipt for content it didn't deliver.
//
// Mirrors proto/go/wire/body_hash.go.

import { sha256 } from '@noble/hashes/sha2.js'

export function bodyHashOfBody(body: Uint8Array): Uint8Array {
    return sha256(body)
}

export function bodyHashFromFrames(frames: Uint8Array[]): Uint8Array {
    const h = sha256.create()
    for (const f of frames) h.update(f)
    return h.digest()
}
