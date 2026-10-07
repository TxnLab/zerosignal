/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The few request fields dispatch reads before it routes. Mirror of
// proto/go/zs/request_parse.go; Go's json decode is reproduced by gojson.ts,
// since a body both SDKs read differently would route differently.

import { decodeGoFields } from './gojson.js'

/** streamableRequest reports whether body asks to stream: true only for a stream of true in a body Go decodes. */
export function streamableRequest(body: string | Uint8Array): boolean {
    try {
        return decodeGoFields(body, { stream: 'boolptr' }).stream === true
    } catch {
        return false
    }
}

/** An image generation's count, size and quality. */
export interface ImageRequest {
    n: number
    size: string
    quality: string
}

/** parseImageRequestN reads an image generation body; n defaults to 1 and must be at least 1. */
export function parseImageRequestN(body: string | Uint8Array): ImageRequest {
    let f
    try {
        f = decodeGoFields(body, { n: 'intptr', size: 'string', quality: 'string' })
    } catch {
        throw new Error('parse image request: invalid JSON')
    }
    const n = typeof f.n === 'bigint' ? f.n : 1n
    if (n < 1n) throw new Error('image request: n must be >= 1')
    // Past 2^53 n rounds where Go's int is exact; no node prices that many images.
    return { n: Number(n), size: f.size as string, quality: f.quality as string }
}
