/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The few request fields dispatch reads before it routes. Mirror of
// proto/go/zs/request_parse.go. Go's json decode is reproduced by gojson.ts and
// its multipart reader by multipart.ts, since a body both SDKs read differently
// would route and price differently.

import { decodeGoFields } from './gojson.js'
import { goQuote } from './gotext.js'
import { MultipartReader, type Part, binaryOf, parseMediaType, textOf, utf8Binary } from './multipart.js'

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

/** An image edit's fields, read from its multipart body. */
export interface ImageEditRequest extends ImageRequest {
    model: string
    stream: boolean
}

const INT64_MIN = -(1n << 63n)
const INT64_MAX = (1n << 63n) - 1n

/**
 * parseImageEditMultipart reads an image edit's multipart/form-data body: the
 * model, n (default 1), size, quality and stream fields, and that an image
 * part is present. It throws Go's errors, by message.
 */
export function parseImageEditMultipart(contentType: string, body: string | Uint8Array): ImageEditRequest {
    if (contentType === '') throw new Error('multipart Content-Type header is required')
    let boundary: string
    try {
        boundary = parseMediaType(utf8Binary(contentType)).params.get('boundary') ?? ''
    } catch (err) {
        throw new Error(`parse Content-Type: ${(err as Error).message}`, { cause: err })
    }
    if (boundary === '') throw new Error('multipart boundary missing from Content-Type')
    const r = new MultipartReader(typeof body === 'string' ? utf8Binary(body) : binaryOf(body), boundary)
    const out: ImageEditRequest = { model: '', n: 1, size: '', quality: '', stream: false }
    let n = 1n
    let sawImage = false
    const field = (part: Part, label: string): string => {
        try {
            return r.readAll(part)
        } catch (err) {
            throw new Error(`read ${label} field: ${(err as Error).message}`, { cause: err })
        }
    }
    for (;;) {
        let part: Part | null
        try {
            part = r.nextPart()
        } catch (err) {
            throw new Error(`read multipart: ${(err as Error).message}`, { cause: err })
        }
        if (part === null) break
        switch (part.formName) {
            case 'image':
                sawImage = true
                r.drain(part)
                break
            case 'model':
                out.model = textOf(field(part, 'model'))
                break
            case 'n': {
                const v = field(part, 'n')
                if (v !== '') n = atoi(v)
                break
            }
            case 'size':
                out.size = textOf(field(part, 'size'))
                break
            case 'quality':
                out.quality = textOf(field(part, 'quality'))
                break
            case 'stream': {
                const v = field(part, 'stream')
                if (v === 'true' || v === '1') out.stream = true
                break
            }
            default:
                r.drain(part)
        }
        // Part.Close drains again; after a failed quoted-printable read it
        // stops at once, so Go resumes wherever its read-ahead left off.
        r.drain(part)
    }
    if (out.model === '') throw new Error('model field is required')
    if (!sawImage) throw new Error('image part is required')
    if (n < 1n) throw new Error(`n must be >= 1, got ${n}`)
    // Past 2^53 n rounds where Go's int is exact; no node prices that many images.
    out.n = Number(n)
    return out
}

// strconv.Atoi on a 64-bit int.
function atoi(v: string): bigint {
    const quoted = goQuote(v)
    if (!/^[+-]?[0-9]+$/.test(v)) throw new Error(`n: strconv.Atoi: parsing ${quoted}: invalid syntax`)
    const n = BigInt(v)
    if (n < INT64_MIN || n > INT64_MAX) throw new Error(`n: strconv.Atoi: parsing ${quoted}: value out of range`)
    return n
}
