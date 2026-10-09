/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The legacy /v1/completions emulation against
// testdata/completions_vectors.json, which Go's zs/handler generates: the
// request rewrite and the reply reshape, byte for byte.

import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import {
    chatRequestFromCompletions,
    completionsChunkFromChat,
    completionsResponseFromChat,
    reshapeChatToText,
} from '../src/fetch/completions.js'

interface RequestCase {
    name: string
    body_b64: string
    out_b64?: string
    status?: number
    type?: string
    code?: string
    message?: string
}

interface ReplyCase {
    name: string
    streaming: boolean
    in_b64: string
    out_b64: string
    reshaped: boolean
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/completions_vectors.json', import.meta.url), 'utf8')) as {
    requests: RequestCase[]
    replies: ReplyCase[]
}

const bytes = (b64: string) => new Uint8Array(Buffer.from(b64, 'base64'))

describe('chatRequestFromCompletions', () => {
    it.each(vectors.requests.map((c) => [c.name, c] as const))('%s', (_name, c) => {
        const got = chatRequestFromCompletions(bytes(c.body_b64))
        if (c.out_b64 !== undefined) {
            expect('body' in got && Buffer.from(got.body).toString('base64')).toBe(c.out_b64)
            return
        }
        expect(got).toEqual({ error: { status: c.status, type: c.type, code: c.code, message: c.message } })
    })
})

describe('reshapeChatToText', () => {
    it.each(vectors.replies.map((c) => [c.name, c] as const))('%s', (_name, c) => {
        const input = bytes(c.in_b64)
        const got = reshapeChatToText(input, c.streaming)
        expect(got !== null).toBe(c.reshaped)
        const shaped = c.streaming ? completionsChunkFromChat(input) : completionsResponseFromChat(input)
        expect(Buffer.from(shaped).toString('base64')).toBe(c.out_b64)
    })
})

// The fixture must keep covering what makes the rewrite hard; a regenerated
// fixture that lost these would pass on its own.
describe('the vectors', () => {
    const names = new Set([...vectors.requests, ...vectors.replies].map((c) => c.name))
    it.each([
        'keys sorted by UTF-8 bytes',
        'invalid UTF-8 in another value',
        'a later null content',
        'a later content in another case',
        'an escaped key',
        'nested past the depth limit',
        'a null choice after a good one',
        'escapes the prompt as Go does',
    ])('include %s', (name) => {
        expect(names.has(name)).toBe(true)
    })
})
