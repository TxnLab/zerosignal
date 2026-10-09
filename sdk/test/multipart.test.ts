/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The multipart reader's header-size limit, at bounds read off Go's
// mime/multipart: a vector body this large doesn't belong in testdata.

import { describe, expect, it } from 'vitest'

import { MultipartReader } from '../src/multipart.js'

// One part whose only header line, "X-A: v…", is length bytes long.
function readAll(length: number): string {
    const body = '--b\r\nX-A: ' + 'v'.repeat(length - 'X-A: '.length) + '\r\n\r\nx\r\n--b--\r\n'
    const r = new MultipartReader(body, 'b')
    try {
        for (let p = r.nextPart(); p !== null; p = r.nextPart()) r.drain(p)
        return 'ok'
    } catch (err) {
        return (err as Error).message
    }
}

describe('MultipartReader header limit', () => {
    const lim = (10 << 20) - 400
    // Go: the line fits the remaining budget, then its key, value and the
    // 200-byte entry overhead overrun it; past lim the line alone does.
    it.each([
        [lim - 198, 'ok'],
        [lim - 197, 'multipart: message too large'],
        [lim, 'multipart: message too large'],
        [lim + 1, 'multipart: message too large'],
    ])('a %i-byte header line reads as Go does', (length, want) => {
        expect(readAll(length)).toBe(want)
    })
})
