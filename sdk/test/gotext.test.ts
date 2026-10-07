/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go's reading of invalid UTF-8, on bodies a JSON vector can't carry: Go's
// encoder replaces the bad bytes before they reach the file.

import { describe, expect, it } from 'vitest'

import { extractMaxOutput, parseImageRequestN } from '../src/index.js'
import { goDecodeUTF8, goQuote } from '../src/gotext.js'

const bytes = (...parts: (string | number[])[]) =>
    new Uint8Array(parts.flatMap((p) => (typeof p === 'string' ? [...new TextEncoder().encode(p)] : p)))

describe('Go text', () => {
    it('replaces each invalid byte, not each broken sequence', () => {
        expect(goDecodeUTF8(bytes('a', [0xf0, 0x9f, 0x98], 'b'))).toBe('a���b')
        expect(goDecodeUTF8(bytes([0xed, 0xa0, 0x80]))).toBe('���')
        expect(goDecodeUTF8(bytes([0xc0, 0xaf, 0xf4, 0x90, 0x80, 0x80]))).toBe('�'.repeat(6))
        expect(goDecodeUTF8(bytes('é€\u{1f600}'))).toBe('é€\u{1f600}')
    })

    // Go's string(b) keeps a leading byte-order mark, valid UTF-8 or not;
    // a default TextDecoder would drop it.
    it('keeps a leading byte-order mark', () => {
        expect(goDecodeUTF8(bytes([0xef, 0xbb, 0xbf], '{}'))).toBe('﻿{}')
        expect(goDecodeUTF8(bytes([0xef, 0xbb, 0xbf, 0xff]))).toBe('﻿�')
    })

    // Each lead byte's bounds: the first sequence past each is one U+FFFD per
    // byte, and the last one inside decodes to its rune.
    it.each([
        [[0xc0, 0x80], '��'],
        [[0xc2, 0x80], '\u0080'],
        [[0xdf, 0xbf], '߿'],
        [[0xe0, 0x9f, 0xbf], '�'.repeat(3)],
        [[0xe0, 0xa0, 0x80], 'ࠀ'],
        [[0xed, 0xa0, 0x80], '�'.repeat(3)],
        [[0xed, 0x9f, 0xbf], '퟿'],
        [[0xef, 0xbf, 0xbf], '￿'],
        [[0xf0, 0x8f, 0xbf, 0xbf], '�'.repeat(4)],
        [[0xf0, 0x90, 0x80, 0x80], '\u{10000}'],
        [[0xf4, 0x90, 0x80, 0x80], '�'.repeat(4)],
        [[0xf4, 0x8f, 0xbf, 0xbf], '\u{10ffff}'],
        [[0xf5, 0x80, 0x80, 0x80], '�'.repeat(4)],
        [[0xe2, 0x82], '��'],
    ])('decodes %j as Go does', (seq, want) => {
        expect(goDecodeUTF8(bytes(seq))).toBe(want)
    })

    it('reads a JSON string field as Go does', () => {
        expect(parseImageRequestN(bytes('{"size":"a', [0xf0, 0x9f, 0x98], 'b"}')).size).toBe('a���b')
        // The key's bad byte is its own U+FFFD, so it matches no field.
        expect(extractMaxOutput(bytes('{"max_', [0xff], 'tokens":5,"max_tokens":3}'))).toBe(3)
    })

    it('quotes as strconv.Quote', () => {
        expect(goQuote('X-Foo: bar\x01')).toBe('"X-Foo: bar\\x01"')
        expect(goQuote('X-K\xffey')).toBe('"X-K\\xffey"')
        expect(goQuote('\x07\x08\x0c\n\r\t\x0b\x7f"\\')).toBe('"\\a\\b\\f\\n\\r\\t\\v\\x7f\\"\\\\"')
        expect(goQuote('\xc3\xa9\xc2\xad\xf0\x9f\x98\x80')).toBe('"é\\u00ad\u{1f600}"')
    })
})
