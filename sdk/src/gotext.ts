/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Go's handling of text that isn't valid UTF-8, for the request readers that
// mirror Go's: a JS TextDecoder replaces a broken sequence with one U+FFFD
// where Go replaces each byte of it, and JSON.parse keeps an escaped lone
// surrogate that Go's decoder replaces.

const REPLACEMENT = 0xfffd

/** A byte source: a Uint8Array, or a binary string of one char per byte. */
export type Bytes = Uint8Array | string

function byteAt(b: Bytes, i: number): number {
    return typeof b === 'string' ? b.charCodeAt(i) : (b[i] as number)
}

function cont(c: number): boolean {
    return (c & 0xc0) === 0x80
}

/** goDecodeRune is utf8.DecodeRune: the rune at i and its width, or U+FFFD and 1 where the bytes are invalid. */
export function goDecodeRune(b: Bytes, i: number): [number, number] {
    const n = b.length - i
    const c0 = byteAt(b, i)
    if (c0 < 0x80) return [c0, 1]
    if (c0 >= 0xc2 && c0 <= 0xdf) {
        if (n >= 2 && cont(byteAt(b, i + 1))) return [((c0 & 0x1f) << 6) | (byteAt(b, i + 1) & 0x3f), 2]
        return [REPLACEMENT, 1]
    }
    if (c0 >= 0xe0 && c0 <= 0xef) {
        const lo = c0 === 0xe0 ? 0xa0 : 0x80
        const hi = c0 === 0xed ? 0x9f : 0xbf
        const c1 = byteAt(b, i + 1)
        if (n >= 3 && c1 >= lo && c1 <= hi && cont(byteAt(b, i + 2))) {
            return [((c0 & 0x0f) << 12) | ((c1 & 0x3f) << 6) | (byteAt(b, i + 2) & 0x3f), 3]
        }
        return [REPLACEMENT, 1]
    }
    if (c0 >= 0xf0 && c0 <= 0xf4) {
        const lo = c0 === 0xf0 ? 0x90 : 0x80
        const hi = c0 === 0xf4 ? 0x8f : 0xbf
        const c1 = byteAt(b, i + 1)
        if (n >= 4 && c1 >= lo && c1 <= hi && cont(byteAt(b, i + 2)) && cont(byteAt(b, i + 3))) {
            return [
                ((c0 & 0x07) << 18) | ((c1 & 0x3f) << 12) | ((byteAt(b, i + 2) & 0x3f) << 6) | (byteAt(b, i + 3) & 0x3f),
                4,
            ]
        }
    }
    return [REPLACEMENT, 1]
}

/** goDecodeUTF8 is string(b) as Go reads it rune by rune: each invalid byte becomes one U+FFFD. */
export function goDecodeUTF8(b: Bytes): string {
    const out: string[] = []
    for (let i = 0; i < b.length; ) {
        const [r, w] = goDecodeRune(b, i)
        out.push(String.fromCodePoint(r))
        i += w
    }
    return out.join('')
}

/** wellFormed replaces each lone surrogate with U+FFFD, as Go's JSON decoder does an escaped one. */
export function wellFormed(s: string): string {
    return s.replace(/[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/g, '�')
}

const PRINTABLE = /^[\p{L}\p{M}\p{N}\p{P}\p{S}]$/u

/** goQuote is strconv.Quote, Go's %q, over a binary string. */
export function goQuote(b: string): string {
    let out = '"'
    for (let i = 0; i < b.length; ) {
        const [r, w] = goDecodeRune(b, i)
        i += w
        if (r === REPLACEMENT && w === 1) {
            out += '\\x' + byteAt(b, i - 1).toString(16).padStart(2, '0')
            continue
        }
        const ch = String.fromCodePoint(r)
        if (ch === '"' || ch === '\\') out += '\\' + ch
        else if (r === 0x20 || (r > 0x20 && r < 0x7f) || (r >= 0x80 && PRINTABLE.test(ch))) out += ch
        else if (r === 0x07) out += '\\a'
        else if (r === 0x08) out += '\\b'
        else if (r === 0x0c) out += '\\f'
        else if (r === 0x0a) out += '\\n'
        else if (r === 0x0d) out += '\\r'
        else if (r === 0x09) out += '\\t'
        else if (r === 0x0b) out += '\\v'
        else if (r < 0x20 || r === 0x7f) out += '\\x' + r.toString(16).padStart(2, '0')
        else if (r < 0x10000) out += '\\u' + r.toString(16).padStart(4, '0')
        else out += '\\U' + r.toString(16).padStart(8, '0')
    }
    return out + '"'
}
