/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Reads a few top-level fields of a request body the way Go's json.Unmarshal
// fills a struct, so the payer's sizing, stream and image-count decisions match
// the Go SDK's for the same bytes. JSON.parse alone can't: it keeps the last of
// two keys that differ only in case where Go assigns them in order, it reads
// 1.0 and 1e3 as integers that Go refuses, and it rounds integers above 2^53.
//
// What Go does, and so this:
//   - refuses the body unless the whole of it is valid JSON, nested no deeper
//     than 10000;
//   - reads each invalid UTF-8 byte, and each escaped lone surrogate, as U+FFFD;
//   - accepts a top-level null as setting nothing, and refuses any other
//     non-object;
//   - matches a key to a field exactly, else case-insensitively under Unicode
//     simple folding (so the Kelvin sign matches k and the long s matches s);
//   - assigns matching members in document order, so the last one wins;
//   - lets null clear a pointer field and leave any other field unchanged;
//   - refuses a value of the wrong type, or an integer out of the field's range.

import { goDecodeUTF8, wellFormed } from './gotext.js'

/** The Go type of a field: a *uint64, an *int, a *bool, a *string, or a string. */
export type GoKind = 'uint64ptr' | 'intptr' | 'boolptr' | 'stringptr' | 'string'

export type GoValue = bigint | boolean | string | undefined

const UINT64_MAX = (1n << 64n) - 1n
const INT64_MIN = -(1n << 63n)
const INT64_MAX = (1n << 63n) - 1n

/** Go's scanner refuses nesting deeper than this, which JSON.parse accepts. */
const MAX_NESTING_DEPTH = 10000

/**
 * decodeGoFields returns each field's value after Go's decode, keyed as in
 * fields: undefined for an unset or cleared pointer, '' for an unset string.
 * It throws where json.Unmarshal would return an error.
 */
export function decodeGoFields<K extends string>(body: string | Uint8Array, fields: Record<K, GoKind>): Record<K, GoValue> {
    // A string body reaches Go as its UTF-8, where a lone surrogate is U+FFFD.
    const text = typeof body === 'string' ? wellFormed(body) : goDecodeUTF8(body)
    const out = {} as Record<K, GoValue>
    const names = Object.keys(fields) as K[]
    for (const n of names) out[n] = fields[n] === 'string' ? '' : undefined
    // Validates the whole text first, as Go does before decoding any of it.
    checkDepth(text)
    const parsed: unknown = JSON.parse(text)
    if (parsed === null) return out
    if (typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new TypeError(`json: cannot unmarshal ${Array.isArray(parsed) ? 'array' : typeof parsed} into Go value of type struct`)
    }
    const folded = new Map<string, K>()
    for (const n of names) folded.set(foldName(n), n)
    let firstErr: Error | undefined
    for (const [key, raw] of members(text)) {
        const name = (Object.hasOwn(fields, key) ? key : folded.get(foldName(key))) as K | undefined
        if (name === undefined) continue
        try {
            const v = decodeValue(raw, fields[name])
            if (v !== KEEP) out[name] = v
        } catch (err) {
            // Go records the first type error and keeps decoding the rest.
            firstErr ??= err as Error
        }
    }
    if (firstErr !== undefined) throw firstErr
    return out
}

const KEEP = Symbol('keep')

function decodeValue(raw: string, kind: GoKind): GoValue | typeof KEEP {
    if (raw === 'null') return kind === 'string' ? KEEP : undefined
    const c = raw[0] ?? ''
    switch (kind) {
        case 'string':
        case 'stringptr':
            if (c === '"') return wellFormed(JSON.parse(raw) as string)
            break
        case 'boolptr':
            if (raw === 'true' || raw === 'false') return raw === 'true'
            break
        case 'uint64ptr':
        case 'intptr': {
            if (c !== '-' && (c < '0' || c > '9')) break
            // A JSON number with a fraction or exponent is no Go integer.
            if (!/^-?(0|[1-9][0-9]*)$/.test(raw)) throw rangeError(raw, kind)
            const n = BigInt(raw)
            const [min, max] = kind === 'uint64ptr' ? [0n, UINT64_MAX] : [INT64_MIN, INT64_MAX]
            // ParseUint refuses a sign, so -0 is out for a uint64.
            if (n < min || n > max || (kind === 'uint64ptr' && raw[0] === '-')) throw rangeError(raw, kind)
            return n
        }
    }
    throw new TypeError(`json: cannot unmarshal ${jsonType(c)} into Go value of type ${goType(kind)}`)
}

function rangeError(raw: string, kind: GoKind): TypeError {
    return new TypeError(`json: cannot unmarshal number ${raw} into Go value of type ${goType(kind)}`)
}

function goType(kind: GoKind): string {
    return { uint64ptr: 'uint64', intptr: 'int', boolptr: 'bool', stringptr: 'string', string: 'string' }[kind]
}

function jsonType(c: string | undefined): string {
    if (c === '"') return 'string'
    if (c === '{') return 'object'
    if (c === '[') return 'array'
    if (c === 't' || c === 'f') return 'bool'
    return 'number'
}

// foldName is Go's encoding/json key folding: ASCII upper-cased, and every
// other rune mapped to the smallest rune of its simple-fold orbit. Only the
// Kelvin sign and the long s fold onto ASCII letters.
function foldName(s: string): string {
    let out = ''
    for (const ch of s) {
        if (ch === 'K') out += 'K'
        else if (ch === 'ſ') out += 'S'
        else if (ch >= 'a' && ch <= 'z') out += ch.toUpperCase()
        else out += ch
    }
    return out
}

// members walks a top-level object already known to be valid JSON, yielding
// each key decoded and its value's raw text, in document order.
function* members(text: string): Generator<[string, string]> {
    let i = skipWS(text, 0) + 1 // past '{'
    for (;;) {
        i = skipWS(text, i)
        if (text[i] === '}') return
        if (text[i] === ',') i = skipWS(text, i + 1)
        const keyEnd = skipString(text, i)
        const key = wellFormed(JSON.parse(text.slice(i, keyEnd)) as string)
        const valueStart = skipWS(text, skipWS(text, keyEnd) + 1) // past ':'
        const valueEnd = skipValue(text, valueStart)
        yield [key, text.slice(valueStart, valueEnd)]
        i = valueEnd
    }
}

function checkDepth(s: string): void {
    let depth = 0
    for (let i = 0; i < s.length; i++) {
        const c = s[i]
        if (c === '"') {
            i = skipString(s, i) - 1
        } else if (c === '{' || c === '[') {
            if (++depth > MAX_NESTING_DEPTH) throw new SyntaxError('exceeded max depth')
        } else if (c === '}' || c === ']') {
            depth--
        }
    }
}

function skipWS(s: string, i: number): number {
    while (i < s.length && (s[i] === ' ' || s[i] === '\t' || s[i] === '\n' || s[i] === '\r')) i++
    return i
}

function skipString(s: string, i: number): number {
    for (i++; i < s.length && s[i] !== '"'; i++) if (s[i] === '\\') i++
    return i + 1
}

function skipValue(s: string, i: number): number {
    const c = s[i]
    if (c === '"') return skipString(s, i)
    if (c !== '{' && c !== '[') {
        while (i < s.length && !',}] \t\n\r'.includes(s[i] as string)) i++
        return i
    }
    let depth = 0
    for (;;) {
        const d = s[i]
        if (d === '"') {
            i = skipString(s, i)
            continue
        }
        if (d === '{' || d === '[') depth++
        else if (d === '}' || d === ']') depth--
        i++
        if (depth === 0) return i
    }
}

// What Go's json.Marshal escapes that JSON.stringify doesn't: the HTML
// characters, and the two line separators. Built from char codes so no
// editor or tool can turn the separators into raw characters.
const GO_JSON_ESCAPES = new RegExp(`[<>&${String.fromCharCode(0x2028, 0x2029)}]`, 'g')

/** goJSON is JSON.stringify(v) with the escapes Go's json.Marshal adds. */
export function goJSON(v: unknown): string {
    return JSON.stringify(v).replace(GO_JSON_ESCAPES, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
}

// Go's map[string]json.RawMessage, the shape the handler rewrites a body
// through. Byte for byte: a raw value keeps whatever bytes it held, invalid
// UTF-8 included, which decoded text could not.

/**
 * goRawObject decodes b as json.Unmarshal does into a map[string]json.RawMessage:
 * each member's value as its raw bytes, under its decoded key, a repeated key
 * keeping its last value. JSON null is Go's nil map, null here. It throws
 * where Go returns an error: b not valid JSON, nested deeper than Go allows,
 * or not an object.
 */
export function goRawObject(b: Uint8Array): Map<string, Uint8Array> | null {
    const s = binaryString(b)
    const v = goValidate(b, s)
    if (v === null) return null
    if (typeof v !== 'object' || Array.isArray(v)) {
        throw new TypeError(`json: cannot unmarshal ${jsonType(s[skipWS(s, 0)])} into Go value of type map[string]json.RawMessage`)
    }
    const out = new Map<string, Uint8Array>()
    for (const [key, start, end] of rawMembers(s)) out.set(key, b.subarray(start, end))
    return out
}

/**
 * goRawObjects decodes b as json.Unmarshal does into a
 * []map[string]json.RawMessage: JSON null is a nil slice, null here, and each
 * null element a nil map. It throws where Go returns an error, including for
 * an element that is neither an object nor null.
 */
export function goRawObjects(b: Uint8Array): (Map<string, Uint8Array> | null)[] | null {
    const s = binaryString(b)
    const v = goValidate(b, s)
    if (v === null) return null
    if (!Array.isArray(v)) {
        throw new TypeError(`json: cannot unmarshal ${jsonType(s[skipWS(s, 0)])} into Go value of type []map[string]json.RawMessage`)
    }
    return rawElements(s).map(([start, end]) => goRawObject(b.subarray(start, end)))
}

/**
 * goMarshalRawObject is json.Marshal of a map[string]json.RawMessage: the
 * keys in Go's order, which is their UTF-8 byte order, and each value
 * compacted as goCompact does. Each value must be valid JSON.
 */
export function goMarshalRawObject(m: ReadonlyMap<string, Uint8Array>): Uint8Array {
    const out = new ByteBuilder()
    out.byte(0x7b)
    let first = true
    for (const k of [...m.keys()].sort(compareCodePoints)) {
        if (!first) out.byte(0x2c)
        first = false
        out.bytes(utf8.encode(goJSON(k)))
        out.byte(0x3a)
        goCompactInto(out, m.get(k)!)
    }
    out.byte(0x7d)
    return out.done()
}

/** goMarshalRawObjects is json.Marshal of a []map[string]json.RawMessage, a nil slice being null. */
export function goMarshalRawObjects(ms: readonly (ReadonlyMap<string, Uint8Array> | null)[] | null): Uint8Array {
    if (ms === null) return utf8.encode('null')
    const out = new ByteBuilder()
    out.byte(0x5b)
    ms.forEach((m, i) => {
        if (i > 0) out.byte(0x2c)
        out.bytes(m === null ? utf8.encode('null') : goMarshalRawObject(m))
    })
    out.byte(0x5d)
    return out.done()
}

/**
 * goCompact is what json.Marshal makes of a json.RawMessage: whitespace
 * outside strings dropped, the HTML characters and the two line separators
 * escaped, and every other byte kept, invalid UTF-8 included. src must be
 * valid JSON.
 */
export function goCompact(src: Uint8Array): Uint8Array {
    const out = new ByteBuilder()
    goCompactInto(out, src)
    return out.done()
}

const utf8 = new TextEncoder()
const HEX = '0123456789abcdef'

function goCompactInto(out: ByteBuilder, src: Uint8Array): void {
    let inString = false
    for (let i = 0; i < src.length; i++) {
        const c = src[i]!
        if (c === 0x3c || c === 0x3e || c === 0x26) {
            out.bytes(utf8.encode(`\\u00${HEX[c >> 4]}${HEX[c & 0xf]}`))
            continue
        }
        // U+2028 and U+2029 are E2 80 A8 and E2 80 A9.
        if (c === 0xe2 && i + 2 < src.length && src[i + 1] === 0x80 && (src[i + 2]! & ~1) === 0xa8) {
            out.bytes(utf8.encode(`\\u202${HEX[src[i + 2]! & 0xf]}`))
            i += 2
            continue
        }
        if (inString) {
            out.byte(c)
            // An escape's next byte is ASCII in valid JSON, and is copied as is.
            if (c === 0x5c) out.byte(src[++i]!)
            else if (c === 0x22) inString = false
            continue
        }
        if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) continue
        if (c === 0x22) inString = true
        out.byte(c)
    }
}

// compareCodePoints orders strings as Go orders their UTF-8 bytes. UTF-16
// order differs only where a surrogate meets U+E000–U+FFFF: the surrogate
// stands for a code point above them both.
function compareCodePoints(a: string, b: string): number {
    const n = Math.min(a.length, b.length)
    for (let i = 0; i < n; i++) {
        const x = a.charCodeAt(i)
        const y = b.charCodeAt(i)
        if (x === y) continue
        const sx = x >= 0xd800 && x <= 0xdfff
        const sy = y >= 0xd800 && y <= 0xdfff
        if (sx !== sy) return sx ? 1 : -1
        return x - y
    }
    return a.length - b.length
}

// goValidate is Go's check of a whole document before it decodes any of it,
// returning the parsed value for its type. s is b as a binary string.
function goValidate(b: Uint8Array, s: string): unknown {
    checkDepth(s)
    return JSON.parse(goDecodeUTF8(b))
}

// binaryString is b with one char per byte, so the string scanners above walk
// it and their offsets index b. JSON's structure is all ASCII, and a byte
// above 0x7f never reads as a quote or a backslash.
function binaryString(b: Uint8Array): string {
    let s = ''
    for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000))
    return s
}

// rawMembers walks a top-level object already known to be valid JSON,
// yielding each key decoded as Go decodes it and its value's offsets.
function* rawMembers(s: string): Generator<[string, number, number]> {
    let i = skipWS(s, 0) + 1 // past '{'
    for (;;) {
        i = skipWS(s, i)
        if (s[i] === '}') return
        if (s[i] === ',') i = skipWS(s, i + 1)
        const keyEnd = skipString(s, i)
        const key = wellFormed(JSON.parse(goDecodeUTF8(s.slice(i, keyEnd))) as string)
        const valueStart = skipWS(s, skipWS(s, keyEnd) + 1) // past ':'
        const valueEnd = skipValue(s, valueStart)
        yield [key, valueStart, valueEnd]
        i = valueEnd
    }
}

// rawElements is the offsets of each element of a top-level array already
// known to be valid JSON.
function rawElements(s: string): [number, number][] {
    const out: [number, number][] = []
    let i = skipWS(s, 0) + 1 // past '['
    for (;;) {
        i = skipWS(s, i)
        if (s[i] === ']') return out
        if (s[i] === ',') i = skipWS(s, i + 1)
        const end = skipValue(s, i)
        out.push([i, end])
        i = end
    }
}

class ByteBuilder {
    #buf = new Uint8Array(256)
    #n = 0

    #grow(need: number): void {
        if (this.#n + need <= this.#buf.length) return
        let size = this.#buf.length * 2
        while (size < this.#n + need) size *= 2
        const next = new Uint8Array(size)
        next.set(this.#buf.subarray(0, this.#n))
        this.#buf = next
    }

    byte(c: number): void {
        this.#grow(1)
        this.#buf[this.#n++] = c
    }

    bytes(b: Uint8Array): void {
        this.#grow(b.length)
        this.#buf.set(b, this.#n)
        this.#n += b.length
    }

    done(): Uint8Array {
        return this.#buf.slice(0, this.#n)
    }
}
