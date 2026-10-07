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

/** The Go type of a field: a *uint64, an *int, a *bool, or a string. */
export type GoKind = 'uint64ptr' | 'intptr' | 'boolptr' | 'string'

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
    return { uint64ptr: 'uint64', intptr: 'int', boolptr: 'bool', string: 'string' }[kind]
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
