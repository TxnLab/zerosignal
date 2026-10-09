/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Reads a signed object's fields from parsed JSON, refusing any value that
// doesn't fit the field's Go type. A field that is absent or null reads as
// zero, as Go's json.Unmarshal leaves it.
//
// The strictness is what makes a check on a signed number sound. The
// canonical bytes write a uint64, so a node that signed 2^64-1 and sent -1
// would otherwise verify and then pass every comparison against it. An integer
// above 2^53 can't be held exactly in a number, so it throws here where Go
// would decode it; both refuse the object.
//
// Go is stricter in one way that doesn't touch those comparisons. JSON.parse
// has already normalised a number's spelling, so 1e3, 1.0 and -0 are accepted
// here as the integers they denote. Go's integer decode refuses all three.

export interface FieldReader {
    uint(name: string, max?: number): number
    int(name: string): number
    float(name: string): number
    str(name: string): string
    bool(name: string): boolean
    object(name: string): FieldReader
}

/** parseObject JSON-decodes raw and reads its fields; what prefixes every error. */
export function parseObject(raw: Uint8Array, what: string): FieldReader {
    let parsed: unknown
    try {
        parsed = JSON.parse(new TextDecoder().decode(raw))
    } catch (err) {
        throw new Error(`${what}: ${err instanceof Error ? err.message : String(err)}`)
    }
    return fieldReader(parsed, what)
}

function fieldReader(parsed: unknown, what: string): FieldReader {
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        throw new Error(`${what}: not an object`)
    }
    const r = parsed as Record<string, unknown>
    const get = (name: string): unknown => r[name]
    const absent = (v: unknown) => v === undefined || v === null
    const integer = (name: string, min: number, max: number): number => {
        const v = get(name)
        if (absent(v)) return 0
        if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || v > max) {
            throw new Error(`${what}: ${name} ${JSON.stringify(v)} is not an integer in [${min}, ${max}]`)
        }
        return v
    }
    return {
        uint: (name, max = Number.MAX_SAFE_INTEGER) => integer(name, 0, max),
        int: (name) => integer(name, Number.MIN_SAFE_INTEGER, Number.MAX_SAFE_INTEGER),
        float: (name) => {
            const v = get(name)
            if (absent(v)) return 0
            // JSON.parse reads 1e400 as Infinity; Go's float64 decode refuses it.
            if (typeof v !== 'number' || !Number.isFinite(v)) {
                const shown = typeof v === 'number' ? String(v) : JSON.stringify(v)
                throw new Error(`${what}: ${name} ${shown} is not a finite number`)
            }
            return v
        },
        str: (name) => {
            const v = get(name)
            if (absent(v)) return ''
            if (typeof v !== 'string') throw new Error(`${what}: ${name} is not a string`)
            return v
        },
        bool: (name) => {
            const v = get(name)
            if (absent(v)) return false
            if (typeof v !== 'boolean') throw new Error(`${what}: ${name} is not a boolean`)
            return v
        },
        object: (name) => {
            const v = get(name)
            return fieldReader(absent(v) ? {} : v, `${what}: ${name}`)
        },
    }
}
