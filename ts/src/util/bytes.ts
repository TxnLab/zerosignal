/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

export function concatBytes(...parts: Uint8Array[]): Uint8Array {
    let total = 0
    for (const p of parts) total += p.length
    const out = new Uint8Array(total)
    let off = 0
    for (const p of parts) {
        out.set(p, off)
        off += p.length
    }
    return out
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    for (let i = 0; i < a.length; i++) {
        if (a[i] !== b[i]) return false
    }
    return true
}

// Constant-time byte comparison. Mirrors Go's subtle.ConstantTimeCompare:
// returns true iff a and b are equal in length and content, with no data-
// dependent early return. Used wherever a length-equal compare touches a
// secret (HMAC tag check, address checksum check).
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false
    let diff = 0
    for (let i = 0; i < a.length; i++) diff |= (a[i]! ^ b[i]!)
    return diff === 0
}

export function utf8(s: string): Uint8Array {
    return new TextEncoder().encode(s)
}
