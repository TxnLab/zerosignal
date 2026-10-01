/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Canonical-bytes builders — the byte-level encoding rules shared by
// Ticket.canonicalBytes and UsageReceipt.canonicalBytes. Mirrors
// proto/go/ticket/ticket.go's appendU64 / appendI64 / appendLenStr so
// the bytes Ed25519 signs are byte-for-byte identical to the Go side.
//
//   - uint64 / int64: 8 bytes big-endian. int64 is encoded by reinterpret
//     cast to uint64 (matches Go's appendI64 → appendU64(uint64(v))).
//   - length-prefixed string: 4-byte big-endian length, then raw UTF-8
//     bytes.
//
// Strings here are always JSON wire strings — base64 ticket id, hex body
// hash, model name. They contain only ASCII so the UTF-8 encoding is the
// same as the raw bytes; a length-prefixed encode is unambiguous either
// way.

import { utf8 } from './bytes.js'

export class CanonicalWriter {
    private chunks: Uint8Array[] = []

    bytes(b: Uint8Array): this {
        this.chunks.push(b)
        return this
    }

    str(s: string): this {
        this.chunks.push(utf8(s))
        return this
    }

    u64(v: number | bigint): this {
        const buf = new Uint8Array(8)
        new DataView(buf.buffer).setBigUint64(0, BigInt(v), false)
        this.chunks.push(buf)
        return this
    }

    // u8 writes a single byte (Go's appendU8). Used for the v2 UsageType
    // discriminators. Values outside 0..255 are masked, matching byte(v).
    u8(v: number): this {
        this.chunks.push(new Uint8Array([v & 0xff]))
        return this
    }

    // i64 reinterpret-casts to uint64 (Go's appendI64 → appendU64). For
    // negative values this wraps via two's complement, exactly like Go.
    i64(v: number | bigint): this {
        const buf = new Uint8Array(8)
        const asU64 = BigInt.asUintN(64, BigInt(v))
        new DataView(buf.buffer).setBigUint64(0, asU64, false)
        this.chunks.push(buf)
        return this
    }

    lenStr(s: string): this {
        const body = utf8(s)
        const lenBuf = new Uint8Array(4)
        new DataView(lenBuf.buffer).setUint32(0, body.length, false)
        this.chunks.push(lenBuf, body)
        return this
    }

    bool(v: boolean): this {
        this.chunks.push(new Uint8Array([v ? 1 : 0]))
        return this
    }

    finish(): Uint8Array {
        let total = 0
        for (const c of this.chunks) total += c.length
        const out = new Uint8Array(total)
        let off = 0
        for (const c of this.chunks) {
            out.set(c, off)
            off += c.length
        }
        return out
    }
}
