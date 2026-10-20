/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Borsh subset the program's instructions, accounts and events use:
// little-endian integers, a bool as one byte, an Option as a 0/1 tag, and a
// string or byte vector as a u32 length and its bytes. Mirrors
// proto/go/solana/zsescrow/borsh.go.

import { type PublicKey, publicKeyBytes, publicKeyFromBytes } from '../key.js'

const U64_MAX = (1n << 64n) - 1n

export class Writer {
    private parts: number[] = []
    private int(v: bigint | number, bytes: number, signed = false): void {
        let x = BigInt(v)
        const bits = BigInt(bytes * 8)
        const lo = signed ? -(1n << (bits - 1n)) : 0n
        const hi = signed ? (1n << (bits - 1n)) - 1n : (1n << bits) - 1n
        if (x < lo || x > hi) throw new RangeError(`zsescrow: ${v} does not fit ${signed ? 'i' : 'u'}${bytes * 8}`)
        if (x < 0n) x += 1n << bits
        for (let i = 0; i < bytes; i++) {
            this.parts.push(Number(x & 0xffn))
            x >>= 8n
        }
    }
    u8(v: number): void {
        this.int(v, 1)
    }
    u16(v: number): void {
        this.int(v, 2)
    }
    u32(v: number): void {
        this.int(v, 4)
    }
    u64(v: bigint): void {
        this.int(v, 8)
    }
    i64(v: bigint): void {
        this.int(v, 8, true)
    }
    bool(v: boolean): void {
        this.parts.push(v ? 1 : 0)
    }
    bytes(b: Uint8Array): void {
        for (const v of b) this.parts.push(v)
    }
    fixed(b: Uint8Array, n: number): void {
        if (b.length !== n) throw new RangeError(`zsescrow: ${b.length} bytes where ${n} belong`)
        this.bytes(b)
    }
    key(k: PublicKey): void {
        this.bytes(publicKeyBytes(k))
    }
    vec(b: Uint8Array): void {
        this.u32(b.length)
        this.bytes(b)
    }
    /** Some(v) or None. */
    option<T>(v: T | null | undefined, put: (v: T) => void): void {
        if (v === null || v === undefined) {
            this.parts.push(0)
            return
        }
        this.parts.push(1)
        put(v)
    }
    done(): Uint8Array {
        return Uint8Array.from(this.parts)
    }
}

export class DecodeError extends Error {
    constructor(detail: string) {
        super(`zsescrow: malformed data: ${detail}`)
        this.name = 'DecodeError'
    }
}

// fatal refuses what Go's utf8.Valid refuses; ignoreBOM keeps a leading
// U+FEFF, which the default decoder drops and Go's string() keeps.
const strictUtf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true })

export function decodeUtf8(b: Uint8Array, what: string): string {
    try {
        return strictUtf8.decode(b)
    } catch {
        throw new DecodeError(`${what} is not UTF-8`)
    }
}

export class Reader {
    constructor(
        private readonly b: Uint8Array,
        public off = 0,
    ) {}
    take(n: number): Uint8Array {
        if (n < 0 || this.off + n > this.b.length) throw new DecodeError(`short read at ${this.off}`)
        const out = this.b.subarray(this.off, this.off + n)
        this.off += n
        return out
    }
    private int(bytes: number): bigint {
        const b = this.take(bytes)
        let v = 0n
        for (let i = bytes - 1; i >= 0; i--) v = (v << 8n) | BigInt(b[i]!)
        return v
    }
    u8(): number {
        return this.take(1)[0]!
    }
    u16(): number {
        return Number(this.int(2))
    }
    u32(): number {
        return Number(this.int(4))
    }
    u64(): bigint {
        return this.int(8)
    }
    i64(): bigint {
        const v = this.int(8)
        return v > U64_MAX >> 1n ? v - (1n << 64n) : v
    }
    key(): PublicKey {
        return publicKeyFromBytes(this.take(32))
    }
    /** Refuses a byte other than 0 or 1, as Borsh does. */
    bool(): boolean {
        const v = this.u8()
        if (v > 1) throw new DecodeError(`bool ${v} at ${this.off - 1}`)
        return v === 1
    }
    vec(): Uint8Array {
        return this.take(this.u32()).slice()
    }
    array(n: number): Uint8Array {
        return this.take(n).slice()
    }
    get remaining(): number {
        return this.b.length - this.off
    }
}
