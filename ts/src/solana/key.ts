/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Keys and base58. Mirrors proto/go/solana/key.go and base58.go, pinned by
// proto/testdata/solana_codec_vectors.json. Keys travel as their base58
// strings, as the RPC and every wallet spell them; the bytes are one
// publicKeyBytes away.

import { base58 } from '@scure/base'

/** A base58 account address: an ed25519 key or a program derived address. */
export type PublicKey = string

/** A base58 blockhash or genesis hash. */
export type Hash = string

export class Base58Error extends Error {
    constructor(what: string) {
        super(`solana: invalid base58 ${what}`)
        this.name = 'Base58Error'
    }
}

/** The longest spelling of size bytes: all zeros, one '1' each, or ceil(size·log 256 / log 58) digits. */
function maxBase58Len(size: number): number {
    return Math.max(size, Math.floor((size * 1366 + 999) / 1000))
}

function quoted(s: string): string {
    return JSON.stringify(s.length > 64 ? `${s.slice(0, 64)}…` : s)
}

/**
 * decodeBase58 decodes s into exactly size bytes. A string that decodes to
 * any other length is refused rather than padded or truncated, so two
 * spellings never name one key. A string longer than any spelling of size
 * bytes is refused before decoding, which is quadratic in its length: keys
 * arrive from RPC answers and node JSON, and a long one would otherwise
 * stall the page.
 */
export function decodeBase58(s: string, size: number): Uint8Array {
    if (s === '' || s.length > maxBase58Len(size)) throw new Base58Error(quoted(s))
    let b: Uint8Array
    try {
        b = base58.decode(s)
    } catch {
        throw new Base58Error(quoted(s))
    }
    if (b.length !== size) throw new Base58Error(quoted(s))
    return b
}

export function encodeBase58(b: Uint8Array): string {
    return base58.encode(b)
}

/** parsePublicKey checks s spells a 32-byte key and returns it. */
export function parsePublicKey(s: string): PublicKey {
    decodeBase58(s, 32)
    return s
}

export function publicKeyBytes(k: PublicKey): Uint8Array {
    return decodeBase58(k, 32)
}

export function publicKeyFromBytes(b: Uint8Array): PublicKey {
    if (b.length !== 32) throw new Base58Error(`key of ${b.length} bytes`)
    return encodeBase58(b)
}

/** compareKeys orders keys by their bytes, the order the runtime's message compiler sorts them in. */
export function compareKeys(a: PublicKey, b: PublicKey): number {
    const x = publicKeyBytes(a)
    const y = publicKeyBytes(b)
    for (let i = 0; i < 32; i++) {
        if (x[i] !== y[i]) return x[i]! - y[i]!
    }
    return 0
}

// The programs and sysvars the rail's transactions name.
export const SYSTEM_PROGRAM_ID: PublicKey = '11111111111111111111111111111111'
export const COMPUTE_BUDGET_PROGRAM_ID: PublicKey = 'ComputeBudget111111111111111111111111111111'
export const TOKEN_PROGRAM_ID: PublicKey = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
export const ASSOCIATED_TOKEN_PROGRAM_ID: PublicKey = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
export const ED25519_PROGRAM_ID: PublicKey = 'Ed25519SigVerify111111111111111111111111111'
export const BPF_LOADER_UPGRADEABLE_PROGRAM_ID: PublicKey = 'BPFLoaderUpgradeab1e11111111111111111111111'
export const SYSVAR_INSTRUCTIONS_ID: PublicKey = 'Sysvar1nstructions1111111111111111111111111'
export const SYSVAR_RENT_ID: PublicKey = 'SysvarRent111111111111111111111111111111111'
export const SYSVAR_CLOCK_ID: PublicKey = 'SysvarC1ock11111111111111111111111111111111'
export const ADDRESS_LOOKUP_TABLE_PROGRAM_ID: PublicKey = 'AddressLookupTab1e1111111111111111111111111'
export const NAME_SERVICE_PROGRAM_ID: PublicKey = 'namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX'
export const SOL_TLD: PublicKey = '58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx'
