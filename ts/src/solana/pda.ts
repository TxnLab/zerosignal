/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Program derived addresses. Mirrors proto/go/solana/pda.go, pinned by the
// PDAs in solana_account_vectors.json and the create_program_address and
// on_curve sections of solana_codec_vectors.json.

import { sha256 } from '@noble/hashes/sha2.js'

import { concatBytes, utf8 } from '../util/bytes.js'
import { ed25519 } from '../util/ed25519.js'
import { ASSOCIATED_TOKEN_PROGRAM_ID, TOKEN_PROGRAM_ID, type PublicKey, publicKeyBytes, publicKeyFromBytes } from './key.js'

export const MAX_SEEDS = 16
export const MAX_SEED_LENGTH = 32

export class ProgramAddressError extends Error {
    constructor(message: string) {
        super(`solana: ${message}`)
        this.name = 'ProgramAddressError'
    }
}

const PDA_MARKER = utf8('ProgramDerivedAddress')

/**
 * isOnCurve reports whether k decodes as an ed25519 point. Like the runtime's
 * curve25519-dalek decompress, it accepts a non-canonical y (ZIP 215).
 */
export function isOnCurve(k: Uint8Array): boolean {
    try {
        ed25519.ExtendedPoint.fromHex(k, true)
        return true
    } catch {
        return false
    }
}

/**
 * createProgramAddress is the runtime's create_program_address: the address
 * must be off the ed25519 curve, so no private key can sign for it and only
 * the program can.
 */
export function createProgramAddress(seeds: Uint8Array[], program: PublicKey): PublicKey {
    const k = programAddressHash(seeds, program)
    if (isOnCurve(k)) throw new ProgramAddressError('seeds give a point on the ed25519 curve')
    return publicKeyFromBytes(k)
}

/**
 * findProgramAddress is find_program_address: the first bump from 255 down
 * to 1 that gives an address off the curve (the runtime never tries 0).
 * Programs check the canonical bump, so any other bump names an address the
 * program refuses.
 */
export function findProgramAddress(seeds: Uint8Array[], program: PublicKey): [PublicKey, number] {
    if (seeds.length >= MAX_SEEDS) throw new ProgramAddressError('too many seeds, or a seed over 32 bytes')
    for (let bump = 255; bump >= 1; bump--) {
        const k = programAddressHash([...seeds, Uint8Array.of(bump)], program)
        if (!isOnCurve(k)) return [publicKeyFromBytes(k), bump]
    }
    throw new ProgramAddressError('no bump gives an address off the curve')
}

function programAddressHash(seeds: Uint8Array[], program: PublicKey): Uint8Array {
    if (seeds.length > MAX_SEEDS || seeds.some((s) => s.length > MAX_SEED_LENGTH)) {
        throw new ProgramAddressError('too many seeds, or a seed over 32 bytes')
    }
    return sha256(concatBytes(...seeds, publicKeyBytes(program), PDA_MARKER))
}

/** associatedTokenAddress is the owner's associated token account for mint under the classic token program. */
export function associatedTokenAddress(owner: PublicKey, mint: PublicKey): [PublicKey, number] {
    return findProgramAddress([publicKeyBytes(owner), publicKeyBytes(TOKEN_PROGRAM_ID), publicKeyBytes(mint)], ASSOCIATED_TOKEN_PROGRAM_ID)
}
