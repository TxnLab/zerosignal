/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// SPL Token's TransferChecked, and the associated token program's
// CreateIdempotent. Mirrors proto/go/solana/token.go.

import { ASSOCIATED_TOKEN_PROGRAM_ID, SYSTEM_PROGRAM_ID, TOKEN_PROGRAM_ID, type PublicKey } from './key.js'
import type { Instruction } from './message.js'
import { associatedTokenAddress } from './pda.js'

/** SPL Token's TransferChecked tag, the first data byte. */
export const TOKEN_TRANSFER_CHECKED = 12

/**
 * Moves amount of mint from source to destination, signed by authority, the
 * source's owner. The token program refuses it unless decimals is the mint's,
 * which is why the open offer uses it rather than Transfer: the escrow program
 * checks the instruction's tag and fields.
 */
export function transferChecked(source: PublicKey, mint: PublicKey, destination: PublicKey, authority: PublicKey, amount: bigint, decimals: number): Instruction {
    if (amount < 0n || amount >= 1n << 64n) throw new RangeError(`solana: transfer amount ${amount} is not a u64`)
    if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) throw new RangeError(`solana: decimals ${decimals} is not a u8`)
    const data = new Uint8Array(10)
    data[0] = TOKEN_TRANSFER_CHECKED
    new DataView(data.buffer).setBigUint64(1, amount, true)
    data[9] = decimals
    return {
        programId: TOKEN_PROGRAM_ID,
        accounts: [
            { publicKey: source, isSigner: false, isWritable: true },
            { publicKey: mint, isSigner: false, isWritable: false },
            { publicKey: destination, isSigner: false, isWritable: true },
            { publicKey: authority, isSigner: true, isWritable: false },
        ],
        data,
    }
}

/** The associated token program's CreateIdempotent tag, its only data byte. */
export const ASSOCIATED_TOKEN_CREATE_IDEMPOTENT = 1

/**
 * Creates owner's associated token account for mint under the classic token
 * program, paid for by payer, and succeeds without change when it already
 * exists for owner, so a transaction can carry it ahead of a payout without
 * first reading the chain. It fails, and with it the whole transaction, when
 * owner has moved that account's ownership to another key, which the classic
 * program allows.
 */
export function createAssociatedTokenAccountIdempotent(payer: PublicKey, owner: PublicKey, mint: PublicKey): Instruction {
    const [ata] = associatedTokenAddress(owner, mint)
    return {
        programId: ASSOCIATED_TOKEN_PROGRAM_ID,
        accounts: [
            { publicKey: payer, isSigner: true, isWritable: true },
            { publicKey: ata, isSigner: false, isWritable: true },
            { publicKey: owner, isSigner: false, isWritable: false },
            { publicKey: mint, isSigner: false, isWritable: false },
            { publicKey: SYSTEM_PROGRAM_ID, isSigner: false, isWritable: false },
            { publicKey: TOKEN_PROGRAM_ID, isSigner: false, isWritable: false },
        ],
        data: Uint8Array.of(ASSOCIATED_TOKEN_CREATE_IDEMPOTENT),
    }
}
