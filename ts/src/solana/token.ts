/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// SPL Token's TransferChecked. Mirrors proto/go/solana/token.go.

import { TOKEN_PROGRAM_ID, type PublicKey } from './key.js'
import type { Instruction } from './message.js'

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
