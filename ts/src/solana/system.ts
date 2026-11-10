/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The system program's Transfer. Mirrors proto/go/solana/system.go.

import { SYSTEM_PROGRAM_ID, type PublicKey } from './key.js'
import type { Instruction } from './message.js'

/** The system program's Transfer tag, the first data word. */
export const SYSTEM_TRANSFER = 2

/**
 * Moves lamports from from, which signs, to to. Sending all of an account's
 * lamports leaves it empty, which the runtime then deletes; a partial send
 * must leave it rent-exempt.
 */
export function systemTransfer(from: PublicKey, to: PublicKey, lamports: bigint): Instruction {
    if (lamports < 0n || lamports >= 1n << 64n) throw new RangeError(`solana: transfer lamports ${lamports} is not a u64`)
    const data = new Uint8Array(12)
    const view = new DataView(data.buffer)
    view.setUint32(0, SYSTEM_TRANSFER, true)
    view.setBigUint64(4, lamports, true)
    return {
        programId: SYSTEM_PROGRAM_ID,
        accounts: [
            { publicKey: from, isSigner: true, isWritable: true },
            { publicKey: to, isSigner: false, isWritable: true },
        ],
        data,
    }
}
