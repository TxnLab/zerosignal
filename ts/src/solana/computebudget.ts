/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The compute budget program's SetComputeUnitLimit and SetComputeUnitPrice.
// Mirrors proto/go/solana/computebudget.go.

import { COMPUTE_BUDGET_PROGRAM_ID } from './key.js'
import type { Instruction } from './message.js'

export const COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT = 2
export const COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE = 3

/**
 * Caps the transaction's compute units. The priority fee is charged on the
 * requested limit, and under the runtime's default limit on units the
 * transaction never uses.
 */
export function setComputeUnitLimit(units: number): Instruction {
    if (!Number.isInteger(units) || units < 0 || units > 0xffffffff) throw new RangeError(`solana: compute units ${units} is not a u32`)
    const data = new Uint8Array(5)
    data[0] = COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT
    new DataView(data.buffer).setUint32(1, units, true)
    return { programId: COMPUTE_BUDGET_PROGRAM_ID, accounts: [], data }
}

/**
 * Sets the priority fee, in micro-lamports per compute unit. A transaction
 * others co-sign sets its own: a fee added after one signer signs changes the
 * message the others signed.
 */
export function setComputeUnitPrice(microLamports: bigint): Instruction {
    if (microLamports < 0n || microLamports >= 1n << 64n) throw new RangeError(`solana: compute unit price ${microLamports} is not a u64`)
    const data = new Uint8Array(9)
    data[0] = COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE
    new DataView(data.buffer).setBigUint64(1, microLamports, true)
    return { programId: COMPUTE_BUDGET_PROGRAM_ID, accounts: [], data }
}
