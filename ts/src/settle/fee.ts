/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The protocol fee on a settled charge, the same on every rail. Mirrors
// proto/go/settle/fee.go, pinned by proto/testdata/settle_vectors.json. All
// amounts are microUSDC.

export const BPS_DENOMINATOR = 10_000n

export interface FeeBreakdown {
    // The operator's take, paid in full. From the signed receipt.
    amountCharged: bigint
    // The protocol fee the payer pays on top of amountCharged.
    netFee: bigint
    // What the escrow returns: maxPrice − amountCharged − netFee, floored at 0.
    refund: bigint
    // The payer's actual cost: amountCharged + netFee.
    totalDebit: bigint
}

// netFee is the contracts' fee math, floor for floor:
//   grossFee = floor(amountCharged * feeBps / 10000)
//   netFee   = floor(grossFee * (10000 - discountBps) / 10000)
// discountBps is 0 on every live ticket (Algorand's discount is retired, Solana
// has none); above 10000 it is clamped so the (10000 - discountBps) term can't
// go negative. The bps arguments also take a number because ticket records
// store them as u16 and decode them as one.
export function netFee(amountCharged: bigint, feeBps: bigint | number, discountBps: bigint | number): bigint {
    const fee = BigInt(feeBps)
    const disc = BigInt(discountBps)
    const discount = disc > BPS_DENOMINATOR ? BPS_DENOMINATOR : disc
    const grossFee = (amountCharged * fee) / BPS_DENOMINATOR
    return (grossFee * (BPS_DENOMINATOR - discount)) / BPS_DENOMINATOR
}

// computeFeeBreakdown decomposes a settled request against the escrowed
// maxPrice and the ticket's open-time fee snapshot.
export function computeFeeBreakdown(
    amountCharged: bigint,
    maxPrice: bigint,
    feeBps: bigint | number,
    discountBps: bigint | number,
): FeeBreakdown {
    const fee = netFee(amountCharged, feeBps, discountBps)
    const totalDebit = amountCharged + fee
    return { amountCharged, netFee: fee, refund: maxPrice > totalDebit ? maxPrice - totalDebit : 0n, totalDebit }
}
