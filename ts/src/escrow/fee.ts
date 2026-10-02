/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Settlement fee math and settle-fee sizing. Mirrors proto/go/escrow/fee.go and
// settle_budget.go, which mirror ZeroSignalEscrow.finalizeSettlement. All
// amounts are microUSDC.

import { BPS_DENOMINATOR, REVENUE_BUCKET_COUNT } from './constants.js'

// Mirror the contract's RING_GAP_OPCODES_PER_ITER and the AVM per-app-call
// opcode budget one op-up grants.
const RING_GAP_OPCODES_PER_ITER = 40n
const AVM_OPCODE_BUDGET_PER_OP_UP = 700n

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

// netFee is the contract's fee math, floor for floor:
//   grossFee = floor(amountCharged * feeBps / 10000)
//   netFee   = floor(grossFee * (10000 - discountBps) / 10000)
// discountBps above 10000 can't occur on chain; it is clamped so the
// (10000 - discountBps) term can't go negative. The bps arguments also take a
// number because TicketRecord stores them as u16 and decodes them as one.
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

// settleInnerCount is an upper bound on the USDC disbursement inner-txns a
// settle submits: operator payout and treasury fee when amountCharged > 0, and
// a refund when maxPrice > amountCharged. It deliberately takes no feeBps: a
// composer holding a cached fee global that the admin rotated mid-ticket would
// under-count either way and under-fund the settle, while this bound never
// under-counts and over-counts by at most one.
export function settleInnerCount(amountCharged: bigint, maxPrice: bigint): bigint {
    let inners = 0n
    if (amountCharged > 0n) inners += 2n
    if (maxPrice > amountCharged) inners += 1n
    return inners
}

// ringGapIters is the number of revenue-ring catch-up iterations a settle runs
// for a box last written on lastDay. Only safe with the box's ACTUAL
// bucketsLastDay: the full-wrap reset makes it non-monotonic, so a staler box
// can score fewer iterations. Given only a lower bound on lastDay, use
// boundedRingGapIters.
export function ringGapIters(lastDay: bigint, currentDay: bigint): bigint {
    if (lastDay === 0n || currentDay <= lastDay) return 0n
    const gap = currentDay - lastDay
    if (gap >= BigInt(REVENUE_BUCKET_COUNT)) return 0n
    return gap - 1n
}

// boundedRingGapIters is ringGapIters made monotone by clamping a full-wrap gap
// to the loop's maximum, so it upper-bounds any box written on or after lastDay.
export function boundedRingGapIters(lastDay: bigint, currentDay: bigint): bigint {
    if (lastDay === 0n || currentDay <= lastDay) return 0n
    const gap = currentDay - lastDay
    if (gap < BigInt(REVENUE_BUCKET_COUNT)) return gap - 1n
    return BigInt(REVENUE_BUCKET_COUNT) - 1n
}

// gapOpUpsForIters converts catch-up iterations (summed over the node and
// operator boxes) into the extra op-up inner-txns a settle must fund:
// ceil(iters * perIter / perOpUp).
export function gapOpUpsForIters(iters: bigint): bigint {
    if (iters === 0n) return 0n
    return (iters * RING_GAP_OPCODES_PER_ITER + AVM_OPCODE_BUDGET_PER_OP_UP - 1n) / AVM_OPCODE_BUDGET_PER_OP_UP
}
