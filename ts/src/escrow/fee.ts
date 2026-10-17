/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Settle-fee sizing for ZeroSignalEscrow. Mirrors proto/go/escrow/fee.go and
// settle_budget.go, which mirror ZeroSignalEscrow.finalizeSettlement. The fee
// itself is the same on every rail and lives in ../settle; it is re-exported
// here for callers that import it from escrow. All amounts are microUSDC.

import { REVENUE_BUCKET_COUNT } from './constants.js'

export { computeFeeBreakdown, netFee, type FeeBreakdown } from '../settle/fee.js'

// Mirror the contract's RING_GAP_OPCODES_PER_ITER and the AVM per-app-call
// opcode budget one op-up grants.
const RING_GAP_OPCODES_PER_ITER = 40n
const AVM_OPCODE_BUDGET_PER_OP_UP = 700n

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
