/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The pool-sizing rule both rails share, Go's planPoolDeposit and poolTarget
// in go/zs/wallet.go. Kept out of mbr.ts, which the package index re-exports,
// because the Go twins are unexported: neither is public API.

const MAX_UINT64 = (1n << 64n) - 1n

/** PoolDepositPlan is one funding pass, as planPoolDeposit sizes it. */
export interface PoolDepositPlan {
    /** To deposit; 0 when nothing is. */
    amount: bigint
    /** After amount lands, the pool is still short of the working set. */
    belowTarget: boolean
    /** The pool backs no ticket slot and the wallet can't fund one. */
    unaffordable: boolean
    /**
     * What the next useful deposit costs the wallet: the quota term a pool
     * backing a slot still lacks, else what the pool's part slot lacks of a
     * whole one, overhead included. Set when nothing is deposited for want of
     * funds.
     */
    need: bigint
}

/**
 * planPoolDeposit sizes a funding pass over either rail's pool: as many whole
 * slots as the wallet affords, up to the working set, with the quota term on
 * top only if it still fits; with no whole slot affordable, the quota term
 * alone, for a pool that already backs a slot. unit is what one ticket holds
 * (box MBR, or rent), gross what the pool backs counting live tickets, and
 * overhead what a deposit costs the wallet past its amount. unit must be
 * non-zero.
 */
export function planPoolDeposit(slots: bigint, unit: bigint, quotaDue: bigint, gross: bigint, overhead: bigint, spendable: bigint): PoolDepositPlan {
    const none: PoolDepositPlan = { amount: 0n, belowTarget: false, unaffordable: false, need: 0n }
    const target = poolTarget(slots, unit, quotaDue)
    if (gross >= target) return none

    const net = spendable > overhead ? spendable - overhead : 0n
    // The next slot costs only what the pool's part slot lacks.
    const need = unit - (gross % unit) + overhead

    const current = gross / unit
    // The pool and the wallet together, so a part slot already in the pool
    // counts toward the next one; saturating as Go's does.
    const reach = gross + net > MAX_UINT64 ? MAX_UINT64 : gross + net
    const affordable = reach / unit
    const targetSlots = affordable < slots ? affordable : slots
    if (targetSlots <= current) {
        const quota = quotaRemainderShortfall(unit, quotaDue, gross)
        if (current >= 1n && quota > 0n) {
            return net >= quota
                ? { ...none, amount: quota, belowTarget: gross + quota < target }
                : { ...none, belowTarget: true, need: quota + overhead }
        }
        return current >= 1n ? { ...none, belowTarget: true, need } : { ...none, unaffordable: true, need }
    }
    let amount = targetSlots * unit - gross
    if (net >= amount + quotaDue) amount += quotaDue
    return { ...none, amount, belowTarget: gross + amount < target }
}

/**
 * slots × unit + quotaDue, saturating at the uint64 ceiling as Go's poolTarget
 * does, so a target past it reads as unaffordable, never as small.
 */
export function poolTarget(slots: bigint, unit: bigint, quotaDue: bigint): bigint {
    const t = slots * unit + quotaDue
    return t > MAX_UINT64 ? MAX_UINT64 : t
}

// The quota term the pool's sub-slot remainder doesn't already cover.
function quotaRemainderShortfall(unit: bigint, quotaDue: bigint, gross: bigint): bigint {
    if (quotaDue === 0n || unit === 0n) return 0n
    const remainder = gross % unit
    return remainder >= quotaDue ? 0n : quotaDue - remainder
}
