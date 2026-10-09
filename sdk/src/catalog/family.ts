/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Which models an automatic pick chooses among for a route, best first. The
// pick is the head of this ranking and a failed pick falls back through the
// rest, so an app that builds both from the same rows gets one answer.

import { type RankedRow, compareUniqueModelRows } from './rows.js'

/**
 * Where the payer's balance stands: still loading, a $0 payer that can use
 * free models only, or funded.
 */
export type FamilyBalance = 'loading' | 'free-only' | 'funded'

/** What the payer can pay for, read per row. */
export interface FamilyAffordability<R> {
    /** Whether the payer can afford this row; absent while that's unknown, and every row then counts. */
    isAffordable?: ((row: R) => boolean) | undefined
    /** Whether this row is a free model; absent reads as none being free. */
    isFree?: ((row: R) => boolean) | undefined
    balance: FamilyBalance
}

/**
 * The rows of a route's family an automatic pick chooses among, ranked by
 * `compareUniqueModelRows`; empty when none qualifies.
 *
 * - The affordable rows, with free ones dropped for a funded payer: it never
 *   spends a daily free-ticket allowance on a turn it didn't pick. This is a
 *   filter rather than a ranking rule because the comparator only demotes free
 *   models incidentally (they offer no image tools).
 * - None of those, and the payer is free-only: nothing. A paid model would only
 *   dead-end at the send-time balance gate.
 * - None, and the payer is funded: the paid rows (all of them if none is
 *   paid), so the balance gate can offer a deposit rather than silently
 *   falling back to free models.
 * - None, and the balance is still loading: every row, so a pick still resolves.
 */
export function rankFamilyCandidates<R extends RankedRow>(
    eligible: readonly R[],
    afford: FamilyAffordability<R>,
    preferImageTools: boolean,
): R[] {
    const { isAffordable, isFree, balance } = afford
    const isPaid = (r: R) => balance !== 'funded' || !isFree?.(r)
    const affordable = isAffordable ? eligible.filter((r) => isAffordable(r)) : [...eligible]
    let candidates = affordable.filter(isPaid)
    if (candidates.length === 0) {
        if (balance === 'free-only') return []
        const paid = eligible.filter(isPaid)
        candidates = paid.length > 0 ? paid : [...eligible]
    }
    return candidates.sort((a, b) => compareUniqueModelRows(a, b, preferImageTools))
}
