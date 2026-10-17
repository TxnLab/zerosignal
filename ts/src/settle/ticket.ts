/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The settlement rules every payment rail shares: what a live ticket allows
// right now. Each rail decodes its own ticket record (escrow for Algorand) into
// a TicketView. Mirrors proto/go/settle, pinned by
// proto/testdata/settle_vectors.json.

/** A live ticket's state, in the terms the settlement rules use. */
export const SettleStatus = {
    /**
     * A state the rail's decoder does not know. Zero, matching Go's zero value,
     * so a view nobody filled in classifies as unknown, never as wait.
     */
    Unrecognized: 0,
    /** Funded, with no claim recorded. */
    Open: 1,
    /** The payer has recorded its half of a cooperative settle; the operator has not matched it. */
    PendingPayer: 2,
    /** The operator has recorded a claim the payer has not matched. */
    PendingOperator: 3,
    /** The sides disagreed, or the payer protested. Terminal: no call accepts it, and nothing on chain resolves it. */
    Frozen: 4,
} as const

export type SettleStatus = (typeof SettleStatus)[keyof typeof SettleStatus]

/** The rail-neutral view of a live ticket that the settlement rules read. */
export interface TicketView {
    /** A SettleStatus; any other number reads as unrecognized. */
    status: number
    /**
     * D = expires_at + the settlement grace, unix seconds, read off the ticket
     * itself: authoritative over a deadline recomputed from a cached grace
     * setting the admin can rotate.
     */
    deadline: bigint
}

// Each verdict is named for the call it authorizes, matching Go's
// Verdict.String().
//   wait            — inside the settlement window: either side may settle,
//                     the payer may protest; neither deadline call is legal yet.
//   refundInactive  — past the deadline with no operator claim; returns the
//                     full maxPrice to the payer.
//   settleLapsed    — past the deadline carrying an operator claim; pays the
//                     claim and refunds the rest.
//   arbitrate       — frozen. No call accepts it at any time and there is no
//                     unfreeze, so the escrow stays locked; any resolution is
//                     off-chain. Don't present it as something that resolves
//                     on its own.
//   unknown         — a state the rules don't recognize. Waiting never makes a
//                     call legal here, so never render it as "too early".
export type Verdict = 'wait' | 'refundInactive' | 'settleLapsed' | 'arbitrate' | 'unknown'

/**
 * classify reports what can legally happen to t at now. Padding now for clock
 * skew against the chain's clock is the caller's job.
 */
export function classify(t: TicketView, now: Date): Verdict {
    // Recognize the state before consulting the clock, so a state no call
    // accepts can't come back as "wait", which would read as "legal at D".
    // Frozen outranks the clock for the same reason.
    const pastDeadline = BigInt(now.getTime()) > t.deadline * 1000n
    switch (t.status) {
        case SettleStatus.Frozen:
            return 'arbitrate'
        case SettleStatus.Open:
        case SettleStatus.PendingPayer:
            return pastDeadline ? 'refundInactive' : 'wait'
        case SettleStatus.PendingOperator:
            return pastDeadline ? 'settleLapsed' : 'wait'
    }
    return 'unknown'
}
