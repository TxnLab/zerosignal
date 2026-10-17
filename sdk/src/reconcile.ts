/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What the payer's sweep does about a ticket it journaled, mirroring
// proto/go/zs's journal records and decideTicket. The contract's rules are
// zs-proto's classify; this adds what only the payer knows, its own receipt.
// proto/testdata/reconcile_vectors.json pins it against Go.

import { type TicketRecord as TicketBox, ticketView } from '@txnlab/zs-proto/escrow'
import { SettleStatus, type TicketView, classify } from '@txnlab/zs-proto/settle'

import type { NodeRef, TicketStatus } from './types.js'

/**
 * SettleArgs are the receipt values the payer co-signs on settle(). The
 * contract freezes the ticket if they disagree with the node's half, so a
 * re-fire must send them verbatim.
 */
export interface SettleArgs {
    amountCharged: bigint
    /** 32 bytes. */
    receiptDigest: Uint8Array
    ttftMs: bigint
    decodeMs: bigint
    inputTokens: bigint
    outputTokens: bigint
    outputUsageType: number
    auxOutputUsageType: number
    auxOutputCount: bigint
}

/**
 * TicketRecord is what a sweep needs to finish a ticket after a restart. Every
 * field is public on chain; no prompt or response content belongs here. Times
 * are unix milliseconds.
 */
export interface TicketRecord {
    ticketId: string
    openTxId: string
    /**
     * Scopes the record to one deployment: the payer's address is valid on
     * every network, so a journal shared across them must never re-fire a
     * testnet ticket against mainnet.
     */
    escrowAppId: bigint
    target: NodeRef
    payer: string
    maxPrice: bigint
    /**
     * The ticket's expiry. The contract refuses an open after it, so a box
     * still missing then never appears. Once the box exists its own deadline
     * is authoritative.
     */
    expiresAt: number
    status: TicketStatus
    createdAt: number
    updatedAt: number
    /** Set with settle_pending. */
    settle?: SettleArgs
}

/** ReconcileAction is named for the escrow call it makes; wait and forget make none. */
export type ReconcileAction = 'wait' | 'forget' | 'refundInactive' | 'settleLapsed' | 'settle'

/**
 * How long a ticket must sit in settle_pending before a sweep re-fires the
 * payer's settle: the live settle may still be confirming, and a re-fire after
 * it lands reverts and costs a fee.
 */
export const SETTLE_PENDING_GRACE_MS = 2 * 60_000

/**
 * How long past the deadline a sweep leaves an operator's claim for the node's
 * own driver before calling settleLapsed itself.
 */
export const DEFAULT_LAPSE_FALLBACK_MS = 10 * 60_000

// Pads every deadline comparison against the gap between the local clock and
// the chain's latest timestamp, so a call is not sent just before (or after)
// the window the contract checks.
const RECONCILE_SKEW_MS = 15_000

/**
 * decideTicket is what a sweep does about one journaled ticket, given its box
 * (null when gone) and the time:
 *
 *   - A settle is legal only inside the window, so a recorded receipt is
 *     re-fired there: against an OPEN box, or a box carrying the operator's
 *     claim when the claim matches the receipt (a mismatch would freeze it).
 *   - Past the window an operator claim goes to settleLapsed, but only once
 *     lapseFallbackMs has passed, since the node's own driver normally does it.
 *   - A missing box is finished only once the ticket has expired: the open is
 *     submitted without waiting for confirmation, and the contract accepts it
 *     until expires_at.
 *   - A frozen box is forgotten: no payer call can change it.
 *
 * The deadlines are the contract's, checked against the chain's clock;
 * the settle-pending grace is about local submit latency, checked against
 * the local one. clock.chainMs, when given, is the chain's latest timestamp
 * and decides the deadlines; without it nowMs decides everything, padded for
 * the skew between the two. Read both fresh for each ticket: a sweep that
 * waits on chain calls between tickets otherwise decides late tickets on an
 * old clock.
 */
export function decideTicket(
    rec: Pick<TicketRecord, 'status' | 'expiresAt' | 'updatedAt' | 'settle'>,
    box: TicketBoxView | null,
    clock: { nowMs: number; chainMs?: number },
    lapseFallbackMs: number = DEFAULT_LAPSE_FALLBACK_MS,
): ReconcileAction {
    if (box === null) return decideSettlement(rec, null, false, clock, lapseFallbackMs)
    const matched = rec.settle !== undefined && claimMatches(rec.settle, box)
    return decideSettlement(rec, ticketView(box), matched, clock, lapseFallbackMs)
}

// decideSettlement is decideTicket over the rail-neutral view of the ticket
// (null when gone), with the rail's answer to whether the operator's pending
// claim carries the payer's recorded receipt. Module-private, like Go's: a
// second rail's wrapper calls it from inside the SDK, and exporting it would
// make it semver surface before that rail exists.
function decideSettlement(
    rec: Pick<TicketRecord, 'status' | 'expiresAt' | 'updatedAt' | 'settle'>,
    view: TicketView | null,
    claimMatched: boolean,
    clock: { nowMs: number; chainMs?: number },
    lapseFallbackMs: number = DEFAULT_LAPSE_FALLBACK_MS,
): ReconcileAction {
    // Whole milliseconds: a clock a caller extrapolated can be fractional,
    // which BigInt refuses, and the skew pad dwarfs what flooring drops. A
    // clock that isn't a number at all decides nothing.
    const nowMs = Math.floor(clock.nowMs)
    const chainMs = Math.floor(clock.chainMs ?? clock.nowMs)
    if (!Number.isFinite(nowMs) || !Number.isFinite(chainMs) || !Number.isFinite(lapseFallbackMs)) {
        return 'wait'
    }
    // A record time that isn't a number reads as Go's zero time: long past,
    // so a missing box is forgotten and the grace has elapsed.
    const expiresAt = Number.isFinite(rec.expiresAt) ? rec.expiresAt : 0
    const updatedAt = Number.isFinite(rec.updatedAt) ? rec.updatedAt : 0
    if (view === null) {
        return chainMs > expiresAt + RECONCILE_SKEW_MS ? 'forget' : 'wait'
    }
    const deadlineMs = view.deadline * 1000n
    switch (classify(view, new Date(chainMs - RECONCILE_SKEW_MS))) {
        case 'arbitrate':
            return 'forget'
        case 'refundInactive':
            return 'refundInactive'
        case 'settleLapsed':
            return BigInt(chainMs) > deadlineMs + BigInt(Math.floor(lapseFallbackMs)) ? 'settleLapsed' : 'wait'
        case 'wait': {
            const s = rec.settle
            if (
                rec.status !== 'settle_pending' ||
                s === undefined ||
                nowMs - updatedAt < SETTLE_PENDING_GRACE_MS ||
                BigInt(chainMs + RECONCILE_SKEW_MS) > deadlineMs
            ) {
                return 'wait'
            }
            if (view.status === SettleStatus.Open) return 'settle'
            if (view.status === SettleStatus.PendingOperator && claimMatched) return 'settle'
            return 'wait'
        }
    }
    return 'wait'
}

/** The box fields decideTicket reads. */
export type TicketBoxView = Pick<
    TicketBox,
    | 'status'
    | 'pendingBy'
    | 'expiresAt'
    | 'settlementGraceSeconds'
    | 'pendingAmount'
    | 'pendingDigest'
    | 'pendingTtftMs'
    | 'pendingDecodeMs'
    | 'pendingInputCount'
    | 'pendingOutputCount'
    | 'pendingOutputUsageType'
    | 'pendingAuxOutputUsageType'
    | 'pendingAuxOutputCount'
>

// Whether the operator's pending claim carries the values the payer's settle
// would send. The contract freezes the ticket on any difference.
function claimMatches(a: SettleArgs, box: TicketBoxView): boolean {
    return (
        a.amountCharged === box.pendingAmount &&
        bytesEqual(a.receiptDigest, box.pendingDigest) &&
        a.ttftMs === box.pendingTtftMs &&
        a.decodeMs === box.pendingDecodeMs &&
        a.inputTokens === box.pendingInputCount &&
        a.outputTokens === box.pendingOutputCount &&
        a.outputUsageType === box.pendingOutputUsageType &&
        a.auxOutputUsageType === box.pendingAuxOutputUsageType &&
        a.auxOutputCount === box.pendingAuxOutputCount
    )
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((x, i) => x === b[i])
}
