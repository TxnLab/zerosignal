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
import { type Ticket as SolanaTicket, claimHash, ticketView as solanaTicketView } from '@txnlab/zs-proto/solana/zsescrow'

import { solanaClaimFields } from './solana/claim.js'
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
     * deployment (a ResolvedNetwork.key) scopes the record to one deployment:
     * the payer's address is valid on every network, so a journal shared
     * across them must never re-fire a testnet ticket against mainnet, nor
     * forget one whose box mainnet does not have.
     * escrowAppId is written too on Algorand, where it was the scope before
     * deployment existed, so an older SDK reading the journal still finds its
     * rows. Absent on a row an older SDK wrote; see ownsRecord.
     */
    escrowAppId: bigint
    deployment?: string
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
    /**
     * Set on an open row whose receipt the node signed but that failed a
     * later check (its amount or its body hash). The payer co-signs none of
     * it; a sweep holds an operator claim against its amount, to freeze one
     * that takes more and never lapse it. A host journal must keep it as it
     * keeps settle.
     */
    signed?: SettleArgs
}

/**
 * The receipt a sweep holds an operator claim against: a verified one on a
 * settle_pending row, else one the node signed that failed a check, else
 * none. Go's TicketRecord.signedArgs.
 */
export function signedArgs(rec: Pick<TicketRecord, 'status' | 'settle' | 'signed'>): SettleArgs | undefined {
    if (rec.status === 'settle_pending' && rec.settle !== undefined) return rec.settle
    return rec.signed
}

/**
 * ReconcileAction is named for the escrow call it makes; wait and forget make
 * none. freeze is the payer's settle() at the row's receipt, sent because it
 * will mismatch the operator's claim, and paid for the freeze it causes.
 */
export type ReconcileAction = 'wait' | 'forget' | 'refundInactive' | 'settleLapsed' | 'settle' | 'freeze'

/**
 * ClaimVerdict is how the operator's pending settle claim on a ticket stands
 * against the payer's own verified receipt for it, Go's ClaimVerdict:
 *
 *   - '' (unread): the ack went through the node's settle group, whose checks
 *     already compare the node's half with the receipt.
 *   - unreadable: the box read failed. The ack goes out anyway, since a failed
 *     read is no evidence against the claim.
 *   - none: no operator claim stands, and none can be answered. The box is
 *     gone, frozen, or carries the payer's own half.
 *   - open: the box is open, with neither side's half on it. The payer's half
 *     at the receipt is the first, and an operator half that differs from it
 *     then freezes the ticket instead of lapsing at the operator's figure.
 *   - agrees: the claim carries every value the payer's settle sends, so that
 *     settle finalizes the ticket.
 *   - overclaims: the claim takes more than the receipt charges. The payer's
 *     settle freezes the ticket. Left alone, the claim is paid in full by
 *     settleLapsed after the deadline.
 *   - contradicts: the claim differs from the receipt but takes no more than
 *     it. A settle would freeze the payer's own escrow and pool slot for
 *     nothing, so the payer leaves the claim to lapse at the operator's figure.
 */
export type ClaimVerdict = '' | 'unreadable' | 'none' | 'open' | 'agrees' | 'overclaims' | 'contradicts'

/**
 * judgeClaim compares the operator's pending claim on box (null when gone)
 * with the payer's settle args. Only the amount separates an over-claim from a
 * contradiction: a timing or usage difference moves the operator's own
 * on-chain aggregates, not the payer's money. Mirrors Go's judgeClaim;
 * testdata/ack_settle_vectors.json pins it.
 */
export function judgeClaim(a: SettleArgs, box: TicketBoxView | null): ClaimVerdict {
    if (box === null) return 'none'
    return weighClaim(ticketView(box).status, box.pendingAmount, a.amountCharged, () => claimMatches(a, box))
}

/** The Solana ticket account fields judgeSolanaClaim reads. */
export type SolanaTicketView = Pick<SolanaTicket, 'status' | 'pendingAmount' | 'claimHash'>

/**
 * judgeSolanaClaim is judgeClaim for a Solana ticket account (null when
 * closed). The account keeps the first half's hash, not its fields, so a
 * claim matches when the payer's own fields hash to it. Mirrors Go's
 * judgeSolanaClaim; testdata/ack_settle_vectors.json pins it.
 */
export function judgeSolanaClaim(a: SettleArgs, t: SolanaTicketView | null): ClaimVerdict {
    if (t === null) return 'none'
    // The verdict reads no deadline, so none is passed.
    const status = solanaTicketView({ status: t.status, expiresAt: 0n, grace: 0 }).status
    return weighClaim(status, t.pendingAmount, a.amountCharged, () => solanaClaimMatches(a, t.claimHash))
}

// Whether a's claim fields hash to claim. Args a host journal mangled (a
// digest that isn't 32 bytes, a count past u64) can't be hashed, and match
// nothing, as judgeClaim's field comparison finds of them.
function solanaClaimMatches(a: SettleArgs, claim: Uint8Array): boolean {
    let h: Uint8Array
    try {
        h = claimHash(solanaClaimFields(a))
    } catch {
        return false
    }
    return bytesEqual(h, claim)
}

// The verdict on a ticket of status carrying an operator claim of pending,
// against a receipt charging charged that the claim matches in full or not.
function weighClaim(status: number, pending: bigint, charged: bigint, matches: () => boolean): ClaimVerdict {
    if (status === SettleStatus.Open) return 'open'
    if (status !== SettleStatus.PendingOperator) return 'none'
    if (pending > charged) return 'overclaims'
    return matches() ? 'agrees' : 'contradicts'
}

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
 *   - A settle is legal only inside the window, so a verified receipt is
 *     re-fired there: against an OPEN box, or a box carrying the operator's
 *     claim when the claim matches the receipt.
 *   - A claim that takes more than a receipt the node signed, verified or
 *     not, is frozen with the receipt's settle inside the window, and the
 *     payer never lapses it after.
 *   - Past the window any other operator claim goes to settleLapsed, but only
 *     once lapseFallbackMs has passed, since the node's own driver normally
 *     does it.
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
    rec: Pick<TicketRecord, 'status' | 'expiresAt' | 'updatedAt' | 'settle' | 'signed'>,
    box: TicketBoxView | null,
    clock: { nowMs: number; chainMs?: number },
    lapseFallbackMs: number = DEFAULT_LAPSE_FALLBACK_MS,
): ReconcileAction {
    if (box === null) return decideSettlement(rec, null, '', clock, lapseFallbackMs)
    const a = signedArgs(rec)
    const claim = a !== undefined ? judgeClaim(a, box) : ''
    return decideSettlement(rec, ticketView(box), claim, clock, lapseFallbackMs)
}

// decideSettlement is decideTicket over the rail-neutral view of the ticket
// (null when gone), with the rail's answer to how the operator's pending claim
// stands against the payer's recorded receipt. Module-private, like Go's: a
// second rail's wrapper calls it from inside the SDK, and exporting it would
// make it semver surface before that rail exists.
function decideSettlement(
    rec: Pick<TicketRecord, 'status' | 'expiresAt' | 'updatedAt' | 'settle' | 'signed'>,
    view: TicketView | null,
    claim: ClaimVerdict,
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
            // The operator can still lapse it, since settleLapsed is
            // permissionless; the payer only declines to pay the fee for a
            // payout its receipt contradicts.
            if (claim === 'overclaims') return 'wait'
            return BigInt(chainMs) > deadlineMs + BigInt(Math.floor(lapseFallbackMs)) ? 'settleLapsed' : 'wait'
        case 'wait': {
            if (BigInt(chainMs + RECONCILE_SKEW_MS) > deadlineMs) return 'wait'
            // Ahead of the grace: the grace waits out a live ack still
            // confirming, and every half the payer signs carries the receipt's
            // amount, so no such ack can be what left an over-claim on the
            // box. Waiting would only spend window the freeze has to land in.
            if (view.status === SettleStatus.PendingOperator && claim === 'overclaims') return 'freeze'
            if (rec.status !== 'settle_pending' || rec.settle === undefined || nowMs - updatedAt < SETTLE_PENDING_GRACE_MS) {
                return 'wait'
            }
            if (view.status === SettleStatus.Open) return 'settle'
            if (view.status === SettleStatus.PendingOperator && claim === 'agrees') return 'settle'
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
