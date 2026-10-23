/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A paid turn's receipt, as the Client handles it, mirroring proto/go/zs
// dispatch.go's checkReceipt: verify the node's signed receipt, record the
// charge with the spend guard, and build the escrow submit the verdict calls
// for (the ack, or a protest of a body that doesn't match its hash). The
// submit runs later: after the reply on a buffered turn, inline on a stream.
// ack.ts's checkReceipt is the standalone primitive; this is the Client's.

import type { Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'

import { NoResolveFrozenError, ProtestAfterDeadlineError, SentSettleError } from './ack.js'
import type { SpendGuard } from './config.js'
import { findError } from './errors.js'
import { APPROVAL_ASSERT, ApprovalError } from './escrow/revert.js'
import { type Operator, refOf } from './operator.js'
import { type OpenHandle, ProtestReason, type ProtestReasonCode } from './parts.js'
import { algoOnly } from './fees.js'
import type { FeeUnit, Rail } from './network.js'
import type { LogAttrs, Logger } from './ports.js'
import { guardRecords } from './spend-guard.js'
import type { NodeExclusionStore } from './routing/exclusion.js'
import type { RelayHop } from './routing/relay.js'
import type { NodeRef, Settlement, SettleKind } from './types.js'
import { ReceiptError, ReceiptForAnotherTicketError, type ReceiptViolation, verifyReceipt } from './verify.js'

/**
 * The contract's default maxDisputeExcerptBytes. The excerpt is cut to it so
 * a protest never reverts on size; below the contract's cap is always safe.
 */
export const DISPUTE_EXCERPT_CAP = 1800

/**
 * Bounds one ack or protest submit. It is detached from the caller's signal,
 * since a caller that leaves the moment it has its content must not abort the
 * settle, so this is what stops a wedged algod holding it forever.
 */
export const SETTLE_SUBMIT_TIMEOUT_MS = 15_000

/**
 * Bounds one journal call on the request path. A TicketJournal takes no
 * signal, so the call is abandoned, not cancelled: a store that hangs costs
 * the turn this long, never the settle.
 */
export const JOURNAL_TIMEOUT_MS = 5000

/** withJournalTimeout settles with p, or rejects once ms pass first. */
export async function withJournalTimeout(p: Promise<void> | void, ms: number = JOURNAL_TIMEOUT_MS): Promise<void> {
    let timer: ReturnType<typeof setTimeout> | undefined
    const late = new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`journal call timed out after ${ms}ms`)), ms)
    })
    try {
        await Promise.race([Promise.resolve(p), late])
    } finally {
        clearTimeout(timer)
    }
}

/** One submit's outcome: what it did, and its error when it failed. */
export interface SettleResult {
    settlement: Settlement
    err?: unknown
}

/** SettleSubmit is the escrow half of receipt handling, the ack or a protest. */
export type SettleSubmit = () => Promise<SettleResult>

/**
 * SettleSlot carries one turn's submit outcome from wherever the submit runs
 * to the caller waiting on the turn, Go's settleSlot.
 */
export class SettleSlot {
    /** Set once a submit is built, before the turn's reply. */
    expected = false
    readonly done: Promise<SettleResult>
    #resolve!: (r: SettleResult) => void
    #result: SettleResult | undefined

    constructor() {
        this.done = new Promise((resolve) => {
            this.#resolve = resolve
        })
    }

    /** The outcome once finish has recorded it. */
    get result(): SettleResult | undefined {
        return this.#result
    }

    /** Records the outcome; only the first call counts. */
    finish(r: SettleResult): void {
        if (this.#result !== undefined) return
        this.#result = r
        this.#resolve(r)
    }
}

/** How a receipt fared and, once its submit has run, what the submit did. */
export interface TurnCheck {
    /** The failed check, or '' when the receipt verified. */
    violation: string
    settled: Settlement
    /** Set when the node was barred on its own signed word. */
    excluded: boolean
    /** How, the NodeExcluded reason: one of EXCLUSION_REASONS. */
    exclusion?: string
}

/**
 * The NodeExcluded reasons a receipt check reports, Go's exclusionSettleGroup,
 * exclusionOverclaim and exclusionReceiptForAnotherTicket.
 */
export const EXCLUSION_REASONS = {
    /** The node's settle group failed verification. */
    settleGroup: 'settle_group_rejected',
    /** The node's settle claim on chain takes more than the receipt it signed. */
    overclaim: 'settle_claim_exceeds_receipt',
    /** The node signed the receipt it handed over for another ticket. */
    receiptForAnotherTicket: 'receipt_names_other_ticket',
} as const

/**
 * The NodeExcluded reason verifyReceipt's refusal alone bars the node for, or
 * undefined when it bars none: Go's receiptExclusion. Apart from
 * checkTurnReceipt so the receipt vectors pin the same classification Go
 * makes.
 */
export function receiptExclusion(err: unknown): string | undefined {
    return findError(err, ReceiptForAnotherTicketError) !== undefined ? EXCLUSION_REASONS.receiptForAnotherTicket : undefined
}

/** What the receipt check reads off the Client. */
export interface ReceiptCheckDeps {
    logger: Logger
    spendGuard?: SpendGuard | undefined
    nodeExclusions?: NodeExclusionStore | undefined
    /**
     * Journals the values the payer will co-sign, before the reply and the
     * submit, so a restart mid-submit can re-fire it. Bounded by
     * journalTimeoutMs; a failure is logged and the ack goes ahead.
     */
    journalReceipt?(handle: OpenHandle, receipt: UsageReceipt): Promise<void> | void
    /**
     * Journals a receipt whose signature verified but that failed a later
     * check, so the reconciler holds an operator claim against it after a
     * restart. Bounded and logged as journalReceipt is.
     */
    journalSigned?(handle: OpenHandle, receipt: UsageReceipt): Promise<void> | void
    /** Overrides JOURNAL_TIMEOUT_MS. */
    journalTimeoutMs?: number | undefined
    /** Stops the refund watchdog tracking a ticket the submit finished. */
    resolveRefund?(ticketId: string): void
    /**
     * Pins the amount the node signed for a ticket on the refund watchdog: the
     * only figure it can hold a later operator claim against.
     */
    recordReceipt?(ticketId: string, node: NodeRef, amountCharged: bigint): void
    /** Watches an atomic settle until it lands, then drops the ticket's journal row. */
    confirmSettled?(ticketId: string, txId: string, handle: OpenHandle): void
    /** The coin the deployment's network fees are paid in. */
    feeUnit: FeeUnit
    /** The deployment's rail, which decides what the settle slot holds; absent is Algorand. */
    rail?: Rail | undefined
}

/** One receipt to check, and the turn it belongs to. */
export interface TurnReceipt {
    endpoint: string
    model: string
    ticket: Ticket
    op: Operator
    /** The opened escrow, or null when there is none to submit against. */
    handle: OpenHandle | null
    receipt: UsageReceipt
    /** sha256 of the body, or of the concatenated stream frames. */
    computedHash: Uint8Array
    /** What the node delivered: the protest's excerpt. */
    plaintext: Uint8Array
    /** The node's settle group, base64, when it sent one that decodes; else null. */
    settleGroup: string | null
    hop: RelayHop | null
    /** Where the turn's caller learns the submit's outcome. */
    slot?: SettleSlot | undefined
}

const opAttrs = (op: Operator): LogAttrs => ({ operator_id: op.id, node_id: op.nodeId })

const relayAttrs = (hop: RelayHop | null): LogAttrs =>
    hop === null ? {} : { relay_operator_id: hop.relayId, relay_node_id: hop.relayNodeId }

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err))

/**
 * checkTurnReceipt verifies a receipt, records the spend outcome, journals a
 * verified receipt, and returns the escrow submit the verdict calls for, or
 * null when there is nothing to submit. check is filled in by the submit when
 * it runs.
 */
export async function checkTurnReceipt(
    deps: ReceiptCheckDeps,
    t: TurnReceipt,
): Promise<{ submit: SettleSubmit | null; check: TurnCheck }> {
    const log = deps.logger
    const { ticket, op, receipt, handle, hop } = t
    const ticketId = ticket.ticket_id
    const check: TurnCheck = { violation: '', settled: emptySettlement(''), excluded: false }

    // Detached from the caller, bounded by its own timeout from when it runs,
    // so a deferred submit gets its whole budget.
    const withSettle = (fn: (signal: AbortSignal) => Promise<SettleResult>): SettleSubmit => {
        if (t.slot) t.slot.expected = true
        return async () => {
            let r: SettleResult
            try {
                r = await fn(AbortSignal.timeout(SETTLE_SUBMIT_TIMEOUT_MS))
            } catch (err) {
                // A submit that threw still tells the waiting caller.
                t.slot?.finish({ settlement: emptySettlement(ticketId), err })
                throw err
            }
            r.settlement.ticketId = ticketId
            check.settled = r.settlement
            t.slot?.finish(r)
            return r
        }
    }

    let verifyErr: unknown
    try {
        verifyReceipt(receipt, ticket, op.ticketSigningKey, t.computedHash)
    } catch (err) {
        verifyErr = err
    }
    if (verifyErr === undefined) {
        // One line per paying request: the node-authoritative usage and charge.
        const paid: LogAttrs = {
            endpoint: t.endpoint,
            model: t.model,
            ...opAttrs(op),
            ...relayAttrs(hop),
            ticket_id: ticketId,
            actual_input_count: receipt.actual_input_count,
            cached_input_count: receipt.cached_input_count,
            actual_output_count: receipt.actual_output_count,
            amount_microusdc: receipt.amount_charged,
        }
        // Inference is denominated in USDC, which is dollar-pegged.
        const usd = receipt.amount_charged / 1_000_000
        if (usd > 0) paid.amount_usd = `$${usd.toFixed(6)}`
        log.info('zs request paid', paid)
        // The settled charge replaces the reserved ceiling. Ahead of the
        // journal: the reconciler reads a journaled receipt as counted.
        const guard = deps.spendGuard
        if (guard) guardRecords(log, 'settle', ticketId, () => guard.settle(ticketId, receipt.amount_charged))
        // The signed amount is the only figure the watchdog can hold a later
        // operator claim against, should the ack below not land.
        deps.recordReceipt?.(ticketId, refOf(op), BigInt(receipt.amount_charged))
        if (handle === null) return { submit: null, check }
        await journal(deps, handle, receipt)
        return {
            submit: withSettle(async (signal) => {
                // A failing ack doesn't fail the turn: the refund watchdog still
                // tracks the ticket. Only the waiting caller hears of it.
                const atomic = t.settleGroup !== null
                const res = await handle.ackSettle(receipt, t.settleGroup, signal)
                if (res.groupRejected && deps.nodeExclusions) {
                    // Proven misbehaviour: the node authored both halves and the
                    // receipt. The payment is unaffected; the ack went standalone.
                    deps.nodeExclusions.excludeNode(refOf(op))
                    check.excluded = true
                    check.exclusion = EXCLUSION_REASONS.settleGroup
                    log.warn('node excluded: handed a fraudulent settle group', {
                        ticket_id: ticketId,
                        operator_id: op.id,
                        node_id: op.nodeId,
                    })
                }
                if (res.claim === 'overclaims') {
                    // The node signed the receipt and posted the claim under one
                    // registered key, so this is the same self-contradiction the
                    // settle-group check bars a node for, whether or not the
                    // freeze went out.
                    excludeOverclaim(deps, check, op)
                    const attrs = { ticket_id: ticketId, ...opAttrs(op), receipt_microusdc: receipt.amount_charged }
                    if (res.frozen === true) {
                        log.warn('node excluded: its on-chain settle claim exceeds the receipt it signed; acked with the receipt to freeze the ticket', attrs)
                    } else if (res.err !== undefined && res.payerSettle === true) {
                        log.warn('node excluded: its on-chain settle claim exceeds the receipt it signed; the settle to freeze the ticket failed', {
                            ...attrs,
                            err: errText(res.err),
                        })
                    } else if (res.err !== undefined) {
                        // The node's group failed to submit and no settle followed it.
                        log.warn(
                            'node excluded: its on-chain settle claim exceeds the receipt it signed; its settle group failed to submit, and no freeze was sent, since the deployed escrow has no resolveFrozen',
                            { ...attrs, err: errText(res.err) },
                        )
                    } else {
                        // Nothing went out, so the turn reports no submit.
                        log.warn(
                            "node excluded: its on-chain settle claim exceeds the receipt it signed; not freezing it, since the deployed escrow has no resolveFrozen and would lock the escrow for good — the claim lapses at the operator's figure",
                            attrs,
                        )
                        return { settlement: emptySettlement(ticketId) }
                    }
                } else if (res.claim === 'contradicts' && res.err === undefined) {
                    log.warn(
                        "operator's settle claim contradicts its own receipt but takes no more; not acking, since that would only freeze the payer's escrow — the claim lapses at the operator's figure",
                        { ticket_id: ticketId, ...opAttrs(op), receipt_microusdc: receipt.amount_charged },
                    )
                    return { settlement: emptySettlement(ticketId) }
                }
                // Only a group that wasn't refused finalized the ticket; the
                // standalone fallback leaves a pending payer claim the watchdog
                // must keep tracking. A freeze, or the payer's half on an open
                // box, is the payer's own settle, sent in the group's place when
                // it failed to submit.
                const settledAtomically = atomic && !res.groupRejected && res.payerSettle !== true
                const kind: SettleKind = settledAtomically ? 'atomic' : 'payer_ack'
                if (res.err !== undefined) {
                    log.warn('ack-settle failed', {
                        ticket_id: ticketId,
                        atomic,
                        group_rejected: res.groupRejected,
                        txid: res.txid,
                        network_fee: res.feeMicroalgos,
                        err: errText(res.err),
                    })
                    // A settle sent and failed names its transaction, and on
                    // Solana may have paid its fee.
                    return { settlement: settlementOf(deps, ticketId, kind, res.txid, res.feeMicroalgos), err: res.err }
                }
                // Info when the payer paid a fee: a buffered reply was written
                // before this submit and can't report it.
                const at = res.feeMicroalgos > 0 ? log.info : log.debug
                at.call(log, 'ack-settle submitted', {
                    ticket_id: ticketId,
                    txid: res.txid,
                    atomic: settledAtomically,
                    network_fee: res.feeMicroalgos,
                })
                if (settledAtomically) {
                    // The group deleted the ticket box: nothing left to refund.
                    deps.resolveRefund?.(ticketId)
                    deps.confirmSettled?.(ticketId, res.txid, handle)
                }
                return { settlement: settlementOf(deps, ticketId, kind, res.txid, res.feeMicroalgos, res.frozen === true) }
            }),
            check,
        }
    }

    const violation: ReceiptViolation | '' = verifyErr instanceof ReceiptError ? verifyErr.violation : ''
    check.violation = violation === '' ? 'unknown' : violation
    log.warn('receipt verification failed', {
        endpoint: t.endpoint,
        model: t.model,
        ...opAttrs(op),
        ...relayAttrs(hop),
        ticket_id: ticketId,
        // Go names a violation of no known kind "ok".
        violation: violation === '' ? 'ok' : violation,
        err: errText(verifyErr),
    })
    // A receipt that didn't verify charged nothing legitimately: the ticket is
    // protested, or refunds or lapses on chain.
    const guard = deps.spendGuard
    if (guard) guardRecords(log, 'release', ticketId, () => guard.release(ticketId))
    // The receipt arrived sealed under this turn's response key, which no
    // relay holds, and its signature verified under the node's key, so the
    // node itself handed over a receipt for another ticket: proof of its
    // misbehaviour, as an over-claim is. In every other way it stays a sig
    // violation: neither pinned, journaled nor protested.
    const reason = receiptExclusion(verifyErr)
    if (reason !== undefined && deps.nodeExclusions) {
        deps.nodeExclusions.excludeNode(refOf(op))
        check.excluded = true
        check.exclusion = reason
        log.warn('node excluded: it signed a receipt for another ticket', {
            ticket_id: ticketId,
            ...opAttrs(op),
            receipt_ticket_id: receipt.ticket_id,
        })
    }
    // Both are found only after the signature verified, so the amount is
    // still one the node signed for this ticket. Named rather than "all but
    // sig": a violation of no known kind has an unknown signature, and a
    // pinned figure set too high would wave every later over-claim through.
    // The journal keeps it for the reconciler, which would otherwise lapse an
    // over-claim the watchdog refused to.
    if (violation === 'amount' || violation === 'body_hash') {
        deps.recordReceipt?.(ticketId, refOf(op), BigInt(receipt.amount_charged))
        if (handle !== null) await journalSigned(deps, handle, receipt)
    }
    // The contract refuses a protest over the signature or the amount. A
    // receipt naming another ticket is a sig violation: where Algorand's
    // protest would take it, it freezes this ticket on evidence about another.
    if (handle === null || violation !== 'body_hash') return { submit: null, check }
    const excerpt = t.plaintext.slice(0, DISPUTE_EXCERPT_CAP)
    return {
        submit: withSettle(async (signal) => {
            let call
            try {
                call = await handle.protest(receipt, excerpt, protestReasonFor(violation), signal)
            } catch (perr) {
                // A Solana protest that landed and failed paid its fee, which
                // the turn reports as the ack path reports a failed settle's.
                const sent = findError(perr, SentSettleError)?.submission
                const protest = { txid: sent?.txid ?? '', fee: Number(sent?.payerFeeMicroalgos ?? 0) }
                // A turn that outlived expires_at + grace can no longer freeze
                // the ticket, and no retry changes that. The same deadline bars
                // settle, so no freeze fallback either: the ticket goes to
                // settleLapsed if the operator has a pending claim and to
                // refundInactive if not; the refund watchdog stays armed and
                // drives whichever applies. Logged apart from a submit fault so
                // it doesn't read as one.
                if (
                    findError(perr, ApprovalError)?.assert === APPROVAL_ASSERT.protestAfterDeadline ||
                    findError(perr, ProtestAfterDeadlineError) !== undefined
                ) {
                    log.warn('protest window closed; the ticket lapses on chain', {
                        ticket_id: ticketId,
                        reason: violation,
                        verification_err: errText(verifyErr),
                    })
                    return { settlement: settlementOf(deps, ticketId, 'protest', protest.txid, protest.fee), err: perr }
                }
                const fallback = await freezeOverclaim(deps, t, check, perr, protest, signal)
                if ('settled' in fallback) return fallback.settled
                log.warn('protest failed', {
                    ticket_id: ticketId,
                    reason: violation,
                    verification_err: errText(verifyErr),
                    submit_err: errText(perr),
                    ...(fallback.claimErr !== undefined ? { claim_err: errText(fallback.claimErr) } : {}),
                })
                return { settlement: settlementOf(deps, ticketId, 'protest', protest.txid, protest.fee), err: perr }
            }
            log.warn('protest submitted', {
                ticket_id: ticketId,
                txid: call.txId,
                reason: violation,
                verification_err: errText(verifyErr),
            })
            // A frozen ticket can't be refunded; arbitration resolves it.
            deps.resolveRefund?.(ticketId)
            return { settlement: settlementOf(deps, ticketId, 'protest', call.txId, call.feeMicroalgos, true) }
        }),
        check,
    }
}

/**
 * excludeOverclaim bars the node whose claim on chain takes more than the
 * receipt it signed, and names the exclusion on check unless an earlier one
 * this turn already did: Go's Client.excludeOverclaim.
 */
function excludeOverclaim(deps: ReceiptCheckDeps, check: TurnCheck, op: Operator): void {
    if (!deps.nodeExclusions) return
    deps.nodeExclusions.excludeNode(refOf(op))
    if (!check.excluded) {
        check.excluded = true
        check.exclusion = EXCLUSION_REASONS.overclaim
    }
}

/**
 * After a refused protest: freezes the ticket with the receipt's settle when
 * the operator's claim on it takes more than the receipt, through the handle's
 * freezeOverclaim, and bars the node as the ack path does. Without a settled
 * outcome, when the handle has no fallback or the claim is anything else, the
 * protest's own failure stands; claimErr is then a box read that failed. A
 * settled outcome reports the fee of each transaction that paid one: the
 * protest's, sent and failed, and the freeze's.
 */
async function freezeOverclaim(
    deps: ReceiptCheckDeps,
    t: TurnReceipt,
    check: TurnCheck,
    protestErr: unknown,
    protest: { txid: string; fee: number },
    signal: AbortSignal,
): Promise<{ settled: SettleResult } | { claimErr?: unknown }> {
    const { handle, op, receipt } = t
    const ticketId = t.ticket.ticket_id
    if (handle === null || !handle.freezeOverclaim) return {}
    const res = await handle.freezeOverclaim(receipt, signal)
    // A failed read is no evidence of an over-claim.
    if (res.claim !== 'overclaims') return res.err !== undefined ? { claimErr: res.err } : {}
    // Same self-contradiction as on the ack path.
    excludeOverclaim(deps, check, op)
    const log = deps.logger
    if (res.err instanceof NoResolveFrozenError) {
        // The protest's own failure stands.
        log.warn(
            "protest refused; the operator's claim exceeds the receipt it signed, but the deployed escrow has no resolveFrozen, so no freeze was sent",
            { ticket_id: ticketId, ...opAttrs(op), protest_err: errText(protestErr) },
        )
        return { settled: { settlement: settlementOf(deps, ticketId, 'protest', protest.txid, protest.fee), err: protestErr } }
    }
    if (res.call === undefined) {
        const err = res.err ?? new Error('freeze: no settle sent')
        log.warn('protest refused, and the settle to freeze an operator claim above the receipt failed', {
            ticket_id: ticketId,
            ...opAttrs(op),
            protest_err: errText(protestErr),
            submit_err: errText(err),
        })
        const sent = findError(err, SentSettleError)?.submission
        const fee = protest.fee + Number(sent?.payerFeeMicroalgos ?? 0)
        return { settled: { settlement: settlementOf(deps, ticketId, 'protest', sent?.txid || protest.txid, fee), err } }
    }
    log.warn(
        "protest refused; the operator's claim exceeds the receipt it signed, so submitted the payer's settle at the receipt to freeze the ticket instead",
        {
            ticket_id: ticketId,
            ...opAttrs(op),
            txid: res.call.txid,
            receipt_microusdc: receipt.amount_charged,
            protest_err: errText(protestErr),
        },
    )
    deps.resolveRefund?.(ticketId)
    const fee = protest.fee + Number(res.call.payerFeeMicroalgos)
    return { settled: { settlement: settlementOf(deps, ticketId, 'protest', res.call.txid, fee, true) } }
}

/** protestReasonFor is the reason code a protest of violation carries. */
export function protestReasonFor(v: ReceiptViolation | ''): ProtestReasonCode {
    switch (v) {
        case 'body_hash':
            return ProtestReason.bodyHash
        case 'sig':
            return ProtestReason.receiptSig
        case 'amount':
            return ProtestReason.amount
        default:
            return ProtestReason.unspecified
    }
}

function emptySettlement(ticketId: string): Settlement {
    return { ticketId, kind: '', txId: '', feesMicroAlgos: 0, networkFees: 0 }
}

// A submit's Settlement, its fee under both names: Go's Client.settlement.
function settlementOf(deps: ReceiptCheckDeps, ticketId: string, kind: SettleKind, txId: string, fee: number, frozen = false): Settlement {
    const s: Settlement = { ticketId, kind, txId, feesMicroAlgos: algoOnly(deps.feeUnit, fee), networkFees: fee }
    if (frozen) s.frozen = true
    return s
}

// journal runs the hook, bounded, and never rejects, so a journal failure
// can't stop the ack.
async function journal(deps: ReceiptCheckDeps, handle: OpenHandle, receipt: UsageReceipt): Promise<void> {
    await journalWith(deps, deps.journalReceipt, handle, receipt)
}

// journalSigned is journal for a receipt that failed a check after its
// signature verified.
async function journalSigned(deps: ReceiptCheckDeps, handle: OpenHandle, receipt: UsageReceipt): Promise<void> {
    await journalWith(deps, deps.journalSigned, handle, receipt)
}

async function journalWith(
    deps: ReceiptCheckDeps,
    write: ((handle: OpenHandle, receipt: UsageReceipt) => Promise<void> | void) | undefined,
    handle: OpenHandle,
    receipt: UsageReceipt,
): Promise<void> {
    if (!write) return
    try {
        await withJournalTimeout(write.call(deps, handle, receipt), deps.journalTimeoutMs)
    } catch (err) {
        deps.logger.warn('ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline', {
            ticket_id: receipt.ticket_id,
            err: errText(err),
        })
    }
}
