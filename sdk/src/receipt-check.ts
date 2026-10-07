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

import type { SpendGuard } from './config.js'
import { type Operator, refOf } from './operator.js'
import { type OpenHandle, ProtestReason, type ProtestReasonCode } from './parts.js'
import type { LogAttrs, Logger } from './ports.js'
import type { NodeExclusionStore } from './routing/exclusion.js'
import type { RelayHop } from './routing/relay.js'
import type { Settlement, SettleKind } from './types.js'
import { ReceiptError, type ReceiptViolation, verifyReceipt } from './verify.js'

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
    #finished = false

    constructor() {
        this.done = new Promise((resolve) => {
            this.#resolve = resolve
        })
    }

    /** Records the outcome; only the first call counts. */
    finish(r: SettleResult): void {
        if (this.#finished) return
        this.#finished = true
        this.#resolve(r)
    }
}

/** How a receipt fared and, once its submit has run, what the submit did. */
export interface TurnCheck {
    /** The failed check, or '' when the receipt verified. */
    violation: string
    settled: Settlement
    /** Set when the node's settle group failed verification and the node was barred. */
    excluded: boolean
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
    /** Overrides JOURNAL_TIMEOUT_MS. */
    journalTimeoutMs?: number | undefined
    /** Stops the refund watchdog tracking a ticket the submit finished. */
    resolveRefund?(ticketId: string): void
    /** Watches an atomic settle until it lands, then drops the ticket's journal row. */
    confirmSettled?(ticketId: string, txId: string, handle: OpenHandle): void
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
    algoUsdPrice: number
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
        deps.spendGuard?.settle(ticketId, receipt.amount_charged)
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
                    log.warn('node excluded: handed a fraudulent settle group', {
                        ticket_id: ticketId,
                        operator_id: op.id,
                        node_id: op.nodeId,
                    })
                }
                // Only a group that wasn't refused finalized the ticket; the
                // standalone fallback leaves a pending payer claim the watchdog
                // must keep tracking.
                const settledAtomically = atomic && !res.groupRejected
                const kind: SettleKind = settledAtomically ? 'atomic' : 'payer_ack'
                if (res.err !== undefined) {
                    log.warn('ack-settle failed', {
                        ticket_id: ticketId,
                        atomic,
                        group_rejected: res.groupRejected,
                        err: errText(res.err),
                    })
                    return { settlement: { ...emptySettlement(ticketId), kind }, err: res.err }
                }
                // Info when the payer paid a fee: a buffered reply was written
                // before this submit and can't report it.
                const at = res.feeMicroalgos > 0 ? log.info : log.debug
                at.call(log, 'ack-settle submitted', {
                    ticket_id: ticketId,
                    txid: res.txid,
                    atomic: settledAtomically,
                    fee_microalgos: res.feeMicroalgos,
                })
                if (settledAtomically) {
                    // The group deleted the ticket box: nothing left to refund.
                    deps.resolveRefund?.(ticketId)
                    deps.confirmSettled?.(ticketId, res.txid, handle)
                }
                return { settlement: { ticketId, kind, txId: res.txid, feesMicroAlgos: res.feeMicroalgos } }
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
    deps.spendGuard?.release(ticketId)
    // The contract refuses a protest over the signature or the amount.
    if (handle === null || violation !== 'body_hash') return { submit: null, check }
    const excerpt = t.plaintext.slice(0, DISPUTE_EXCERPT_CAP)
    return {
        submit: withSettle(async (signal) => {
            let call
            try {
                call = await handle.protest(receipt, excerpt, protestReasonFor(violation), signal)
            } catch (perr) {
                log.warn('protest failed', {
                    ticket_id: ticketId,
                    reason: violation,
                    verification_err: errText(verifyErr),
                    submit_err: errText(perr),
                })
                return { settlement: { ...emptySettlement(ticketId), kind: 'protest' }, err: perr }
            }
            log.warn('protest submitted', {
                ticket_id: ticketId,
                txid: call.txId,
                reason: violation,
                verification_err: errText(verifyErr),
            })
            // A frozen ticket can't be refunded; arbitration resolves it.
            deps.resolveRefund?.(ticketId)
            return { settlement: { ticketId, kind: 'protest', txId: call.txId, feesMicroAlgos: call.feeMicroalgos } }
        }),
        check,
    }
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
    return { ticketId, kind: '', txId: '', feesMicroAlgos: 0 }
}

// journal runs the hook, bounded, and never rejects, so a journal failure
// can't stop the ack.
async function journal(deps: ReceiptCheckDeps, handle: OpenHandle, receipt: UsageReceipt): Promise<void> {
    if (!deps.journalReceipt) return
    try {
        await withJournalTimeout(deps.journalReceipt(handle, receipt), deps.journalTimeoutMs)
    } catch (err) {
        deps.logger.warn('ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline', {
            ticket_id: receipt.ticket_id,
            err: errText(err),
        })
    }
}
