/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The end of a paid turn: check the node's signed receipt, then ack it on
// chain, through the node's pre-signed settle group when it sent one and the
// payer's standalone settle otherwise. Mirrors proto/go/zs's checkReceipt and
// OpenHandle.AckSettle; testdata/ack_settle_vectors.json pins ackSettle's
// decision against Go's. A body_hash violation is protested on chain by
// receipt-check.ts, as Go does, rather than acked.

import algosdk from 'algosdk'

import { type UsageReceipt, receiptSigDigest } from '@txnlab/zs-proto/ticket'

import type { SettleGroupSpec } from './escrow/settle.js'
import { SettleGroupRejectedError } from './escrow/settle.js'
import { type Logger, discardLogger } from './ports.js'
import type { ClaimVerdict, SettleArgs } from './reconcile.js'
import type { SettleKind } from './types.js'
import { ReceiptError, type ReceiptViolation, verifyReceipt } from './verify.js'

/**
 * settleArgsOf is what the payer co-signs on settle() for a verified receipt.
 * Every value comes straight from the node's signed receipt, so the payer's
 * half matches the node's verbatim; a mismatch on any one freezes the ticket.
 */
export function settleArgsOf(receipt: UsageReceipt): SettleArgs {
    return {
        amountCharged: BigInt(receipt.amount_charged),
        receiptDigest: receiptSigDigest(receipt),
        ttftMs: BigInt(receipt.ttft_ms),
        decodeMs: BigInt(receipt.decode_ms),
        inputTokens: BigInt(receipt.actual_input_count),
        outputTokens: BigInt(receipt.actual_output_count),
        outputUsageType: receipt.output_usage_type,
        auxOutputUsageType: receipt.aux_output_usage_type,
        auxOutputCount: BigInt(receipt.aux_output_count),
    }
}

const TICKET_ID_LEN = 16

/** What the group's two halves must say besides the receipt's values. */
export interface SettleGroupIds {
    appId: bigint
    /** The 16-byte ticket id, not its base64. */
    ticketIdRaw: Uint8Array
    payerAddr: string
    /** The serving node's signing address. */
    operatorSigningAddr: string
}

/**
 * settleGroupSpecOf is the spec a node's settle group is checked against, Go's
 * settleGroupSpec. It throws on an id that is malformed, as Go's decodes do:
 * a spec built from one would refuse an honest node's group and bar the node
 * for the payer's own mistake, where a spec failure only sends the ack standalone.
 */
export function settleGroupSpecOf(receipt: UsageReceipt, ids: SettleGroupIds): SettleGroupSpec {
    if (ids.ticketIdRaw.length !== TICKET_ID_LEN) {
        throw new Error(`ticket id is ${ids.ticketIdRaw.length} bytes, want ${TICKET_ID_LEN}`)
    }
    if (!algosdk.isValidAddress(ids.payerAddr)) throw new Error(`payer address ${ids.payerAddr} is not an address`)
    if (!algosdk.isValidAddress(ids.operatorSigningAddr)) {
        throw new Error(`operator signing address ${ids.operatorSigningAddr} is not an address`)
    }
    const a = settleArgsOf(receipt)
    return {
        ...ids,
        amountCharged: a.amountCharged,
        receiptDigest: a.receiptDigest,
        ttftMs: a.ttftMs,
        decodeMs: a.decodeMs,
        inputCount: a.inputTokens,
        outputCount: a.outputTokens,
        outputUsageType: BigInt(a.outputUsageType),
        auxOutputUsageType: BigInt(a.auxOutputUsageType),
        auxOutputCount: a.auxOutputCount,
    }
}

/**
 * One settle submitted: its txid and the fee the payer's own txns carried, in
 * base units of the rail's fee (lamports on Solana).
 */
export interface SettleSubmission {
    txid: string
    payerFeeMicroalgos: bigint | number
}

/**
 * SentSettleError: a submit that sent its transaction, which didn't settle. It
 * names the transaction, and the fee when it landed and failed, which a Solana
 * transaction pays: the ack reports both beside the error, as Go's submits
 * return their ackSubmission beside one.
 */
export class SentSettleError extends Error {
    override readonly name: string = 'SentSettleError'

    constructor(
        readonly submission: SettleSubmission,
        msg: string,
        cause?: unknown,
    ) {
        super(msg, cause === undefined ? undefined : { cause })
    }
}

/**
 * NoSettleAckRouteError: a deliverAck failure that sent nothing, because no
 * relay can carry the ack yet (every relay predates SETTLE_ACK_MIN_VERSION).
 * The ack then goes out as it did before 9.12, at exactly the old privacy
 * cost: on Algorand the payer broadcasts the group, and on Solana, where it
 * cannot submit the node's settle, ackSettle acks standalone. Go's
 * errNoSettleAckRoute.
 */
export class NoSettleAckRouteError extends Error {
    override readonly name = 'NoSettleAckRouteError'

    constructor() {
        super('zs: no relay serves the settle ack')
    }
}

/**
 * The ways an ack goes on chain, which the host supplies. S is what the node's
 * settle slot decodes to: Algorand's group spec, Solana's open_seq.
 */
export interface AckSettlePorts<S = SettleGroupSpec> {
    /** Builds the group's spec. A failure is the host's, not the node's: the ack goes standalone. */
    spec(): Promise<S>
    /**
     * Checks the node's group against spec, signs the payer's half and submits
     * it, or on Solana hands the node the payer's ack. Throws
     * SettleGroupRejectedError, possibly as a cause, when the checks refuse
     * the group, and NoSettleAckRouteError, possibly as a cause, when it sent
     * nothing and could not, which ackSettle answers by acking standalone.
     */
    submitGroup(spec: S): Promise<SettleSubmission>
    /**
     * How the operator's claim on the ticket's box stands against the
     * receipt (judgeClaim), read before a standalone ack and after the node's
     * group fails to submit. Without it the ack reads nothing and reports
     * claim ''.
     */
    claim?(): Promise<ClaimVerdict>
    /** The payer's own settle(), signed and paid by the payer. */
    standalone(): Promise<SettleSubmission>
    /**
     * standalone paid for the freeze an over-claim turns it into: the outer
     * call alone. Without it an over-claim is frozen through standalone.
     */
    freeze?(): Promise<SettleSubmission>
    /**
     * The payer's half on an open box after the node's group failed, paid the
     * same way: a first half finalizes nothing. Without it none is sent.
     */
    half?(): Promise<SettleSubmission>
    /**
     * Whether the deployed escrow has resolveFrozen, asked only before a
     * freeze or the half after a failed group submit. Without it, or
     * when it rejects, neither is sent, since a frozen ticket's escrow would be
     * locked for good. Go's ackSettleDeps.freezes.
     */
    resolvesFrozen?(): Promise<boolean>
}

/**
 * NoResolveFrozenError is why a freeze was not sent: the deployed escrow has no
 * resolveFrozen, so a frozen ticket's escrow would be locked for good. Go's
 * errNoResolveFrozen.
 */
export class NoResolveFrozenError extends Error {
    override readonly name = 'NoResolveFrozenError'
    constructor() {
        super('wallet: freeze not sent: the deployed escrow has no resolveFrozen')
    }
}

export interface AckSettleCall<S = SettleGroupSpec> extends AckSettlePorts<S> {
    /**
     * Whether the node sent a settle group that decodes; check it with
     * decodeSettleGroup first. One that doesn't is absent, as Go's
     * checkSettleGroupHeader has it: a decode failure inside submitGroup is
     * an ordinary error, and the ack would then not go standalone.
     */
    atomic: boolean
    log?: Logger
}

/**
 * The ack's outcome. groupRejected is set when the node's group was refused,
 * through a standalone ack that succeeded or not: the node contradicted its
 * own receipt either way. err is the submit's error when the ack failed.
 */
export interface AckSettleResult {
    /**
     * The payer's settle, or the node's group on Algorand. A payer's settle
     * that failed has one when it was sent: on Solana it may have landed, or
     * may still.
     */
    txid: string
    /**
     * The fee the payer's own transactions paid, in base units of the rail's
     * fee (lamports on Solana): 0 on the node's group or ack. A Solana settle
     * that landed and failed paid its fee too, so it is set beside err.
     */
    feeMicroalgos: number
    groupRejected: boolean
    /** The refusal, when groupRejected: which check the node's group failed. */
    rejection?: SettleGroupRejectedError
    /**
     * How the operator's claim on the box stood when the payer read it: before
     * a standalone ack, or after the node's group failed to submit. '' or
     * absent when none was read. On contradicts nothing was sent. On
     * overclaims the payer's settle was sent to freeze the ticket, unless the
     * deployed escrow has no resolveFrozen, when nothing was sent.
     */
    claim?: ClaimVerdict
    /**
     * Set when the payer's own settle was sent, or failed to send, in place of
     * the node's group: standalone, to freeze an over-claim, or as its half on
     * an open box after the group failed.
     */
    payerSettle?: boolean
    /** Set when the payer's settle went out to freeze an over-claim. */
    frozen?: boolean
    err?: unknown
}

/**
 * ackSettle acks a verified receipt: through the node's group when it sent one
 * and the group passes the payer's checks, standalone when it sent none, its
 * spec can't be built, the checks refuse it, or no relay can carry the ack. A group that passes but fails
 * to submit is returned as the error, never re-sent standalone at the payer's
 * expense: the sweep re-fires or refunds the ticket. The exceptions, on an
 * escrow with resolveFrozen, are an operator claim above the receipt, which
 * the payer then freezes, and an open box, where it posts its own half.
 *
 * Before a standalone ack it reads the operator's claim on the box, which no
 * check has compared with the receipt on that path. A claim that contradicts
 * the receipt without taking more is not acked. Mirrors Go's ackSettle.
 */
export async function ackSettle<S = SettleGroupSpec>(call: AckSettleCall<S>): Promise<AckSettleResult> {
    const log = call.log ?? discardLogger
    const readClaim = async (): Promise<ClaimVerdict> => {
        if (!call.claim) return ''
        try {
            return await call.claim()
        } catch (err) {
            log.debug('ack-settle: operator claim unreadable', { err: message(err) })
            return 'unreadable'
        }
    }
    // frozen: the settle freezes the ticket once it lands.
    const send = async (
        submit: () => Promise<SettleSubmission>,
        rejected: { groupRejected: boolean; rejection?: SettleGroupRejectedError },
        claim: ClaimVerdict,
        frozen = false,
    ): Promise<AckSettleResult> => {
        try {
            const res = await submit()
            return { txid: res.txid, feeMicroalgos: Number(res.payerFeeMicroalgos), ...rejected, claim, payerSettle: true, frozen }
        } catch (err) {
            const sent = findInCauses(err, SentSettleError)?.submission
            return { txid: sent?.txid ?? '', feeMicroalgos: Number(sent?.payerFeeMicroalgos ?? 0), ...rejected, claim, payerSettle: true, frozen: false, err }
        }
    }
    const freezes = async (): Promise<boolean> => {
        if (!call.resolvesFrozen) return false
        try {
            return await call.resolvesFrozen()
        } catch {
            return false
        }
    }
    const freeze = () => (call.freeze ? call.freeze() : call.standalone())
    let rejection: SettleGroupRejectedError | undefined
    if (call.atomic) {
        let spec: { s: S } | undefined
        try {
            spec = { s: await call.spec() }
        } catch (err) {
            log.warn('ack-settle: settle-group spec build failed; falling back to standalone', { err: message(err) })
        }
        if (spec !== undefined) {
            try {
                const res = await call.submitGroup(spec.s)
                return { txid: res.txid, feeMicroalgos: Number(res.payerFeeMicroalgos), groupRejected: false }
            } catch (err) {
                rejection = findInCauses(err, SettleGroupRejectedError)
                if (findInCauses(err, NoSettleAckRouteError) !== undefined) {
                    // Nothing reached the node, and no relay can carry the
                    // ack to it. On Solana the payer cannot submit the node's
                    // settle, so it acks standalone, as when no slot came; the
                    // node is not at fault.
                    log.info('ack-settle: no relay serves the settle ack; acking standalone')
                    rejection = undefined
                } else if (rejection === undefined) {
                    // The node may still land the group, so no settle that
                    // could finalize goes out in its place. Two box states call
                    // for the payer's settle at one fee, as Go's ackSettle
                    // has it: an over-claim, which the node's group can then
                    // only revert against, and which lapses unless frozen; and
                    // an open box, where the payer's half at the receipt goes
                    // first, so a node half at another figure freezes the
                    // ticket instead of lapsing. Both can freeze the ticket, so
                    // neither goes to an escrow that cannot resolve one.
                    const claim = await readClaim()
                    if ((claim === 'overclaims' || claim === 'open') && (await freezes())) {
                        if (claim === 'overclaims') {
                            log.warn('ack-settle: settle group failed to submit over an operator claim above the receipt; freezing the ticket', {
                                err: message(err),
                            })
                            return send(freeze, { groupRejected: false }, claim, true)
                        }
                        const half = call.half
                        if (half) {
                            log.warn("ack-settle: settle group failed to submit over an open ticket; posting the payer's half at the receipt", {
                                err: message(err),
                            })
                            return send(() => half(), { groupRejected: false }, claim)
                        }
                    }
                    return { txid: '', feeMicroalgos: 0, groupRejected: false, claim, err }
                } else {
                    // The node authored both halves and the receipt, so a
                    // refused group is proven misbehaviour. The standalone ack
                    // still settles the turn; groupRejected lets the caller bar
                    // the node.
                    log.warn('ack-settle: operator settle group REJECTED; refusing atomic path, falling back to standalone ack', {
                        field: rejection.field,
                        detail: rejection.detail,
                    })
                }
            }
        }
    }
    const rejected = rejection !== undefined ? { groupRejected: true, rejection } : { groupRejected: false }
    // The standalone ack is checked against nothing else: the node's group is
    // verified before the payer signs it, but a node that posts its own first
    // half and then sends no group, or one the checks refuse, has the payer
    // settle into a claim nobody compared with the receipt. So read it.
    const claim = await readClaim()
    // The settle would freeze a ticket whose claim takes no more than the
    // receipt. Nothing is sent, so the refund watchdog keeps the ticket.
    if (claim === 'contradicts') return { txid: '', feeMicroalgos: 0, ...rejected, claim }
    if (claim === 'overclaims') {
        // On an escrow without resolveFrozen the freeze would keep max_price
        // locked for good: the claim's lapse costs the payer less. Nothing is
        // sent.
        if (!(await freezes())) return { txid: '', feeMicroalgos: 0, ...rejected, claim }
        return send(freeze, rejected, claim, true)
    }
    return send(() => call.standalone(), rejected, claim)
}

// findInCauses finds an E in err's cause chain, as Go's errors.As finds one
// through %w.
function findInCauses<E extends Error>(err: unknown, cls: abstract new (...args: never[]) => E): E | undefined {
    for (let e: unknown = err, depth = 0; e instanceof Error && depth < 16; e = e.cause, depth++) {
        if (e instanceof cls) return e
    }
    return undefined
}

/** What a verified receipt's ack did. */
export interface Settled extends AckSettleResult {
    kind: SettleKind
    /** Set when the node's group was refused and excludeNode was called. */
    excluded: boolean
}

export interface CheckReceiptCall {
    receipt: UsageReceipt
    ticket: Parameters<typeof verifyReceipt>[1]
    /** The serving node's ed25519 signing key. */
    signingKey: Uint8Array
    /** sha256 of the body, or of the concatenated stream frames. */
    computedHash: Uint8Array
    /**
     * The ack's ports and whether a group came, or null when there is no
     * escrow to ack: the receipt is still checked.
     */
    ack: (AckSettlePorts & { atomic: boolean }) | null
    /**
     * Records the verified receipt before the ack runs, so a process that dies
     * mid-submit can re-fire it from the journal: Go's journalReceipt.
     */
    journal?(receipt: UsageReceipt): void | Promise<void>
    /** Bars the node for good. Called once the ack is done, when its group was refused. */
    excludeNode?(rejection: SettleGroupRejectedError): void
    log?: Logger
}

/**
 * The receipt's verdict. violation is null when it verified, and otherwise
 * one of ReceiptViolation, or "unknown" for an error of no known kind. submit
 * is the ack the verdict calls for, or null when there is none; the caller
 * runs it after the response is in hand.
 */
export interface ReceiptCheck {
    violation: ReceiptViolation | 'unknown' | null
    err?: unknown
    submit: (() => Promise<Settled>) | null
}

/**
 * checkReceipt verifies a receipt and returns the ack it calls for, mirroring
 * Go's checkReceipt. Unlike the Client's receipt check it bars no node over a
 * refused receipt, since excludeNode takes only a refused group: a host that
 * bars the node for a receipt it validly signed for another ticket finds a
 * ReceiptForAnotherTicketError in err's cause chain.
 */
export function checkReceipt(call: CheckReceiptCall): ReceiptCheck {
    const log = call.log ?? discardLogger
    try {
        verifyReceipt(call.receipt, call.ticket, call.signingKey, call.computedHash)
    } catch (err) {
        return { violation: err instanceof ReceiptError ? err.violation : 'unknown', err, submit: null }
    }
    const ack = call.ack
    if (ack === null) return { violation: null, submit: null }
    const journaled = journal(call, log)
    return {
        violation: null,
        submit: async () => {
            // The ack waits for the journal, so it is on record before the
            // submit; a failed write is only logged, as Go's journalPut.
            await journaled
            const res = await ackSettle({ ...ack, log })
            let excluded = false
            if (res.rejection !== undefined && call.excludeNode) {
                try {
                    call.excludeNode(res.rejection)
                    excluded = true
                } catch (err) {
                    log.warn('node exclusion failed', { err: message(err) })
                }
            }
            // As Go reports it: atomic whenever a group came and wasn't refused,
            // nor replaced by the payer's own settle.
            const kind: SettleKind = ack.atomic && !res.groupRejected && res.payerSettle !== true ? 'atomic' : 'payer_ack'
            return { ...res, kind, excluded }
        },
    }
}

// journal runs the journal hook, sync or async, and never rejects: a journal
// that fails must not stop the receipt's ack.
async function journal(call: CheckReceiptCall, log: Logger): Promise<void> {
    try {
        await call.journal?.(call.receipt)
    } catch (err) {
        log.warn('receipt journal failed; acking anyway', { err: message(err) })
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
