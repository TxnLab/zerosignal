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
import type { SettleArgs } from './reconcile.js'
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

/** One settle submitted: its txid and the fee the payer's own txns carried. */
export interface SettleSubmission {
    txid: string
    payerFeeMicroalgos: bigint | number
}

/** The ways an ack goes on chain, which the host supplies. */
export interface AckSettlePorts {
    /** Builds the group's spec. A failure is the host's, not the node's: the ack goes standalone. */
    spec(): Promise<SettleGroupSpec>
    /**
     * Checks the node's group against spec, signs the payer's half and submits
     * it. Throws SettleGroupRejectedError, possibly as a cause, when the checks
     * refuse the group.
     */
    submitGroup(spec: SettleGroupSpec): Promise<SettleSubmission>
    /** The payer's own settle(), signed and paid by the payer. */
    standalone(): Promise<SettleSubmission>
}

export interface AckSettleCall extends AckSettlePorts {
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
    txid: string
    feeMicroalgos: number
    groupRejected: boolean
    /** The refusal, when groupRejected: which check the node's group failed. */
    rejection?: SettleGroupRejectedError
    err?: unknown
}

/**
 * ackSettle acks a verified receipt: through the node's group when it sent one
 * and the group passes the payer's checks, standalone when it sent none, its
 * spec can't be built, or the checks refuse it. A group that passes but fails
 * to submit is returned as the error, never re-sent standalone at the payer's
 * expense: the sweep re-fires or refunds the ticket. Mirrors Go's ackSettle.
 */
export async function ackSettle(call: AckSettleCall): Promise<AckSettleResult> {
    const log = call.log ?? discardLogger
    let rejection: SettleGroupRejectedError | undefined
    if (call.atomic) {
        let spec: SettleGroupSpec | undefined
        try {
            spec = await call.spec()
        } catch (err) {
            log.warn('ack-settle: settle-group spec build failed; falling back to standalone', { err: message(err) })
        }
        if (spec !== undefined) {
            try {
                const res = await call.submitGroup(spec)
                return { txid: res.txid, feeMicroalgos: Number(res.payerFeeMicroalgos), groupRejected: false }
            } catch (err) {
                rejection = rejectionOf(err)
                if (rejection === undefined) return { txid: '', feeMicroalgos: 0, groupRejected: false, err }
                // The node authored both halves and the receipt, so a refused
                // group is proven misbehaviour. The standalone ack still settles
                // the turn; groupRejected lets the caller bar the node.
                log.warn('ack-settle: operator settle group REJECTED; refusing atomic path, falling back to standalone ack', {
                    field: rejection.field,
                    detail: rejection.detail,
                })
            }
        }
    }
    const rejected = rejection !== undefined ? { groupRejected: true, rejection } : { groupRejected: false }
    try {
        const res = await call.standalone()
        return { txid: res.txid, feeMicroalgos: Number(res.payerFeeMicroalgos), ...rejected }
    } catch (err) {
        return { txid: '', feeMicroalgos: 0, ...rejected, err }
    }
}

// rejectionOf finds a SettleGroupRejectedError in err's cause chain, as Go's
// errors.As finds one through %w.
function rejectionOf(err: unknown): SettleGroupRejectedError | undefined {
    for (let e: unknown = err, depth = 0; e instanceof Error && depth < 16; e = e.cause, depth++) {
        if (e instanceof SettleGroupRejectedError) return e
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

/** checkReceipt verifies a receipt and returns the ack it calls for, mirroring Go's checkReceipt. */
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
            // As Go reports it: atomic whenever a group came and wasn't refused.
            const kind: SettleKind = ack.atomic && !res.groupRejected ? 'atomic' : 'payer_ack'
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
