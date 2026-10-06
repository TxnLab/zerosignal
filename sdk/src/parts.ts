/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Client's network-facing parts, mirroring proto/go/zs: operator
// discovery (RegistryProvider), the reserve call (ReserveClient), escrow
// (WalletOpener), and the ticket journal. A host supplies any it builds
// itself; the Client builds the rest from Config.

import type { BytesSigner, Ticket, UsageReceipt } from '@txnlab/zs-proto/ticket'

import type { AckSettleResult } from './ack.js'
import { decodeOpenGroup } from './escrow/open.js'
import { type Operator, refOf, sealRecipientOf } from './operator.js'
import type { Clock, Fetch } from './ports.js'
import type { SettleArgs, TicketRecord } from './reconcile.js'
import { type ReserveCall, type Reservation, reserve } from './reserve.js'
import type { TargetBackoffStore } from './routing/backoff.js'
import type { NodeExclusionStore } from './routing/exclusion.js'
import type { RelayLatencyStore } from './routing/latency.js'
import type { RelayHop } from './routing/relay.js'
import type { RelayReputationStore } from './routing/reputation.js'
import type { NodeRef } from './types.js'
import { verifyTicketSignature } from './verify.js'

/** RegistryProvider is operator discovery, as dispatch reads it. */
export interface RegistryProvider {
    /** The operators to consider for model. */
    operators(model: string, signal?: AbortSignal): Promise<Operator[]>
    /**
     * One node by its ref, or undefined when the registry has none. Dispatch
     * reads a rejection the same way, as Go reads any Resolve error.
     */
    resolve(ref: NodeRef, signal?: AbortSignal): Promise<Operator | undefined>
    /** Every operator, for the relay pool. */
    allOperators(signal?: AbortSignal): Promise<Operator[]>
    /**
     * Re-probes op live to refresh its ephemeral recipient, returning the
     * refreshed operator if it can now seal, else null. Dispatch calls it to
     * self-heal a candidate skipped for a stale ephemeral, typically a node
     * that just restarted. A registry with no live probe re-checks op as is.
     */
    reprobeEphemeral(op: Operator, signal?: AbortSignal): Promise<Operator | null>
    /** Notes that model was just requested, so a refresh can probe its servers first. Advisory. */
    recordModelDemand(model: string): void
}

/** Reserved is a reservation and the recipient its body was sealed to. */
export interface Reserved extends Reservation {
    /**
     * The inference request must be sealed to this, not to op's recipient at
     * the time: a refresh can rotate or expire that between reserve and
     * inference, and the node only promises to open what reserve committed to.
     */
    sealRecipient: string
}

/** ReserveClient is the reserve call, sealed to op's ephemeral recipient. */
export interface ReserveClient {
    /**
     * Reserves on op, through hop when one is given. A result has passed every
     * check that needs only the node's answer: the ticket's signature under
     * op.ticketSigningKey, its terms against the request, commit_k, and that
     * any presigned open group decodes. Dispatch escrows on it without
     * checking again, so a failure here moves on to the next candidate.
     * Rejects with NoEphemeralError when op has no recipient to seal to,
     * which dispatch reads as "skip this candidate".
     */
    reserve(op: Operator, request: ReserveCall['request'], hop: RelayHop | null, signal?: AbortSignal): Promise<Reserved>
}

export interface HttpReserveClientOptions {
    fetch: Fetch
    /**
     * Signs each request under its payer_addr. Without one the request goes
     * unsigned, which a node accepts under verify-if-present.
     */
    signer?: BytesSigner | undefined
    timeoutMs?: number | undefined
    clock?: Clock | undefined
}

/** httpReserveClient is the default ReserveClient, Go's HTTPReserveClient. */
export function httpReserveClient(o: HttpReserveClientOptions): ReserveClient {
    const clock = o.clock ?? Date.now
    return {
        // async, so a missing recipient rejects like every other failure.
        async reserve(op, request, hop, signal) {
            const ref = refOf(op)
            const sealRecipient = sealRecipientOf(op, clock())
            const call: ReserveCall = {
                target: { operatorId: ref.op, nodeId: ref.node, baseUrl: op.baseUrl, sealRecipient },
                request,
                hop,
                fetch: o.fetch,
                clock,
            }
            if (o.signer) call.signer = o.signer
            // A non-positive or non-finite timeout is unset, as in resolveConfig
            // and Go's zero value, rather than one that aborts every reserve.
            if (o.timeoutMs !== undefined && Number.isFinite(o.timeoutMs) && o.timeoutMs > 0) call.timeoutMs = o.timeoutMs
            if (signal) call.signal = signal
            const r = await reserve(call)
            // reserve() leaves these to its caller; Go's Reserve runs both, and
            // its dispatch trusts the result.
            verifyTicketSignature(r.ticket, op.ticketSigningKey)
            if (r.presignedOpenTxn) {
                try {
                    decodeOpenGroup(r.presignedOpenTxn)
                } catch (err) {
                    throw new Error(`decode presigned open group: ${err instanceof Error ? err.message : String(err)}`, {
                        cause: err,
                    })
                }
            }
            return { ...r, sealRecipient }
        },
    }
}

/** Escrow-contract protest reasons; the contract rejects unspecified. */
export const ProtestReason = {
    unspecified: 0,
    bodyHash: 1,
    receiptSig: 2,
    amount: 3,
    sealing: 4,
    receiptMissing: 5,
} as const

export type ProtestReasonCode = (typeof ProtestReason)[keyof typeof ProtestReason]

/** One submitted escrow call and the fee the payer's own transactions paid. */
export interface EscrowCall {
    txId: string
    feeMicroalgos: number
}

/** Where a submitted settle stands in the transaction pool. */
export type SettleOutcome = 'pending' | 'landed' | 'dropped'

/**
 * OpenHandle is one opened escrow, for the rest of the request: the ack, a
 * protest, and the deadline paths.
 */
export interface OpenHandle {
    /** The open() app call's txid, which the envelope carries so the node can find it. */
    appCallTxId: string
    /** The open group's id. Kept for audit; algod cannot look a group up. */
    groupId: string
    ticketId: string
    /** The operator dispatched to. */
    operator: Operator
    /** The ceiling the contract enforces on settle. */
    maxPrice: number
    /** The payer's own share of the open group's fees; 0 when the operator pays the group. */
    openFeesMicroalgos: number
    /** The submitted group's signed transactions, kept as dispute evidence. */
    signedGroup: Uint8Array[]
    /**
     * Settles on the receipt: through the node's presigned settle group when
     * settleGroup carries one (base64), else standalone at the payer's fee.
     * settleGroup is null when the node sent none or it doesn't decode
     * (decodeSettleGroup), as Go's caller passes only a decoded group.
     *
     * It never rejects: a failed ack is result.err, so that groupRejected,
     * which proves the node handed a fraudulent group and gets it excluded,
     * survives a standalone fallback that also failed.
     */
    ackSettle(receipt: UsageReceipt, settleGroup: string | null, signal?: AbortSignal): Promise<AckSettleResult>
    /** Freezes the ticket. The payer signs and pays for it. */
    protest(receipt: UsageReceipt, excerpt: Uint8Array, reason: ProtestReasonCode, signal?: AbortSignal): Promise<EscrowCall>
    refundInactive(signal?: AbortSignal): Promise<string>
    settleLapsed(signal?: AbortSignal): Promise<string>
    /**
     * Looks up a submitted settle. Optional: without it the Client cannot
     * confirm an atomic settle landed, and leaves the journal row to the sweep.
     */
    settleOutcome?(txId: string, signal?: AbortSignal): Promise<SettleOutcome>
}

/** WalletOpener is the escrow side of the payer. */
export interface WalletOpener {
    /**
     * Completes and submits the node's presigned open group (base64) for
     * ticket. The ticket box's MBR comes from the payer's prepaid pool, not
     * this group.
     */
    open(ticket: Ticket, op: Operator, presignedOpenGroup: string, signal?: AbortSignal): Promise<OpenHandle>
    /** The address reserve requests name as the payer. */
    payerAddr(): string
    /**
     * The live protocol fee in basis points. Optional: without it responses
     * carry no fee breakdown.
     */
    protocolFeeBps?(signal?: AbortSignal): Promise<number>
}

/**
 * TicketJournal persists open tickets so a restarted process can still settle
 * or refund them. Without a durable one, a restart strands every open ticket
 * until someone calls refundInactive by hand.
 */
export interface TicketJournal {
    /** Inserts or replaces the record for rec.ticketId. */
    put(rec: TicketRecord): Promise<void>
    /** Removes a ticket that reached a terminal state; an unknown id is not an error. */
    delete(ticketId: string): Promise<void>
    /** The records for payer under escrowAppId only, oldest first. */
    list(payer: string, escrowAppId: bigint): Promise<TicketRecord[]>
}

function cloneRecord(r: TicketRecord): TicketRecord {
    const out: TicketRecord = { ...r, target: { ...r.target } }
    if (r.settle) {
        const s: SettleArgs = { ...r.settle, receiptDigest: r.settle.receiptDigest.slice() }
        out.settle = s
    }
    return out
}

/**
 * memoryJournal is the default TicketJournal: it outlives a request but not
 * the process. Records are copied in and out, as Go's are values.
 */
export function memoryJournal(): TicketJournal {
    const recs = new Map<string, TicketRecord>()
    return {
        put(rec) {
            recs.set(rec.ticketId, cloneRecord(rec))
            return Promise.resolve()
        },
        delete(ticketId) {
            recs.delete(ticketId)
            return Promise.resolve()
        },
        list(payer, escrowAppId) {
            const out = [...recs.values()]
                .filter((r) => r.payer === payer && r.escrowAppId === escrowAppId)
                .map(cloneRecord)
            // Oldest first, so a sweep finishes the longest-stranded ticket first.
            out.sort((a, b) => {
                if (a.createdAt !== b.createdAt) return a.createdAt - b.createdAt
                return a.ticketId < b.ticketId ? -1 : a.ticketId > b.ticketId ? 1 : 0
            })
            return Promise.resolve(out)
        },
    }
}

/**
 * Stores are the Client's state that can outlive it or be shared. An absent
 * routing store keeps no such signal.
 */
export interface Stores {
    /**
     * Records open tickets. When the Client builds the wallet, absent is
     * memoryJournal(), which a restart loses. With a supplied wallet there is
     * no default: only the Client's own wallet runs the sweep that deletes
     * rows, so a supplied journal is the host's to drain.
     */
    journal?: TicketJournal
    relayReputation?: RelayReputationStore
    relayLatency?: RelayLatencyStore
    targetBackoff?: TargetBackoffStore
    nodeExclusions?: NodeExclusionStore
}
