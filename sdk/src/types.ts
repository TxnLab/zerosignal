/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Value types and enums shared with proto/go/zs (names pinned by
// testdata/sdk_vocabulary_vectors.json).

import type { Ticket as SignedTicket } from '@txnlab/zs-proto/ticket'
import type { AttributionValue } from '@txnlab/zs-proto/transient'

/** Attribution names the hop a retryable failure is charged to. */
export type Attribution = AttributionValue

/**
 * NodeRef addresses one running node: an operator runs many, each keyed by
 * (operator id, node id). Anything that caches, dedups or compares routing
 * targets keys by both.
 */
export interface NodeRef {
    op: number
    node: number
}

export function nodeRefString(r: NodeRef): string {
    return `${r.op}/${r.node}`
}

/** Privacy is the transport-privacy mode. The default is relay_required. */
export type Privacy = 'relay_required' | 'direct'

export type AffinityPolicy = 'prefer' | 'strict' | 'none'

export type RelayHopReason = 'chosen' | 'rotated'

/** ToolState is a built-in (zs_*) tool call's progress. */
export type ToolState = 'in_progress' | 'completed'

export type TicketStatus = 'open' | 'settle_pending'

/** SettleKind is what a turn submitted to the escrow; '' is nothing. */
export type SettleKind = '' | 'atomic' | 'payer_ack' | 'protest'

export type Endpoint =
    | '/v1/chat/completions'
    | '/v1/responses'
    | '/v1/images/generations'
    | '/v1/images/edits'

/**
 * Item is one output item of a /v1/responses reply (a message, reasoning
 * block, function call, image or built-in tool call). raw is the item's JSON
 * for fields the SDK does not model.
 */
export interface Item {
    id: string
    type: string
    raw: unknown
}

/**
 * Ticket is one paid reservation and its open escrow box: the only handle
 * that can move that ticket's money.
 */
export interface Ticket {
    /** The base64 ticket id, as carried in the envelope. */
    id: string
    /** The operator-signed ticket the reservation returned. */
    signed: SignedTicket
    /** The node that issued it and that the escrow pays. */
    target: NodeRef
}

/** Settlement is a turn's payer-side escrow submit. */
export interface Settlement {
    ticketId: string
    kind: SettleKind
    txId: string
    /** @deprecated networkFees on Algorand, 0 on any other rail. */
    feesMicroAlgos: number
    /** The payer's fee for the submit, in base units of the deployment's fee unit. */
    networkFees: number
    /**
     * Set when the submit freezes the ticket once it lands, leaving its escrow
     * to arbitration: a protest, or the payer's settle against an operator
     * claim above the receipt, under any kind. Absent where Go's Frozen is
     * false.
     */
    frozen?: boolean
}
