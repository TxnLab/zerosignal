/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A turn's ordered events, mirroring proto/go/zs Event: `type` is Go's
// EventType and the fields are Go's in lower camel case (pinned by
// testdata/sdk_vocabulary_vectors.json). Content deltas and payment milestones
// share the sequence so their relative order survives: a consumer can tell
// which text arrived before payment.committed and which after.
//
// The set grows: a consumer that switches on `type` must ignore the ones it
// does not handle.

import type { Ticket as SignedTicket, UsageReceipt } from '@txnlab/zs-proto/ticket'

import type { Attribution, Item, NodeRef, RelayHopReason, ToolState } from './types.js'

/**
 * Routing ordered these targets for the request, once it finds any, and again
 * before each repeat sweep. A sweep repeats when every candidate failed
 * transiently or was at capacity.
 */
export interface RouteCandidates {
    type: 'route.candidates'
    model: string
    candidates: NodeRef[]
}

/**
 * The SDK picked the route to a candidate, or rotated to another relay before
 * payment. relay is null for a direct connection, which only happens under
 * the direct privacy mode.
 */
export interface RelayHopChanged {
    type: 'relay.hop'
    relay: NodeRef | null
    target: NodeRef
    reason: RelayHopReason
}

/** Before each reserve. attempt counts from 1 per candidate. */
export interface ReserveStarted {
    type: 'reserve.started'
    target: NodeRef
    relay: NodeRef | null
    attempt: number
}

/**
 * Before asking the same candidate again after an infrastructure failure,
 * which only ever happens before payment. status is 0 for a transport
 * failure; code is empty when the answer carried none. attempt is the attempt
 * about to start, after waiting `wait` milliseconds.
 */
export interface ReserveRetrying {
    type: 'reserve.retrying'
    target: NodeRef
    status: number
    code: string
    attribution: Attribution
    wait: number
    attempt: number
}

/** Once, when a node issues a signed ticket. maxPrice is microUSDC. */
export interface ReserveSucceeded {
    type: 'reserve.succeeded'
    ticketId: string
    target: NodeRef
    maxPrice: number
    expiresAt: Date
}

/**
 * Once, when the escrow open confirms. Nothing is resent after it: a later
 * failure ends in settle, protest or refund.
 */
export interface PaymentCommitted {
    type: 'payment.committed'
    ticketId: string
    openTxId: string
    feesMicroAlgos: number
}

/**
 * Before any reserve, when the request asked for more output than the
 * routable nodes allow and was lowered to ceiling rather than refused.
 */
export interface MaxOutputClamped {
    type: 'max_output.clamped'
    ceiling: number
}

/**
 * Once, when the node answers. header omits the node's X-Zs-* fields, which
 * are protocol plumbing. streaming is false for a single-body reply, which
 * then arrives as one frame.
 */
export interface ResponseStarted {
    type: 'response.started'
    status: number
    header: Headers
    streaming: boolean
}

/**
 * One Server-Sent Event of the node's response, as an OpenAI-compatible
 * endpoint would have written it, so an adapter can re-emit it. sealed frames
 * were decrypted; the rest (the [DONE] sentinel, keepalive comments) pass
 * through as the node sent them.
 */
export interface Frame {
    type: 'frame'
    event: string
    id: string
    data: string
    comment: string
    retry: number
    sealed: boolean
}

export interface ItemOpened {
    type: 'item.opened'
    item: Item
}

export interface ItemClosed {
    type: 'item.closed'
    item: Item
}

/** A piece of the answer text. A chat turn's deltas carry no itemId. */
export interface TextDelta {
    type: 'delta.text'
    itemId: string
    delta: string
}

/** A piece of the model's reasoning, or of its summary. */
export interface ReasoningDelta {
    type: 'delta.reasoning'
    itemId: string
    delta: string
}

/** A piece of a function call's arguments; callId and name repeat on each. */
export interface ToolCallDelta {
    type: 'delta.tool_call'
    itemId: string
    callId: string
    name: string
    argumentsDelta: string
}

/** A citation or similar annotation on a text item. */
export interface AnnotationAdded {
    type: 'annotation.added'
    itemId: string
    annotation: unknown
}

/**
 * A built-in tool the node runs on the caller's behalf. icons are the
 * sources' favicons by host, as data URLs, limited in number, size and type
 * because the node chooses their bytes. itemId is the output item the call
 * runs as; both its events carry it.
 */
export interface ToolStatus {
    type: 'tool.status'
    itemId: string
    callId: string
    name: string
    state: ToolState
    action: unknown
    icons: Record<string, string>
}

export interface ImageProgress {
    type: 'image.progress'
    itemId: string
    value: number
    max: number
}

export interface ImagePartial {
    type: 'image.partial'
    itemId: string
    b64: string
    mime: string
}

/**
 * Token counts as the response carries them; source is "response". Counts
 * are running totals, so a later usage replaces an earlier one. The billed
 * figures are the receipt's.
 */
export interface Usage {
    type: 'usage'
    inputTokens: number
    outputTokens: number
    reasoningTokens: number
    source: string
}

/**
 * Once, before done, when the node's signed receipt checks out against the
 * ticket and the content delivered. feeBps is valid only when feeBpsKnown.
 */
export interface ReceiptVerified {
    type: 'receipt.verified'
    receipt: UsageReceipt
    ticket: SignedTicket
    target: NodeRef
    ownerAddr: string
    openFeesMicroAlgos: number
    settleFeesMicroAlgos: number
    /** The ALGO/USD rate the reserve priced at; 0 when unknown. */
    algoUsd: number
    feeBps: number
    feeBpsKnown: boolean
}

/**
 * Replaces receipt.verified when a check fails; nothing is charged against
 * the SpendGuard. violation is "sig", "amount", "body_hash" or "unknown".
 */
export interface ReceiptViolated {
    type: 'receipt.violated'
    violation: string
    protestTxId: string
}

/**
 * On a stream, after receipt.verified, when the payer's settle was submitted.
 * atomic is false when the SDK fell back to a standalone payer ack.
 */
export interface SettleSubmitted {
    type: 'settle.submitted'
    ticketId: string
    txId: string
    feesMicroAlgos: number
    atomic: boolean
}

/**
 * On a stream, when the node's pre-signed settle group fails verification;
 * the node is barred for the rest of the process.
 */
export interface NodeExcluded {
    type: 'node.excluded'
    node: NodeRef
    reason: string
}

/**
 * The last event of a turn the node sealed as finished. finishReason is the
 * dialect's own; empty means the turn produced no answer.
 */
export interface Done {
    type: 'done'
    finishReason: string
    incompleteReason: string
    empty: boolean
}

export type Event =
    | RouteCandidates
    | RelayHopChanged
    | ReserveStarted
    | ReserveRetrying
    | ReserveSucceeded
    | PaymentCommitted
    | MaxOutputClamped
    | ResponseStarted
    | Frame
    | ItemOpened
    | ItemClosed
    | TextDelta
    | ReasoningDelta
    | ToolCallDelta
    | AnnotationAdded
    | ToolStatus
    | ImageProgress
    | ImagePartial
    | Usage
    | ReceiptVerified
    | ReceiptViolated
    | SettleSubmitted
    | NodeExcluded
    | Done

export type EventType = Event['type']
