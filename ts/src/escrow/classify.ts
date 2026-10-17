/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What can legally happen to a live ticket box right now. The rules are the
// rail-neutral ones in ../settle; this maps ZeroSignalEscrow's box encoding
// onto them. Mirrors proto/go/escrow/classify.go, pinned by the escrow vectors.

import { SettleStatus, type TicketView, type Verdict, classify as classifyView } from '../settle/ticket.js'
import { PENDING_BY_OPERATOR, PENDING_BY_PAYER, STATUS_FROZEN, STATUS_OPEN, STATUS_PENDING_SETTLE } from './constants.js'
import type { TicketRecord } from './records.js'

export type { Verdict }

type BoxFields = Pick<TicketRecord, 'status' | 'pendingBy' | 'expiresAt' | 'settlementGraceSeconds'>

// settlementDeadline is D = expiresAt + settlementGraceSeconds (unix seconds),
// read off the box — authoritative over any deadline recomputed from a cached
// grace global the admin can rotate.
export function settlementDeadline(t: Pick<TicketRecord, 'expiresAt' | 'settlementGraceSeconds'>): bigint {
    return t.expiresAt + t.settlementGraceSeconds
}

// ticketView maps a box onto the rail-neutral view. Only OPEN, FROZEN, and
// PENDING_SETTLE with a side are ever written; SETTLED / REFUNDED mean the box
// was deleted, and a pending settle with no side is not a state the contract
// writes, so each of those reads as unrecognized.
export function ticketView(t: BoxFields): TicketView {
    let status: number = SettleStatus.Unrecognized
    if (t.status === STATUS_OPEN) status = SettleStatus.Open
    else if (t.status === STATUS_FROZEN) status = SettleStatus.Frozen
    else if (t.status === STATUS_PENDING_SETTLE && t.pendingBy === PENDING_BY_PAYER) status = SettleStatus.PendingPayer
    else if (t.status === STATUS_PENDING_SETTLE && t.pendingBy === PENDING_BY_OPERATOR) status = SettleStatus.PendingOperator
    return { status, deadline: settlementDeadline(t) }
}

// classify reports what can legally happen to t at now. Padding now for clock
// skew against the chain's latest timestamp is the caller's job.
export function classify(t: BoxFields, now: Date): Verdict {
    return classifyView(ticketView(t), now)
}
