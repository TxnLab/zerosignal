/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What can legally happen to a live ticket box right now. Mirrors
// proto/go/escrow/classify.go; both encode ZeroSignalEscrow's settlement rules
// and are pinned against each other by the escrow vectors.

import { PENDING_BY_OPERATOR, PENDING_BY_PAYER, STATUS_FROZEN, STATUS_OPEN, STATUS_PENDING_SETTLE } from './constants.js'
import type { TicketRecord } from './records.js'

// Each verdict is named for the call it authorizes, matching Go's
// Verdict.String().
//   wait            — inside the settlement window: either side may settle(),
//                     the payer may protest(); neither deadline call is legal yet.
//   refundInactive  — past the deadline with no operator claim; returns the
//                     full maxPrice to the payer.
//   settleLapsed    — past the deadline carrying an operator claim; pays the
//                     claim and refunds the rest.
//   arbitrate       — FROZEN. No contract method accepts it at any time, and
//                     the escrow and the payer's MBR slot stay locked. Don't
//                     present it as something that resolves on its own.
//   unknown         — a status this contract never writes (usually bindings
//                     older than the deployed app). Waiting never makes a call
//                     legal here, so never render it as "too early".
export type Verdict = 'wait' | 'refundInactive' | 'settleLapsed' | 'arbitrate' | 'unknown'

// settlementDeadline is D = expiresAt + settlementGraceSeconds (unix seconds),
// read off the box — authoritative over any deadline recomputed from a cached
// grace global the admin can rotate.
export function settlementDeadline(t: Pick<TicketRecord, 'expiresAt' | 'settlementGraceSeconds'>): bigint {
    return t.expiresAt + t.settlementGraceSeconds
}

// classify reports what can legally happen to t at now. Padding now for clock
// skew against the chain's latest timestamp is the caller's job.
export function classify(
    t: Pick<TicketRecord, 'status' | 'pendingBy' | 'expiresAt' | 'settlementGraceSeconds'>,
    now: Date,
): Verdict {
    // FROZEN outranks the clock: no method accepts it at any time.
    if (t.status === STATUS_FROZEN) return 'arbitrate'
    // Recognize the state before consulting the clock, so a status no method
    // accepts can't come back as "wait" — which would read as "legal at D".
    const pastDeadline = BigInt(now.getTime()) > settlementDeadline(t) * 1000n
    if (t.status === STATUS_OPEN || (t.status === STATUS_PENDING_SETTLE && t.pendingBy === PENDING_BY_PAYER)) {
        return pastDeadline ? 'refundInactive' : 'wait'
    }
    if (t.status === STATUS_PENDING_SETTLE && t.pendingBy === PENDING_BY_OPERATOR) {
        return pastDeadline ? 'settleLapsed' : 'wait'
    }
    return 'unknown'
}
