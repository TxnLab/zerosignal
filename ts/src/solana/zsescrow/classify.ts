/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What can legally happen to a live Solana ticket right now. The rules are the
// rail-neutral ones in ../../settle; this maps the program's ticket account
// onto them. Mirrors proto/go/solana/zsescrow/classify.go, pinned by
// solana_zsescrow_vectors.json.

import { SettleStatus, type TicketView, type Verdict, classify as classifyView } from '../../settle/ticket.js'
import { TICKET_FROZEN, TICKET_OPEN, TICKET_PENDING_BY_OPERATOR, TICKET_PENDING_BY_PAYER, type Ticket, ticketDeadline } from './accounts.js'

type TicketFields = Pick<Ticket, 'status' | 'expiresAt' | 'grace'>

/**
 * Maps a ticket account onto the rail-neutral view. A status this package
 * doesn't know reads as unrecognized. A deadline before the epoch, which no
 * open the program accepts can produce, reads as the epoch: long past.
 */
export function ticketView(t: TicketFields): TicketView {
    let status: number = SettleStatus.Unrecognized
    if (t.status === TICKET_OPEN) status = SettleStatus.Open
    else if (t.status === TICKET_PENDING_BY_PAYER) status = SettleStatus.PendingPayer
    else if (t.status === TICKET_PENDING_BY_OPERATOR) status = SettleStatus.PendingOperator
    else if (t.status === TICKET_FROZEN) status = SettleStatus.Frozen
    const d = ticketDeadline(t)
    return { status, deadline: d > 0n ? d : 0n }
}

/** What can legally happen to t at now. Padding now for clock skew is the caller's job. */
export function classify(t: TicketFields, now: Date): Verdict {
    return classifyView(ticketView(t), now)
}
