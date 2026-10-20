/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The program's events. Mirrors proto/go/solana/zsescrow/events.go, pinned by
// solana_event_vectors.json. The program emits them by invoking itself
// (Anchor's emit_cpi), signed by the event authority, so they sit in a
// transaction's inner instructions, where a log truncation can't drop them.
// The data is EVENT_IX_TAG, the event's discriminator, then its Borsh fields.

import { equalBytes } from '../../util/bytes.js'
import type { PublicKey } from '../key.js'
import { DecodeError, Reader, decodeUtf8 } from './borsh.js'
import { type Addresses, discriminator } from './program.js'

/** Anchor's EVENT_IX_TAG, little-endian. */
export const EVENT_IX_TAG = Uint8Array.of(0xe4, 0x45, 0xa5, 0x2e, 0x51, 0xcb, 0x9a, 0x1d)

export class NotEventError extends Error {
    constructor(detail = '') {
        super(`zsescrow: not an event${detail ? `: ${detail}` : ''}`)
        this.name = 'NotEventError'
    }
}

/** How a ticket ended; an unknown byte reads as `SettleOutcome(n)`. */
export function settleOutcomeName(o: number): string {
    return ['Cooperative', 'Acked', 'Lapsed', 'RefundedInactive', 'Resolved'][o] ?? `SettleOutcome(${o})`
}

export interface TicketSettled {
    event: 'TicketSettled'
    ticket: PublicKey
    node: PublicKey
    outcome: number
    amount: bigint
    fee: bigint
    refund: bigint
    /** The refund went to the payer's RefundOwed, not its token account. */
    refundOwed: boolean
}

export interface TicketClaimed {
    event: 'TicketClaimed'
    ticket: PublicKey
    node: PublicKey
    amount: bigint
}

export interface TicketProtested {
    event: 'TicketProtested'
    ticket: PublicKey
    node: PublicKey
    reason: number
    /** What the protested receipt charged, read from the bytes the node signed. */
    amount: bigint
}

export interface OperatorEvicted {
    event: 'OperatorEvicted'
    operatorId: bigint
    slashed: bigint
    reason: string
}

export type Event = TicketSettled | TicketClaimed | TicketProtested | OperatorEvicted

/**
 * isEventInstruction reports whether an inner instruction is one of d's
 * event self-invocations: to the program, with its event authority as the
 * one account. Only the program can sign for that authority, and the
 * program's event handler refuses an unsigned call, so in a transaction that
 * succeeded such an instruction is the program's own; data of that shape
 * anywhere else is a forgery. A caller must read events only from the inner
 * instructions of a transaction whose meta.err is null: a failed
 * transaction's metadata can still list inner instructions, events of state
 * that never landed.
 */
export function isEventInstruction(d: Addresses, programId: PublicKey, accounts: PublicKey[]): boolean {
    return programId === d.program && accounts.length === 1 && accounts[0] === d.eventAuthority()
}

const DISC = {
    TicketSettled: discriminator('event', 'TicketSettled'),
    TicketClaimed: discriminator('event', 'TicketClaimed'),
    TicketProtested: discriminator('event', 'TicketProtested'),
    OperatorEvicted: discriminator('event', 'OperatorEvicted'),
}

/** parseEvent decodes an event self-invocation's data. Check isEventInstruction first. */
export function parseEvent(data: Uint8Array): Event {
    if (data.length < 16 || !equalBytes(data.subarray(0, 8), EVENT_IX_TAG)) throw new NotEventError()
    const r = new Reader(data, 16)
    const disc = data.subarray(8, 16)
    let ev: Event
    if (equalBytes(disc, DISC.TicketSettled)) {
        ev = { event: 'TicketSettled', ticket: r.key(), node: r.key(), outcome: r.u8(), amount: r.u64(), fee: r.u64(), refund: r.u64(), refundOwed: r.bool() }
    } else if (equalBytes(disc, DISC.TicketClaimed)) {
        ev = { event: 'TicketClaimed', ticket: r.key(), node: r.key(), amount: r.u64() }
    } else if (equalBytes(disc, DISC.TicketProtested)) {
        ev = { event: 'TicketProtested', ticket: r.key(), node: r.key(), reason: r.u8(), amount: r.u64() }
    } else if (equalBytes(disc, DISC.OperatorEvicted)) {
        ev = { event: 'OperatorEvicted', operatorId: r.u64(), slashed: r.u64(), reason: decodeUtf8(r.vec(), 'reason') }
    } else {
        throw new NotEventError(`discriminator ${Array.from(disc, (b) => b.toString(16).padStart(2, '0')).join('')}`)
    }
    if (r.remaining !== 0) throw new DecodeError(`${r.remaining} trailing bytes`)
    return ev
}
