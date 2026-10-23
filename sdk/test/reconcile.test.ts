/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// decideTicket and decideSolanaTicket, checked against
// testdata/reconcile_vectors.json, which Go generates from its own with times
// on every boundary it draws.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import {
    type ReconcileAction,
    type SettleArgs,
    type SolanaSweptTicket,
    type TicketBoxView,
    decideSolanaTicket,
    decideTicket,
} from '../src/index.js'
import type { TicketStatus } from '../src/types.js'

interface VectorSettle {
    amount_charged: number
    receipt_digest: string
    ttft_ms: number
    decode_ms: number
    input_tokens: number
    output_tokens: number
    output_usage_type: number
    aux_output_usage_type: number
    aux_output_count: number
}

interface VectorBox {
    status: number
    pending_by: number
    expires_at: number
    settlement_grace_seconds: number
    pending_amount: number
    pending_digest: string
    pending_ttft_ms: number
    pending_decode_ms: number
    pending_input_count: number
    pending_output_count: number
    pending_output_usage_type: number
    pending_aux_output_usage_type: number
    pending_aux_output_count: number
}

interface VectorTicket {
    status: number
    expires_at: number
    grace: number
    pending: {
        amount: number
        receipt_digest: string
        ttft_ms: number
        decode_ms: number
        input_units: number
        output_units: number
        output_usage_type: number
        aux_usage_type: number
        aux_count: number
    }
}

interface Vector {
    name: string
    status: TicketStatus
    expires_at_ms: number
    updated_at_ms: number
    settle: VectorSettle | null
    signed?: VectorSettle
    box: VectorBox | null
    /** A Solana ticket account in place of the box: decideSolanaTicket's case. */
    ticket?: VectorTicket
    /** A Solana ticket with no account: decideSolanaTicket's case too. */
    ticket_closed?: boolean
    now_ms: number
    lapse_fallback_ms: number
    action: ReconcileAction
}

const vectors: Vector[] = JSON.parse(
    readFileSync(new URL('../../testdata/reconcile_vectors.json', import.meta.url), 'utf8'),
)

const b64 = (s: string) => new Uint8Array(Buffer.from(s, 'base64'))

function settleOf(s: VectorSettle): SettleArgs {
    return {
        amountCharged: BigInt(s.amount_charged),
        receiptDigest: b64(s.receipt_digest),
        ttftMs: BigInt(s.ttft_ms),
        decodeMs: BigInt(s.decode_ms),
        inputTokens: BigInt(s.input_tokens),
        outputTokens: BigInt(s.output_tokens),
        outputUsageType: s.output_usage_type,
        auxOutputUsageType: s.aux_output_usage_type,
        auxOutputCount: BigInt(s.aux_output_count),
    }
}

function boxOf(b: VectorBox): TicketBoxView {
    return {
        status: b.status,
        pendingBy: b.pending_by,
        expiresAt: BigInt(b.expires_at),
        settlementGraceSeconds: BigInt(b.settlement_grace_seconds),
        pendingAmount: BigInt(b.pending_amount),
        pendingDigest: b64(b.pending_digest),
        pendingTtftMs: BigInt(b.pending_ttft_ms),
        pendingDecodeMs: BigInt(b.pending_decode_ms),
        pendingInputCount: BigInt(b.pending_input_count),
        pendingOutputCount: BigInt(b.pending_output_count),
        pendingOutputUsageType: b.pending_output_usage_type,
        pendingAuxOutputUsageType: b.pending_aux_output_usage_type,
        pendingAuxOutputCount: BigInt(b.pending_aux_output_count),
    }
}

function ticketOf(t: VectorTicket): SolanaSweptTicket {
    const p = t.pending
    return {
        status: t.status,
        expiresAt: BigInt(t.expires_at),
        grace: t.grace,
        pending: {
            amount: BigInt(p.amount),
            receiptDigest: b64(p.receipt_digest),
            ttftMs: BigInt(p.ttft_ms),
            decodeMs: BigInt(p.decode_ms),
            inputUnits: BigInt(p.input_units),
            outputUnits: BigInt(p.output_units),
            outputUsageType: p.output_usage_type,
            auxUsageType: p.aux_usage_type,
            auxCount: BigInt(p.aux_count),
        },
    }
}

describe('decideTicket', () => {
    it.each(vectors.map((v) => [v.name, v] as const))('%s', (_name, v) => {
        const rec = {
            status: v.status,
            expiresAt: v.expires_at_ms,
            updatedAt: v.updated_at_ms,
            ...(v.settle && { settle: settleOf(v.settle) }),
            ...(v.signed && { signed: settleOf(v.signed) }),
        }
        const decide = (clock: { nowMs: number; chainMs?: number }) =>
            v.ticket || v.ticket_closed
                ? decideSolanaTicket(rec, v.ticket ? ticketOf(v.ticket) : null, clock, v.lapse_fallback_ms)
                : decideTicket(rec, v.box ? boxOf(v.box) : null, clock, v.lapse_fallback_ms)
        expect(decide({ nowMs: v.now_ms })).toBe(v.action)
        // One clock given twice is Go's one clock.
        expect(decide({ nowMs: v.now_ms, chainMs: v.now_ms })).toBe(v.action)
    })

    describe('with a chain clock apart from the local one', () => {
        const E = 1_700_000_000
        const D = (E + 300) * 1000
        const box = (status: number): TicketBoxView => ({
            status,
            pendingBy: 0,
            expiresAt: BigInt(E),
            settlementGraceSeconds: 300n,
            pendingAmount: 0n,
            pendingDigest: new Uint8Array(32),
            pendingTtftMs: 0n,
            pendingDecodeMs: 0n,
            pendingInputCount: 0n,
            pendingOutputCount: 0n,
            pendingOutputUsageType: 0,
            pendingAuxOutputUsageType: 0,
            pendingAuxOutputCount: 0n,
        })
        const settle: SettleArgs = {
            amountCharged: 0n,
            receiptDigest: new Uint8Array(32),
            ttftMs: 0n,
            decodeMs: 0n,
            inputTokens: 0n,
            outputTokens: 0n,
            outputUsageType: 0,
            auxOutputUsageType: 0,
            auxOutputCount: 0n,
        }
        const day = 86_400_000

        it('checks the deadline on the chain clock', () => {
            const rec = { status: 'open' as const, expiresAt: E * 1000, updatedAt: 0 }
            expect(decideTicket(rec, box(1), { nowMs: D - day, chainMs: D + 20_000 })).toBe('refundInactive')
            expect(decideTicket(rec, box(1), { nowMs: D + day, chainMs: D - 20_000 })).toBe('wait')
        })

        it('checks a missing box against the chain clock', () => {
            const rec = { status: 'open' as const, expiresAt: E * 1000, updatedAt: 0 }
            expect(decideTicket(rec, null, { nowMs: 0, chainMs: E * 1000 + 20_000 })).toBe('forget')
            expect(decideTicket(rec, null, { nowMs: E * 1000 + day, chainMs: E * 1000 })).toBe('wait')
        })

        // A slow local clock must not let a settle through after the chain's
        // deadline, nor hold one back that the chain still allows.
        it('checks the resettle cut-off on the chain clock', () => {
            const rec = { status: 'settle_pending' as const, expiresAt: E * 1000, updatedAt: 0, settle }
            expect(decideTicket(rec, box(1), { nowMs: D + day, chainMs: D - 15_001 })).toBe('settle')
            expect(decideTicket(rec, box(1), { nowMs: D - day, chainMs: D - 14_999 })).toBe('wait')
        })

        it('checks the lapse fallback on the chain clock', () => {
            const claim = { ...box(5), pendingBy: 1 }
            const rec = { status: 'open' as const, expiresAt: E * 1000, updatedAt: 0 }
            expect(decideTicket(rec, claim, { nowMs: D - day, chainMs: D + 600_001 })).toBe('settleLapsed')
            expect(decideTicket(rec, claim, { nowMs: D + day, chainMs: D + 600_000 })).toBe('wait')
        })

        it('checks the settle-pending grace on the local clock', () => {
            const updatedAt = 5 * day
            const rec = { status: 'settle_pending' as const, expiresAt: E * 1000, updatedAt, settle }
            const inWindow = D - 20_000
            expect(decideTicket(rec, box(1), { nowMs: updatedAt + 1_000, chainMs: inWindow })).toBe('wait')
            expect(decideTicket(rec, box(1), { nowMs: updatedAt + 120_000, chainMs: inWindow })).toBe('settle')
        })
    })

    describe('on inputs Go never sees', () => {
        const D = (1_700_000_000 + 300) * 1000
        const open: TicketBoxView = {
            status: 1,
            pendingBy: 0,
            expiresAt: 1_700_000_000n,
            settlementGraceSeconds: 300n,
            pendingAmount: 0n,
            pendingDigest: new Uint8Array(32),
            pendingTtftMs: 0n,
            pendingDecodeMs: 0n,
            pendingInputCount: 0n,
            pendingOutputCount: 0n,
            pendingOutputUsageType: 0,
            pendingAuxOutputUsageType: 0,
            pendingAuxOutputCount: 0n,
        }
        const settle: SettleArgs = {
            amountCharged: 0n,
            receiptDigest: new Uint8Array(32),
            ttftMs: 0n,
            decodeMs: 0n,
            inputTokens: 0n,
            outputTokens: 0n,
            outputUsageType: 0,
            auxOutputUsageType: 0,
            auxOutputCount: 0n,
        }
        const rec = { status: 'settle_pending' as const, expiresAt: 0, updatedAt: 0, settle }

        // An extrapolated clock: decided as its whole millisecond.
        it('decides a fractional clock instead of throwing', () => {
            expect(decideTicket(rec, open, { nowMs: D - 15_000.5 })).toBe('settle')
            expect(decideTicket(rec, open, { nowMs: D, chainMs: D - 60_000.5 })).toBe('settle')
            expect(decideTicket(rec, { ...open, pendingBy: 1, status: 5 }, { nowMs: D + 600_001.5 })).toBe(
                'settleLapsed',
            )
            // A computed fallback, such as 4.35 minutes, is rarely whole.
            expect(decideTicket(rec, { ...open, pendingBy: 1, status: 5 }, { nowMs: D + 600_001 }, 600_000.5)).toBe(
                'settleLapsed',
            )
        })

        it('does nothing on a clock that is not a number', () => {
            expect(decideTicket(rec, open, { nowMs: Number.NaN })).toBe('wait')
            expect(decideTicket(rec, null, { nowMs: D, chainMs: Number.NaN })).toBe('wait')
            // With a box, where the chain clock reaches classify and BigInt.
            expect(decideTicket(rec, open, { nowMs: D, chainMs: Number.NaN })).toBe('wait')
            expect(decideTicket(rec, open, { nowMs: D, chainMs: Number.POSITIVE_INFINITY })).toBe('wait')
            expect(decideTicket(rec, open, { nowMs: D + 60_000 }, Number.NaN)).toBe('wait')
        })

        // Go's vectors always carry 32 bytes; a journal can hold fewer. A
        // prefix of the claim must not match it: that settle would freeze.
        it('does not match a receipt digest shorter than the claim', () => {
            const claim = { ...open, status: 5, pendingBy: 1, pendingDigest: new Uint8Array(32).fill(7) }
            const full = { ...rec, settle: { ...settle, receiptDigest: new Uint8Array(32).fill(7) } }
            expect(decideTicket(full, claim, { nowMs: D - 60_000 })).toBe('settle')
            for (const digest of [new Uint8Array(16).fill(7), new Uint8Array(0)]) {
                const short = { ...rec, settle: { ...settle, receiptDigest: digest } }
                expect(decideTicket(short, claim, { nowMs: D - 60_000 })).toBe('wait')
            }
        })

        // As Go's zero time: long past.
        it('reads a record time that is not a number as long past', () => {
            expect(decideTicket({ ...rec, expiresAt: Number.NaN }, null, { nowMs: D })).toBe('forget')
            expect(decideTicket({ ...rec, updatedAt: Number.NaN }, open, { nowMs: D - 60_000 })).toBe('settle')
        })
    })

    // Go's generator guarantees this too; a fixture that lost an action would
    // leave the port's branch for it unchecked.
    it('has a vector for every action, on each rail', () => {
        const actions: ReconcileAction[] = ['wait', 'forget', 'refundInactive', 'settleLapsed', 'settle', 'freeze']
        for (const solana of [false, true]) {
            const rail = vectors.filter((v) => (v.ticket !== undefined || v.ticket_closed === true) === solana)
            expect(new Set(rail.map((v) => v.action))).toEqual(new Set(actions))
        }
        // A closed account is the no-box case on Solana, its own branch.
        expect(vectors.some((v) => v.ticket_closed === true)).toBe(true)
    })
})
