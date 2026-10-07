/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A verified receipt as the OpenAI-compatible surface reports it, mirroring
// proto/go/zs handler/usage.go: the X-Zs-* usage headers on a whole reply, and
// the opt-in zs.usage frame on a stream.

import { computeFeeBreakdown } from '@txnlab/zs-proto/escrow'

import type { ReceiptVerified } from '../events.js'
import { goJSON } from '../responder.js'
import { type StreamFrame, emptyFrame } from '../stream.js'

/**
 * USAGE_FRAME_EVENT is the SSE event the stream carries the usage in. Its data
 * is not an OpenAI chat chunk, and strict OpenAI clients that parse every
 * data line rather than dispatching on the event type fail on it, so it is
 * sent only to a caller that asks with USAGE_FRAME_HEADER.
 */
export const USAGE_FRAME_EVENT = 'zs.usage'

/** USAGE_FRAME_HEADER is the request header (any non-empty value) that opts a stream into the zs.usage frame. */
export const USAGE_FRAME_HEADER = 'X-Zs-Usage-Frame'

/**
 * The HAY fee discount is retired, so always 0. It stays in the X-Zs-Discount-Bps
 * header and the frame's discount_bps for wire-shape stability.
 */
const RETIRED_DISCOUNT_BPS = 0

// The contract escrows USDC (SPEC §3.3a). A function's worth of indirection
// in Go, so a per-ticket currency could plug in without renaming any field.
const CURRENCY = 'USDC'
const DECIMALS = 6

/**
 * The additive-fee decomposition of a settled request, from the signed
 * amount_charged and the payer's fee rate: platform_fee rides on top of the
 * operator's charge, and total_debit is what the payer pays. Nested, so a
 * rate that wasn't known reads apart from a genuine 0 fee.
 */
export interface FeeBreakdown {
    fee_bps: number
    discount_bps: number
    platform_fee_microusdc: number
    refund_microusdc: number
    total_debit_microusdc: number
    total_debit_usd?: number
}

/** feeBreakdownFor is the breakdown, or undefined when the fee rate wasn't known. */
export function feeBreakdownFor(amountCharged: number, maxPrice: number, feeBps: number, haveFee: boolean): FeeBreakdown | undefined {
    if (!haveFee) return undefined
    const b = computeFeeBreakdown(BigInt(amountCharged), BigInt(maxPrice), feeBps, RETIRED_DISCOUNT_BPS)
    const out: FeeBreakdown = {
        fee_bps: feeBps,
        discount_bps: RETIRED_DISCOUNT_BPS,
        platform_fee_microusdc: Number(b.netFee),
        refund_microusdc: Number(b.refund),
        total_debit_microusdc: Number(b.totalDebit),
    }
    const usd = Number(b.totalDebit) / 10 ** DECIMALS
    if (usd !== 0) out.total_debit_usd = usd
    return out
}

/** A dollar figure as Go's "$%.6f" writes it. */
export function dollars(x: number): string {
    return `$${fixed6(x)}`
}

/**
 * x to six decimals as Go's %.6f writes it, which toFixed doesn't quite: Go
 * rounds an exact half to even where toFixed rounds it up, and Go prints every
 * digit past 1e21 where toFixed switches to an exponent.
 */
function fixed6(x: number): string {
    if (Number.isNaN(x)) return 'NaN'
    if (!Number.isFinite(x)) return x > 0 ? '+Inf' : '-Inf'
    const sign = x < 0 || Object.is(x, -0) ? '-' : ''
    const a = Math.abs(x)
    if (a >= 1e21) return `${sign}${BigInt(a)}.000000`
    // A double sits exactly halfway between two millionths only when it is
    // odd/128, since 1e6 * 2 = 2^7 * 5^6 and the 5^6 must divide the numerator.
    const q = a * 128
    if (Number.isInteger(q) && q % 2 === 1) {
        // a * 1e6 = q * 15625 / 2, exactly halfway: take the even neighbour.
        let n = (BigInt(q) * 15625n) / 2n
        if (n % 2n === 1n) n += 1n
        return `${sign}${n / 1_000_000n}.${String(n % 1_000_000n).padStart(6, '0')}`
    }
    return `${sign}${a.toFixed(6)}`
}

/** x in plain decimal, shortest, as Go's strconv.FormatFloat(x, 'f', -1, 64) writes it. */
export function plainFloat(x: number): string {
    const s = String(x)
    const m = /^(-?)(\d)(?:\.(\d+))?e([+-]\d+)$/.exec(s)
    if (m === null) return s
    const [, sign, int, frac = '', expText] = m
    const exp = Number(expText)
    const digits = int! + frac
    if (exp < 0) return `${sign}0.${'0'.repeat(-exp - 1)}${digits}`
    return `${sign}${digits}${'0'.repeat(Math.max(0, exp - frac.length))}`
}

/**
 * setUsageHeaders renders a verified receipt as X-Zs-* response headers, so
 * a caller reading a whole reply sees what it cost in inference and fees.
 * The settle fee is known only once the settle is submitted, after the reply,
 * so it counts 0 here: exact on the atomic path (where the payer's fee is 0),
 * an undercount on the standalone ack. A stream's headers are sent before its
 * receipt, so a stream reports through the zs.usage frame instead. Fees the
 * operator pays are left out: they are not the payer's.
 */
export function setUsageHeaders(h: Headers, ev: ReceiptVerified): void {
    const r = ev.receipt
    const t = ev.ticket
    const totalFees = ev.openFeesMicroAlgos + ev.settleFeesMicroAlgos
    h.set('X-Zs-Ticket-Id', r.ticket_id)
    // Operator and node ids are 1-based on chain; 0 is unset.
    if (ev.target.op !== 0) h.set('X-Zs-Operator-Id', String(ev.target.op))
    if (ev.target.node !== 0) h.set('X-Zs-Node-Id', String(ev.target.node))
    if (ev.ownerAddr !== '') h.set('X-Zs-Operator-Owner-Addr', ev.ownerAddr)
    h.set('X-Zs-Actual-Input-Count', String(r.actual_input_count))
    h.set('X-Zs-Actual-Output-Count', String(r.actual_output_count))
    // The operator's charge; the payer's full debit adds the protocol fee,
    // which the Fee-Bps headers below break down.
    h.set('X-Zs-Inference-Amount', String(r.amount_charged))
    h.set('X-Zs-Inference-Currency', CURRENCY)
    h.set('X-Zs-Inference-Decimals', String(DECIMALS))
    // The escrowed ceiling, grossed up for the fee: the refund is not
    // max_price minus the charge.
    h.set('X-Zs-Max-Price-Amount', String(t.max_price))
    // Always sent, 0 for no floor, so a caller can rely on its presence.
    h.set('X-Zs-Min-Price-Amount', String(t.min_price))
    h.set('X-Zs-Fees-Microalgos', String(totalFees))
    if (r.amount_charged > 0) h.set('X-Zs-Inference-Amount-Usd', dollars(r.amount_charged / 10 ** DECIMALS))
    if (ev.algoUsd > 0) {
        h.set('X-Zs-Fees-Usd', dollars((totalFees / 1_000_000) * ev.algoUsd))
        h.set('X-Zs-Algo-Usd-Rate', plainFloat(ev.algoUsd))
    }
    const fb = feeBreakdownFor(r.amount_charged, t.max_price, ev.feeBps, ev.feeBpsKnown)
    if (fb !== undefined) {
        h.set('X-Zs-Fee-Bps', String(fb.fee_bps))
        h.set('X-Zs-Discount-Bps', String(fb.discount_bps))
        h.set('X-Zs-Platform-Fee-Microusdc', String(fb.platform_fee_microusdc))
        h.set('X-Zs-Refund-Microusdc', String(fb.refund_microusdc))
        h.set('X-Zs-Total-Debit-Microusdc', String(fb.total_debit_microusdc))
        if ((fb.total_debit_usd ?? 0) > 0) h.set('X-Zs-Total-Debit-Usd', dollars(fb.total_debit_usd!))
    }
}

/**
 * usageFrame renders a verified receipt as the zs.usage frame, after the
 * receipt has verified. Its fees are the payer's shares of the open and
 * settle, summed; the receipt's signature and body hash, which a caller
 * can't check, are left out.
 */
export function usageFrame(ev: ReceiptVerified): StreamFrame {
    const r = ev.receipt
    const t = ev.ticket
    const totalFees = ev.openFeesMicroAlgos + ev.settleFeesMicroAlgos
    // Keys in Go's field order, each omitted where Go's omitempty would.
    const inference: Record<string, unknown> = { amount: r.amount_charged, currency: CURRENCY, decimals: DECIMALS }
    if (r.amount_charged > 0) inference.amount_usd = r.amount_charged / 10 ** DECIMALS
    const u: Record<string, unknown> = { type: USAGE_FRAME_EVENT, ticket_id: r.ticket_id }
    if (ev.target.op !== 0) u.operator_id = ev.target.op
    if (ev.target.node !== 0) u.node_id = ev.target.node
    if (ev.ownerAddr !== '') u.operator_owner_addr = ev.ownerAddr
    u.actual_input_count = r.actual_input_count
    u.actual_output_count = r.actual_output_count
    u.inference = inference
    u.max_price_amount = t.max_price
    if (t.min_price !== 0) u.min_price_amount = t.min_price
    u.algo_fees_microalgos = totalFees
    if (ev.algoUsd > 0) {
        const usd = (totalFees / 1_000_000) * ev.algoUsd
        if (usd !== 0) u.algo_fees_usd = usd
        u.algo_usd_rate = ev.algoUsd
    }
    const fee = feeBreakdownFor(r.amount_charged, t.max_price, ev.feeBps, ev.feeBpsKnown)
    if (fee !== undefined) u.fee = fee
    return { ...emptyFrame(), event: USAGE_FRAME_EVENT, data: new TextEncoder().encode(goJSON(u)) }
}
