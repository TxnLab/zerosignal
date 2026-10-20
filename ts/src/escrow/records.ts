/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Fixed-offset decoders for the escrow app's ticket, operator and node boxes.
// Mirrors proto/go/escrow/{tickets,operators,nodes,record_metrics}.go.
//
// The boxes are ARC-4 tuples of fixed-size fields, byte-packed with no
// alignment, so they decode by offset with no ARC-4 machinery. A layout change
// in the contract must land here, in the Go parsers, and in the regenerated
// escrow vectors together: a decoder that drifts reads a valid-looking record
// out of the wrong bytes rather than failing.
//
// uint64 fields are bigint. Fields the contract narrows to 1 or 2 bytes
// (statuses, pending side, usage types, fee bps, freeze origin, staging, the
// resolved-ticket count) are number.

import { encodeAlgorandAddress } from '../ticket/signing.js'
import { BASE_URL_MAX, OUTPUT_UNITS_LEN, REVENUE_BUCKET_COUNT } from './constants.js'

// RecordMetrics is the block the contract writes identically onto an operator
// record (the rollup across its nodes) and a node record (that node alone).
export interface RecordMetrics {
    lastActivityAt: bigint
    ticketsOpened: bigint
    ticketsSettled: bigint
    ticketsLapsedSettled: bigint
    ticketsRefundedInactive: bigint
    totalRefundedInactiveUsdc: bigint
    ticketsProtested: bigint
    totalProtestedUsdc: bigint
    ticketsFrozenDispute: bigint
    totalFrozenDisputeUsdc: bigint
    latencyTotalMs: bigint
    latencyEwmaMs: bigint
    totalRevenueGross: bigint
    bucketsLastDay: bigint
    revenueBuckets: bigint[]
    totalInputTokens: bigint
    outputUnits: bigint[]
    tokensPerSecEwma: bigint
}

export interface TicketRecord {
    payerAddr: string
    operatorId: bigint
    nodeId: bigint
    operatorOwnerAddr: string // settlement payout destination
    // The serving node's key at open(). protest() verifies receipts under it;
    // settle's operator half takes the node box's current key instead, and
    // this one only once the node box is gone.
    nodeSigningAddr: string
    maxPrice: bigint
    openedAt: bigint
    expiresAt: bigint
    settlementGraceSeconds: bigint
    status: number
    pendingAmount: bigint
    pendingBy: number
    pendingDigest: Uint8Array
    pendingTtftMs: bigint
    pendingDecodeMs: bigint
    pendingInputCount: bigint
    pendingOutputCount: bigint
    pendingOutputUsageType: number
    pendingAuxOutputUsageType: number
    pendingAuxOutputCount: bigint
    // The protocol-fee rate snapshotted at open() and fixed for the ticket's
    // life — the settle-time debit is a pure function of these.
    feeBps: number
    discountBps: number
    // When and by which path (FREEZE_ORIGIN_*) the ticket froze; both 0
    // unless it is frozen. An arbiter needs the origin, since nothing else on
    // the box tells a protest from a settle mismatch.
    frozenAt: bigint
    freezeOrigin: number
    reservedSlots: Uint8Array
}

// The block both records end with, after usdcEscrowed (operator) or staging
// (node).
export interface RecordTail {
    // Frozen tickets the admin closed with resolveFrozen. A uint16 on chain
    // that saturates at 65535, so read it as "at least" at the ceiling.
    ticketsResolvedAdmin: number
    // The operator's awards from those resolutions, kept out of the revenue
    // metrics because an award is not a sale.
    totalResolvedUsdc: bigint
    reservedSlots: Uint8Array
    // The exact denominator for mean TTFT: bumped only on token-output settles,
    // so dividing latencyTotalMs by the settle counts instead understates it.
    latencySamples: bigint
}

export interface OperatorRecord extends RecordMetrics, RecordTail {
    id: bigint
    ownerAddr: string
    status: number
    nfdAppId: bigint
    nextNodeId: bigint
    liveNodeCount: bigint
    usdcEscrowed: bigint
}

export interface NodeRecord extends RecordMetrics, RecordTail {
    // Not stored in the box: they come from the box key the caller read.
    operatorId: bigint
    nodeId: bigint
    status: number
    signingAddr: string
    baseUrl: string
    usdcEscrowed: bigint
    staging: number
}

const RECORD_METRICS_SIZE = 8 * 12 + 8 + 8 + 8 * REVENUE_BUCKET_COUNT + 8 + 8 * OUTPUT_UNITS_LEN + 8 // 432
const RECORD_RESERVED_LEN = 14
const RECORD_TAIL_SIZE = 2 + 8 + RECORD_RESERVED_LEN + 8 // 32
const TICKET_RESERVED_LEN = 23

export const TICKET_RECORD_SIZE =
    32 + 8 + 8 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 8 + 1 + 32 + 8 + 8 + 8 + 8 + 1 + 1 + 8 + 2 + 2 + 8 + 1 + TICKET_RESERVED_LEN // 264
export const OPERATOR_RECORD_SIZE = 32 + 1 + 8 + 8 + 8 + RECORD_METRICS_SIZE + 8 + RECORD_TAIL_SIZE // 529
export const NODE_RECORD_SIZE = 1 + 32 + 1 + BASE_URL_MAX + RECORD_METRICS_SIZE + 8 + 1 + RECORD_TAIL_SIZE // 755

// Reader walks a box value front to back, so each decoder states the field
// order once instead of repeating offsets that can drift apart.
class Reader {
    private off = 0
    private readonly view: DataView

    constructor(private readonly data: Uint8Array) {
        this.view = new DataView(data.buffer, data.byteOffset, data.byteLength)
    }

    u8(): number {
        return this.view.getUint8(this.off++)
    }

    u16(): number {
        const v = this.view.getUint16(this.off, false)
        this.off += 2
        return v
    }

    u64(): bigint {
        const v = this.view.getBigUint64(this.off, false)
        this.off += 8
        return v
    }

    bytes(n: number): Uint8Array {
        const b = this.data.slice(this.off, this.off + n)
        this.off += n
        return b
    }

    address(): string {
        return encodeAlgorandAddress(this.bytes(32))
    }
}

function readMetrics(r: Reader): RecordMetrics {
    return {
        lastActivityAt: r.u64(),
        ticketsOpened: r.u64(),
        ticketsSettled: r.u64(),
        ticketsLapsedSettled: r.u64(),
        ticketsRefundedInactive: r.u64(),
        totalRefundedInactiveUsdc: r.u64(),
        ticketsProtested: r.u64(),
        totalProtestedUsdc: r.u64(),
        ticketsFrozenDispute: r.u64(),
        totalFrozenDisputeUsdc: r.u64(),
        latencyTotalMs: r.u64(),
        latencyEwmaMs: r.u64(),
        totalRevenueGross: r.u64(),
        bucketsLastDay: r.u64(),
        revenueBuckets: Array.from({ length: REVENUE_BUCKET_COUNT }, () => r.u64()),
        totalInputTokens: r.u64(),
        outputUnits: Array.from({ length: OUTPUT_UNITS_LEN }, () => r.u64()),
        tokensPerSecEwma: r.u64(),
    }
}

// The dispute block was carved from the head of the original 32-byte reserve
// and latencySamples from its tail end, so the residual sits between them.
// Reading any two in the wrong order yields garbage with the box length
// unchanged.
function readTail(r: Reader): RecordTail {
    return {
        ticketsResolvedAdmin: r.u16(),
        totalResolvedUsdc: r.u64(),
        reservedSlots: r.bytes(RECORD_RESERVED_LEN),
        latencySamples: r.u64(),
    }
}

// decodeTicketRecord parses a ticket box value. Trailing bytes past the known
// layout are ignored, matching the Go parser.
export function decodeTicketRecord(data: Uint8Array): TicketRecord {
    if (data.length < TICKET_RECORD_SIZE) {
        throw new Error(`ticket box too short: ${data.length} bytes (want ${TICKET_RECORD_SIZE})`)
    }
    const r = new Reader(data)
    return {
        payerAddr: r.address(),
        operatorId: r.u64(),
        nodeId: r.u64(),
        operatorOwnerAddr: r.address(),
        nodeSigningAddr: r.address(),
        maxPrice: r.u64(),
        openedAt: r.u64(),
        expiresAt: r.u64(),
        settlementGraceSeconds: r.u64(),
        status: r.u8(),
        pendingAmount: r.u64(),
        pendingBy: r.u8(),
        pendingDigest: r.bytes(32),
        pendingTtftMs: r.u64(),
        pendingDecodeMs: r.u64(),
        pendingInputCount: r.u64(),
        pendingOutputCount: r.u64(),
        pendingOutputUsageType: r.u8(),
        pendingAuxOutputUsageType: r.u8(),
        pendingAuxOutputCount: r.u64(),
        feeBps: r.u16(),
        discountBps: r.u16(),
        frozenAt: r.u64(),
        freezeOrigin: r.u8(),
        reservedSlots: r.bytes(TICKET_RESERVED_LEN),
    }
}

export function decodeOperatorRecord(id: bigint, data: Uint8Array): OperatorRecord {
    if (data.length < OPERATOR_RECORD_SIZE) {
        throw new Error(`operator ${id} box too short: ${data.length} bytes (want ${OPERATOR_RECORD_SIZE})`)
    }
    const r = new Reader(data)
    const ownerAddr = r.address()
    const status = r.u8()
    const nfdAppId = r.u64()
    const nextNodeId = r.u64()
    const liveNodeCount = r.u64()
    const metrics = readMetrics(r)
    const usdcEscrowed = r.u64()
    return { id, ownerAddr, status, nfdAppId, nextNodeId, liveNodeCount, ...metrics, usdcEscrowed, ...readTail(r) }
}

/**
 * NodeBaseUrlEncodingError is a node box whose base URL is not UTF-8, which Go
 * decodes and TypeScript cannot. It is its own type so a reader of many boxes
 * can skip that one node rather than fail the read. Go keeps and routes such a
 * node; a JS string cannot carry its URL.
 */
export class NodeBaseUrlEncodingError extends Error {
    constructor(
        readonly operatorId: bigint,
        readonly nodeId: bigint,
    ) {
        super(`node ${operatorId}/${nodeId} baseUrl is not valid UTF-8`)
        this.name = 'NodeBaseUrlEncodingError'
    }
}

// decodeNodeRecord parses a node box value. operatorId and nodeId are the ones
// the caller built the box key from; the box itself doesn't carry them.
export function decodeNodeRecord(operatorId: bigint, nodeId: bigint, data: Uint8Array): NodeRecord {
    if (data.length < NODE_RECORD_SIZE) {
        throw new Error(`node ${operatorId}/${nodeId} box too short: ${data.length} bytes (want ${NODE_RECORD_SIZE})`)
    }
    const r = new Reader(data)
    const status = r.u8()
    const signingAddr = r.address()
    const baseUrlLen = r.u8()
    if (baseUrlLen > BASE_URL_MAX) {
        throw new Error(`node ${operatorId}/${nodeId} baseUrlLen ${baseUrlLen} exceeds ${BASE_URL_MAX}`)
    }
    const urlField = r.bytes(BASE_URL_MAX)
    let end = baseUrlLen
    while (end > 0 && urlField[end - 1] === 0) end--
    // ignoreBOM keeps a leading U+FEFF, as Go's string conversion does; the
    // default decoder would silently drop it.
    //
    // fatal refuses invalid UTF-8, where Go keeps the raw bytes (and its HTTP
    // client percent-escapes them, so Go can still reach such a node). A JS
    // string can't hold them, and substituting U+FFFD would hand back a URL
    // that differs from the stored one while decoding as if nothing were
    // wrong, so the box is refused rather than decoded into the wrong URL.
    let baseUrl: string
    try {
        baseUrl = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true }).decode(urlField.subarray(0, end))
    } catch {
        throw new NodeBaseUrlEncodingError(operatorId, nodeId)
    }
    const metrics = readMetrics(r)
    const usdcEscrowed = r.u64()
    const staging = r.u8()
    return { operatorId, nodeId, status, signingAddr, baseUrl, ...metrics, usdcEscrowed, staging, ...readTail(r) }
}

// windowedRingRevenue sums the daily-revenue ring over the trailing windowDays
// (1..30) ending at currentDay, inclusive. Day indices are
// floor(unix_seconds / SECONDS_PER_DAY). The contract zeros stale slots, so the
// day filter is defensive.
export function windowedRingRevenue(
    bucketsLastDay: bigint,
    buckets: readonly bigint[],
    currentDay: bigint,
    windowDays: bigint,
): bigint {
    if (buckets.length !== REVENUE_BUCKET_COUNT) {
        throw new Error(`revenue ring has ${buckets.length} buckets, want ${REVENUE_BUCKET_COUNT}`)
    }
    const ring = BigInt(REVENUE_BUCKET_COUNT)
    if (windowDays === 0n || windowDays > ring) return 0n
    if (bucketsLastDay === 0n) return 0n
    if (currentDay < bucketsLastDay) return 0n
    const cutoff = currentDay + 1n > windowDays ? currentDay - windowDays + 1n : 0n
    if (bucketsLastDay + ring <= cutoff) return 0n
    let total = 0n
    for (let step = 0n; step < ring; step++) {
        if (step > bucketsLastDay) break
        const day = bucketsLastDay - step
        if (day < cutoff) break
        if (day > currentDay) continue
        total += buckets[Number(day % ring)] ?? 0n // in range: length checked above
    }
    return total
}
