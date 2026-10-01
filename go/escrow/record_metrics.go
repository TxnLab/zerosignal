/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import "encoding/binary"

// RecordMetrics is the reliability / revenue / volume block the contract
// writes identically onto an OperatorRecord and a NodeRecord — the operator
// copy being the rollup across every node that operator owns, the node copy
// being that one node's own. Same fields, same order, same 432 bytes; only the
// offset into the box differs.
//
// It is ONE type, embedded anonymously in both records, because carving a
// typed field out of the reserve is the documented growth path
// (contracts/AGENTS.md) and every carve has to be mirrored into the Go
// positional parsers. As two hand-maintained copies, a carve mirrored into one
// parser and not the other still passed TestRecordSizes_UnchangedByCarves —
// the totals stay constant across a carve by construction — and silently
// mis-decoded the other record type from that field onward. One declaration
// and one parser make that shape of mistake unrepresentable rather than
// merely unlikely.
//
// UsdcEscrowed is deliberately NOT here: the operator's is the base stake plus
// every live node's increment, the node's is that node's increment alone, so
// they are different quantities that happen to share a width.
//
// Embedding promotes every field, so a plain read (rec.TicketsSettled) is
// unchanged. A keyed composite literal must nest: RecordMetrics{...}.
type RecordMetrics struct {
	// LastActivityAt is the unix-seconds timestamp of the most recent
	// ticket-touching state change (open / settle finalize / refund / protest /
	// freeze). 0 = no activity since registration.
	LastActivityAt uint64

	TicketsOpened             uint64
	TicketsSettled            uint64
	TicketsLapsedSettled      uint64
	TicketsRefundedInactive   uint64
	TotalRefundedInactiveUsdc uint64 // Σ t.maxPrice on refundInactive
	TicketsProtested          uint64
	TotalProtestedUsdc        uint64 // Σ amountCharged on protest
	TicketsFrozenDispute      uint64
	TotalFrozenDisputeUsdc    uint64 // Σ t.pendingAmount on settle-disagreement freeze
	LatencyTotalMs            uint64
	LatencyEwmaMs             uint64

	// ===== Lifetime revenue =====
	TotalRevenueGross uint64 // Σ amountCharged

	// ===== Daily revenue ring buffer =====
	//
	// BucketsLastDay = floor(latestTimestamp / SecondsPerDay) of the most
	// recent bucket update. The on-chain write path zeros stale slots so
	// windowed reads (Revenue24h, Revenue7d, Revenue30d) are blind sums.
	BucketsLastDay uint64
	RevenueBuckets [RevenueBucketCount]uint64

	// ===== Token consumption =====
	// Input stays token-denominated (no per-modality input vector yet).
	TotalInputTokens uint64

	// ===== Output volume by modality =====
	// OutputUnits[t] is Σ output count credited under ticket.UsageType t across
	// every finalized settlement (clean + lapsed). A tool turn bumps BOTH
	// OutputUnits[Tokens] (chat text) and OutputUnits[Images] (tool-produced
	// images); a dedicated image route bumps only OutputUnits[Images]. Slot
	// [1]=Tokens reproduces the old scalar TotalOutputTokens. Mirrors
	// outputUnits in ZeroSignalEscrow.algo.ts.
	OutputUnits [OutputUnitsLen]uint64

	// ===== Throughput =====
	// EWMA of generation throughput (output tokens / sec); see
	// ZeroSignalEscrow.algo.ts. Folded only on token-output settles.
	TokensPerSecEwma uint64
}

// recordMetricsSize is the serialized byte length of the shared block. Both
// record-size constants add it, so a carve that changes it moves both totals
// together — which is what makes TestRecordSizes_UnchangedByCarves meaningful
// rather than tautological.
//
//	lastActivityAt … latencyEwmaMs  (12 × uint64)  96
//	totalRevenueGross                               8
//	bucketsLastDay                                  8
//	revenueBuckets[30]                            240
//	totalInputTokens                                8
//	outputUnits[8]                                 64
//	tokensPerSecEwma                                8
const recordMetricsSize = 8*12 + // 96 — reliability counters (lastActivityAt … latencyEwmaMs)
	8 + // 8  — totalRevenueGross
	8 + // 8  — bucketsLastDay
	8*RevenueBucketCount + // 240 — revenueBuckets[30]
	8 + // 8  — totalInputTokens
	8*OutputUnitsLen + // 64 — outputUnits[8]
	8 // 8  — tokensPerSecEwma
// Total: 96 + 8 + 8 + 240 + 8 + 64 + 8 = 432.

// recordTailSize is the serialized byte length of the reserve + latency-sample
// tail both records end with (see parseRecordTail).
const recordTailSize = 24 + 8

// parseRecordMetrics decodes the shared block starting at off and returns it
// with the offset just past it. The caller has already length-guarded data;
// every read here is unconditional.
func parseRecordMetrics(data []byte, off int) (RecordMetrics, int) {
	var m RecordMetrics
	next := func() uint64 {
		v := binary.BigEndian.Uint64(data[off : off+8])
		off += 8
		return v
	}
	m.LastActivityAt = next()
	m.TicketsOpened = next()
	m.TicketsSettled = next()
	m.TicketsLapsedSettled = next()
	m.TicketsRefundedInactive = next()
	m.TotalRefundedInactiveUsdc = next()
	m.TicketsProtested = next()
	m.TotalProtestedUsdc = next()
	m.TicketsFrozenDispute = next()
	m.TotalFrozenDisputeUsdc = next()
	m.LatencyTotalMs = next()
	m.LatencyEwmaMs = next()
	m.TotalRevenueGross = next()
	m.BucketsLastDay = next()
	for i := range m.RevenueBuckets {
		m.RevenueBuckets[i] = next()
	}
	m.TotalInputTokens = next()
	for i := range m.OutputUnits {
		m.OutputUnits[i] = next()
	}
	m.TokensPerSecEwma = next()
	return m, off
}

// parseRecordTail decodes the reserve blob and the mean-TTFT denominator that
// close both record types, writing them through the pointers.
//
// One home for the order, because it is not the obvious one: the residual
// reserve PRECEDES latencySamples — the carve took the tail END of the
// original 32 bytes, not its head. Reading these two the other way round
// yields a garbage sample count and a corrupt reserve, silently, with the box
// length unchanged. See the contract's reservedSlots for why the carve went
// that way.
//
// Returns nothing on purpose: this is the LAST field block in both records, so
// there is no next offset to chain. An advertised return that both call sites
// discard is a signature nothing verifies — if a third block is ever appended,
// give it a real offset then.
func parseRecordTail(data []byte, off int, reserved *[24]byte, latencySamples *uint64) {
	copy(reserved[:], data[off:off+24])
	off += 24
	*latencySamples = binary.BigEndian.Uint64(data[off : off+8])
}

// Revenue24h returns gross revenue for the calendar day represented by
// currentDay (= floor(unix_seconds / SecondsPerDay)).
//
// The contract zeros stale slots on rotation, so a slot whose stored day is
// outside the rolling 30-day window will already be zero — but windowedRevenue
// also filters by day-stamp defensively, in case a caller passes a currentDay
// that happens to equal a stale slot's old day-stamp under modular arithmetic.
// (For the contract-cleared layout that can't happen: every non-zero slot was
// written on a day inside the window relative to BucketsLastDay. The
// defensive filter just makes Revenue* correct under any future relaxation.)
func (m *RecordMetrics) Revenue24h(currentDay uint64) uint64 {
	return m.windowedRevenue(currentDay, 1)
}

// Revenue7d returns gross revenue over the trailing 7 calendar days ending at
// currentDay (inclusive).
func (m *RecordMetrics) Revenue7d(currentDay uint64) uint64 {
	return m.windowedRevenue(currentDay, 7)
}

// Revenue30d returns gross revenue over the trailing 30 calendar days ending
// at currentDay (inclusive). Equivalent to summing every non-zero slot in
// RevenueBuckets when the contract has been keeping up with rotation.
func (m *RecordMetrics) Revenue30d(currentDay uint64) uint64 {
	return m.windowedRevenue(currentDay, RevenueBucketCount)
}

// windowedRevenue is the canonical read algorithm shared by Revenue24h /
// Revenue7d / Revenue30d. windowDays must be in [1, 30].
func (m *RecordMetrics) windowedRevenue(currentDay uint64, windowDays uint64) uint64 {
	return windowedRingRevenue(m.BucketsLastDay, &m.RevenueBuckets, currentDay, windowDays)
}
