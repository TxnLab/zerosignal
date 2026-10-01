/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// TestParseOperatorRecord_AllFields pins the positional parser against
// a hand-built box image with a distinct non-zero value in every
// field, so a future reorder / off-by-eight in the offset walk shows
// up here rather than silently mislabeling metrics. The byte layout
// mirrors the field order in ZeroSignalEscrow.OperatorRecord (and the
// SPEC §3c table).
func TestParseOperatorRecord_AllFields(t *testing.T) {
	var owner types.Address
	for i := range owner {
		owner[i] = byte(i + 1)
	}

	put64 := func(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

	var data []byte
	data = append(data, owner[:]...)                 // owner address (32)
	data = append(data, byte(OperatorStatusEvicted)) // status (arc4.Uint8, 1 byte)
	data = put64(data, 4242)                         // nfdAppId
	data = put64(data, 5)                            // nextNodeId
	data = put64(data, 3)                            // liveNodeCount
	// rolled-up reliability metrics — distinct values
	data = put64(data, 1_700_000_000) // lastActivityAt
	data = put64(data, 100)           // ticketsOpened
	data = put64(data, 70)            // ticketsSettled
	data = put64(data, 5)             // ticketsLapsedSettled
	data = put64(data, 3)             // ticketsRefundedInactive
	data = put64(data, 30_000)        // totalRefundedInactiveUsdc
	data = put64(data, 2)             // ticketsProtested
	data = put64(data, 15_000)        // totalProtestedUsdc
	data = put64(data, 1)             // ticketsFrozenDispute
	data = put64(data, 9_000)         // totalFrozenDisputeUsdc
	data = put64(data, 525_000)       // latencyTotalMs
	data = put64(data, 7_000)         // latencyEwmaMs
	// lifetime revenue
	data = put64(data, 1_234_500) // totalRevenueGross
	// daily ring
	data = put64(data, 20_001) // bucketsLastDay
	for i := 0; i < RevenueBucketCount; i++ {
		data = put64(data, uint64(1000+i)) // revenueBuckets[i]
	}
	// token consumption + output modality vector
	data = put64(data, 5_555_000) // totalInputTokens
	for i := 0; i < OutputUnitsLen; i++ {
		data = put64(data, uint64(8_888_000+i)) // outputUnits[i]
	}
	// throughput
	data = put64(data, 333_000) // tokensPerSecEwma
	// operator USDC stake
	data = put64(data, 250_000_000) // usdcEscrowed ($250)
	// Reserved padding — recognizable pattern that round-trips through the
	// parser. 24 bytes, and it comes BEFORE latencySamples: the carve took the
	// tail END so it can't collide with a head carve. Appending these two in
	// the other order still yields a well-formed image of the right length,
	// which is exactly why the values below are distinguishable.
	reservedPattern := bytes.Repeat([]byte{0xAB}, 24)
	data = append(data, reservedPattern...)
	data = put64(data, 61) // latencySamples

	if len(data) != operatorRecordSize {
		t.Fatalf("built box image = %d bytes, want operatorRecordSize %d", len(data), operatorRecordSize)
	}

	rec, err := parseOperatorRecord(7, data)
	if err != nil {
		t.Fatalf("parseOperatorRecord: %v", err)
	}
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"Status", rec.Status, OperatorStatusEvicted},
		{"NFDAppID", rec.NFDAppID, 4242},
		{"NextNodeID", rec.NextNodeID, 5},
		{"LiveNodeCount", rec.LiveNodeCount, 3},
		{"LastActivityAt", rec.LastActivityAt, 1_700_000_000},
		{"TicketsOpened", rec.TicketsOpened, 100},
		{"TicketsSettled", rec.TicketsSettled, 70},
		{"TicketsLapsedSettled", rec.TicketsLapsedSettled, 5},
		{"TicketsRefundedInactive", rec.TicketsRefundedInactive, 3},
		{"TotalRefundedInactiveUsdc", rec.TotalRefundedInactiveUsdc, 30_000},
		{"TicketsProtested", rec.TicketsProtested, 2},
		{"TotalProtestedUsdc", rec.TotalProtestedUsdc, 15_000},
		{"TicketsFrozenDispute", rec.TicketsFrozenDispute, 1},
		{"TotalFrozenDisputeUsdc", rec.TotalFrozenDisputeUsdc, 9_000},
		{"LatencyTotalMs", rec.LatencyTotalMs, 525_000},
		{"LatencyEwmaMs", rec.LatencyEwmaMs, 7_000},
		{"TotalRevenueGross", rec.TotalRevenueGross, 1_234_500},
		{"BucketsLastDay", rec.BucketsLastDay, 20_001},
		{"TotalInputTokens", rec.TotalInputTokens, 5_555_000},
		{"TokensPerSecEwma", rec.TokensPerSecEwma, 333_000},
		{"UsdcEscrowed", rec.UsdcEscrowed, 250_000_000},
		{"LatencySamples", rec.LatencySamples, 61},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	if rec.ID != 7 {
		t.Errorf("ID = %d, want 7", rec.ID)
	}
	if rec.OwnerAddr != owner.String() {
		t.Errorf("OwnerAddr = %q, want %q", rec.OwnerAddr, owner.String())
	}
	for i := 0; i < RevenueBucketCount; i++ {
		if rec.RevenueBuckets[i] != uint64(1000+i) {
			t.Errorf("RevenueBuckets[%d] = %d, want %d", i, rec.RevenueBuckets[i], 1000+i)
		}
	}
	for i := 0; i < OutputUnitsLen; i++ {
		if rec.OutputUnits[i] != uint64(8_888_000+i) {
			t.Errorf("OutputUnits[%d] = %d, want %d", i, rec.OutputUnits[i], 8_888_000+i)
		}
	}
	if !bytes.Equal(rec.ReservedSlots[:], reservedPattern) {
		t.Errorf("ReservedSlots = %x, want %x", rec.ReservedSlots, reservedPattern)
	}
}

// TestParseNodeRecord_AllFields pins the node-box positional parser the same
// way: a hand-built image with a distinct value per field. The (operatorId,
// nodeId) pair comes from the box key, not the value, so the parser takes
// them as args.
func TestParseNodeRecord_AllFields(t *testing.T) {
	var signing types.Address
	for i := range signing {
		signing[i] = byte(0x40 + i)
	}
	const baseURL = "https://node.example:8443"

	put64 := func(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

	var data []byte
	data = append(data, byte(NodeStatusActive)) // status (arc4.Uint8, 1 byte)
	data = append(data, signing[:]...)          // signing address (32)
	data = append(data, byte(len(baseURL)))     // baseUrlLen (arc4.Uint8, 1 byte)
	urlBuf := make([]byte, 248)
	copy(urlBuf, baseURL)
	data = append(data, urlBuf...) // baseUrl byte[248]
	// per-node reliability metrics — distinct values
	data = put64(data, 1_700_000_000) // lastActivityAt
	data = put64(data, 100)           // ticketsOpened
	data = put64(data, 70)            // ticketsSettled
	data = put64(data, 5)             // ticketsLapsedSettled
	data = put64(data, 3)             // ticketsRefundedInactive
	data = put64(data, 30_000)        // totalRefundedInactiveUsdc
	data = put64(data, 2)             // ticketsProtested
	data = put64(data, 15_000)        // totalProtestedUsdc
	data = put64(data, 1)             // ticketsFrozenDispute
	data = put64(data, 9_000)         // totalFrozenDisputeUsdc
	data = put64(data, 525_000)       // latencyTotalMs
	data = put64(data, 7_000)         // latencyEwmaMs
	data = put64(data, 1_234_500)     // totalRevenueGross
	data = put64(data, 20_001)        // bucketsLastDay
	for i := 0; i < RevenueBucketCount; i++ {
		data = put64(data, uint64(1000+i)) // revenueBuckets[i]
	}
	data = put64(data, 5_555_000) // totalInputTokens
	for i := 0; i < OutputUnitsLen; i++ {
		data = put64(data, uint64(8_888_000+i)) // outputUnits[i]
	}
	data = put64(data, 333_000)    // tokensPerSecEwma
	data = put64(data, 25_000_000) // usdcEscrowed ($25)
	data = append(data, byte(1))   // staging (arc4.Uint8, 1 byte)
	// 24-byte residual, then latencySamples — see the operator twin above for
	// why the reserve precedes the carved field.
	reservedPattern := bytes.Repeat([]byte{0xCD}, 24)
	data = append(data, reservedPattern...)
	data = put64(data, 61) // latencySamples

	if len(data) != nodeRecordSize {
		t.Fatalf("built node box image = %d bytes, want nodeRecordSize %d", len(data), nodeRecordSize)
	}

	rec, err := parseNodeRecord(7, 3, data)
	if err != nil {
		t.Fatalf("parseNodeRecord: %v", err)
	}
	if rec.OperatorID != 7 || rec.NodeID != 3 {
		t.Errorf("OperatorID/NodeID = %d/%d, want 7/3", rec.OperatorID, rec.NodeID)
	}
	if rec.Status != NodeStatusActive {
		t.Errorf("Status = %d, want %d", rec.Status, NodeStatusActive)
	}
	if rec.SigningAddr != signing.String() {
		t.Errorf("SigningAddr = %q, want %q", rec.SigningAddr, signing.String())
	}
	if rec.BaseURL != baseURL {
		t.Errorf("BaseURL = %q, want %q", rec.BaseURL, baseURL)
	}
	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"LastActivityAt", rec.LastActivityAt, 1_700_000_000},
		{"TicketsOpened", rec.TicketsOpened, 100},
		{"TicketsSettled", rec.TicketsSettled, 70},
		{"TotalRevenueGross", rec.TotalRevenueGross, 1_234_500},
		{"BucketsLastDay", rec.BucketsLastDay, 20_001},
		{"TotalInputTokens", rec.TotalInputTokens, 5_555_000},
		{"TokensPerSecEwma", rec.TokensPerSecEwma, 333_000},
		{"UsdcEscrowed", rec.UsdcEscrowed, 25_000_000},
		{"Staging", rec.Staging, 1},
		{"LatencySamples", rec.LatencySamples, 61},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
	for i := 0; i < OutputUnitsLen; i++ {
		if rec.OutputUnits[i] != uint64(8_888_000+i) {
			t.Errorf("OutputUnits[%d] = %d, want %d", i, rec.OutputUnits[i], 8_888_000+i)
		}
	}
	if !bytes.Equal(rec.ReservedSlots[:], reservedPattern) {
		t.Errorf("ReservedSlots = %x, want %x", rec.ReservedSlots, reservedPattern)
	}
}

// TestRecordSizes_UnchangedByCarves pins the two box sizes as literals.
// Growing either record is a per-box MBR change that updateApplication cannot
// perform, so every field added here must be CARVED from reservedSlots at a
// constant total. These numbers are also confirmed against the deployed
// mainnet boxes; if a carve is done wrong the arithmetic in the size constant
// still adds up locally, and this is the check that catches it.
func TestRecordSizes_UnchangedByCarves(t *testing.T) {
	if operatorRecordSize != 529 {
		t.Errorf("operatorRecordSize = %d, want 529 — a carve must keep the total constant", operatorRecordSize)
	}
	if nodeRecordSize != 755 {
		t.Errorf("nodeRecordSize = %d, want 755 — a carve must keep the total constant", nodeRecordSize)
	}
}

// TestParseRecords_PreCarveBoxes decodes box images written by the contract
// version BEFORE latencySamples was carved: identical bytes except the tail is
// a full 32-byte zero reserve. Every box on chain today is one of these, so
// this is what the parsers actually meet the moment updateApplication lands.
//
// The property that makes the upgrade safe: latencySamples occupies the LAST 8
// bytes of that old reserve, which are zero — so it reads 0 (no token settle
// recorded yet) and the contract's one-time seed fires on the next one. Had the
// carve taken the reserve's head instead, these same bytes would still parse
// without error while shifting the residual.
func TestParseRecords_PreCarveBoxes(t *testing.T) {
	put64 := func(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

	// Operator box, pre-carve layout: everything up to usdcEscrowed, then 32
	// zero bytes. Same total length — that is the whole point of a carve.
	var op []byte
	op = append(op, make([]byte, 32)...)        // owner
	op = append(op, byte(OperatorStatusActive)) // status
	op = put64(op, 0)                           // nfdAppId
	op = put64(op, 2)                           // nextNodeId
	op = put64(op, 1)                           // liveNodeCount
	op = put64(op, 1_700_000_000)               // lastActivityAt
	op = put64(op, 832)                         // ticketsOpened
	op = put64(op, 830)                         // ticketsSettled
	op = put64(op, 2)                           // ticketsLapsedSettled
	for i := 0; i < 6; i++ {
		op = put64(op, 0) // refunded/protested/frozen counters + totals
	}
	op = put64(op, 3_644_160) // latencyTotalMs — real history, non-zero
	op = put64(op, 1_130)     // latencyEwmaMs
	op = put64(op, 9_000_000) // totalRevenueGross
	op = put64(op, 20_001)    // bucketsLastDay
	for i := 0; i < RevenueBucketCount; i++ {
		op = put64(op, 0)
	}
	op = put64(op, 1_000_000) // totalInputTokens
	for i := 0; i < OutputUnitsLen; i++ {
		op = put64(op, 0)
	}
	op = put64(op, 40)                   // tokensPerSecEwma
	op = put64(op, 250_000_000)          // usdcEscrowed
	op = append(op, make([]byte, 32)...) // the OLD reservedSlots<32>, all zero

	if len(op) != operatorRecordSize {
		t.Fatalf("pre-carve operator image = %d bytes, want %d — the carve was not size-neutral", len(op), operatorRecordSize)
	}
	opRec, err := parseOperatorRecord(1, op)
	if err != nil {
		t.Fatalf("parseOperatorRecord: %v", err)
	}
	if opRec.LatencyTotalMs != 3_644_160 {
		t.Errorf("LatencyTotalMs = %d, want 3644160 — history must survive the layout change", opRec.LatencyTotalMs)
	}
	if opRec.LatencySamples != 0 {
		t.Errorf("LatencySamples = %d, want 0 on a pre-carve box", opRec.LatencySamples)
	}
	if opRec.UsdcEscrowed != 250_000_000 {
		t.Errorf("UsdcEscrowed = %d, want 250000000 — the field before the reserve must not shift", opRec.UsdcEscrowed)
	}
	if !bytes.Equal(opRec.ReservedSlots[:], make([]byte, 24)) {
		t.Errorf("ReservedSlots = %x, want 24 zero bytes", opRec.ReservedSlots)
	}

	// Node box, pre-carve layout.
	var nd []byte
	nd = append(nd, byte(NodeStatusActive))
	nd = append(nd, make([]byte, 32)...) // signing
	nd = append(nd, byte(0))             // baseUrlLen
	nd = append(nd, make([]byte, 248)...)
	nd = put64(nd, 1_700_000_000) // lastActivityAt
	nd = put64(nd, 832)           // ticketsOpened
	nd = put64(nd, 830)           // ticketsSettled
	nd = put64(nd, 2)             // ticketsLapsedSettled
	for i := 0; i < 6; i++ {
		nd = put64(nd, 0)
	}
	nd = put64(nd, 3_644_160) // latencyTotalMs
	nd = put64(nd, 1_130)     // latencyEwmaMs
	nd = put64(nd, 9_000_000) // totalRevenueGross
	nd = put64(nd, 20_001)    // bucketsLastDay
	for i := 0; i < RevenueBucketCount; i++ {
		nd = put64(nd, 0)
	}
	nd = put64(nd, 1_000_000) // totalInputTokens
	for i := 0; i < OutputUnitsLen; i++ {
		nd = put64(nd, 0)
	}
	nd = put64(nd, 40)                   // tokensPerSecEwma
	nd = put64(nd, 25_000_000)           // usdcEscrowed
	nd = append(nd, byte(1))             // staging
	nd = append(nd, make([]byte, 32)...) // the OLD reservedSlots<32>, all zero

	if len(nd) != nodeRecordSize {
		t.Fatalf("pre-carve node image = %d bytes, want %d — the carve was not size-neutral", len(nd), nodeRecordSize)
	}
	ndRec, err := parseNodeRecord(1, 1, nd)
	if err != nil {
		t.Fatalf("parseNodeRecord: %v", err)
	}
	if ndRec.LatencyTotalMs != 3_644_160 {
		t.Errorf("LatencyTotalMs = %d, want 3644160", ndRec.LatencyTotalMs)
	}
	if ndRec.LatencySamples != 0 {
		t.Errorf("LatencySamples = %d, want 0 on a pre-carve box", ndRec.LatencySamples)
	}
	// Staging sits immediately before the reserve, so a mis-sized carve shows
	// up here as a shifted flag rather than as a length error.
	if ndRec.Staging != 1 {
		t.Errorf("Staging = %d, want 1", ndRec.Staging)
	}
	if !bytes.Equal(ndRec.ReservedSlots[:], make([]byte, 24)) {
		t.Errorf("ReservedSlots = %x, want 24 zero bytes", ndRec.ReservedSlots)
	}
}

// TestWindowedRevenue_Boundaries pins the read-side semantics of the
// 30-day revenue ring. The contract zeros stale slots on rotation, so
// in production every non-zero slot in `RevenueBuckets` is guaranteed
// to fall inside the rolling 30-day window relative to `BucketsLastDay`.
// These tests exercise the off-chain reader against hand-constructed
// records covering the cases where the boundary matters most.
func TestWindowedRevenue_Boundaries(t *testing.T) {
	t.Run("never_written", func(t *testing.T) {
		var r OperatorRecord
		if got := r.Revenue24h(100); got != 0 {
			t.Errorf("Revenue24h on empty record = %d, want 0", got)
		}
		if got := r.Revenue7d(100); got != 0 {
			t.Errorf("Revenue7d on empty record = %d, want 0", got)
		}
		if got := r.Revenue30d(100); got != 0 {
			t.Errorf("Revenue30d on empty record = %d, want 0", got)
		}
	})

	t.Run("single_day_today", func(t *testing.T) {
		const day = uint64(20_000)
		var r OperatorRecord
		r.BucketsLastDay = day
		r.RevenueBuckets[day%RevenueBucketCount] = 12_345
		if got := r.Revenue24h(day); got != 12_345 {
			t.Errorf("Revenue24h = %d, want 12345", got)
		}
		if got := r.Revenue7d(day); got != 12_345 {
			t.Errorf("Revenue7d = %d, want 12345", got)
		}
		if got := r.Revenue30d(day); got != 12_345 {
			t.Errorf("Revenue30d = %d, want 12345", got)
		}
	})

	t.Run("seven_consecutive_days", func(t *testing.T) {
		const start = uint64(20_000)
		var r OperatorRecord
		var sum uint64
		for i := uint64(0); i < 7; i++ {
			day := start + i
			val := (i + 1) * 1_000
			r.RevenueBuckets[day%RevenueBucketCount] = val
			sum += val
		}
		r.BucketsLastDay = start + 6
		if got := r.Revenue7d(start + 6); got != sum {
			t.Errorf("Revenue7d on contiguous fill = %d, want %d", got, sum)
		}
		if got := r.Revenue24h(start + 6); got != 7_000 {
			t.Errorf("Revenue24h should only see today = %d, want 7000", got)
		}
	})

	// At currentDay = BucketsLastDay + 30 the cutoff exactly equals
	// BucketsLastDay + 1, so the most recent slot is one day too old —
	// the 30-day window must report 0. This is the boundary the original
	// review flagged as worth pinning.
	t.Run("cutoff_eq_lastDay_plus_one", func(t *testing.T) {
		const lastDay = uint64(20_000)
		var r OperatorRecord
		r.BucketsLastDay = lastDay
		r.RevenueBuckets[lastDay%RevenueBucketCount] = 50_000
		if got := r.Revenue30d(lastDay + 30); got != 0 {
			t.Errorf("Revenue30d with currentDay = lastDay+30 should exclude lastDay; got %d, want 0", got)
		}
		// Sanity: a single day earlier (currentDay = lastDay+29), the
		// most recent slot is still inside the 30-day window.
		if got := r.Revenue30d(lastDay + 29); got != 50_000 {
			t.Errorf("Revenue30d with currentDay = lastDay+29 should include lastDay; got %d, want 50000", got)
		}
	})

	t.Run("currentDay_in_past_returns_zero", func(t *testing.T) {
		const lastDay = uint64(20_000)
		var r OperatorRecord
		r.BucketsLastDay = lastDay
		r.RevenueBuckets[lastDay%RevenueBucketCount] = 50_000
		if got := r.Revenue7d(lastDay - 1); got != 0 {
			t.Errorf("Revenue7d with currentDay < lastDay should return 0; got %d", got)
		}
	})

	t.Run("oversized_window", func(t *testing.T) {
		var r OperatorRecord
		r.BucketsLastDay = 20_000
		r.RevenueBuckets[20_000%RevenueBucketCount] = 1_000
		// windowedRevenue rejects windowDays > RevenueBucketCount.
		if got := r.windowedRevenue(20_000, RevenueBucketCount+1); got != 0 {
			t.Errorf("oversized window should return 0; got %d", got)
		}
	})
}

// TestRecordMetrics_DecodeIdenticallyFromBothRecords feeds the SAME 432-byte
// metrics span through both box parsers — at operator offset 57 and node
// offset 282 — and requires the decoded blocks to be equal.
//
// This is the check TestRecordSizes_UnchangedByCarves cannot make. A carve
// keeps both totals constant by construction, so the size test stays green
// even when a new field is read in one parser and not the other; the box then
// mis-decodes from that field onward rather than failing. Sharing one
// RecordMetrics parser is what makes that unrepresentable, and this test is
// what would notice if someone hand-inlined it again.
func TestRecordMetrics_DecodeIdenticallyFromBothRecords(t *testing.T) {
	put64 := func(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }

	// Every slot a distinct non-zero value, so a one-field shift moves a
	// recognizable number rather than sliding zeros past zeros. Counting from
	// 101 keeps every value clear of the small constants elsewhere in the box.
	var metrics []byte
	next := uint64(101)
	for range recordMetricsSize / 8 {
		metrics = put64(metrics, next)
		next++
	}
	if len(metrics) != recordMetricsSize {
		t.Fatalf("metrics span = %d bytes, want %d", len(metrics), recordMetricsSize)
	}

	var op []byte
	op = append(op, make([]byte, 32)...)        // owner
	op = append(op, byte(OperatorStatusActive)) // status
	op = put64(op, 7)                           // nfdAppId
	op = put64(op, 2)                           // nextNodeId
	op = put64(op, 1)                           // liveNodeCount
	op = append(op, metrics...)
	op = put64(op, 250_000_000)          // usdcEscrowed
	op = append(op, make([]byte, 24)...) // reservedSlots
	op = put64(op, 55)                   // latencySamples
	if len(op) != operatorRecordSize {
		t.Fatalf("operator image = %d bytes, want %d", len(op), operatorRecordSize)
	}

	var nd []byte
	nd = append(nd, byte(NodeStatusActive))
	nd = append(nd, make([]byte, 32)...) // signingAddr
	nd = append(nd, byte(0))             // baseUrlLen
	nd = append(nd, make([]byte, BaseURLMax)...)
	nd = append(nd, metrics...)
	nd = put64(nd, 25_000_000)           // usdcEscrowed
	nd = append(nd, byte(0))             // staging
	nd = append(nd, make([]byte, 24)...) // reservedSlots
	nd = put64(nd, 55)                   // latencySamples
	if len(nd) != nodeRecordSize {
		t.Fatalf("node image = %d bytes, want %d", len(nd), nodeRecordSize)
	}

	opRec, err := parseOperatorRecord(1, op)
	if err != nil {
		t.Fatalf("parseOperatorRecord: %v", err)
	}
	ndRec, err := parseNodeRecord(1, 1, nd)
	if err != nil {
		t.Fatalf("parseNodeRecord: %v", err)
	}

	if opRec.RecordMetrics != ndRec.RecordMetrics {
		t.Errorf("the same metrics span decoded differently:\n operator=%+v\n node=%+v",
			opRec.RecordMetrics, ndRec.RecordMetrics)
	}
	// Guard against the equality above being satisfied by two zero blocks: pin
	// the first and last fields of the span to what was written.
	if opRec.LastActivityAt != 101 {
		t.Errorf("LastActivityAt = %d, want 101 — the span did not start at the expected offset", opRec.LastActivityAt)
	}
	if want := 101 + uint64(recordMetricsSize/8) - 1; opRec.TokensPerSecEwma != want {
		t.Errorf("TokensPerSecEwma = %d, want %d — the span did not end where the size constant says", opRec.TokensPerSecEwma, want)
	}
	// And that the fields AFTER the span still land where each record puts
	// them — the operator has no staging byte, the node does.
	if opRec.UsdcEscrowed != 250_000_000 || ndRec.UsdcEscrowed != 25_000_000 {
		t.Errorf("UsdcEscrowed = op %d / node %d, want 250000000 / 25000000",
			opRec.UsdcEscrowed, ndRec.UsdcEscrowed)
	}
	if opRec.LatencySamples != 55 || ndRec.LatencySamples != 55 {
		t.Errorf("LatencySamples = op %d / node %d, want 55 / 55 — the tail shifted",
			opRec.LatencySamples, ndRec.LatencySamples)
	}
}
