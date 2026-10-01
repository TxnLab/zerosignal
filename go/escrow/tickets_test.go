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

// TestParseTicketRecord_AllFields pins the positional parser against a
// hand-built box image with a distinct non-zero value in every field,
// so a future reorder / off-by-eight in the offset walk surfaces here
// rather than silently dropping pending-state metadata. The byte
// layout mirrors the field order in ZeroSignalEscrow.TicketRecord (and the
// trailing pendingTtftMs + pendingDecodeMs + pendingInputTokens + pendingOutputTokens that finalize and
// settleLapsed read, the feeBps + discountBps open-time fee snapshot, plus the reservedSlots[32] tail).
func TestParseTicketRecord_AllFields(t *testing.T) {
	var payer, opOwner, nodeSigning types.Address
	for i := range payer {
		payer[i] = byte(i + 1)
	}
	for i := range opOwner {
		opOwner[i] = byte(0x20 + i)
	}
	for i := range nodeSigning {
		nodeSigning[i] = byte(0x40 + i)
	}
	var pendingDigest [32]byte
	for i := range pendingDigest {
		pendingDigest[i] = byte(0x80 + i)
	}

	put64 := func(b []byte, v uint64) []byte { return binary.BigEndian.AppendUint64(b, v) }
	put16 := func(b []byte, v uint16) []byte { return binary.BigEndian.AppendUint16(b, v) }

	var data []byte
	data = append(data, payer[:]...)          // 0..32
	data = put64(data, 4242)                  // operatorId  32..40
	data = put64(data, 9)                     // nodeId      40..48
	data = append(data, opOwner[:]...)        // 48..80
	data = append(data, nodeSigning[:]...)    // 80..112
	data = put64(data, 200_000)               // maxPrice                112..120
	data = put64(data, 1_700_000_000)         // openedAt                120..128
	data = put64(data, 1_700_003_600)         // expiresAt               128..136
	data = put64(data, 600)                   // settlementGraceSeconds  136..144
	data = append(data, byte(StatusFrozen))   // status (arc4.Uint8)     144..145
	data = put64(data, 175_000)               // pendingAmount           145..153
	data = append(data, byte(PendingByPayer)) // pendingBy (arc4.Uint8)  153..154
	data = append(data, pendingDigest[:]...)  // pendingDigest       154..186
	data = put64(data, 1234)                  // pendingTtftMs           186..194
	data = put64(data, 5678)                  // pendingDecodeMs         194..202
	data = put64(data, 250)                   // pendingInputCount       202..210
	data = put64(data, 750)                   // pendingOutputCount      210..218
	data = append(data, byte(1))              // pendingOutputUsageType (arc4.Uint8 = Tokens)    218..219
	data = append(data, byte(2))              // pendingAuxOutputUsageType (arc4.Uint8 = Images) 219..220
	data = put64(data, 3)                     // pendingAuxOutputCount   220..228
	data = put16(data, 1000)                  // feeBps (arc4.Uint16)    228..230
	data = put16(data, 2000)                  // discountBps (arc4.Uint16) 230..232
	// reserved padding — recognizable pattern that round-trips through the parser
	reservedPattern := bytes.Repeat([]byte{0xC3}, 32)
	data = append(data, reservedPattern...) // 232..264

	if len(data) != ticketRecordSize {
		t.Fatalf("built box image = %d bytes, want ticketRecordSize %d", len(data), ticketRecordSize)
	}

	rec, err := parseTicketRecord(data)
	if err != nil {
		t.Fatalf("parseTicketRecord: %v", err)
	}

	if rec.PayerAddr != payer.String() {
		t.Errorf("PayerAddr = %q, want %q", rec.PayerAddr, payer.String())
	}
	if rec.OperatorOwnerAddr != opOwner.String() {
		t.Errorf("OperatorOwnerAddr = %q, want %q", rec.OperatorOwnerAddr, opOwner.String())
	}
	if rec.NodeSigningAddr != nodeSigning.String() {
		t.Errorf("NodeSigningAddr = %q, want %q", rec.NodeSigningAddr, nodeSigning.String())
	}
	if rec.PendingDigest != pendingDigest {
		t.Errorf("PendingDigest mismatch")
	}

	checks := []struct {
		name string
		got  uint64
		want uint64
	}{
		{"OperatorID", rec.OperatorID, 4242},
		{"NodeID", rec.NodeID, 9},
		{"MaxPrice", rec.MaxPrice, 200_000},
		{"OpenedAt", rec.OpenedAt, 1_700_000_000},
		{"ExpiresAt", rec.ExpiresAt, 1_700_003_600},
		{"SettlementGraceSeconds", rec.SettlementGraceSeconds, 600},
		{"Status", rec.Status, StatusFrozen},
		{"PendingAmount", rec.PendingAmount, 175_000},
		{"PendingBy", rec.PendingBy, PendingByPayer},
		{"PendingTtftMs", rec.PendingTtftMs, 1234},
		{"PendingDecodeMs", rec.PendingDecodeMs, 5678},
		{"PendingInputCount", rec.PendingInputCount, 250},
		{"PendingOutputCount", rec.PendingOutputCount, 750},
		{"PendingOutputUsageType", rec.PendingOutputUsageType, 1},
		{"PendingAuxOutputUsageType", rec.PendingAuxOutputUsageType, 2},
		{"PendingAuxOutputCount", rec.PendingAuxOutputCount, 3},
		{"FeeBps", rec.FeeBps, 1000},
		{"DiscountBps", rec.DiscountBps, 2000},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}

	if !bytes.Equal(rec.ReservedSlots[:], reservedPattern) {
		t.Errorf("ReservedSlots = %x, want %x", rec.ReservedSlots, reservedPattern)
	}
}

// TestParseTicketRecord_ShortInput guards against the silent-truncation
// regression: prior to wiring the pending-processing-time / pending-tokens
// / reserved-slots trailers, a 192-byte input parsed cleanly and the
// trailing 48 bytes of any longer real box vanished. The size check must
// now reject anything shorter than the full ticketRecordSize.
func TestParseTicketRecord_ShortInput(t *testing.T) {
	short := make([]byte, ticketRecordSize-1)
	if _, err := parseTicketRecord(short); err == nil {
		t.Fatal("parseTicketRecord(short) returned nil error; want size-check failure")
	}
}
