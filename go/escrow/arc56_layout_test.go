/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

// The positional parsers decode boxes by hand-written offset, and every other
// fixture in this package (and the escrow vectors TS replays) is built from
// those same offsets, so a parser and its fixtures can agree with each other
// and still disagree with the contract. The size pin cannot see it either: a
// carve keeps the total constant by construction.
//
// The embedded ARC-56 is the one input here the compiler wrote. This test
// lays each record out from its structs block, fills a box with
// non-repeating bytes, and requires every field the parser returns to equal
// what the ARC-56 says sits at that field's offset. A carve in the contract
// that the parser misses fails here: as a field with no accessor below, or as
// a value read from the wrong bytes.

type arc56Field struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

type layoutField struct {
	name, typ   string
	off, width  int
	elemWidth   int // array element width; 0 for a scalar
	elemPrimary string
}

// abiStaticWidth is the encoded width of a fixed-size ARC-4 type. A box record
// has no dynamic fields, so anything else fails the test rather than being
// skipped.
func abiStaticWidth(t string) (int, error) {
	if i := strings.IndexByte(t, '['); i >= 0 && strings.HasSuffix(t, "]") {
		n, err := strconv.Atoi(t[i+1 : len(t)-1])
		if err != nil {
			return 0, fmt.Errorf("array length in %q: %w", t, err)
		}
		w, err := abiStaticWidth(t[:i])
		if err != nil {
			return 0, err
		}
		return w * n, nil
	}
	switch t {
	case "address":
		return 32, nil
	case "byte", "uint8":
		return 1, nil
	case "uint16":
		return 2, nil
	case "uint64":
		return 8, nil
	}
	return 0, fmt.Errorf("unhandled ABI type %q", t)
}

func arc56Layout(t *testing.T, record string) ([]layoutField, int) {
	t.Helper()
	var raw struct {
		Structs map[string][]arc56Field `json:"structs"`
	}
	if err := json.Unmarshal(ZeroSignalEscrowARC56, &raw); err != nil {
		t.Fatalf("parse embedded ARC-56: %v", err)
	}
	fields, ok := raw.Structs[record]
	if !ok || len(fields) == 0 {
		t.Fatalf("%s missing from the embedded ARC-56 structs", record)
	}
	var out []layoutField
	off := 0
	for _, f := range fields {
		w, err := abiStaticWidth(f.Type)
		if err != nil {
			t.Fatalf("%s.%s: %v", record, f.Name, err)
		}
		lf := layoutField{name: f.Name, typ: f.Type, off: off, width: w}
		if i := strings.IndexByte(f.Type, '['); i >= 0 {
			lf.elemPrimary = f.Type[:i]
			lf.elemWidth, _ = abiStaticWidth(lf.elemPrimary)
		}
		out = append(out, lf)
		off += w
	}
	return out, off
}

// arc56Value decodes field f out of box the way its ARC-56 type says to, in
// the Go shapes the parsers return: uint64 for every unsigned int, the address
// string, []uint64 for a uint array, and []byte for a byte array.
func arc56Value(t *testing.T, f layoutField, box []byte) any {
	t.Helper()
	b := box[f.off : f.off+f.width]
	be := func(b []byte) uint64 {
		var v uint64
		for _, c := range b {
			v = v<<8 | uint64(c)
		}
		return v
	}
	switch {
	case f.typ == "address":
		var a types.Address
		copy(a[:], b)
		return a.String()
	case f.elemPrimary == "byte":
		return append([]byte(nil), b...)
	case f.elemWidth > 0:
		out := make([]uint64, 0, f.width/f.elemWidth)
		for i := 0; i < f.width; i += f.elemWidth {
			out = append(out, be(b[i:i+f.elemWidth]))
		}
		return out
	case strings.HasPrefix(f.typ, "uint"):
		return be(b)
	}
	t.Fatalf("%s: no decoding for ABI type %q", f.name, f.typ)
	return nil
}

func metricsAccessors[R any](m func(R) *RecordMetrics) map[string]func(R) any {
	return map[string]func(R) any{
		"lastActivityAt":            func(r R) any { return m(r).LastActivityAt },
		"ticketsOpened":             func(r R) any { return m(r).TicketsOpened },
		"ticketsSettled":            func(r R) any { return m(r).TicketsSettled },
		"ticketsLapsedSettled":      func(r R) any { return m(r).TicketsLapsedSettled },
		"ticketsRefundedInactive":   func(r R) any { return m(r).TicketsRefundedInactive },
		"totalRefundedInactiveUsdc": func(r R) any { return m(r).TotalRefundedInactiveUsdc },
		"ticketsProtested":          func(r R) any { return m(r).TicketsProtested },
		"totalProtestedUsdc":        func(r R) any { return m(r).TotalProtestedUsdc },
		"ticketsFrozenDispute":      func(r R) any { return m(r).TicketsFrozenDispute },
		"totalFrozenDisputeUsdc":    func(r R) any { return m(r).TotalFrozenDisputeUsdc },
		"latencyTotalMs":            func(r R) any { return m(r).LatencyTotalMs },
		"latencyEwmaMs":             func(r R) any { return m(r).LatencyEwmaMs },
		"totalRevenueGross":         func(r R) any { return m(r).TotalRevenueGross },
		"bucketsLastDay":            func(r R) any { return m(r).BucketsLastDay },
		"revenueBuckets":            func(r R) any { return m(r).RevenueBuckets[:] },
		"totalInputTokens":          func(r R) any { return m(r).TotalInputTokens },
		"outputUnits":               func(r R) any { return m(r).OutputUnits[:] },
		"tokensPerSecEwma":          func(r R) any { return m(r).TokensPerSecEwma },
	}
}

// checkLayout compares every ARC-56 field of box against the parser's value,
// and requires the accessor table to name exactly the ARC-56's fields.
func checkLayout[R any](t *testing.T, record string, layout []layoutField, box []byte, rec R, get map[string]func(R) any) {
	t.Helper()
	seen := make(map[string]bool, len(layout))
	for _, f := range layout {
		seen[f.name] = true
		acc, ok := get[f.name]
		if !ok {
			t.Errorf("%s.%s (byte %d, %s) is in the contract but the parser has no field for it — mirror the carve",
				record, f.name, f.off, f.typ)
			continue
		}
		want := arc56Value(t, f, box)
		if got := acc(rec); !reflect.DeepEqual(got, want) {
			t.Errorf("%s.%s: parser read %v, the contract puts %v at byte %d", record, f.name, got, want, f.off)
		}
	}
	for name := range get {
		if !seen[name] {
			t.Errorf("%s.%s: the parser reads it but the contract no longer declares it", record, name)
		}
	}
}

func TestARC56Layout_TicketRecord(t *testing.T) {
	layout, size := arc56Layout(t, "TicketRecord")
	if size != ticketRecordSize {
		t.Fatalf("TicketRecord: ARC-56 encodes %d bytes, parser expects %d", size, ticketRecordSize)
	}
	box := patternBytes(size, 0xa1)
	rec, err := parseTicketRecord(box)
	if err != nil {
		t.Fatal(err)
	}
	checkLayout(t, "TicketRecord", layout, box, rec, map[string]func(*TicketRecord) any{
		"payer":                     func(r *TicketRecord) any { return r.PayerAddr },
		"operatorId":                func(r *TicketRecord) any { return r.OperatorID },
		"nodeId":                    func(r *TicketRecord) any { return r.NodeID },
		"operatorOwner":             func(r *TicketRecord) any { return r.OperatorOwnerAddr },
		"nodeSigning":               func(r *TicketRecord) any { return r.NodeSigningAddr },
		"maxPrice":                  func(r *TicketRecord) any { return r.MaxPrice },
		"openedAt":                  func(r *TicketRecord) any { return r.OpenedAt },
		"expiresAt":                 func(r *TicketRecord) any { return r.ExpiresAt },
		"settlementGraceSeconds":    func(r *TicketRecord) any { return r.SettlementGraceSeconds },
		"status":                    func(r *TicketRecord) any { return r.Status },
		"pendingAmount":             func(r *TicketRecord) any { return r.PendingAmount },
		"pendingBy":                 func(r *TicketRecord) any { return r.PendingBy },
		"pendingDigest":             func(r *TicketRecord) any { return r.PendingDigest[:] },
		"pendingTtftMs":             func(r *TicketRecord) any { return r.PendingTtftMs },
		"pendingDecodeMs":           func(r *TicketRecord) any { return r.PendingDecodeMs },
		"pendingInputCount":         func(r *TicketRecord) any { return r.PendingInputCount },
		"pendingOutputCount":        func(r *TicketRecord) any { return r.PendingOutputCount },
		"pendingOutputUsageType":    func(r *TicketRecord) any { return r.PendingOutputUsageType },
		"pendingAuxOutputUsageType": func(r *TicketRecord) any { return r.PendingAuxOutputUsageType },
		"pendingAuxOutputCount":     func(r *TicketRecord) any { return r.PendingAuxOutputCount },
		"feeBps":                    func(r *TicketRecord) any { return r.FeeBps },
		"discountBps":               func(r *TicketRecord) any { return r.DiscountBps },
		"frozenAt":                  func(r *TicketRecord) any { return r.FrozenAt },
		"freezeOrigin":              func(r *TicketRecord) any { return r.FreezeOrigin },
		"reservedSlots":             func(r *TicketRecord) any { return r.ReservedSlots[:] },
	})
}

func TestARC56Layout_OperatorRecord(t *testing.T) {
	layout, size := arc56Layout(t, "OperatorRecord")
	if size != operatorRecordSize {
		t.Fatalf("OperatorRecord: ARC-56 encodes %d bytes, parser expects %d", size, operatorRecordSize)
	}
	box := patternBytes(size, 0xa2)
	rec, err := parseOperatorRecord(1, box)
	if err != nil {
		t.Fatal(err)
	}
	get := metricsAccessors(func(r *OperatorRecord) *RecordMetrics { return &r.RecordMetrics })
	for name, acc := range map[string]func(*OperatorRecord) any{
		"owner":                func(r *OperatorRecord) any { return r.OwnerAddr },
		"status":               func(r *OperatorRecord) any { return r.Status },
		"nfdAppId":             func(r *OperatorRecord) any { return r.NFDAppID },
		"nextNodeId":           func(r *OperatorRecord) any { return r.NextNodeID },
		"liveNodeCount":        func(r *OperatorRecord) any { return r.LiveNodeCount },
		"usdcEscrowed":         func(r *OperatorRecord) any { return r.UsdcEscrowed },
		"ticketsResolvedAdmin": func(r *OperatorRecord) any { return r.TicketsResolvedAdmin },
		"totalResolvedUsdc":    func(r *OperatorRecord) any { return r.TotalResolvedUsdc },
		"reservedSlots":        func(r *OperatorRecord) any { return r.ReservedSlots[:] },
		"latencySamples":       func(r *OperatorRecord) any { return r.LatencySamples },
	} {
		get[name] = acc
	}
	checkLayout(t, "OperatorRecord", layout, box, rec, get)
}

func TestARC56Layout_NodeRecord(t *testing.T) {
	layout, size := arc56Layout(t, "NodeRecord")
	if size != nodeRecordSize {
		t.Fatalf("NodeRecord: ARC-56 encodes %d bytes, parser expects %d", size, nodeRecordSize)
	}
	box := patternBytes(size, 0xa3)
	// The parser refuses a URL length over the field and trims trailing NULs,
	// so give it a declared length in range and printable bytes to read.
	var lenOff, urlOff int
	for _, f := range layout {
		switch f.name {
		case "baseUrlLen":
			lenOff = f.off
		case "baseUrl":
			urlOff = f.off
		}
	}
	const urlLen = 21
	box[lenOff] = urlLen
	for i := range urlLen {
		box[urlOff+i] = 'a' + byte(i)
	}
	rec, err := parseNodeRecord(1, 1, box)
	if err != nil {
		t.Fatal(err)
	}
	get := metricsAccessors(func(r *NodeRecord) *RecordMetrics { return &r.RecordMetrics })
	for name, acc := range map[string]func(*NodeRecord) any{
		"status":     func(r *NodeRecord) any { return r.Status },
		"signing":    func(r *NodeRecord) any { return r.SigningAddr },
		"baseUrlLen": func(r *NodeRecord) any { return uint64(len(r.BaseURL)) },
		// The parser keeps only the declared prefix of the field, so compare
		// that prefix; the length check above pins where it ends.
		"baseUrl": func(r *NodeRecord) any {
			return append([]byte(r.BaseURL), box[urlOff+len(r.BaseURL):urlOff+BaseURLMax]...)
		},
		"usdcEscrowed":         func(r *NodeRecord) any { return r.UsdcEscrowed },
		"staging":              func(r *NodeRecord) any { return r.Staging },
		"ticketsResolvedAdmin": func(r *NodeRecord) any { return r.TicketsResolvedAdmin },
		"totalResolvedUsdc":    func(r *NodeRecord) any { return r.TotalResolvedUsdc },
		"reservedSlots":        func(r *NodeRecord) any { return r.ReservedSlots[:] },
		"latencySamples":       func(r *NodeRecord) any { return r.LatencySamples },
	} {
		get[name] = acc
	}
	checkLayout(t, "NodeRecord", layout, box, rec, get)
	if rec.BaseURL != "abcdefghijklmnopqrstu" {
		t.Errorf("BaseURL = %q, want the %d declared bytes", rec.BaseURL, urlLen)
	}
}

// The carved fields' offsets as literals, against the ARC-56. The pattern
// comparison above already fails on a wrong offset; this names the byte in the
// failure and pins the layout the SPEC tables describe.
func TestARC56Layout_CarvedOffsets(t *testing.T) {
	for record, want := range map[string]map[string]int{
		"TicketRecord":   {"feeBps": 228, "discountBps": 230, "frozenAt": 232, "freezeOrigin": 240, "reservedSlots": 241},
		"OperatorRecord": {"usdcEscrowed": 489, "ticketsResolvedAdmin": 497, "totalResolvedUsdc": 499, "reservedSlots": 507, "latencySamples": 521},
		"NodeRecord":     {"usdcEscrowed": 714, "staging": 722, "ticketsResolvedAdmin": 723, "totalResolvedUsdc": 725, "reservedSlots": 733, "latencySamples": 747},
	} {
		layout, _ := arc56Layout(t, record)
		got := make(map[string]int, len(layout))
		for _, f := range layout {
			got[f.name] = f.off
		}
		for name, off := range want {
			if g, ok := got[name]; !ok || g != off {
				t.Errorf("%s.%s at byte %d (present=%v), want %d", record, name, g, ok, off)
			}
		}
	}
}
