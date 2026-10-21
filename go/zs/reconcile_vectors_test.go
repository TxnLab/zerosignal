/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/reconcile_vectors.json: a journaled
// ticket, its box (or none) and the time in, the sweep's action out. Times sit
// on every boundary decideTicket draws: the skew either side of the deadline,
// the lapse fallback, the settle-pending grace and the record's own expiry.
//
//	cd proto/go && go test ./zs -run TestReconcileVectors -update

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const reconcileVectorsPath = "../../testdata/reconcile_vectors.json"

type reconcileVectorSettle struct {
	AmountCharged      uint64 `json:"amount_charged"`
	ReceiptDigest      string `json:"receipt_digest"` // base64, 32 bytes
	TtftMs             uint64 `json:"ttft_ms"`
	DecodeMs           uint64 `json:"decode_ms"`
	InputTokens        uint64 `json:"input_tokens"`
	OutputTokens       uint64 `json:"output_tokens"`
	OutputUsageType    uint64 `json:"output_usage_type"`
	AuxOutputUsageType uint64 `json:"aux_output_usage_type"`
	AuxOutputCount     uint64 `json:"aux_output_count"`
}

type reconcileVectorBox struct {
	Status                    uint64 `json:"status"`
	PendingBy                 uint64 `json:"pending_by"`
	ExpiresAt                 uint64 `json:"expires_at"`
	SettlementGraceSeconds    uint64 `json:"settlement_grace_seconds"`
	PendingAmount             uint64 `json:"pending_amount"`
	PendingDigest             string `json:"pending_digest"` // base64, 32 bytes
	PendingTtftMs             uint64 `json:"pending_ttft_ms"`
	PendingDecodeMs           uint64 `json:"pending_decode_ms"`
	PendingInputCount         uint64 `json:"pending_input_count"`
	PendingOutputCount        uint64 `json:"pending_output_count"`
	PendingOutputUsageType    uint64 `json:"pending_output_usage_type"`
	PendingAuxOutputUsageType uint64 `json:"pending_aux_output_usage_type"`
	PendingAuxOutputCount     uint64 `json:"pending_aux_output_count"`
}

type reconcileVectorCase struct {
	Name string `json:"name"`
	// The journaled record; times are unix milliseconds.
	Status      TicketStatus           `json:"status"`
	ExpiresAtMs int64                  `json:"expires_at_ms"`
	UpdatedAtMs int64                  `json:"updated_at_ms"`
	Settle      *reconcileVectorSettle `json:"settle"`
	// Signed is the receipt that failed a check, absent when none.
	Signed *reconcileVectorSettle `json:"signed,omitempty"`
	// Box is null when the ticket has no box on chain.
	Box             *reconcileVectorBox `json:"box"`
	NowMs           int64               `json:"now_ms"`
	LapseFallbackMs int64               `json:"lapse_fallback_ms"`

	Action string `json:"action"`
}

const (
	rvExpiresAt = 1_700_000_000
	rvGrace     = 300
	rvLapse     = defaultLapseFallback
)

func rvDigest() [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = byte(i + 1)
	}
	return d
}

func rvSettle() reconcileVectorSettle {
	d := rvDigest()
	return reconcileVectorSettle{
		AmountCharged: 2600, ReceiptDigest: base64.StdEncoding.EncodeToString(d[:]),
		TtftMs: 120, DecodeMs: 900, InputTokens: 42, OutputTokens: 17,
		OutputUsageType: uint64(ticket.UsageTypeTokens), AuxOutputUsageType: uint64(ticket.UsageTypeImages), AuxOutputCount: 3,
	}
}

// rvBox is a box whose pending half carries exactly rvSettle's values.
func rvBox(status, pendingBy uint64) reconcileVectorBox {
	s := rvSettle()
	return reconcileVectorBox{
		Status: status, PendingBy: pendingBy, ExpiresAt: rvExpiresAt, SettlementGraceSeconds: rvGrace,
		PendingAmount: s.AmountCharged, PendingDigest: s.ReceiptDigest,
		PendingTtftMs: s.TtftMs, PendingDecodeMs: s.DecodeMs,
		PendingInputCount: s.InputTokens, PendingOutputCount: s.OutputTokens,
		PendingOutputUsageType: s.OutputUsageType, PendingAuxOutputUsageType: s.AuxOutputUsageType,
		PendingAuxOutputCount: s.AuxOutputCount,
	}
}

func reconcileVectorInputs() []reconcileVectorCase {
	deadlineMs := int64(rvExpiresAt+rvGrace) * 1000
	skew, lapse := reconcileSkew.Milliseconds(), rvLapse.Milliseconds()
	grace := settlePendingGrace.Milliseconds()

	boxes := []struct {
		name string
		box  reconcileVectorBox
	}{
		{"open", rvBox(escrow.StatusOpen, 0)},
		{"pending_payer", rvBox(escrow.StatusPendingSettle, escrow.PendingByPayer)},
		{"pending_operator", rvBox(escrow.StatusPendingSettle, escrow.PendingByOperator)},
		{"frozen", rvBox(escrow.StatusFrozen, escrow.PendingByOperator)},
		{"pending_no_side", rvBox(escrow.StatusPendingSettle, 0)},
		{"settled_status", rvBox(escrow.StatusSettled, 0)},
	}
	// On and one past each boundary decideTicket draws (each is strict): the
	// resettle cut-off (D - skew), the classify cut-off (D + skew) and the
	// lapse fallback (D + lapse); D itself for reference.
	offsets := []int64{-skew - 1, -skew, -skew + 1, 0, skew, skew + 1, lapse, lapse + 1}
	type record struct {
		name   string
		status TicketStatus
		settle bool
		ageMs  int64
		signed bool
	}
	records := []record{
		{"open", TicketOpen, false, grace, false},
		{"settle_pending", TicketSettlePending, true, grace, false},
		{"settle_pending_young", TicketSettlePending, true, grace - 1, false},
		{"settle_pending_no_args", TicketSettlePending, false, grace, false},
		// Receipt values on a row not yet marked settle_pending: the status,
		// not the values, decides a re-fire.
		{"open_with_args", TicketOpen, true, grace, false},
		// A receipt that failed a check: held against a claim, never re-fired.
		{"open_signed", TicketOpen, false, grace, true},
	}
	mk := func(name string, r record, box *reconcileVectorBox, now int64) reconcileVectorCase {
		c := reconcileVectorCase{
			Name: name, Status: r.status, ExpiresAtMs: rvExpiresAt * 1000, UpdatedAtMs: now - r.ageMs,
			Box: box, NowMs: now, LapseFallbackMs: lapse,
		}
		if r.settle {
			s := rvSettle()
			c.Settle = &s
		}
		if r.signed {
			s := rvSettle()
			c.Signed = &s
		}
		return c
	}

	var cases []reconcileVectorCase
	for _, b := range boxes {
		for _, off := range offsets {
			for _, r := range records {
				box := b.box
				cases = append(cases, mk(fmt.Sprintf("%s/%s at D%+dms", b.name, r.name, off), r, &box, deadlineMs+off))
			}
		}
	}

	// An operator claim inside the window that differs from the receipt in
	// one co-signed value: re-firing it would freeze the ticket.
	mismatches := []struct {
		field string
		edit  func(*reconcileVectorBox)
	}{
		{"amount", func(b *reconcileVectorBox) { b.PendingAmount++ }},
		{"digest", func(b *reconcileVectorBox) {
			d := rvDigest()
			d[31] ^= 1
			b.PendingDigest = base64.StdEncoding.EncodeToString(d[:])
		}},
		{"ttft_ms", func(b *reconcileVectorBox) { b.PendingTtftMs++ }},
		{"decode_ms", func(b *reconcileVectorBox) { b.PendingDecodeMs++ }},
		{"input_count", func(b *reconcileVectorBox) { b.PendingInputCount++ }},
		{"output_count", func(b *reconcileVectorBox) { b.PendingOutputCount++ }},
		{"output_usage_type", func(b *reconcileVectorBox) { b.PendingOutputUsageType++ }},
		{"aux_output_usage_type", func(b *reconcileVectorBox) { b.PendingAuxOutputUsageType++ }},
		{"aux_output_count", func(b *reconcileVectorBox) { b.PendingAuxOutputCount++ }},
	}
	for _, m := range mismatches {
		box := rvBox(escrow.StatusPendingSettle, escrow.PendingByOperator)
		m.edit(&box)
		cases = append(cases, mk("pending_operator/claim_differs_in_"+m.field, records[1], &box, deadlineMs-skew-1))
	}

	// An operator claim against the receipt's amount, across every boundary.
	// One above it is frozen inside the window, ahead of the settle-pending
	// grace, and never lapsed by the payer after it; one below it, or level
	// with it on another digest, is left alone inside the window and lapsed
	// like any other claim after it.
	otherDigest := func(b *reconcileVectorBox) {
		d := rvDigest()
		d[0] ^= 0xff
		b.PendingDigest = base64.StdEncoding.EncodeToString(d[:])
	}
	claims := []struct {
		name string
		edit func(*reconcileVectorBox)
	}{
		{"claim_above_receipt", func(b *reconcileVectorBox) { b.PendingAmount += 1000; otherDigest(b) }},
		{"claim_below_receipt", func(b *reconcileVectorBox) { b.PendingAmount -= 1000; otherDigest(b) }},
		{"claim_level_other_digest", otherDigest},
	}
	for _, cl := range claims {
		for _, off := range offsets {
			for _, r := range records {
				box := rvBox(escrow.StatusPendingSettle, escrow.PendingByOperator)
				cl.edit(&box)
				cases = append(cases, mk(fmt.Sprintf("pending_operator/%s/%s at D%+dms", cl.name, r.name, off), r, &box, deadlineMs+off))
			}
		}
	}

	// Other lapse fallbacks: one below the skew, where the classify cut-off
	// decides instead, and one longer than the default.
	for _, lf := range []int64{10_000, 30 * 60_000} {
		for _, off := range []int64{skew, skew + 1, lf, lf + 1} {
			box := rvBox(escrow.StatusPendingSettle, escrow.PendingByOperator)
			c := mk(fmt.Sprintf("pending_operator/settle_pending lapse %dms at D%+dms", lf, off), records[1], &box, deadlineMs+off)
			c.LapseFallbackMs = lf
			cases = append(cases, c)
		}
	}

	// No box: the open may still land until the record's own expiry.
	expiryMs := int64(rvExpiresAt) * 1000
	for _, off := range []int64{-1, skew, skew + 1} {
		for _, r := range records[:2] {
			cases = append(cases, mk(fmt.Sprintf("no_box/%s at expiry%+dms", r.name, off), r, nil, expiryMs+off))
		}
	}
	return cases
}

func runReconcileVector(t *testing.T, c reconcileVectorCase) string {
	t.Helper()
	rec, box := reconcileVectorInputsOf(t, c)
	return decideTicket(rec, box, time.UnixMilli(c.NowMs), time.Duration(c.LapseFallbackMs)*time.Millisecond).String()
}

// reconcileVectorInputsOf decodes a case into the record and box (nil when
// none) it describes.
func reconcileVectorInputsOf(t *testing.T, c reconcileVectorCase) (TicketRecord, *escrow.TicketRecord) {
	t.Helper()
	rec := TicketRecord{
		Status:    c.Status,
		ExpiresAt: time.UnixMilli(c.ExpiresAtMs),
		UpdatedAt: time.UnixMilli(c.UpdatedAtMs),
	}
	rec.Settle, rec.Signed = rvArgs(t, c.Settle), rvArgs(t, c.Signed)
	var box *escrow.TicketRecord
	if b := c.Box; b != nil {
		box = &escrow.TicketRecord{
			Status: b.Status, PendingBy: b.PendingBy, ExpiresAt: b.ExpiresAt, SettlementGraceSeconds: b.SettlementGraceSeconds,
			PendingAmount: b.PendingAmount, PendingDigest: rvDecode32(t, b.PendingDigest),
			PendingTtftMs: b.PendingTtftMs, PendingDecodeMs: b.PendingDecodeMs,
			PendingInputCount: b.PendingInputCount, PendingOutputCount: b.PendingOutputCount,
			PendingOutputUsageType: b.PendingOutputUsageType, PendingAuxOutputUsageType: b.PendingAuxOutputUsageType,
			PendingAuxOutputCount: b.PendingAuxOutputCount,
		}
	}
	return rec, box
}

func rvArgs(t *testing.T, s *reconcileVectorSettle) *SettleArgs {
	t.Helper()
	if s == nil {
		return nil
	}
	return &SettleArgs{
		AmountCharged: s.AmountCharged, ReceiptDigest: rvDecode32(t, s.ReceiptDigest),
		TtftMs: s.TtftMs, DecodeMs: s.DecodeMs, InputTokens: s.InputTokens, OutputTokens: s.OutputTokens,
		OutputUsageType: ticket.UsageType(s.OutputUsageType), AuxOutputUsageType: ticket.UsageType(s.AuxOutputUsageType),
		AuxOutputCount: s.AuxOutputCount,
	}
}

func rvDecode32(t *testing.T, s string) [32]byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("digest %q: %v (len %d)", s, err, len(b))
	}
	return [32]byte(b)
}

func TestReconcileVectors(t *testing.T) {
	cases := reconcileVectorInputs()
	for i := range cases {
		cases[i].Action = runReconcileVector(t, cases[i])
	}
	out, err := json.MarshalIndent(cases, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(reconcileVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(reconcileVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("decideTicket differs from %s; if the change is intended, regenerate with -update and review the diff", reconcileVectorsPath)
	}
}

// Every action decideTicket can return appears in the fixture, so a port that
// never returns one is caught.
func TestReconcileVectorsCoverEveryAction(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range reconcileVectorInputs() {
		seen[runReconcileVector(t, c)] = true
	}
	for a := reconcileWait; a <= reconcileFreeze; a++ {
		if !seen[a.String()] {
			t.Errorf("no vector yields %s", a)
		}
	}
}
