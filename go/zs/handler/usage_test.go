/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// TestFeeBreakdownFor pins the additive-fee decomposition the proxy derives
// from the open-time snapshot, and the absent-vs-zero distinction.
func TestFeeBreakdownFor(t *testing.T) {
	if got := feeBreakdownFor(1_000_000, 1_100_000, 1000, 0, false, "USDC", 6); got != nil {
		t.Fatalf("haveFee=false should yield nil breakdown, got %+v", got)
	}
	fb := feeBreakdownFor(1_000_000, 1_100_000, 1000, 0, true, "USDC", 6)
	if fb == nil {
		t.Fatal("haveFee=true yielded nil breakdown")
	}
	if fb.FeeBps != 1000 || fb.DiscountBps != 0 {
		t.Errorf("rate = %d/%d, want 1000/0", fb.FeeBps, fb.DiscountBps)
	}
	if fb.PlatformFeeMicrousdc != 100_000 || fb.RefundMicrousdc != 0 || fb.TotalDebitMicrousdc != 1_100_000 {
		t.Errorf("breakdown = %+v", fb)
	}
	if fb.TotalDebitUsd < 1.0999 || fb.TotalDebitUsd > 1.1001 {
		t.Errorf("total_debit_usd = %v, want ~1.10", fb.TotalDebitUsd)
	}

	// A genuine 0 platform fee (feeBps=0) is still a present breakdown — that's
	// why the object is nested, not omitempty top-level fields.
	zero := feeBreakdownFor(200_000, 500_000, 0, 0, true, "USDC", 6)
	if zero == nil || zero.PlatformFeeMicrousdc != 0 || zero.RefundMicrousdc != 300_000 {
		t.Errorf("zero-fee breakdown = %+v", zero)
	}
}

// TestHayaiUsageFrame_FeeBreakdown checks the breakdown rides the zs.usage
// SSE frame when readable and is wholly absent (no `fee` key) when not.
func TestHayaiUsageFrame_FeeBreakdown(t *testing.T) {
	r := &ticket.UsageReceipt{TicketID: "tid", AmountCharged: 1_000_000}
	tk := &ticket.Ticket{MaxPrice: 1_100_000}
	op := hayai.Operator{ID: 7}

	fr := hayaiUsageFrame(r, tk, op, 0, 0, 0, 1000, 0, true)
	var u hayaiUsage
	if err := json.Unmarshal(fr.Data, &u); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if u.Fee == nil {
		t.Fatal("expected fee breakdown in frame")
	}
	if u.Fee.PlatformFeeMicrousdc != 100_000 || u.Fee.TotalDebitMicrousdc != 1_100_000 {
		t.Errorf("frame fee = %+v", u.Fee)
	}

	fr2 := hayaiUsageFrame(r, tk, op, 0, 0, 0, 0, 0, false)
	if strings.Contains(string(fr2.Data), `"fee"`) {
		t.Errorf("fee key present when snapshot absent: %s", fr2.Data)
	}
}

// The usage event carries what the frame reports: the receipt's ticket, the
// open-time ticket's ceiling, and the fee snapshot.
func TestUsageFrame_FromReceiptVerified(t *testing.T) {
	fr := usageFrame(hayai.ReceiptVerified{
		Receipt:     ticket.UsageReceipt{TicketID: "tid", AmountCharged: 1_000_000},
		Ticket:      ticket.Ticket{MaxPrice: 1_100_000},
		Target:      hayai.NodeRef{Op: 7, Node: 2},
		FeeBps:      1000,
		FeeBpsKnown: true,
	})
	if fr.Event != hayaiUsageFrameEvent {
		t.Errorf("event = %q, want %q", fr.Event, hayaiUsageFrameEvent)
	}
	var u hayaiUsage
	if err := json.Unmarshal(fr.Data, &u); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if u.Fee == nil || u.Fee.TotalDebitMicrousdc != 1_100_000 {
		t.Errorf("frame fee = %+v, want the snapshot's breakdown", u.Fee)
	}
	if !strings.Contains(string(fr.Data), `"tid"`) {
		t.Errorf("frame %s, want the receipt's ticket id", fr.Data)
	}
	if u.OperatorID != 7 || u.NodeID != 2 {
		t.Errorf("frame names operator %d node %d, want 7/2", u.OperatorID, u.NodeID)
	}
}

// The usage headers name the serving node, not just its operator.
func TestSetUsageHeaders_NamesTheNode(t *testing.T) {
	h := http.Header{}
	setUsageHeaders(h, hayai.ReceiptVerified{
		Receipt:   ticket.UsageReceipt{TicketID: "tid"},
		Target:    hayai.NodeRef{Op: 7, Node: 2},
		OwnerAddr: "OWNER",
	})
	if h.Get("X-Zs-Operator-Id") != "7" || h.Get("X-Zs-Node-Id") != "2" {
		t.Errorf("headers name operator %q node %q, want 7/2", h.Get("X-Zs-Operator-Id"), h.Get("X-Zs-Node-Id"))
	}
}
