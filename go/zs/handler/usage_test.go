/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
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

// TestReceiptUsageFrame_FeeBreakdown checks the breakdown rides the zs.usage
// SSE frame when readable and is wholly absent (no `fee` key) when not.
func TestReceiptUsageFrame_FeeBreakdown(t *testing.T) {
	r := &ticket.UsageReceipt{TicketID: "tid", AmountCharged: 1_000_000}
	tk := &ticket.Ticket{MaxPrice: 1_100_000}
	op := zs.Operator{ID: 7}

	fr := receiptUsageFrame(r, tk, op, 0, 0, 0, 1000, 0, true)
	var u usageBody
	if err := json.Unmarshal(fr.Data, &u); err != nil {
		t.Fatalf("unmarshal frame: %v", err)
	}
	if u.Fee == nil {
		t.Fatal("expected fee breakdown in frame")
	}
	if u.Fee.PlatformFeeMicrousdc != 100_000 || u.Fee.TotalDebitMicrousdc != 1_100_000 {
		t.Errorf("frame fee = %+v", u.Fee)
	}

	fr2 := receiptUsageFrame(r, tk, op, 0, 0, 0, 0, 0, false)
	if strings.Contains(string(fr2.Data), `"fee"`) {
		t.Errorf("fee key present when snapshot absent: %s", fr2.Data)
	}
}

// The usage event carries what the frame reports: the receipt's ticket, the
// open-time ticket's ceiling, and the fee snapshot.
func TestUsageFrame_FromReceiptVerified(t *testing.T) {
	fr := usageFrame(zs.ReceiptVerified{
		Receipt:     ticket.UsageReceipt{TicketID: "tid", AmountCharged: 1_000_000},
		Ticket:      ticket.Ticket{MaxPrice: 1_100_000},
		Target:      zs.NodeRef{Op: 7, Node: 2},
		FeeBps:      1000,
		FeeBpsKnown: true,
	})
	if fr.Event != usageFrameEvent {
		t.Errorf("event = %q, want %q", fr.Event, usageFrameEvent)
	}
	var u usageBody
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
	setUsageHeaders(h, zs.ReceiptVerified{
		Receipt:   ticket.UsageReceipt{TicketID: "tid"},
		Target:    zs.NodeRef{Op: 7, Node: 2},
		OwnerAddr: "OWNER",
	})
	if h.Get("X-Zs-Operator-Id") != "7" || h.Get("X-Zs-Node-Id") != "2" {
		t.Errorf("headers name operator %q node %q, want 7/2", h.Get("X-Zs-Operator-Id"), h.Get("X-Zs-Node-Id"))
	}
}

// A browser reads a response header only when CORS exposes it by name, so a
// usage header left off the list is invisible to every browser caller.
func TestCORSExposesEveryUsageHeader(t *testing.T) {
	h := http.Header{}
	// Every branch on: a charge, an ALGO rate and a readable fee rate.
	setReceiptUsageHeaders(h,
		&ticket.UsageReceipt{TicketID: "tid", AmountCharged: 1_000},
		&ticket.Ticket{MaxPrice: 2_000},
		zs.Operator{ID: 7, NodeID: 2, OwnerAddr: "OWNER"},
		1_000, 0, 0.25, 1000, 0, true)
	w := httptest.NewRecorder()
	writeCORSHeaders(w, httptest.NewRequest(http.MethodOptions, "/v1/chat/completions", nil))
	exposed := map[string]bool{}
	for name := range strings.SplitSeq(w.Header().Get("Access-Control-Expose-Headers"), ",") {
		exposed[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
	}
	for name := range h {
		if !exposed[name] {
			t.Errorf("Access-Control-Expose-Headers omits %s", name)
		}
	}
	if len(h) < 21 {
		t.Fatalf("only %d usage headers set; the fixture no longer reaches every branch", len(h))
	}
}
