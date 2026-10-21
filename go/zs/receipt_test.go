/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/sha256"
	"testing"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// TestVerifyReceipt_FreeModel: a free model produces a ticket with
// max_price == 0 and a receipt with amount_charged == 0. VerifyReceipt
// must accept it — the "amount_charged ≤ max_price" check is satisfied
// at 0 ≤ 0, and a valid signature plus a matching body hash are all
// that's left to check. A positive amount against a zero ceiling is
// still a violation.
func TestVerifyReceipt_FreeModel(t *testing.T) {
	signAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signer := rawKeyBytesSigner{addr: signAddr, priv: priv}

	body := []byte(`{"id":"chatcmpl-x","choices":[]}`)
	sum := sha256.Sum256(body)

	rcpt := &ticket.UsageReceipt{
		TicketID:          "AAAAAAAAAAAAAAAAAAAAAA==",
		ActualInputCount:  1234,
		ActualOutputCount: 5678,
		AmountCharged:     0,
		TtftMs:            42,
		DecodeMs:          0,
	}
	rcpt.SetBodyHashBytes(sum)
	if err := rcpt.Sign(context.Background(), signer, signAddr); err != nil {
		t.Fatal(err)
	}

	tkt := &ticket.Ticket{TicketID: rcpt.TicketID, MaxPrice: 0}
	op := Operator{TicketSigningKey: pub}

	if err := VerifyReceipt(ReceiptCheck{Ticket: tkt, Operator: op, Receipt: rcpt, ComputedHash: sum}); err != nil {
		t.Fatalf("VerifyReceipt(free model, amount_charged 0) = %v, want nil", err)
	}

	// Overcharge relative to a zero ceiling is still rejected as an
	// amount violation (protest material), not silently accepted.
	rcpt.AmountCharged = 1
	if err := rcpt.Sign(context.Background(), signer, signAddr); err != nil {
		t.Fatal(err)
	}
	err = VerifyReceipt(ReceiptCheck{Ticket: tkt, Operator: op, Receipt: rcpt, ComputedHash: sum})
	if err == nil {
		t.Fatal("VerifyReceipt: amount_charged 1 > max_price 0 should be rejected")
	}
	if re, ok := AsReceiptError(err); !ok || re.Violation != ReceiptViolationAmount {
		t.Errorf("violation = %v (err %v), want amount", re, err)
	}
}

// With no ticket there is nothing to bind the receipt to, so it is refused
// rather than verified on its signature alone.
func TestVerifyReceipt_NilTicketIsRefused(t *testing.T) {
	_, pub, _, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	err = VerifyReceipt(ReceiptCheck{Operator: Operator{TicketSigningKey: pub}, Receipt: &ticket.UsageReceipt{TicketID: "AAAAAAAAAAAAAAAAAAAAAA=="}})
	if re, ok := AsReceiptError(err); !ok || re.Violation != ReceiptViolationSig {
		t.Errorf("VerifyReceipt(nil ticket) = %v, want a sig violation", err)
	}
}

// TestVerifyReceipt_CachedTokenDiscount: a discounted receipt carries a
// cached_input_count and an amount_charged strictly below the ticket's
// max_price — VerifyReceipt must accept it (the discount only lowers the
// charge). A receipt whose cached_input_count exceeds actual_input_count is a
// self-inconsistent billing tuple and must be rejected (amount violation).
func TestVerifyReceipt_CachedTokenDiscount(t *testing.T) {
	signAddr, pub, priv, err := ticket.GenerateAlgorandKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signer := rawKeyBytesSigner{addr: signAddr, priv: priv}

	body := []byte(`{"id":"chatcmpl-x","choices":[]}`)
	sum := sha256.Sum256(body)

	tkt := &ticket.Ticket{TicketID: "AAAAAAAAAAAAAAAAAAAAAA==", MaxPrice: 210_000}
	op := Operator{TicketSigningKey: pub}

	// Discounted receipt: 800 of 1000 input tokens cache-served, charged
	// well under the ceiling.
	rcpt := &ticket.UsageReceipt{
		TicketID:          "AAAAAAAAAAAAAAAAAAAAAA==",
		ActualInputCount:  1000,
		ActualOutputCount: 500,
		AmountCharged:     120_000,
		CachedInputCount:  800,
	}
	rcpt.SetBodyHashBytes(sum)
	if err := rcpt.Sign(context.Background(), signer, signAddr); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReceipt(ReceiptCheck{Ticket: tkt, Operator: op, Receipt: rcpt, ComputedHash: sum}); err != nil {
		t.Fatalf("VerifyReceipt(discounted receipt) = %v, want nil", err)
	}

	// cached_input_count > actual_input_count → rejected as an amount
	// violation. Re-sign so the signature is valid over the bad tuple (we're
	// testing the shape check, not the sig check).
	rcpt.CachedInputCount = rcpt.ActualInputCount + 1
	if err := rcpt.Sign(context.Background(), signer, signAddr); err != nil {
		t.Fatal(err)
	}
	err = VerifyReceipt(ReceiptCheck{Ticket: tkt, Operator: op, Receipt: rcpt, ComputedHash: sum})
	if err == nil {
		t.Fatal("VerifyReceipt: cached_input_count > actual_input_count should be rejected")
	}
	if re, ok := AsReceiptError(err); !ok || re.Violation != ReceiptViolationAmount {
		t.Errorf("violation = %v (err %v), want amount", re, err)
	}
}
