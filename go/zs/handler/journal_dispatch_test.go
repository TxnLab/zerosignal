/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs"
)

// recordingJournal keeps every Put in order.
type recordingJournal struct {
	mu   sync.Mutex
	puts []zs.TicketRecord
}

func (j *recordingJournal) Put(_ context.Context, rec zs.TicketRecord) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.puts = append(j.puts, rec)
	return nil
}

func (j *recordingJournal) Delete(context.Context, string) error { return nil }

func (j *recordingJournal) List(context.Context, string, zs.Deployment) ([]zs.TicketRecord, error) {
	return nil, nil
}

// A paid turn journals the ticket when the escrow opens, then the values the
// payer co-signs once the receipt verifies, so a restart can re-fire the
// settle with exactly what the node signed.
func TestDispatch_JournalsOpenThenReceipt(t *testing.T) {
	reply := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	var receipt *ticket.UsageReceipt
	const replyDelay = 20 * time.Millisecond
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		onRequest:      func(*http.Request, []byte) { time.Sleep(replyDelay) },
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			receipt = &ticket.UsageReceipt{ActualInputCount: 8, ActualOutputCount: 3, AmountCharged: 321, TtftMs: 40, DecodeMs: 90}
			receipt.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
			return receipt
		},
	})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	journal := &recordingJournal{}
	opts.Journal = journal
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}

	journal.mu.Lock()
	puts := journal.puts
	journal.mu.Unlock()
	if len(puts) != 2 {
		t.Fatalf("journal Puts = %d, want 2 (open, then receipt): %+v", len(puts), puts)
	}
	open, settle := puts[0], puts[1]
	wallet := opts.Wallet.(*fakeWallet)
	if open.Status != zs.TicketOpen || open.Settle != nil {
		t.Errorf("first Put: status %q settle %v, want an open ticket with no settle values", open.Status, open.Settle)
	}
	if open.TicketID == "" || open.TicketID != wallet.lastTID || open.OpenTxID != "TESTTX" ||
		open.EscrowAppID != 1 || open.Deployment != "algorand-localnet-1" || open.Payer != wallet.PayerAddr() || open.Target != zs.RefOf(cfg.ResolvedOperators[0]) ||
		open.MaxPrice == 0 || !open.ExpiresAt.After(open.CreatedAt) || open.ExpiresAt.After(open.CreatedAt.Add(time.Hour)) {
		t.Errorf("open record = %+v", open)
	}
	if settle.Status != zs.TicketSettlePending || settle.Settle == nil {
		t.Fatalf("second Put: status %q settle %v, want settle_pending with values", settle.Status, settle.Settle)
	}
	if settle.TicketID != open.TicketID || settle.OpenTxID != open.OpenTxID || settle.Target != open.Target ||
		settle.MaxPrice != open.MaxPrice || !settle.CreatedAt.Equal(open.CreatedAt) {
		t.Errorf("receipt record changed the open fields: %+v, was %+v", settle, open)
	}
	// The re-settle grace runs from the receipt, not the open.
	if d := settle.UpdatedAt.Sub(open.UpdatedAt); d < replyDelay {
		t.Errorf("receipt UpdatedAt is %v after the open's, want at least the %v reply delay", d, replyDelay)
	}
	want := zs.SettleArgs{
		AmountCharged:      receipt.AmountCharged,
		ReceiptDigest:      ticket.ReceiptSigDigest(receipt),
		TtftMs:             receipt.TtftMs,
		DecodeMs:           receipt.DecodeMs,
		InputTokens:        receipt.ActualInputCount,
		OutputTokens:       receipt.ActualOutputCount,
		OutputUsageType:    receipt.OutputUsageType,
		AuxOutputUsageType: receipt.AuxOutputUsageType,
		AuxOutputCount:     receipt.AuxOutputCount,
	}
	if *settle.Settle != want {
		t.Errorf("settle values = %+v, want %+v", *settle.Settle, want)
	}
}
