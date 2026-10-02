/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// fakeSpendGuard is a SpendGuard for dispatch tests: reserveErr forces a cap
// trip, reserved captures each Reserve amount, released captures the amounts
// backed out (a failed open, or a receipt that didn't verify), and settled
// captures each Settle so a test can assert the actual charge was recorded.
//
// It mirrors the real guard's exactly-once semantics — reservations keyed by
// ticket id, Settle/Release resolving the amount from the reservation and
// dropping it, later calls for the same ticket no-ops, and a duplicate ticket id
// REFUSED with hayai.ErrDuplicateTicket — so the "must NOT Release" / "must NOT
// Settle" assertions below measure what the dispatch path actually decided rather
// than how many times it happened to call through.
type fakeSpendGuard struct {
	reserveErr error
	reserved   []uint64
	released   []uint64
	settled    []settleCall

	open map[string]uint64
}

type settleCall struct{ maxPrice, spent uint64 }

func (f *fakeSpendGuard) Reserve(ticketID string, amt uint64) error {
	if f.reserveErr != nil {
		return f.reserveErr
	}
	if f.open == nil {
		f.open = make(map[string]uint64)
	}
	if _, dup := f.open[ticketID]; dup {
		// The real guard REFUSES a duplicate (wrapping hayai.ErrDuplicateTicket)
		// rather than accepting it, and the dispatch path maps that sentinel to a
		// distinct 502. Returning nil here would let a regression that reused a
		// ticket id pass unnoticed at this level.
		return fmt.Errorf("%w: %q (fake)", hayai.ErrDuplicateTicket, ticketID)
	}
	f.open[ticketID] = amt
	f.reserved = append(f.reserved, amt)
	return nil
}

func (f *fakeSpendGuard) Settle(ticketID string, spent uint64) {
	maxPrice, ok := f.open[ticketID]
	if !ok {
		return
	}
	delete(f.open, ticketID)
	f.settled = append(f.settled, settleCall{maxPrice, spent})
}

func (f *fakeSpendGuard) Release(ticketID string) {
	amt, ok := f.open[ticketID]
	if !ok {
		return
	}
	delete(f.open, ticketID)
	f.released = append(f.released, amt)
}

// TestDispatchHayai_WalletUnfunded_402 asserts an underfunded open surfaces an
// actionable 402 wallet_unfunded rather than a generic 502.
func TestDispatchHayai_WalletUnfunded_402(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	opts.Wallet = &fakeWallet{err: errors.New("wallet: submit presigned open group: overspend (account XYZ)")}
	guard := &fakeSpendGuard{}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d body=%s; want 402", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"wallet_unfunded"`) {
		t.Errorf("body missing wallet_unfunded code: %s", w.Body.String())
	}
	// The reservation made before the (failed) open must be released so a
	// failed attempt doesn't permanently consume the cap.
	if len(guard.reserved) != 1 || len(guard.released) != 1 {
		t.Errorf("reserved=%v released=%v; want one reserve backed out by one release", guard.reserved, guard.released)
	}
}

// The web app is built for one network, so the 402 may point a payer at it only
// on mainnet; anywhere else it would fund the same address on the wrong chain.
func TestDispatchHayai_WalletUnfunded_402_FundingHintByNetwork(t *testing.T) {
	const fundingURL = "https://app.example.test"
	for _, tc := range []struct {
		network    string
		fundingURL string
		wantWebApp bool
	}{
		{"mainnet", fundingURL, true},
		{"testnet", fundingURL, false},
		{"", fundingURL, false},
		// No URL to name: an empty "web app ()" hint is worse than none.
		{"mainnet", "", false},
	} {
		t.Run("network="+tc.network+"/url="+tc.fundingURL, func(t *testing.T) {
			node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
			cfg := testConfig()
			cfg.Network = tc.network
			cfg.FundingURL = tc.fundingURL
			opts := setupHayai(t, cfg, node)
			opts.Wallet = &fakeWallet{payer: "PAYERADDR", err: errors.New("wallet: submit presigned open group: overspend (account XYZ)")}
			opts.SpendGuard = &fakeSpendGuard{}
			s := testServer(cfg, opts)

			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

			body := w.Body.String()
			if w.Result().StatusCode != http.StatusPaymentRequired || !strings.Contains(body, `"wallet_unfunded"`) {
				t.Fatalf("status = %d body=%s; want 402 wallet_unfunded", w.Result().StatusCode, body)
			}
			// The deposit address is the actionable part; swapped with the
			// network it would point the payer at a non-address.
			if want := "wallet PAYERADDR can't pay for this request on " + tc.network + " "; !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
			if got := strings.Contains(body, "web app"); got != tc.wantWebApp {
				t.Errorf("body offers the web app = %v, want %v:\n%s", got, tc.wantWebApp, body)
			}
			if tc.wantWebApp && !strings.Contains(body, tc.fundingURL) {
				t.Errorf("body offers the web app without naming %s:\n%s", tc.fundingURL, body)
			}
			if !strings.Contains(body, "zs-proxy fund") {
				t.Errorf("body doesn't name `zs-proxy fund`:\n%s", body)
			}
		})
	}
}

// TestDispatchHayai_MbrPoolUnderfunded_402 asserts that an open failing because
// the payer can't fund the prepaid ticket-MBR pool (ALGO shortfall, holds USDC)
// surfaces the distinct, actionable mbr_pool_underfunded code with the µALGO
// detail — NOT the generic wallet_unfunded (which reads as a USDC/onboarding
// problem and hides the real "add ALGO" cause).
func TestDispatchHayai_MbrPoolUnderfunded_402(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	// The wallet wraps ErrDepositUnaffordable the way ensureDepositForServe does;
	// errors.Is must still see the sentinel through the wrap.
	opts.Wallet = &fakeWallet{err: fmt.Errorf("wallet: ensure MBR deposit: %w: need 577000 µALGO (575000 shortfall + 2000 fee), have 489000 µALGO spendable — fund the wallet with more ALGO", hayai.ErrDepositUnaffordable)}
	opts.SpendGuard = &fakeSpendGuard{}
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d body=%s; want 402", w.Result().StatusCode, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"mbr_pool_underfunded"`) {
		t.Errorf("body missing mbr_pool_underfunded code: %s", body)
	}
	if strings.Contains(body, `"wallet_unfunded"`) {
		t.Errorf("body should NOT use the generic wallet_unfunded code: %s", body)
	}
	// The actionable µALGO detail from the sentinel must reach the caller.
	if !strings.Contains(body, "spendable") || !strings.Contains(body, "ALGO") {
		t.Errorf("body missing the actionable ALGO shortfall detail: %s", body)
	}
}

// TestDispatchHayai_MbrPoolExhausted_429 is the other half: the wallet HOLDS
// the ALGO, every prepaid slot is just reserved by an in-flight ticket, so
// open() reverts on a pool guard. That is a transient concurrency cap with a
// knob attached, not an unfunded wallet — 429 + Retry-After, never a 402 "fund
// me" or an opaque 502.
//
// The wallet's error is the real *escrow.ApprovalError shape, wrapped the way
// Wallet.Open wraps it, because the whole classification now rests on the type
// surviving that wrap. algod puts only "assert failed pc=NNN" on the wire, so
// there is no text to fall back on if the type is lost.
func TestDispatchHayai_MbrPoolExhausted_429(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	opts.Wallet = &fakeWallet{err: fmt.Errorf("wallet: submit presigned open group: %w", &escrow.ApprovalError{
		Method:  "open",
		PC:      3255,
		Message: escrow.AssertInsufficientMbrDeposit,
		Err:     errors.New("logic eval error: assert failed pc=3255"),
	})}
	opts.SpendGuard = &fakeSpendGuard{}
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d body=%s; want 429", w.Result().StatusCode, w.Body.String())
	}
	if got := w.Header().Get("Retry-After"); got != "2" {
		t.Errorf("Retry-After = %q, want 2 — the condition self-heals, so the nudge is honest", got)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"mbr_pool_exhausted"`) {
		t.Errorf("body missing mbr_pool_exhausted code: %s", body)
	}
	if !strings.Contains(body, "zs.concurrent_slots") {
		t.Errorf("body must name the knob that fixes it: %s", body)
	}
}

// TestDispatchHayai_SpendCapExceeded_402 asserts the spend guard refuses past
// the cap with a 402 spend_cap_exceeded and never opens the escrow (no money
// committed).
func TestDispatchHayai_SpendCapExceeded_402(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	fw := &fakeWallet{
		appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000",
	}
	opts.Wallet = fw
	opts.SpendGuard = &fakeSpendGuard{reserveErr: errors.New("daily spend cap exceeded")}
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d body=%s; want 402", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"spend_cap_exceeded"`) {
		t.Errorf("body missing spend_cap_exceeded code: %s", w.Body.String())
	}
	if fw.openCalls != 0 {
		t.Errorf("wallet.Open should NOT be called when the spend cap trips, got %d", fw.openCalls)
	}
}

// TestDispatchHayai_DuplicateTicketID_502 asserts the OTHER Reserve failure gets
// its own diagnosis. A reused ticket id is the operator's node handing out an id
// already in flight for this payer — nothing the payer configured and nothing a
// config change can fix — so it must not surface as the 402 spend_cap_exceeded
// that tells them to raise spend.daily_cap_usdc or wait for the UTC day to roll.
// Distinguished by the hayai.ErrDuplicateTicket sentinel, so the two Reserve
// errors can't be conflated by message text.
func TestDispatchHayai_DuplicateTicketID_502(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	fw := &fakeWallet{appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000"}
	opts.Wallet = fw
	opts.SpendGuard = &fakeSpendGuard{
		reserveErr: fmt.Errorf("%w: %q (operator reused a ticket id)", hayai.ErrDuplicateTicket, "tid"),
	}
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s; want 502 (operator fault, not a payer cap trip)", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"operator_ticket_reuse"`) {
		t.Errorf("body missing operator_ticket_reuse code: %s", w.Body.String())
	}
	if strings.Contains(w.Body.String(), "spend_cap") {
		t.Errorf("body blames the spend cap for an operator fault: %s", w.Body.String())
	}
	if fw.openCalls != 0 {
		t.Errorf("wallet.Open should NOT be called when Reserve refuses, got %d", fw.openCalls)
	}
}

// TestDispatchHayai_SpendReservedOnSuccess asserts a committed open reserves the
// ticket's MaxPrice exactly once and never releases it.
func TestDispatchHayai_SpendReservedOnSuccess(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	fw := &fakeWallet{appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000"}
	opts.Wallet = fw
	guard := &fakeSpendGuard{}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want 200", w.Result().StatusCode, w.Body.String())
	}
	if len(guard.reserved) != 1 {
		t.Fatalf("Reserve calls = %d, want 1", len(guard.reserved))
	}
	if len(guard.released) != 0 {
		t.Errorf("a committed open must NOT release its reservation, got releases %v", guard.released)
	}
}

// TestDispatchHayai_SpendSettledOnValidReceipt asserts that when the operator's
// signed receipt verifies, the guard records the *actual* charge (Settle with
// the receipt's AmountCharged) against the reserved MaxPrice ceiling — and does
// not Release. This is the fix for `zs status` showing reserved ceilings
// instead of real spend.
func TestDispatchHayai_SpendSettledOnValidReceipt(t *testing.T) {
	const charged = 8*2 + 3*5 // matches the receipt built below
	reply := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{ActualInputCount: 8, ActualOutputCount: 3, AmountCharged: charged}
			r.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
			return r
		},
	})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	guard := &fakeSpendGuard{}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), reply) {
		t.Errorf("body = %s", w.Body.String())
	}
	if len(guard.reserved) != 1 {
		t.Fatalf("Reserve calls = %d, want 1", len(guard.reserved))
	}
	if len(guard.released) != 0 {
		t.Errorf("a verified receipt must NOT Release; got %v", guard.released)
	}
	if len(guard.settled) != 1 {
		t.Fatalf("Settle calls = %d, want 1", len(guard.settled))
	}
	if got := guard.settled[0]; got.maxPrice != guard.reserved[0] || got.spent != charged {
		t.Errorf("Settle = {maxPrice:%d spent:%d}, want {maxPrice:%d spent:%d}",
			got.maxPrice, got.spent, guard.reserved[0], charged)
	}
}

// TestDispatchHayai_SpendReleasedOnBadReceipt asserts that a receipt which fails
// verification (here a body_hash mismatch) backs the reservation out via
// Release and records no spend — the disputed/failed request must not count
// toward the daily total.
func TestDispatchHayai_SpendReleasedOnBadReceipt(t *testing.T) {
	reply := []byte(`{"choices":[{"message":{"content":"actual"}}]}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(_ []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{ActualInputCount: 8, ActualOutputCount: 3, AmountCharged: 100}
			r.SetBodyHashBytes(wire.BodyHashOfBody([]byte("different bytes"))) // != response body → verify fails
			return r
		},
	})
	cfg := testConfig()
	opts := setupHayai(t, cfg, node)
	guard := &fakeSpendGuard{}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Result().StatusCode, w.Body.String())
	}
	if len(guard.reserved) != 1 {
		t.Fatalf("Reserve calls = %d, want 1", len(guard.reserved))
	}
	if len(guard.settled) != 0 {
		t.Errorf("a failed receipt must NOT Settle; got %v", guard.settled)
	}
	if len(guard.released) != 1 {
		t.Fatalf("Release calls = %d, want 1 (failed receipt backs out the reservation)", len(guard.released))
	}
	if guard.released[0] != guard.reserved[0] {
		t.Errorf("Release amount = %d, want the reserved ceiling %d", guard.released[0], guard.reserved[0])
	}
}
