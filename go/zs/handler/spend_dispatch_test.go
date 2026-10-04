/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// fakeSpendGuard is a SpendGuard for dispatch tests: reserveErr forces a cap
// trip, reserved captures each Reserve amount, released captures the amounts
// backed out (a failed open, or a receipt that didn't verify), and settled
// captures each Settle so a test can assert the actual charge was recorded.
//
// It mirrors the real guard's exactly-once semantics — reservations keyed by
// ticket id, Settle/Release resolving the amount from the reservation and
// dropping it, later calls for the same ticket no-ops, and a duplicate ticket id
// REFUSED with zs.ErrDuplicateTicket — so the "must NOT Release" / "must NOT
// Settle" assertions below measure what the dispatch path actually decided rather
// than how many times it happened to call through.
type fakeSpendGuard struct {
	reserveErr error
	// refuseFirst refuses that many Reserves as cap trips, then admits.
	refuseFirst int
	refusals    int
	asks        int // every Reserve call, refused or not
	reserved    []uint64
	released    []uint64
	settled     []settleCall

	open map[string]uint64
}

type settleCall struct{ maxPrice, spent uint64 }

func (f *fakeSpendGuard) Reserve(ticketID string, amt uint64) error {
	f.asks++
	if f.reserveErr != nil {
		return f.reserveErr
	}
	if f.refusals < f.refuseFirst {
		f.refusals++
		return errors.New("per-request spend cap exceeded (fake)")
	}
	if f.open == nil {
		f.open = make(map[string]uint64)
	}
	if _, dup := f.open[ticketID]; dup {
		// The real guard REFUSES a duplicate (wrapping zs.ErrDuplicateTicket)
		// rather than accepting it, and the dispatch path maps that sentinel to a
		// distinct 502. Returning nil here would let a regression that reused a
		// ticket id pass unnoticed at this level.
		return fmt.Errorf("%w: %q (fake)", zs.ErrDuplicateTicket, ticketID)
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

// TestDispatch_WalletUnfunded_402 asserts an underfunded open surfaces an
// actionable 402 wallet_unfunded rather than a generic 502.
func TestDispatch_WalletUnfunded_402(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, node)
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
func TestDispatch_WalletUnfunded_402_FundingHintByNetwork(t *testing.T) {
	const fundingURL = "https://app.example.test"
	for _, tc := range []struct {
		network    string
		fundingURL string
		wantWebApp bool
		// nilConfig builds the Server with a nil handler Config, which New
		// allows.
		nilConfig bool
	}{
		{"mainnet", fundingURL, true, false},
		// The network name is matched in any case, as algod.Resolve does.
		{"Mainnet", fundingURL, true, false},
		{"testnet", fundingURL, false, false},
		{"localnet", fundingURL, false, false},
		// No URL to name: an empty "web app ()" hint is worse than none.
		{"mainnet", "", false, false},
		{"mainnet", "", false, true},
	} {
		t.Run(fmt.Sprintf("network=%s/url=%s/nil=%v", tc.network, tc.fundingURL, tc.nilConfig), func(t *testing.T) {
			node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
			cfg := testConfig()
			cfg.Network = tc.network
			cfg.FundingURL = tc.fundingURL
			opts := setup(t, cfg, node)
			opts.Wallet = &fakeWallet{payer: "PAYERADDR", err: errors.New("wallet: submit presigned open group: overspend (account XYZ)")}
			opts.SpendGuard = &fakeSpendGuard{}
			opts.Remedies.Fund = "run the fund remedy"
			s := testServer(cfg, opts)
			if tc.nilConfig {
				s = New(s.Client, nil, silentLogger(), transform.Passthrough{}, transform.Passthrough{}, Options{})
			}

			w := httptest.NewRecorder()
			s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

			body := w.Body.String()
			if w.Result().StatusCode != http.StatusPaymentRequired || !strings.Contains(body, `"wallet_unfunded"`) {
				t.Fatalf("status = %d body=%s; want 402 wallet_unfunded", w.Result().StatusCode, body)
			}
			// The deposit address is the actionable part; swapped with the
			// network it would point the payer at a non-address.
			if want := "wallet PAYERADDR can't pay for this request on " + strings.ToLower(tc.network) + ". "; !strings.Contains(body, want) {
				t.Errorf("body missing %q:\n%s", want, body)
			}
			if got := strings.Contains(body, "web app"); got != tc.wantWebApp {
				t.Errorf("body offers the web app = %v, want %v:\n%s", got, tc.wantWebApp, body)
			}
			if tc.wantWebApp && !strings.Contains(body, tc.fundingURL) {
				t.Errorf("body offers the web app without naming %s:\n%s", tc.fundingURL, body)
			}
			if !strings.Contains(body, "run the fund remedy.") {
				t.Errorf("body doesn't carry Remedies.Fund:\n%s", body)
			}
		})
	}
}

// TestDispatch_MbrPoolUnderfunded_402 asserts that an open failing because
// the payer can't fund the prepaid ticket-MBR pool (ALGO shortfall, holds USDC)
// surfaces the distinct, actionable mbr_pool_underfunded code with the µALGO
// detail — NOT the generic wallet_unfunded (which reads as a USDC/onboarding
// problem and hides the real "add ALGO" cause).
func TestDispatch_MbrPoolUnderfunded_402(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	// The wallet wraps ErrDepositUnaffordable the way ensureDepositForServe does;
	// errors.Is must still see the sentinel through the wrap.
	opts.Wallet = &fakeWallet{err: fmt.Errorf("wallet: ensure MBR deposit: %w: need 577000 µALGO (575000 shortfall + 2000 fee), have 489000 µALGO spendable — fund the wallet with more ALGO", zs.ErrDepositUnaffordable)}
	opts.SpendGuard = &fakeSpendGuard{}
	opts.Remedies.Fund = "run the fund remedy"
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
	if !strings.Contains(body, "run the fund remedy") {
		t.Errorf("body must carry Remedies.Fund: %s", body)
	}
}

// TestDispatch_MbrPoolExhausted_429 is the other half: the wallet HOLDS
// the ALGO, every prepaid slot is just reserved by an in-flight ticket, so
// open() reverts on a pool guard. That is a transient concurrency cap with a
// knob attached, not an unfunded wallet — 429 + Retry-After, never a 402 "fund
// me" or an opaque 502.
//
// The wallet's error is the real *escrow.ApprovalError shape, wrapped the way
// Wallet.Open wraps it, because the whole classification now rests on the type
// surviving that wrap. algod puts only "assert failed pc=NNN" on the wire, so
// there is no text to fall back on if the type is lost.
func TestDispatch_MbrPoolExhausted_429(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	opts.Wallet = &fakeWallet{err: fmt.Errorf("wallet: submit presigned open group: %w", &escrow.ApprovalError{
		Method:  "open",
		PC:      3255,
		Message: escrow.AssertInsufficientMbrDeposit,
		Err:     errors.New("logic eval error: assert failed pc=3255"),
	})}
	opts.SpendGuard = &fakeSpendGuard{}
	opts.Remedies.RaiseSlots = "raise the slots remedy"
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
	if !strings.Contains(body, "raise the slots remedy") {
		t.Errorf("body must carry Remedies.RaiseSlots: %s", body)
	}
}

// TestDispatch_SpendCapExceeded_402 asserts the spend guard refuses past
// the cap with a 402 spend_cap_exceeded and never opens the escrow (no money
// committed).
func TestDispatch_SpendCapExceeded_402(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	fw := &fakeWallet{
		appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000",
	}
	opts.Wallet = fw
	opts.SpendGuard = &fakeSpendGuard{reserveErr: errors.New("daily spend cap exceeded")}
	opts.Remedies.RaiseSpendCap = "raise the cap remedy"
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusPaymentRequired {
		t.Fatalf("status = %d body=%s; want 402", w.Result().StatusCode, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"spend_cap_exceeded"`) {
		t.Errorf("body missing spend_cap_exceeded code: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "raise the cap remedy") {
		t.Errorf("body must carry Remedies.RaiseSpendCap: %s", w.Body.String())
	}
	if fw.openCalls != 0 {
		t.Errorf("wallet.Open should NOT be called when the spend cap trips, got %d", fw.openCalls)
	}
}

// Candidates come in routing order, not price order, so a cap trip on one
// operator's ticket moves on to the next, which may be cheaper.
func TestDispatch_SpendCapTriesTheNextOperator(t *testing.T) {
	a := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	b := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, a, b)
	fw := opts.Wallet.(*fakeWallet)
	guard := &fakeSpendGuard{refuseFirst: 1}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d body=%s; want the second operator to serve it", w.Result().StatusCode, w.Body.String())
	}
	if guard.refusals != 1 || len(guard.reserved) != 1 || fw.openCalls != 1 {
		t.Errorf("refusals %d, reserved %v, opens %d: want one refusal, then one reserve and one open",
			guard.refusals, guard.reserved, fw.openCalls)
	}
}

// A cap trip on one operator and a busy answer from another is operators_busy:
// the busy one may fit once a slot frees. The cap trip also ends the sweeps,
// so the capped operator is not asked for another reservation.
func TestDispatch_SpendCapYieldsToBusy(t *testing.T) {
	busy := newFakeNode(t, &nodeConfig{mode: modeReserveBusy, retryAfterSeconds: 7})
	capped := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, busy, capped)
	guard := &fakeSpendGuard{reserveErr: errors.New("daily spend cap exceeded")}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if w.Result().StatusCode != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "operators_busy") {
		t.Errorf("status = %d body=%s; want 503 operators_busy", w.Result().StatusCode, w.Body.String())
	}
	if guard.asks != 1 {
		t.Errorf("guard asked %d times, want 1: a cap trip must not trigger a busy re-sweep", guard.asks)
	}
}

// A candidate that passed the image-tool factor gate and was refused only by
// the spend cap proves the tool is serviceable, as a busy one does. Admit
// prices no tool allowance, so the allowance is what tips the signed ticket
// over the cap; the payer must hear about the cap, not that no operator serves
// the tool.
func TestDispatch_ToolBudgets_SpendCapBeatsUnsupportedTool(t *testing.T) {
	capped := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	factorless := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	capped.operator.ModelCapacities = map[string]zs.ModelCapacity{
		"gpt-test": {ImageToolRateMicroUSDC: 100_000, OutputUSDPer1M: 10},
	}
	factorless.operator.ModelCapacities = map[string]zs.ModelCapacity{
		"gpt-test": {OutputUSDPer1M: 10},
	}
	cfg := testConfig()
	opts := setup(t, cfg, capped, factorless)
	guard := &fakeSpendGuard{reserveErr: errors.New("daily spend cap exceeded")}
	opts.SpendGuard = guard
	s := testServer(cfg, opts)

	body := `{"model":"gpt-test","input":[{"role":"user","content":"hi"}],"max_output_tokens":50,"tool_budgets":{"zs_image_generation":{"max_n":2}}}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/responses", body))

	if guard.asks != 1 {
		t.Fatalf("guard asked %d times, want 1: the factored operator must reach the cap", guard.asks)
	}
	if got := w.Body.String(); w.Result().StatusCode != http.StatusPaymentRequired || !strings.Contains(got, "spend_cap_exceeded") {
		t.Errorf("status = %d body = %s; want 402 spend_cap_exceeded, not unsupported_tool", w.Result().StatusCode, got)
	}
}

// TestDispatch_DuplicateTicketID_502 asserts the OTHER Reserve failure gets
// its own diagnosis. A reused ticket id is the operator's node handing out an id
// already in flight for this payer — nothing the payer configured and nothing a
// config change can fix — so it must not surface as the 402 spend_cap_exceeded
// that tells them to raise spend.daily_cap_usdc or wait for the UTC day to roll.
// Distinguished by the zs.ErrDuplicateTicket sentinel, so the two Reserve
// errors can't be conflated by message text.
func TestDispatch_DuplicateTicketID_502(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	fw := &fakeWallet{appCallTxID: "APPCALLTXID00000000000000000000000000000000000000000"}
	opts.Wallet = fw
	opts.SpendGuard = &fakeSpendGuard{
		reserveErr: fmt.Errorf("%w: %q (operator reused a ticket id)", zs.ErrDuplicateTicket, "tid"),
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

// TestDispatch_SpendReservedOnSuccess asserts a committed open reserves the
// ticket's MaxPrice exactly once and never releases it.
func TestDispatch_SpendReservedOnSuccess(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{"ok":true}`)})
	cfg := testConfig()
	opts := setup(t, cfg, node)
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
	// The whole signed ceiling: anything less lets the cap fail open, since
	// settleLapsed can still claim up to MaxPrice.
	node.mu.Lock()
	signed := node.maxPrices
	node.mu.Unlock()
	if len(signed) != 1 || signed[0] == 0 || guard.reserved[0] != signed[0] {
		t.Errorf("reserved %v, want the MaxPrice the node signed (%v)", guard.reserved, signed)
	}
	if len(guard.released) != 0 {
		t.Errorf("a committed open must NOT release its reservation, got releases %v", guard.released)
	}
}

// TestDispatch_SpendSettledOnValidReceipt asserts that when the operator's
// signed receipt verifies, the guard records the *actual* charge (Settle with
// the receipt's AmountCharged) against the reserved MaxPrice ceiling — and does
// not Release. This is the fix for `zs status` showing reserved ceilings
// instead of real spend.
func TestDispatch_SpendSettledOnValidReceipt(t *testing.T) {
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
	opts := setup(t, cfg, node)
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

// failingJournal refuses every write and counts the attempts.
type failingJournal struct{ puts atomic.Int32 }

func (j *failingJournal) Put(context.Context, zs.TicketRecord) error {
	j.puts.Add(1)
	return errors.New("disk full")
}
func (*failingJournal) Delete(context.Context, string) error { return nil }
func (*failingJournal) List(context.Context, string, uint64) ([]zs.TicketRecord, error) {
	return nil, nil
}

// The journal only shortens recovery after a crash. By the time it is written
// the escrow is open and the payer is paying, so a failed write must not cost
// them the reply or the settle.
func TestDispatch_JournalWriteFailureKeepsTheTurn(t *testing.T) {
	reply := []byte(`{"choices":[{"message":{"content":"hi"}}]}`)
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: reply,
		buildReceipt: func(plaintext []byte) *ticket.UsageReceipt {
			r := &ticket.UsageReceipt{ActualInputCount: 8, ActualOutputCount: 3, AmountCharged: 31}
			r.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
			return r
		},
	})
	cfg := testConfig()
	opts := setup(t, cfg, node)
	guard := &fakeSpendGuard{}
	opts.SpendGuard = guard
	journal := &failingJournal{}
	opts.Journal = journal
	s := testServer(cfg, opts)

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

	if journal.puts.Load() == 0 {
		t.Fatal("the journal was never written, so this tests nothing")
	}
	if w.Result().StatusCode != http.StatusOK || !bytes.Equal(w.Body.Bytes(), reply) {
		t.Errorf("status = %d body = %s; want the reply", w.Result().StatusCode, w.Body.String())
	}
	if len(guard.settled) != 1 || guard.settled[0].spent != 31 {
		t.Errorf("settled %v, want the receipt's 31", guard.settled)
	}
}

// TestDispatch_SpendReleasedOnBadReceipt asserts that a receipt which fails
// verification (here a body_hash mismatch) backs the reservation out via
// Release and records no spend — the disputed/failed request must not count
// toward the daily total.
func TestDispatch_SpendReleasedOnBadReceipt(t *testing.T) {
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
	opts := setup(t, cfg, node)
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
