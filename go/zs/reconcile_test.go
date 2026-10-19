/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

var reconcileNow = time.Unix(1_800_000_000, 0)

// box is a ticket box whose deadline is deadlineIn from reconcileNow.
func box(status, pendingBy uint64, deadlineIn time.Duration) *escrow.TicketRecord {
	return &escrow.TicketRecord{
		Status:                 status,
		PendingBy:              pendingBy,
		ExpiresAt:              uint64(reconcileNow.Add(deadlineIn).Unix()) - 60,
		SettlementGraceSeconds: 60,
		OperatorOwnerAddr:      "OWNER",
	}
}

var settled = SettleArgs{AmountCharged: 7, ReceiptDigest: [32]byte{1}, TtftMs: 2, DecodeMs: 3, InputTokens: 4, OutputTokens: 5, OutputUsageType: 1, AuxOutputUsageType: 2, AuxOutputCount: 6}

// withClaim is b carrying the operator claim a's values describe.
func withClaim(b *escrow.TicketRecord, a SettleArgs) *escrow.TicketRecord {
	b.PendingAmount, b.PendingDigest = a.AmountCharged, a.ReceiptDigest
	b.PendingTtftMs, b.PendingDecodeMs = a.TtftMs, a.DecodeMs
	b.PendingInputCount, b.PendingOutputCount = a.InputTokens, a.OutputTokens
	b.PendingOutputUsageType, b.PendingAuxOutputUsageType = uint64(a.OutputUsageType), uint64(a.AuxOutputUsageType)
	b.PendingAuxOutputCount = a.AuxOutputCount
	return b
}

func openRec() TicketRecord {
	return TicketRecord{TicketID: "T", Status: TicketOpen, UpdatedAt: reconcileNow.Add(-time.Hour)}
}

// pendingRec has the payer's receipt recorded age ago.
func pendingRec(age time.Duration) TicketRecord {
	a := settled
	return TicketRecord{TicketID: "T", Status: TicketSettlePending, Settle: &a, UpdatedAt: reconcileNow.Add(-age)}
}

func TestDecideTicket(t *testing.T) {
	const lapse = 10 * time.Minute
	mismatched := settled
	mismatched.TtftMs++
	expiring := func(in time.Duration) TicketRecord {
		r := openRec()
		r.ExpiresAt = reconcileNow.Add(in)
		return r
	}
	for _, tc := range []struct {
		name string
		rec  TicketRecord
		box  *escrow.TicketRecord
		want reconcileAction
	}{
		{"box gone", openRec(), nil, reconcileForget},
		{"frozen", openRec(), box(escrow.StatusFrozen, 0, -time.Hour), reconcileForget},
		{"open in window", openRec(), box(escrow.StatusOpen, 0, time.Hour), reconcileWait},
		{"open past deadline", openRec(), box(escrow.StatusOpen, 0, -time.Minute), reconcileRefund},
		{"open past deadline with a receipt", pendingRec(time.Hour), box(escrow.StatusOpen, 0, -time.Minute), reconcileRefund},
		{"payer claim past deadline", openRec(), box(escrow.StatusPendingSettle, escrow.PendingByPayer, -time.Minute), reconcileRefund},
		{"payer claim in window", pendingRec(time.Hour), box(escrow.StatusPendingSettle, escrow.PendingByPayer, time.Hour), reconcileWait},
		{"operator claim, deadline just past", openRec(), box(escrow.StatusPendingSettle, escrow.PendingByOperator, -time.Minute), reconcileWait},
		{"operator claim, past the node's lapse", openRec(), box(escrow.StatusPendingSettle, escrow.PendingByOperator, -lapse-time.Second), reconcileLapse},
		{"receipt, open box in window", pendingRec(time.Hour), box(escrow.StatusOpen, 0, time.Hour), reconcileResettle},
		{"young receipt, open box", pendingRec(time.Minute), box(escrow.StatusOpen, 0, time.Hour), reconcileWait},
		{"receipt matching the operator claim", pendingRec(time.Hour), withClaim(box(escrow.StatusPendingSettle, escrow.PendingByOperator, time.Hour), settled), reconcileResettle},
		{"receipt not matching the operator claim", pendingRec(time.Hour), withClaim(box(escrow.StatusPendingSettle, escrow.PendingByOperator, time.Hour), mismatched), reconcileWait},
		{"young receipt matching the claim", pendingRec(time.Minute), withClaim(box(escrow.StatusPendingSettle, escrow.PendingByOperator, time.Hour), settled), reconcileWait},
		{"unknown status", openRec(), box(9, 0, -time.Hour), reconcileWait},
		// The open may still confirm until the ticket expires.
		{"no box yet, ticket live", expiring(time.Minute), nil, reconcileWait},
		{"no box, expired inside the skew", expiring(-reconcileSkew + time.Second), nil, reconcileWait},
		{"no box, expired past the skew", expiring(-reconcileSkew - time.Second), nil, reconcileForget},
		// Deadline comparisons are padded for clock skew, both ways.
		{"refund inside the skew", openRec(), box(escrow.StatusOpen, 0, -reconcileSkew+time.Second), reconcileWait},
		{"refund past the skew", openRec(), box(escrow.StatusOpen, 0, -reconcileSkew-time.Second), reconcileRefund},
		{"re-settle inside the skew", pendingRec(time.Hour), box(escrow.StatusOpen, 0, reconcileSkew-time.Second), reconcileWait},
		{"re-settle clear of the skew", pendingRec(time.Hour), box(escrow.StatusOpen, 0, reconcileSkew+time.Second), reconcileResettle},
		{"receipt just inside the grace", pendingRec(settlePendingGrace - time.Second), box(escrow.StatusOpen, 0, time.Hour), reconcileWait},
		{"receipt at the grace", pendingRec(settlePendingGrace), box(escrow.StatusOpen, 0, time.Hour), reconcileResettle},
		{"operator claim, just inside the node's lapse", openRec(), box(escrow.StatusPendingSettle, escrow.PendingByOperator, -lapse+time.Second), reconcileWait},
		// The payer's own pending claim needs the operator, not another settle.
		{"payer's own claim matching the receipt", pendingRec(time.Hour), withClaim(box(escrow.StatusPendingSettle, escrow.PendingByPayer, time.Hour), settled), reconcileWait},
		{"settle_pending row without values", TicketRecord{TicketID: "T", Status: TicketSettlePending, UpdatedAt: reconcileNow.Add(-time.Hour)},
			withClaim(box(escrow.StatusPendingSettle, escrow.PendingByOperator, time.Hour), settled), reconcileWait},
	} {
		if got := decideTicket(tc.rec, tc.box, reconcileNow, lapse); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// Every co-signed value must match: a re-fire with any one different freezes
// the ticket.
func TestClaimMatches_EveryField(t *testing.T) {
	b := withClaim(&escrow.TicketRecord{}, settled)
	if !claimMatches(settled, b) {
		t.Fatal("control: identical values do not match")
	}
	for name, mut := range map[string]func(*SettleArgs){
		"amount":   func(a *SettleArgs) { a.AmountCharged++ },
		"digest":   func(a *SettleArgs) { a.ReceiptDigest[31]++ },
		"ttft":     func(a *SettleArgs) { a.TtftMs++ },
		"decode":   func(a *SettleArgs) { a.DecodeMs++ },
		"input":    func(a *SettleArgs) { a.InputTokens++ },
		"output":   func(a *SettleArgs) { a.OutputTokens++ },
		"usage":    func(a *SettleArgs) { a.OutputUsageType++ },
		"auxusage": func(a *SettleArgs) { a.AuxOutputUsageType++ },
		"auxcount": func(a *SettleArgs) { a.AuxOutputCount++ },
	} {
		a := settled
		mut(&a)
		if claimMatches(a, b) {
			t.Errorf("%s differs but matches", name)
		}
	}
}

// fakeChain answers box reads from boxes and records each submit.
type fakeChain struct {
	mu      sync.Mutex
	boxes   map[string]*escrow.TicketRecord
	readErr error
	callErr error
	calls   []string
}

func (f *fakeChain) readBox(_ context.Context, id string) (*escrow.TicketRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.boxes[id], f.readErr
}

func (f *fakeChain) record(call string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	return "TX", f.callErr
}

func (f *fakeChain) refund(_ context.Context, rec TicketRecord) (string, error) {
	return f.record("refund " + rec.TicketID)
}
func (f *fakeChain) lapse(_ context.Context, rec TicketRecord, _ *escrow.TicketRecord) (string, error) {
	return f.record("lapse " + rec.TicketID)
}
func (f *fakeChain) resettle(_ context.Context, rec TicketRecord, _ *escrow.TicketRecord) (string, error) {
	return f.record("settle " + rec.TicketID)
}

func (f *fakeChain) seen() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls)
}

// journalDeployment owns the rows put writes, which name only app 7, as a row
// from before rows named their deployment does.
var journalDeployment = Deployment{Rail: ticket.RailAlgorand, Network: "custom", EscrowAppID: 7}

func testReconciler(j TicketJournal, chain ticketChain, watching ...string) *reconciler {
	r := newReconciler(j, chain, "PAYER", journalDeployment, func(id string) bool { return slices.Contains(watching, id) }, nil, discardLogger())
	r.now = func() time.Time { return reconcileNow }
	return r
}

func put(t *testing.T, j TicketJournal, recs ...TicketRecord) {
	t.Helper()
	for _, r := range recs {
		if r.Payer == "" {
			r.Payer = "PAYER"
		}
		if r.EscrowAppID == 0 {
			r.EscrowAppID = 7
		}
		if err := j.Put(context.Background(), r); err != nil {
			t.Fatal(err)
		}
	}
}

func ids(t *testing.T, j TicketJournal) []string {
	t.Helper()
	recs, err := j.List(context.Background(), "PAYER", journalDeployment)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range recs {
		out = append(out, r.TicketID)
	}
	return out
}

// A sweep acts on each ticket nobody else drives, forgets the ones whose box is
// gone, and keeps the ones it submitted for until a later sweep sees them gone.
func TestReconciler_Sweep(t *testing.T) {
	j := newMemJournal()
	// The watched ticket sorts first, so skipping it must not end the sweep.
	gone, stale, watched, other := openRec(), openRec(), openRec(), openRec()
	gone.TicketID, stale.TicketID, watched.TicketID, other.TicketID = "GONE", "STALE", "AWATCHED", "OTHER"
	put(t, j, gone, stale, watched)
	other.Payer = "SOMEONE"
	put(t, j, other)
	chain := &fakeChain{boxes: map[string]*escrow.TicketRecord{
		"STALE":    box(escrow.StatusOpen, 0, -time.Minute),
		"AWATCHED": box(escrow.StatusOpen, 0, -time.Minute),
		"OTHER":    box(escrow.StatusOpen, 0, -time.Minute),
	}}
	r := testReconciler(j, chain, "AWATCHED")
	r.sweep()
	if got := chain.seen(); !slices.Equal(got, []string{"refund STALE"}) {
		t.Errorf("calls %v, want only the unwatched stale ticket refunded", got)
	}
	if got := ids(t, j); !slices.Equal(got, []string{"AWATCHED", "STALE"}) && !slices.Equal(got, []string{"STALE", "AWATCHED"}) {
		t.Errorf("journal %v, want STALE kept until its box is gone, GONE forgotten", got)
	}

	chain.boxes["STALE"] = nil
	r.sweep()
	if got := ids(t, j); !slices.Equal(got, []string{"AWATCHED"}) {
		t.Errorf("journal %v after the refund landed, want only AWATCHED", got)
	}
}

// A sweep submits the call its verdict names: a re-settle for a stranded
// receipt, and settleLapsed once the production lapse fallback has passed.
func TestReconciler_SubmitsTheVerdictsCall(t *testing.T) {
	for _, tc := range []struct {
		name string
		rec  TicketRecord
		box  *escrow.TicketRecord
		want []string
	}{
		{"stranded receipt", pendingRec(time.Hour), box(escrow.StatusOpen, 0, time.Hour), []string{"settle T"}},
		{"operator claim past the lapse fallback", openRec(), box(escrow.StatusPendingSettle, escrow.PendingByOperator, -11*time.Minute), []string{"lapse T"}},
		{"operator claim inside the lapse fallback", openRec(), box(escrow.StatusPendingSettle, escrow.PendingByOperator, -9*time.Minute), nil},
	} {
		j := newMemJournal()
		put(t, j, tc.rec)
		chain := &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": tc.box}}
		testReconciler(j, chain).sweep()
		if got := chain.seen(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: calls %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A frozen ticket is arbitration's, and no call can touch it, so the sweep
// drops its row rather than re-reading the box every minute forever.
func TestReconciler_FrozenBoxIsForgotten(t *testing.T) {
	j := newMemJournal()
	put(t, j, openRec())
	chain := &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": box(escrow.StatusFrozen, 0, -time.Minute)}}
	testReconciler(j, chain).sweep()
	if got := ids(t, j); len(got) != 0 || len(chain.seen()) != 0 {
		t.Errorf("journal %v, calls %v: want the row dropped and nothing submitted", got, chain.seen())
	}
}

// A box that cannot be read is retried, never forgotten.
func TestReconciler_UnreadableBoxIsKept(t *testing.T) {
	j := newMemJournal()
	put(t, j, openRec())
	chain := &fakeChain{readErr: errors.New("algod down")}
	testReconciler(j, chain).sweep()
	if got := ids(t, j); len(got) != 1 || len(chain.seen()) != 0 {
		t.Errorf("journal %v, calls %v: want the ticket kept and nothing submitted", got, chain.seen())
	}
}

// A ticket whose submit keeps failing stops costing fees after the cap, for
// this process.
func TestReconciler_FailureCap(t *testing.T) {
	j := newMemJournal()
	put(t, j, openRec())
	chain := &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": box(escrow.StatusOpen, 0, -time.Minute)}, callErr: errors.New("rejected")}
	r := testReconciler(j, chain)
	var logs bytes.Buffer
	r.log = slog.New(slog.NewTextHandler(&logs, nil))
	r.remedy = "recover it by hand"
	for range reconcileMaxFailures + 3 {
		r.sweep()
	}
	if got := len(chain.seen()); got != reconcileMaxFailures {
		t.Errorf("%d submits, want %d", got, reconcileMaxFailures)
	}
	// The ticket is left on chain, so the give-up line is the payer's lead.
	if !strings.Contains(logs.String(), `remedy="recover it by hand"`) {
		t.Errorf("give-up log lacks the remedy:\n%s", logs.String())
	}
	if got := ids(t, j); len(got) != 1 {
		t.Errorf("journal %v, want the ticket kept for the next start", got)
	}

	// An exhausted ticket listed first does not stop the sweep reaching a later one.
	later := openRec()
	later.TicketID, later.CreatedAt = "U", reconcileNow
	put(t, j, later)
	chain.boxes["U"] = box(escrow.StatusOpen, 0, -time.Minute)
	r.sweep()
	if got := chain.seen(); got[len(got)-1] != "refund U" {
		t.Errorf("calls %v, want the later ticket refunded", got)
	}
}

// start sweeps at once, and close waits for the loop to end.
func TestReconciler_StartSweepsAtOnceAndCloseStops(t *testing.T) {
	j := newMemJournal()
	put(t, j, openRec())
	r := testReconciler(j, &fakeChain{})
	r.interval = time.Hour
	r.start()
	deadline := time.Now().Add(5 * time.Second)
	for len(ids(t, j)) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the first sweep did not run")
		}
		time.Sleep(5 * time.Millisecond)
	}
	r.close(nil)
	r.close(nil)
	select {
	case <-r.done:
	default:
		t.Error("close returned with the loop still running")
	}
}

// firstReleasePanics is a host spend guard with a bug: its first Release panics.
type firstReleasePanics struct{ calls atomic.Int32 }

func (*firstReleasePanics) Admit(uint64) error           { return nil }
func (*firstReleasePanics) Reserve(string, uint64) error { return nil }
func (*firstReleasePanics) Settle(string, uint64)        {}
func (g *firstReleasePanics) Release(string) {
	if g.calls.Add(1) == 1 {
		panic("guard bug")
	}
}

// panicGuard is a host spend guard whose Settle and Release always panic.
type panicGuard struct{}

func (panicGuard) Admit(uint64) error           { return nil }
func (panicGuard) Reserve(string, uint64) error { return nil }
func (panicGuard) Settle(string, uint64)        { panic("guard bug") }
func (panicGuard) Release(string)               { panic("guard bug") }

// A closed ticket's row goes even when the guard panics on its release; kept,
// it would be re-read and re-released every sweep.
func TestReconciler_ForgetsPastAPanickingGuard(t *testing.T) {
	j := newMemJournal()
	put(t, j, pendingRec(time.Hour))
	r := testReconciler(j, &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": nil}})
	r.spend = panicGuard{}
	r.sweep()
	if got := ids(t, j); len(got) != 0 {
		t.Errorf("journal %v, want the closed ticket forgotten", got)
	}
}

// A guard that panics on the outcome of a submit the chain accepted costs a
// log line, not a failed attempt: the submit succeeded, and counting it would
// give up on a ticket that was fine.
func TestReconciler_PanickingGuardAfterASubmitIsNoFailure(t *testing.T) {
	claimed := box(escrow.StatusPendingSettle, escrow.PendingByOperator, -11*time.Minute)
	for _, tc := range []struct {
		name string
		rec  TicketRecord
		box  *escrow.TicketRecord
	}{
		{"refund, released", openRec(), box(escrow.StatusOpen, 0, -time.Minute)},
		{"lapse, settled", openRec(), claimed},
		{"lapse after a receipt, released", pendingRec(time.Hour), claimed},
	} {
		j := newMemJournal()
		put(t, j, tc.rec)
		r := testReconciler(j, &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": tc.box}})
		r.spend = panicGuard{}
		r.sweep()
		if n := r.failures["T"]; n != 0 {
			t.Errorf("%s: %d failed attempt(s) counted for a submit that went through", tc.name, n)
		}
	}
}

// failingOpenWallet's Open always fails, as a payer short of funds does.
type failingOpenWallet struct{}

func (failingOpenWallet) Open(context.Context, *ticket.Ticket, Operator, string) (*OpenHandle, error) {
	return nil, errors.New("insufficient funds")
}
func (failingOpenWallet) PayerAddr() string { return "PAYER" }

// A guard that panics while a failed open is backed out still leaves the
// request failed with the open's error, not a panic.
func TestRunSealed_FailsTheOpenPastAPanickingGuard(t *testing.T) {
	c := settleClient()
	c.wallet = failingOpenWallet{}
	c.spend = panicGuard{}
	em := &recEmitter{}
	rt := &ReservedTicket{Ticket: &ticket.Ticket{TicketID: "T"}}
	c.runSealed(context.Background(), em, endpointChatCompletions, "m", []byte(`{}`), Operator{ID: 1}, rt, false, nil)
	if em.failed == nil || em.failed.Code != "wallet_open" {
		t.Errorf("failed with %v, want the open's wallet_open", em.failed)
	}
}

// panicChain is chain code that panics reading one ticket's box.
type panicChain struct {
	*fakeChain
	on string
}

func (c panicChain) readBox(ctx context.Context, id string) (*escrow.TicketRecord, error) {
	if id == c.on {
		panic("chain bug")
	}
	return c.fakeChain.readBox(ctx, id)
}

// A row that panics costs that row a failed attempt, not the sweep or the
// process: the next row is still reconciled, and a row that always panics is
// given up on like any other failure.
func TestReconciler_PanickingRowCountsAsAFailure(t *testing.T) {
	j := newMemJournal()
	a, b := openRec(), openRec()
	a.TicketID, b.TicketID = "A", "B"
	put(t, j, a, b)
	chain := panicChain{fakeChain: &fakeChain{boxes: map[string]*escrow.TicketRecord{"B": box(escrow.StatusOpen, 0, -time.Minute)}}, on: "A"}
	r := testReconciler(j, chain)
	r.sweep()
	if got := chain.seen(); !slices.Equal(got, []string{"refund B"}) {
		t.Errorf("calls %v, want B refunded past A's panic", got)
	}
	for range reconcileMaxFailures {
		r.sweep()
	}
	if !r.exhausted("A") {
		t.Error("a row that always panics is never given up on")
	}
}

// A journal whose List panics costs the sweep, not the process.
func TestReconciler_PanickingListIsContained(t *testing.T) {
	r := testReconciler(panicList{newMemJournal()}, &fakeChain{})
	r.sweep()
}

type panicList struct{ *memJournal }

func (panicList) List(context.Context, string, Deployment) ([]TicketRecord, error) {
	panic("journal bug")
}

// A host hook that panics on one ticket costs that ticket, not the sweep or
// the process: the next row is still reconciled.
func TestReconciler_HostPanicCostsOnlyItsRow(t *testing.T) {
	j := newMemJournal()
	a, b := openRec(), openRec()
	a.TicketID, b.TicketID = "A", "B"
	put(t, j, a, b)
	chain := &fakeChain{boxes: map[string]*escrow.TicketRecord{
		"A": box(escrow.StatusOpen, 0, -time.Minute),
		"B": box(escrow.StatusOpen, 0, -time.Minute),
	}}
	r := testReconciler(j, chain)
	guard := &firstReleasePanics{}
	r.spend = guard
	r.sweep()
	if got := chain.seen(); len(got) != 2 {
		t.Errorf("calls %v, want both tickets refunded", got)
	}
	if n := guard.calls.Load(); n != 2 {
		t.Errorf("guard released %d tickets, want 2", n)
	}
}

// The journal claim is given back even when the hand-off before it panics:
// kept, it bars every later Client from sweeping that journal.
func TestReconciler_CloseReleasesWhenTheHandOffPanics(t *testing.T) {
	r := testReconciler(newMemJournal(), &fakeChain{})
	released := false
	r.release = func() { released = true }
	r.start()
	func() {
		defer func() { _ = recover() }()
		r.close(func() { panic("hand-off bug") })
	}()
	if !released {
		t.Error("close kept the journal claim after the hand-off panicked")
	}
}

// The file journal survives a reopen and scopes List to payer and app.
func TestFileJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "tickets.json")
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	a := pendingRec(time.Hour)
	a.TicketID, a.CreatedAt = "A", reconcileNow
	b := openRec()
	b.TicketID, b.CreatedAt = "B", reconcileNow.Add(-time.Minute)
	put(t, j, a, b)
	other := openRec()
	other.TicketID, other.EscrowAppID, other.Payer = "C", 8, "PAYER"
	b.Target, b.OpenTxID, b.MaxPrice, b.ExpiresAt = NodeRef{Op: 3, Node: 4}, "OPENTX", 99, reconcileNow.Add(time.Minute)
	put(t, j, other, b)
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}

	j2, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j2.Close() })
	recs, err := j2.List(context.Background(), "PAYER", journalDeployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].TicketID != "B" || recs[1].TicketID != "A" {
		t.Fatalf("reopened %v, want B then A (oldest first), C excluded", recs)
	}
	if recs[1].Settle == nil || *recs[1].Settle != settled || recs[1].Status != TicketSettlePending {
		t.Errorf("A came back as %+v", recs[1])
	}
	want := b
	want.Payer, want.EscrowAppID = "PAYER", 7
	if got := recs[0]; got.Target != want.Target || got.OpenTxID != want.OpenTxID || got.MaxPrice != want.MaxPrice ||
		!got.ExpiresAt.Equal(want.ExpiresAt) || !got.CreatedAt.Equal(want.CreatedAt) || !got.UpdatedAt.Equal(want.UpdatedAt) ||
		got.Status != want.Status || got.Payer != want.Payer || got.EscrowAppID != want.EscrowAppID || got.Settle != nil {
		t.Errorf("B came back as %+v, want %+v", got, want)
	}
	if err := j2.Delete(context.Background(), "B"); err != nil {
		t.Fatal(err)
	}
	if err := j2.Delete(context.Background(), "missing"); err != nil {
		t.Errorf("deleting an unknown id: %v", err)
	}
	if got := ids(t, j2); !slices.Equal(got, []string{"A"}) {
		t.Errorf("after delete %v, want A", got)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Errorf("journal mode %v, want no group or other access", info.Mode().Perm())
	}
}

// A journal path that exists but cannot be read is an error, not an empty
// journal whose first write would replace it.
func TestOpenFileJournal_RefusesAnUnreadablePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tickets.json")
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if j, err := OpenFileJournal(path); err == nil {
		j.Close()
		t.Error("a directory at the journal path opened as an empty journal")
	}
}

// journalV1 is a version-1 journal file as an earlier build wrote it. A field
// renamed in the file format would load as zero and break this.
const journalV1 = `{
  "version": 1,
  "tickets": [
    {
      "ticket_id": "T",
      "open_tx_id": "OPENTX",
      "escrow_app_id": 7,
      "operator_id": 3,
      "node_id": 4,
      "payer": "PAYER",
      "max_price": 99,
      "expires_at": "2027-01-15T08:00:30Z",
      "status": "settle_pending",
      "created_at": "2027-01-15T08:00:00Z",
      "updated_at": "2027-01-15T08:00:10Z",
      "settle": {
        "amount_charged": 1,
        "receipt_digest": "0200000000000000000000000000000000000000000000000000000000000000",
        "ttft_ms": 3,
        "decode_ms": 4,
        "input_tokens": 5,
        "output_tokens": 6,
        "output_usage_type": 7,
        "aux_output_usage_type": 8,
        "aux_output_count": 9
      }
    }
  ]
}`

// A file in the version-1 format loads into exactly the record it describes,
// and the same record saves back to the same document.
func TestFileJournal_ReadsAndWritesTheV1Format(t *testing.T) {
	at := func(s string) time.Time {
		v, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	want := TicketRecord{
		TicketID: "T", OpenTxID: "OPENTX", EscrowAppID: 7, Target: NodeRef{Op: 3, Node: 4}, Payer: "PAYER", MaxPrice: 99,
		ExpiresAt: at("2027-01-15T08:00:30Z"), Status: TicketSettlePending,
		CreatedAt: at("2027-01-15T08:00:00Z"), UpdatedAt: at("2027-01-15T08:00:10Z"),
		Settle: &SettleArgs{AmountCharged: 1, ReceiptDigest: [32]byte{2}, TtftMs: 3, DecodeMs: 4, InputTokens: 5,
			OutputTokens: 6, OutputUsageType: 7, AuxOutputUsageType: 8, AuxOutputCount: 9},
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "old.json")
	if err := os.WriteFile(path, []byte(journalV1), 0o600); err != nil {
		t.Fatal(err)
	}
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	recs, err := j.List(context.Background(), "PAYER", journalDeployment)
	if err != nil || len(recs) != 1 {
		t.Fatalf("List = %v, %v; want one record", recs, err)
	}
	if !reflect.DeepEqual(recs[0], want) {
		t.Errorf("loaded\n  %+v\nwant\n  %+v", recs[0], want)
	}

	fresh, err := OpenFileJournal(filepath.Join(dir, "new.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := fresh.Put(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "new.json")); string(got) != journalV1 {
		t.Errorf("saved\n%s\nwant\n%s", got, journalV1)
	}
}

// One FileJournal holds a file at a time; Close lets the next one in.
func TestOpenFileJournal_OneOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tickets.json")
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenFileJournal(path); !errors.Is(err, ErrJournalInUse) {
		t.Fatalf("second open: err = %v, want ErrJournalInUse", err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if err := j.Put(context.Background(), openRec()); err == nil {
		t.Error("a closed journal accepted a write")
	}
	j2, err := OpenFileJournal(path)
	if err != nil {
		t.Fatalf("open after Close: %v", err)
	}
	j2.Close()
}

// A write that fails to reach the file leaves the journal as it was, in memory
// and on disk.
func TestFileJournal_FailedWriteRollsBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	path := filepath.Join(dir, "tickets.json")
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	kept := openRec()
	kept.Status = TicketOpen
	put(t, j, kept)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o700) })

	changed := pendingRec(time.Hour)
	changed.Payer, changed.EscrowAppID = "PAYER", 7
	added := openRec()
	added.TicketID, added.Payer, added.EscrowAppID = "NEW", "PAYER", 7
	if j.Put(context.Background(), changed) == nil || j.Put(context.Background(), added) == nil || j.Delete(context.Background(), "T") == nil {
		t.Fatal("a write to a read-only directory succeeded")
	}
	recs, _ := j.List(context.Background(), "PAYER", journalDeployment)
	if len(recs) != 1 || recs[0].TicketID != "T" || recs[0].Status != TicketOpen {
		t.Errorf("in memory after failed writes: %+v, want only T, still open", recs)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Error("the file changed")
	}
}

// close cancels a chain call in flight rather than waiting out its timeout,
// and counts no failure for it.
func TestReconciler_CloseCancelsACallInFlight(t *testing.T) {
	j := newMemJournal()
	put(t, j, openRec())
	chain := &blockingChain{entered: make(chan struct{})}
	r := testReconciler(j, chain)
	r.callTimeout = time.Hour
	r.start()
	<-chain.entered
	done := make(chan struct{})
	go func() { r.close(nil); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close waited on the call")
	}
	if len(r.failures) != 0 {
		t.Errorf("failures %v, want none for a cancelled call", r.failures)
	}
}

// blockingChain's box read reports an open box past its deadline, and its
// refund blocks until cancelled.
type blockingChain struct {
	fakeChain
	entered chan struct{}
}

func (c *blockingChain) readBox(context.Context, string) (*escrow.TicketRecord, error) {
	return box(escrow.StatusOpen, 0, -time.Hour), nil
}

func (c *blockingChain) refund(ctx context.Context, _ TicketRecord) (string, error) {
	close(c.entered)
	<-ctx.Done()
	return "", ctx.Err()
}

// A journal it cannot parse is an error, not an empty journal: starting empty
// would forget tickets still holding the payer's USDC.
func TestOpenFileJournal_RefusesAnUnreadableFile(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"garbage":       "not json",
		"wrong version": `{"version":2,"tickets":[]}`,
		"bad digest":    `{"version":1,"tickets":[{"ticket_id":"T","settle":{"receipt_digest":"zz"}}]}`,
		"short digest":  `{"version":1,"tickets":[{"ticket_id":"T","settle":{"receipt_digest":"01"}}]}`,
		"no version":    `{"tickets":[]}`,
	} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := OpenFileJournal(path); err == nil {
			t.Errorf("%s: opened", name)
		}
		// The failed open released its lock: once the file is fixed, it opens.
		if err := os.WriteFile(path, []byte(`{"version":1,"tickets":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		j, err := OpenFileJournal(path)
		if err != nil {
			t.Errorf("%s: reopening the fixed file: %v", name, err)
			continue
		}
		j.Close()
	}
}
