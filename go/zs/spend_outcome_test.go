/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	neturl "net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
)

// outcomeGuard records each Settle and Release it hears.
type outcomeGuard struct {
	mu    sync.Mutex
	calls []string
}

func (*outcomeGuard) Admit(uint64) error           { return nil }
func (*outcomeGuard) Reserve(string, uint64) error { return nil }
func (g *outcomeGuard) Settle(id string, charged uint64) {
	g.add(fmt.Sprintf("settle %s %d", id, charged))
}
func (g *outcomeGuard) Release(id string) { g.add("release " + id) }

func (g *outcomeGuard) add(call string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.calls = append(g.calls, call)
}

func (g *outcomeGuard) seen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.calls)
}

// The reconciler tells the guard each outcome the chain has fixed: a refund
// algod accepted frees the reservation, and a lapse charges the operator's
// claim. A journaled receipt was counted when the request settled it, so its
// ticket is only released. Where the outcome is still open, or unknown, it
// says nothing.
func TestReconciler_TellsTheSpendGuardHowATicketEnded(t *testing.T) {
	claimed := func() *escrow.TicketRecord {
		b := box(escrow.StatusPendingSettle, escrow.PendingByOperator, -11*time.Minute)
		b.PendingAmount = 9
		return b
	}
	// A receipt past the settle window, whose operator claim (9, not 7)
	// the payer's settle would contradict.
	receiptThenClaim := pendingRec(time.Hour)
	for _, tc := range []struct {
		name    string
		rec     TicketRecord
		box     *escrow.TicketRecord
		callErr error
		want    []string
	}{
		{"refund submitted", openRec(), box(escrow.StatusOpen, 0, -time.Minute), nil, []string{"release T"}},
		{"refund refused", openRec(), box(escrow.StatusOpen, 0, -time.Minute), errors.New("rejected"), nil},
		{"lapse submitted", openRec(), claimed(), nil, []string{"settle T 9"}},
		{"lapse refused", openRec(), claimed(), errors.New("rejected"), nil},
		{"lapse submitted, receipt already counted", receiptThenClaim, claimed(), nil, []string{"release T"}},
		{"inside the window", openRec(), box(escrow.StatusOpen, 0, time.Hour), nil, nil},
		{"re-settle submitted", pendingRec(time.Hour), box(escrow.StatusOpen, 0, time.Hour), nil, nil},
		{"box gone, with a receipt", pendingRec(time.Hour), nil, nil, []string{"release T"}},
		{"box gone, no receipt", openRec(), nil, nil, nil},
		{"frozen, with a receipt", pendingRec(time.Hour), box(escrow.StatusFrozen, 0, -time.Minute), nil, nil},
	} {
		j := newMemJournal()
		put(t, j, tc.rec)
		chain := &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": tc.box}, callErr: tc.callErr}
		guard := &outcomeGuard{}
		r := testReconciler(j, chain)
		r.spend = guard
		r.sweep()
		if got := guard.seen(); !slices.Equal(got, tc.want) {
			t.Errorf("%s: guard heard %v, want %v", tc.name, got, tc.want)
		}
	}
}

// With no SpendGuard, the default, a closed ticket with a receipt is still
// forgotten, and nothing is told.
func TestReconciler_NoSpendGuard(t *testing.T) {
	j := newMemJournal()
	put(t, j, pendingRec(time.Hour))
	testReconciler(j, &fakeChain{boxes: map[string]*escrow.TicketRecord{"T": nil}}).sweep()
	if got := ids(t, j); len(got) != 0 {
		t.Errorf("journal %v, want the closed ticket forgotten", got)
	}
}

// The watchdog reports a refund algod accepted, and only that: a box gone, a
// lapse it drove, or a frozen box may each have ended at a charge.
func TestRefundWatchdog_ReportsTheRefund(t *testing.T) {
	past := time.Now().Add(-time.Minute)
	gone := func(context.Context) (ticketProbe, error) { return ticketProbe{}, nil }
	unreadable := func(context.Context) (ticketProbe, error) { return ticketProbe{}, errors.New("algod down") }
	lapsed := func(context.Context) (string, error) { return "TX", nil }
	for _, tc := range []struct {
		name  string
		probe func(context.Context) (ticketProbe, error)
		// refunds are the answers to successive refund calls.
		refunds []error
		want    []string
	}{
		{"accepted", liveBox(), []error{nil}, []string{"tik"}},
		{"accepted on a retry", liveBox(), []error{errors.New("timeout"), nil}, []string{"tik"}},
		{"accepted with the box unreadable", unreadable, []error{nil}, []string{"tik"}},
		{"refused", liveBox(), []error{errors.New("rejected")}, nil},
		{"box gone", gone, nil, nil},
		{"lapse driven", boxAt(past, escrow.VerdictLapse), nil, nil},
		{"frozen", boxAt(past, escrow.VerdictArbitrate), nil, nil},
	} {
		rw := testWatchdog()
		var mu sync.Mutex
		var heard []string
		var calls int
		rw.refunded = func(id string) { mu.Lock(); heard = append(heard, id); mu.Unlock() }
		refund := func(context.Context) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if len(tc.refunds) == 0 {
				t.Errorf("%s: a refund was sent", tc.name)
				return "", errors.New("unexpected refund")
			}
			err := tc.refunds[min(calls, len(tc.refunds)-1)]
			calls++
			return "TX", err
		}
		rw.track("tik", time.Now(), tc.probe, refund, lapsed)
		rw.running.Wait()
		mu.Lock()
		got := slices.Clone(heard)
		mu.Unlock()
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s: refunded heard %v, want %v", tc.name, got, tc.want)
		}
	}
}

// New hands the caller's guard to both: the watchdog's refunds Release, and
// the reconciler already holds it for the sweep it starts with, which is the
// one that finds what a restart left behind.
func TestNew_WiresTheSpendGuardToTheTicketOutcomes(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	// Every box reads as gone.
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/box") {
			http.NotFound(w, r)
			return
		}
		target, _ := neturl.Parse(url)
		httputil.NewSingleHostReverseProxy(target).ServeHTTP(w, r)
	}))
	t.Cleanup(front.Close)
	j := openTestJournal(t)
	id := base64.StdEncoding.EncodeToString(make([]byte, 16))
	left := pendingRec(time.Hour)
	left.TicketID, left.EscrowAppID = id, 1
	put(t, j, left)
	cfg := sweepingConfig(t, front.URL, j)
	guard := &outcomeGuard{}
	cfg.SpendGuard = guard
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitFor(t, "the first sweep to tell the guard", func() bool { return len(guard.seen()) > 0 })
	if got := guard.seen(); !slices.Equal(got, []string{"release " + id}) {
		t.Fatalf("the first sweep told the guard %v, want a release of the closed ticket", got)
	}
	guard.mu.Lock()
	guard.calls = nil
	guard.mu.Unlock()
	if c.refunds.refunded == nil {
		t.Fatal("the watchdog's refunds reach no guard")
	}
	c.refunds.refunded("X")
	if got := guard.seen(); !slices.Equal(got, []string{"release X"}) {
		t.Errorf("a watchdog refund told the guard %v, want a release", got)
	}
	if c.reconcile.spend != guard {
		t.Error("the reconciler does not hold the caller's guard")
	}
}
