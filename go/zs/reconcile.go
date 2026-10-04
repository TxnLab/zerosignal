/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"log/slog"
	"reflect"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const (
	// reconcileInterval is how often the sweep reads the journal. A stranded
	// ticket's deadline is minutes away, so a minute's lag costs nothing.
	reconcileInterval = 60 * time.Second
	// settlePendingGrace is how long a ticket must sit in TicketSettlePending
	// before the sweep re-fires the payer's settle: the live settle may still
	// be confirming, and a re-fire after it lands reverts and costs a fee.
	settlePendingGrace = 2 * time.Minute
	// defaultLapseFallback is how long past the deadline the sweep leaves an
	// operator's claim to the node's own driver before calling settleLapsed.
	defaultLapseFallback = 10 * time.Minute
	// reconcileMaxFailures bounds the failed submits per ticket per process,
	// so a ticket that can never settle doesn't cost a fee every sweep.
	reconcileMaxFailures = 10
	// reconcileSkew pads every deadline comparison against the gap between
	// the local clock and the chain's latestTimestamp, so a call is not sent
	// just before (or after) the window the contract checks. Matches the
	// refund watchdog's margin.
	reconcileSkew = 15 * time.Second
)

type reconcileAction uint8

const (
	reconcileWait reconcileAction = iota
	// reconcileForget: the box is gone, or frozen, which no payer call can
	// change.
	reconcileForget
	reconcileRefund
	reconcileLapse
	reconcileResettle
)

func (a reconcileAction) String() string {
	switch a {
	case reconcileForget:
		return "forget"
	case reconcileRefund:
		return "refundInactive"
	case reconcileLapse:
		return "settleLapsed"
	case reconcileResettle:
		return "settle"
	}
	return "wait"
}

// decideTicket is what the sweep does about one journaled ticket, given its
// box (nil when gone) and the time. The contract's rules come from
// escrow.Classify; what this adds is the payer's own receipt:
//
//   - A settle is legal only inside the window, so a recorded receipt is
//     re-fired there: against an OPEN box, or a box carrying the operator's
//     claim when the claim matches the receipt (a mismatch would freeze it).
//   - Past the window an operator claim goes to settleLapsed, but only once
//     lapseFallback has passed, since the node's own driver normally does it.
//   - A missing box is finished only once the ticket has expired: the open is
//     submitted without waiting for confirmation, and the contract accepts it
//     until expires_at.
func decideTicket(rec TicketRecord, box *escrow.TicketRecord, now time.Time, lapseFallback time.Duration) reconcileAction {
	if box == nil {
		if now.After(rec.ExpiresAt.Add(reconcileSkew)) {
			return reconcileForget
		}
		return reconcileWait
	}
	switch escrow.Classify(box, now.Add(-reconcileSkew)) {
	case escrow.VerdictArbitrate:
		return reconcileForget
	case escrow.VerdictRefund:
		return reconcileRefund
	case escrow.VerdictLapse:
		if now.After(box.SettlementDeadline().Add(lapseFallback)) {
			return reconcileLapse
		}
		return reconcileWait
	case escrow.VerdictWait:
		if rec.Status != TicketSettlePending || rec.Settle == nil || now.Sub(rec.UpdatedAt) < settlePendingGrace ||
			now.Add(reconcileSkew).After(box.SettlementDeadline()) {
			return reconcileWait
		}
		switch {
		case box.Status == escrow.StatusOpen:
			return reconcileResettle
		case box.Status == escrow.StatusPendingSettle && box.PendingBy == escrow.PendingByOperator && claimMatches(*rec.Settle, box):
			return reconcileResettle
		}
	}
	return reconcileWait
}

// claimMatches reports whether the operator's pending claim on box carries the
// values the payer's settle would send. The contract freezes the ticket on
// any difference.
func claimMatches(a SettleArgs, box *escrow.TicketRecord) bool {
	return a.AmountCharged == box.PendingAmount &&
		a.ReceiptDigest == box.PendingDigest &&
		a.TtftMs == box.PendingTtftMs &&
		a.DecodeMs == box.PendingDecodeMs &&
		a.InputTokens == box.PendingInputCount &&
		a.OutputTokens == box.PendingOutputCount &&
		uint64(a.OutputUsageType) == box.PendingOutputUsageType &&
		uint64(a.AuxOutputUsageType) == box.PendingAuxOutputUsageType &&
		a.AuxOutputCount == box.PendingAuxOutputCount
}

// ticketChain is what the sweep does on chain for one ticket. *Wallet
// provides it; tests fake it.
type ticketChain interface {
	readBox(ctx context.Context, ticketID string) (*escrow.TicketRecord, error)
	refund(ctx context.Context, rec TicketRecord) (string, error)
	lapse(ctx context.Context, rec TicketRecord, box *escrow.TicketRecord) (string, error)
	resettle(ctx context.Context, rec TicketRecord, box *escrow.TicketRecord) (string, error)
}

// reconciler finishes journaled tickets this process is not watching: those
// left by an earlier run, and those whose refund watchdog gave up. Each
// ticket has one driver at a time; a live ticket stays with the watchdog.
type reconciler struct {
	journal  TicketJournal
	chain    ticketChain
	payer    string
	appID    uint64
	watching func(ticketID string) bool
	log      *slog.Logger
	remedy   string // Remedies.RecoverTicket
	// release gives back the claim New took on journal, once closed.
	release func()
	// handOff is set when journal outlives the Client: Close then stops the
	// watchdog before releasing the claim, so the next sweeper owns the rows.
	handOff bool
	// spend learns how each ticket ended, so a reservation a restarted
	// SpendGuard restored frees its headroom then; nil when there is none.
	spend SpendGuard

	now           func() time.Time
	interval      time.Duration
	callTimeout   time.Duration
	lapseFallback time.Duration

	mu       sync.Mutex
	failures map[string]int
	// ctx is every chain and journal call's parent; close cancels it so a
	// wedged algod can't hold Client.Close for a call timeout.
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// spend is an argument rather than a field set later because start sweeps at
// once, and that first sweep is the one that finds what a restart left behind.
func newReconciler(journal TicketJournal, chain ticketChain, payer string, appID uint64, watching func(string) bool, spend SpendGuard, log *slog.Logger) *reconciler {
	ctx, cancel := context.WithCancel(context.Background())
	return &reconciler{
		journal:       journal,
		chain:         chain,
		payer:         payer,
		appID:         appID,
		watching:      watching,
		spend:         spend,
		log:           log,
		remedy:        Remedies{}.withDefaults().RecoverTicket,
		now:           time.Now,
		interval:      reconcileInterval,
		callTimeout:   30 * time.Second,
		lapseFallback: defaultLapseFallback,
		failures:      map[string]int{},
		ctx:           ctx,
		cancel:        cancel,
		done:          make(chan struct{}),
	}
}

// start sweeps at once, then every interval, until close.
func (r *reconciler) start() {
	go func() {
		defer close(r.done)
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			r.sweep()
			select {
			case <-r.ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// close stops the loop, cancelling any call in flight, and waits for it. Then
// it runs beforeRelease, if any, and gives up the journal claim: after a
// sweep can no longer act and before another Client may.
func (r *reconciler) close(beforeRelease func()) {
	r.cancel()
	<-r.done
	if beforeRelease != nil {
		beforeRelease()
	}
	if r.release != nil {
		r.release()
	}
}

// journalsSwept holds each journal a reconciler in this process sweeps. Two
// reconcilers over one journal each read the other Client's live tickets as
// nobody's, and both submit the same refund or lapse.
var journalsSwept sync.Map

// claimJournal reserves j for one reconciler, returning the release, or false
// when another holds it. A journal value that cannot key a map is not
// guarded; the type alone can't tell, since an interface field may hold a
// slice.
func claimJournal(j TicketJournal) (release func(), ok bool) {
	if !reflect.ValueOf(j).Comparable() {
		return func() {}, true
	}
	if _, taken := journalsSwept.LoadOrStore(j, struct{}{}); taken {
		return nil, false
	}
	return sync.OnceFunc(func() { journalsSwept.Delete(j) }), true
}

func (r *reconciler) stopped() bool { return r.ctx.Err() != nil }

// sweep acts once on every journaled ticket nobody else is driving. It never
// fails: whatever goes wrong is retried next sweep.
func (r *reconciler) sweep() {
	ctx, cancel := context.WithTimeout(r.ctx, r.callTimeout)
	recs, err := r.journal.List(ctx, r.payer, r.appID)
	cancel()
	if err != nil {
		r.log.Warn("ticket reconciler: journal read failed", slog.Any("err", err))
		return
	}
	for _, rec := range recs {
		if r.stopped() {
			return
		}
		if r.watching(rec.TicketID) || r.exhausted(rec.TicketID) {
			continue
		}
		r.reconcile(rec)
	}
}

func (r *reconciler) exhausted(ticketID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failures[ticketID] >= reconcileMaxFailures
}

func (r *reconciler) reconcile(rec TicketRecord) {
	ctx, cancel := context.WithTimeout(r.ctx, r.callTimeout)
	box, err := r.chain.readBox(ctx, rec.TicketID)
	cancel()
	if err != nil {
		r.log.Debug("ticket reconciler: box read failed; retrying next sweep",
			slog.String("ticket_id", rec.TicketID), slog.Any("err", err))
		return
	}
	action := decideTicket(rec, box, r.now(), r.lapseFallback)
	var submit func(context.Context) (string, error)
	switch action {
	case reconcileWait:
		return
	case reconcileForget:
		r.forget(rec, box)
		return
	case reconcileRefund:
		submit = func(ctx context.Context) (string, error) { return r.chain.refund(ctx, rec) }
	case reconcileLapse:
		submit = func(ctx context.Context) (string, error) { return r.chain.lapse(ctx, rec, box) }
	case reconcileResettle:
		submit = func(ctx context.Context) (string, error) { return r.chain.resettle(ctx, rec, box) }
	}
	ctx, cancel = context.WithTimeout(r.ctx, r.callTimeout)
	txid, err := submit(ctx)
	cancel()
	if err != nil && r.stopped() {
		return // cut off by close, not refused
	}
	if err == nil {
		// Kept until a later sweep finds the box gone: a submitted call is not
		// a confirmed one.
		r.log.Info("ticket reconciler: submitted "+action.String(),
			slog.String("ticket_id", rec.TicketID), slog.String("txid", txid))
		if r.spend != nil {
			// Once algod accepts a refund or a lapse no other outcome is
			// legal: no charge for a refund (see RefundWatchdog.refunded), the
			// operator's claim for a lapse. A journaled receipt means the
			// request path already counted its charge, so a lapse only drops
			// what reservation is left, rather than counting a second charge.
			switch {
			case action == reconcileRefund, action == reconcileLapse && rec.Settle != nil:
				r.spend.Release(rec.TicketID)
			case action == reconcileLapse:
				r.spend.Settle(rec.TicketID, box.PendingAmount)
			}
		}
		return
	}
	r.mu.Lock()
	r.failures[rec.TicketID]++
	n := r.failures[rec.TicketID]
	r.mu.Unlock()
	if n >= reconcileMaxFailures {
		r.log.Warn("ticket reconciler: "+action.String()+" keeps failing; leaving the ticket for the next start",
			slog.String("ticket_id", rec.TicketID), slog.Int("attempts", n), slog.Any("err", err), slog.String("remedy", r.remedy))
		return
	}
	r.log.Debug("ticket reconciler: "+action.String()+" failed; retrying next sweep",
		slog.String("ticket_id", rec.TicketID), slog.Int("attempt", n), slog.Any("err", err))
}

// journalTimeout bounds one journal write on the request path.
const journalTimeout = 5 * time.Second

// journalOpen records a ticket whose escrow just opened. A failed write is
// logged, not returned: the USDC is already locked, and the watchdog still
// drives the ticket while this process runs.
func (s *Client) journalOpen(h *OpenHandle, t *ticket.Ticket) {
	if s.journal == nil || h == nil {
		return
	}
	now := time.Now()
	h.journaled = TicketRecord{
		TicketID:    t.TicketID,
		OpenTxID:    h.AppCallTxID,
		EscrowAppID: s.cfg.Network.EscrowAppID,
		Target:      RefOf(h.Operator),
		Payer:       s.wallet.PayerAddr(),
		MaxPrice:    t.MaxPrice,
		ExpiresAt:   time.Unix(t.ExpiresAt, 0),
		Status:      TicketOpen,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	s.journalPut(h.journaled)
}

// journalReceipt records the values the payer will co-sign for a verified
// receipt, before the settle is submitted, so a restart mid-submit can still
// re-fire it.
func (s *Client) journalReceipt(handle settlementHandle, receipt *ticket.UsageReceipt) {
	h, ok := handle.(*OpenHandle)
	if !ok || s.journal == nil || h.journaled.TicketID == "" {
		return
	}
	rec := h.journaled
	a := settleArgsOf(receipt)
	rec.Status, rec.Settle, rec.UpdatedAt = TicketSettlePending, &a, time.Now()
	s.journalPut(rec)
}

func (s *Client) journalPut(rec TicketRecord) {
	ctx, cancel := context.WithTimeout(context.Background(), journalTimeout)
	defer cancel()
	if err := s.journal.Put(ctx, rec); err != nil {
		s.log.Warn("ticket journal write failed; a restart before this ticket settles leaves it to its refund deadline",
			slog.String("ticket_id", rec.TicketID), slog.Any("err", err))
	}
}

func (r *reconciler) forget(rec TicketRecord, box *escrow.TicketRecord) {
	if box != nil {
		// Frozen: no contract call accepts it, and the escrowed USDC and the
		// MBR slot stay locked until arbitration. The reservation stays too.
		r.log.Warn("ticket reconciler: ticket is frozen; leaving it to arbitration",
			slog.String("ticket_id", rec.TicketID))
	} else if rec.Settle != nil && r.spend != nil {
		// Closed, with a verified receipt. The request path settles before it
		// journals the receipt, so the charge is already counted; a
		// reservation still open here survived a crash between the guard's
		// two writes, and settling it again would count the charge twice.
		// With no receipt nothing here says what the ticket cost, so its
		// reservation ages out.
		r.spend.Release(rec.TicketID)
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.callTimeout)
	defer cancel()
	if err := r.journal.Delete(ctx, rec.TicketID); err != nil {
		r.log.Warn("ticket reconciler: journal delete failed", slog.String("ticket_id", rec.TicketID), slog.Any("err", err))
	}
}
