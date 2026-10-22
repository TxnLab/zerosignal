/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"reflect"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/settle"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
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
	// reconcileFreeze is the payer's settle() at the row's receipt, sent
	// because it will mismatch the operator's claim, and paid for the freeze
	// it causes.
	reconcileFreeze
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
	case reconcileFreeze:
		return "freeze"
	}
	return "wait"
}

// ClaimVerdict is how the operator's pending settle claim on a ticket stands
// against the payer's own verified receipt for it.
type ClaimVerdict string

const (
	// ClaimUnread: the payer did not read the ticket, because the ack went
	// through the node's settle group, whose checks already compare the
	// node's half with the receipt.
	ClaimUnread ClaimVerdict = ""
	// ClaimUnreadable: the box read failed. The ack goes out anyway, since a
	// failed read is no evidence against the claim.
	ClaimUnreadable ClaimVerdict = "unreadable"
	// ClaimNone: no operator claim stands, and none can be answered. The box
	// is gone, frozen, or carries the payer's own half.
	ClaimNone ClaimVerdict = "none"
	// ClaimOpen: the box is open, with neither side's half on it. The payer's
	// half at the receipt is the first, and an operator half that differs
	// from it then freezes the ticket instead of lapsing at the operator's
	// figure.
	ClaimOpen ClaimVerdict = "open"
	// ClaimAgrees: the claim carries every value the payer's settle sends, so
	// that settle finalizes the ticket.
	ClaimAgrees ClaimVerdict = "agrees"
	// ClaimOverclaims: the claim takes more than the receipt charges. The
	// payer's settle freezes the ticket. Left alone, the claim is paid in full
	// by settleLapsed after the deadline.
	ClaimOverclaims ClaimVerdict = "overclaims"
	// ClaimContradicts: the claim differs from the receipt but takes no more
	// than it, through a lower amount or the same amount with another digest
	// or usage value. A settle would freeze the payer's own escrow and pool
	// slot for nothing, so the payer leaves the claim to lapse at the
	// operator's figure.
	ClaimContradicts ClaimVerdict = "contradicts"
)

// judgeClaim compares the operator's pending claim on box (nil when gone) with
// the payer's settle args. Only the amount separates an over-claim from a
// contradiction: a timing or usage difference moves the operator's own
// on-chain aggregates, not the payer's money.
func judgeClaim(a SettleArgs, box *escrow.TicketRecord) ClaimVerdict {
	if box == nil {
		return ClaimNone
	}
	return weighClaim(box.View().Status, box.PendingAmount, a.AmountCharged, claimMatches(a, box))
}

// judgeSolanaClaim is judgeClaim for a Solana ticket account (nil when
// closed). The account keeps the first half's hash, not its fields, so a
// claim matches when the payer's own fields hash to it.
func judgeSolanaClaim(a SettleArgs, t *zsescrow.Ticket) ClaimVerdict {
	if t == nil {
		return ClaimNone
	}
	return weighClaim(t.View().Status, t.PendingAmount, a.AmountCharged, zsescrow.ClaimHash(solanaClaimFields(a)) == t.ClaimHash)
}

// weighClaim is the verdict on a ticket of status carrying an operator claim
// of pending, against a receipt charging charged that the claim matches in
// full or not.
func weighClaim(status settle.Status, pending, charged uint64, matches bool) ClaimVerdict {
	switch status {
	case settle.StatusOpen:
		return ClaimOpen
	case settle.StatusPendingOperator:
	default:
		return ClaimNone
	}
	switch {
	case pending > charged:
		return ClaimOverclaims
	case matches:
		return ClaimAgrees
	}
	return ClaimContradicts
}

// solanaClaimFields are the claim fields the payer's half carries for a.
func solanaClaimFields(a SettleArgs) zsescrow.ClaimFields {
	return zsescrow.ClaimFields{
		Amount:          a.AmountCharged,
		ReceiptDigest:   a.ReceiptDigest,
		TTFTMs:          a.TtftMs,
		DecodeMs:        a.DecodeMs,
		InputUnits:      a.InputTokens,
		OutputUnits:     a.OutputTokens,
		OutputUsageType: uint8(a.OutputUsageType),
		AuxUsageType:    uint8(a.AuxOutputUsageType),
		AuxCount:        a.AuxOutputCount,
	}
}

// decideTicket is decideSettlement for a ZeroSignalEscrow box (nil when gone).
func decideTicket(rec TicketRecord, box *escrow.TicketRecord, now time.Time, lapseFallback time.Duration) reconcileAction {
	if box == nil {
		return decideSettlement(rec, nil, ClaimUnread, now, lapseFallback)
	}
	view := box.View()
	claim := ClaimUnread
	if a := rec.signedArgs(); a != nil {
		claim = judgeClaim(*a, box)
	}
	return decideSettlement(rec, &view, claim, now, lapseFallback)
}

// decideSettlement is what the sweep does about one journaled ticket, given
// its rail-neutral view (nil when gone), how the operator's pending claim
// stands against the receipt the row records, and the time. The contract's
// rules come from settle.Classify; what this adds is the payer's own receipt:
//
//   - A settle is legal only inside the window, so a verified receipt is
//     re-fired there: against an open ticket, or one carrying the operator's
//     claim when the claim matches the receipt.
//   - A claim that takes more than a receipt the node signed, verified or
//     not, is frozen with the receipt's settle inside the window, and the
//     payer never lapses it after.
//   - Past the window any other operator claim goes to settleLapsed, but only
//     once lapseFallback has passed, since the node's own driver normally does
//     it.
//   - A missing ticket is finished only once it has expired: the open is
//     submitted without waiting for confirmation, and the contract accepts it
//     until expires_at.
func decideSettlement(rec TicketRecord, t *settle.Ticket, claim ClaimVerdict, now time.Time, lapseFallback time.Duration) reconcileAction {
	if t == nil {
		if now.After(rec.ExpiresAt.Add(reconcileSkew)) {
			return reconcileForget
		}
		return reconcileWait
	}
	switch settle.Classify(*t, now.Add(-reconcileSkew)) {
	case settle.VerdictArbitrate:
		return reconcileForget
	case settle.VerdictRefund:
		return reconcileRefund
	case settle.VerdictLapse:
		// The operator can still lapse it, since settleLapsed is
		// permissionless; the payer only declines to pay the fee for a payout
		// its receipt contradicts.
		if claim != ClaimOverclaims && now.After(t.DeadlineTime().Add(lapseFallback)) {
			return reconcileLapse
		}
		return reconcileWait
	case settle.VerdictWait:
		if now.Add(reconcileSkew).After(t.DeadlineTime()) {
			return reconcileWait
		}
		// Ahead of the grace: the grace waits out a live ack still confirming,
		// and every half the payer signs carries the receipt's amount, so no
		// such ack can be what left an over-claim on the box. Waiting would
		// only spend window the freeze has to land in.
		if t.Status == settle.StatusPendingOperator && claim == ClaimOverclaims {
			return reconcileFreeze
		}
		if rec.Status != TicketSettlePending || rec.Settle == nil || now.Sub(rec.UpdatedAt) < settlePendingGrace {
			return reconcileWait
		}
		switch {
		case t.Status == settle.StatusOpen:
			return reconcileResettle
		case t.Status == settle.StatusPendingOperator && claim == ClaimAgrees:
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
	// freeze sends the payer's settle at a, against an operator claim on box
	// that takes more.
	freeze(ctx context.Context, rec TicketRecord, box *escrow.TicketRecord, a SettleArgs) (string, error)
	// freezes is whether the deployed escrow has resolveFrozen. Without it
	// freeze is never called: the frozen escrow would be locked for good.
	freezes() bool
}

// reconciler finishes journaled tickets this process is not watching: those
// left by an earlier run, and those whose refund watchdog gave up. Each
// ticket has one driver at a time; a live ticket stays with the watchdog,
// except for a freeze. The watchdog acts only past the deadline and the live
// ack reads the box once, so an over-claim the node posts after that read, or
// after the ack failed, would otherwise lapse.
type reconciler struct {
	journal    TicketJournal
	chain      ticketChain
	payer      string
	deployment Deployment
	watching   func(ticketID string) bool
	log        *slog.Logger
	remedy     string // Remedies.RecoverTicket
	// release gives back the claim New took on journal, once closed.
	release func()
	// handOff is set when journal outlives the Client: Close then stops the
	// watchdog before releasing the claim, so the next sweeper owns the rows.
	handOff bool
	// spend learns how each ticket ended, so a reservation a restarted
	// SpendGuard restored frees its headroom then; nil when there is none.
	spend SpendGuard
	// overclaimed hears of each ticket whose box carries an operator claim
	// above the receipt its row records, every sweep that reads one, so the
	// node is barred though the live ack never saw the claim: posted after
	// its read, or after a restart. Nil when nothing bars nodes.
	overclaimed func(rec TicketRecord)

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
func newReconciler(journal TicketJournal, chain ticketChain, payer string, d Deployment, watching func(string) bool, spend SpendGuard, log *slog.Logger) *reconciler {
	ctx, cancel := context.WithCancel(context.Background())
	return &reconciler{
		journal:       journal,
		chain:         chain,
		payer:         payer,
		deployment:    d,
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
	// A claim never given back bars every later Client from sweeping this
	// journal, so it goes even if beforeRelease panics.
	if r.release != nil {
		defer r.release()
	}
	if beforeRelease != nil {
		beforeRelease()
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

// journalPathsOpen holds the Stores.JournalPath files Clients in this process
// have open, by absolute path. The file lock alone cannot tell another Client
// here from another process.
var journalPathsOpen sync.Map

func journalPathKey(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// claimJournalPath reports false when another Client in this process has path
// open.
func claimJournalPath(path string) bool {
	_, taken := journalPathsOpen.LoadOrStore(journalPathKey(path), struct{}{})
	return !taken
}

func releaseJournalPath(path string) { journalPathsOpen.Delete(journalPathKey(path)) }

func (r *reconciler) stopped() bool { return r.ctx.Err() != nil }

// sweep acts once on every journaled ticket nobody else is driving. It never
// fails: whatever goes wrong is retried next sweep.
func (r *reconciler) sweep() {
	defer r.recoverHook()
	ctx, cancel := context.WithTimeout(r.ctx, r.callTimeout)
	recs, err := r.journal.List(ctx, r.payer, r.deployment)
	cancel()
	if err != nil {
		r.log.Warn("ticket reconciler: journal read failed", slog.Any("err", err))
		return
	}
	for _, rec := range recs {
		if r.stopped() {
			return
		}
		if r.exhausted(rec.TicketID) {
			continue
		}
		// A watched row is read only when it records a receipt, the one case
		// a freeze can come of, and only on an escrow that can resolve one.
		watched := r.watching(rec.TicketID)
		if watched && (rec.signedArgs() == nil || !r.chain.freezes()) {
			continue
		}
		r.reconcileRow(rec, watched)
	}
}

// reconcileRow keeps a panic in one row, from the journal or chain code the
// host supplied, from ending the sweep goroutine and with it the process. It
// counts as a failed attempt, so a row that always panics is given up on.
func (r *reconciler) reconcileRow(rec TicketRecord, watched bool) {
	defer func() {
		if p := recover(); p != nil {
			r.failed(rec, "reconcile", fmt.Errorf("panic: %v", p))
		}
	}()
	r.reconcile(rec, watched)
}

// recoverHook keeps a panicking journal List from ending the sweep goroutine.
func (r *reconciler) recoverHook() {
	if p := recover(); p != nil {
		r.log.Error("ticket reconciler: journal read panicked; retrying next sweep", slog.Any("panic", p))
	}
}

func (r *reconciler) exhausted(ticketID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failures[ticketID] >= reconcileMaxFailures
}

// reconcile acts on rec. A watched ticket gets a freeze or nothing: every
// other call is its watchdog's.
func (r *reconciler) reconcile(rec TicketRecord, watched bool) {
	ctx, cancel := context.WithTimeout(r.ctx, r.callTimeout)
	box, err := r.chain.readBox(ctx, rec.TicketID)
	cancel()
	if err != nil {
		r.log.Debug("ticket reconciler: box read failed; retrying next sweep",
			slog.String("ticket_id", rec.TicketID), slog.Any("err", err))
		return
	}
	action := decideTicket(rec, box, r.now(), r.lapseFallback)
	if a := rec.signedArgs(); a != nil && r.overclaimed != nil && judgeClaim(*a, box) == ClaimOverclaims {
		r.overclaimed(rec)
	}
	if action == reconcileFreeze && !r.chain.freezes() {
		// No freeze, and still no lapse: decideSettlement never lapses an
		// over-claim, which the operator can lapse itself.
		action = reconcileWait
	}
	if watched && action != reconcileFreeze {
		return
	}
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
	case reconcileFreeze:
		// The receipt's values, not the box's: settling at the claim's own
		// figure would match it and pay it.
		submit = func(ctx context.Context) (string, error) { return r.chain.freeze(ctx, rec, box, *rec.signedArgs()) }
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
		if action == reconcileFreeze {
			// Warn: the escrow now goes to arbitration rather than settlement,
			// on the operator's doing.
			r.log.Warn("ticket reconciler: operator's settle claim exceeds its signed receipt; submitted the receipt's settle to freeze the ticket",
				slog.String("ticket_id", rec.TicketID), slog.String("txid", txid),
				slog.Uint64("claimed_microusdc", box.PendingAmount), slog.Uint64("receipt_microusdc", rec.signedArgs().AmountCharged))
			return
		}
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
				recordSpend(r.log, "release", rec.TicketID, func() { r.spend.Release(rec.TicketID) })
			case action == reconcileLapse:
				recordSpend(r.log, "settle", rec.TicketID, func() { r.spend.Settle(rec.TicketID, box.PendingAmount) })
			}
		}
		return
	}
	r.failed(rec, action.String(), err)
}

func (r *reconciler) failed(rec TicketRecord, what string, err error) {
	r.mu.Lock()
	r.failures[rec.TicketID]++
	n := r.failures[rec.TicketID]
	r.mu.Unlock()
	if n >= reconcileMaxFailures {
		r.log.Warn("ticket reconciler: "+what+" keeps failing; leaving the ticket for the next start",
			slog.String("ticket_id", rec.TicketID), slog.Int("attempts", n), slog.Any("err", err), slog.String("remedy", r.remedy))
		return
	}
	r.log.Debug("ticket reconciler: "+what+" failed; retrying next sweep",
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
		EscrowAppID: s.deployment.EscrowAppID,
		Deployment:  s.deployment.Key(),
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

// journalSigned records a receipt whose signature verified but that failed a
// later check, on the row's open status: the payer settles nothing from it,
// but the reconciler holds an operator claim against its amount, after a
// restart as before one.
func (s *Client) journalSigned(handle settlementHandle, receipt *ticket.UsageReceipt) {
	h, ok := handle.(*OpenHandle)
	if !ok || s.journal == nil || h.journaled.TicketID == "" {
		return
	}
	rec := h.journaled
	a := settleArgsOf(receipt)
	rec.Signed, rec.UpdatedAt = &a, time.Now()
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
		// Frozen: only the admin's resolveFrozen can close it, so the escrowed
		// USDC and the MBR slot stay locked until the arbiter acts, and
		// nothing the payer can call applies. The spend reservation is left
		// open: it outlives a resolveFrozen refund until it ages out.
		r.log.Warn("ticket reconciler: ticket is frozen; leaving it to arbitration",
			slog.String("ticket_id", rec.TicketID))
	} else if rec.Settle != nil && r.spend != nil {
		// Closed, with a verified receipt. The request path settles before it
		// journals the receipt, so the charge is already counted; a
		// reservation still open here survived a crash between the guard's
		// two writes, and settling it again would count the charge twice.
		// With no receipt nothing here says what the ticket cost, so its
		// reservation ages out.
		recordSpend(r.log, "release", rec.TicketID, func() { r.spend.Release(rec.TicketID) })
	}
	ctx, cancel := context.WithTimeout(r.ctx, r.callTimeout)
	defer cancel()
	if err := r.journal.Delete(ctx, rec.TicketID); err != nil {
		r.log.Warn("ticket reconciler: journal delete failed", slog.String("ticket_id", rec.TicketID), slog.Any("err", err))
	}
}
