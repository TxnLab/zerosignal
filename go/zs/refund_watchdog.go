/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
)

// RefundWatchdog recovers escrowed USDC for tickets whose settlement never
// arrived. The proxy submits the open() group *before* the node's admission
// check runs, so a post-open failure — the node burning the ticket on a
// payment-verification error, a transport failure mid-request, an operator
// that dies before settling — leaves max_price locked in the ticket box with
// nobody driving a settle. The contract's escape hatch is refundInactive
// (SPEC.md §3a "Settlement windows"): after D = expires_at + grace, anyone
// may refund a ticket with no pending operator claim. The node has no ledger
// row for a request it refused, so the payer is the only party that KNOWS
// the ticket was orphaned — this watchdog is that knowledge acting.
//
// Lifecycle: Track every successful Open; Resolve when settlement definitely
// finalized (atomic settle group landed) or the ticket froze via protest
// (refundInactive would revert on FROZEN). Everything still tracked at
// D + margin gets a ticket-box read: box gone (settled/lapsed by the node's
// driver) is a cheap no-op; a FROZEN box is left to arbitration; a box
// carrying an OPERATOR-side pending claim is left to the node's settleLapsed
// (refundInactive is not legal on it — see below); a live box whose own
// expires_at + settlement_grace_seconds deadline is still in the future
// re-arms the timer to that on-chain value — the box is the authoritative
// window, so a locally-computed deadline that ran early (the cached `grace`
// global was rotated, or an open() carried a window our verification missed)
// waits instead of burning retries on guaranteed "refund before deadline"
// reverts. Otherwise refundInactive is attempted.
//
// The pending-claim side decides which deadline path is legal, and the two are
// disjoint (contract: refundInactive vs settleLapsed). A standalone
// (non-atomic) PAYER ack stays tracked on purpose: it leaves a pending payer
// claim the operator must still match, and refundInactive is exactly the
// deadline path for a payer claim the operator never acked. An OPERATOR-side
// claim is the mirror image — the contract sends it to settleLapsed and
// asserts 'ticket not refundable' against refundInactive — so the watchdog
// must read pending_by, not just "box still there", before attempting.
// Operator-pending hands off to driveLapse, which defers to the node's own
// settleLapsed and only posts one itself if the node never does.
//
// State is in-memory only. A ticket outlives a restart through the journal
// (Stores.Journal): the reconciler picks up any row the watchdog is not
// watching. With the in-memory default journal, a restart leaves the escrowed
// USDC to a manual refundInactive (the ticket id is in the logs).
type RefundWatchdog struct {
	log *slog.Logger

	// margin pads the on-chain deadline D before the first attempt so a
	// small skew between local clock and Global.latestTimestamp doesn't
	// produce a guaranteed "refund before deadline" revert.
	margin time.Duration
	// retryDelay spaces the bounded re-attempts after a failed refund
	// (deadline skew, transient algod error).
	retryDelay time.Duration
	// attempts bounds total refundInactive (or settleLapsed) tries per ticket.
	attempts int
	// callTimeout bounds ONE algod round trip — each probe and each submit gets
	// its own (see probeOnce), never a shared budget.
	callTimeout time.Duration
	// lapseFallback is how long past the on-chain deadline the watchdog waits
	// for the node's driver to finalize its own pending claim before posting
	// settleLapsed itself. It must clear the node's whole lapse schedule, not
	// just the contract deadline: the node lapses at expires_at +
	// LapseGraceSeconds (default 5m) — which can sit well AFTER the contract's
	// own expires_at + settlement_grace_seconds — and then retries up to 5
	// times. Undershooting doesn't corrupt anything (the loser of the race
	// reverts on the deleted box), it just spends a fee racing a node that was
	// going to succeed, so this is deliberately generous.
	lapseFallback time.Duration
	// remedy is Remedies.RecoverTicket. The box outlives this process, so a
	// give-up log that names only the ticket id is a dead end.
	remedy string

	mu      sync.Mutex
	pending map[string]chan struct{} // ticket_id → cancel signal
	// handedOff is set by handOff: Track arms nothing more.
	handedOff bool
	// refunded hears each ticket a refundInactive was submitted for; nil
	// when nothing listens. Submitted is enough: algod accepts the call only
	// past the settlement deadline and with no operator claim on the box, so
	// no charge can land after it, and the only call that can beat it to the
	// box is another refund.
	refunded func(ticketID string)
	// running counts the per-ticket goroutines, which handOff waits out.
	running sync.WaitGroup
}

// NewRefundWatchdog constructs a watchdog with production timing defaults.
func NewRefundWatchdog(log *slog.Logger) *RefundWatchdog {
	if log == nil {
		log = slog.Default()
	}
	return &RefundWatchdog{
		log:           log,
		margin:        15 * time.Second,
		retryDelay:    60 * time.Second,
		attempts:      3,
		callTimeout:   30 * time.Second,
		lapseFallback: 10 * time.Minute,
		remedy:        Remedies{}.withDefaults().RecoverTicket,
		pending:       map[string]chan struct{}{},
	}
}

// probeOnce runs one box read under its own timeout, and callOnce one on-chain
// submit under its own.
//
// Each network call gets a fresh budget on purpose. Sharing a single deadline
// across the probe AND the submit that follows it lets a degraded algod spend
// the whole window on the read, leaving the submit to fail instantly on a
// nearly-dead context — burning an attempt for a reason that has nothing to do
// with the ticket, and exhausting the budget precisely when the chain is slow,
// which is when the watchdog is most needed. The submit is the expensive half
// (ComposeSettleLapsed re-reads the box, gathers params, then waits for
// confirmation), so it must not inherit whatever the probe left over.
//
// A probe also ends when the ticket's cancel closes. A submit does not: once
// it may have reached algod, handOff waits for its answer, so the next
// sweeper reads the outcome rather than racing it. callOnce refuses to start
// one after cancel.
func (rw *RefundWatchdog) probeOnce(cancel <-chan struct{}, probe func(context.Context) (ticketProbe, error)) (ticketProbe, error) {
	ctx, stop := context.WithTimeout(context.Background(), rw.callTimeout)
	defer stop()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-cancel:
			stop()
		case <-done:
		}
	}()
	return probe(ctx)
}

func (rw *RefundWatchdog) callOnce(cancel <-chan struct{}, call func(context.Context) (string, error)) (string, error) {
	select {
	case <-cancel:
		return "", errCancelled
	default:
	}
	ctx, stop := context.WithTimeout(context.Background(), rw.callTimeout)
	defer stop()
	return call(ctx)
}

// errCancelled is callOnce's answer once the ticket was resolved or handed
// off; the loops return on it rather than retry.
var errCancelled = errors.New("refund watchdog: cancelled")

// probeState renders what the last box read actually told us, for a give-up log.
// On a probe error there is NO on-chain state to report — the attempt went ahead
// under the "a revert is cheap and the error may be transient" rule — so say so
// rather than print a zero verdict and a year-1 deadline as if they'd been read
// off the box. Probe and submit usually fail for the same reason (algod down),
// so this is the common give-up path, not a corner.
func probeState(res ticketProbe, err error) slog.Attr {
	if err != nil {
		return slog.Group("probe", slog.Any("err", err))
	}
	return slog.Group("probe",
		slog.String("verdict", res.verdict.String()),
		slog.Time("deadline", res.deadline),
	)
}

// ticketProbe is the fire-time snapshot of a tracked ticket's on-chain box.
type ticketProbe struct {
	// exists is false when the box is gone — settled or lapsed elsewhere.
	exists bool
	// verdict is which deadline call the contract allows on this box right now
	// (escrow.Classify). VerdictArbitrate (frozen) and VerdictLapse (an
	// operator-side claim, which refundInactive asserts 'ticket not refundable'
	// against) are both terminal for the refund path: neither state has an edge
	// back to one refundInactive accepts, so no retry can make it legal.
	// VerdictWait means the box's own deadline is still ahead — the re-arm
	// below, not a reason to stop.
	verdict escrow.Verdict
	// deadline is the box's own refundInactive deadline
	// D = expires_at + settlement_grace_seconds — the authoritative value,
	// unlike the Track-time computation from the cached grace default.
	deadline time.Time
}

// Track arms a deferred refundInactive for the ticket behind h, firing at
// expires_at + settlement grace + margin unless Resolve is called first.
// Nil-safe on every input so test fakes (detached handles) and wiring
// without a watchdog are no-ops.
func (rw *RefundWatchdog) Track(h *OpenHandle, expiresAt int64) {
	if rw == nil || h == nil || h.wallet == nil || h.wallet.chain == nil {
		return
	}
	chain := h.wallet.chain
	ticketIDRaw, err := decodeTicketID(h.TicketID)
	if err != nil {
		rw.log.Warn("refund watchdog: undecodable ticket id; not tracking",
			slog.String("ticket_id", h.TicketID), slog.Any("err", err))
		return
	}
	grace := time.Duration(chain.Config().SettlementGraceDefault) * time.Second
	deadline := time.Unix(expiresAt, 0).Add(grace + rw.margin)
	probe := func(ctx context.Context) (ticketProbe, error) {
		rec, err := chain.ReadTicketBox(ctx, ticketIDRaw)
		if err != nil {
			return ticketProbe{}, err
		}
		if rec == nil {
			return ticketProbe{exists: false}, nil
		}
		return ticketProbe{
			exists:   true,
			verdict:  escrow.Classify(rec, time.Now()),
			deadline: rec.SettlementDeadline(),
		}, nil
	}
	refund := func(ctx context.Context) (string, error) {
		return h.RefundInactive(ctx)
	}
	lapse := func(ctx context.Context) (string, error) {
		return h.SettleLapsed(ctx)
	}
	rw.track(h.TicketID, deadline, probe, refund, lapse)
}

// driveLapse is the payer-side backstop for a ticket parked in PENDING_SETTLE
// with an operator-side claim, where refundInactive is illegal by construction.
// Recovering the payer's share of max_price depends on SOMEONE posting
// settleLapsed; normally the node's own driver does, so this waits out that
// whole schedule (lapseFallback) and re-probes before spending anything. If the
// box is gone by then — the overwhelmingly common case — the node did its job
// and this costs one box read. If it's still parked, the node is stalled (dead
// after its claim confirmed, ledger lost, or lapse-retries exhausted) and
// nobody else will ever move it, so the payer posts settleLapsed itself: it is
// permissionless, and it returns max_price minus the operator's claim.
//
// Driven unconditionally, even when the operator's claim eats the whole
// max_price and the USDC refund would be 0 — settling is still strictly better
// than leaving the box parked, because finalizing is what decrements
// openTickets(payer). A parked ticket holds one prepaid-MBR-pool slot out of
// the payer's bounded working set forever AND blocks closeDeposit ('tickets
// still open'), so the ALGO is what's really being recovered in that case.
//
// Runs on the tracking goroutine (Resolve still cancels it) and shares the
// refund path's attempt bound, so a stalled ticket costs a bounded number of
// tries either way.
func (rw *RefundWatchdog) driveLapse(ticketID string, cancel <-chan struct{}, probe func(context.Context) (ticketProbe, error), lapse func(context.Context) (string, error)) {
	select {
	case <-cancel:
		return
	case <-time.After(rw.lapseFallback):
	}

	for attempt := 1; ; attempt++ {
		// No deadline re-arm here, unlike the refund loop: driveLapse is only
		// reached once the box's own deadline has already passed (Classify only
		// says Lapse past it), and that deadline is immutable once written — so
		// there is no "on-chain window still ahead" case left to wait out.
		res, perr := rw.probeOnce(cancel, probe)
		if perr == nil {
			switch {
			case !res.exists:
				// The node's driver finalized it, as expected.
				rw.log.Debug("refund watchdog: operator-pending ticket finalized by the node",
					slog.String("ticket_id", ticketID))
				return
			case res.verdict == escrow.VerdictArbitrate:
				rw.log.Info("refund watchdog: ticket froze while awaiting settleLapsed; leaving to arbitration",
					slog.String("ticket_id", ticketID))
				return
			case res.verdict == escrow.VerdictUnknown:
				// These bindings can't classify the box, so settleLapsed is a
				// guess. Don't spend fees on it.
				rw.log.Warn("refund watchdog: unrecognized ticket state, likely a contract newer than these escrow bindings; not attempting settleLapsed — upgrade before acting on this ticket",
					slog.String("ticket_id", ticketID))
				return
			}
		}
		// Box still parked past the node's own lapse schedule (or the probe
		// errored — try anyway; a revert is cheap and the error may be
		// transient).
		txid, lerr := rw.callOnce(cancel, lapse)
		if errors.Is(lerr, errCancelled) {
			return
		}
		if lerr == nil {
			rw.log.Info("refund watchdog: finalized a stalled operator claim via settleLapsed",
				slog.String("ticket_id", ticketID),
				slog.String("txid", txid))
			return
		}
		if attempt >= rw.attempts {
			rw.log.Warn("refund watchdog: settleLapsed failed; giving up",
				slog.String("ticket_id", ticketID),
				slog.String("remedy", rw.remedy),
				slog.Int("attempts", attempt),
				slog.Any("err", lerr),
				probeState(res, perr))
			return
		}
		rw.log.Debug("refund watchdog: settleLapsed attempt failed; retrying",
			slog.String("ticket_id", ticketID),
			slog.Int("attempt", attempt),
			slog.Any("err", lerr))
		select {
		case <-cancel:
			return
		case <-time.After(rw.retryDelay):
		}
	}
}

// Resolve cancels a pending probe: settlement finalized (box deleted) or the
// ticket froze via protest (refundInactive would revert). Unknown ids are a
// no-op — Resolve races the probe's own completion harmlessly.
func (rw *RefundWatchdog) Resolve(ticketID string) {
	if rw == nil {
		return
	}
	rw.mu.Lock()
	cancel, ok := rw.pending[ticketID]
	if ok {
		delete(rw.pending, ticketID)
	}
	rw.mu.Unlock()
	if ok {
		close(cancel)
	}
}

// handOff cancels every armed ticket and arms no more, leaving them to the
// reconciler that next sweeps a durable journal. Both driving one ticket
// submit the same refund or lapse, and the loser pays a fee for a revert.
func (rw *RefundWatchdog) handOff() {
	rw.mu.Lock()
	rw.handedOff = true
	pending := rw.pending
	rw.pending = map[string]chan struct{}{}
	rw.mu.Unlock()
	for _, cancel := range pending {
		close(cancel)
	}
	// A submit already sent finishes first, for up to callTimeout: released
	// sooner, the next sweeper would submit the same call alongside it.
	rw.running.Wait()
}

// watching reports whether the watchdog is still driving ticketID: armed and
// not yet resolved, settled or given up.
func (rw *RefundWatchdog) watching(ticketID string) bool {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	_, ok := rw.pending[ticketID]
	return ok
}

// track is the injectable core (tests supply fake probe/refund closures and
// short timings). One goroutine per tracked ticket, bounded by the ticket's
// own lifetime (TTL + grace, minutes).
func (rw *RefundWatchdog) track(ticketID string, deadline time.Time, probe func(context.Context) (ticketProbe, error), refund func(context.Context) (string, error), lapse func(context.Context) (string, error)) {
	cancel := make(chan struct{})
	rw.mu.Lock()
	if rw.handedOff {
		rw.mu.Unlock()
		return
	}
	if _, dup := rw.pending[ticketID]; dup {
		rw.mu.Unlock()
		return // already tracked (shouldn't happen — ticket ids are single-use)
	}
	rw.pending[ticketID] = cancel
	rw.running.Add(1)
	rw.mu.Unlock()

	go func() {
		defer rw.running.Done()
		// The refunded hook is the host's; its panic must not end the process.
		defer func() {
			if p := recover(); p != nil {
				rw.log.Error("refund watchdog: ticket driver panicked",
					slog.String("ticket_id", ticketID), slog.Any("panic", p))
			}
		}()
		// Entry stays in the map through the retry loop so Resolve can still
		// cancel mid-retry; cleaned up on exit. Resolve is the only closer of
		// the channel (delete+close under the lock), so there's no double-close.
		defer func() {
			rw.mu.Lock()
			delete(rw.pending, ticketID)
			rw.mu.Unlock()
		}()
		timer := time.NewTimer(time.Until(deadline))
		defer timer.Stop()
		select {
		case <-cancel:
			return
		case <-timer.C:
		}

		for attempt := 1; ; attempt++ {
			res, perr := rw.probeOnce(cancel, probe)
			if perr == nil {
				switch {
				case !res.exists:
					// Settled or lapsed by the operator's driver after we lost
					// sight of it — the normal benign outcome for a tracked
					// ticket whose ack path failed.
					rw.log.Debug("refund watchdog: ticket box already gone (settled elsewhere)",
						slog.String("ticket_id", ticketID))
					return
				case res.verdict == escrow.VerdictArbitrate:
					// refundInactive reverts on FROZEN — only the admin's
					// resolveFrozen closes it, nothing for the watchdog to do.
					rw.log.Info("refund watchdog: ticket is frozen (dispute); leaving to arbitration",
						slog.String("ticket_id", ticketID))
					return
				case res.verdict == escrow.VerdictLapse:
					// The operator got a settle claim in after we lost sight of
					// the ticket (its standalone-settle watchdog fired because
					// our ack never landed). Not an orphaned ticket, and not
					// refundable: the contract asserts 'ticket not refundable'
					// here and routes the claim to settleLapsed instead.
					// Retrying refundInactive can never help (see ticketProbe).
					rw.log.Info("refund watchdog: operator has a pending settle claim; refundInactive is not legal — deferring to the node's settleLapsed",
						slog.String("ticket_id", ticketID))
					rw.driveLapse(ticketID, cancel, probe, lapse)
					return
				case res.verdict == escrow.VerdictUnknown:
					// These bindings can't classify the box, so refundInactive
					// is a guess. Don't spend fees on it.
					rw.log.Warn("refund watchdog: unrecognized ticket state, likely a contract newer than these escrow bindings; not attempting refundInactive — upgrade before acting on this ticket",
						slog.String("ticket_id", ticketID))
					return
				}
				if wait := time.Until(res.deadline.Add(rw.margin)); wait > 0 {
					// The box's own expires_at + grace is authoritative and
					// still in the future — our Track-time computation ran
					// early (stale/rotated `grace` default). Re-arm to the
					// on-chain deadline instead of burning retries on
					// guaranteed "refund before deadline" reverts. Does not
					// consume an attempt; bounded because the box deadline
					// is immutable once written.
					rw.log.Debug("refund watchdog: on-chain deadline still ahead; re-arming",
						slog.String("ticket_id", ticketID),
						slog.Time("deadline", res.deadline))
					attempt--
					select {
					case <-cancel:
						return
					case <-time.After(wait):
					}
					continue
				}
			}
			// Box live and past its deadline (or the probe errored — attempt
			// the refund anyway; a revert is cheap and the error may be
			// transient).
			txid, rerr := rw.callOnce(cancel, refund)
			if errors.Is(rerr, errCancelled) {
				return
			}
			if rerr == nil {
				rw.log.Info("refund watchdog: recovered escrowed USDC via refundInactive",
					slog.String("ticket_id", ticketID),
					slog.String("txid", txid))
				if rw.refunded != nil {
					rw.refunded(ticketID)
				}
				return
			}
			if attempt >= rw.attempts {
				rw.log.Warn("refund watchdog: refundInactive failed; giving up",
					slog.String("ticket_id", ticketID),
					slog.String("remedy", rw.remedy),
					slog.Int("attempts", attempt),
					slog.Any("err", rerr),
					probeState(res, perr))
				return
			}
			rw.log.Debug("refund watchdog: refundInactive attempt failed; retrying",
				slog.String("ticket_id", ticketID),
				slog.Int("attempt", attempt),
				slog.Any("err", rerr))
			select {
			case <-cancel:
				return
			case <-time.After(rw.retryDelay):
			}
		}
	}()
}
