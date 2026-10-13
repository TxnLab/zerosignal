/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
)

func testWatchdog() *RefundWatchdog {
	rw := NewRefundWatchdog(slog.Default())
	rw.margin = 0
	rw.retryDelay = 5 * time.Millisecond
	rw.lapseFallback = 5 * time.Millisecond
	return rw
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// boxAt fakes escrow.Classify over a live box: the verdict is time-dependent,
// reading "wait" until the box's own deadline passes and `then` afterwards.
// Keeping the fake time-aware matters — a static verdict could describe a state
// the contract can't hold (an operator claim that is somehow lapse-able before
// its deadline), and the re-arm paths exist precisely for that boundary.
func boxAt(deadline time.Time, then escrow.Verdict) func(context.Context) (ticketProbe, error) {
	return func(context.Context) (ticketProbe, error) {
		v := escrow.VerdictWait
		if time.Now().After(deadline) {
			v = then
		}
		return ticketProbe{exists: true, verdict: v, deadline: deadline}, nil
	}
}

// liveBox returns a probe for a live, unfrozen box whose on-chain deadline is
// already in the past — the "refund now" state.
func liveBox() func(context.Context) (ticketProbe, error) {
	return boxAt(time.Now().Add(-time.Minute), escrow.VerdictRefund)
}

// noLapse is the settleLapsed closure for tests whose ticket never reaches the
// operator-pending branch: calling it at all is the failure.
func noLapse(t *testing.T) func(context.Context) (string, error) {
	t.Helper()
	return func(context.Context) (string, error) {
		t.Error("settleLapsed driven on a ticket with no operator-side claim")
		return "", errors.New("unexpected settleLapsed")
	}
}

// A hand-off mid-probe ends the probe and sends nothing: the next sweeper
// owns the ticket the moment handOff returns.
func TestRefundWatchdog_HandOffStopsAProbeInFlight(t *testing.T) {
	rw := testWatchdog()
	rw.callTimeout = time.Hour // so only the hand-off can end the probe
	probing := make(chan struct{})
	var refunds atomic.Int32
	rw.track("tik", time.Now(),
		func(ctx context.Context) (ticketProbe, error) {
			close(probing)
			<-ctx.Done()
			return liveBox()(ctx) // a box that would be refunded, had it got this far
		},
		func(context.Context) (string, error) { refunds.Add(1); return "TX", nil },
		noLapse(t))
	<-probing
	handedOff := make(chan struct{})
	go func() { rw.handOff(); close(handedOff) }()
	select {
	case <-handedOff:
	case <-time.After(2 * time.Second):
		t.Fatal("handOff waited on a probe it should have ended")
	}
	if n := refunds.Load(); n != 0 {
		t.Errorf("%d refunds sent after handOff returned", n)
	}
	rw.track("late", time.Now(), liveBox(),
		func(context.Context) (string, error) { refunds.Add(1); return "TX", nil }, noLapse(t))
	time.Sleep(20 * time.Millisecond)
	if n := refunds.Load(); n != 0 {
		t.Errorf("a ticket armed after handOff was refunded")
	}
}

// A refund already sent is waited for: released sooner, the next sweeper
// would send the same refund alongside it.
func TestRefundWatchdog_HandOffWaitsOutASubmitInFlight(t *testing.T) {
	rw := testWatchdog()
	submitting, finish := make(chan struct{}), make(chan struct{})
	rw.track("tik", time.Now(), liveBox(),
		func(context.Context) (string, error) {
			close(submitting)
			<-finish
			return "TX", nil
		},
		noLapse(t))
	<-submitting
	handedOff := make(chan struct{})
	go func() { rw.handOff(); close(handedOff) }()
	select {
	case <-handedOff:
		t.Fatal("handOff returned while a refund was still in flight")
	case <-time.After(20 * time.Millisecond):
	}
	close(finish)
	select {
	case <-handedOff:
	case <-time.After(2 * time.Second):
		t.Fatal("handOff never returned after the refund finished")
	}
}

// A tracked ticket whose box still exists (deadline passed) gets a
// refundInactive.
func TestRefundWatchdog_FiresRefundAfterDeadline(t *testing.T) {
	rw := testWatchdog()
	var refunds atomic.Int32
	rw.track("tik-1", time.Now().Add(5*time.Millisecond),
		liveBox(),
		func(context.Context) (string, error) { refunds.Add(1); return "TXID", nil },
		noLapse(t),
	)
	waitFor(t, "refund attempt", func() bool { return refunds.Load() == 1 })
}

// A refunded hook that panics is the host's bug: the ticket's goroutine ends
// and the process does not. Unrecovered, the panic fails the whole test binary.
func TestRefundWatchdog_RefundedPanicIsContained(t *testing.T) {
	rw := testWatchdog()
	var heard atomic.Int32
	rw.refunded = func(string) {
		heard.Add(1)
		panic("guard bug")
	}
	rw.track("tik", time.Now(), liveBox(), func(context.Context) (string, error) { return "TX", nil }, noLapse(t))
	waitFor(t, "the refunded hook", func() bool { return heard.Load() == 1 })
	rw.handOff()
	if rw.watching("tik") {
		t.Error("the ticket is still pending after its driver panicked")
	}
}

// A box already deleted at deadline (operator settled standalone after the
// proxy lost sight of it) is a no-op — no refund attempt.
func TestRefundWatchdog_BoxGoneIsNoOp(t *testing.T) {
	rw := testWatchdog()
	var probes, refunds atomic.Int32
	rw.track("tik-2", time.Now().Add(5*time.Millisecond),
		func(context.Context) (ticketProbe, error) { probes.Add(1); return ticketProbe{exists: false}, nil },
		func(context.Context) (string, error) { refunds.Add(1); return "", nil },
		noLapse(t),
	)
	waitFor(t, "box probe", func() bool { return probes.Load() >= 1 })
	time.Sleep(20 * time.Millisecond)
	if refunds.Load() != 0 {
		t.Fatalf("refund fired despite box gone: %d attempts", refunds.Load())
	}
}

// A FROZEN box (protest / disputed settle) is left to arbitration —
// refundInactive would revert, so no attempt fires.
func TestRefundWatchdog_FrozenIsNoOp(t *testing.T) {
	rw := testWatchdog()
	var probes, refunds atomic.Int32
	rw.track("tik-frozen", time.Now().Add(5*time.Millisecond),
		func(context.Context) (ticketProbe, error) {
			probes.Add(1)
			return ticketProbe{exists: true, verdict: escrow.VerdictArbitrate, deadline: time.Now().Add(-time.Minute)}, nil
		},
		func(context.Context) (string, error) { refunds.Add(1); return "", nil },
		noLapse(t),
	)
	waitFor(t, "box probe", func() bool { return probes.Load() >= 1 })
	time.Sleep(20 * time.Millisecond)
	if refunds.Load() != 0 {
		t.Fatalf("refund fired on a frozen ticket: %d attempts", refunds.Load())
	}
}

// operatorPendingBox returns a probe for a live box parked in PENDING_SETTLE
// with an operator-side claim, past its deadline — refundInactive is illegal on
// it, settleLapsed is the only legal move.
func operatorPendingBox(probes *atomic.Int32) func(context.Context) (ticketProbe, error) {
	return func(context.Context) (ticketProbe, error) {
		probes.Add(1)
		return ticketProbe{exists: true, verdict: escrow.VerdictLapse, deadline: time.Now().Add(-time.Minute)}, nil
	}
}

// The regression: a PENDING_SETTLE box whose claim is the OPERATOR's must never
// see a refundInactive. The contract asserts 'ticket not refundable' on it, so
// attempting one just burns the whole attempt budget on guaranteed reverts.
func TestRefundWatchdog_OperatorPendingNeverRefunds(t *testing.T) {
	rw := testWatchdog()
	var probes, refunds atomic.Int32
	rw.track("tik-op-pending", time.Now().Add(5*time.Millisecond),
		operatorPendingBox(&probes),
		func(context.Context) (string, error) { refunds.Add(1); return "", nil },
		func(context.Context) (string, error) { return "TXID", nil },
	)
	waitFor(t, "box probe", func() bool { return probes.Load() >= 1 })
	time.Sleep(20 * time.Millisecond)
	if refunds.Load() != 0 {
		t.Fatalf("refund fired on an operator-pending ticket: %d attempts", refunds.Load())
	}
}

// The node's driver finalizes its own claim during the fallback wait (box gone
// by the re-probe) — the payer must not spend a fee racing a node that did its
// job.
func TestRefundWatchdog_OperatorPendingDefersToNodesLapse(t *testing.T) {
	rw := testWatchdog()
	var lapses atomic.Int32
	var probed atomic.Int32
	rw.track("tik-node-lapsed", time.Now().Add(2*time.Millisecond),
		func(context.Context) (ticketProbe, error) {
			// First probe: parked. Later probes (post-fallback): the node
			// finalized it, so the box is gone.
			if probed.Add(1) == 1 {
				return ticketProbe{exists: true, verdict: escrow.VerdictLapse, deadline: time.Now().Add(-time.Minute)}, nil
			}
			return ticketProbe{exists: false}, nil
		},
		func(context.Context) (string, error) {
			t.Error("refundInactive on an operator-pending ticket")
			return "", nil
		},
		func(context.Context) (string, error) { lapses.Add(1); return "", nil },
	)
	waitFor(t, "post-fallback re-probe", func() bool { return probed.Load() >= 2 })
	time.Sleep(20 * time.Millisecond)
	if lapses.Load() != 0 {
		t.Fatalf("payer drove settleLapsed though the node already finalized: %d attempts", lapses.Load())
	}
}

// The node never lapses (dead after its claim confirmed / ledger lost / retries
// exhausted) — the payer drives settleLapsed itself, or its share of max_price
// is locked forever with refundInactive barred from recovering it.
func TestRefundWatchdog_OperatorPendingDrivesLapseWhenNodeStalls(t *testing.T) {
	rw := testWatchdog()
	var probes, lapses atomic.Int32
	rw.track("tik-node-stalled", time.Now().Add(2*time.Millisecond),
		operatorPendingBox(&probes),
		func(context.Context) (string, error) {
			t.Error("refundInactive on an operator-pending ticket")
			return "", nil
		},
		func(context.Context) (string, error) { lapses.Add(1); return "TXID", nil },
	)
	waitFor(t, "payer-driven settleLapsed", func() bool { return lapses.Load() == 1 })
}

// settleLapsed gates on the box's own expires_at + grace, so an operator-pending
// ticket must not be lapsed early when the Track-time fire (computed off the
// startup-cached `grace` default) lands before the box's real deadline — that
// would burn the attempt budget on guaranteed "too early to lapse settle"
// reverts and strand the ticket.
//
// The re-arm that saves it is TRACK's: an operator-pending box before its
// deadline classifies as Wait, not Lapse, so driveLapse isn't reached until the
// deadline has passed. That is also why driveLapse itself has no re-arm — by
// construction it only ever runs past a deadline that can no longer move.
func TestRefundWatchdog_LapseReArmsToOnChainDeadline(t *testing.T) {
	rw := testWatchdog()
	var lapses atomic.Int32
	onchain := time.Now().Add(60 * time.Millisecond)
	rw.track("tik-lapse-rearm", time.Now().Add(2*time.Millisecond),
		boxAt(onchain, escrow.VerdictLapse),
		func(context.Context) (string, error) {
			t.Error("refundInactive on an operator-pending ticket")
			return "", nil
		},
		func(context.Context) (string, error) { lapses.Add(1); return "TXID", nil },
	)
	// Well before the box's deadline: the early fire must have re-armed.
	time.Sleep(20 * time.Millisecond)
	if lapses.Load() != 0 {
		t.Fatalf("settleLapsed fired before the on-chain deadline: %d attempts", lapses.Load())
	}
	// Once it passes, exactly one — the re-arm must not have consumed attempts.
	waitFor(t, "post-deadline settleLapsed", func() bool { return lapses.Load() == 1 })
}

// A failing settleLapsed retries to the same bound as the refund path, then
// gives up — a permanently stalled ticket can't spin forever.
func TestRefundWatchdog_LapseRetriesThenGivesUp(t *testing.T) {
	rw := testWatchdog()
	var probes, lapses atomic.Int32
	rw.track("tik-lapse-fail", time.Now().Add(2*time.Millisecond),
		operatorPendingBox(&probes),
		func(context.Context) (string, error) {
			t.Error("refundInactive on an operator-pending ticket")
			return "", nil
		},
		func(context.Context) (string, error) { lapses.Add(1); return "", errors.New("algod down") },
	)
	waitFor(t, "all lapse retries", func() bool { return int(lapses.Load()) == rw.attempts })
	time.Sleep(3 * rw.retryDelay)
	if got := int(lapses.Load()); got != rw.attempts {
		t.Fatalf("settleLapsed attempts = %d, want exactly %d", got, rw.attempts)
	}
}

// The box outlives the process, so the give-up line is the payer's only lead:
// it carries the configured remedy, and the default one when none was set.
func TestRefundWatchdog_GiveUpLogsTheRemedy(t *testing.T) {
	for _, remedy := range []string{"", "recover it by hand"} {
		var buf bytes.Buffer
		var mu sync.Mutex
		rw := testWatchdog()
		rw.log = slog.New(slog.NewTextHandler(&lockedWriter{w: &buf, mu: &mu}, nil))
		if remedy != "" {
			rw.remedy = remedy
		}
		want := cmp.Or(remedy, Remedies{}.withDefaults().RecoverTicket)
		var refunds atomic.Int32
		rw.track("tik-give-up", time.Now().Add(2*time.Millisecond), liveBox(),
			func(context.Context) (string, error) { refunds.Add(1); return "", errors.New("algod down") },
			noLapse(t))
		waitFor(t, "the give-up line", func() bool {
			mu.Lock()
			defer mu.Unlock()
			return strings.Contains(buf.String(), "giving up")
		})
		mu.Lock()
		if !strings.Contains(buf.String(), strconv.Quote(want)) {
			t.Errorf("give-up log lacks remedy %q:\n%s", want, buf.String())
		}
		mu.Unlock()
	}
}

type lockedWriter struct {
	w  *bytes.Buffer
	mu *sync.Mutex
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// A box these bindings can't classify (they disagree with the deployed app)
// must not be guessed at: neither call is known to be legal, so posting one
// spends fees on a probable revert. Stop and tell the operator instead.
func TestRefundWatchdog_UnknownStateAttemptsNothing(t *testing.T) {
	rw := testWatchdog()
	var probes atomic.Int32
	unknown := func(context.Context) (ticketProbe, error) {
		probes.Add(1)
		return ticketProbe{exists: true, verdict: escrow.VerdictUnknown, deadline: time.Now().Add(-time.Minute)}, nil
	}
	rw.track("tik-unknown", time.Now().Add(2*time.Millisecond), unknown,
		func(context.Context) (string, error) {
			t.Error("refundInactive on an unrecognized ticket state")
			return "", nil
		},
		noLapse(t),
	)
	waitFor(t, "box probe", func() bool { return probes.Load() >= 1 })
	// Give the loop room to retry if it were going to.
	time.Sleep(3 * rw.retryDelay)
	if got := probes.Load(); got != 1 {
		t.Fatalf("probes = %d, want exactly 1 — an unrecognized state is terminal, not retried", got)
	}
}

// The box can change while the lapse fallback runs: a freeze or a state these
// bindings can't read stops the lapse as it stops the refund.
func TestRefundWatchdog_LapseStopsOnABoxThatTurnsDuringTheFallback(t *testing.T) {
	for _, verdict := range []escrow.Verdict{escrow.VerdictArbitrate, escrow.VerdictUnknown} {
		t.Run(verdict.String(), func(t *testing.T) {
			rw := testWatchdog()
			var probes atomic.Int32
			rw.track("tik-turned", time.Now().Add(2*time.Millisecond),
				func(context.Context) (ticketProbe, error) {
					v := verdict
					if probes.Add(1) == 1 {
						v = escrow.VerdictLapse
					}
					return ticketProbe{exists: true, verdict: v, deadline: time.Now().Add(-time.Minute)}, nil
				},
				func(context.Context) (string, error) {
					t.Error("refundInactive on an operator-pending ticket")
					return "", nil
				},
				func(context.Context) (string, error) {
					t.Error("settleLapsed on a box that froze or turned unclassifiable during the fallback")
					return "", errors.New("unexpected settleLapsed")
				},
			)
			waitFor(t, "post-fallback re-probe", func() bool { return probes.Load() >= 2 })
			time.Sleep(3 * rw.retryDelay)
			if got := probes.Load(); got != 2 {
				t.Fatalf("probes = %d, want exactly 2 — the turned box ends the run", got)
			}
		})
	}
}

// A PENDING_SETTLE box whose claim is the PAYER's own standalone ack IS
// refundable — the operator never matched it, so refundInactive is exactly the
// deadline path. Guards the operator-pending skip from over-reaching.
func TestRefundWatchdog_PayerPendingStillRefunds(t *testing.T) {
	rw := testWatchdog()
	var refunds atomic.Int32
	rw.track("tik-payer-pending", time.Now().Add(2*time.Millisecond),
		func(context.Context) (ticketProbe, error) {
			// Payer-side pending claim → operatorPending stays false.
			return ticketProbe{exists: true, verdict: escrow.VerdictRefund, deadline: time.Now().Add(-time.Minute)}, nil
		},
		func(context.Context) (string, error) { refunds.Add(1); return "TXID", nil },
		noLapse(t),
	)
	waitFor(t, "refund attempt", func() bool { return refunds.Load() == 1 })
}

// When the box's own expires_at + grace deadline is still ahead of the
// locally-computed fire time (stale/rotated `grace` default), the watchdog
// re-arms to the on-chain deadline instead of burning retries on guaranteed
// "refund before deadline" reverts — then refunds once it truly passes.
func TestRefundWatchdog_ReArmsToOnChainDeadline(t *testing.T) {
	rw := testWatchdog()
	var refunds atomic.Int32
	onchain := time.Now().Add(60 * time.Millisecond)
	rw.track("tik-rearm", time.Now().Add(2*time.Millisecond),
		boxAt(onchain, escrow.VerdictRefund),
		func(context.Context) (string, error) { refunds.Add(1); return "TXID", nil },
		noLapse(t),
	)
	// Well before the on-chain deadline: the early fire must have re-armed,
	// not refunded.
	time.Sleep(20 * time.Millisecond)
	if refunds.Load() != 0 {
		t.Fatalf("refund fired before the on-chain deadline: %d attempts", refunds.Load())
	}
	// After it passes, exactly one (successful) refund — the re-arm pass must
	// not have consumed retry attempts.
	waitFor(t, "post-deadline refund", func() bool { return refunds.Load() == 1 })
}

// Resolve before the deadline cancels the probe entirely.
func TestRefundWatchdog_ResolveCancels(t *testing.T) {
	rw := testWatchdog()
	var touched atomic.Int32
	rw.track("tik-3", time.Now().Add(30*time.Millisecond),
		func(context.Context) (ticketProbe, error) {
			touched.Add(1)
			return ticketProbe{exists: true, verdict: escrow.VerdictRefund, deadline: time.Now().Add(-time.Minute)}, nil
		},
		func(context.Context) (string, error) { touched.Add(1); return "", nil },
		noLapse(t),
	)
	rw.Resolve("tik-3")
	time.Sleep(60 * time.Millisecond)
	if touched.Load() != 0 {
		t.Fatalf("cancelled probe still ran: %d touches", touched.Load())
	}
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if len(rw.pending) != 0 {
		t.Fatalf("pending map not cleaned up: %d entries", len(rw.pending))
	}
}

// Failed refund attempts retry up to the bound, then give up.
func TestRefundWatchdog_RetriesThenGivesUp(t *testing.T) {
	rw := testWatchdog()
	var refunds atomic.Int32
	rw.track("tik-4", time.Now().Add(2*time.Millisecond),
		liveBox(),
		func(context.Context) (string, error) { refunds.Add(1); return "", errors.New("refund before deadline") },
		noLapse(t),
	)
	waitFor(t, "all retries", func() bool { return int(refunds.Load()) == rw.attempts })
	time.Sleep(3 * rw.retryDelay)
	if got := int(refunds.Load()); got != rw.attempts {
		t.Fatalf("refund attempts = %d, want exactly %d", got, rw.attempts)
	}
}

// A probe error is not trusted as "box gone" — the refund is attempted anyway
// (a revert is cheap; the error may be transient).
func TestRefundWatchdog_ProbeErrorStillRefunds(t *testing.T) {
	rw := testWatchdog()
	var refunds atomic.Int32
	rw.track("tik-5", time.Now().Add(2*time.Millisecond),
		func(context.Context) (ticketProbe, error) { return ticketProbe{}, errors.New("algod flake") },
		func(context.Context) (string, error) { refunds.Add(1); return "TXID", nil },
		noLapse(t),
	)
	waitFor(t, "refund despite probe error", func() bool { return refunds.Load() == 1 })
}

// Track with a detached handle (test fakes / nil wallet) is a safe no-op,
// as is a nil watchdog receiver.
func TestRefundWatchdog_NilSafety(t *testing.T) {
	var nilRW *RefundWatchdog
	nilRW.Track(&OpenHandle{TicketID: "x"}, time.Now().Unix())
	nilRW.Resolve("x")

	rw := testWatchdog()
	rw.Track(nil, 0)
	rw.Track(&OpenHandle{TicketID: "x"}, time.Now().Unix()) // wallet == nil → skipped
	rw.mu.Lock()
	defer rw.mu.Unlock()
	if len(rw.pending) != 0 {
		t.Fatalf("detached handles must not be tracked: %d entries", len(rw.pending))
	}
}
