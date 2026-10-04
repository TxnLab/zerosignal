/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
)

// sweepingConfig is a Config whose Client builds its own *Wallet over j, so
// New claims j for its reconciler.
func sweepingConfig(t *testing.T, url string, j TicketJournal) Config {
	t.Helper()
	cfg := suppliedParts(t)
	cfg.Network.Algod = algod.Config{Network: "testnet", Endpoint: url}
	cfg.Wallet = nil
	cfg.Stores.Journal = j
	return cfg
}

func openTestJournal(t *testing.T) *FileJournal {
	t.Helper()
	j, err := OpenFileJournal(filepath.Join(t.TempDir(), "journal.json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	return j
}

// Close stops this Client's watchdog and its reconciler loop before it gives
// the journal back: the moment the claim is released, the next Client may
// sweep the same rows, and anything of ours still driving them submits the
// same refund or lapse.
func TestClose_ReleasesTheJournalLast(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	c, err := New(context.Background(), sweepingConfig(t, url, openTestJournal(t)))
	if err != nil {
		t.Fatal(err)
	}
	nop := func(context.Context) (string, error) { return "", nil }
	probe := func(context.Context) (ticketProbe, error) { return ticketProbe{}, nil }
	c.refunds.track("LIVE", time.Now().Add(time.Hour), probe, nop, nop)

	release := c.reconcile.release
	var releases int
	c.reconcile.release = func() {
		releases++
		if c.refunds.watching("LIVE") {
			t.Error("the journal was released while this Client's watchdog still drove one of its tickets")
		}
		select {
		case <-c.reconcile.done:
		default:
			t.Error("the journal was released while this Client's reconciler loop was still running")
		}
		release()
	}
	c.Close()
	if releases == 0 {
		t.Fatal("Close never released the journal")
	}
}

// Close is safe to call more than once, and a late second Close must neither
// panic nor give back a claim that a newer Client now holds.
func TestClose_ASecondCloseKeepsTheNextClientsClaim(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	j := openTestJournal(t)
	first, err := New(context.Background(), sweepingConfig(t, url, j))
	if err != nil {
		t.Fatal(err)
	}
	nop := func(context.Context) (string, error) { return "", nil }
	probe := func(context.Context) (ticketProbe, error) { return ticketProbe{}, nil }
	first.refunds.track("LIVE", time.Now().Add(time.Hour), probe, nop, nop)
	closeNoPanic := func(which string) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s Close panicked: %v", which, r)
			}
		}()
		first.Close()
	}
	closeNoPanic("the first")
	closeNoPanic("a second")

	next, err := New(context.Background(), sweepingConfig(t, url, j))
	if err != nil {
		t.Fatalf("after the first closed: %v", err)
	}
	defer next.Close()

	closeNoPanic("a late")

	third, err := New(context.Background(), sweepingConfig(t, url, j))
	if err == nil {
		third.Close()
		t.Error("a stale second Close gave back the journal the next Client sweeps: a third sweeper was admitted")
	}
}

// handOff forgets every ticket it cancelled in the same critical section, so
// a Resolve racing Close (a stream ending as the Client shuts down) or a
// second hand-off finds nothing to close twice. One P keeps the cancelled
// ticket's goroutine from deregistering itself first, which would hide a
// stale map.
func TestRefundWatchdog_HandOffForgetsWhatItCancelled(t *testing.T) {
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	rw := NewRefundWatchdog(discardLogger())
	nop := func(context.Context) (string, error) { return "", nil }
	probe := func(context.Context) (ticketProbe, error) { return ticketProbe{}, nil }
	rw.track("LIVE", time.Now().Add(time.Hour), probe, nop, nop)
	rw.handOff()
	if rw.watching("LIVE") {
		t.Error("a handed-off ticket still reads as watched")
	}
	noPanic := func(what string, f func()) {
		defer func() {
			if r := recover(); r != nil {
				t.Errorf("%s after handOff panicked: %v", what, r)
			}
		}()
		f()
	}
	noPanic("Resolve", func() { rw.Resolve("LIVE") })
	noPanic("a second handOff", rw.handOff)
}

// unhashableJournal is a journal value that cannot key a map: its type is a
// comparable struct, but the interface field holds a slice, so only the value
// says so.
type unhashableJournal struct {
	*memJournal
	tag any
}

// New accepts a journal value that cannot key a map rather than panicking in
// the claim.
func TestNew_AcceptsAnUnhashableJournal(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	j := unhashableJournal{memJournal: newMemJournal(), tag: []int{1}}
	var c *Client
	var err error
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("New panicked on a journal value that cannot key a map: %v", r)
			}
		}()
		c, err = New(context.Background(), sweepingConfig(t, url, j))
	}()
	if err != nil {
		t.Fatalf("New refused a journal value that cannot key a map: %v", err)
	}
	c.Close()
}

func registryLoops() int {
	var b strings.Builder
	_ = pprof.Lookup("goroutine").WriteTo(&b, 1)
	return strings.Count(b.String(), "(*DynamicRegistryProvider).run")
}

// A New refused for a journal another Client sweeps must not leave the
// discovery loop it already started running: the caller gets no Client to
// Close.
func TestNew_RefusedNewStopsTheRegistryItBuilt(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	j := openTestJournal(t)
	first, err := New(context.Background(), sweepingConfig(t, url, j))
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()

	before := registryLoops()
	cfg := sweepingConfig(t, url, j)
	cfg.Registry = nil
	cfg.Logger = discardLogger()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if c, err := New(ctx, cfg); err == nil {
		c.Close()
		t.Fatal("a second Client sweeping the journal was admitted")
	}
	if after := registryLoops(); after > before {
		t.Errorf("a refused New left %d discovery loop(s) running", after-before)
	}
}
