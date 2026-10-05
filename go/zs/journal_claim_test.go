/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"os"
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

// pathConfig is sweepingConfig with the journal named by path.
func pathConfig(t *testing.T, url, path string) Config {
	t.Helper()
	cfg := sweepingConfig(t, url, nil)
	cfg.Stores.JournalPath = path
	return cfg
}

// New holds the file named by Stores.JournalPath for the Client's life, sweeps
// it, and Close lets it go after the reconciler has.
func TestJournalPath_HeldUntilClose(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	path := filepath.Join(t.TempDir(), "journal.json")
	c, err := New(context.Background(), pathConfig(t, url, path))
	if err != nil {
		t.Fatal(err)
	}
	if c.reconcile == nil || !c.reconcile.handOff || !c.JournalDurable() {
		t.Error("the Client does not sweep the file as a durable journal")
	}
	if j, err := OpenFileJournal(path); !errors.Is(err, ErrJournalInUse) {
		if j != nil {
			j.Close()
		}
		t.Fatalf("while the Client is open, a second open got %v, want ErrJournalInUse", err)
	}

	release := c.reconcile.release
	var released bool
	c.reconcile.release = func() {
		if !released && c.ownJournal.lock == nil {
			t.Error("the journal file was closed before the reconciler let go of it")
		}
		released = true
		release()
	}
	c.Close()
	if !released {
		t.Fatal("Close never released the journal")
	}
	j, err := OpenFileJournal(path)
	if err != nil {
		t.Fatalf("after Close the file is still held: %v", err)
	}
	j.Close()
	c.Close() // a second Close is still safe
}

// A file another process holds, or one that will not load, is not this
// caller's to fix at startup: New journals in memory, says so through
// JournalDurable, and leaves the file as it found it.
func TestJournalPath_UnusableFileJournalsInMemory(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	for name, prepare := range map[string]func(t *testing.T, path string){
		"held elsewhere": func(t *testing.T, path string) {
			other, err := OpenFileJournal(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { other.Close() })
		},
		"unreadable": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "journal.json")
			prepare(t, path)
			before, _ := os.ReadFile(path)

			c, err := New(context.Background(), pathConfig(t, url, path))
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			defer c.Close()
			if _, ok := c.journal.(*memJournal); !ok || c.ownJournal != nil {
				t.Errorf("journal is %T (own %v), want the in-memory default", c.journal, c.ownJournal)
			}
			if c.JournalDurable() || c.reconcile.handOff {
				t.Error("an in-memory journal reports itself durable")
			}
			if after, _ := os.ReadFile(path); string(after) != string(before) {
				t.Errorf("the file changed from %q to %q", before, after)
			}
		})
	}
}

func TestJournalPath_Refusals(t *testing.T) {
	url, _, _ := fakeEscrowAlgod(t, 123_400)
	dir := t.TempDir()

	t.Run("Journal and JournalPath", func(t *testing.T) {
		both := pathConfig(t, url, filepath.Join(dir, "both.json"))
		both.Stores.Journal = openTestJournal(t)
		if c, err := New(context.Background(), both); err == nil {
			c.Close()
			t.Fatal("New succeeded")
		}
	})

	// A hot swap that builds the new Client before closing the old one must
	// not quietly lose the journal.
	t.Run("same file, same process", func(t *testing.T) {
		path := filepath.Join(dir, "shared.json")
		first, err := New(context.Background(), pathConfig(t, url, path))
		if err != nil {
			t.Fatal(err)
		}
		if c, err := New(context.Background(), pathConfig(t, url, path)); err == nil {
			c.Close()
			first.Close()
			t.Fatal("a second Client on the same journal file was admitted")
		}
		first.Close()
		next, err := New(context.Background(), pathConfig(t, url, path))
		if err != nil {
			t.Fatalf("after the first Client closed, the file was still claimed: %v", err)
		}
		if !next.JournalDurable() {
			t.Error("the next Client does not journal to the file")
		}
		next.Close()
	})
}
