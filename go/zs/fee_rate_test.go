/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestFeeRateCache covers the non-blocking serve-stale cache that backs the
// payer-facing fee breakdown: a cold read returns ok=false and kicks an async
// refresh; a successful refresh warms it; a failing refresh leaves it cold.
func TestFeeRateCache(t *testing.T) {
	var c feeRateCache
	okRefresh := func(context.Context) (uint64, error) { return 1000, nil }

	// Cold: no value yet, never blocks.
	if _, ok := c.get(okRefresh); ok {
		t.Fatal("cold cache should return ok=false")
	}
	// The async refresh warms it shortly.
	if !pollUntil(t, func() bool {
		fee, ok := c.get(okRefresh)
		return ok && fee == 1000
	}) {
		t.Fatal("cache never warmed with the refreshed rate")
	}

	// A failing refresh leaves the cache cold (no breakdown), never a stale lie.
	var c2 feeRateCache
	errRefresh := func(context.Context) (uint64, error) { return 0, errors.New("boom") }
	c2.get(errRefresh) // kicks the (failing) refresh
	time.Sleep(50 * time.Millisecond)
	if _, ok := c2.get(errRefresh); ok {
		t.Error("errored refresh must leave the cache cold (ok=false)")
	}

	// A panicking fetch must not crash the process (the recover would let the
	// goroutine panic take down the test binary otherwise) and must clear
	// `refreshing` so a later read can retry and warm the cache.
	var c3 feeRateCache
	c3.get(func(context.Context) (uint64, error) { panic("kaboom") })
	time.Sleep(50 * time.Millisecond)
	if !pollUntil(t, func() bool {
		_, ok := c3.get(okRefresh)
		return ok
	}) {
		t.Fatal("cache wedged after a panicking refresh — refreshing was not cleared")
	}
}

// The TTL half of get's staleness test was unmeasured: dropping it entirely
// (stale := !c.ok) left every test green, which would pin the fee for the
// process lifetime and never surface an on-chain protocolFeeBps change until a
// restart. Serving the OLD value on the read that finds it stale is the other
// half — the cache must never block on the refresh it just kicked.
func TestFeeRateCache_RefreshesAfterTheTTLAndServesStaleMeanwhile(t *testing.T) {
	var c feeRateCache
	var rate atomic.Uint64
	rate.Store(1000)
	fetch := func(context.Context) (uint64, error) { return rate.Load(), nil }

	c.get(fetch)
	if !pollUntil(t, func() bool { _, ok := c.get(fetch); return ok }) {
		t.Fatal("cache never warmed")
	}

	// Age the entry past the TTL and change what the chain would report.
	c.mu.Lock()
	c.fetchedAt = time.Now().Add(-2 * feeRateCacheTTL)
	c.mu.Unlock()
	rate.Store(2000)

	if fee, ok := c.get(fetch); !ok || fee != 1000 {
		t.Errorf("stale read returned (%d, %v), want the old value (1000, true): the read "+
			"that finds the entry stale must serve it, not wait for the refresh", fee, ok)
	}
	if !pollUntil(t, func() bool { fee, ok := c.get(fetch); return ok && fee == 2000 }) {
		t.Error("cache never converged on the new rate after the TTL elapsed; a fee change " +
			"would not reach /v1/models until restart")
	}
}

// get documents that it triggers a SINGLE background refresh, and the
// `!c.refreshing` guard is what makes that true. Without it every concurrent
// read during the cold window spawns its own algod global read. Nothing
// exercised that: deleting the guard left the suite green.
func TestFeeRateCache_ConcurrentColdReadsFetchOnce(t *testing.T) {
	var c feeRateCache
	var calls atomic.Int32
	release := make(chan struct{})
	// entered is the rendezvous this test synchronizes on, and it is the fix for
	// a flake that made this test fail on its own scheduling.
	//
	// get() spawns the refresh with `go` and returns immediately, so wg.Wait()
	// below establishes only that every reader DECIDED whether to refresh — not
	// that the goroutine it spawned has reached fetch. The original version read
	// `calls` at that point and routinely saw 0, reporting "fetched the fee 0
	// times" about a guard that was working.
	//
	// Buffered past the worst case (one refresh per reader), so a BROKEN guard
	// records every entry instead of parking on the send and hiding the extras.
	entered := make(chan int32, 32)
	fetch := func(context.Context) (uint64, error) {
		entered <- calls.Add(1)
		<-release // hold the refresh open so every reader sees `refreshing`
		return 1000, nil
	}

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get(fetch)
		}()
	}
	// Every spawn decision has now been made — they happen synchronously inside
	// get(), under c.mu. What has not necessarily happened is the spawned
	// goroutines running, which is the whole difficulty below.
	wg.Wait()

	// A cold cache MUST refresh once. Blocking on the rendezvous instead of
	// polling a counter is what makes this half deterministic.
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("a cold cache started no refresh at all, so the fee breakdown never loads")
	}
	close(release)

	// ...and no other reader may start a second one. Asserting that an event
	// does NOT happen needs a window, and this one is as strong as the shape
	// allows: every goroutine a broken guard would have spawned already existed
	// before wg.Wait() returned and is now unblocked, so it has only to be
	// scheduled. The window errs toward a false PASS on a wedged machine, which
	// is the opposite of the instantaneous read it replaces — that one produced
	// false FAILS, and a test that cries wolf gets deleted.
	select {
	case n := <-entered:
		t.Errorf("a second concurrent cold read started its own refresh (fetch #%d); want "+
			"exactly 1: the single-flight guard is what keeps a burst of first requests "+
			"from fanning out chain reads", n)
	case <-time.After(250 * time.Millisecond):
	}

	if !pollUntil(t, func() bool { _, ok := c.get(fetch); return ok }) {
		t.Error("cache never warmed after the concurrent cold reads")
	}
	// The count again, now that the cache has demonstrably warmed: one refresh
	// has completed a full round trip, so anything else that was spawned has had
	// every opportunity to be counted. The reads above cannot themselves add to
	// it — refresh publishes the value BEFORE its deferred reset clears
	// `refreshing`, so a get() arriving at any point in that sequence sees either
	// a refresh in flight or a warm cache, and spawns nothing.
	if n := calls.Load(); n != 1 {
		t.Errorf("the cold window fetched the fee %d times, want 1", n)
	}
}

func pollUntil(t *testing.T, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}
