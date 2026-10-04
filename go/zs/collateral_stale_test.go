/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The stale fallback exists because a PCS outage longer than the TTL
// otherwise takes every TEE operator out of routing — and the proxy's
// callers are long-lived agent sessions where that lands as the session
// breaking on whoever is mid-task, with nobody reading the log.
//
// What each case pins is the BOUNDARY, since the failure modes either
// side of it are opposite: too tight and the outage is not survived at
// all, too loose and a platform revoked during the outage keeps
// verifying indefinitely.
func TestCachingGetter_StaleWhileRevalidate(t *testing.T) {
	const url = "https://pcs.example/tcb"

	// warm returns a cache holding one entry fetched at `now`, plus the
	// stub behind it and a pointer to the clock the test can advance.
	warm := func(t *testing.T) (*cachingGetter, *stubCollateral, *time.Time) {
		t.Helper()
		stub := &stubCollateral{body: []byte("fresh")}
		now := time.Unix(1_750_000_000, 0)
		c := &cachingGetter{
			inner:   stub,
			ttl:     collateralTTL,
			now:     func() time.Time { return now },
			entries: map[string]collateralEntry{},
		}
		if _, _, _, err := c.getWithContext(context.Background(), url); err != nil {
			t.Fatalf("seeding the cache: %v", err)
		}
		return c, stub, &now
	}

	t.Run("serves the cached entry when the fetch fails", func(t *testing.T) {
		c, stub, now := warm(t)
		*now = now.Add(collateralTTL + time.Minute)
		stub.err = errors.New("dial tcp: connection refused")

		_, body, staleCause, err := c.getWithContext(context.Background(), url)
		if err != nil {
			t.Fatalf("err = %v, want the stale entry to be served", err)
		}
		if string(body) != "fresh" {
			t.Errorf("body = %q, want the cached document", body)
		}
		if staleCause == nil {
			t.Error("staleCause = nil — the caller cannot tell this verdict rode cached collateral")
		}
		// The CAUSE, not merely the fact. A stale serve that then fails
		// verification is attributed with this error, so a cache that
		// reported staleness without the reason would leave the
		// attribution with nothing to blame the outage on.
		if !errors.Is(staleCause, stub.err) {
			t.Errorf("staleCause = %v, want the fetch failure that forced the stale serve (%v)",
				staleCause, stub.err)
		}
		if stub.count() != 2 {
			t.Errorf("%d fetches, want 2 — the stale path must still ATTEMPT a refresh", stub.count())
		}
	})

	t.Run("refuses once the entry is past collateralStaleMax", func(t *testing.T) {
		// The bound derived from the constant, never a literal: a
		// hardcoded offset passes for any production value, including one
		// long enough to serve collateral from a previous quarter.
		c, stub, now := warm(t)
		*now = now.Add(collateralStaleMax + time.Minute)
		stub.err = errors.New("dial tcp: connection refused")

		if _, _, _, err := c.getWithContext(context.Background(), url); err == nil {
			t.Fatal("an entry past collateralStaleMax was served")
		}
	})

	t.Run("a fetch failure with no entry is still an error", func(t *testing.T) {
		stub := &stubCollateral{err: errors.New("dial tcp: connection refused")}
		c := &cachingGetter{inner: stub, ttl: collateralTTL, entries: map[string]collateralEntry{}}
		if _, _, _, err := c.getWithContext(context.Background(), url); err == nil {
			t.Fatal("a cold cache under an outage reported success")
		}
	})

	t.Run("a fresh entry never reports stale", func(t *testing.T) {
		// Guards the direction that would be silent: if the fresh path
		// ever set the flag, every verdict would carry a staleness
		// warning and the signal would stop meaning anything.
		c, stub, _ := warm(t)
		stub.err = errors.New("should not be reached")

		_, _, staleCause, err := c.getWithContext(context.Background(), url)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if staleCause != nil {
			t.Errorf("staleCause = %v for an entry inside its TTL", staleCause)
		}
	})

	t.Run("an entry stamped in the future is not fresh", func(t *testing.T) {
		// A fast RTC (snapshot restore, unsynced boot) writes these. The
		// age goes negative, which satisfies "< ttl" and short-circuits
		// to a serve — skipping the fetch AND never reaching
		// collateralStaleMax, so both bounds are off at once and a CRL
		// predating a revocation keeps passing until the clock catches
		// up. Asserted by the FETCH, because a future entry and a fresh
		// one return identical bytes; only the refresh attempt
		// distinguishes them.
		c, stub, now := warm(t)
		*now = now.Add(-2 * 24 * time.Hour)
		before := stub.count()

		if _, _, _, err := c.getWithContext(context.Background(), url); err != nil {
			t.Fatalf("err = %v", err)
		}
		if stub.count() == before {
			t.Error("no refresh was attempted for a future-dated entry — it was served as fresh, " +
				"which turns off both the TTL and collateralStaleMax")
		}
	})

	t.Run("a future entry IS served as stale, once the refresh has failed", func(t *testing.T) {
		// The deliberate asymmetry with the case above, and it is a
		// different question rather than an inconsistency. Up there a
		// negative age skips the refresh, so both bounds go off at once.
		// Here the refresh has already been attempted and failed, and
		// refusing is the fleet-wide outage this fallback exists to
		// prevent — a clock stepped backwards poisons every entry at
		// once, with no successful fetch available to re-stamp them.
		// go-tdx-guest still enforces each document's own nextUpdate.
		c, stub, now := warm(t)
		*now = now.Add(-2 * 24 * time.Hour)
		stub.err = errors.New("dial tcp: connection refused")

		_, body, staleCause, err := c.getWithContext(context.Background(), url)
		if err != nil {
			t.Fatalf("err = %v — a future-dated entry took every TEE operator out of routing "+
				"during an outage, which is what the stale fallback exists to prevent", err)
		}
		if string(body) != "fresh" {
			t.Errorf("body = %q, want the cached document", body)
		}
		if staleCause == nil {
			t.Error("staleCause = nil — the serve was not reported as stale")
		}
	})

	t.Run("a recovered fetch clears the stale flag and re-arms the warning", func(t *testing.T) {
		c, stub, now := warm(t)
		*now = now.Add(collateralTTL + time.Minute)
		stub.err = errors.New("dial tcp: connection refused")
		if _, _, staleCause, _ := c.getWithContext(context.Background(), url); staleCause == nil {
			t.Fatal("expected the stale path")
		}

		stub.err = nil
		stub.body = []byte("recovered")
		_, body, staleCause, err := c.getWithContext(context.Background(), url)
		if err != nil {
			t.Fatalf("err = %v", err)
		}
		if staleCause != nil {
			t.Errorf("staleCause = %v after PCS recovered", staleCause)
		}
		if string(body) != "recovered" {
			t.Errorf("body = %q, want the refetched document", body)
		}
		c.mu.Lock()
		warned := c.staleWarned[url]
		c.mu.Unlock()
		if warned {
			t.Error("the stale warning stayed armed after recovery, so a relapse would be silent")
		}
	})
}

// staleStub always answers from "cache", the shape cachingGetter
// presents to verifyGetter during an outage.
type staleStub struct {
	calls int
	cause error
}

func (s *staleStub) getWithContext(context.Context, string) (map[string][]string, []byte, error, error) {
	s.calls++
	cause := s.cause
	if cause == nil {
		cause = errors.New("dial tcp: connection refused")
	}
	return map[string][]string{}, []byte("cached"), cause, nil
}

// A stale-served artifact must still count toward requireCollateralFetched,
// and must latch staleUsed.
//
// THE GUARD COUNTS GETTER CALLS. A refactor that served stale collateral
// without passing through verifyGetter would turn "a pass that consulted
// no collateral is not a pass" off silently: verification would still
// pass, and nothing would report that the tripwire had stopped covering
// anything.
//
// Driven at verifyGetter rather than through verifyTDXQuoteChainWith on
// purpose. A full stale-path verification needs collateral that actually
// satisfies Intel's chain for this quote, which no stub can synthesize —
// so a test shaped that way could only assert the COLD path while
// claiming to cover the stale one.
func TestVerifyGetter_StaleArtifactCountsAsFetched(t *testing.T) {
	stub := &staleStub{}
	g := &verifyGetter{inner: stub, ctx: context.Background()}

	if _, _, err := g.Get("https://pcs.example/tcb"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g.count() == 0 {
		t.Error("a stale-served artifact did not count as fetched — requireCollateralFetched " +
			"would refuse a verification it should allow")
	}
	if err := requireCollateralFetched(g.count()); err != nil {
		t.Errorf("requireCollateralFetched: %v", err)
	}
	if !g.staleUsed() {
		t.Error("staleUsed() = false after a stale artifact — tee inspect would report " +
			"a stale verdict as a fresh one")
	}
	if g.err() != nil {
		t.Errorf("err() = %v — a served stale artifact is not a fetch failure", g.err())
	}
	// err() and staleCause() must disagree here, and that disagreement is
	// the fix: err() answers "did a Get return nothing", which is false,
	// while staleCause() answers "was cached collateral used because PCS
	// was unreachable", which is true.
	if g.staleCause() == nil {
		t.Error("staleCause() = nil after a stale serve — a verification that then fails " +
			"would be reported as the operator's forged evidence rather than as the " +
			"undetermined outcome it is")
	}
}

// THE MISDIAGNOSIS THE STALE PATH REINTRODUCED, pinned end to end.
//
// collateralStaleMax is measured from OUR fetch time; a document's own
// nextUpdate is measured from Intel's issue time. They are unrelated
// windows, so an artifact well inside the first can be past the second —
// and go-tdx-guest rejects it during RawTdxQuote. Served with a nil
// error, that rejection is indistinguishable from a forged quote, so one
// Intel outage stamps "this node's evidence is invalid" on every dstack
// operator at once — exactly what FailureCollateralUnreachable exists to
// prevent.
//
// The stub's bytes are not real collateral, which is what makes this
// drivable at all: the library refuses them the same way it refuses an
// expired document, and the assertion is about ATTRIBUTION, not about
// which refusal occurred.
func TestVerifyTDXQuoteChain_StaleServeThatFailsIsOurOutage(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	outage := errors.New("dial tcp: connection refused")
	stub := &stubCollateral{body: []byte("cached-but-unusable"), staleCause: outage}

	_, err := verifyTDXQuoteChainWith(context.Background(), quote, stub)
	if err == nil {
		t.Fatal("verification passed on unusable collateral")
	}
	if !errors.Is(err, ErrStaleCollateralRejected) {
		t.Fatalf("err = %v, want ErrStaleCollateralRejected — a rejection reached on OUR stale "+
			"collateral is being reported as the operator's evidence being forged", err)
	}
	// And NOT as the outage tag. That one means "we could not check",
	// which is false here — collateral was obtained and it refused — and
	// `zs-proxy tee inspect` continues its report on it, printing the
	// release-allowlist values a refused quote names for itself.
	if errors.Is(err, ErrCollateralUnavailable) {
		t.Error("a refusal reached ON collateral is reported as collateral being unavailable; " +
			"tee inspect would carry on and print the rejected quote's own trust values")
	}
}

// BOTH SLOTS SET AT ONCE, which the two tests either side of this one
// cannot observe: each drives a stub that sets exactly one, so the
// PRECEDENCE between them is unobserved and swapping the two arms leaves
// the whole suite green.
//
// It is the ordinary shape of a partly-warm cache during an outage — TCB
// info served from cache past its refresh window, QE identity with no
// entry at all and hard-failing — and the two arms disagree about the
// outcome: err() first yields ErrCollateralUnavailable and ALLOWS the
// node-carried fallback, staleCause first yields
// ErrStaleCollateralRejected and denies it.
//
// err() must win. obtainCollateral aborts at the first failed Get, so a
// hard error means gathering never finished and no verdict was reached —
// "we could not check" is simply true, and the stale serve that preceded
// it is incidental. staleCause means "a verdict was reached, partly on
// our aging document" only when gathering COMPLETED, which is exactly
// when err() is nil.
func TestVerifyTDXQuoteChain_AHardFailureOutranksAStaleServe(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	outage := errors.New("dial tcp: connection refused")
	// stubCollateral CANNOT express this — it returns early on `err` with a
	// nil staleCause, so a stub with both fields set still only ever sets
	// one slot. Reaching the state needs a getter whose FIRST answer is
	// good enough for the library to accept and move on (so a second call
	// happens at all) and which then hard-fails, which is exactly the
	// partly-warm cache being modelled. The embedded getter supplies the
	// first answer.
	inner, err := newEmbeddedGetter(quote, testCarriedCollateral(t, time.Now()))
	if err != nil {
		t.Fatalf("newEmbeddedGetter: %v", err)
	}
	stub := &staleThenFailGetter{inner: inner, outage: outage}

	_, err = verifyTDXQuoteChainWith(context.Background(), quote, stub)
	if err == nil {
		t.Fatal("verification passed on unusable collateral")
	}
	if !errors.Is(err, ErrCollateralUnavailable) {
		t.Fatalf("err = %v, want ErrCollateralUnavailable — a verification whose collateral "+
			"gathering aborted never reached a verdict, so it must stay eligible for the "+
			"node-carried fallback", err)
	}
	if errors.Is(err, ErrStaleCollateralRejected) {
		t.Error("a verification that never completed is reported as a refusal reached on our " +
			"own collateral, which denies the rung-3 fallback and makes tee inspect stop")
	}
	// The premise: both slots really were set. Without this the test passes
	// for a getter that only ever set one, which is the state stubCollateral
	// is stuck in and the reason the arms' precedence went unobserved.
	if !stub.served || !stub.failed {
		t.Fatalf("the getter did not reach the state under test (served=%v failed=%v) — "+
			"only one slot was ever set, so the precedence is not being exercised",
			stub.served, stub.failed)
	}
}

// staleThenFailGetter answers the first request from `inner` while
// reporting a stale cause, then hard-fails every later one — a cache
// holding some of this platform's artifacts and none of the rest, with
// Intel unreachable to refill it.
type staleThenFailGetter struct {
	inner  contextGetter
	outage error
	served bool
	failed bool
}

func (g *staleThenFailGetter) getWithContext(
	ctx context.Context, url string,
) (map[string][]string, []byte, error, error) {
	if !g.served {
		header, body, _, err := g.inner.getWithContext(ctx, url)
		if err != nil {
			return nil, nil, nil, err
		}
		g.served = true
		return header, body, g.outage, nil
	}
	g.failed = true
	return nil, nil, nil, g.outage
}

// The direction that would make the fix too broad: a live fetch that
// verifies badly is still the operator's problem.
//
// Without this, "attribute to ourselves when in doubt" could be widened
// until FailureVendorChainInvalid never fires and a genuinely forged
// quote reads as an Intel outage forever.
func TestVerifyTDXQuoteChain_FreshServeThatFailsIsNotOurOutage(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	stub := &stubCollateral{body: []byte("live-but-unusable")}

	_, err := verifyTDXQuoteChainWith(context.Background(), quote, stub)
	if err == nil {
		t.Fatal("verification passed on unusable collateral")
	}
	if errors.Is(err, ErrCollateralUnavailable) {
		t.Fatalf("err = %v, want a vendor-chain failure — nothing was stale and nothing "+
			"failed to fetch, so this is a statement about the quote", err)
	}
}

// The other direction, which would be silent: a verification that only
// ever saw fresh artifacts must not latch.
func TestVerifyGetter_FreshArtifactDoesNotLatchStale(t *testing.T) {
	g := &verifyGetter{inner: &stubCollateral{body: []byte("fresh")}, ctx: context.Background()}
	if _, _, err := g.Get("https://pcs.example/tcb"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if g.staleUsed() {
		t.Error("staleUsed() = true for a fresh fetch")
	}
}

// THE NUMBER, pinned to a literal, because every Go reference derives
// from the constant and therefore moves with it — widening it to ten days
// leaves proxy, proto and node all green while the browser twin holds at
// seven. `COLLATERAL_STALE_MAX_MS` is pinned exactly this way on the TS
// side, so without this the "matches the proxy, deliberately" claim is
// enforced in one direction only.
//
// It also became load-bearing in a second place: collateralStore.load
// prunes past it, so a change here silently changes what survives a
// restart.
func TestCollateralStaleMaxIsSevenDays(t *testing.T) {
	if collateralStaleMax != 7*24*time.Hour {
		t.Fatalf("collateralStaleMax = %v, want 7 days — the client's COLLATERAL_STALE_MAX_MS "+
			"pins the same number, and the two are hand-mirrored", collateralStaleMax)
	}
}

func TestCollateralStore(t *testing.T) {
	// RELATIVE, not a fixed instant. load prunes past collateralStaleMax,
	// so a hardcoded timestamp is a fixture with an expiry date: it works
	// until the wall clock passes it and then fails as a round-trip
	// problem it isn't.
	entry := collateralEntry{
		header:  map[string][]string{"X-Chain": {"pem"}},
		body:    []byte("collateral"),
		fetched: time.Now().Add(-2 * time.Hour).UTC(),
	}

	t.Run("round-trips an entry with its original fetch time", func(t *testing.T) {
		// The fetch time is the load-bearing field: it is what
		// collateralStaleMax is measured against, so a store that reset
		// it on load would hand every restart a fresh-looking cache and
		// silently disable the bound.
		s := &collateralStore{path: filepath.Join(t.TempDir(), collateralStoreFile)}
		s.save(map[string]collateralEntry{"u": entry})

		got := s.load()
		if len(got) != 1 {
			t.Fatalf("loaded %d entries, want 1", len(got))
		}
		back, ok := got["u"]
		if !ok {
			t.Fatal("the URL key did not survive the round trip")
		}
		if string(back.body) != string(entry.body) {
			t.Errorf("body = %q, want %q", back.body, entry.body)
		}
		if !back.fetched.Equal(entry.fetched) {
			t.Errorf("fetched = %v, want %v — the staleness bound would restart from zero",
				back.fetched, entry.fetched)
		}
		if len(back.header["X-Chain"]) != 1 {
			t.Errorf("header did not survive: %v — the issuer chain rides there", back.header)
		}
	})

	t.Run("a corrupt file starts cold rather than failing", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), collateralStoreFile)
		if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := (&collateralStore{path: path}).load(); got != nil {
			t.Errorf("loaded %v from a corrupt file", got)
		}
	})

	t.Run("an absent file starts cold", func(t *testing.T) {
		s := &collateralStore{path: filepath.Join(t.TempDir(), "absent.json")}
		if got := s.load(); got != nil {
			t.Errorf("loaded %v from a missing file", got)
		}
	})

	t.Run("a file from a newer version is ignored", func(t *testing.T) {
		// Guessing at an unknown shape is how a mis-read Fetched widens
		// collateralStaleMax without anything failing. One cold round of
		// fetches is the cheaper mistake.
		path := filepath.Join(t.TempDir(), collateralStoreFile)
		raw, err := json.Marshal(persistedCollateral{
			Version: collateralStoreVersion + 1,
			Entries: []persistedEntry{{URL: "u", Body: []byte("x"), Fetched: entry.fetched}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := (&collateralStore{path: path}).load(); got != nil {
			t.Errorf("loaded %v from a future version", got)
		}
	})

	t.Run("an entry with no fetch time is dropped", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), collateralStoreFile)
		raw, err := json.Marshal(persistedCollateral{
			Version: collateralStoreVersion,
			Entries: []persistedEntry{{URL: "u", Body: []byte("x")}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := (&collateralStore{path: path}).load(); len(got) != 0 {
			t.Errorf("loaded %v, want the undated entry dropped", got)
		}
	})

	t.Run("an entry stamped in the future is dropped", func(t *testing.T) {
		// The direction that matters. A future Fetched makes the age
		// negative, which reads as fresher than fresh and turns off the
		// TTL and collateralStaleMax together — and persisting it is
		// what carries the condition past the restart that used to
		// clear it.
		path := filepath.Join(t.TempDir(), collateralStoreFile)
		raw, err := json.Marshal(persistedCollateral{
			Version: collateralStoreVersion,
			Entries: []persistedEntry{{
				URL: "u", Body: []byte("x"), Fetched: time.Now().Add(2 * 24 * time.Hour),
			}},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if got := (&collateralStore{path: path}).load(); len(got) != 0 {
			t.Errorf("loaded %v, want the future-dated entry dropped", got)
		}
	})

	t.Run("an entry past collateralStaleMax is pruned, one inside it is kept", func(t *testing.T) {
		// Pruning changes no verdict — the stale arm already refuses one
		// this old — so the assertion is about the FILE not growing
		// without bound: save re-serializes the loaded map, so an entry
		// nothing can ever serve would otherwise be rewritten forever.
		//
		// Both sides of the boundary, because "drop everything" satisfies
		// the first half alone and would empty the cache on every restart,
		// which is the failure this whole store exists to prevent.
		path := filepath.Join(t.TempDir(), collateralStoreFile)
		raw, err := json.Marshal(persistedCollateral{
			Version: collateralStoreVersion,
			Entries: []persistedEntry{
				{URL: "dead", Body: []byte("x"), Fetched: time.Now().Add(-collateralStaleMax - time.Hour)},
				{URL: "live", Body: []byte("y"), Fetched: time.Now().Add(-collateralStaleMax + time.Hour)},
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		got := (&collateralStore{path: path}).load()
		if _, ok := got["dead"]; ok {
			t.Error("an entry past collateralStaleMax survived the load and will be rewritten")
		}
		if _, ok := got["live"]; !ok {
			t.Errorf("loaded %v — an entry INSIDE the bound was pruned, which throws away "+
				"the outage cache on every restart", got)
		}
	})

	t.Run("a nil store is a no-op, not a panic", func(t *testing.T) {
		// A machine with no resolvable state directory must degrade to
		// the in-memory cache rather than fail to start.
		var s *collateralStore
		s.save(map[string]collateralEntry{"u": entry})
		if got := s.load(); got != nil {
			t.Errorf("load() = %v on a nil store", got)
		}
	})
}

// THE CACHE HAS TO ACTUALLY REACH THE STORE, and nothing proved it did.
//
// TestCollateralStore exercises save/load in isolation, so both halves of
// the wiring could be removed with the suite green: deleting
// persistSoon()'s call site, or setting store to nil where the shared
// cache is built. Either one restores the failure mode the store exists
// to close — a restart mid-outage starting cold, with stale-while-
// revalidate holding nothing to serve.
//
// Driven through getWithContext rather than by calling persistSoon
// directly, because the call SITE is the part that goes missing.
func TestCachingGetter_PersistsAfterASuccessfulFetch(t *testing.T) {
	path := filepath.Join(t.TempDir(), collateralStoreFile)
	c := &cachingGetter{
		inner:           &stubCollateral{body: []byte("collateral")},
		ttl:             collateralTTL,
		entries:         map[string]collateralEntry{},
		store:           newCollateralStoreAt(path),
		persistDebounce: time.Millisecond,
	}

	const url = "https://pcs.example/tcb"
	if _, _, _, err := c.getWithContext(context.Background(), url); err != nil {
		t.Fatalf("getWithContext: %v", err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if got := (&collateralStore{path: path}).load(); len(got) == 1 {
			if string(got[url].body) != "collateral" {
				t.Errorf("persisted body = %q, want the fetched document", got[url].body)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("a successful fetch never reached the store — the cache dies with the " +
				"process, so a restart during a PCS outage starts cold")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A store attached to a cache already in use loads what the file holds
// without overwriting what this process fetched, then persists to that path
// and no other.
func TestCachingGetter_AttachStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), collateralStoreFile)
	old := time.Now().Add(-time.Hour)
	(&collateralStore{path: path}).save(map[string]collateralEntry{
		"https://pcs.example/a": {body: []byte("disk a"), fetched: old},
		"https://pcs.example/b": {body: []byte("disk b"), fetched: old},
	})
	c := &cachingGetter{
		ttl:     collateralTTL,
		entries: map[string]collateralEntry{"https://pcs.example/a": {body: []byte("fetched a"), fetched: time.Now()}},
	}
	if err := c.attachStore(path); err != nil {
		t.Fatal(err)
	}
	if got := string(c.entries["https://pcs.example/a"].body); got != "fetched a" {
		t.Errorf("entry a = %q: the file replaced what this process fetched", got)
	}
	if got := string(c.entries["https://pcs.example/b"].body); got != "disk b" {
		t.Errorf("entry b = %q, want the file's", got)
	}
	if c.store == nil || c.store.path != path {
		t.Fatalf("store %+v, want one at %s", c.store, path)
	}
	if err := c.attachStore(path); err != nil {
		t.Errorf("the same path again: %v", err)
	}
	if err := c.attachStore(filepath.Join(t.TempDir(), collateralStoreFile)); err == nil {
		t.Error("a second path was accepted; the cache persists to one")
	}
	if c.store.path != path {
		t.Errorf("store moved to %s", c.store.path)
	}
}
