/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// A pass that consulted no collateral is a silent downgrade to "the
// chain signs this and roots at Intel" — which a revoked platform, or
// one at a withdrawn TCB level, satisfies perfectly. A genuine quote
// verifies either way, so the only observable difference is the absence
// of PCS traffic.

// stubCollateral is a contextGetter that can succeed, fail, or block.
//
// staleCause makes it answer the way cachingGetter does during an
// outage: bytes and a nil error, plus the fetch failure that forced them
// out of cache.
type stubCollateral struct {
	mu         sync.Mutex
	calls      int
	err        error
	staleCause error
	body       []byte
	block      time.Duration
	blocks     int
}

func (s *stubCollateral) getWithContext(ctx context.Context, _ string) (map[string][]string, []byte, error, error) {
	s.mu.Lock()
	s.calls++
	block := s.block
	s.mu.Unlock()

	if block > 0 {
		s.mu.Lock()
		s.blocks++
		s.mu.Unlock()
		// Honour the deadline, which is the whole property under test.
		select {
		case <-ctx.Done():
			return nil, nil, nil, ctx.Err()
		case <-time.After(block):
		}
	}
	if s.err != nil {
		return nil, nil, nil, s.err
	}
	return map[string][]string{}, s.body, s.staleCause, nil
}

func (s *stubCollateral) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.calls
}

// An unreachable PCS must surface as OUR outage and must do so
// PROMPTLY. Both halves matter and they fail in different ways:
// mis-tagging turns one Intel outage into "every operator is forging
// evidence", while a slow return blows the whole refresh cycle — the
// probes share one WaitGroup under DefaultRefreshTimeout, so a single
// stalled dstack operator delays discovery fleet-wide.
func TestVerifyTDXQuoteChain_UnreachablePCS(t *testing.T) {
	quote, _ := loadDstackVectors(t)

	t.Run("maps to ErrCollateralUnavailable", func(t *testing.T) {
		stub := &stubCollateral{err: errors.New("dial tcp: connection refused")}
		_, err := verifyTDXQuoteChainWith(context.Background(), quote, stub)
		if !errors.Is(err, ErrCollateralUnavailable) {
			t.Fatalf("err = %v, want ErrCollateralUnavailable", err)
		}
		if stub.count() == 0 {
			t.Error("no collateral fetch was attempted")
		}
	})

	t.Run("returns within the collateral timeout", func(t *testing.T) {
		// Blocks far longer than the ceiling. The library's own default
		// getter would sit here for two minutes — it wraps a bare
		// http.Get on a client with no timeout and consults a context
		// only BETWEEN retries — so this is the regression that a
		// context-aware getter exists to prevent.
		//
		// THE BOUNDS ARE LITERALS, NOT MULTIPLES OF collateralTimEOUT.
		// An earlier version blocked `10 * collateralTimeout` and
		// asserted `elapsed < collateralTimeout + 2s`, which scales
		// with the constant under test and therefore passes for ANY
		// value of it — including 80s, which blows the refresh cycle
		// this constant exists to stay inside.
		const (
			blockFor = 90 * time.Second
			mustBeat = 15 * time.Second
		)
		stub := &stubCollateral{block: blockFor}

		start := time.Now()
		_, err := verifyTDXQuoteChainWith(context.Background(), quote, stub)
		elapsed := time.Since(start)

		if !errors.Is(err, ErrCollateralUnavailable) {
			t.Errorf("err = %v, want ErrCollateralUnavailable", err)
		}
		if elapsed > mustBeat {
			t.Errorf("took %v, want under %v — the deadline does not reach the fetch",
				elapsed, mustBeat)
		}
	})

	t.Run("an already-cancelled context does not fetch", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		stub := &stubCollateral{}
		if _, err := verifyTDXQuoteChainWith(ctx, quote, stub); !errors.Is(err, ErrCollateralUnavailable) {
			t.Errorf("err = %v, want ErrCollateralUnavailable", err)
		}
		if stub.count() != 0 {
			t.Errorf("%d fetches issued under a cancelled context", stub.count())
		}
	})
}

// The zero-fetch tripwire, tested DIRECTLY.
//
// An earlier version of this test drove verifyTDXQuoteChainWith with an
// empty-body stub and asserted only that it errored — which it does,
// from the library's own collateral parsing, BEFORE the guard is ever
// reached. The guard could be deleted outright and that test stayed
// green: it was named for a property it never executed.
//
// The guard is now its own function precisely so it can be pinned
// without needing a scenario where the library succeeds while fetching
// nothing — a state that is unreachable through the real options, which
// is exactly why the integration-shaped test could not work.
func TestRequireCollateralFetched(t *testing.T) {
	if err := requireCollateralFetched(0); err == nil {
		t.Error("requireCollateralFetched(0) = nil — a pass that consulted no " +
			"collateral would be accepted, i.e. revocation and TCB checks skipped")
	}
	for _, n := range []int{1, 2, 17} {
		if err := requireCollateralFetched(n); err != nil {
			t.Errorf("requireCollateralFetched(%d) = %v, want nil", n, err)
		}
	}
}

// collateralTimeout is sized against the REFRESH CYCLE, and that
// relationship is the whole reason for its value — the probes share one
// WaitGroup under DefaultRefreshTimeout, so a ceiling near it lets one
// unreachable third party cost the proxy a complete refresh.
//
// Asserted against the thing it is sized against rather than against
// itself.
func TestCollateralTimeoutFitsTheRefreshCycle(t *testing.T) {
	if collateralTimeout >= DefaultRefreshTimeout {
		t.Errorf("collateralTimeout = %v, DefaultRefreshTimeout = %v — one stalled "+
			"operator can now consume the whole refresh cycle",
			collateralTimeout, DefaultRefreshTimeout)
	}
	// Comfortably inside, not merely under: several operators may stall
	// in the same cycle.
	if collateralTimeout > DefaultRefreshTimeout/2 {
		t.Errorf("collateralTimeout = %v is more than half of DefaultRefreshTimeout (%v)",
			collateralTimeout, DefaultRefreshTimeout)
	}
}

// recordingCollateral records the URLs a verification requests while
// delegating the fetch, so a test can assert WHICH Intel endpoints were
// consulted.
//
// It has to delegate rather than stub: the library requests the CRL
// only after the TCB fetch SUCCEEDS, so a getter that errors never
// reaches the endpoint the assertion is about. That is why the
// revocation check is pinned in the network-gated file rather than
// here.
type recordingCollateral struct {
	inner contextGetter
	mu    sync.Mutex
	seen  []string
}

func (r *recordingCollateral) getWithContext(ctx context.Context, url string) (map[string][]string, []byte, error, error) {
	r.mu.Lock()
	r.seen = append(r.seen, url)
	r.mu.Unlock()
	return r.inner.getWithContext(ctx, url)
}

func (r *recordingCollateral) urls() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.seen...)
}

func (r *recordingCollateral) sawCRL() bool {
	for _, u := range r.urls() {
		if strings.Contains(strings.ToLower(u), "crl") {
			return true
		}
	}
	return false
}

// The deadline has to survive every seam between the refresh cycle and
// the socket. Severing it at ANY of them restores the two-minute stall
// this code was rewritten to remove, and each seam is a one-line edit
// that compiles.
//
// Driven through BundleVerifier rather than the helper, because the
// seam that carries ctx into the dstack branch is the one the other
// tests bypass — every dstack test stubs VerifyChain, so none of them
// exercises cancellation through the dispatch path at all.
func TestBundleVerifier_CarriesTheDeadlineIntoTheChainCheck(t *testing.T) {
	v, op, bundle := dstackFixture(t)

	var sawCtx context.Context
	v.VerifyChain = func(ctx context.Context, _ []byte) error {
		sawCtx = ctx
		return ctx.Err()
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	verdict := v.Verify(ctx, dstackAdvertisement(), bundle, op)
	if verdict.Pass {
		t.Fatal("verified under a cancelled context")
	}
	if sawCtx == nil {
		t.Fatal("the chain check never ran")
	}
	if sawCtx.Err() == nil {
		t.Error("the chain check received a live context from a cancelled one — " +
			"the refresh cycle's deadline does not reach collateral fetching")
	}
}

// A NIL VerifyChain MUST REACH THE REAL INTEL VERIFICATION, and that
// branch is the only one production ever takes: buildTEEVerifier never
// sets the field, while every other test in this package does. So the
// one path that matters was the one path nothing executed.
//
// What it protects: with the fallback replaced by an accept-everything
// stub, an operator's self-authored bytes are accepted as a hardware
// quote — and because report_data is signed blindly, every downstream
// check (replay, allowlist, key binding, posture) silently becomes a
// statement about a file the operator wrote.
//
// Driven with an already-cancelled context so this runs offline: the
// real verifier reports ErrCollateralUnavailable, which an
// accept-everything stub cannot produce.
func TestDstackVerifier_NilVerifyChainUsesTheRealVerifier(t *testing.T) {
	_, op, bundle := dstackFixture(t)

	dv := &DstackVerifier{
		TrustedComposeHashes: []string{capturedComposeHash},
		TrustedOSImages:      []string{capturedOSImage},
		VerifyChain:          nil, // the production wiring
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	tag := dv.Verify(ctx, bundle, op)
	if tag == "" {
		t.Fatal("a nil VerifyChain PASSED verification — the real Intel check is not " +
			"reached, so self-authored bytes would be accepted as a hardware quote")
	}
	if tag != FailureCollateralUnreachable {
		t.Errorf("tag = %q, want %q — the nil fallback is not VerifyTDXQuoteChain",
			tag, FailureCollateralUnreachable)
	}
}

// The shared cache has to be the one PRODUCTION uses. TestCachingGetter
// proves the type works; nothing proved VerifyTDXQuoteChain reaches it,
// so the whole layer could be unplugged — restoring one Intel request
// per operator per refresh cycle, and a hard routing dependency on PCS
// uptime.
func TestSharedCollateralCacheIsAProcessSingleton(t *testing.T) {
	a, b := sharedCollateralCache(), sharedCollateralCache()
	if a != b {
		t.Error("sharedCollateralCache() returned different instances; the TTL cache " +
			"is per-call and therefore does nothing")
	}
	if a.ttl != collateralTTL {
		t.Errorf("shared cache ttl = %v, want collateralTTL (%v)", a.ttl, collateralTTL)
	}
	if _, ok := a.inner.(*pcsGetter); !ok {
		t.Errorf("shared cache wraps %T, want *pcsGetter", a.inner)
	}

	// And it must be PERSISTED, at the state directory. Without the store
	// the cache dies with the process, which is failure mode (2) the
	// whole file exists to close: a restart during a PCS outage starts
	// cold and stale-while-revalidate has nothing to serve. The path is
	// asserted too: it must be the directory the process configured, which
	// TestMain sets to a temporary one.
	dir := testStateDir
	if dir == "" {
		t.Fatal("TestMain did not persist the collateral cache")
	}
	if a.store == nil {
		t.Fatal("the shared cache has no store — nothing survives a restart")
	}
	if want := filepath.Join(dir, collateralStoreFile); a.store.path != want {
		t.Errorf("store path = %q, want %q", a.store.path, want)
	}
}

// pcsGetter must put the deadline on the REQUEST, and its client must
// carry a timeout as a backstop. Both are what stop a socket that
// connects and goes silent from blocking indefinitely — the library's
// default getter did exactly that.
func TestPCSGetter_HonoursTheContext(t *testing.T) {
	g := &pcsGetter{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	// A cancelled context must fail immediately and must not reach the
	// network. 127.0.0.1:1 would otherwise refuse fast; the assertion
	// is that we never get that far.
	start := time.Now()
	_, _, _, err := g.getWithContext(ctx, "https://127.0.0.1:1/tcb")
	if err == nil {
		t.Fatal("getWithContext succeeded under a cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled — the request does not carry the context", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("took %v under an already-cancelled context", elapsed)
	}

	// The backstop, asserted as a property of the client rather than by
	// waiting for it.
	if pcsHTTPClient.Timeout <= 0 {
		t.Error("pcsHTTPClient has no timeout; a silent socket would block forever " +
			"if a context ever failed to reach it")
	}
	if pcsHTTPClient.Timeout > collateralTimeout {
		t.Errorf("pcsHTTPClient.Timeout = %v exceeds collateralTimeout = %v",
			pcsHTTPClient.Timeout, collateralTimeout)
	}
}

// Everything AFTER the response arrives. TestPCSGetter_HonoursTheContext
// only drives the cancelled path, where Do returns before a response
// exists — so the status check, the body cap, and the client actually
// being used were all unexecuted.
func TestPCSGetter_Response(t *testing.T) {
	g := &pcsGetter{}

	t.Run("a non-200 is an error, not collateral", func(t *testing.T) {
		// Otherwise a PCS 404/500 error page is handed to the library
		// AS collateral — and cachingGetter stores it as a success for
		// the full TTL, while verifyGetter records no error, so the
		// verdict is tagged vendor_chain_invalid ("this operator forged
		// evidence") for the whole hour.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("upstream unavailable"))
		}))
		defer srv.Close()

		if _, _, _, err := g.getWithContext(context.Background(), srv.URL); err == nil {
			t.Error("a 503 was accepted as collateral")
		}
	})

	t.Run("a 200 is returned", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("collateral"))
		}))
		defer srv.Close()

		_, body, _, err := g.getWithContext(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("getWithContext: %v", err)
		}
		if string(body) != "collateral" {
			t.Errorf("body = %q", body)
		}
	})

	t.Run("the body is capped", func(t *testing.T) {
		// A hijacked or misbehaving endpoint must not stream unbounded
		// bytes into the proxy's memory.
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			chunk := make([]byte, 1<<20)
			for i := 0; i < (maxCollateralBytes/len(chunk))+2; i++ {
				if _, err := w.Write(chunk); err != nil {
					return
				}
			}
		}))
		defer srv.Close()

		_, body, _, err := g.getWithContext(context.Background(), srv.URL)
		if err != nil {
			t.Fatalf("getWithContext: %v", err)
		}
		if len(body) > maxCollateralBytes {
			t.Errorf("body is %d bytes, want at most %d — the read is unbounded",
				len(body), maxCollateralBytes)
		}
	})

	t.Run("the fetch goes through pcsHTTPClient", func(t *testing.T) {
		// Asserting the client's Timeout is a property of the VARIABLE
		// and says nothing about whether the variable is used —
		// swapping in http.DefaultClient (no timeout) is exactly the
		// regression this type exists to prevent.
		orig := pcsHTTPClient
		t.Cleanup(func() { pcsHTTPClient = orig })

		rt := &recordingRoundTripper{inner: http.DefaultTransport}
		pcsHTTPClient = &http.Client{Transport: rt, Timeout: collateralTimeout}

		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte("ok"))
		}))
		defer srv.Close()

		if _, _, _, err := g.getWithContext(context.Background(), srv.URL); err != nil {
			t.Fatalf("getWithContext: %v", err)
		}
		if rt.count() == 0 {
			t.Error("the request did not go through pcsHTTPClient")
		}
	})
}

type recordingRoundTripper struct {
	inner http.RoundTripper
	mu    sync.Mutex
	n     int
}

func (r *recordingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.n++
	r.mu.Unlock()
	return r.inner.RoundTrip(req)
}

func (r *recordingRoundTripper) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.n
}

func TestCachingGetter(t *testing.T) {
	t.Run("failures are not cached", func(t *testing.T) {
		// Caching a failure pins a transient PCS blip for the whole TTL
		// and takes every TEE operator out of routing at once.
		stub := &stubCollateral{err: errors.New("503")}
		c := &cachingGetter{inner: stub, ttl: time.Hour, entries: map[string]collateralEntry{}}

		for i := 0; i < 3; i++ {
			if _, _, _, err := c.getWithContext(context.Background(), "u"); err == nil {
				t.Fatal("expected an error")
			}
		}
		if stub.count() != 3 {
			t.Errorf("%d fetches, want 3 — a failure was cached", stub.count())
		}
	})

	t.Run("successes are cached until the TTL elapses", func(t *testing.T) {
		// Without expiry, CRLs and TCB info are fetched once per
		// process — so a platform Intel revokes an hour into uptime
		// keeps verifying for the life of the proxy.
		stub := &stubCollateral{body: []byte("ok")}
		now := time.Unix(1_750_000_000, 0)
		// collateralTTL, not a hardcoded time.Hour. They are equal
		// today, so a literal here passes for ANY production value —
		// including one long enough that a platform Intel revokes keeps
		// verifying for the rest of the process's life.
		c := &cachingGetter{
			inner:   stub,
			ttl:     collateralTTL,
			now:     func() time.Time { return now },
			entries: map[string]collateralEntry{},
		}

		for i := 0; i < 3; i++ {
			if _, _, _, err := c.getWithContext(context.Background(), "u"); err != nil {
				t.Fatal(err)
			}
		}
		if stub.count() != 1 {
			t.Errorf("%d fetches inside the TTL, want 1", stub.count())
		}

		now = now.Add(collateralTTL + time.Second)
		if _, _, _, err := c.getWithContext(context.Background(), "u"); err != nil {
			t.Fatal(err)
		}
		if stub.count() != 2 {
			t.Errorf("%d fetches after the TTL elapsed, want 2 — the entry never expires", stub.count())
		}
	})

	t.Run("distinct URLs do not share an entry", func(t *testing.T) {
		stub := &stubCollateral{body: []byte("ok")}
		c := &cachingGetter{inner: stub, ttl: time.Hour, entries: map[string]collateralEntry{}}
		for _, u := range []string{"a", "b", "a"} {
			if _, _, _, err := c.getWithContext(context.Background(), u); err != nil {
				t.Fatal(err)
			}
		}
		if stub.count() != 2 {
			t.Errorf("%d fetches, want 2", stub.count())
		}
	})
}

// The allowlist is typed by a human into YAML while the measurement
// side arrives already lowercased and 0x-stripped. So the normalization
// that matters is the CONFIG side, and an exact compare silently empties
// the allowlist for perfectly reasonable entries.
func TestContainsHexFold(t *testing.T) {
	const want = "6e6f3898b6c20ee50c12713a80453da2c992de95e857d64791b909037f157485"

	cases := []struct {
		name string
		list []string
		in   string
		ok   bool
	}{
		{"exact", []string{want}, want, true},
		{"uppercase config entry", []string{strings.ToUpper(want)}, want, true},
		{"0x-prefixed config entry", []string{"0x" + want}, want, true},
		{"whitespace around config entry", []string{"  " + want + "\t"}, want, true},
		{"0x-prefixed measurement", []string{want}, "0x" + want, true},
		// BOTH at once. The uppercase and 0x-prefix cases above are
		// each satisfied by either ordering of ToLower/TrimPrefix — only
		// an entry carrying both distinguishes them, and `0X`-prefixed
		// uppercase is what an operator pasting a digest out of a block
		// explorer produces. The failure is silent: the entry never
		// matches and every dstack operator fails measurement_mismatch.
		{"0X-prefixed uppercase config entry", []string{"0X" + strings.ToUpper(want)}, want, true},
		{"0X-prefixed uppercase measurement", []string{want}, "0X" + strings.ToUpper(want), true},
		{"not present", []string{strings.Repeat("aa", 32)}, want, false},
		{"empty allowlist", nil, want, false},
		// The one direction that fails OPEN: an empty measurement must
		// never match, even against an allowlist entry that is also
		// empty (`trusted_os_images: [""]` is easy to write by
		// accident).
		{"empty measurement against empty entry", []string{""}, "", false},
		{"empty measurement against a real entry", []string{want}, "", false},
		// The same hole one normalization step later, and the reason the
		// emptiness test moved AFTER normalizeHex. "0x" and "  " are not
		// empty strings, so a guard on the raw value waves them through;
		// they then normalize to "" and match a blank list entry. A
		// stray `- ""` in YAML is the easiest possible config typo, and
		// this is the shape where it turns into "accept anything".
		{"0x-only measurement against empty entry", []string{""}, "0x", false},
		{"whitespace measurement against empty entry", []string{""}, "   ", false},
		{"0x-only measurement against 0x-only entry", []string{"0x"}, "0x", false},
		// ...and a blank entry must not become a wildcard for a real
		// measurement either.
		{"real measurement against a list of blanks", []string{"", "  ", "0x"}, want, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := containsHexFold(tc.list, tc.in); got != tc.ok {
				t.Errorf("containsHexFold(%q, %q) = %v, want %v", tc.list, tc.in, got, tc.ok)
			}
		})
	}
}
