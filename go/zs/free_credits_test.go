/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/freecredit"
	"github.com/TxnLab/zerosignal/go/ticket"
)

var creditDep = ticket.DeploymentID{0xc0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}

// fakeIssuer signs with a day signer it makes for each epoch it is asked for.
type fakeIssuer struct {
	t      *testing.T
	master ed25519.PrivateKey

	mu      sync.Mutex
	signers map[freecredit.Epoch]*freecredit.DaySigner
	dayKeys int
	issues  int
	// err fails every call; exhausted answers credits_exhausted.
	err       error
	exhausted *CreditsExhaustedError
	// signOnly signs only the first n messages when set.
	signOnly int
	// certFor, when set, replaces the certificate served.
	certFor func(freecredit.DayKeyCert) freecredit.DayKeyCert
	// signWith, when set, signs with this signer instead.
	signWith *freecredit.DaySigner
	// gate blocks Issue until closed.
	gate chan struct{}
}

func newFakeIssuer(t *testing.T) *fakeIssuer {
	_, master, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeIssuer{t: t, master: master, signers: map[freecredit.Epoch]*freecredit.DaySigner{}}
}

func (f *fakeIssuer) key() string {
	return base64.StdEncoding.EncodeToString(f.master.Public().(ed25519.PublicKey))
}

func (f *fakeIssuer) signer(epoch freecredit.Epoch) *freecredit.DaySigner {
	if s := f.signers[epoch]; s != nil {
		return s
	}
	s, err := freecredit.NewDaySigner(nil, f.master, creditDep, epoch)
	if err != nil {
		f.t.Fatal(err)
	}
	f.signers[epoch] = s
	return s
}

func (f *fakeIssuer) DayKey(_ context.Context, dep ticket.DeploymentID, epoch freecredit.Epoch) (freecredit.DayKeyCert, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dayKeys++
	if f.err != nil {
		return freecredit.DayKeyCert{}, f.err
	}
	cert := f.signer(epoch).Key().Cert()
	if f.certFor != nil {
		cert = f.certFor(cert)
	}
	return cert, nil
}

func (f *fakeIssuer) Issue(ctx context.Context, _ ticket.DeploymentID, epoch freecredit.Epoch, blinded [][]byte) ([][]byte, error) {
	f.mu.Lock()
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.issues++
	if f.err != nil {
		return nil, f.err
	}
	if f.exhausted != nil {
		return nil, f.exhausted
	}
	s := f.signer(epoch)
	if f.signWith != nil {
		s = f.signWith
	}
	n := len(blinded)
	if f.signOnly > 0 {
		n = min(n, f.signOnly)
	}
	out := make([][]byte, n)
	for i := range n {
		sig, err := s.Sign(blinded[i])
		if err != nil {
			return nil, err
		}
		out[i] = sig
	}
	return out, nil
}

func (f *fakeIssuer) calls() (dayKeys, issues int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.dayKeys, f.issues
}

// testClock is a settable clock.
type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.now = c.now.Add(d)
	c.mu.Unlock()
}

// noon is the middle of a UTC day, well clear of the grace either side.
var noon = time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)

func newTestCreditWallet(t *testing.T, issuers map[string]CreditIssuer) (*creditWallet, *testClock) {
	t.Helper()
	clock := &testClock{now: noon}
	w := newCreditWallet(FreeCredits{Issuers: issuers}, ticket.RailSolana, creditDep, clock.Now, slog.New(slog.DiscardHandler))
	if w == nil {
		t.Fatal("no wallet")
	}
	return w, clock
}

var creditTestNode = freecredit.Node{Operator: 7, Node: 2}

// verifies checks that h is a credit node accepts today from issuer.
func verifies(t *testing.T, h *heldCredit, issuer *fakeIssuer, node freecredit.Node) {
	t.Helper()
	if h == nil {
		t.Fatal("no credit")
	}
	c, err := freecredit.ParseCredit(h.raw)
	if err != nil {
		t.Fatal(err)
	}
	pub := issuer.master.Public().(ed25519.PublicKey)
	if err := freecredit.Verify([]ed25519.PublicKey{pub}, creditDep, node, freecredit.AcceptedEpochs(noon), c); err != nil {
		t.Fatalf("the credit does not verify: %v", err)
	}
}

func stored(w *creditWallet) int {
	m := w.store.(*memoryCreditStore)
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, cs := range m.credits {
		n += len(cs)
	}
	return n
}

// One fetch brings a batch: the first credit now, the rest for the node's
// next turns, which fetch nothing until the batch is spent.
func TestCreditWallet_FetchesABatchForLaterTurns(t *testing.T) {
	is := newFakeIssuer(t)
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	seen := map[string]bool{}
	for i := range DefaultFreeCreditBatch {
		h := w.take(t.Context(), []string{is.key()}, creditTestNode)
		verifies(t, h, is, creditTestNode)
		if seen[string(h.credit.Nonce)] {
			t.Fatalf("turn %d got a credit already given", i)
		}
		seen[string(h.credit.Nonce)] = true
		h.spend()
	}
	if dk, iss := is.calls(); dk != 1 || iss != 1 {
		t.Fatalf("%d day key and %d issue calls for one batch, want 1 and 1", dk, iss)
	}
	verifies(t, w.take(t.Context(), []string{is.key()}, creditTestNode), is, creditTestNode)
	if dk, iss := is.calls(); dk != 1 || iss != 2 {
		t.Errorf("%d day key and %d issue calls after the batch, want the day key kept and a second issue", dk, iss)
	}
}

// A credit names its node, so another node's turn fetches its own.
func TestCreditWallet_KeepsEachNodesCreditsApart(t *testing.T) {
	is := newFakeIssuer(t)
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	w.take(t.Context(), []string{is.key()}, creditTestNode).spend()
	other := freecredit.Node{Operator: 7, Node: 3}
	verifies(t, w.take(t.Context(), []string{is.key()}, other), is, other)
	if _, iss := is.calls(); iss != 2 {
		t.Errorf("%d issue calls for two nodes, want 2", iss)
	}
}

// Turns at one node that find a fetch running wait for it and share its batch,
// so a burst costs the issuer one call.
func TestCreditWallet_OneFetchAtATimePerNode(t *testing.T) {
	is := newFakeIssuer(t)
	is.gate = make(chan struct{})
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	const turns = 5
	got := make(chan *heldCredit, turns)
	var wg sync.WaitGroup
	for range turns {
		wg.Go(func() { got <- w.take(t.Context(), []string{is.key()}, creditTestNode) })
	}
	// Let every turn reach the fetch before the issuer answers.
	time.Sleep(50 * time.Millisecond)
	close(is.gate)
	wg.Wait()
	close(got)
	n := 0
	for h := range got {
		if h != nil {
			verifies(t, h, is, creditTestNode)
			n++
		}
	}
	if _, iss := is.calls(); iss != 1 {
		t.Errorf("%d issue calls for a burst, want 1", iss)
	}
	if n != DefaultFreeCreditBatch {
		t.Errorf("%d turns got a credit, want the batch's %d", n, DefaultFreeCreditBatch)
	}
}

// An issuer that fails is skipped for a minute, so a down issuer costs one
// timeout a minute and not one a turn.
func TestCreditWallet_SkipsAFailingIssuerForAMinute(t *testing.T) {
	is := newFakeIssuer(t)
	is.err = errors.New("down")
	w, clock := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	if h := w.take(t.Context(), []string{is.key()}, creditTestNode); h != nil {
		t.Fatal("a credit from a failing issuer")
	}
	clock.add(freeCreditFailureBackoff - time.Second)
	w.take(t.Context(), []string{is.key()}, creditTestNode)
	if dk, _ := is.calls(); dk != 1 {
		t.Fatalf("asked %d times within the backoff, want once", dk)
	}
	clock.add(time.Second)
	is.mu.Lock()
	is.err = nil
	is.mu.Unlock()
	verifies(t, w.take(t.Context(), []string{is.key()}, creditTestNode), is, creditTestNode)
}

// Once its cap is spent an issuer is skipped until its Retry-After, or with
// none until the next UTC day, when the cap resets; never for less than the
// failure backoff.
func TestCreditWallet_SkipsAnExhaustedIssuer(t *testing.T) {
	for _, tc := range []struct {
		name       string
		retryAfter time.Duration
		want       time.Duration
	}{
		{"its Retry-After", 2 * time.Hour, 2 * time.Hour},
		{"no Retry-After: the next day", 0, 12 * time.Hour},
		{"at least the failure backoff", time.Second, freeCreditFailureBackoff},
		{"at most a day", 72 * time.Hour, 24 * time.Hour},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := newFakeIssuer(t)
			is.exhausted = &CreditsExhaustedError{RetryAfter: tc.retryAfter}
			w, clock := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
			w.take(t.Context(), []string{is.key()}, creditTestNode)
			if got := w.issuers[is.key()].skipUntil.Sub(clock.Now()); got != tc.want {
				t.Errorf("skipped for %s, want %s", got, tc.want)
			}
		})
	}
}

// A turn takes from the first issuer that gives a credit, so a down issuer
// leaves the next one to serve.
func TestCreditWallet_FallsThroughToTheNextIssuer(t *testing.T) {
	down, up := newFakeIssuer(t), newFakeIssuer(t)
	down.err = errors.New("down")
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{down.key(): down, up.key(): up})
	unknown := base64.StdEncoding.EncodeToString(make([]byte, 32))
	verifies(t, w.take(t.Context(), []string{unknown, down.key(), up.key()}, creditTestNode), up, creditTestNode)
}

// The payer blinds only to a day key its issuer certified for this day and
// deployment, and keeps only credits that verify: anything else is an issuer
// fault, which benches it.
func TestCreditWallet_RefusesWhatTheIssuerShouldNotHaveSent(t *testing.T) {
	impostor := newFakeIssuer(t)
	other, err := freecredit.NewDaySigner(nil, newFakeIssuer(t).master, creditDep, freecredit.EpochAt(noon))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		set  func(*fakeIssuer)
	}{
		{"a day key another issuer certified", func(f *fakeIssuer) {
			f.certFor = func(freecredit.DayKeyCert) freecredit.DayKeyCert {
				return impostor.signer(freecredit.EpochAt(noon)).Key().Cert()
			}
		}},
		// Signed under the day key served, so only the epoch check refuses it.
		{"yesterday's day key", func(f *fakeIssuer) {
			s := f.signer(freecredit.EpochAt(noon) - 1)
			f.certFor = func(freecredit.DayKeyCert) freecredit.DayKeyCert { return s.Key().Cert() }
			f.signWith = s
		}},
		{"a day key for another day", func(f *fakeIssuer) {
			s := f.signer(freecredit.EpochAt(noon) + 1)
			f.certFor = func(freecredit.DayKeyCert) freecredit.DayKeyCert { return s.Key().Cert() }
			f.signWith = s
		}},
		{"a tampered certificate", func(f *fakeIssuer) {
			f.certFor = func(c freecredit.DayKeyCert) freecredit.DayKeyCert {
				c.CertSig = append(freecredit.Bytes(nil), c.CertSig...)
				c.CertSig[0] ^= 1
				return c
			}
		}},
		{"signatures under another day key", func(f *fakeIssuer) { f.signWith = other }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := newFakeIssuer(t)
			tc.set(is)
			w, clock := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
			if h := w.take(t.Context(), []string{is.key()}, creditTestNode); h != nil {
				t.Fatal("kept a credit")
			}
			if stored(w) != 0 {
				t.Error("stored credits")
			}
			if !clock.Now().Before(w.issuers[is.key()].skipUntil) {
				t.Error("the issuer was not benched")
			}
		})
	}
}

// An issuer near its cap signs only the first few; those are kept.
func TestCreditWallet_KeepsAPartialBatch(t *testing.T) {
	is := newFakeIssuer(t)
	is.signOnly = 2
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	verifies(t, w.take(t.Context(), []string{is.key()}, creditTestNode), is, creditTestNode)
	if n := stored(w); n != 1 {
		t.Errorf("%d kept, want the second signed one", n)
	}
}

// A credit the turn didn't use goes back for the node's next turn; one it
// spent, or the node refused, doesn't.
func TestHeldCredit_GoesBackUnlessUsed(t *testing.T) {
	is := newFakeIssuer(t)
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	h := w.take(t.Context(), []string{is.key()}, creditTestNode)
	h.giveBack(t.Context())
	h.giveBack(t.Context())
	if n := stored(w); n != DefaultFreeCreditBatch {
		t.Fatalf("%d kept after a give-back, want the whole batch", n)
	}
	h = w.take(t.Context(), []string{is.key()}, creditTestNode)
	h.spend()
	h.giveBack(t.Context())
	h = w.take(t.Context(), []string{is.key()}, creditTestNode)
	h.drop()
	h.giveBack(t.Context())
	if n := stored(w); n != DefaultFreeCreditBatch-2 {
		t.Errorf("%d kept, want the spent and dropped ones gone", n)
	}
	var none *heldCredit
	none.spend()
	none.giveBack(t.Context())
}

// The day turns: today's credits are minted under today's key.
func TestCreditWallet_MintsUnderEachDaysKey(t *testing.T) {
	is := newFakeIssuer(t)
	w, clock := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	first := w.take(t.Context(), []string{is.key()}, creditTestNode)
	clock.add(24 * time.Hour)
	second := w.take(t.Context(), []string{is.key()}, creditTestNode)
	if second == nil || second.credit.Epoch != first.credit.Epoch+1 {
		t.Fatalf("the next day's credit is for epoch %v, want %d", second, first.credit.Epoch+1)
	}
	if dk, _ := is.calls(); dk != 2 {
		t.Errorf("%d day key fetches over two days, want 2", dk)
	}
}

// The memory store forgets a day once a later day's credits are put, since a
// node accepts the previous day only in the grace after midnight.
func TestMemoryCreditStore_ForgetsOldDays(t *testing.T) {
	s := NewMemoryCreditStore()
	key := CreditKey{Deployment: creditDep, Node: creditTestNode, Epoch: 100, Issuer: "k"}
	c := freecredit.Credit{Nonce: freecredit.Bytes("n")}
	_ = s.Put(t.Context(), key, []freecredit.Credit{c})
	yesterday := key
	key.Epoch = 101
	_ = s.Put(t.Context(), key, []freecredit.Credit{c})
	if _, ok, _ := s.Take(t.Context(), yesterday); !ok {
		t.Fatal("yesterday's credit is gone the next day")
	}
	_ = s.Put(t.Context(), yesterday, []freecredit.Credit{c})
	key.Epoch = 102
	_ = s.Put(t.Context(), key, []freecredit.Credit{c})
	if _, ok, _ := s.Take(t.Context(), yesterday); ok {
		t.Error("a credit two days old is still kept")
	}
}

// The HTTP issuer speaks the issue wire, carries the host's gate headers, and
// reads a spent cap as CreditsExhaustedError with its Retry-After.
func TestHTTPCreditIssuer_SpeaksTheIssueWire(t *testing.T) {
	is := newFakeIssuer(t)
	exhausted := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Gate") != "token" {
			http.Error(w, "no gate", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case freecredit.DayKeyPath:
			var req freecredit.DayKeyRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil || string(req.Deployment) != string(creditDep[:]) {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			cert, _ := is.DayKey(r.Context(), creditDep, req.Epoch)
			_ = json.NewEncoder(w).Encode(cert)
		case freecredit.IssuePath:
			if exhausted {
				w.Header().Set("Retry-After", "120")
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(`{"error":{"code":"credits_exhausted","message":"spent"}}`))
				return
			}
			var req freecredit.IssueRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}
			blinded := make([][]byte, len(req.Blinded))
			for i, b := range req.Blinded {
				blinded[i] = b
			}
			sigs, err := is.Issue(r.Context(), creditDep, req.Epoch, blinded)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			resp := freecredit.IssueResponse{Signatures: make([]freecredit.Bytes, len(sigs))}
			for i, s := range sigs {
				resp.Signatures[i] = s
			}
			_ = json.NewEncoder(w).Encode(resp)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	port := &HTTPCreditIssuer{URL: srv.URL + "/", Header: func(_ context.Context, h http.Header) error {
		h.Set("X-Gate", "token")
		return nil
	}}
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): port})
	verifies(t, w.take(t.Context(), []string{is.key()}, creditTestNode), is, creditTestNode)

	exhausted = true
	_, err := port.Issue(t.Context(), creditDep, freecredit.EpochAt(noon), [][]byte{{1}})
	if ce, ok := errors.AsType[*CreditsExhaustedError](err); !ok || ce.RetryAfter != 2*time.Minute {
		t.Errorf("err = %v, want credits exhausted for 2m", err)
	}
	_, err = (&HTTPCreditIssuer{URL: srv.URL}).DayKey(t.Context(), creditDep, 1)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("err = %v, want the refusal's status", err)
	}
	gateErr := errors.New("no token yet")
	_, err = (&HTTPCreditIssuer{URL: srv.URL, Header: func(context.Context, http.Header) error { return gateErr }}).DayKey(t.Context(), creditDep, 1)
	if !errors.Is(err, gateErr) {
		t.Errorf("err = %v, want the header hook's", err)
	}
}

// Config refuses issuers it could never use, and warns that credits are
// Solana's.
func TestConfig_ChecksFreeCredits(t *testing.T) {
	is := newFakeIssuer(t)
	for _, tc := range []struct {
		name string
		fc   FreeCredits
		want string
	}{
		{"a key that is not 32 bytes", FreeCredits{Issuers: map[string]CreditIssuer{"AAAA": is}}, "32 bytes"},
		{"no way to reach the issuer", FreeCredits{Issuers: map[string]CreditIssuer{is.key(): nil}}, "is nil"},
		{"a batch past the issue cap", FreeCredits{Batch: freecredit.MaxIssueBatch + 1}, "Batch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := suppliedParts(t)
			cfg.FreeCredits = tc.fc
			_, _, err := cfg.withDefaults().validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want one naming %q", err, tc.want)
			}
		})
	}
	cfg := suppliedParts(t)
	// The issue cap itself is a batch an issuer answers.
	cfg.FreeCredits = FreeCredits{Issuers: map[string]CreditIssuer{is.key(): is}, Batch: freecredit.MaxIssueBatch}
	_, warnings, err := cfg.withDefaults().validate()
	if err != nil || len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "FreeCredits") {
		t.Errorf("err %v, warnings %q; want a warning that credits are Solana's", err, warnings)
	}
	if newCreditWallet(cfg.FreeCredits, ticket.RailAlgorand, creditDep, time.Now, slog.Default()) != nil {
		t.Error("a credit wallet on Algorand")
	}
	if newCreditWallet(cfg.FreeCredits, ticket.RailSolana, ticket.DeploymentID{}, time.Now, slog.Default()) != nil {
		t.Error("a credit wallet with no deployment to mint for")
	}
}

// freeCreditClient is a Solana client over one free node trusting is, whose
// reserves rc answers.
func freeCreditClient(t *testing.T, is *fakeIssuer, model ModelCapacity, script ...error) (*Client, *scriptedReserveClient, *creditWallet) {
	t.Helper()
	op := retryOp(7, "OWNER")
	op.NodeID = 2
	op.ModelCapacities = map[string]ModelCapacity{"gpt-test": model}
	op.FreeCreditIssuers = []string{is.key()}
	c, rc := admitClient(t, []Operator{op}, nil)
	rc.script = script
	c.deployment.Rail = ticket.RailSolana
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	c.freeCredits = w
	return c, rc, w
}

func sentCredit(t *testing.T, req ticket.ReserveRequest) *freecredit.Credit {
	t.Helper()
	if req.FreeCredit == nil {
		return nil
	}
	c, err := freecredit.ParseCredit(req.FreeCredit)
	if err != nil {
		t.Fatalf("the reserve's credit does not parse: %v", err)
	}
	return &c
}

// A free reserve at a node that trusts the issuer carries a verifying credit,
// which a refusal of the reserve returns for the node's next turn.
func TestDispatch_FreeReserveCarriesACredit(t *testing.T) {
	is := newFakeIssuer(t)
	c, rc, w := freeCreditClient(t, is, ModelCapacity{}, &ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_reserve"})
	_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	if len(rc.reqs) == 0 {
		t.Fatal("no reserve")
	}
	sent := sentCredit(t, rc.reqs[0])
	if sent == nil {
		t.Fatal("the free reserve carried no credit")
	}
	pub := is.master.Public().(ed25519.PublicKey)
	if err := freecredit.Verify([]ed25519.PublicKey{pub}, creditDep, creditTestNode, freecredit.AcceptedEpochs(noon), *sent); err != nil {
		t.Errorf("the credit does not verify at the node: %v", err)
	}
	if n := stored(w); n != DefaultFreeCreditBatch {
		t.Errorf("%d credits kept after the refusal, want the whole batch back", n)
	}
}

// A credit rides only a free Solana reserve at a node advertising an issuer
// the payer fetches from.
func TestDispatch_NoCreditWhereNoneIsWanted(t *testing.T) {
	refuse := &ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_reserve"}
	for _, tc := range []struct {
		name string
		edit func(*Client, *fakeIssuer)
	}{
		{"a priced model", func(c *Client, _ *fakeIssuer) {
			reg, _ := NewStaticRegistryProvider([]Operator{func() Operator {
				op := pricedOp(7, 1, 2)
				op.NodeID, op.FreeCreditIssuers = 2, c.freeCreditsIssuers()
				return op
			}()})
			c.registryProvider = reg
		}},
		{"the Algorand rail", func(c *Client, _ *fakeIssuer) { c.deployment.Rail = ticket.RailAlgorand }},
		{"a node trusting another issuer", func(c *Client, _ *fakeIssuer) {
			reg, _ := NewStaticRegistryProvider([]Operator{func() Operator {
				op := retryOp(7, "OWNER")
				op.NodeID, op.ModelCapacities = 2, map[string]ModelCapacity{"gpt-test": {}}
				op.FreeCreditIssuers = []string{newFakeIssuer(t).key()}
				return op
			}()})
			c.registryProvider = reg
		}},
		{"no credit wallet", func(c *Client, _ *fakeIssuer) { c.freeCredits = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := newFakeIssuer(t)
			c, rc, _ := freeCreditClient(t, is, ModelCapacity{}, refuse)
			tc.edit(c, is)
			_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
			if len(rc.reqs) == 0 {
				t.Fatal("no reserve")
			}
			if sentCredit(t, rc.reqs[0]) != nil {
				t.Error("the reserve carried a credit")
			}
			if dk, _ := is.calls(); dk != 0 {
				t.Errorf("%d fetches for a reserve that wanted no credit", dk)
			}
		})
	}
}

// freeCreditsIssuers is the keys of the issuers c's credit wallet has.
func (s *Client) freeCreditsIssuers() []string {
	var out []string
	for k := range s.freeCredits.issuers {
		out = append(out, k)
	}
	return out
}

// A credit the node says it already consumed is dropped, and the node is
// asked once more with another.
func TestDispatch_SpentCreditIsReplacedOnce(t *testing.T) {
	spent := &ReserveHTTPError{Status: http.StatusConflict, Code: freecredit.CodeFreeCreditSpent}
	is := newFakeIssuer(t)
	c, rc, w := freeCreditClient(t, is, ModelCapacity{}, spent, spent)
	_, err := runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	if err == nil {
		t.Fatal("the turn succeeded")
	}
	if len(rc.reqs) != 2 {
		t.Fatalf("%d reserves, want the first and one more", len(rc.reqs))
	}
	first, second := sentCredit(t, rc.reqs[0]), sentCredit(t, rc.reqs[1])
	if first == nil || second == nil || string(first.Nonce) == string(second.Nonce) {
		t.Fatalf("credits %v then %v, want two different ones", first, second)
	}
	// The batch less the two the node called spent.
	if n := stored(w); n != DefaultFreeCreditBatch-2 {
		t.Errorf("%d kept, want %d", n, DefaultFreeCreditBatch-2)
	}
}

// A credit the node refuses is dropped, the node is asked again without one,
// since it serves a free turn without a credit, and it is sent none for the
// rest of the day.
func TestDispatch_RefusedCreditIsDroppedAndTheNodeAskedWithout(t *testing.T) {
	is := newFakeIssuer(t)
	c, rc, w := freeCreditClient(t, is, ModelCapacity{},
		&ReserveHTTPError{Status: http.StatusBadRequest, Code: freecredit.CodeFreeCreditInvalid},
		&ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_reserve"})
	_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	if len(rc.reqs) != 2 {
		t.Fatalf("%d reserves, want the first and one without a credit", len(rc.reqs))
	}
	if sentCredit(t, rc.reqs[0]) == nil || sentCredit(t, rc.reqs[1]) != nil {
		t.Error("want a credit on the first reserve and none on the second")
	}
	if n := stored(w); n != DefaultFreeCreditBatch-1 {
		t.Errorf("%d kept, want the refused one gone", n)
	}
	_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	if len(rc.reqs) != 3 || sentCredit(t, rc.reqs[2]) != nil {
		t.Errorf("the next turn at a node that refused a credit today carried one")
	}
	if n := stored(w); n != DefaultFreeCreditBatch-1 {
		t.Errorf("%d kept after the next turn, want %d", n, DefaultFreeCreditBatch-1)
	}
}

// A node answering every credit as spent costs two credits, then is sent
// none: refusals can't drain the issuer's cap a batch a turn.
func TestDispatch_ANodeSpendingEveryCreditIsSentNoneMore(t *testing.T) {
	spent := &ReserveHTTPError{Status: http.StatusConflict, Code: freecredit.CodeFreeCreditSpent}
	is := newFakeIssuer(t)
	c, rc, w := freeCreditClient(t, is, ModelCapacity{}, spent)
	for range 3 {
		_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	}
	sent := 0
	for _, r := range rc.reqs {
		if sentCredit(t, r) != nil {
			sent++
		}
	}
	if sent != 2 {
		t.Errorf("%d credits sent over three turns, want 2", sent)
	}
	if n := stored(w); n != DefaultFreeCreditBatch-2 {
		t.Errorf("%d kept, want %d", n, DefaultFreeCreditBatch-2)
	}
}

// No credit sent, no retry: a spent answer to a reserve without a credit is
// the node's to explain, not a stale store.
func TestDispatch_SpentWithoutACreditIsNotRetried(t *testing.T) {
	is := newFakeIssuer(t)
	c, rc, _ := freeCreditClient(t, is, ModelCapacity{}, &ReserveHTTPError{Status: http.StatusConflict, Code: freecredit.CodeFreeCreditSpent})
	c.freeCredits = nil
	_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	if len(rc.reqs) != 1 {
		t.Errorf("%d reserves, want 1", len(rc.reqs))
	}
}

// ticketReserve answers each reserve with script's error, or past it with a
// ticket at maxPrice and input rate inRate.
type ticketReserve struct {
	scriptedReserveClient
	maxPrice, inRate uint64
}

func (r *ticketReserve) Reserve(ctx context.Context, op Operator, req ticket.ReserveRequest, hop *RelayHop) (*ReservedTicket, error) {
	if _, err := r.scriptedReserveClient.Reserve(ctx, op, req, hop); err != nil {
		return nil, err
	}
	return &ReservedTicket{Ticket: &ticket.Ticket{
		TicketID: fmt.Sprint(op.ID), OperatorID: op.ID, NodeID: op.NodeID, Model: req.Model,
		InputCount: req.InputCount, MaxOutputCount: req.MaxOutputCount, InputRate: r.inRate,
		MaxPrice: r.maxPrice, MinPrice: r.maxPrice,
	}}, nil
}

// dupGuard admits every estimate and refuses every reservation as a ticket id
// already in flight.
type dupGuard struct{ admitGuard }

func (*dupGuard) Reserve(string, uint64) error { return ErrDuplicateTicket }

// The node consumes a credit with a free ticket's turn, so the credit leaves
// the store once that turn is sealed. A ticket that came back priced, or one
// the payer turned down, leaves it for the node's next turn.
func TestDispatch_ACreditGoesWithItsFreeTurn(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rc    *ticketReserve
		guard SpendGuard
		// minCharge is the node's minimum charge, which prices a ticket at
		// zero rates: a priced ticket that passes the price check.
		minCharge uint64
		script    []error
		wantNow   int
	}{
		{"a free ticket spends it", &ticketReserve{}, nil, 0, nil, DefaultFreeCreditBatch - 1},
		{"a priced ticket leaves it", &ticketReserve{maxPrice: 1000}, nil, 1000, nil, DefaultFreeCreditBatch},
		{"a ticket over the spend cap leaves it", &ticketReserve{}, &capGuard{admitGuard{limit: ^uint64(0)}}, 0, nil, DefaultFreeCreditBatch},
		{"a reused ticket id leaves it", &ticketReserve{}, &dupGuard{admitGuard{limit: ^uint64(0)}}, 0, nil, DefaultFreeCreditBatch},
		{"a mis-priced ticket leaves it", &ticketReserve{inRate: 1_000_000_000}, nil, 0, nil, DefaultFreeCreditBatch},
		{"a spent credit's retry spends the next", &ticketReserve{}, nil, 0,
			[]error{&ReserveHTTPError{Status: http.StatusConflict, Code: freecredit.CodeFreeCreditSpent}, nil}, DefaultFreeCreditBatch - 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			is := newFakeIssuer(t)
			c, _, w := freeCreditClient(t, is, ModelCapacity{})
			if tc.minCharge > 0 {
				op := retryOp(7, "OWNER")
				op.NodeID, op.ModelCapacities = 2, map[string]ModelCapacity{"gpt-test": {}}
				op.FreeCreditIssuers, op.MinChargeMicroUSDC = []string{is.key()}, tc.minCharge
				reg, err := NewStaticRegistryProvider([]Operator{op})
				if err != nil {
					t.Fatal(err)
				}
				c.registryProvider = reg
				// The open fails, ending the turn after the credit's fate.
				c.wallet = &noOpenWallet{}
			}
			tc.rc.script = tc.script
			c.reserveClient = tc.rc
			c.spend = tc.guard
			_, _ = runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
			if len(tc.rc.reqs) == 0 || sentCredit(t, tc.rc.reqs[len(tc.rc.reqs)-1]) == nil {
				t.Fatal("the reserve carried no credit")
			}
			if n := stored(w); n != tc.wantNow {
				t.Errorf("%d kept, want %d", n, tc.wantNow)
			}
		})
	}
}

// A fetch is bounded, so a slow issuer costs the turn its timeout and then a
// minute's skip; a turn the caller ends doesn't bench the issuer.
func TestCreditWallet_BoundsAFetchAndIgnoresTheCallersAbort(t *testing.T) {
	is := newFakeIssuer(t)
	is.gate = make(chan struct{})
	t.Cleanup(func() { close(is.gate) })
	w, clock := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	w.fetchTimeout = 20 * time.Millisecond
	ctx, cancel := context.WithCancel(t.Context())
	go func() { time.Sleep(5 * time.Millisecond); cancel() }()
	if w.take(ctx, []string{is.key()}, creditTestNode) != nil {
		t.Fatal("a credit from an aborted fetch")
	}
	if !w.issuers[is.key()].skipUntil.IsZero() {
		t.Error("the caller's abort benched the issuer")
	}
	start := time.Now()
	if w.take(t.Context(), []string{is.key()}, creditTestNode) != nil {
		t.Fatal("a credit from an issuer that never answered")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("waited %s on a silent issuer", waited)
	}
	if !clock.Now().Before(w.issuers[is.key()].skipUntil) {
		t.Error("a silent issuer was not benched")
	}
}

// A turn waiting on another turn's fetch goes when its own caller ends it,
// rather than waiting out the fetch.
func TestCreditWallet_AWaiterGoesWhenItsCallerAborts(t *testing.T) {
	is := newFakeIssuer(t)
	is.gate = make(chan struct{})
	w, _ := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	leader := make(chan *heldCredit)
	go func() { leader <- w.take(t.Context(), []string{is.key()}, creditTestNode) }()
	time.Sleep(20 * time.Millisecond)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	start := time.Now()
	if w.take(ctx, []string{is.key()}, creditTestNode) != nil {
		t.Fatal("a credit for a waiter whose caller ended it")
	}
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("an aborted waiter waited %s", waited)
	}
	close(is.gate)
	verifies(t, <-leader, is, creditTestNode)
}

// A node that refused a credit is sent none for the rest of that UTC day,
// and is sent one again the next.
func TestCreditWallet_ARefusalLastsTheDay(t *testing.T) {
	is := newFakeIssuer(t)
	w, clock := newTestCreditWallet(t, map[string]CreditIssuer{is.key(): is})
	w.refuse(creditTestNode)
	if w.take(t.Context(), []string{is.key()}, creditTestNode) != nil {
		t.Fatal("a credit for a node that refused one today")
	}
	clock.add(12 * time.Hour)
	if h := w.take(t.Context(), []string{is.key()}, creditTestNode); h == nil || h.credit.Epoch != freecredit.EpochAt(noon)+1 {
		t.Errorf("the next day's credit is %v, want one for epoch %d", h, freecredit.EpochAt(noon)+1)
	}
}

// ctxStore is a memory store whose Put honours its context, and blocks until
// it ends once block is set.
type ctxStore struct {
	mem   *memoryCreditStore
	block atomic.Bool
}

func (s *ctxStore) Take(ctx context.Context, key CreditKey) (freecredit.Credit, bool, error) {
	return s.mem.Take(ctx, key)
}

func (s *ctxStore) Put(ctx context.Context, key CreditKey, cs []freecredit.Credit) error {
	if s.block.Load() {
		<-ctx.Done()
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.mem.Put(ctx, key, cs)
}

// A give-back outlives the caller's cancel, so the credit isn't lost to it,
// and is bounded, so a stuck store can't hold the turn.
func TestHeldCredit_GiveBackOutlivesTheCallerButNotAStuckStore(t *testing.T) {
	is := newFakeIssuer(t)
	store := &ctxStore{mem: NewMemoryCreditStore().(*memoryCreditStore)}
	w := newCreditWallet(FreeCredits{Issuers: map[string]CreditIssuer{is.key(): is}, Store: store},
		ticket.RailSolana, creditDep, func() time.Time { return noon }, slog.New(slog.DiscardHandler))
	w.fetchTimeout = 20 * time.Millisecond
	h := w.take(t.Context(), []string{is.key()}, creditTestNode)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.giveBack(ctx)
	if n := stored(&creditWallet{store: store.mem}); n != DefaultFreeCreditBatch {
		t.Errorf("%d kept after a give-back on a cancelled turn, want %d", n, DefaultFreeCreditBatch)
	}

	h = w.take(t.Context(), []string{is.key()}, creditTestNode)
	store.block.Store(true)
	done := make(chan struct{})
	go func() {
		h.giveBack(t.Context())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("a give-back is still waiting on a stuck store")
	}
}

// The HTTP issuer reads no more than its cap of an answer, and takes only a
// 429 for a spent cap: any other status is a failure, benched for a minute.
func TestHTTPCreditIssuer_CapsTheAnswerAndReadsOnlyA429AsExhausted(t *testing.T) {
	// Valid base64 past the cap: read whole, it would parse.
	big := strings.Repeat("A", freeCreditMaxBody+16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case freecredit.IssuePath:
			_, _ = fmt.Fprintf(w, `{"signatures":[%q]}`, big)
		case freecredit.DayKeyPath:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"credits_exhausted","message":"no"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	port := &HTTPCreditIssuer{URL: srv.URL}
	if _, err := port.Issue(t.Context(), creditDep, 1, [][]byte{{1}}); err == nil {
		t.Error("an answer past the cap was read")
	}
	_, err := port.DayKey(t.Context(), creditDep, 1)
	if _, ok := errors.AsType[*CreditsExhaustedError](err); ok || err == nil {
		t.Errorf("err = %v, want a plain failure for a 500", err)
	}
	key := newFakeIssuer(t).key()
	w, clock := newTestCreditWallet(t, map[string]CreditIssuer{key: port})
	w.take(t.Context(), []string{key}, creditTestNode)
	if got := w.issuers[key].skipUntil.Sub(clock.Now()); got != freeCreditFailureBackoff {
		t.Errorf("skipped for %s, want the failure backoff", got)
	}
}

// Credits need the deployment they are minted for; a Solana Client that
// read none says its credits are off rather than going without them silently.
func TestNew_WarnsWhenCreditsHaveNoDeployment(t *testing.T) {
	cfg := suppliedParts(t)
	s := newTestSolanaSigner()
	cfg.Signer, cfg.SolanaSigner, cfg.Network = nil, &s, SolanaLocalnet()
	cfg.FreeCredits = FreeCredits{Issuers: map[string]CreditIssuer{newFakeIssuer(t).key(): newFakeIssuer(t)}}
	var logs bytes.Buffer
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	c, err := New(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	if c.freeCredits != nil || !strings.Contains(logs.String(), "FreeCredits are off") {
		t.Errorf("wallet %v, logs %q; want no wallet and a warning", c.freeCredits, logs.String())
	}
}
