/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/selection"
)

// stubReader is a readSpendable seam: per-address values or errors, counting
// every call.
type stubReader struct {
	mu     sync.Mutex
	values map[string]uint64
	fail   map[string]bool
	calls  map[string]int
}

func newStubReader() *stubReader {
	return &stubReader{values: map[string]uint64{}, fail: map[string]bool{}, calls: map[string]int{}}
}

func (r *stubReader) read(ctx context.Context, addr string) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls[addr]++
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if r.fail[addr] {
		return 0, errors.New("algod unavailable")
	}
	v, ok := r.values[addr]
	if !ok {
		return 0, fmt.Errorf("no stub value for %s", addr)
	}
	return v, nil
}

func signerOps(addrs ...string) []Operator {
	ops := make([]Operator, len(addrs))
	for i, a := range addrs {
		ops[i] = Operator{ID: uint64(i + 1), NodeID: 1, SigningAddr: a}
	}
	return ops
}

func spendableOf(t *testing.T, op Operator) (uint64, bool) {
	t.Helper()
	if op.SignerSpendableMicroAlgos == nil {
		return 0, false
	}
	return *op.SignerSpendableMicroAlgos, true
}

func TestSpendableMicroAlgos_FloorsAtZero(t *testing.T) {
	cases := []struct{ amount, minBal, want uint64 }{
		{5_100_000, 100_000, 5_000_000},
		{100_000, 100_000, 0},
		{50_000, 100_000, 0}, // below its own minimum: nothing is sendable
	}
	for _, tc := range cases {
		if got := spendableMicroAlgos(tc.amount, tc.minBal); got != tc.want {
			t.Errorf("spendableMicroAlgos(%d, %d) = %d, want %d", tc.amount, tc.minBal, got, tc.want)
		}
	}
}

// Two nodes behind one signing account cost one read, and both carry it.
func TestFillSignerBalances_DedupesSharedSigner(t *testing.T) {
	r := newStubReader()
	r.values["A"] = 7_000_000
	s := &ChainOperatorSource{readSpendable: r.read}

	ops := signerOps("A", "A")
	s.fillSignerBalances(context.Background(), ops)

	if r.calls["A"] != 1 {
		t.Errorf("reads of A = %d, want 1", r.calls["A"])
	}
	for i, op := range ops {
		if v, ok := spendableOf(t, op); !ok || v != 7_000_000 {
			t.Errorf("ops[%d] spendable = %d (set=%v), want 7000000", i, v, ok)
		}
	}
	if ops[0].SignerSpendableMicroAlgos == ops[1].SignerSpendableMicroAlgos {
		t.Error("ops share one pointer; each must own its value so no snapshot can alias another")
	}
}

// The whole point of the cache: a failed read must not turn a known-broke
// signer back into "unknown" (which routes). Established from a dirty state —
// first a successful underfunded read, then a failing pass.
func TestFillSignerBalances_StickyOnFailure(t *testing.T) {
	r := newStubReader()
	r.values["broke"] = 1_000_000
	r.values["funded"] = 50_000_000
	r.fail["never"] = true
	s := &ChainOperatorSource{readSpendable: r.read}

	s.fillSignerBalances(context.Background(), signerOps("broke", "funded", "never"))

	r.fail["broke"], r.fail["funded"] = true, true
	ops := signerOps("broke", "funded", "never")
	s.fillSignerBalances(context.Background(), ops)

	if v, ok := spendableOf(t, ops[0]); !ok || v != 1_000_000 {
		t.Fatalf("broke signer after a failed read = %d (set=%v), want the last-known 1000000", v, ok)
	}
	if !ops[0].SignerUnderfunded() {
		t.Error("a failed read re-admitted a node last seen below the floor")
	}
	if v, ok := spendableOf(t, ops[1]); !ok || v != 50_000_000 {
		t.Errorf("funded signer after a failed read = %d (set=%v), want the last-known 50000000", v, ok)
	}
	if _, ok := spendableOf(t, ops[2]); ok {
		t.Error("a signer never read successfully must stay nil (unknown routes)")
	}
}

// A fresh success replaces the remembered value — a refunded node comes back.
func TestFillSignerBalances_SuccessReplacesLastKnown(t *testing.T) {
	r := newStubReader()
	r.values["A"] = 0
	s := &ChainOperatorSource{readSpendable: r.read}
	s.fillSignerBalances(context.Background(), signerOps("A"))

	r.values["A"] = selection.MinSignerSpendableMicroAlgos
	ops := signerOps("A")
	s.fillSignerBalances(context.Background(), ops)

	if ops[0].SignerUnderfunded() {
		t.Errorf("topped-up signer still underfunded: %v", *ops[0].SignerSpendableMicroAlgos)
	}
}

// A signer that leaves the fleet is forgotten, so if it returns and its first
// read fails it is unknown — not judged on a reading from before it left.
func TestFillSignerBalances_PrunesDepartedAddresses(t *testing.T) {
	r := newStubReader()
	r.values["A"], r.values["B"] = 0, 9_000_000
	s := &ChainOperatorSource{readSpendable: r.read}
	s.fillSignerBalances(context.Background(), signerOps("A", "B"))

	s.fillSignerBalances(context.Background(), signerOps("B"))
	if _, kept := s.signerSpendable["A"]; kept {
		t.Fatal("departed signer A still cached")
	}

	r.fail["A"] = true
	ops := signerOps("A")
	s.fillSignerBalances(context.Background(), ops)
	if _, ok := spendableOf(t, ops[0]); ok {
		t.Error("returning signer A inherited a pre-departure reading")
	}
}

func TestFillSignerBalances_BoundsConcurrency(t *testing.T) {
	var inFlight, peak atomic.Int32
	release := make(chan struct{})
	read := func(ctx context.Context, _ string) (uint64, error) {
		n := inFlight.Add(1)
		defer inFlight.Add(-1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		select {
		case <-release:
		case <-ctx.Done():
		}
		return 1, nil
	}
	s := &ChainOperatorSource{readSpendable: read}
	addrs := make([]string, 3*signerBalanceConcurrency)
	for i := range addrs {
		addrs[i] = fmt.Sprintf("S%d", i)
	}

	done := make(chan struct{})
	go func() {
		s.fillSignerBalances(context.Background(), signerOps(addrs...))
		close(done)
	}()
	deadline := time.After(5 * time.Second)
	for peak.Load() < int32(signerBalanceConcurrency) {
		select {
		case <-deadline:
			t.Fatalf("peak in-flight = %d, never reached %d", peak.Load(), signerBalanceConcurrency)
		case <-time.After(time.Millisecond):
		}
	}
	close(release)
	<-done
	if p := peak.Load(); p != int32(signerBalanceConcurrency) {
		t.Errorf("peak in-flight reads = %d, want exactly %d", p, signerBalanceConcurrency)
	}
}

// A pass whose context is already gone reads nothing and keeps every
// last-known value — the timeout path, driven without waiting it out.
func TestFillSignerBalances_CancelledPassKeepsLastKnown(t *testing.T) {
	r := newStubReader()
	r.values["A"] = 2_000_000
	s := &ChainOperatorSource{readSpendable: r.read}
	s.fillSignerBalances(context.Background(), signerOps("A"))

	// Had the pass read, it would have seen a different value.
	r.values["A"] = 90_000_000
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ops := signerOps("A")
	s.fillSignerBalances(ctx, ops)

	if v, ok := spendableOf(t, ops[0]); !ok || v != 2_000_000 {
		t.Errorf("after a cancelled pass: %d (set=%v), want last-known 2000000", v, ok)
	}
}

// The pass carries its own deadline, so a slow algod can't spend the whole
// refresh budget the details probes share.
func TestFillSignerBalances_PassHasItsOwnDeadline(t *testing.T) {
	var deadline time.Time
	var hasDeadline bool
	read := func(ctx context.Context, _ string) (uint64, error) {
		deadline, hasDeadline = ctx.Deadline()
		return 1, nil
	}
	s := &ChainOperatorSource{readSpendable: read}
	start := time.Now()
	s.fillSignerBalances(context.Background(), signerOps("A"))
	end := time.Now()

	if !hasDeadline {
		t.Fatal("read ran with no deadline under a parent that has none")
	}
	if deadline.Before(start.Add(signerBalanceTimeout)) || deadline.After(end.Add(signerBalanceTimeout)) {
		t.Errorf("read deadline %v, want signerBalanceTimeout (%v) after the pass began", deadline.Sub(start), signerBalanceTimeout)
	}
}

// A partial failure is reported: a rate-limited algod fails a fraction of
// reads every cycle, and those nodes route on stale values.
func TestFillSignerBalances_WarnsOnPartialFailure(t *testing.T) {
	r := newStubReader()
	r.values["A"] = 9_000_000
	r.fail["B"] = true
	var buf bytes.Buffer
	s := &ChainOperatorSource{
		readSpendable: r.read,
		Log:           slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}
	s.fillSignerBalances(context.Background(), signerOps("A", "B"))

	out := buf.String()
	if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "failed=1") || !strings.Contains(out, "signers=2") {
		t.Errorf("want one WARN with failed=1 signers=2, got %q", out)
	}
}

// FetchChain is the one call every refresh path makes, so it is where the
// balance pass must run; without it every balance stays nil and the gate never
// fires, silently.
func TestFetchChain_RunsBalancePass(t *testing.T) {
	r := newStubReader()
	r.values["A"], r.values["B"] = 0, 9_000_000
	s := &ChainOperatorSource{
		readSpendable: r.read,
		readChain: func(context.Context) ([]Operator, error) {
			return signerOps("A", "B"), nil
		},
	}
	ops, err := s.FetchChain(context.Background())
	if err != nil {
		t.Fatalf("FetchChain: %v", err)
	}
	if !ops[0].SignerUnderfunded() {
		t.Error("node A (0 spendable) not marked underfunded by FetchChain")
	}
	if v, ok := spendableOf(t, ops[1]); !ok || v != 9_000_000 {
		t.Errorf("node B spendable = %d (set=%v), want 9000000", v, ok)
	}
}

func TestFillSignerBalances_NoAlgodIsNoop(t *testing.T) {
	s := &ChainOperatorSource{}
	ops := signerOps("A")
	s.fillSignerBalances(context.Background(), ops)
	if ops[0].SignerSpendableMicroAlgos != nil {
		t.Error("with no algod and no seam, the balance must stay unknown")
	}
}

// The production read against a fake algod: the request must ask for
// exclude=all (the small response) and the answer must be amount − min-balance.
func TestAlgodSpendable_ExcludeAllAndMinBalance(t *testing.T) {
	const addr = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAY5HFKQ"
	var sawExclude string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasSuffix(r.URL.Path, "/v2/accounts/"+addr) {
			http.NotFound(w, r)
			return
		}
		sawExclude = r.URL.Query().Get("exclude")
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"address":"`+addr+`","amount":5100000,"min-balance":200000,`+
			`"amount-without-pending-rewards":5100000,"pending-rewards":0,"rewards":0,"round":1,`+
			`"status":"Offline","total-apps-opted-in":0,"total-assets-opted-in":1,`+
			`"total-created-apps":0,"total-created-assets":0}`)
	}))
	t.Cleanup(srv.Close)
	c, err := algod.NewClient(srv.URL, "test-token")
	if err != nil {
		t.Fatalf("algod.NewClient: %v", err)
	}

	s := &ChainOperatorSource{Algod: c}
	got, err := s.algodSpendable(context.Background(), addr)
	if err != nil {
		t.Fatalf("algodSpendable: %v", err)
	}
	if got != 4_900_000 {
		t.Errorf("spendable = %d, want 4900000 (amount − min-balance)", got)
	}
	if sawExclude != "all" {
		t.Errorf("exclude query = %q, want \"all\"", sawExclude)
	}
}
