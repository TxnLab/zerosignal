/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/zs"
)

// countingFeeWallet reports a fee and records how many times it was asked, so a
// test can tell a warm that actually reached the wallet from one that returned
// the zero value and did nothing. A non-nil release holds every read until it
// is closed.
type countingFeeWallet struct {
	*fakeWallet
	calls   atomic.Int32
	done    chan struct{}
	release chan struct{}
}

func (w *countingFeeWallet) ProtocolFeeBps(_ context.Context) (uint64, error) {
	if w.calls.Add(1) == 1 {
		close(w.done)
	}
	if w.release != nil {
		<-w.release
	}
	return 1000, nil
}

// pricedIDs returns the ids in a /v1/models body that carry a pricing object.
func pricedIDs(t *testing.T, body []byte) []string {
	t.Helper()
	var out struct {
		Data []inject.OpenAIModel `json:"data"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}
	var ids []string
	for _, m := range out.Data {
		if m.Pricing != nil {
			ids = append(ids, m.ID)
		}
	}
	return ids
}

// A fee not yet read publishes NO price: a pre-fee rate in the OpenAI shape
// understates the payer's cost with no field to say so. Held mid-read, the
// warm New started leaves the cache cold for the first request, and that
// request does not start a second read.
func TestListModels_ColdFeeCachePublishesNoPricing(t *testing.T) {
	w := &countingFeeWallet{fakeWallet: &fakeWallet{}, done: make(chan struct{}), release: make(chan struct{})}
	defer close(w.release)
	s := testServer(testConfig(), deps{
		RegistryProvider: modelsRegistry(t, []zs.Operator{richOperator()}),
		Wallet:           w,
	})
	// Without this the test passes against a wallet that isn't feeRateCapable at
	// all, where the absent pricing proves nothing about coldness — and it
	// collapses into a duplicate of TestHandleListModels_ColdFeePublishesNoPrice,
	// which covers that branch already.
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the wallet was never asked for the fee; the absent pricing below would " +
			"prove nothing about a cold cache")
	}

	if got := pricedIDs(t, getJSON(t, "/v1/models", s.handleListModels)); len(got) != 0 {
		t.Fatalf("cold fee cache published pricing for %v", got)
	}
	if n := w.calls.Load(); n != 1 {
		t.Errorf("wallet asked %d times while one read was in flight, want 1", n)
	}
}

// New must reach the wallet and land the value WITHOUT any request having
// been served. Asserting only that a later request is priced would pass on
// the cold path too, since that request kicks its own refresh.
func TestNew_WarmsTheFeeRateBeforeTheFirstRequest(t *testing.T) {
	w := &countingFeeWallet{fakeWallet: &fakeWallet{}, done: make(chan struct{})}
	s := testServer(testConfig(), deps{
		RegistryProvider: modelsRegistry(t, []zs.Operator{richOperator()}),
		Wallet:           w,
	})

	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("New never asked the wallet for the protocol fee")
	}
	// get() stores the value after fetch returns, so wait for the visible state
	// rather than the call — the call alone doesn't mean the cache is warm.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.FeeRate(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fee never became known after New")
		}
		time.Sleep(5 * time.Millisecond)
	}

	priced := pricedIDs(t, getJSON(t, "/v1/models", s.handleListModels))
	if len(priced) == 0 {
		t.Fatal("catalog still unpriced after a warm fee cache")
	}
	// The warm must not have cost an extra chain read on the request path: the
	// entry is fresh, so get() takes its fast path.
	if n := w.calls.Load(); n != 1 {
		t.Errorf("protocol fee read %d times, want exactly 1 (the warm)", n)
	}
}

// A wallet that cannot report a fee must not be warmed into a false "known" —
// feeRateNow type-asserts for feeRateCapable first, so this is the branch where
// the warm has to be a no-op rather than seeding a zero fee, which would
// publish raw operator rates as if they were payer-net.
func TestNew_DoesNotWarmAFeeBlindWallet(t *testing.T) {
	s := testServer(testConfig(), deps{
		RegistryProvider: modelsRegistry(t, []zs.Operator{richOperator()}),
		Wallet:           &fakeWallet{},
	})

	if _, ok := s.FeeRate(); ok {
		t.Fatal("fee reported known for a wallet that cannot read it")
	}
	if got := pricedIDs(t, getJSON(t, "/v1/models", s.handleListModels)); len(got) != 0 {
		t.Fatalf("published pricing without a known fee for %v", got)
	}
}
