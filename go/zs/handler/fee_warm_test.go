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
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// countingFeeWallet reports a fee and records how many times it was asked, so a
// test can tell a warm that actually reached the wallet from one that returned
// the zero value and did nothing.
type countingFeeWallet struct {
	*fakeWallet
	calls atomic.Int32
	done  chan struct{}
}

func (w *countingFeeWallet) ProtocolFeeBps(_ context.Context) (uint64, error) {
	if w.calls.Add(1) == 1 {
		close(w.done)
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

// A cold fee cache publishes NO price, and the read that finds it cold is the
// one that pays for it — feeRateCache.get returns (0,false) and kicks the
// refresh asynchronously. This pins the behaviour WarmFeeRate exists to move
// off the client's first request; without it the first GET /v1/models after a
// restart is unpriced.
func TestListModels_ColdFeeCachePublishesNoPricing(t *testing.T) {
	w := &countingFeeWallet{fakeWallet: &fakeWallet{}, done: make(chan struct{})}
	s := testServer(testConfig(), Options{
		RegistryProvider: modelsRegistry(t, []hayai.Operator{richOperator()}),
		Wallet:           w,
	})

	if got := pricedIDs(t, getJSON(t, "/v1/models", s.handleListModels)); len(got) != 0 {
		t.Fatalf("cold fee cache published pricing for %v; a pre-fee rate in this shape "+
			"understates the payer's cost with no field to say so", got)
	}
	// Without this the test passes against a wallet that isn't feeRateCapable at
	// all, where the absent pricing proves nothing about coldness — and it
	// collapses into a duplicate of TestHandleListModels_ColdFeePublishesNoPrice,
	// which covers that branch already. The property here is specifically that a
	// CAPABLE wallet's first read is cold and kicks the refresh.
	//
	// Wait for the kick rather than sampling the counter: get() returns BEFORE
	// its refresh goroutine runs, so an immediate read races the scheduler and
	// fails only under load — which is exactly how it fails in a full-package
	// run and passes when the test is run alone.
	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("the cold read never kicked a refresh; the absent pricing above proves " +
			"nothing about a cold cache unless the wallet was actually asked")
	}
	if n := w.calls.Load(); n != 1 {
		t.Errorf("cold read asked the wallet %d times, want exactly 1", n)
	}
}

// WarmFeeRate must reach the wallet and land the value WITHOUT any request
// having been served. Asserting only that a later request is priced would pass
// on the cold path too, since that request kicks its own refresh.
func TestWarmFeeRate_PricesTheCatalogBeforeTheFirstRequest(t *testing.T) {
	w := &countingFeeWallet{fakeWallet: &fakeWallet{}, done: make(chan struct{})}
	s := testServer(testConfig(), Options{
		RegistryProvider: modelsRegistry(t, []hayai.Operator{richOperator()}),
		Wallet:           w,
	})

	s.WarmFeeRate()

	select {
	case <-w.done:
	case <-time.After(2 * time.Second):
		t.Fatal("WarmFeeRate never asked the wallet for the protocol fee")
	}
	// get() stores the value after fetch returns, so wait for the visible state
	// rather than the call — the call alone doesn't mean the cache is warm.
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, ok := s.feeRateNow(); ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("fee never became known after WarmFeeRate")
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
// WarmFeeRate has to be a no-op rather than seeding a zero fee, which would
// publish raw operator rates as if they were payer-net.
func TestWarmFeeRate_IsANoOpForAFeeBlindWallet(t *testing.T) {
	s := testServer(testConfig(), Options{
		RegistryProvider: modelsRegistry(t, []hayai.Operator{richOperator()}),
		Wallet:           &fakeWallet{},
	})

	s.WarmFeeRate()

	if _, ok := s.feeRateNow(); ok {
		t.Fatal("fee reported known for a wallet that cannot read it")
	}
	if got := pricedIDs(t, getJSON(t, "/v1/models", s.handleListModels)); len(got) != 0 {
		t.Fatalf("published pricing without a known fee for %v", got)
	}
}
