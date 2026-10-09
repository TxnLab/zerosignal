/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"net/http"
	"testing"
)

// A turn the caller's own context ended is not advised as a retry, whatever
// the failure reads as by its kind.
func TestStream_CallerCancelIsNotRetryable(t *testing.T) {
	rc := &scriptedReserveClient{script: []error{context.Canceled}}
	c := retryServer(t, false, rc, []Operator{retryOp(1, "OWNER_A")})
	c.tokenizer = testTokenizer()
	c.wallet = fakeFeeWallet{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.Stream(ctx, Request{Endpoint: EndpointChatCompletions, Body: []byte(`{"model":"gpt-test"}`)}).Text()
	ze, ok := errors.AsType[*Error](err)
	if !ok {
		t.Fatalf("ended in %v, want *Error", err)
	}
	if ze.Code != "canceled" || ze.Retryable {
		t.Errorf("%s/%s (retryable %v) after the caller cancelled, want canceled and not retryable", ze.Kind, ze.Code, ze.Retryable)
	}

	// The emitter weighs the caller's context over the kind, for a failure
	// that is retryable by kind and reached the end after a cancel.
	busy := newError("operators_busy", "m")
	if !retryable(busy) {
		t.Fatal("operators_busy is not retryable by kind, so this asserts nothing")
	}
	em := &streamEmitter{yield: func(Event, error) bool { return true }, callerCtx: ctx}
	em.end(busy)
	if busy.Retryable {
		t.Error("a kind-retryable error after the caller cancelled is Retryable")
	}
}

// A Stream runs its turn once. Ranging it again must not run the turn again:
// a second run reserves and pays a second time.
func TestStream_EventsRunsOnce(t *testing.T) {
	rc := &scriptedReserveClient{script: []error{&ReserveHTTPError{Status: http.StatusBadRequest, Code: "invalid_request"}}}
	c := retryServer(t, false, rc, []Operator{retryOp(1, "OWNER_A")})
	c.tokenizer = testTokenizer()
	c.wallet = fakeFeeWallet{}
	st := c.Stream(context.Background(), Request{Endpoint: EndpointChatCompletions, Body: []byte(`{"model":"gpt-test"}`)})

	for range st.Events() {
	}
	if rc.calls() != 1 {
		t.Fatalf("first range made %d reserves, want 1", rc.calls())
	}

	var got []error
	for ev, err := range st.Events() {
		if ev != nil {
			t.Errorf("second range yielded %T", ev)
		}
		got = append(got, err)
	}
	if len(got) != 1 || !errors.Is(got[0], errStreamReused) {
		t.Errorf("second range yielded %v, want only errStreamReused", got)
	}
	if rc.calls() != 1 {
		t.Errorf("second range made %d more reserves", rc.calls()-1)
	}
}
