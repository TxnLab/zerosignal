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
