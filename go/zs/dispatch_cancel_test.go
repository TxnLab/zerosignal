/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
)

// cancelingReserve cancels the caller's context during the first reserve and
// answers it busy, the way a node at capacity does.
type cancelingReserve struct {
	cancel context.CancelFunc
	calls  atomic.Int32
}

func (r *cancelingReserve) Reserve(context.Context, Operator, ticket.ReserveRequest, *RelayHop) (*ReservedTicket, error) {
	r.calls.Add(1)
	r.cancel()
	return nil, &BusyError{Code: "no_capacity", RetryAfter: time.Second}
}

// A caller that cancels while the sweep is reserving gets canceled, unpaid and
// not retryable, and no further candidate is asked. The candidates' answers so
// far would otherwise reach the terminal ladder as operators_busy.
func TestDispatch_CallerCancelDuringReserve(t *testing.T) {
	c, _ := admitClient(t, []Operator{retryOp(1, "OWNER_A"), retryOp(2, "OWNER_B")}, &admitGuard{limit: ^uint64(0)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rc := &cancelingReserve{cancel: cancel}
	c.reserveClient = rc

	st := c.Stream(ctx, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	var err error
	for _, e := range st.Events() {
		if e != nil {
			err = e
		}
	}
	ze, ok := errors.AsType[*Error](err)
	if !ok {
		t.Fatalf("turn error = %v (%T), want *Error", err, err)
	}
	if ze.Code != "canceled" || ze.Kind != KindInterrupted || ze.Paid || ze.Retryable {
		t.Errorf("code %q kind %q paid %v retryable %v, want canceled / interrupted / unpaid / not retryable",
			ze.Code, ze.Kind, ze.Paid, ze.Retryable)
	}
	if !errors.Is(ze, context.Canceled) {
		t.Errorf("error %v does not wrap context.Canceled", ze)
	}
	if n := rc.calls.Load(); n != 1 {
		t.Errorf("%d reserves after the caller canceled at the first, want 1", n)
	}
}
