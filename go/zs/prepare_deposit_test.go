/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"testing"
)

// preparerWallet adds DepositPreparer to a test wallet.
type preparerWallet struct {
	WalletOpener
	calls     int
	err       error
	onPrepare func(ctx context.Context)
}

// ProtocolFeeBps keeps the wrapped wallet's fee rate visible, which Admit
// prices with.
func (p *preparerWallet) ProtocolFeeBps(ctx context.Context) (uint64, error) {
	if f, ok := p.WalletOpener.(feeRateCapable); ok {
		return f.ProtocolFeeBps(ctx)
	}
	return 0, errors.New("no fee rate")
}

func (p *preparerWallet) PrepareDeposit(ctx context.Context) error {
	p.calls++
	if p.onPrepare != nil {
		p.onPrepare(ctx)
	}
	return p.err
}

// A request the spend cap refuses deposits nothing: the cap is checked first.
func TestDispatch_AdmitRefusalPreparesNoDeposit(t *testing.T) {
	c, rc := admitClient(t, []Operator{pricedOp(1, 1, 2)}, &admitGuard{limit: 0})
	pw := &preparerWallet{WalletOpener: c.wallet}
	c.wallet = pw
	if ze := turnErr(t, c, string(admitBody)); ze.Code != "spend_cap_exceeded" {
		t.Fatalf("code %q, want spend_cap_exceeded", ze.Code)
	}
	if pw.calls != 0 {
		t.Errorf("PrepareDeposit calls = %d, want 0", pw.calls)
	}
	if rc.calls() != 0 {
		t.Errorf("%d reserves, want 0", rc.calls())
	}
}

// PrepareDeposit runs under the request's context, and a request cancelled
// during it ends canceled rather than as a funds failure, however the cut-off
// read surfaced.
func TestDispatch_CancelDuringPrepareDeposit(t *testing.T) {
	c, _ := admitClient(t, []Operator{retryOp(1, "OWNER_A")}, &admitGuard{limit: ^uint64(0)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pw := &preparerWallet{
		WalletOpener: c.wallet,
		err:          ErrDepositUnaffordable,
		onPrepare: func(pctx context.Context) {
			cancel()
			if pctx.Err() == nil {
				t.Error("PrepareDeposit did not get the request's context")
			}
		},
	}
	c.wallet = pw

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
	if ze.Code != "canceled" {
		t.Errorf("code %q, want canceled", ze.Code)
	}
	if pw.calls != 1 {
		t.Errorf("PrepareDeposit calls = %d, want 1", pw.calls)
	}
}
