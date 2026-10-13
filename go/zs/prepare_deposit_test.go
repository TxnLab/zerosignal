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

// recheckerWallet counts RecheckDeposit calls on a test wallet.
type recheckerWallet struct {
	WalletOpener
	rechecks int
}

func (r *recheckerWallet) ProtocolFeeBps(ctx context.Context) (uint64, error) {
	if f, ok := r.WalletOpener.(feeRateCapable); ok {
		return f.ProtocolFeeBps(ctx)
	}
	return 0, errors.New("no fee rate")
}

func (r *recheckerWallet) RecheckDeposit() { r.rechecks++ }

// A node refusing the payer as unopted means the MBR deposit the wallet
// checked may be gone, so dispatch has the wallet check it again; any other
// payer refusal leaves it alone.
func TestDispatch_NotOptedInRefusalRechecksTheDeposit(t *testing.T) {
	for code, want := range map[string]int{"payer_not_opted_in": 1, "free_quota_exhausted": 0} {
		t.Run(code, func(t *testing.T) {
			c, rc := admitClient(t, []Operator{retryOp(1, "OWNER_A")}, &admitGuard{limit: ^uint64(0)})
			rc.script = []error{&PayerRefusalError{Code: code, Message: "refused"}}
			rw := &recheckerWallet{WalletOpener: c.wallet}
			c.wallet = rw
			if ze := turnErr(t, c, string(admitBody)); ze.Code != code {
				t.Fatalf("code %q, want %s", ze.Code, code)
			}
			if rw.rechecks != want {
				t.Errorf("RecheckDeposit calls = %d, want %d", rw.rechecks, want)
			}
		})
	}
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
