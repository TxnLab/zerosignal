/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
)

// confirmChain answers Confirm's two reads from scripts, the last entry of
// each repeating, and counts them.
type confirmChain struct {
	mu       sync.Mutex
	statuses []*SignatureStatus
	heights  []uint64
	nStatus  int
	nHeight  int
	// heightAt records each height read's commitment.
	heightAt []Commitment
}

func (c *confirmChain) GetSignatureStatuses(_ context.Context, sigs []solana.Signature, _ bool) ([]*SignatureStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.statuses[min(c.nStatus, len(c.statuses)-1)]
	c.nStatus++
	return []*SignatureStatus{s}, nil
}

func (c *confirmChain) GetBlockHeight(_ context.Context, cm Commitment) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.heights[min(c.nHeight, len(c.heights)-1)]
	c.nHeight++
	c.heightAt = append(c.heightAt, cm)
	return h, nil
}

func (c *confirmChain) reads() (int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nStatus, c.nHeight
}

func (*confirmChain) GetAccountInfo(context.Context, solana.PublicKey, Commitment) (*Account, error) {
	panic("unused")
}
func (*confirmChain) GetProgramAccounts(context.Context, solana.PublicKey, Commitment, ...Filter) ([]KeyedAccount, error) {
	panic("unused")
}
func (*confirmChain) GetBalance(context.Context, solana.PublicKey, Commitment) (uint64, error) {
	panic("unused")
}
func (*confirmChain) GetLatestBlockhash(context.Context, Commitment) (Blockhash, error) {
	panic("unused")
}
func (*confirmChain) GetGenesisHash(context.Context) (solana.Hash, error) { panic("unused") }
func (*confirmChain) GetMinimumBalanceForRentExemption(context.Context, uint64, Commitment) (uint64, error) {
	panic("unused")
}
func (*confirmChain) SendTransaction(context.Context, []byte, SendOptions) (solana.Signature, error) {
	panic("unused")
}

func at(slot uint64, c Commitment) *SignatureStatus {
	return &SignatureStatus{Slot: slot, ConfirmationStatus: c}
}

var fast = ConfirmOptions{Poll: time.Millisecond, HeightCheck: time.Millisecond}

func TestConfirmWaitsForTheCommitment(t *testing.T) {
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(7, Processed), at(7, Confirmed)}, heights: []uint64{90}}
	r, err := Confirm(t.Context(), c, testSig, 100, Confirmed, fast)
	if err != nil || r.Slot != 7 || r.Err != nil {
		t.Fatalf("Confirm = %+v, %v", r, err)
	}
	// The processed status is a landed transaction: no height is read for it.
	if s, h := c.reads(); s != 3 || h != 1 {
		t.Fatalf("reads: %d statuses, %d heights; want 3, 1", s, h)
	}
}

func TestConfirmReturnsAFailedLanding(t *testing.T) {
	failed := at(9, Finalized)
	failed.Err = json.RawMessage(`{"InstructionError":[2,{"Custom":6054}]}`)
	c := &confirmChain{statuses: []*SignatureStatus{failed}, heights: []uint64{0}}
	r, err := Confirm(t.Context(), c, testSig, 100, "", fast)
	if err != nil || r.Slot != 9 || TxErrName(r.Err) != "InstructionError" {
		t.Fatalf("Confirm = %+v, %v", r, err)
	}
}

func TestConfirmExpiresOnlyPastTheHeightWithNoStatus(t *testing.T) {
	c := &confirmChain{statuses: []*SignatureStatus{nil}, heights: []uint64{99, 100, 101}}
	if _, err := Confirm(t.Context(), c, testSig, 100, Confirmed, fast); !errors.Is(err, ErrExpired) {
		t.Fatalf("err = %v, want ErrExpired", err)
	}
	// At the height itself the transaction can still land.
	if _, h := c.reads(); h != 3 {
		t.Fatalf("%d height reads, want 3", h)
	}
	// The confirmed height, not the finalized one, which lags and would
	// declare the expiry late.
	for _, cm := range c.heightAt {
		if cm != Confirmed {
			t.Fatalf("height read at %q", cm)
		}
	}
}

func TestConfirmReadsTheStatusOnceMorePastTheHeight(t *testing.T) {
	// The transaction landed between the status read and the height read.
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(100, Finalized)}, heights: []uint64{101}}
	r, err := Confirm(t.Context(), c, testSig, 100, Finalized, fast)
	if err != nil || r.Slot != 100 {
		t.Fatalf("Confirm = %+v, %v", r, err)
	}
}

func TestConfirmWaitsOnALandingPastTheHeight(t *testing.T) {
	// Landed but short of the commitment when the height passed: not expired.
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(100, Processed), at(100, Confirmed)}, heights: []uint64{101}}
	r, err := Confirm(t.Context(), c, testSig, 100, Confirmed, fast)
	if err != nil || r.Slot != 100 {
		t.Fatalf("Confirm = %+v, %v", r, err)
	}
}

func TestConfirmEndsWithTheContext(t *testing.T) {
	c := &confirmChain{statuses: []*SignatureStatus{nil}, heights: []uint64{1}}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, err := Confirm(ctx, c, testSig, 100, Confirmed, fast); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestReachedReadsAnOlderRPCsStatus(t *testing.T) {
	two := uint64(2)
	for _, tc := range []struct {
		s    SignatureStatus
		c    Commitment
		want bool
	}{
		{SignatureStatus{ConfirmationStatus: Processed}, Processed, true},
		{SignatureStatus{ConfirmationStatus: Processed}, Confirmed, false},
		{SignatureStatus{ConfirmationStatus: Confirmed}, Confirmed, true},
		{SignatureStatus{ConfirmationStatus: Confirmed}, Finalized, false},
		{SignatureStatus{ConfirmationStatus: Finalized}, Confirmed, true},
		{SignatureStatus{Confirmations: &two}, Processed, true},
		{SignatureStatus{Confirmations: &two}, Confirmed, false},
		{SignatureStatus{}, Finalized, true},
	} {
		if got := reached(&tc.s, tc.c); got != tc.want {
			t.Errorf("reached(%+v, %s) = %v", tc.s, tc.c, got)
		}
	}
}

func TestConfirmTakesTheWatchsAnswer(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	// The status stays unknown and the height low, so only the watch can end it.
	c := &confirmChain{statuses: []*SignatureStatus{nil}, heights: []uint64{1}}
	type out struct {
		r   SignatureResult
		err error
	}
	done := make(chan out, 1)
	go func() {
		r, err := Confirm(t.Context(), c, testSig, 100, Confirmed, ConfirmOptions{PubSub: p, Poll: time.Millisecond, HeightCheck: time.Hour})
		done <- out{r, err}
	}()
	call := f.next(t)
	if string(call.Params) != `["`+testSig.String()+`",{"commitment":"confirmed"}]` {
		t.Fatalf("subscribe params = %s", call.Params)
	}
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":4,"id":%d}`, call.ID)
	sendFrame(t, ws, `{"jsonrpc":"2.0","method":"signatureNotification","params":{"result":{"context":{"slot":12},"value":{"err":null}},"subscription":4}}`)
	select {
	case o := <-done:
		if o.err != nil || o.r.Slot != 12 {
			t.Fatalf("Confirm = %+v, %v", o.r, o.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm never returned")
	}
	// One status read while arming, then nothing polled.
	if s, _ := c.reads(); s != 1 {
		t.Fatalf("%d status reads with a watch armed, want 1", s)
	}
}

// armedConfirm runs Confirm with a watch the fake arms and never notifies.
func armedConfirm(t *testing.T, c *confirmChain, o ConfirmOptions) <-chan error {
	t.Helper()
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	o.PubSub = p
	done := make(chan error, 1)
	go func() {
		_, err := Confirm(t.Context(), c, testSig, 100, Confirmed, o)
		done <- err
	}()
	call := f.next(t)
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":4,"id":%d}`, call.ID)
	return done
}

func waitConfirmed(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm never returned")
	}
}

func TestConfirmTakesALandingFoundPastTheHeightWithAWatch(t *testing.T) {
	// With a watch armed the ticks read only the height, so the read past it
	// is the one that finds the landing.
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(100, Confirmed)}, heights: []uint64{90, 101}}
	waitConfirmed(t, armedConfirm(t, c, ConfirmOptions{Poll: time.Hour, HeightCheck: time.Millisecond}))
	if s, _ := c.reads(); s != 2 {
		t.Fatalf("%d status reads, want 2", s)
	}
}

func TestConfirmReadsOnlyTheHeightWhileAWatchIsArmed(t *testing.T) {
	c := &confirmChain{statuses: []*SignatureStatus{nil}, heights: []uint64{1}}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	done := make(chan error, 1)
	go func() {
		_, err := Confirm(ctx, c, testSig, 100, Confirmed, ConfirmOptions{PubSub: p, Poll: time.Millisecond, HeightCheck: time.Millisecond})
		done <- err
	}()
	call := f.next(t)
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":4,"id":%d}`, call.ID)
	for {
		if _, h := c.reads(); h >= 6 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	// The status was read once, while arming: the watch is what saves the polls.
	if s, _ := c.reads(); s != 1 {
		t.Fatalf("%d status reads with a watch armed, want 1", s)
	}
}

func TestConfirmPollsWhenTheSubscribeGoesUnanswered(t *testing.T) {
	f := newFakePubSub(t)
	p, _ := dial(t, f, nil)
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(5, Confirmed)}, heights: []uint64{1}}
	done := make(chan error, 1)
	go func() {
		_, err := Confirm(t.Context(), c, testSig, 100, Confirmed, ConfirmOptions{PubSub: p, Poll: time.Millisecond, HeightCheck: 20 * time.Millisecond})
		done <- err
	}()
	f.next(t) // the subscribe, never answered
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm waited on a subscribe nobody answers")
	}
	if s, _ := c.reads(); s != 2 {
		t.Fatalf("%d status reads, want 2", s)
	}
}

func TestConfirmPollsWhenTheSubscribeFails(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	_ = ws.Close()
	<-p.Done()
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(5, Confirmed)}, heights: []uint64{1}}
	if _, err := Confirm(t.Context(), c, testSig, 100, Confirmed, ConfirmOptions{PubSub: p, Poll: time.Millisecond, HeightCheck: time.Hour}); err != nil {
		t.Fatal(err)
	}
}

func TestConfirmPollsOnceTheWatchDrops(t *testing.T) {
	f := newFakePubSub(t)
	p, ws := dial(t, f, nil)
	// Poll is an hour, so only a status read at the drop itself ends it.
	c := &confirmChain{statuses: []*SignatureStatus{nil, at(5, Confirmed)}, heights: []uint64{1}}
	done := make(chan error, 1)
	go func() {
		_, err := Confirm(t.Context(), c, testSig, 100, Confirmed, ConfirmOptions{PubSub: p, Poll: time.Hour, HeightCheck: time.Hour})
		done <- err
	}()
	call := f.next(t)
	sendFrame(t, ws, `{"jsonrpc":"2.0","result":4,"id":%d}`, call.ID)
	for {
		if s, _ := c.reads(); s >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	_ = ws.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Confirm never fell back to polling")
	}
	if s, _ := c.reads(); s != 2 {
		t.Fatalf("%d status reads, want 2", s)
	}
}
