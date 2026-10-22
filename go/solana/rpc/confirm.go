/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package rpc

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
)

// ErrExpired is a transaction that can never land: the cluster has confirmed
// a block past its blockhash's lastValidBlockHeight, and it has no status.
// Anything else, a missing status included, may still land.
var ErrExpired = errors.New("solana rpc: transaction expired without landing")

const (
	// DefaultConfirmPoll is the wait between status polls once no watch is
	// armed. Each poll is a request against the endpoint's rate limit, where
	// a watch costs none, so it is slow; the watch is the fast path.
	DefaultConfirmPoll = 2 * time.Second
	// DefaultConfirmHeightCheck is the wait between block-height reads while
	// a watch is armed: the watch says when the transaction lands, the height
	// when it can no longer.
	DefaultConfirmHeightCheck = 5 * time.Second
)

// ConfirmOptions tunes Confirm. The zero value polls at the defaults.
type ConfirmOptions struct {
	// PubSub watches the signature. Nil, or a watch that fails, isn't armed
	// within HeightCheck, or whose socket drops, polls instead.
	PubSub *PubSub
	// Poll and HeightCheck override DefaultConfirmPoll and
	// DefaultConfirmHeightCheck.
	Poll        time.Duration
	HeightCheck time.Duration
}

// Confirm waits until sig reaches cm and returns how it landed: Err set is a
// transaction that landed and failed. It returns ErrExpired once the
// transaction can no longer land (lastValid is its blockhash's
// lastValidBlockHeight), and ctx's error when ctx ends first. cm empty waits
// for finalized, the RPC's default.
func Confirm(ctx context.Context, c Client, sig solana.Signature, lastValid uint64, cm Commitment, o ConfirmOptions) (SignatureResult, error) {
	if cm == "" {
		cm = Finalized
	}
	poll, heightCheck := o.Poll, o.HeightCheck
	if poll <= 0 {
		poll = DefaultConfirmPoll
	}
	if heightCheck <= 0 {
		heightCheck = DefaultConfirmHeightCheck
	}
	var sub *SignatureSubscription
	if o.PubSub != nil {
		// Bounded, so a socket that stays open and never answers the
		// subscribe costs one height check before polling, not the caller's
		// whole deadline.
		actx, cancel := context.WithTimeout(ctx, heightCheck)
		s, err := o.PubSub.SignatureSubscribe(actx, sig, cm)
		cancel()
		if err == nil {
			sub = s
			defer sub.Unsubscribe()
		} else if ctx.Err() != nil {
			return SignatureResult{}, ctx.Err()
		}
	}
	// One status read even with a watch armed: the transaction may have
	// reached c before the watch did.
	checkStatus := true
	for {
		if r, done, err := confirmStep(ctx, c, sig, lastValid, cm, checkStatus); done || err != nil {
			return r, err
		}
		wait := poll
		var subDone <-chan struct{}
		if sub != nil {
			wait, subDone = heightCheck, sub.Done()
		}
		t := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			t.Stop()
			return SignatureResult{}, ctx.Err()
		case <-subDone:
			t.Stop()
			if r, err := sub.Result(); err == nil {
				return r, nil
			}
			// The socket dropped: poll from here.
			sub = nil
			checkStatus = true
		case <-t.C:
			checkStatus = sub == nil
		}
	}
}

// confirmStep reads the status when checkStatus is set, and the block
// height whenever no status settles it. done reports a result or an expiry.
func confirmStep(ctx context.Context, c Client, sig solana.Signature, lastValid uint64, cm Commitment, checkStatus bool) (SignatureResult, bool, error) {
	status := func() (*SignatureStatus, error) {
		s, err := c.GetSignatureStatuses(ctx, []solana.Signature{sig}, false)
		if err != nil {
			return nil, err
		}
		if len(s) != 1 {
			return nil, fmt.Errorf("solana rpc: %d statuses for one signature", len(s))
		}
		return s[0], nil
	}
	if checkStatus {
		s, err := status()
		if err != nil {
			return SignatureResult{}, false, err
		}
		if s != nil {
			if reached(s, cm) {
				return SignatureResult{Slot: s.Slot, Err: s.Err}, true, nil
			}
			// Landed, not yet at cm: no height read while it stands. A fork
			// that drops it brings back no status, and the height rule.
			return SignatureResult{}, false, nil
		}
	}
	h, err := c.GetBlockHeight(ctx, Confirmed)
	if err != nil {
		return SignatureResult{}, false, err
	}
	if h <= lastValid {
		return SignatureResult{}, false, nil
	}
	// Past the height: one last read decides, since it may have landed
	// since the status read, or no status was read.
	s, err := status()
	switch {
	case err != nil:
		return SignatureResult{}, false, err
	case s == nil:
		return SignatureResult{}, true, ErrExpired
	case reached(s, cm):
		return SignatureResult{Slot: s.Slot, Err: s.Err}, true, nil
	}
	return SignatureResult{}, false, nil
}

var commitmentRank = map[Commitment]int{Processed: 1, Confirmed: 2, Finalized: 3}

// reached reports whether a status is at c or beyond. A status without a
// confirmationStatus is an older RPC's: finalized when its confirmations are
// nil (the block is rooted), else processed.
func reached(s *SignatureStatus, c Commitment) bool {
	got := s.ConfirmationStatus
	if got == "" {
		got = Processed
		if s.Confirmations == nil {
			got = Finalized
		}
	}
	return commitmentRank[got] >= commitmentRank[c]
}
