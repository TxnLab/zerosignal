/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"sync"
)

// SettleKind is which escrow submit a turn made. With an error from Wait it is
// the submit that was attempted, not one that took effect.
type SettleKind string

const (
	// SettleNone: the turn opened no escrow, no receipt arrived, or the
	// receipt called for nothing on chain (a violation the contract would not
	// accept a protest for). An escrow opened without a submit is the refund
	// watchdog's and the journal's to recover. A submit that panicked also
	// reports SettleNone, with an error.
	SettleNone SettleKind = ""
	// SettleAtomic: the node's pre-signed group with the payer's half, which
	// finishes the ticket once it lands.
	SettleAtomic SettleKind = "atomic"
	// SettlePayerAck: the payer's half alone, posted when the node sent no
	// group or one that failed verification. The ticket finishes when the
	// operator matches it, or by refund at the deadline; the refund watchdog
	// and the journal see to that.
	SettlePayerAck SettleKind = "payer_ack"
	// SettleProtest: the receipt's body hash did not match the content, so
	// the payer protested, which freezes the ticket for arbitration once it
	// lands.
	SettleProtest SettleKind = "protest"
)

// Settlement is a turn's payer-side escrow submit, as Stream.Wait reports it.
type Settlement struct {
	TicketID       string
	Kind           SettleKind
	TxID           string
	FeesMicroAlgos uint64
}

var errStreamNotRun = errors.New("zs: Wait called before the Stream's events were ranged over")

// settleSlot carries one turn's submit outcome from wherever the submit runs
// (inline on a stream, in the background after a whole reply) to Wait.
type settleSlot struct {
	once sync.Once
	done chan struct{}
	// expected is set when a submit is built, which happens on the goroutine
	// running Events, before dispatch returns. The submit itself may run
	// later on another goroutine, but it reports through finish.
	expected bool
	result   Settlement
	err      error
}

func newSettleSlot() *settleSlot { return &settleSlot{done: make(chan struct{})} }

func (s *settleSlot) finish(r Settlement, err error) {
	s.once.Do(func() {
		s.result, s.err = r, err
		close(s.done)
	})
}

type settleSlotKey struct{}

func withSettleSlot(ctx context.Context, s *settleSlot) context.Context {
	return context.WithValue(ctx, settleSlotKey{}, s)
}

func settleSlotFrom(ctx context.Context) *settleSlot {
	s, _ := ctx.Value(settleSlotKey{}).(*settleSlot)
	return s
}

// Wait blocks until this turn's escrow submit has returned, or ctx is done,
// and reports it. It does not wait for confirmation: a submitted transaction
// can still fail to land, which the refund watchdog and the journal cover.
// Call it after the Events loop has finished; a turn with no submit returns
// at once with SettleNone. Called from inside the loop it can wait forever:
// a whole reply's submit starts only once the loop has returned.
func (s *Stream) Wait(ctx context.Context) (Settlement, error) {
	if !s.started.Load() {
		return Settlement{}, errStreamNotRun
	}
	// A select with both ready picks at random, and a caller waiting on its
	// request's context after the client hung up would lose a submit that
	// happened.
	select {
	case <-s.settle.done:
		return s.settle.result, s.settle.err
	default:
	}
	select {
	case <-s.settle.done:
		return s.settle.result, s.settle.err
	case <-ctx.Done():
		return Settlement{}, ctx.Err()
	}
}
