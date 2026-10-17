/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"net/http"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// noteLog collects the events a turn notes.
type noteLog struct {
	mu  sync.Mutex
	evs []Event
}

func (l *noteLog) note(ev Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evs = append(l.evs, ev)
}

func (l *noteLog) seen() []Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]Event(nil), l.evs...)
}

func ofType[T Event](evs []Event) []T {
	var out []T
	for _, ev := range evs {
		if e, ok := ev.(T); ok {
			out = append(out, e)
		}
	}
	return out
}

// Each sweep names its candidates in order, and each candidate's reserve is
// announced with the route chosen for it. A pool that stays at capacity is
// swept again, which shows as a second RouteCandidates.
func TestDispatch_AnnouncesSweepsRoutesAndReserves(t *testing.T) {
	ops := []Operator{pricedOp(1, 1, 2), pricedOp(2, 1, 2)}
	c, rc := admitClient(t, ops, nil)
	rc.script = []error{&BusyError{Code: "no_capacity"}}
	c.sweepDelayFn = func(int) time.Duration { return time.Millisecond }
	evs, err := runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: admitBody})
	if err == nil {
		t.Fatal("a pool always at capacity served the turn")
	}

	sweeps := ofType[RouteCandidates](evs)
	if len(sweeps) < 2 {
		t.Fatalf("%d RouteCandidates, want one per sweep and a re-sweep of a busy pool", len(sweeps))
	}
	want := RouteCandidates{Model: "gpt-test", Candidates: []NodeRef{RefOf(ops[0]), RefOf(ops[1])}}
	for i, s := range sweeps {
		if !reflect.DeepEqual(s, want) {
			t.Errorf("sweep %d = %+v, want %+v", i, s, want)
		}
	}

	// Every reserve follows its candidate's route, and names the same target.
	var route *RelayHopChanged
	var reserves int
	for _, ev := range evs {
		switch ev := ev.(type) {
		case RouteCandidates:
			route = nil
		case RelayHopChanged:
			if ev.Reason != RelayHopChosen || ev.Relay != nil {
				t.Errorf("direct route = %+v, want chosen with no relay", ev)
			}
			route = &ev
		case ReserveStarted:
			reserves++
			if route == nil || ev.Target != route.Target || ev.Relay != nil || ev.Attempt != 1 {
				t.Errorf("reserve %+v does not follow its route %+v", ev, route)
			}
		}
	}
	if reserves != rc.calls() {
		t.Errorf("%d ReserveStarted for %d reserves", reserves, rc.calls())
	}
}

// A retry is announced with the failure that caused it, then the relay it
// rotates to, then the reserve it starts.
func TestReserveWithTransientRetry_AnnouncesTheRetry(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	relayA := retryOp(2, "OWNER-A")
	relayB := retryOp(3, "OWNER-B")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout), nil}}
	s := retryServer(t, true, rc, []Operator{target, relayA, relayB})
	relaySel := selOf(target, relayA, relayB)
	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatal(err)
	}
	var log noteLog
	ctx := withNote(context.Background(), log.note)
	if got := s.reserveWithTransientRetry(ctx, target, ticket.ReserveRequest{}, hop, relaySel, true, false, time.Now().Add(10*time.Second), nil); got.Err != nil {
		t.Fatalf("reserve err = %v, want success on the rotated retry", got.Err)
	}

	first, second := rc.hopAt(0).RelayRef(), rc.hopAt(1).RelayRef()
	evs := log.seen()
	if len(evs) != 4 {
		t.Fatalf("events %+v, want started, retrying, rotated, started", evs)
	}
	if ev, ok := evs[0].(ReserveStarted); !ok || ev.Target != RefOf(target) || ev.Relay == nil || *ev.Relay != first || ev.Attempt != 1 {
		t.Errorf("first = %+v, want attempt 1 through %+v", evs[0], first)
	}
	retry, ok := evs[1].(ReserveRetrying)
	if !ok || retry.Target != RefOf(target) || retry.Status != http.StatusGatewayTimeout || retry.Code != "" || retry.Attempt != 2 || retry.Wait <= 0 {
		t.Errorf("second = %+v, want attempt 2 after the 504, with its wait", evs[1])
	}
	if rot, ok := evs[2].(RelayHopChanged); !ok || rot.Reason != RelayHopRotated || rot.Relay == nil || *rot.Relay != second || rot.Target != RefOf(target) {
		t.Errorf("third = %+v, want a rotation to %+v", evs[2], second)
	}
	if ev, ok := evs[3].(ReserveStarted); !ok || ev.Relay == nil || *ev.Relay != second || ev.Attempt != 2 {
		t.Errorf("fourth = %+v, want attempt 2 through %+v", evs[3], second)
	}
}

// With no other relay to rotate to, the retry does not happen, so it is not
// announced.
func TestReserveWithTransientRetry_NoRelayLeftAnnouncesNoRetry(t *testing.T) {
	target := retryOp(1, "OWNER-TARGET")
	relayA := retryOp(2, "OWNER-A")
	rc := &scriptedReserveClient{script: []error{gatewayErr(http.StatusGatewayTimeout)}}
	s := retryServer(t, true, rc, []Operator{target, relayA})
	relaySel := selOf(target, relayA)
	hop, err := s.relayHopForPool(relaySel, target, true)
	if err != nil {
		t.Fatal(err)
	}
	var log noteLog
	ctx := withNote(context.Background(), log.note)
	s.reserveWithTransientRetry(ctx, target, ticket.ReserveRequest{}, hop, relaySel, true, false, time.Now().Add(10*time.Second), nil)
	if rc.calls() != 1 {
		t.Fatalf("reserve calls = %d, want 1", rc.calls())
	}
	if n := len(ofType[ReserveRetrying](log.seen())); n != 0 {
		t.Errorf("%d retries announced for none made", n)
	}
}

// noteSpyHandle notes an event from inside the settle submit, as any code
// on that path reaching for the turn's note would.
type noteSpyHandle struct{ scriptedSettleHandle }

func (h *noteSpyHandle) AckSettle(ctx context.Context, r *ticket.UsageReceipt, g string) (string, uint64, bool, error) {
	noteFrom(ctx)(Done{})
	return h.scriptedSettleHandle.AckSettle(ctx, r, g)
}

// A settle can run after the turn's events have ended, so its context
// carries no note: the emitter cannot take an event then.
func TestCheckReceipt_SettleCarriesNoNote(t *testing.T) {
	f := newSettleFixture(t)
	var log noteLog
	ctx := withNote(withSettleSlot(context.Background(), newSettleSlot()), log.note)
	submit, _ := settleClient().checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op,
		&noteSpyHandle{scriptedSettleHandle{txid: "ACK"}}, f.receipt, wire.BodyHashOfBody(f.plaintext), f.plaintext, "", nil)
	if submit == nil {
		t.Fatal("a verified receipt built no submit")
	}
	if _, err := submit(); err != nil {
		t.Fatal(err)
	}
	if evs := log.seen(); len(evs) != 0 {
		t.Errorf("the settle reached the turn's note: %+v", evs)
	}
}

// The receipt's report: a violation replaces the verified receipt and says
// nothing of a settle, and a verified one is followed by the node's
// exclusion and the settle submitted, in that order.
func TestUsageReport_Events(t *testing.T) {
	op := Operator{ID: 7, NodeID: 2}
	report := func(check receiptCheck) []Event {
		u := &usageReport{receipt: &ticket.UsageReceipt{}, ticket: &ticket.Ticket{TicketID: "T"}, op: op, check: check}
		evs := u.events()
		if _, ok := evs[0].(ReceiptVerified); ok {
			evs[0] = ReceiptVerified{} // its fields are TestUsageReport_Event's
		}
		return evs
	}
	for _, tc := range []struct {
		name  string
		check receiptCheck
		want  []Event
	}{
		{"verified, nothing submitted", receiptCheck{}, []Event{ReceiptVerified{}}},
		{"verified, the submit failed", receiptCheck{settled: Settlement{Kind: SettleAtomic}}, []Event{ReceiptVerified{}}},
		{"verified, settled atomically",
			receiptCheck{settled: Settlement{Kind: SettleAtomic, TxID: "TX", FeesMicroAlgos: 0}},
			[]Event{ReceiptVerified{}, SettleSubmitted{TicketID: "T", TxID: "TX", Atomic: true}}},
		{"verified, a forged group, then a payer ack",
			receiptCheck{excluded: true, settled: Settlement{Kind: SettlePayerAck, TxID: "ACK", FeesMicroAlgos: 1000}},
			[]Event{ReceiptVerified{}, NodeExcluded{Node: NodeRef{Op: 7, Node: 2}, Reason: "settle_group_rejected"},
				SettleSubmitted{TicketID: "T", TxID: "ACK", FeesMicroAlgos: 1000}}},
		{"body_hash, protested",
			receiptCheck{violation: "body_hash", settled: Settlement{Kind: SettleProtest, TxID: "PROTEST"}},
			[]Event{ReceiptViolated{Violation: "body_hash", ProtestTxID: "PROTEST"}}},
		{"body_hash, protest not yet run", receiptCheck{violation: "body_hash"}, []Event{ReceiptViolated{Violation: "body_hash"}}},
		{"sig", receiptCheck{violation: "sig"}, []Event{ReceiptViolated{Violation: "sig"}}},
	} {
		if got := report(tc.check); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: events %+v, want %+v", tc.name, got, tc.want)
		}
	}
}
