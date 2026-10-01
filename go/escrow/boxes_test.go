/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// fakeBoxLister satisfies protoalgod.BoxLister with a canned box set (it ignores
// the prefix — each test supplies only the boxes for the prefix under test). err
// lets a test drive the capability-probe fallback, which is otherwise
// unreachable through a fake that always succeeds.
type fakeBoxLister struct {
	boxes []protoalgod.Box
	err   error
}

func (f fakeBoxLister) ListApplicationBoxes(_ context.Context, _ uint64, _ []byte) ([]protoalgod.Box, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.boxes, nil
}

func TestTicketIDFromBoxName(t *testing.T) {
	id := bytes.Repeat([]byte{0xAB}, 16)
	got, ok := ticketIDFromBoxName(TicketBoxKey(id))
	if !ok || !bytes.Equal(got, id) {
		t.Fatalf("round-trip = %x/%v, want %x/true", got, ok, id)
	}
	if _, ok := ticketIDFromBoxName(OperatorBoxKey(1)); ok {
		t.Fatal("an operator box name must not parse as a ticket box")
	}
	// A `t:` box whose suffix isn't a 16-byte id is not a ticket this contract
	// writes — the listing must skip it rather than guess.
	if _, ok := ticketIDFromBoxName([]byte("t:short")); ok {
		t.Fatal("a wrong-length name must not parse")
	}
	// The returned id must not alias the caller's name buffer.
	name := TicketBoxKey(id)
	got, _ = ticketIDFromBoxName(name)
	name[2] = 0x00
	if got[0] != 0xAB {
		t.Fatal("returned id aliases the box-name buffer")
	}
}

// ticketBoxValue is a minimal parseable ticket box image: an all-zero record
// with just the fields the fetch path surfaces set.
func ticketBoxValue(status, grace uint64) []byte {
	b := make([]byte, ticketRecordSize)
	binary.BigEndian.PutUint64(b[136:144], grace)
	b[144] = byte(status)
	return b
}

func TestFetchAllTicketsBulk_ParsesSkipsForeignNamesAndSorts(t *testing.T) {
	idHi := bytes.Repeat([]byte{0x02}, 16)
	idLo := bytes.Repeat([]byte{0x01}, 16)
	c := &Client{AppID: 100}
	bl := fakeBoxLister{boxes: []protoalgod.Box{
		{Name: TicketBoxKey(idHi), Value: ticketBoxValue(StatusFrozen, 300)},
		{Name: TicketBoxKey(idLo), Value: ticketBoxValue(StatusOpen, 600)},
		// algod filters by prefix server-side, but a defensive skip keeps a
		// stray non-ticket box from being parsed as one.
		{Name: OperatorBoxKey(1), Value: opBoxValue(OperatorStatusActive)},
	}}
	got, err := c.fetchAllTicketsBulk(context.Background(), bl)
	if err != nil {
		t.Fatalf("fetchAllTicketsBulk: %v", err)
	}
	if len(got.Tickets) != 2 {
		t.Fatalf("got %d tickets, want 2 (non-ticket box name skipped)", len(got.Tickets))
	}
	if !bytes.Equal(got.Tickets[0].IDRaw, idLo) || !bytes.Equal(got.Tickets[1].IDRaw, idHi) {
		t.Fatalf("not sorted by id: %x, %x", got.Tickets[0].IDRaw, got.Tickets[1].IDRaw)
	}
	// Values arrive with the names — no follow-up read needed to see the record.
	if got.Tickets[0].Record.Status != StatusOpen || got.Tickets[0].Record.SettlementGraceSeconds != 600 {
		t.Fatalf("record not parsed from the listing value: %+v", got.Tickets[0].Record)
	}
	if got.Tickets[1].Record.Status != StatusFrozen {
		t.Fatalf("record not parsed from the listing value: %+v", got.Tickets[1].Record)
	}
}

// An undecodable box must cost the caller only that box. Failing the whole fetch
// would mean one poisoned box (bindings behind the deployed app) stops the payer
// refunding anything and the operator claiming anything — and the sweep filters
// by operator only AFTER this fetch, so the bad box may not even be theirs.
func TestFetchAllTicketsBulk_UnreadableBoxDoesNotHideTheRest(t *testing.T) {
	good := bytes.Repeat([]byte{0x01}, 16)
	short := bytes.Repeat([]byte{0x02}, 16)
	c := &Client{AppID: 100}
	bl := fakeBoxLister{boxes: []protoalgod.Box{
		{Name: TicketBoxKey(short), Value: []byte("truncated")},
		{Name: TicketBoxKey(good), Value: ticketBoxValue(StatusOpen, 300)},
	}}
	got, err := c.fetchAllTicketsBulk(context.Background(), bl)
	if err != nil {
		t.Fatalf("one bad box must not fail the fetch: %v", err)
	}
	if len(got.Tickets) != 1 || !bytes.Equal(got.Tickets[0].IDRaw, good) {
		t.Fatalf("good ticket lost: %+v", got.Tickets)
	}
	// Dropped, but never silently.
	if len(got.Unreadable) != 1 || !bytes.Equal(got.Unreadable[0].IDRaw, short) {
		t.Fatalf("unreadable box not reported: %+v", got.Unreadable)
	}
	if got.Unreadable[0].Err == nil {
		t.Fatal("unreadable box reported without a cause")
	}
}

// A listing error is fetch-wide (nothing is known), unlike a single bad box.
func TestFetchAllTicketsBulk_ListingErrorFailsTheFetch(t *testing.T) {
	c := &Client{AppID: 100}
	bl := fakeBoxLister{err: errors.New("algod down")}
	if _, err := c.fetchAllTicketsBulk(context.Background(), bl); err == nil {
		t.Fatal("a failed listing must fail the fetch")
	}
}

// fallbackProbeAlgod satisfies protoalgod.Client AND BoxLister, so the
// capability probe takes the bulk path; its SDK client is unusable, so the
// per-box fallback fails loudly instead of silently passing.
type fallbackProbeAlgod struct {
	stubAlgod
	protoalgod.BoxLister
}

// ErrBoxValuesUnsupported is the "this algod is too old" signal, not a real
// failure: it must route to the per-box fallback rather than reach the caller.
func TestFetchAllTickets_FallsBackWhenValuesUnsupported(t *testing.T) {
	c := &Client{AppID: 100, Algod: fallbackProbeAlgod{
		BoxLister: fakeBoxLister{err: protoalgod.ErrBoxValuesUnsupported},
	}}
	_, err := c.FetchAllTickets(context.Background())
	if err == nil {
		t.Fatal("want the fallback to run and fail on the unusable SDK client")
	}
	if errors.Is(err, protoalgod.ErrBoxValuesUnsupported) {
		t.Fatalf("sentinel leaked to the caller instead of triggering the fallback: %v", err)
	}
}

// A non-sentinel listing error is a real failure — don't mask it by falling back
// to an O(N) walk that will hit the same broken algod.
func TestFetchAllTickets_RealListingErrorDoesNotFallBack(t *testing.T) {
	c := &Client{AppID: 100, Algod: fallbackProbeAlgod{
		BoxLister: fakeBoxLister{err: errors.New("algod down")},
	}}
	_, err := c.FetchAllTickets(context.Background())
	if err == nil || !strings.Contains(err.Error(), "algod down") {
		t.Fatalf("want the listing error surfaced verbatim, got %v", err)
	}
}

func TestOperatorIDFromBoxName(t *testing.T) {
	if id, ok := operatorIDFromBoxName(OperatorBoxKey(42)); !ok || id != 42 {
		t.Fatalf("round-trip = %d/%v, want 42/true", id, ok)
	}
	if _, ok := operatorIDFromBoxName(NodeBoxKey(1, 1)); ok {
		t.Fatal("a node box name must not parse as an operator box")
	}
	if _, ok := operatorIDFromBoxName([]byte("o:short")); ok {
		t.Fatal("a wrong-length name must not parse")
	}
}

func TestNodeIDsFromBoxName(t *testing.T) {
	if op, node, ok := nodeIDsFromBoxName(NodeBoxKey(7, 3)); !ok || op != 7 || node != 3 {
		t.Fatalf("round-trip = %d/%d/%v, want 7/3/true", op, node, ok)
	}
	if _, _, ok := nodeIDsFromBoxName(OperatorBoxKey(1)); ok {
		t.Fatal("an operator box name must not parse as a node box")
	}
}

// opBoxValue is a minimal parseable operator box image (all-zero fields with the
// status byte set) — enough to exercise the bulk fetch's parse + filter + sort.
func opBoxValue(status uint64) []byte {
	b := make([]byte, operatorRecordSize)
	b[32] = byte(status) // Status is the byte after the 32-byte owner address
	return b
}

func TestFetchAllOperatorsBulk_ParsesAndSorts(t *testing.T) {
	bl := fakeBoxLister{boxes: []protoalgod.Box{
		{Name: OperatorBoxKey(3), Value: opBoxValue(OperatorStatusActive)},
		{Name: OperatorBoxKey(1), Value: opBoxValue(OperatorStatusEvicted)},
		{Name: []byte("t:not-an-operator-box"), Value: opBoxValue(OperatorStatusActive)},
	}}
	recs, err := fetchAllOperatorsBulk(context.Background(), 100, bl)
	if err != nil {
		t.Fatalf("fetchAllOperatorsBulk: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d operators, want 2 (non-operator box name skipped)", len(recs))
	}
	if recs[0].ID != 1 || recs[1].ID != 3 {
		t.Fatalf("not sorted by id: %d, %d", recs[0].ID, recs[1].ID)
	}
	if recs[0].Status != OperatorStatusEvicted {
		t.Fatalf("Status not parsed from box value: %d", recs[0].Status)
	}
}

func TestFetchAllNodesBulk_FiltersByOperatorAndSorts(t *testing.T) {
	ops := []OperatorRecord{
		{ID: 1, Status: OperatorStatusActive},
		{ID: 2, Status: OperatorStatusEvicted},
	}
	nodeVal := func() []byte { return make([]byte, nodeRecordSize) }
	bl := fakeBoxLister{boxes: []protoalgod.Box{
		{Name: NodeBoxKey(1, 2), Value: nodeVal()},
		{Name: NodeBoxKey(1, 1), Value: nodeVal()},
		{Name: NodeBoxKey(2, 1), Value: nodeVal()}, // operator 2 evicted → dropped
		{Name: NodeBoxKey(9, 1), Value: nodeVal()}, // operator 9 not in ops → dropped
	}}
	recs, err := fetchAllNodesBulk(context.Background(), 100, ops, bl)
	if err != nil {
		t.Fatalf("fetchAllNodesBulk: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d nodes, want 2 (evicted + unknown operator dropped)", len(recs))
	}
	if recs[0].OperatorID != 1 || recs[0].NodeID != 1 || recs[1].OperatorID != 1 || recs[1].NodeID != 2 {
		t.Fatalf("not sorted by (operator, node): %+v", recs)
	}
}
