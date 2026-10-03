/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// scriptedSettleHandle returns fixed results from AckSettle and Protest, or
// panics from either.
type scriptedSettleHandle struct {
	txid          string
	fee           uint64
	groupRejected bool
	err           error
	panicWith     any
}

func (h *scriptedSettleHandle) AckSettle(context.Context, *ticket.UsageReceipt, []types.SignedTxn) (string, uint64, bool, error) {
	if h.panicWith != nil {
		panic(h.panicWith)
	}
	return h.txid, h.fee, h.groupRejected, h.err
}

func (h *scriptedSettleHandle) Protest(context.Context, *ticket.UsageReceipt, []byte, escrow.ProtestReasonCode) (string, uint64, error) {
	if h.panicWith != nil {
		panic(h.panicWith)
	}
	return h.txid, h.fee, h.err
}

// settleFixture is a ticket and a receipt its operator signed over plaintext.
type settleFixture struct {
	op        Operator
	tkt       *ticket.Ticket
	receipt   *ticket.UsageReceipt
	plaintext []byte
}

func newSettleFixture(t *testing.T) settleFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var addr types.Address
	copy(addr[:], pub)
	op := Operator{ID: 7, NodeID: 3, SigningAddr: addr.String(), TicketSigningKey: pub}
	tkt := &ticket.Ticket{TicketID: "dGlja2V0LXdhaXQtMDAwMDA=", OperatorID: op.ID, NodeID: op.NodeID, MaxPrice: 100_000}
	plaintext := []byte("hello world")
	receipt := &ticket.UsageReceipt{TicketID: tkt.TicketID, ActualInputCount: 10, ActualOutputCount: 5, AmountCharged: 50_000}
	receipt.SetBodyHashBytes(wire.BodyHashOfBody(plaintext))
	if err := receipt.Sign(context.Background(), rawKeyBytesSigner{addr: op.SigningAddr, priv: priv}, op.SigningAddr); err != nil {
		t.Fatal(err)
	}
	return settleFixture{op: op, tkt: tkt, receipt: receipt, plaintext: plaintext}
}

func settleClient() *Client {
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Client{cfg: Config{Privacy: PrivacyDirect}, log: discard, refunds: NewRefundWatchdog(discard)}
}

// check runs checkReceipt with slot in its context. matching picks whether the
// computed body hash is the receipt's (a paid turn) or not (a protest).
func (f settleFixture) check(c *Client, slot *settleSlot, h settlementHandle, matching bool, group []types.SignedTxn) settleSubmit {
	computed := wire.BodyHashOfBody(f.plaintext)
	if !matching {
		computed = wire.BodyHashOfBody([]byte("other content"))
	}
	ctx := withSettleSlot(context.Background(), slot)
	return c.checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, h, f.receipt, computed, f.plaintext, 0, group, nil)
}

func slotResult(t *testing.T, slot *settleSlot) (Settlement, error) {
	t.Helper()
	select {
	case <-slot.done:
		return slot.result, slot.err
	default:
		t.Fatal("slot not finished")
		return Settlement{}, nil
	}
}

// Each submit finishes the slot with its outcome. Only a submit that ends the
// ticket on chain (a landed atomic group, a protest that froze it) stops the
// refund watchdog; a payer-only ack or a failed submit leaves it watching, so
// the escrow is still recovered at the deadline.
func TestCheckReceipt_FinishesTheSlotWithTheSubmit(t *testing.T) {
	ackErr := errors.New("algod down")
	cases := []struct {
		name     string
		handle   *scriptedSettleHandle
		matching bool
		group    []types.SignedTxn
		want     Settlement
		wantErr  error
		watched  bool
	}{
		{"atomic", &scriptedSettleHandle{txid: "GROUPTX"}, true, []types.SignedTxn{{}, {}},
			Settlement{Kind: SettleAtomic, TxID: "GROUPTX"}, nil, false},
		{"payer ack without a group", &scriptedSettleHandle{txid: "ACKTX", fee: 1000}, true, nil,
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000}, nil, true},
		{"payer ack after a rejected group", &scriptedSettleHandle{txid: "ACKTX", fee: 1000, groupRejected: true}, true, []types.SignedTxn{{}, {}},
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000}, nil, true},
		{"failed ack", &scriptedSettleHandle{txid: "IGNORED", fee: 7, err: ackErr}, true, []types.SignedTxn{{}, {}},
			Settlement{Kind: SettleAtomic}, ackErr, true},
		// The payer signs the protest, so its fee is the payer's.
		{"protest", &scriptedSettleHandle{txid: "PROTESTTX", fee: 3000}, false, nil,
			Settlement{Kind: SettleProtest, TxID: "PROTESTTX", FeesMicroAlgos: 3000}, nil, false},
		{"failed protest", &scriptedSettleHandle{txid: "IGNORED", err: ackErr}, false, nil,
			Settlement{Kind: SettleProtest}, ackErr, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			slot := newSettleSlot()
			submit := f.check(c, slot, tc.handle, tc.matching, tc.group)
			if submit == nil {
				t.Fatal("no submit")
			}
			if !slot.expected {
				t.Error("building the submit did not mark the slot expected")
			}
			select {
			case <-slot.done:
				t.Fatal("slot finished before the submit ran")
			default:
			}
			r, err := submit()
			tc.want.TicketID = f.tkt.TicketID
			if r != tc.want || !errors.Is(err, tc.wantErr) {
				t.Errorf("submit = %+v, %v; want %+v, %v", r, err, tc.want, tc.wantErr)
			}
			sr, serr := slotResult(t, slot)
			if sr != r || serr != err {
				t.Errorf("slot = %+v, %v; submit returned %+v, %v", sr, serr, r, err)
			}
			if got := c.refunds.watching(f.tkt.TicketID); got != tc.watched {
				t.Errorf("refund watchdog watching = %v, want %v", got, tc.watched)
			}
		})
	}
}

// The streaming responder reports the payer's settle fee in its usage frame;
// runReceiptChecks is where it comes from.
func TestRunReceiptChecks_ReturnsTheSubmitsFee(t *testing.T) {
	f := newSettleFixture(t)
	fee := settleClient().runReceiptChecks(withSettleSlot(context.Background(), newSettleSlot()),
		endpointChatCompletions, "m", f.tkt, f.op, &scriptedSettleHandle{txid: "ACKTX", fee: 1000},
		f.receipt, wire.BodyHashOfBody(f.plaintext), f.plaintext, 0, nil, nil)
	if fee != 1000 {
		t.Errorf("fee = %d, want the ack's 1000", fee)
	}
}

// A verdict with nothing to submit builds no submit and leaves the slot for
// Events to finish.
func TestCheckReceipt_NothingToSubmitLeavesTheSlotUnexpected(t *testing.T) {
	f := newSettleFixture(t)
	// No escrow was opened.
	slot := newSettleSlot()
	if submit := f.check(settleClient(), slot, nil, true, nil); submit != nil {
		t.Error("no handle: built a submit")
	}
	if slot.expected {
		t.Error("no handle: slot marked expected")
	}
	// A bad signature is a violation the contract takes no protest for.
	bad := *f.receipt
	bad.AmountCharged++
	f.receipt = &bad
	slot = newSettleSlot()
	if submit := f.check(settleClient(), slot, &scriptedSettleHandle{}, true, nil); submit != nil {
		t.Error("a bad signature built a submit")
	}
	if slot.expected {
		t.Error("a bad signature marked the slot expected")
	}
}

// A panicking submit still finishes the slot, so Wait does not hang, and the
// panic still reaches the caller's recover.
func TestCheckReceipt_PanickingSubmitFinishesTheSlot(t *testing.T) {
	f := newSettleFixture(t)
	slot := newSettleSlot()
	submit := f.check(settleClient(), slot, &scriptedSettleHandle{panicWith: "boom"}, true, nil)
	func() {
		defer func() {
			if p := recover(); p != "boom" {
				t.Errorf("recovered %v, want the submit's panic", p)
			}
		}()
		submit()
	}()
	r, err := slotResult(t, slot)
	if err == nil || !strings.Contains(err.Error(), "boom") || r.TicketID != f.tkt.TicketID || r.Kind != SettleNone {
		t.Errorf("slot = %+v, %v; want SettleNone for the ticket and an error naming the panic", r, err)
	}
}

// The non-streaming responder runs the submit after the response; Wait learns
// it from the background goroutine, panic included.
func TestSubmitAfterResponse_FinishesTheSlot(t *testing.T) {
	f := newSettleFixture(t)
	for name, h := range map[string]*scriptedSettleHandle{
		"ok":    {txid: "ACKTX"},
		"panic": {panicWith: "boom"},
	} {
		c := settleClient()
		slot := newSettleSlot()
		c.submitAfterResponse(f.tkt.TicketID, f.check(c, slot, h, true, nil))
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		if err := c.WaitSettles(ctx); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		cancel()
		r, err := slotResult(t, slot)
		if name == "ok" && (err != nil || r.TxID != "ACKTX") {
			t.Errorf("ok: slot = %+v, %v", r, err)
		}
		if name == "panic" && err == nil {
			t.Error("panic: slot finished without an error")
		}
	}
}

func TestWait_BeforeEvents(t *testing.T) {
	st := settleClient().Stream(context.Background(), Request{Endpoint: EndpointChatCompletions})
	if _, err := st.Wait(context.Background()); !errors.Is(err, errStreamNotRun) {
		t.Errorf("Wait before Events = %v, want errStreamNotRun", err)
	}
}

func TestWait_ReturnsWhenItsContextEnds(t *testing.T) {
	st := settleClient().Stream(context.Background(), Request{Endpoint: EndpointChatCompletions})
	st.started.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := st.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("Wait on an unfinished slot = %v, want context.Canceled", err)
	}
	st.settle.finish(Settlement{TicketID: "T", Kind: SettleAtomic}, nil)
	if r, err := st.Wait(context.Background()); err != nil || r.TicketID != "T" {
		t.Errorf("Wait after finish = %+v, %v", r, err)
	}
}

// A finished submit wins over an ended context: a handler waiting on its
// request's context after the client hung up still learns the txid.
func TestWait_FinishedResultBeatsAnEndedContext(t *testing.T) {
	st := settleClient().Stream(context.Background(), Request{Endpoint: EndpointChatCompletions})
	st.started.Store(true)
	st.settle.finish(Settlement{TicketID: "T", TxID: "TX"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 200 {
		if r, err := st.Wait(ctx); err != nil || r.TxID != "TX" {
			t.Fatalf("Wait = %+v, %v; want the finished result", r, err)
		}
	}
}

// A loop body that panics skips the rest of Events; a caller that recovers
// can still Wait.
func TestWait_AfterAPanickingLoopBody(t *testing.T) {
	rc := &scriptedReserveClient{script: []error{errors.New("refused")}}
	c := retryServer(t, false, rc, []Operator{retryOp(1, "OWNER_A")})
	c.tokenizer = testTokenizer()
	c.wallet = fakeFeeWallet{}
	st := c.Stream(context.Background(), Request{Endpoint: EndpointChatCompletions, Body: []byte(`{"model":"gpt-test"}`)})
	func() {
		defer func() {
			if recover() == nil {
				t.Error("the turn yielded nothing to panic on")
			}
		}()
		for range st.Events() {
			panic("caller bug")
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if r, err := st.Wait(ctx); err != nil || r != (Settlement{}) {
		t.Errorf("Wait = %+v, %v; want SettleNone", r, err)
	}
}

// A turn that fails before any escrow finishes Wait with SettleNone.
func TestWait_TurnWithoutASubmit(t *testing.T) {
	rc := &scriptedReserveClient{script: []error{errors.New("refused")}}
	c := retryServer(t, false, rc, []Operator{retryOp(1, "OWNER_A")})
	c.tokenizer = testTokenizer()
	c.wallet = fakeFeeWallet{}
	st := c.Stream(context.Background(), Request{Endpoint: EndpointChatCompletions, Body: []byte(`{"model":"gpt-test"}`)})
	if _, err := st.Text(); err == nil {
		t.Fatal("turn succeeded; this asserts nothing about a failed one")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := st.Wait(ctx)
	if err != nil || r != (Settlement{}) {
		t.Errorf("Wait = %+v, %v; want SettleNone", r, err)
	}
}
