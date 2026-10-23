/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/algod"
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
	claim         ClaimVerdict
	payerSettle   bool
	frozen        bool
	err           error
	panicWith     any
}

func (h *scriptedSettleHandle) AckSettle(context.Context, *ticket.UsageReceipt, string) (AckResult, error) {
	if h.panicWith != nil {
		panic(h.panicWith)
	}
	return AckResult{
		TxID: h.txid, FeeMicroalgos: h.fee, GroupRejected: h.groupRejected, Claim: h.claim,
		PayerSettle: h.payerSettle, Frozen: h.frozen,
	}, h.err
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
	tkt := &ticket.Ticket{TicketID: "dGlja2V0LXdhaXQtMDAwMA==", OperatorID: op.ID, NodeID: op.NodeID, MaxPrice: 100_000}
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
func (f settleFixture) check(c *Client, slot *settleSlot, h settlementHandle, matching bool, group string) settleSubmit {
	computed := wire.BodyHashOfBody(f.plaintext)
	if !matching {
		computed = wire.BodyHashOfBody([]byte("other content"))
	}
	ctx := withSettleSlot(context.Background(), slot)
	submit, _ := c.checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, h, f.receipt, computed, f.plaintext, group, nil)
	return submit
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
		group    string
		want     Settlement
		wantErr  error
		watched  bool
	}{
		{"atomic", &scriptedSettleHandle{txid: "GROUPTX"}, true, testSettleGroup,
			Settlement{Kind: SettleAtomic, TxID: "GROUPTX"}, nil, false},
		{"payer ack without a group", &scriptedSettleHandle{txid: "ACKTX", fee: 1000}, true, "",
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000, NetworkFees: 1000}, nil, true},
		{"payer ack after a rejected group", &scriptedSettleHandle{txid: "ACKTX", fee: 1000, groupRejected: true}, true, testSettleGroup,
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000, NetworkFees: 1000}, nil, true},
		// A failed ack reports what it sent and paid: a Solana ack that landed
		// and failed paid its fee.
		{"failed ack", &scriptedSettleHandle{txid: "SENTTX", fee: 7, err: ackErr}, true, testSettleGroup,
			Settlement{Kind: SettleAtomic, TxID: "SENTTX", FeesMicroAlgos: 7, NetworkFees: 7}, ackErr, true},
		// The payer signs the protest, so its fee is the payer's.
		{"protest", &scriptedSettleHandle{txid: "PROTESTTX", fee: 3000}, false, "",
			Settlement{Kind: SettleProtest, TxID: "PROTESTTX", FeesMicroAlgos: 3000, NetworkFees: 3000, Frozen: true}, nil, false},
		// So does a failed protest: a Solana protest that landed and failed
		// paid its fee too.
		{"failed protest", &scriptedSettleHandle{txid: "SENTTX", fee: 7, err: ackErr}, false, "",
			Settlement{Kind: SettleProtest, TxID: "SENTTX", FeesMicroAlgos: 7, NetworkFees: 7}, ackErr, true},
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

// A protest refused for its deadline is the ticket lapsing on chain, not a
// submit fault, so it logs apart from one. Either way the submit's error is
// returned and the refund watchdog stays armed to drive the deadline path.
func TestCheckReceipt_ProtestAfterDeadlineLogsApart(t *testing.T) {
	late := fmt.Errorf("protest: %w", escrow.ErrProtestAfterDeadline)
	other := errors.New("algod down")
	for _, tc := range []struct {
		name          string
		err           error
		want, notWant string
	}{
		{"after the deadline", late, "protest window closed", "protest failed"},
		{"any other failure", other, "protest failed", "protest window closed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			var logs bytes.Buffer
			c.log = slog.New(slog.NewTextHandler(&logs, nil))
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			submit := f.check(c, newSettleSlot(), &scriptedSettleHandle{err: tc.err}, false, "")
			if submit == nil {
				t.Fatal("no submit")
			}
			r, err := submit()
			if r.Kind != SettleProtest || !errors.Is(err, tc.err) {
				t.Errorf("submit = %+v, %v; want a protest settlement and %v", r, err, tc.err)
			}
			if got := logs.String(); !strings.Contains(got, tc.want) || strings.Contains(got, tc.notWant) {
				t.Errorf("logs = %q; want %q and not %q", got, tc.want, tc.notWant)
			}
			if !c.refunds.watching(f.tkt.TicketID) {
				t.Error("refund watchdog stopped watching a ticket the protest did not freeze")
			}
		})
	}
}

// The streaming responder reports the payer's settle fee in its usage frame;
// runReceiptChecks is where it comes from.
// On another rail a submit's fee is reported under NetworkFees alone, never
// in the field named for µALGO.
func TestCheckReceipt_FeesInAnotherCoin(t *testing.T) {
	for _, tc := range []struct {
		name     string
		matching bool
	}{{"payer ack", true}, {"protest", false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			c.deployment = Deployment{Rail: ticket.RailSolana}
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			submit := f.check(c, newSettleSlot(), &scriptedSettleHandle{txid: "TX", fee: 5000}, tc.matching, "")
			if submit == nil {
				t.Fatal("no submit")
			}
			r, err := submit()
			if err != nil || r.NetworkFees != 5000 || r.FeesMicroAlgos != 0 {
				t.Errorf("submit = %+v, %v; want 5000 under NetworkFees only", r, err)
			}
		})
	}
}

func TestRunReceiptChecks_ReturnsTheSubmitsFee(t *testing.T) {
	f := newSettleFixture(t)
	check := settleClient().runReceiptChecks(withSettleSlot(context.Background(), newSettleSlot()),
		endpointChatCompletions, "m", f.tkt, f.op, &scriptedSettleHandle{txid: "ACKTX", fee: 1000},
		f.receipt, wire.BodyHashOfBody(f.plaintext), f.plaintext, "", nil)
	if check.settled.FeesMicroAlgos != 1000 || check.settled.TxID != "ACKTX" || check.violation != "" {
		t.Errorf("check = %+v, want the ack's ACKTX and 1000, no violation", check)
	}
}

// A verdict with nothing to submit builds no submit and leaves the slot for
// Events to finish.
func TestCheckReceipt_NothingToSubmitLeavesTheSlotUnexpected(t *testing.T) {
	f := newSettleFixture(t)
	// No escrow was opened.
	slot := newSettleSlot()
	if submit := f.check(settleClient(), slot, nil, true, ""); submit != nil {
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
	if submit := f.check(settleClient(), slot, &scriptedSettleHandle{}, true, ""); submit != nil {
		t.Error("a bad signature built a submit")
	}
	if slot.expected {
		t.Error("a bad signature marked the slot expected")
	}
	// Nor for a receipt naming another ticket, even over a body that doesn't
	// match its hash.
	f = newSettleFixture(t)
	forAnotherTicket(&f)
	slot = newSettleSlot()
	if submit := f.check(settleClient(), slot, &scriptedSettleHandle{}, false, ""); submit != nil {
		t.Error("a receipt for another ticket built a submit")
	}
	if slot.expected {
		t.Error("a receipt for another ticket marked the slot expected")
	}
}

// A panicking submit still finishes the slot, so Wait does not hang, and the
// panic still reaches the caller's recover.
func TestCheckReceipt_PanickingSubmitFinishesTheSlot(t *testing.T) {
	f := newSettleFixture(t)
	slot := newSettleSlot()
	submit := f.check(settleClient(), slot, &scriptedSettleHandle{panicWith: "boom"}, true, "")
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
		c.submitAfterResponse(f.tkt.TicketID, f.check(c, slot, h, true, ""))
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

// watchStep is one answer to a settle lookup.
type watchStep struct {
	out SettleOutcome
	err error
}

// watchedSettleHandle is a scriptedSettleHandle whose settle lookups follow
// script, repeating its last step; an empty script is pending forever.
type watchedSettleHandle struct {
	scriptedSettleHandle
	script []watchStep
	looks  atomic.Int32
	txid   atomic.Value // the txid last looked up
}

func (h *watchedSettleHandle) settleOutcome(_ context.Context, txid string) (SettleOutcome, error) {
	h.txid.Store(txid)
	n := int(h.looks.Add(1))
	if len(h.script) == 0 {
		return SettlePending, nil
	}
	s := h.script[min(n, len(h.script))-1]
	return s.out, s.err
}

func shortConfirmWatch(t *testing.T, timeout time.Duration) {
	t.Helper()
	prevTimeout, prevPoll := settleConfirmTimeout, settleConfirmPoll
	settleConfirmTimeout, settleConfirmPoll = timeout, 5*time.Millisecond
	t.Cleanup(func() { settleConfirmTimeout, settleConfirmPoll = prevTimeout, prevPoll })
}

// An atomic settle is seen confirmed before WaitSettles returns, and only
// then does the ticket's journal row go. A ticket that may still be open on
// chain keeps its row for the reconciler: a settle dropped from the pool, one
// never confirmed, one whose lookups fail, and every kind but a landed
// atomic group.
// The charge is decided before the guard hears of it: a host guard that
// panics can't stop the settle, or the protest, that follows.
func TestCheckReceipt_SettlesPastAPanickingSpendGuard(t *testing.T) {
	f := newSettleFixture(t)
	c := settleClient()
	c.spend = panicGuard{}
	if submit := f.check(c, newSettleSlot(), &scriptedSettleHandle{txid: "A"}, true, ""); submit == nil {
		t.Error("no settle after Settle panicked")
	}
	if submit := f.check(c, newSettleSlot(), &scriptedSettleHandle{txid: "P"}, false, ""); submit == nil {
		t.Error("no protest after Release panicked")
	}
}

func TestConfirmSettled_DropsTheRowOnceTheSettleIsConfirmed(t *testing.T) {
	shortConfirmWatch(t, 300*time.Millisecond)
	pending, landed, dropped := watchStep{out: SettlePending}, watchStep{out: SettleLanded}, watchStep{out: SettleDropped}
	failing := watchStep{err: errors.New("algod down")}

	group := testSettleGroup
	handle := func(s scriptedSettleHandle, script ...watchStep) *watchedSettleHandle {
		return &watchedSettleHandle{scriptedSettleHandle: s, script: script}
	}
	cases := []struct {
		name      string
		handle    *watchedSettleHandle
		group     string
		noJournal bool
		wantRow   bool
		wantLooks int // 0: never watched; -1: watched until the deadline
	}{
		{"confirmed on the third look", handle(scriptedSettleHandle{txid: "G"}, pending, pending, landed), group, false, false, 3},
		{"failed lookups, then confirmed", handle(scriptedSettleHandle{txid: "G"}, failing, landed), group, false, false, 2},
		{"never confirmed", handle(scriptedSettleHandle{txid: "G"}, pending), group, false, true, -1},
		{"lookups keep failing", handle(scriptedSettleHandle{txid: "G"}, failing), group, false, true, -1},
		{"dropped from the pool", handle(scriptedSettleHandle{txid: "G"}, pending, dropped), group, false, true, 2},
		// The operator still has to match a payer-only ack.
		{"payer ack", handle(scriptedSettleHandle{txid: "A"}, landed), "", false, true, 0},
		{"rejected group", handle(scriptedSettleHandle{txid: "A", groupRejected: true}, landed), group, false, true, 0},
		{"failed submit", handle(scriptedSettleHandle{err: errors.New("algod down")}, landed), group, false, true, 0},
		// No journal, no row to drop: nothing to wait on algod for.
		{"no journal", handle(scriptedSettleHandle{txid: "G"}, landed), group, true, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			j := newMemJournal()
			if !tc.noJournal {
				c.journal = j
				_ = j.Put(context.Background(), TicketRecord{TicketID: f.tkt.TicketID, Status: TicketSettlePending})
			}

			_, _ = f.check(c, newSettleSlot(), tc.handle, true, tc.group)()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := c.WaitSettles(ctx); err != nil {
				t.Fatal(err)
			}
			if _, has := j.recs[f.tkt.TicketID]; has != tc.wantRow {
				t.Errorf("journal row present = %v, want %v", has, tc.wantRow)
			}
			looks := int(tc.handle.looks.Load())
			switch {
			case tc.wantLooks == -1 && looks < 2:
				t.Errorf("gave up after %d look(s) before the deadline", looks)
			case tc.wantLooks == -1 && looks > int(settleConfirmTimeout/settleConfirmPoll)+2:
				t.Errorf("looked %d times in %v: not waiting %v between looks", looks, settleConfirmTimeout, settleConfirmPoll)
			case tc.wantLooks >= 0 && looks != tc.wantLooks:
				t.Errorf("looked %d time(s), want %d", looks, tc.wantLooks)
			}
			if looks > 0 && tc.handle.txid.Load() != tc.handle.scriptedSettleHandle.txid {
				t.Errorf("looked up %v, want the submitted %s", tc.handle.txid.Load(), tc.handle.scriptedSettleHandle.txid)
			}
			// A finished watch is no longer reported as in flight.
			c.settlesInFlight.Range(func(k, _ any) bool {
				t.Errorf("still in flight after WaitSettles: %v", k)
				return true
			})
		})
	}
}

func TestSettleOutcomeOf(t *testing.T) {
	for _, tc := range []struct {
		name string
		info models.PendingTransactionInfoResponse
		want SettleOutcome
	}{
		{"in the pool", models.PendingTransactionInfoResponse{}, SettlePending},
		{"confirmed", models.PendingTransactionInfoResponse{ConfirmedRound: 1}, SettleLanded},
		{"dropped", models.PendingTransactionInfoResponse{PoolError: "overspend"}, SettleDropped},
		{"confirmed over a pool error", models.PendingTransactionInfoResponse{ConfirmedRound: 1, PoolError: "overspend"}, SettleLanded},
	} {
		if got := settleOutcomeOf(tc.info); got != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, got, tc.want)
		}
	}
}

// A settle group that doesn't decode is passed on as none, so the ack goes
// standalone: passed through, the wallet's own decode would fail inside the
// atomic branch, which surfaces the error and sends no ack at all.
func TestCheckSettleGroupHeader(t *testing.T) {
	f := newSettleFixture(t)
	for _, tc := range []struct {
		name         string
		rail         ticket.Rail
		header, want string
	}{
		{"absent", 0, "", ""},
		{"malformed", 0, "AAAA", ""},
		{"not base64", 0, "not-base64!", ""},
		{"decodes", 0, testSettleGroup, testSettleGroup},
		{"decodes, rail named", ticket.RailAlgorand, testSettleGroup, testSettleGroup},
		{"an open_seq on Algorand", ticket.RailAlgorand, "7", ""},
		// On Solana the slot is the ticket's open_seq, in its one spelling.
		{"open_seq", ticket.RailSolana, "7", "7"},
		{"open_seq zero", ticket.RailSolana, "0", "0"},
		{"open_seq max", ticket.RailSolana, "18446744073709551615", "18446744073709551615"},
		{"open_seq past u64", ticket.RailSolana, "18446744073709551616", ""},
		{"open_seq leading zero", ticket.RailSolana, "07", ""},
		{"open_seq signed", ticket.RailSolana, "+7", ""},
		{"an Algorand group on Solana", ticket.RailSolana, testSettleGroup, ""},
		{"absent on Solana", ticket.RailSolana, "", ""},
	} {
		c := settleClient()
		c.deployment.Rail = tc.rail
		if got := checkSettleGroupHeader(c, tc.header, f.op, f.tkt, nil); got != tc.want {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The bridge reads the deployment's settings off the client: the grace here
// is every refund watchdog deadline, and the app id every settle group spec.
func TestEscrowClientChain_Config(t *testing.T) {
	got := NewEscrowChain(&escrow.Client{AppID: 42, SettlementGraceDefault: 600, ResolvesFrozen: true}).Config()
	if got != (EscrowChainConfig{AppID: 42, SettlementGraceDefault: 600, ResolvesFrozen: true}) {
		t.Errorf("Config = %+v, want app 42, grace 600 and resolveFrozen", got)
	}
	if NewEscrowChain(nil) != nil {
		t.Error("NewEscrowChain(nil) is a non-nil chain the wallet's nil guards would miss")
	}
}

// pendingAlgod answers PendingTransactionInformation; nothing else is called.
type pendingAlgod struct {
	algod.Client
	info models.PendingTransactionInfoResponse
	err  error
	txid string
}

func (a *pendingAlgod) PendingTransactionInformation(_ context.Context, txid string) (models.PendingTransactionInfoResponse, error) {
	a.txid = txid
	return a.info, a.err
}

// The real handle asks algod about the settle transaction itself, never the
// box, and an algod error is no outcome.
func TestOpenHandle_SettleOutcome(t *testing.T) {
	fail := errors.New("algod down")
	for _, tc := range []struct {
		name    string
		algod   *pendingAlgod
		want    SettleOutcome
		wantErr bool
	}{
		{"confirmed", &pendingAlgod{info: models.PendingTransactionInfoResponse{ConfirmedRound: 9}}, SettleLanded, false},
		{"pending", &pendingAlgod{}, SettlePending, false},
		{"lookup failed", &pendingAlgod{err: fail}, SettlePending, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := &OpenHandle{TicketID: "T", wallet: &Wallet{chain: NewEscrowChain(&escrow.Client{Algod: tc.algod})}}
			got, err := h.settleOutcome(context.Background(), "TX")
			if got != tc.want || (err != nil) != tc.wantErr {
				t.Errorf("settleOutcome = %v, %v; want %v (error %v)", got, err, tc.want, tc.wantErr)
			}
			if tc.algod.txid != "TX" {
				t.Errorf("looked up %q, want TX", tc.algod.txid)
			}
		})
	}
	if _, err := (&OpenHandle{}).settleOutcome(context.Background(), "TX"); err == nil {
		t.Error("a handle with no wallet reported an outcome")
	}
	if _, err := NewEscrowChain(&escrow.Client{}).SettleOutcome(context.Background(), "TX"); err == nil {
		t.Error("a chain with no algod reported an outcome")
	}
}

// Close ends a watch WaitSettles would otherwise wait out, and the row stays.
func TestConfirmSettled_CloseEndsTheWatch(t *testing.T) {
	shortConfirmWatch(t, time.Minute)
	f := newSettleFixture(t)
	c := settleClient()
	c.life, c.endLife = context.WithCancel(context.Background())
	j := newMemJournal()
	c.journal = j
	_ = j.Put(context.Background(), TicketRecord{TicketID: f.tkt.TicketID})
	_, _ = f.check(c, newSettleSlot(), &watchedSettleHandle{scriptedSettleHandle: scriptedSettleHandle{txid: "G"}}, true, testSettleGroup)()

	c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.WaitSettles(ctx); err != nil {
		t.Fatalf("the watch outlived Close: %v", err)
	}
	if _, has := j.recs[f.tkt.TicketID]; !has {
		t.Error("an unconfirmed settle lost its journal row")
	}
}

// Work may start from none while WaitSettles waits, as a stream's settle
// does; the drain neither panics nor reports idle while it runs.
func TestDrain(t *testing.T) {
	var d drain
	select {
	case <-d.done():
	default:
		t.Fatal("an empty drain is not done")
	}
	release := make(chan struct{})
	waited := make(chan struct{})
	go func() { <-d.done(); close(waited) }()
	d.Go(func() { <-release })
	select {
	case <-d.done():
		t.Fatal("done while work runs")
	default:
	}
	close(release)
	<-waited
	select {
	case <-d.done():
	case <-time.After(5 * time.Second):
		t.Fatal("not done once the work returned")
	}

	// Work started by running work, as a whole reply's submit starts its
	// settle's watch: a waiter that looked before the inner work began is
	// released once both are done.
	started, release := make(chan struct{}), make(chan struct{})
	d.Go(func() {
		<-started
		d.Go(func() { <-release })
	})
	w := d.done()
	close(started)
	close(release)
	select {
	case <-w:
	case <-time.After(5 * time.Second):
		t.Fatal("a waiter was not released after nested work finished")
	}
}

// A shutdown that cannot wait out a confirmation says the settle was
// submitted, not that it was abandoned.
func TestWaitSettles_NamesAConfirmationApart(t *testing.T) {
	shortConfirmWatch(t, time.Second)

	f := newSettleFixture(t)
	c := settleClient()
	c.journal = newMemJournal()
	h := &watchedSettleHandle{scriptedSettleHandle: scriptedSettleHandle{txid: "G"}}
	_, _ = f.check(c, newSettleSlot(), h, true, testSettleGroup)()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := c.WaitSettles(ctx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitSettles = %v, want a deadline", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "not yet seen to land, left journaled: "+f.tkt.TicketID) || strings.Contains(msg, "still settling") {
		t.Errorf("WaitSettles = %q, want the ticket named as a confirmation only", msg)
	}
	_ = c.WaitSettles(context.Background())
}
