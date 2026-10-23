/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/crypto"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/wire"
)

// What the ack's reading of the operator's claim does to the turn: a claim
// above the receipt bars the node, even when the node's group failed to submit,
// the freeze did, or none was sent for want of resolveFrozen, and the turn
// reports the freeze only when one went out; a claim that contradicts the
// receipt without taking more is not acked, and the turn reports no submit
// unless one failed; the payer's half on an open box after a failed group is
// the payer's own ack. None stops the refund watchdog.
func TestCheckReceipt_ActsOnTheOperatorClaim(t *testing.T) {
	ackErr := errors.New("algod down")
	for _, tc := range []struct {
		name          string
		handle        *scriptedSettleHandle
		group         string
		want          Settlement
		wantErr       error
		wantExclusion string
	}{
		{"claim above the receipt", &scriptedSettleHandle{txid: "ACKTX", fee: 1000, claim: ClaimOverclaims, payerSettle: true, frozen: true}, "",
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000, NetworkFees: 1000, Frozen: true}, nil, exclusionOverclaim},
		// The group's refusal came first, so it is the reason reported.
		{"rejected group, then a claim above the receipt", &scriptedSettleHandle{txid: "ACKTX", fee: 1000, groupRejected: true, claim: ClaimOverclaims, payerSettle: true, frozen: true}, testSettleGroup,
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000, NetworkFees: 1000, Frozen: true}, nil, exclusionSettleGroup},
		// The freeze is the payer's own settle, not the group, so it neither
		// reports atomic nor stops the watchdog.
		{"failed group, then a claim above the receipt", &scriptedSettleHandle{txid: "FREEZETX", fee: 1000, claim: ClaimOverclaims, payerSettle: true, frozen: true}, testSettleGroup,
			Settlement{Kind: SettlePayerAck, TxID: "FREEZETX", FeesMicroAlgos: 1000, NetworkFees: 1000, Frozen: true}, nil, exclusionOverclaim},
		{"claim above the receipt, freeze failed", &scriptedSettleHandle{claim: ClaimOverclaims, payerSettle: true, err: ackErr}, "",
			Settlement{Kind: SettlePayerAck}, ackErr, exclusionOverclaim},
		// Nothing went out on an escrow without resolveFrozen, but the claim is
		// still the node's own contradiction.
		{"claim above the receipt, no resolveFrozen", &scriptedSettleHandle{claim: ClaimOverclaims}, "", Settlement{}, nil, exclusionOverclaim},
		{"failed group, then a claim above the receipt, no resolveFrozen", &scriptedSettleHandle{claim: ClaimOverclaims, err: ackErr}, testSettleGroup,
			Settlement{Kind: SettleAtomic}, ackErr, exclusionOverclaim},
		{"claim contradicting the receipt", &scriptedSettleHandle{claim: ClaimContradicts}, "", Settlement{}, nil, ""},
		{"failed group, then a claim contradicting the receipt", &scriptedSettleHandle{claim: ClaimContradicts, err: ackErr}, testSettleGroup,
			Settlement{Kind: SettleAtomic}, ackErr, ""},
		{"claim agreeing with the receipt", &scriptedSettleHandle{txid: "ACKTX", fee: 1000, claim: ClaimAgrees, payerSettle: true}, "",
			Settlement{Kind: SettlePayerAck, TxID: "ACKTX", FeesMicroAlgos: 1000, NetworkFees: 1000}, nil, ""},
		// The payer's half leaves a pending payer claim the node must still
		// match, so the watchdog keeps the ticket for refundInactive.
		{"failed group, then the payer's half on an open box", &scriptedSettleHandle{txid: "HALFTX", fee: 1000, claim: ClaimOpen, payerSettle: true}, testSettleGroup,
			Settlement{Kind: SettlePayerAck, TxID: "HALFTX", FeesMicroAlgos: 1000, NetworkFees: 1000}, nil, ""},
		{"failed group, then a failed half on an open box", &scriptedSettleHandle{claim: ClaimOpen, payerSettle: true, err: ackErr}, testSettleGroup,
			Settlement{Kind: SettlePayerAck}, ackErr, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			source := &ChainOperatorSource{}
			c.nodeExcluder = source
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			ctx := withSettleSlot(context.Background(), newSettleSlot())
			submit, check := c.checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, tc.handle, f.receipt,
				wire.BodyHashOfBody(f.plaintext), f.plaintext, tc.group, nil)
			if submit == nil {
				t.Fatal("no submit")
			}
			r, err := submit()
			tc.want.TicketID = f.tkt.TicketID
			if !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) || r != tc.want {
				t.Errorf("submit = %+v, %v; want %+v, %v", r, err, tc.want, tc.wantErr)
			}
			if check.exclusion != tc.wantExclusion || check.excluded != (tc.wantExclusion != "") {
				t.Errorf("exclusion %q (excluded %v), want %q", check.exclusion, check.excluded, tc.wantExclusion)
			}
			if got := source.NodeExcluded(RefOf(f.op)); got != (tc.wantExclusion != "") {
				t.Errorf("node excluded = %v, want %v", got, tc.wantExclusion != "")
			}
			if !c.refunds.watching(f.tkt.TicketID) {
				t.Error("the watchdog stopped watching a ticket no settle finished")
			}
		})
	}
}

// A failed ack over an over-claim is logged as a failed freeze only when the
// payer's settle went out; when the node's group failed and nothing followed
// it, the log says no freeze was sent.
func TestCheckReceipt_LogsWhetherTheFreezeWentOut(t *testing.T) {
	ackErr := errors.New("algod down")
	for _, tc := range []struct {
		name    string
		handle  *scriptedSettleHandle
		want    string
		notWant string
	}{
		{"freeze failed", &scriptedSettleHandle{claim: ClaimOverclaims, payerSettle: true, err: ackErr},
			"the settle to freeze the ticket failed", "no freeze was sent"},
		{"nothing sent", &scriptedSettleHandle{claim: ClaimOverclaims, err: ackErr},
			"no freeze was sent", "the settle to freeze the ticket failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			var buf bytes.Buffer
			c.log = slog.New(slog.NewTextHandler(&buf, nil))
			c.nodeExcluder = &ChainOperatorSource{}
			ctx := withSettleSlot(context.Background(), newSettleSlot())
			submit, _ := c.checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, tc.handle, f.receipt,
				wire.BodyHashOfBody(f.plaintext), f.plaintext, testSettleGroup, nil)
			if submit == nil {
				t.Fatal("no submit")
			}
			if _, err := submit(); !errors.Is(err, ackErr) {
				t.Fatalf("submit err = %v, want %v", err, ackErr)
			}
			if got := buf.String(); !strings.Contains(got, tc.want) || strings.Contains(got, tc.notWant) {
				t.Errorf("log %q: want %q and not %q", got, tc.want, tc.notWant)
			}
		})
	}
}

// freezingHandle is a settlement handle whose protest is refused, with the
// protest's fallback scripted.
type freezingHandle struct {
	scriptedSettleHandle
	protestErr error
	claim      ClaimVerdict
	freezeErr  error
	freezes    int
	// A protest, or a freeze, that was sent and failed, as a Solana
	// transaction that lands and fails is: its id and the fee it paid.
	protestTx, failedFreezeTx   string
	protestFee, failedFreezeFee uint64
}

func (h *freezingHandle) Protest(context.Context, *ticket.UsageReceipt, []byte, escrow.ProtestReasonCode) (string, uint64, error) {
	return h.protestTx, h.protestFee, h.protestErr
}

func (h *freezingHandle) freezeOverclaim(context.Context, *ticket.UsageReceipt) (string, uint64, ClaimVerdict, error) {
	if h.claim != ClaimOverclaims {
		return "", 0, h.claim, nil
	}
	h.freezes++
	if h.freezeErr != nil {
		return h.failedFreezeTx, h.failedFreezeFee, h.claim, h.freezeErr
	}
	return "FREEZETX", 4000, h.claim, nil
}

// A protest that was sent and failed paid its fee, and so did a freeze after
// it, sent and failed or not: the turn's settlement reports the fee of every
// transaction the payer paid for, under the last one's id, as the ack path
// reports a failed settle's.
func TestCheckReceipt_ReportsWhatAFailedProtestPaid(t *testing.T) {
	late := fmt.Errorf("protest: %w", escrow.ErrProtestAfterDeadline)
	refused := errors.New("refused")
	freezeFailed := errors.New("freeze failed")
	paid := func(tx string, fee uint64, frozen bool) Settlement {
		return Settlement{Kind: SettleProtest, TxID: tx, FeesMicroAlgos: fee, NetworkFees: fee, Frozen: frozen}
	}
	for _, tc := range []struct {
		name    string
		h       freezingHandle
		want    Settlement
		wantErr error
	}{
		{"past the deadline", freezingHandle{protestErr: late, claim: ClaimOverclaims}, paid("PROTESTTX", 10000, false), late},
		{"refused, nothing to freeze", freezingHandle{protestErr: refused, claim: ClaimOpen}, paid("PROTESTTX", 10000, false), refused},
		{"refused, then frozen", freezingHandle{protestErr: refused, claim: ClaimOverclaims}, paid("FREEZETX", 14000, true), nil},
		{"refused, then a freeze sent and failed", freezingHandle{protestErr: refused, claim: ClaimOverclaims, freezeErr: freezeFailed,
			failedFreezeTx: "FAILEDFREEZE", failedFreezeFee: 5000}, paid("FAILEDFREEZE", 15000, false), freezeFailed},
		{"refused, then a freeze never sent", freezingHandle{protestErr: refused, claim: ClaimOverclaims, freezeErr: freezeFailed},
			paid("PROTESTTX", 10000, false), freezeFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			h := tc.h
			h.protestTx, h.protestFee = "PROTESTTX", 10000
			r, err := f.check(c, newSettleSlot(), &h, false, "")()
			tc.want.TicketID = f.tkt.TicketID
			if r != tc.want || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil) != (err == nil) {
				t.Errorf("submit = %+v, %v; want %+v, %v", r, err, tc.want, tc.wantErr)
			}
		})
	}
}

// A protest the contract refuses falls back to the receipt's settle only when
// the operator's claim takes more than the receipt, which freezes the ticket
// as the protest would have. Any other claim is left to lapse, and the
// protest's error stands.
func TestCheckReceipt_RefusedProtestFreezesAnOverclaim(t *testing.T) {
	refused := errors.New("receiptDigest must match the pending claim")
	freezeFailed := errors.New("algod down")
	for _, tc := range []struct {
		name      string
		claim     ClaimVerdict
		freezeErr error
		want      Settlement
		wantErr   error
		watched   bool
		excluded  bool
	}{
		{"claim above the receipt", ClaimOverclaims, nil,
			Settlement{Kind: SettleProtest, TxID: "FREEZETX", FeesMicroAlgos: 4000, NetworkFees: 4000, Frozen: true}, nil, false, true},
		{"claim above the receipt, freeze failed", ClaimOverclaims, freezeFailed, Settlement{Kind: SettleProtest}, freezeFailed, true, true},
		// No freeze went out, so the protest's own failure stands.
		{"claim above the receipt, no resolveFrozen", ClaimOverclaims, errNoResolveFrozen, Settlement{Kind: SettleProtest}, refused, true, true},
		{"claim below the receipt", ClaimContradicts, nil, Settlement{Kind: SettleProtest}, refused, true, false},
		{"claim matching the receipt", ClaimAgrees, nil, Settlement{Kind: SettleProtest}, refused, true, false},
		{"no operator claim", ClaimNone, nil, Settlement{Kind: SettleProtest}, refused, true, false},
		{"box unreadable", ClaimUnreadable, nil, Settlement{Kind: SettleProtest}, refused, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			c := settleClient()
			source := &ChainOperatorSource{}
			c.nodeExcluder = source
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			h := &freezingHandle{protestErr: refused, claim: tc.claim, freezeErr: tc.freezeErr}
			ctx := withSettleSlot(context.Background(), newSettleSlot())
			submit, check := c.checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, h, f.receipt,
				wire.BodyHashOfBody([]byte("other content")), f.plaintext, "", nil)
			if submit == nil {
				t.Fatal("no submit")
			}
			r, err := submit()
			tc.want.TicketID = f.tkt.TicketID
			if r != tc.want || !errors.Is(err, tc.wantErr) || (tc.wantErr == nil && err != nil) {
				t.Errorf("submit = %+v, %v; want %+v, %v", r, err, tc.want, tc.wantErr)
			}
			if got := c.refunds.watching(f.tkt.TicketID); got != tc.watched {
				t.Errorf("watching = %v, want %v", got, tc.watched)
			}
			if got := source.NodeExcluded(RefOf(f.op)); got != tc.excluded {
				t.Errorf("node excluded = %v, want %v", got, tc.excluded)
			}
			// Named, so the turn's events report the bar as the ack path's do.
			if wantReason := map[bool]string{true: exclusionOverclaim}[tc.excluded]; check.exclusion != wantReason || check.excluded != tc.excluded {
				t.Errorf("exclusion %q (excluded %v), want %q", check.exclusion, check.excluded, wantReason)
			}
		})
	}
}

// A protest that lands needs no fallback.
func TestCheckReceipt_LandedProtestReadsNoClaim(t *testing.T) {
	f := newSettleFixture(t)
	h := &freezingHandle{claim: ClaimOverclaims}
	submit := f.check(settleClient(), newSettleSlot(), h, false, "")
	if _, err := submit(); err != nil {
		t.Fatal(err)
	}
	if h.freezes != 0 {
		t.Errorf("%d freezes after a protest that landed, want 0", h.freezes)
	}
}

// A protest refused for its deadline gets no freeze, since the same deadline
// bars settle: the protest's error stands and the watchdog keeps the ticket.
func TestCheckReceipt_LateProtestTriesNoFreeze(t *testing.T) {
	f := newSettleFixture(t)
	c := settleClient()
	c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
	t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
	late := fmt.Errorf("protest: %w", escrow.ErrProtestAfterDeadline)
	h := &freezingHandle{protestErr: late, claim: ClaimOverclaims}
	r, err := f.check(c, newSettleSlot(), h, false, "")()
	if r.Kind != SettleProtest || r.TxID != "" || !errors.Is(err, late) {
		t.Errorf("submit = %+v, %v; want an unsubmitted protest and %v", r, err, late)
	}
	if h.freezes != 0 {
		t.Errorf("%d freezes after a protest refused for its deadline, want 0", h.freezes)
	}
	if !c.refunds.watching(f.tkt.TicketID) {
		t.Error("the watchdog stopped watching a ticket nothing froze")
	}
}

// forAnotherTicket hands the payer a receipt the node validly signed, for a
// ticket other than the one the payer opened.
func forAnotherTicket(f *settleFixture) { f.tkt.TicketID = "YW5vdGhlci10aWNrZXQhIQ==" }

// A receipt the node validly signed for another ticket bars the node, as an
// over-claim does, and the turn reports why. Only a signature that verified
// shows the node wrote it, and a ticket id the payer holds in another
// spelling is the payer's fault, so neither bars anyone. Barred or not, the
// receipt stays a sig violation: released, with no submit and nothing pinned.
func TestCheckReceipt_BarsANodeThatSignsAReceiptForAnotherTicket(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(f *settleFixture)
		matching bool
		barred   bool
	}{
		{"receipt for another ticket", forAnotherTicket, true, true},
		// The body_hash would have driven a protest.
		{"receipt for another ticket over a body that doesn't match it", forAnotherTicket, false, true},
		{"bad signature", func(f *settleFixture) { f.receipt.Sig = "" }, true, false},
		{"bad signature on a receipt for another ticket", func(f *settleFixture) { forAnotherTicket(f); f.receipt.Sig = "" }, true, false},
		{"signing key of the wrong length", func(f *settleFixture) { forAnotherTicket(f); f.op.TicketSigningKey = f.op.TicketSigningKey[:31] }, true, false},
		// The fixture's id with non-zero padding bits: the same bytes, which
		// the receipt names in their canonical spelling.
		{"payer's ticket id not canonical", func(f *settleFixture) { f.tkt.TicketID = "dGlja2V0LXdhaXQtMDAwMB==" }, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			tc.mutate(&f)
			c := settleClient()
			var logged bytes.Buffer
			c.log = slog.New(slog.NewTextHandler(&logged, nil))
			source := &ChainOperatorSource{}
			c.nodeExcluder = source
			guard := &outcomeGuard{}
			c.spend = guard
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			computed := wire.BodyHashOfBody(f.plaintext)
			if !tc.matching {
				computed = wire.BodyHashOfBody([]byte("other content"))
			}
			ctx := withSettleSlot(context.Background(), newSettleSlot())
			submit, check := c.checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, &scriptedSettleHandle{}, f.receipt,
				computed, f.plaintext, "", nil)

			if submit != nil {
				t.Error("a sig violation built a submit")
			}
			if got := source.NodeExcluded(RefOf(f.op)); got != tc.barred {
				t.Errorf("node excluded = %v, want %v", got, tc.barred)
			}
			wantEvents := []Event{ReceiptViolated{Violation: "sig"}}
			if tc.barred {
				wantEvents = append(wantEvents, NodeExcluded{Node: RefOf(f.op), Reason: "receipt_names_other_ticket"})
			}
			u := &usageReport{receipt: f.receipt, ticket: f.tkt, op: f.op, check: *check}
			if got := u.events(); !reflect.DeepEqual(got, wantEvents) {
				t.Errorf("events %+v, want %+v", got, wantEvents)
			}
			if got := strings.Contains(logged.String(), "node excluded: it signed a receipt for another ticket"); got != tc.barred {
				t.Errorf("logged the bar = %v, want %v", got, tc.barred)
			}
			if got, want := guard.seen(), []string{"release " + f.tkt.TicketID}; !slices.Equal(got, want) {
				t.Errorf("spend guard heard %v, want %v", got, want)
			}
			if _, ok := c.refunds.signedAmount(f.tkt.TicketID); ok {
				t.Error("pinned the figure of a receipt that failed its sig check")
			}
		})
	}
}

// Without a NodeExcluder there is nothing to bar the node in, and the turn
// reports no exclusion.
func TestCheckReceipt_ReceiptForAnotherTicketWithoutAnExcluder(t *testing.T) {
	f := newSettleFixture(t)
	forAnotherTicket(&f)
	ctx := withSettleSlot(context.Background(), newSettleSlot())
	_, check := settleClient().checkReceipt(ctx, endpointChatCompletions, "m", f.tkt, f.op, &scriptedSettleHandle{}, f.receipt,
		wire.BodyHashOfBody(f.plaintext), f.plaintext, "", nil)
	if check.violation != "sig" || check.excluded || check.exclusion != "" {
		t.Errorf("check %+v, want a sig violation and no exclusion", *check)
	}
}

// The watchdog holds a later operator claim against the amount the node
// signed. Only a receipt whose signature verified counts: a figure from an
// unverified one could be anything, and one set too high would let every
// over-claim through.
func TestCheckReceipt_PinsTheSignedAmountForTheWatchdog(t *testing.T) {
	for _, tc := range []struct {
		name     string
		mutate   func(f *settleFixture)
		matching bool
		want     bool
	}{
		{"verified", nil, true, true},
		{"body hash mismatch", nil, false, true},
		{"amount above max price", func(f *settleFixture) { f.tkt.MaxPrice = f.receipt.AmountCharged - 1 }, true, true},
		{"bad signature", func(f *settleFixture) { f.receipt.Sig = "" }, true, false},
		// Its figure is for that other ticket.
		{"receipt for another ticket", forAnotherTicket, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			c := settleClient()
			c.refunds.track(f.tkt.TicketID, time.Now().Add(time.Hour), nil, nil, nil)
			t.Cleanup(func() { c.refunds.Resolve(f.tkt.TicketID) })
			f.check(c, newSettleSlot(), &scriptedSettleHandle{}, tc.matching, "")
			got, ok := c.refunds.signedAmount(f.tkt.TicketID)
			if ok != tc.want || (ok && got != f.receipt.AmountCharged) {
				t.Errorf("pinned %d (%v), want %v at %d", got, ok, tc.want, f.receipt.AmountCharged)
			}
		})
	}
}

// The journal keeps the signed receipt too, so the reconciler, which outlives
// the watchdog's memory, holds an operator claim against the same figure: a
// verified receipt as the settle to re-fire, one that failed a check after its
// signature verified as Signed on the open row, an unverified one not at all.
func TestCheckReceipt_JournalsTheSignedReceipt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mutate     func(f *settleFixture)
		matching   bool
		wantStatus TicketStatus
		wantSettle bool
		wantSigned bool
	}{
		{"verified", nil, true, TicketSettlePending, true, false},
		{"body hash mismatch", nil, false, TicketOpen, false, true},
		{"amount above max price", func(f *settleFixture) { f.tkt.MaxPrice = f.receipt.AmountCharged - 1 }, true, TicketOpen, false, true},
		{"bad signature", func(f *settleFixture) { f.receipt.Sig = "" }, true, "", false, false},
		{"receipt for another ticket", forAnotherTicket, false, "", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			if tc.mutate != nil {
				tc.mutate(&f)
			}
			c := settleClient()
			j := newMemJournal()
			c.journal = j
			h := &OpenHandle{TicketID: f.tkt.TicketID, journaled: TicketRecord{TicketID: f.tkt.TicketID, Status: TicketOpen}}
			f.check(c, newSettleSlot(), h, tc.matching, "")
			rec, ok := j.recs[f.tkt.TicketID]
			if tc.wantStatus == "" {
				if ok {
					t.Errorf("journaled %+v for a receipt whose signature failed", rec)
				}
				return
			}
			want := settleArgsOf(f.receipt)
			if rec.Status != tc.wantStatus || (rec.Settle != nil) != tc.wantSettle || (rec.Signed != nil) != tc.wantSigned ||
				(rec.Settle != nil && *rec.Settle != want) || (rec.Signed != nil && *rec.Signed != want) {
				t.Errorf("journaled %+v; want status %s, settle %v, signed %v at %+v", rec, tc.wantStatus, tc.wantSettle, tc.wantSigned, want)
			}
		})
	}
}

// An untracked ticket pins nothing: no driver would read or delete the entry.
func TestRefundWatchdog_RecordReceiptNeedsATrackedTicket(t *testing.T) {
	rw := NewRefundWatchdog(slog.New(slog.NewTextHandler(io.Discard, nil)))
	rw.recordReceipt("T", NodeRef{}, 5)
	if _, ok := rw.signedAmount("T"); ok {
		t.Error("an untracked ticket's receipt was pinned")
	}
	var nilWatchdog *RefundWatchdog
	nilWatchdog.recordReceipt("T", NodeRef{}, 5)
}

// The claim the watchdog refuses to lapse bars the node that signed the
// receipt, which the live ack may never have read.
func TestRefundWatchdog_BarsTheNodeOfAnOverclaim(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim uint64
		want  bool
	}{
		{"claim above the receipt", 101, true},
		{"claim equal to the receipt", 100, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := testWatchdog()
			var barred atomic.Value
			rw.overclaimed = func(ticketID string, node NodeRef) { barred.Store(node) }
			rw.track("T", time.Now().Add(20*time.Millisecond),
				func(context.Context) (ticketProbe, error) {
					return ticketProbe{exists: true, verdict: escrow.VerdictLapse, deadline: time.Now().Add(-time.Minute), pendingAmount: tc.claim}, nil
				},
				func(context.Context) (string, error) { return "", nil },
				func(context.Context) (string, error) { return "TX", nil },
			)
			node := NodeRef{Op: 3, Node: 4}
			rw.recordReceipt("T", node, 100)
			waitFor(t, "the ticket's driver to finish", func() bool { return !rw.watching("T") })
			got, _ := barred.Load().(NodeRef)
			if (got == node) != tc.want {
				t.Errorf("barred %+v, want barred %v", got, tc.want)
			}
		})
	}
}

// A box that can't be read past the deadline is not lapsed blind while the
// watchdog holds a receipt: the claim on it could be above the receipt, and
// settleLapsed would pay it in full. With no receipt to hold it against, the
// lapse goes ahead as before.
func TestRefundWatchdog_LapsesNoUnreadBoxAgainstAReceipt(t *testing.T) {
	for _, tc := range []struct {
		name      string
		receipt   bool
		wantLapse bool
	}{
		{"receipt recorded", true, false},
		{"no receipt", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := testWatchdog()
			var probes, lapses atomic.Int32
			rw.track("T", time.Now().Add(20*time.Millisecond),
				func(context.Context) (ticketProbe, error) {
					// The first read finds the operator claim; every one after
					// it, inside driveLapse, fails.
					if probes.Add(1) == 1 {
						return ticketProbe{exists: true, verdict: escrow.VerdictLapse, deadline: time.Now().Add(-time.Minute), pendingAmount: 50}, nil
					}
					return ticketProbe{}, errors.New("algod down")
				},
				func(context.Context) (string, error) { t.Error("refundInactive on an operator claim"); return "", nil },
				func(context.Context) (string, error) { lapses.Add(1); return "TX", nil },
			)
			if tc.receipt {
				rw.recordReceipt("T", NodeRef{}, 100)
			}
			waitFor(t, "the ticket's driver to finish", func() bool { return !rw.watching("T") })
			if got := lapses.Load() > 0; got != tc.wantLapse {
				t.Errorf("lapsed %v, want %v", got, tc.wantLapse)
			}
			if tc.receipt && probes.Load() < 1+int32(rw.attempts) {
				t.Errorf("%d reads, want the box re-read on each of %d attempts", probes.Load(), rw.attempts)
			}
		})
	}
}

// The payer never pays the fee for a settleLapsed its receipt contradicts. A
// claim at or below the receipt still lapses, and so does any claim on a
// ticket this process saw no receipt for.
func TestRefundWatchdog_RefusesToLapseAnOverclaim(t *testing.T) {
	for _, tc := range []struct {
		name      string
		receipt   *uint64
		claim     uint64
		wantLapse bool
	}{
		{"claim above the receipt", new(uint64(100)), 101, false},
		{"claim equal to the receipt", new(uint64(100)), 100, true},
		{"claim below the receipt", new(uint64(100)), 99, true},
		{"no receipt seen", nil, 101, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rw := testWatchdog()
			var lapses atomic.Int32
			// Armed far enough out that the receipt is pinned before it fires.
			rw.track("T", time.Now().Add(20*time.Millisecond),
				func(context.Context) (ticketProbe, error) {
					return ticketProbe{exists: true, verdict: escrow.VerdictLapse, deadline: time.Now().Add(-time.Minute), pendingAmount: tc.claim}, nil
				},
				func(context.Context) (string, error) { t.Error("refundInactive on an operator claim"); return "", nil },
				func(context.Context) (string, error) { lapses.Add(1); return "TX", nil },
			)
			if tc.receipt != nil {
				rw.recordReceipt("T", NodeRef{}, *tc.receipt)
			}
			waitFor(t, "the ticket's driver to finish", func() bool { return !rw.watching("T") })
			if got := lapses.Load() == 1; got != tc.wantLapse {
				t.Errorf("lapsed %v, want %v", got, tc.wantLapse)
			}
			if _, ok := rw.signedAmount("T"); ok {
				t.Error("the pinned receipt outlived the ticket's driver")
			}
		})
	}
}

// lapseChain is an ackChain that also records each settleLapsed.
type lapseChain struct {
	ackChain
	lapses atomic.Int32
}

func (c *lapseChain) ComposeSettleLapsed(context.Context, escrow.SettleLapsedArgs, transaction.TransactionSigner, string) (escrow.CallResult, error) {
	c.lapses.Add(1)
	return escrow.CallResult{TxID: "LAPSETX"}, nil
}

// Track's own probe reads the claimed amount off the box, so a real handle's
// watchdog holds an operator claim against the receipt the same way the
// scripted probes do: above it, no settleLapsed and the node barred; at it,
// the stalled claim is lapsed.
func TestRefundWatchdog_TrackReadsTheClaimedAmount(t *testing.T) {
	for _, tc := range []struct {
		name      string
		claim     uint64
		wantLapse bool
	}{
		{"claim above the receipt", 101, false},
		{"claim at the receipt", 100, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			past := uint64(time.Now().Add(-time.Minute).Unix())
			chain := &lapseChain{ackChain: ackChain{box: &escrow.TicketRecord{
				Status: escrow.StatusPendingSettle, PendingBy: escrow.PendingByOperator, PendingAmount: tc.claim, ExpiresAt: past,
			}}}
			h := ackHandle(t, &chain.ackChain, nil)
			h.wallet.chain = chain
			rw := testWatchdog()
			var barred atomic.Int32
			rw.overclaimed = func(string, NodeRef) { barred.Add(1) }
			// Track takes whole seconds, so +2 fires at least a second out,
			// after the receipt is pinned.
			rw.Track(h, time.Now().Unix()+2)
			rw.recordReceipt(h.TicketID, RefOf(h.Operator), 100)
			// waitFor's 2s is shorter than the arming above.
			for end := time.Now().Add(5 * time.Second); rw.watching(h.TicketID); time.Sleep(5 * time.Millisecond) {
				if time.Now().After(end) {
					t.Fatal("timed out waiting for the ticket's driver to finish")
				}
			}
			if got := chain.lapses.Load() == 1; got != tc.wantLapse {
				t.Errorf("lapsed %v, want %v", got, tc.wantLapse)
			}
			if got := barred.Load() == 1; got == tc.wantLapse {
				t.Errorf("node barred %v, want %v", got, !tc.wantLapse)
			}
		})
	}
}

// ackChain is an EscrowChain for one ack: it completes the node's group, reads
// box, and records each standalone settle. A read or a settle on a context
// already done fails, as algod's would.
type ackChain struct {
	EscrowChain
	box             *escrow.TicketRecord
	noResolveFrozen bool
	reads           atomic.Int32
	sent            []escrow.SettleArgs
}

func (c *ackChain) Config() EscrowChainConfig {
	return EscrowChainConfig{AppID: 1, ResolvesFrozen: !c.noResolveFrozen}
}

func (c *ackChain) CompletePresignedSettleGroup([]types.SignedTxn, transaction.TransactionSigner, escrow.SettleGroupSpec) (escrow.CallResult, string, error) {
	return escrow.CallResult{TxID: "GROUPTX"}, testSettleGroup, nil
}

func (c *ackChain) ReadTicketBox(ctx context.Context, _ []byte) (*escrow.TicketRecord, error) {
	c.reads.Add(1)
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.box, nil
}

func (c *ackChain) ComposeSettleStandalone(ctx context.Context, args escrow.SettleArgs, _ transaction.TransactionSigner, _ string) (escrow.CallResult, error) {
	if err := ctx.Err(); err != nil {
		return escrow.CallResult{}, err
	}
	c.sent = append(c.sent, args)
	return escrow.CallResult{TxID: "HALFTX", PayerFeeMicroalgos: 1000}, nil
}

// ackHandle is an OpenHandle on chain whose node takes the ack by deliver.
func ackHandle(t *testing.T, chain *ackChain, deliver func(context.Context, wire.SettleAck) error) *OpenHandle {
	t.Helper()
	w := &Wallet{chain: chain, payerAddr: crypto.GenerateAccount().Address.String(), log: slog.New(slog.DiscardHandler)}
	op := Operator{ID: 3, NodeID: 4, SigningAddr: crypto.GenerateAccount().Address.String(), OwnerAddr: crypto.GenerateAccount().Address.String()}
	return &OpenHandle{TicketID: "NkImzFiSJz3WK6cx7PFU1Q==", Operator: op, MaxPrice: 99, wallet: w, deliverAck: deliver}
}

// An ack delivery the node holds open spends the whole of the ack's context.
// The box read after it, and the payer's half on the open box it finds, run on
// a budget of their own, so the half still goes out at the receipt's values
// for the outer call's fee. A caller that cancels outright stops them too.
func TestOpenHandle_AckAfterAStalledDeliveryStillPostsTheHalf(t *testing.T) {
	r := &ticket.UsageReceipt{AmountCharged: 11, TtftMs: 2}
	held := func(ctx context.Context, _ wire.SettleAck) error { <-ctx.Done(); return ctx.Err() }

	t.Run("deadline spent", func(t *testing.T) {
		chain := &ackChain{box: &escrow.TicketRecord{Status: escrow.StatusOpen}}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
		defer cancel()
		ack, err := ackHandle(t, chain, held).AckSettle(ctx, r, testSettleGroup)
		if err != nil {
			t.Fatalf("AckSettle: %v", err)
		}
		if ack.Claim != ClaimOpen || !ack.PayerSettle || ack.Frozen || ack.TxID != "HALFTX" || ack.FeeMicroalgos != 1000 {
			t.Errorf("ack %+v, want the payer's half on an open box", ack)
		}
		if len(chain.sent) != 1 || !chain.sent[0].OuterFeeOnly || chain.sent[0].AsOperator || chain.sent[0].AmountCharged != 11 || chain.sent[0].TtftMs != 2 {
			t.Errorf("settles sent %+v, want one payer half at the receipt paying the outer call alone", chain.sent)
		}
	})

	t.Run("caller cancelled", func(t *testing.T) {
		chain := &ackChain{box: &escrow.TicketRecord{Status: escrow.StatusOpen}}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { time.Sleep(20 * time.Millisecond); cancel() }()
		ack, err := ackHandle(t, chain, held).AckSettle(ctx, r, testSettleGroup)
		if err == nil || len(chain.sent) != 0 || ack.Claim != ClaimUnreadable {
			t.Errorf("ack %+v, err %v, sent %+v; want the read cut off with the caller", ack, err, chain.sent)
		}
	})
}

// The protest's fallback on a real handle: a claim above the receipt gets the
// payer's settle at the receipt's values, paying for the outer call alone,
// since the freeze branch fires no inner transaction.
func TestOpenHandle_FreezeOverclaimSettlesAtTheReceiptForOneFee(t *testing.T) {
	r := &ticket.UsageReceipt{AmountCharged: 11, TtftMs: 2}
	chain := &ackChain{box: &escrow.TicketRecord{Status: escrow.StatusPendingSettle, PendingBy: escrow.PendingByOperator, PendingAmount: 12}}
	txid, fee, claim, err := ackHandle(t, chain, nil).freezeOverclaim(context.Background(), r)
	if err != nil || claim != ClaimOverclaims || txid != "HALFTX" || fee != 1000 {
		t.Fatalf("freezeOverclaim = %q, %d, %s, %v; want the freeze sent", txid, fee, claim, err)
	}
	if len(chain.sent) != 1 || !chain.sent[0].OuterFeeOnly || chain.sent[0].AsOperator || chain.sent[0].AmountCharged != 11 || chain.sent[0].TtftMs != 2 {
		t.Errorf("settles sent %+v, want one payer settle at the receipt paying the outer call alone", chain.sent)
	}
}

// On an escrow without resolveFrozen the ack sends neither the half on an open
// box after a failed group nor a freeze of a claim above the receipt. The
// claim is still read and reported.
func TestOpenHandle_AckSendsNoFreezeWithoutResolveFrozen(t *testing.T) {
	r := &ticket.UsageReceipt{AmountCharged: 11}
	failed := func(context.Context, wire.SettleAck) error { return errors.New("node answered 503") }
	over := &escrow.TicketRecord{Status: escrow.StatusPendingSettle, PendingBy: escrow.PendingByOperator, PendingAmount: 12}
	for _, tc := range []struct {
		name    string
		box     *escrow.TicketRecord
		group   string
		want    ClaimVerdict
		wantErr bool
	}{
		{"failed group over an open box", &escrow.TicketRecord{Status: escrow.StatusOpen}, testSettleGroup, ClaimOpen, true},
		{"failed group over a claim above the receipt", over, testSettleGroup, ClaimOverclaims, true},
		{"no group, a claim above the receipt", over, "", ClaimOverclaims, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			chain := &ackChain{box: tc.box, noResolveFrozen: true}
			ack, err := ackHandle(t, chain, failed).AckSettle(context.Background(), r, tc.group)
			if (err != nil) != tc.wantErr || ack.Claim != tc.want || ack.PayerSettle || len(chain.sent) != 0 {
				t.Errorf("ack %+v, err %v, sent %+v; want claim %s read and nothing sent", ack, err, chain.sent, tc.want)
			}
		})
	}
	// The protest's fallback reads the claim and reports it, but sends no
	// freeze either.
	chain := &ackChain{box: over, noResolveFrozen: true}
	_, _, claim, err := ackHandle(t, chain, nil).freezeOverclaim(context.Background(), r)
	if claim != ClaimOverclaims || !errors.Is(err, errNoResolveFrozen) || len(chain.sent) != 0 {
		t.Errorf("freezeOverclaim: claim %s, err %v, sent %+v; want the over-claim reported and no freeze", claim, err, chain.sent)
	}
}
