/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

var solanaJournalDeployment = Deployment{Rail: ticket.RailSolana, Network: "custom"}

// solanaReconciler sweeps the fixture's wallet's journal rows, on the wall
// clock the ticket account's deadlines are set against.
func (f *solanaAckFixture) reconciler(j TicketJournal, spend SpendGuard) *reconciler {
	return newReconciler(j, solanaChain{f.wallet}, f.wallet.PayerAddr(), solanaJournalDeployment, func(string) bool { return false }, spend, discardLogger())
}

// row is the fixture ticket's journal row.
func (f *solanaAckFixture) row(status TicketStatus, settle *SettleArgs) TicketRecord {
	return TicketRecord{
		TicketID: base64.StdEncoding.EncodeToString(f.ticketID[:]), Deployment: solanaJournalDeployment.Key(),
		Target: NodeRef{Op: f.operatorID, Node: f.nodeID}, Payer: f.wallet.PayerAddr(),
		ExpiresAt: time.Now().Add(-time.Hour), Status: status, Settle: settle, UpdatedAt: time.Now().Add(-time.Hour),
	}
}

// sentMessage is the message of the only transaction the fixture's cluster
// was sent.
func (f *solanaAckFixture) sentMessage(t *testing.T) []byte {
	t.Helper()
	if len(f.cluster.acks) != 1 {
		t.Fatalf("%d sent, want 1", len(f.cluster.acks))
	}
	m, err := f.cluster.acks[0].Message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// endingMessage is the payer's ending ix on tk, as the builders make it.
func (f *solanaAckFixture) endingMessage(t *testing.T, tk *zsescrow.Ticket, ix func(zsescrow.Deployment, zsescrow.Ending) solana.Instruction) []byte {
	t.Helper()
	e := zsescrow.Ending{Submitter: f.wallet.payer, OperatorID: f.operatorID, NodeID: f.nodeID, TicketID: f.ticketID,
		RentPayer: tk.RentPayer, Payer: f.wallet.payer}
	m, err := solana.Compile(f.wallet.payer, f.cluster.blockhash, []solana.Instruction{ix(f.cluster.d, e)}, solana.Legacy)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := m.MarshalBinary()
	return b
}

// The reconciler finishes a journaled Solana ticket as it does an Algorand
// one, reading the ticket account where Algorand reads the box: it refunds an
// open ticket past its deadline, lapses a node's claim the node left, re-fires
// the payer's ack against a claim at the receipt, freezes one above it with
// the receipt's ack, and forgets a ticket frozen or gone. It tells the spend
// guard how each refund and lapse ended, and bars a node whose claim is above
// the receipt, inside the window or past it.
func TestReconciler_SweepsASolanaTicket(t *testing.T) {
	over := func(fl *zsescrow.ClaimFields) { fl.Amount++ }
	for _, c := range []struct {
		name string
		// gone is no ticket account; status, claim and edit are its state
		// otherwise, its deadline deadlineIn from now.
		gone       bool
		status     zsescrow.TicketStatus
		edit       func(*zsescrow.ClaimFields)
		deadlineIn time.Duration
		rec        TicketStatus
		receipt    bool
		// ending is the ending sent; ack is the payer's ack at the receipt.
		ending func(zsescrow.Deployment, zsescrow.Ending) solana.Instruction
		ack    bool
		kept   bool
		// spend is what the guard hears: release, settle at the claim, or
		// nothing.
		spend string
		// barred is the node barred for a claim above the receipt.
		barred bool
	}{
		{name: "open past its deadline", status: zsescrow.TicketOpen, deadlineIn: -time.Hour, rec: TicketOpen,
			ending: zsescrow.Deployment.RefundInactive, kept: true, spend: "release"},
		{name: "a node's claim left to lapse", status: zsescrow.TicketPendingByOperator, deadlineIn: -time.Hour, rec: TicketOpen,
			ending: zsescrow.Deployment.SettleLapsed, kept: true, spend: "settle"},
		{name: "a node's claim left to lapse, with a receipt", status: zsescrow.TicketPendingByOperator, deadlineIn: -time.Hour, rec: TicketSettlePending, receipt: true,
			ending: zsescrow.Deployment.SettleLapsed, kept: true, spend: "release"},
		{name: "a node's claim at the receipt", status: zsescrow.TicketPendingByOperator, deadlineIn: time.Hour, rec: TicketSettlePending, receipt: true,
			ack: true, kept: true},
		{name: "an open ticket with a receipt", status: zsescrow.TicketOpen, deadlineIn: time.Hour, rec: TicketSettlePending, receipt: true,
			ack: true, kept: true},
		{name: "a node's claim above the receipt", status: zsescrow.TicketPendingByOperator, edit: over, deadlineIn: time.Hour, rec: TicketSettlePending, receipt: true,
			ack: true, kept: true, barred: true},
		{name: "a node's claim above the receipt past the window", status: zsescrow.TicketPendingByOperator, edit: over, deadlineIn: -time.Hour, rec: TicketSettlePending, receipt: true,
			kept: true, barred: true},
		{name: "frozen", status: zsescrow.TicketFrozen, deadlineIn: time.Hour, rec: TicketSettlePending, receipt: true},
		{name: "gone", gone: true, rec: TicketSettlePending, receipt: true, spend: "release"},
		{name: "gone without a receipt", gone: true, rec: TicketOpen},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			var tk *zsescrow.Ticket
			if c.gone {
				f.cluster.accounts[f.ticketAddr] = nil
			} else {
				amount := f.args.AmountCharged
				if c.status == zsescrow.TicketOpen {
					amount = 0
				}
				f.setTicket(t, c.status, amount, c.edit)
				f.setTicketDeadline(t, time.Now().Add(c.deadlineIn))
				tk = f.ticket(t)
			}
			rec := f.row(c.rec, nil)
			if c.receipt {
				a := f.args
				rec.Settle = &a
			}
			j := newMemJournal()
			if err := j.Put(t.Context(), rec); err != nil {
				t.Fatal(err)
			}
			g := &outcomeGuard{}
			r := f.reconciler(j, g)
			var barred []NodeRef
			r.overclaimed = func(rec TicketRecord) { barred = append(barred, rec.Target) }
			r.sweep()

			switch {
			case c.ending != nil:
				if !bytes.Equal(f.sentMessage(t), f.endingMessage(t, tk, c.ending)) {
					t.Fatal("the reconciler sent another ending")
				}
			case c.ack:
				if len(f.cluster.acks) != 1 {
					t.Fatalf("%d sent, want the payer's ack at the receipt", len(f.cluster.acks))
				}
				if got, _ := f.cluster.acks[0].MarshalBinary(); !bytes.Equal(got, f.wire) {
					t.Fatal("the reconciler sent another ack than the payer's at the receipt")
				}
			default:
				if len(f.cluster.acks) != 0 {
					t.Fatalf("%d sent, want none", len(f.cluster.acks))
				}
			}
			recs, err := j.List(t.Context(), f.wallet.PayerAddr(), solanaJournalDeployment)
			if err != nil {
				t.Fatal(err)
			}
			if kept := len(recs) == 1; kept != c.kept {
				t.Errorf("row kept %v, want %v", kept, c.kept)
			}
			var want []string
			switch c.spend {
			case "release":
				want = []string{"release " + rec.TicketID}
			case "settle":
				want = []string{fmt.Sprintf("settle %s %d", rec.TicketID, f.args.AmountCharged)}
			}
			if got := g.seen(); !slices.Equal(got, want) {
				t.Errorf("spend guard heard %q, want %q", got, want)
			}
			var wantBarred []NodeRef
			if c.barred {
				wantBarred = []NodeRef{rec.Target}
			}
			if !slices.Equal(barred, wantBarred) {
				t.Errorf("barred %v, want %v", barred, wantBarred)
			}
		})
	}
}

// A node's $0 claim is accepted with the payer's ack at the claim's own
// fields, not the receipt's: the program settles at once only on a match, and
// the row's receipt here differs from the claim in more than the amount.
func TestReconciler_AcceptsASolanaZeroClaim(t *testing.T) {
	ttft := func(fl *zsescrow.ClaimFields) { fl.TTFTMs += 5 }
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketPendingByOperator, 0, ttft)
	f.setTicketDeadline(t, time.Now().Add(time.Hour))
	a := f.args
	rec := f.row(TicketSettlePending, &a)
	j := newMemJournal()
	if err := j.Put(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	g := &outcomeGuard{}
	f.reconciler(j, g).sweep()
	if len(f.cluster.acks) != 1 {
		t.Fatalf("%d sent, want the payer's ack at the claim", len(f.cluster.acks))
	}
	got, _ := f.cluster.acks[0].MarshalBinary()

	// The same ack built by hand, from the claim's fields as the program
	// stores them.
	want := newSolanaAckFixture(t)
	want.setTicket(t, zsescrow.TicketPendingByOperator, 0, ttft)
	want.setTicketDeadline(t, time.Now().Add(time.Hour))
	claim := f.args
	claim.AmountCharged, claim.TtftMs = 0, f.args.TtftMs+5
	if _, err := want.wallet.sendAck(t.Context(), want.ticket(t), want.operatorID, want.nodeID, want.ticketID, claim); err != nil {
		t.Fatal(err)
	}
	if w, _ := want.cluster.acks[0].MarshalBinary(); !bytes.Equal(got, w) {
		t.Fatal("the reconciler's ack is not the payer's at the claim's own fields")
	}
	if seen := g.seen(); !slices.Equal(seen, []string{"release " + rec.TicketID}) {
		t.Errorf("spend guard heard %q, want the reservation released", seen)
	}
}

// The Solana accept refuses a claim above $0 before anything is sent, as the
// box path's does, so a caller other than decideSettlement can't echo a paid
// claim the payer holds no receipt for.
func TestSolanaChain_AcceptRefusesAPaidClaim(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketPendingByOperator, 1, nil)
	rec := f.row(TicketSettlePending, nil)
	if _, err := (solanaChain{f.wallet}).accept(t.Context(), rec, sweptSolana(f.ticket(t))); err == nil {
		t.Error("accept of a 1-microUSDC claim succeeded")
	}
	if len(f.cluster.acks) != 0 {
		t.Errorf("%d acks sent for a paid claim", len(f.cluster.acks))
	}
}

// A Solana submit waits for its confirmation, which can outlast the sweep's
// callTimeout. It is waited for, so a refund that lands late frees its
// reservation that sweep, rather than read as a ticket gone on the next.
func TestReconciler_WaitsForASolanaSubmitToConfirm(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketOpen, 0, nil)
	f.setTicketDeadline(t, time.Now().Add(-time.Hour))
	f.wallet.rpc = &walletClusterSlowConfirm{walletCluster: f.cluster, landAt: time.Now().Add(150 * time.Millisecond)}
	rec := f.row(TicketOpen, nil)
	j := newMemJournal()
	if err := j.Put(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	g := &outcomeGuard{}
	r := f.reconciler(j, g)
	r.callTimeout = 20 * time.Millisecond
	r.sweep()
	if got := g.seen(); len(f.cluster.acks) != 1 || !slices.Equal(got, []string{"release " + rec.TicketID}) {
		t.Fatalf("%d sent, spend guard heard %q", len(f.cluster.acks), got)
	}
	if solanaChain.submitTimeout(solanaChain{}) != solanaEndingTimeout || (boxChain{}).submitTimeout() != 0 {
		t.Error("a Solana submit's budget is not the watchdog's, or an Algorand one's is not the call timeout")
	}
}

// The reconciler reads the ticket at the row's node, operator id then node
// id, as the open put it there.
func TestReconciler_ReadsTheSolanaTicketAtItsNode(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketOpen, 0, nil)
	f.setTicketDeadline(t, time.Now().Add(-time.Hour))
	const opID, nodeID = 7, 9
	d := f.cluster.d
	f.cluster.accounts[d.Ticket(d.Node(opID, nodeID), f.ticketID)] = f.cluster.accounts[f.ticketAddr]
	f.cluster.accounts[f.ticketAddr] = nil
	rec := f.row(TicketOpen, nil)
	rec.Target = NodeRef{Op: opID, Node: nodeID}
	j := newMemJournal()
	if err := j.Put(t.Context(), rec); err != nil {
		t.Fatal(err)
	}
	f.reconciler(j, nil).sweep()
	if len(f.cluster.acks) != 1 {
		t.Fatalf("%d sent, want the refund", len(f.cluster.acks))
	}
}

// A ticket the sweep cannot read is no ticket gone: a failed read, or a row
// whose ticket id does not decode, keeps the row past its expiry, with nothing
// sent or released, for the next sweep to retry.
func TestReconciler_KeepsASolanaRowItCannotRead(t *testing.T) {
	for _, c := range []struct {
		name string
		bad  func(f *solanaAckFixture, rec *TicketRecord)
	}{
		{"a failed read", func(f *solanaAckFixture, _ *TicketRecord) {
			c := &walletClusterFailingRead{walletCluster: f.cluster, ticket: f.ticketAddr}
			c.fail.Store(1 << 20)
			f.wallet.rpc = c
		}},
		{"an undecodable ticket id", func(_ *solanaAckFixture, rec *TicketRecord) { rec.TicketID = "not a ticket id" }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			rec := f.row(TicketSettlePending, &f.args)
			c.bad(f, &rec)
			j := newMemJournal()
			if err := j.Put(t.Context(), rec); err != nil {
				t.Fatal(err)
			}
			g := &outcomeGuard{}
			f.reconciler(j, g).sweep()
			recs, err := j.List(t.Context(), f.wallet.PayerAddr(), solanaJournalDeployment)
			if err != nil {
				t.Fatal(err)
			}
			if len(recs) != 1 || len(f.cluster.acks) != 0 || len(g.seen()) != 0 {
				t.Fatalf("%d rows kept, %d sent, spend guard heard %q; want the row kept and nothing else", len(recs), len(f.cluster.acks), g.seen())
			}
		})
	}
}

// A re-settle, freeze or accept that fails says which, over the cause.
func TestSolanaChain_WrapsAFailedAck(t *testing.T) {
	f := newSolanaAckFixture(t)
	rec := f.row(TicketSettlePending, &f.args)
	ch := solanaChain{f.wallet}
	for what, call := range map[string]func() (string, error){
		"wallet: re-settle: ": func() (string, error) { return ch.resettle(t.Context(), rec, nil) },
		"wallet: freeze: ":    func() (string, error) { return ch.freeze(t.Context(), rec, nil, f.args) },
	} {
		if _, err := call(); err == nil || !strings.HasPrefix(err.Error(), what) || !strings.Contains(err.Error(), "no ticket account") {
			t.Errorf("err %v, want %q over the wallet's refusal", err, what)
		}
	}
	// An accept always has a ticket read; another payer's is refused.
	if _, err := ch.accept(t.Context(), rec, solanaSweptTicket{&zsescrow.Ticket{}}); err == nil ||
		!strings.HasPrefix(err.Error(), "wallet: accept claim: ") || !strings.Contains(err.Error(), "not this wallet's") {
		t.Errorf("accept err %v, want it wrapped over the wallet's refusal", err)
	}
}

// A closed account is no swept ticket at all, not a typed nil the sweep would
// read as frozen and forget.
func TestSweptTicketOfNoneIsNil(t *testing.T) {
	if sweptBox(nil) != nil || sweptSolana(nil) != nil {
		t.Error("no box or account wraps as a non-nil sweptTicket")
	}
}

// A Solana wallet gets a reconciler over the default journal, as the SDK's
// Algorand wallet does, and a second such Client on one journal is refused.
func TestNew_ASolanaWalletRunsAReconciler(t *testing.T) {
	f := newSolanaAckFixture(t)
	cfg := suppliedParts(t)
	cfg.Wallet = f.wallet
	c, err := New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	r := c.reconcile
	if r == nil || c.journal == nil || r.journal != c.journal || r.payer != f.wallet.PayerAddr() {
		t.Fatalf("reconciler %+v over journal %v, want one over the client's journal for the wallet's payer", r, c.journal)
	}
	if sc, ok := r.chain.(solanaChain); !ok || sc.w != f.wallet {
		t.Errorf("reconciler chain %#v, want the Solana wallet's", r.chain)
	}

	shared := suppliedParts(t)
	shared.Wallet = f.wallet
	shared.Stores.Journal = newMemJournal()
	first, err := New(context.Background(), shared)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := New(context.Background(), shared); err == nil || !strings.Contains(err.Error(), "Stores.Journal") {
		if second != nil {
			second.Close()
		}
		t.Fatalf("second Solana Client on one journal: err %v, want the journal named", err)
	}
}
