/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/wire"
)

// walletClusterTicketScript answers each read of the ticket account by the
// next step of script, repeating its last: 'o' the fixture's account, 'p' it
// with another payer, '-' no account, 'x' a failed read. The n-th read (from
// 1) is as of slot 10+n, or by slots, its last repeating, when set. It is the
// slot-aware RPC the watch needs, and keeps the minContextSlot each read sent.
type walletClusterTicketScript struct {
	*walletCluster
	ticket solana.PublicKey
	script string
	slots  []uint64
	other  *rpc.Account
	reads  atomic.Int32
	mu     sync.Mutex
	mins   []uint64
	cms    []rpc.Commitment
}

var _ rpc.AccountAtReader = (*walletClusterTicketScript)(nil)

func (c *walletClusterTicketScript) GetAccountInfo(ctx context.Context, k solana.PublicKey, cm rpc.Commitment) (*rpc.Account, error) {
	a, _, err := c.GetAccountInfoAt(ctx, k, cm, 0)
	return a, err
}

func (c *walletClusterTicketScript) GetAccountInfoAt(ctx context.Context, k solana.PublicKey, cm rpc.Commitment, minContextSlot uint64) (*rpc.Account, uint64, error) {
	if k != c.ticket {
		a, err := c.walletCluster.GetAccountInfo(ctx, k, cm)
		return a, 0, err
	}
	n := int(c.reads.Add(1))
	c.mu.Lock()
	c.mins = append(c.mins, minContextSlot)
	c.cms = append(c.cms, cm)
	c.mu.Unlock()
	slot := uint64(10 + n)
	if len(c.slots) > 0 {
		slot = c.slots[min(n, len(c.slots))-1]
	}
	switch c.script[min(n, len(c.script))-1] {
	case 'o':
		a, err := c.walletCluster.GetAccountInfo(ctx, k, cm)
		return a, slot, err
	case 'p':
		return c.other, slot, nil
	case 'x':
		return nil, 0, context.DeadlineExceeded
	}
	return nil, slot, rpc.ErrNotFound
}

func (c *walletClusterTicketScript) sent() []uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return slices.Clone(c.mins)
}

// allConfirmed fails t unless every ticket read was at confirmed: an open seen
// at processed could be on a fork that is dropped.
func (c *walletClusterTicketScript) allConfirmed(t *testing.T) {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, cm := range c.cms {
		if cm != rpc.Confirmed {
			t.Fatalf("read the ticket at %q, want confirmed", cm)
		}
	}
}

// otherPayers is the fixture's ticket account with another payer in the
// payer's place.
func (f *solanaAckFixture) otherPayers(t *testing.T) *rpc.Account {
	t.Helper()
	a := f.cluster.accounts[f.ticketAddr]
	data := append([]byte(nil), a.Data...)
	at := bytes.Index(data, f.wallet.payer[:])
	if at < 0 {
		t.Fatal("no payer in the ticket account")
	}
	other := solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG")
	copy(data[at:], other[:])
	if tk, err := zsescrow.DecodeTicket(data); err != nil || tk.Payer != other {
		t.Fatalf("the payer's offset is off: %+v, %v", tk, err)
	}
	return &rpc.Account{Owner: a.Owner, Data: data}
}

func shortSolanaConfirmWatch(t *testing.T, timeout time.Duration) {
	t.Helper()
	prevTimeout, prevPoll := solanaSettleConfirmTimeout, settleConfirmPoll
	solanaSettleConfirmTimeout, settleConfirmPoll = timeout, 5*time.Millisecond
	t.Cleanup(func() { solanaSettleConfirmTimeout, settleConfirmPoll = prevTimeout, prevPoll })
}

// A delivered Solana ack's settle is the node's transaction, whose signature
// the payer never learns, so the watch reads the ticket account instead: once
// it closes after the watch saw it open, the journal row goes, as on Algorand
// once the group confirms. An account not seen yet may be an open still
// confirming, since the node serves before it lands, so its absence keeps the
// row, as do an account that stays open, one of another payer's, and a failed
// read; the reconciler finishes each. Closed counts only as of a slot after
// the one the account was last seen at, which each read asks for: a provider's
// node behind the one that showed it can answer that it is missing.
func TestConfirmSettled_ReadsASolanaTicket(t *testing.T) {
	shortSolanaConfirmWatch(t, 300*time.Millisecond)
	for _, c := range []struct {
		name    string
		script  string
		slots   []uint64
		wantRow bool
		// reads is the reads to the row's drop; 0 when it stays.
		reads int32
		// sent is the minContextSlot of the first reads.
		sent []uint64
	}{
		{name: "open, then closed", script: "o-", reads: 2, sent: []uint64{0, 11}},
		{name: "open for three reads, then closed", script: "ooo-", reads: 4, sent: []uint64{0, 11, 12, 13}},
		{name: "failed reads, open, then closed", script: "xxo-", reads: 4, sent: []uint64{0, 0, 0, 13}},
		{name: "not open yet, open, then closed", script: "--o-", reads: 4, sent: []uint64{0, 0, 0, 13}},
		{name: "never seen open", script: "-", wantRow: true},
		{name: "never closed", script: "o", wantRow: true},
		{name: "another payer's, then closed", script: "p-", wantRow: true},
		{name: "reads keep failing", script: "x", wantRow: true},
		{name: "closed as of the slot it was seen at, then after", script: "o--", slots: []uint64{20, 20, 21}, reads: 3, sent: []uint64{0, 20, 20}},
		{name: "closed as of an earlier slot, then after", script: "o--", slots: []uint64{20, 19, 21}, reads: 3},
		{name: "only ever closed as of the slot it was seen at", script: "o-", slots: []uint64{20, 20, 20}, wantRow: true},
		// A stale answer that still shows the account does not move the slot
		// back for the closed reads after it.
		{name: "seen, seen as of an earlier slot, closed between", script: "oo-", slots: []uint64{20, 5, 6, 21}, reads: 4, sent: []uint64{0, 20, 20, 20}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			cl := &walletClusterTicketScript{walletCluster: f.cluster, ticket: f.ticketAddr, script: c.script, slots: c.slots, other: f.otherPayers(t)}
			f.wallet.rpc = cl
			h := f.handle(nil)
			sc := settleClient()
			j := newMemJournal()
			sc.journal = j
			_ = j.Put(t.Context(), TicketRecord{TicketID: h.TicketID, Status: TicketSettlePending})

			sc.confirmSettled(h.TicketID, "", h)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := sc.WaitSettles(ctx); err != nil {
				t.Fatal(err)
			}
			if _, has := j.recs[h.TicketID]; has != c.wantRow {
				t.Errorf("journal row present = %v, want %v", has, c.wantRow)
			}
			reads := cl.reads.Load()
			switch {
			case c.wantRow && reads < 2:
				t.Errorf("gave up after %d read(s) before the deadline", reads)
			case !c.wantRow && reads != c.reads:
				t.Errorf("read the ticket %d times, want %d", reads, c.reads)
			}
			if sent := cl.sent(); c.sent != nil && !slices.Equal(sent[:min(len(sent), len(c.sent))], c.sent) {
				t.Errorf("sent minContextSlot %v, want %v first", sent, c.sent)
			}
			cl.allConfirmed(t)
		})
	}
}

// The watch of a Solana settle has the watchdog's budget, past a blockhash's
// life; an Algorand one needs its txid, and keeps its own budget. An RPC
// client without the slot-aware read gets no watch, since no absence it
// reports can be trusted, and the row stays with the reconciler.
func TestOpenHandle_SettleWatch(t *testing.T) {
	if solanaSettleConfirmTimeout != solanaEndingTimeout || settleConfirmTimeout != 20*time.Second {
		t.Fatalf("budgets %v and %v, want the Solana ending's and 20s", solanaSettleConfirmTimeout, settleConfirmTimeout)
	}
	slotAware := &SolanaWallet{rpc: &walletClusterTicketScript{}}
	if d, byTicket := (&OpenHandle{solana: slotAware}).settleWatch(); d != solanaEndingTimeout || !byTicket {
		t.Errorf("Solana handle watch %v by ticket %v", d, byTicket)
	}
	f := newSolanaAckFixture(t)
	f.wallet.rpc = f.cluster
	plain := f.handle(nil)
	if _, byTicket := plain.settleWatch(); byTicket {
		t.Error("watched by ticket over an RPC without the slot-aware read")
	}
	if out, err := plain.solanaSettleOutcome(t.Context()); out != SettlePending || !errors.Is(err, errNoSlotRead) {
		t.Errorf("outcome over an RPC without the slot-aware read: %v, %v", out, err)
	}
	// Nor does a delivered ack's watch start.
	sc := settleClient()
	sc.journal = newMemJournal()
	sc.confirmSettled(plain.TicketID, "", plain)
	if n := 0; func() int { sc.settlesInFlight.Range(func(any, any) bool { n++; return true }); return n }() != 0 {
		t.Error("watched a Solana settle over an RPC without the slot-aware read")
	}
	if d, byTicket := (&OpenHandle{}).settleWatch(); d != settleConfirmTimeout || byTicket {
		t.Errorf("Algorand handle watch %v by ticket %v", d, byTicket)
	}
	// With no txid an Algorand handle has nothing to watch.
	sc = settleClient()
	sc.journal = newMemJournal()
	sc.confirmSettled("T", "", &OpenHandle{})
	if n := 0; func() int { sc.settlesInFlight.Range(func(any, any) bool { n++; return true }); return n }() != 0 {
		t.Error("watched an Algorand settle with no txid")
	}
}

// The receipt check watches a Solana ack it delivered to the node, which has
// no txid, and drops the ticket's row once the account is closed. The ticket
// is read once before the ack goes, since the node cannot settle without it:
// a settle that lands before the watch's first read is then still seen
// closing. A failed read there leaves the watch to see the account itself.
func TestCheckReceipt_ConfirmsADeliveredSolanaAck(t *testing.T) {
	shortSolanaConfirmWatch(t, 2*time.Second)
	for _, c := range []struct {
		name   string
		script string
		reads  int32
	}{
		{name: "seen before the delivery, closed at the watch's first read", script: "o-", reads: 2},
		{name: "unread before the delivery, seen by the watch, then closed", script: "xo-", reads: 3},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			cl := &walletClusterTicketScript{walletCluster: f.cluster, ticket: f.ticketAddr, script: c.script}
			f.wallet.rpc = cl
			var delivered, readsBefore int32
			h := f.handle(func(context.Context, wire.SettleAck) error {
				delivered++
				readsBefore = cl.reads.Load()
				return nil
			})
			sf := newSettleFixtureFor(t, h.TicketID)
			sc := settleClient()
			j := newMemJournal()
			sc.journal = j
			_ = j.Put(t.Context(), TicketRecord{TicketID: sf.tkt.TicketID, Status: TicketSettlePending})

			if _, err := sf.check(sc, newSettleSlot(), h, true, "7")(); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			if err := sc.WaitSettles(ctx); err != nil {
				t.Fatal(err)
			}
			if delivered != 1 || readsBefore != 1 {
				t.Fatalf("delivered %d acks after %d ticket reads, want 1 after 1", delivered, readsBefore)
			}
			if _, has := j.recs[sf.tkt.TicketID]; has {
				t.Error("the row stayed after the ticket account closed")
			}
			if n := cl.reads.Load(); n != c.reads {
				t.Errorf("read the ticket %d times, want %d", n, c.reads)
			}
			cl.allConfirmed(t)
		})
	}
}

// The read before an ack goes holds up the delivery only for its own budget,
// and an RPC client without the slot-aware read makes none.
func TestSolanaSettleBaseline_Bounded(t *testing.T) {
	prev := solanaSettleBaselineTimeout
	solanaSettleBaselineTimeout = 20 * time.Millisecond
	t.Cleanup(func() { solanaSettleBaselineTimeout = prev })
	f := newSolanaAckFixture(t)
	f.wallet.rpc = &walletClusterTicketHang{walletClusterTicketScript{walletCluster: f.cluster, ticket: f.ticketAddr, script: "o"}}
	h := f.handle(nil)
	// The caller's own budget is longer, so only the read's ends it early.
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	start := time.Now()
	h.solanaSettleBaseline(ctx)
	if d := time.Since(start); d > time.Second {
		t.Errorf("the read held the delivery %v", d)
	}
	if h.ticketSeenSlot.Load() != 0 {
		t.Error("a read cut off by its budget marked the ticket seen")
	}

	plain := newSolanaAckFixture(t)
	plain.wallet.rpc = plain.cluster
	ph := plain.handle(nil)
	ph.solanaSettleBaseline(t.Context())
	if ph.ticketSeenSlot.Load() != 0 {
		t.Error("marked the ticket seen over an RPC without the slot-aware read")
	}
}

// walletClusterTicketHang answers no slot-aware ticket read before its ctx ends.
type walletClusterTicketHang struct{ walletClusterTicketScript }

func (c *walletClusterTicketHang) GetAccountInfoAt(ctx context.Context, k solana.PublicKey, cm rpc.Commitment, minContextSlot uint64) (*rpc.Account, uint64, error) {
	if k != c.ticket {
		return c.walletClusterTicketScript.GetAccountInfoAt(ctx, k, cm, minContextSlot)
	}
	<-ctx.Done()
	return nil, 0, ctx.Err()
}
