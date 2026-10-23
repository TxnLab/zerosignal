/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// ticketExpiresAtOffset is the ticket account's expires_at, after the
// discriminator, the header, open_seq, max_price, the pending claim and
// opened_at.
const ticketExpiresAtOffset = 123

// setTicketDeadline moves the fixture's ticket account's deadline, its
// expires_at plus the grace it took at open, to d.
func (f *solanaAckFixture) setTicketDeadline(t *testing.T, d time.Time) {
	t.Helper()
	a := f.cluster.accounts[f.ticketAddr]
	tk, err := zsescrow.DecodeTicket(a.Data)
	if err != nil {
		t.Fatal(err)
	}
	data := append([]byte(nil), a.Data...)
	binary.LittleEndian.PutUint64(data[ticketExpiresAtOffset:], uint64(d.Unix()-int64(tk.Grace)))
	if tk, err = zsescrow.DecodeTicket(data); err != nil || tk.Deadline() != d.Unix() {
		t.Fatalf("the ticket's expires_at offset is off: %+v, %v", tk, err)
	}
	f.cluster.accounts[f.ticketAddr] = &rpc.Account{Owner: a.Owner, Data: data}
}

// solanaWatchdog is a watchdog on short timings, with what it reported.
type solanaWatchdog struct {
	*RefundWatchdog
	refunds, bars atomic.Int32
}

func newSolanaWatchdog() *solanaWatchdog {
	w := &solanaWatchdog{RefundWatchdog: testWatchdog()}
	w.refunded = func(string) { w.refunds.Add(1) }
	return w
}

// finish waits for the watchdog to stop driving the handle's ticket.
func (w *solanaWatchdog) finish(t *testing.T, h *OpenHandle) {
	t.Helper()
	waitFor(t, "the ticket's driver to finish", func() bool { return !w.watching(h.TicketID) })
}

// The watchdog drives a Solana handle as it drives an Algorand one, reading
// the ticket account where Algorand reads the box: refund_inactive on an open
// ticket past its deadline, nothing on a ticket gone or frozen, settle_lapsed
// on a node's claim the node never lapsed, and nothing on a claim above the
// receipt the node signed, whose node it bars.
func TestRefundWatchdog_DrivesASolanaTicket(t *testing.T) {
	for _, c := range []struct {
		name string
		// gone is no ticket account; status is the ticket's otherwise.
		gone    bool
		status  zsescrow.TicketStatus
		claim   uint64
		receipt bool
		// send is the ending sent, nil for none.
		send             func(zsescrow.Deployment, zsescrow.Ending) solana.Instruction
		refunded, barred bool
	}{
		{name: "open", status: zsescrow.TicketOpen, send: zsescrow.Deployment.RefundInactive, refunded: true},
		{name: "the payer's own claim", status: zsescrow.TicketPendingByPayer, claim: 100, send: zsescrow.Deployment.RefundInactive, refunded: true},
		{name: "gone", gone: true},
		{name: "frozen", status: zsescrow.TicketFrozen, claim: 100},
		{name: "the node's claim", status: zsescrow.TicketPendingByOperator, claim: 100, send: zsescrow.Deployment.SettleLapsed},
		{name: "the node's claim at the receipt", status: zsescrow.TicketPendingByOperator, claim: 100, receipt: true, send: zsescrow.Deployment.SettleLapsed},
		{name: "the node's claim above the receipt", status: zsescrow.TicketPendingByOperator, claim: 101, receipt: true, barred: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			var tk *zsescrow.Ticket
			if c.gone {
				f.cluster.accounts[f.ticketAddr] = nil
			} else {
				f.setTicket(t, c.status, c.claim, nil)
				f.setTicketDeadline(t, time.Now().Add(-time.Minute))
				tk = f.ticket(t)
			}
			f.wallet.defaultGrace = 0
			rw := newSolanaWatchdog()
			// Long enough that the receipt is pinned before the lapse reads it.
			rw.lapseFallback = 100 * time.Millisecond
			rw.overclaimed = func(_ string, n NodeRef) {
				if n != (NodeRef{Op: f.operatorID, Node: f.nodeID}) {
					t.Errorf("barred %+v", n)
				}
				rw.bars.Add(1)
			}
			h := f.handle(nil)
			before := f.readsOfTicket()
			rw.Track(h, time.Now().Add(-time.Minute).Unix())
			if c.receipt {
				rw.recordReceipt(h.TicketID, RefOf(h.Operator), 100)
			}
			rw.finish(t, h)

			if f.readsOfTicket() == before {
				t.Fatal("the ticket account was never read")
			}
			// A ticket gone is read once, with no refund or lapse to read it again.
			if c.gone && f.readsOfTicket()-before != 1 {
				t.Fatalf("read a ticket gone %d times", f.readsOfTicket()-before)
			}
			if c.send == nil {
				if len(f.cluster.acks) != 0 {
					t.Fatalf("%d sent", len(f.cluster.acks))
				}
			} else {
				if len(f.cluster.acks) != 1 {
					t.Fatalf("%d sent", len(f.cluster.acks))
				}
				e := zsescrow.Ending{Submitter: f.wallet.payer, OperatorID: f.operatorID, NodeID: f.nodeID, TicketID: f.ticketID,
					RentPayer: tk.RentPayer, Payer: f.wallet.payer}
				want, err := solana.Compile(f.wallet.payer, f.cluster.blockhash, []solana.Instruction{c.send(f.cluster.d, e)}, solana.Legacy)
				if err != nil {
					t.Fatal(err)
				}
				wantMsg, _ := want.MarshalBinary()
				gotMsg, _ := f.cluster.acks[0].Message.MarshalBinary()
				if !bytes.Equal(gotMsg, wantMsg) {
					t.Fatal("the watchdog sent another ending")
				}
			}
			if got := rw.refunds.Load() == 1; got != c.refunded {
				t.Errorf("refunded %v, want %v", got, c.refunded)
			}
			if got := rw.bars.Load() == 1; got != c.barred {
				t.Errorf("barred %v, want %v", got, c.barred)
			}
		})
	}
}

// The watchdog first reads a Solana ticket at expires_at plus the Config's
// default_grace, the grace a payer's open takes, and waits out the ticket's
// own deadline when that is later.
func TestRefundWatchdog_TimesASolanaTicket(t *testing.T) {
	t.Run("the Config's grace", func(t *testing.T) {
		f := newSolanaAckFixture(t)
		f.setTicket(t, zsescrow.TicketOpen, 0, nil)
		f.setTicketDeadline(t, time.Now().Add(-time.Minute))
		cfg, err := zsescrow.DecodeConfig(f.cluster.config.Data)
		if err != nil || cfg.DefaultGrace <= 60 {
			t.Fatalf("the Config's default_grace %d, %v: too short to sit inside", cfg.DefaultGrace, err)
		}
		rw := newSolanaWatchdog()
		h := f.handle(nil)
		// Past expires_at by less than the grace the wallet read.
		rw.Track(h, time.Now().Unix()-int64(cfg.DefaultGrace)+60)
		time.Sleep(50 * time.Millisecond)
		if n := f.readsOfTicket(); n != 0 || !rw.watching(h.TicketID) {
			t.Fatalf("read the ticket %d times before expires_at plus the grace", n)
		}
		rw.Resolve(h.TicketID)
	})

	t.Run("the ticket's own deadline", func(t *testing.T) {
		f := newSolanaAckFixture(t)
		f.setTicket(t, zsescrow.TicketOpen, 0, nil)
		// Whole seconds, as the ticket holds it.
		ahead := time.Unix(time.Now().Add(2*time.Second).Unix(), 0)
		f.setTicketDeadline(t, ahead)
		f.wallet.defaultGrace = 0
		rw := newSolanaWatchdog()
		h := f.handle(nil)
		rw.Track(h, time.Now().Add(-time.Minute).Unix())
		waitFor(t, "the first read", func() bool {
			f.cluster.mu.Lock()
			defer f.cluster.mu.Unlock()
			return f.readsOfTicket() > 0
		})
		f.cluster.mu.Lock()
		sent := len(f.cluster.acks)
		f.cluster.mu.Unlock()
		if sent != 0 {
			t.Fatal("refunded before the ticket's own deadline")
		}
		for end := time.Now().Add(5 * time.Second); rw.watching(h.TicketID); time.Sleep(5 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatal("timed out waiting for the ticket's driver to finish")
			}
		}
		if len(f.cluster.acks) != 1 || rw.refunds.Load() != 1 {
			t.Fatalf("%d sent, refunded %d", len(f.cluster.acks), rw.refunds.Load())
		}
		if time.Now().Before(ahead) {
			t.Fatal("refunded before the ticket's own deadline")
		}
	})
}

// walletClusterSlowConfirm reports no status for a sent transaction until
// landAt, at a height that never passes its blockhash.
type walletClusterSlowConfirm struct {
	*walletCluster
	landAt time.Time
}

func (c *walletClusterSlowConfirm) GetSignatureStatuses(ctx context.Context, sigs []solana.Signature, b bool) ([]*rpc.SignatureStatus, error) {
	if time.Now().Before(c.landAt) {
		return make([]*rpc.SignatureStatus, len(sigs)), nil
	}
	return c.walletCluster.GetSignatureStatuses(ctx, sigs, b)
}

func (*walletClusterSlowConfirm) GetBlockHeight(context.Context, rpc.Commitment) (uint64, error) {
	return 0, nil
}

// A Solana refund or lapse waits for its confirmation, which can outlast the
// watchdog's callTimeout. It is waited for rather than cut short and sent
// again, so a refund that lands late is reported as one. The budget is past
// a blockhash's life, a minute or so, with room for a slow cluster.
func TestRefundWatchdog_WaitsForASolanaEndingToConfirm(t *testing.T) {
	if solanaEndingTimeout != 3*time.Minute {
		t.Fatalf("solanaEndingTimeout = %v, want 3m", solanaEndingTimeout)
	}
	for _, c := range []struct {
		name     string
		status   zsescrow.TicketStatus
		claim    uint64
		refunded int32
	}{
		{"refund_inactive", zsescrow.TicketOpen, 0, 1},
		{"settle_lapsed", zsescrow.TicketPendingByOperator, 100, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			f.setTicket(t, c.status, c.claim, nil)
			f.setTicketDeadline(t, time.Now().Add(-time.Minute))
			f.wallet.defaultGrace = 0
			f.wallet.rpc = &walletClusterSlowConfirm{walletCluster: f.cluster, landAt: time.Now().Add(150 * time.Millisecond)}
			rw := newSolanaWatchdog()
			rw.callTimeout = 20 * time.Millisecond
			h := f.handle(nil)
			rw.Track(h, time.Now().Add(-time.Minute).Unix())
			rw.finish(t, h)
			if len(f.cluster.acks) != 1 || rw.refunds.Load() != c.refunded {
				t.Fatalf("%d sent, refunded %d", len(f.cluster.acks), rw.refunds.Load())
			}
		})
	}
}

// walletClusterFailingRead fails the first fail reads of the ticket account,
// as an RPC outage would.
type walletClusterFailingRead struct {
	*walletCluster
	ticket solana.PublicKey
	fail   atomic.Int32
}

func (c *walletClusterFailingRead) GetAccountInfo(ctx context.Context, k solana.PublicKey, cm rpc.Commitment) (*rpc.Account, error) {
	if k == c.ticket && c.fail.Add(-1) >= 0 {
		return nil, errors.New("rpc down")
	}
	return c.walletCluster.GetAccountInfo(ctx, k, cm)
}

// A ticket read that fails is not a ticket gone: the watchdog goes on to the
// refund, as on Algorand, and it lands once the read works again.
func TestRefundWatchdog_ASolanaReadFailureIsNoTicketGone(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketOpen, 0, nil)
	f.setTicketDeadline(t, time.Now().Add(-time.Minute))
	f.wallet.defaultGrace = 0
	c := &walletClusterFailingRead{walletCluster: f.cluster, ticket: f.ticketAddr}
	c.fail.Store(1)
	f.wallet.rpc = c
	rw := newSolanaWatchdog()
	h := f.handle(nil)
	rw.Track(h, time.Now().Add(-time.Minute).Unix())
	rw.finish(t, h)
	if len(f.cluster.acks) != 1 || rw.refunds.Load() != 1 {
		t.Fatalf("%d sent, refunded %d", len(f.cluster.acks), rw.refunds.Load())
	}
}

// The watchdog reads the ticket at the handle's node, operator id then node
// id, as the open put it there.
func TestRefundWatchdog_ReadsTheSolanaTicketAtItsNode(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketOpen, 0, nil)
	f.setTicketDeadline(t, time.Now().Add(-time.Minute))
	f.wallet.defaultGrace = 0
	const opID, nodeID = 7, 9
	d := f.cluster.d
	f.cluster.accounts[d.Ticket(d.Node(opID, nodeID), f.ticketID)] = f.cluster.accounts[f.ticketAddr]
	f.cluster.accounts[f.ticketAddr] = nil
	rw := newSolanaWatchdog()
	h := f.handle(nil)
	h.Operator = Operator{ID: opID, NodeID: nodeID}
	rw.Track(h, time.Now().Add(-time.Minute).Unix())
	rw.finish(t, h)
	if len(f.cluster.acks) != 1 || rw.refunds.Load() != 1 {
		t.Fatalf("%d sent, refunded %d", len(f.cluster.acks), rw.refunds.Load())
	}
}
