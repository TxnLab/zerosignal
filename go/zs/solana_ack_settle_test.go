/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/wire"
)

// solanaHandle is the fixture ticket's handle, which hands its ack to deliver;
// nil hands it to no node.
func (f *solanaAckFixture) handle(deliver func(context.Context, wire.SettleAck) error) *OpenHandle {
	return &OpenHandle{
		TicketID:   base64.StdEncoding.EncodeToString(f.ticketID[:]),
		Operator:   Operator{ID: f.operatorID, NodeID: f.nodeID},
		deliverAck: deliver,
		solana:     f.wallet,
	}
}

// The ticket account's offsets of the fields a claim is judged on, after the
// 8-byte discriminator.
const (
	ticketStatusOffset        = 9
	ticketPendingAmountOffset = 33
	ticketClaimHashOffset     = 185
)

// setTicket rewrites the fixture's ticket account: status, and a claim of
// pending whose hash is the receipt's fields with the amount set to pending,
// as a node claiming pending would write it.
func (f *solanaAckFixture) setTicket(t *testing.T, status zsescrow.TicketStatus, pending uint64, edit func(*zsescrow.ClaimFields)) {
	t.Helper()
	data := append([]byte(nil), f.ticketAcct.Data...)
	fields := solanaClaimFields(f.args)
	fields.Amount = pending
	if edit != nil {
		edit(&fields)
	}
	h := zsescrow.ClaimHash(fields)
	data[ticketStatusOffset] = byte(status)
	binary.LittleEndian.PutUint64(data[ticketPendingAmountOffset:], pending)
	copy(data[ticketClaimHashOffset:], h[:])
	tk, err := zsescrow.DecodeTicket(data)
	if err != nil || tk.Status != status || tk.PendingAmount != pending || tk.ClaimHash != h {
		t.Fatalf("the ticket offsets are off: %+v, %v", tk, err)
	}
	f.cluster.accounts[f.ticketAddr] = &rpc.Account{Owner: f.cluster.d.Program, Data: data}
}

// readsOfTicket counts the reads of the fixture's ticket account.
func (f *solanaAckFixture) readsOfTicket() int {
	n := 0
	for _, k := range f.cluster.accountReads {
		if k == f.ticketAddr {
			n++
		}
	}
	return n
}

// With the node's open_seq the payer hands the node its ack: its signature
// over the receipt's ack digest at that open_seq, as payment_settle. It reads
// nothing, sends nothing and pays nothing; the node submits its settle.
func TestSolanaHandle_HandsTheNodeItsAck(t *testing.T) {
	f := newSolanaAckFixture(t)
	var got []wire.SettleAck
	h := f.handle(func(_ context.Context, ack wire.SettleAck) error {
		got = append(got, ack)
		return nil
	})
	// Ids that differ, so the digest binds each in its place; nothing here
	// reads the ticket account at them.
	const opID, nodeID = 3, 5
	h.Operator = Operator{ID: opID, NodeID: nodeID}
	res, err := h.AckSettle(t.Context(), f.receipt, "7")
	if err != nil {
		t.Fatal(err)
	}
	if res != (AckResult{}) {
		t.Fatalf("result %+v, want none of the payer's own", res)
	}
	if len(got) != 1 || got[0].TicketID != h.TicketID {
		t.Fatalf("delivered %+v", got)
	}
	sig, err := zsescrow.DecodeAckSignature(got[0].SettleGroup)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := zsescrow.ReceiptAckDigest(f.cluster.d, f.wallet.genesis, opID, nodeID, f.ticketID, 7, f.receipt)
	if err != nil {
		t.Fatal(err)
	}
	if !solana.VerifyStrict(f.wallet.payer, digest[:], sig) {
		t.Fatal("payment_settle is not the payer's signature over the ack digest at open_seq 7")
	}
	if cfg, _ := zsescrow.DecodeConfig(f.cluster.config.Data); f.wallet.genesis != cfg.GenesisHash || f.wallet.genesis == (solana.Hash{}) {
		t.Fatal("the ack digest does not bind the Config's genesis hash")
	}
	if f.readsOfTicket() != 0 || len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
		t.Fatalf("%d ticket reads, %d acks sent, %d signed", f.readsOfTicket(), len(f.cluster.acks), f.signer.asked.Load())
	}
}

// Without the node's open_seq, or with no relay to carry the ack, the payer
// sends its own ack over the ticket it read, and pays for it: here the node's
// claim matches the receipt, so the ack settles the ticket.
func TestSolanaHandle_AcksAloneWithoutTheNode(t *testing.T) {
	for _, c := range []struct {
		name    string
		slot    string
		deliver func(context.Context, wire.SettleAck) error
	}{
		{"no slot", "", func(context.Context, wire.SettleAck) error { t.Error("delivered"); return nil }},
		{"no relay", "7", func(context.Context, wire.SettleAck) error { return errNoSettleAckRoute }},
		{"no ack route at all", "7", nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			res, err := f.handle(c.deliver).AckSettle(t.Context(), f.receipt, c.slot)
			if err != nil {
				t.Fatal(err)
			}
			want := AckResult{TxID: f.sig, FeeMicroalgos: solanaSignatureFee, Claim: ClaimAgrees, PayerSettle: true}
			if res != want {
				t.Fatalf("result %+v, want %+v", res, want)
			}
			if len(f.cluster.acks) != 1 {
				t.Fatalf("%d acks sent", len(f.cluster.acks))
			}
			if got, _ := f.cluster.acks[0].MarshalBinary(); string(got) != string(f.wire) {
				t.Fatal("the ack is not the program's own ack of this ticket")
			}
			// The ack names the account the claim was judged on.
			if n := f.readsOfTicket(); n != 1 {
				t.Fatalf("%d reads of the ticket", n)
			}
		})
	}
}

// With no route nothing reached the node, so the payer's own ack runs on the
// caller's budget, not a fresh one: a caller whose deadline has passed gets
// nothing sent.
func TestSolanaHandle_AcksAloneOnTheCallersBudget(t *testing.T) {
	f := newSolanaAckFixture(t)
	ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	_, err := f.handle(func(context.Context, wire.SettleAck) error { return errNoSettleAckRoute }).AckSettle(ctx, f.receipt, "7")
	if !errors.Is(err, context.DeadlineExceeded) || len(f.cluster.acks) != 0 {
		t.Fatalf("err = %v, %d acks sent", err, len(f.cluster.acks))
	}
}

// What the payer's own ack does turns on the claim it read, as on Algorand:
// an over-claim is acked to freeze it, a claim that contradicts the receipt
// without taking more is left to lapse, and an open ticket gets the payer's
// first half.
func TestSolanaHandle_AcksAloneByTheClaim(t *testing.T) {
	f0 := newSolanaAckFixture(t)
	amount := f0.args.AmountCharged
	otherDigest := func(c *zsescrow.ClaimFields) { c.ReceiptDigest[0] ^= 0xff }
	for _, c := range []struct {
		name    string
		status  zsescrow.TicketStatus
		pending uint64
		edit    func(*zsescrow.ClaimFields)
		claim   ClaimVerdict
		sent    bool
		frozen  bool
	}{
		{"an over-claim is frozen", zsescrow.TicketPendingByOperator, amount + 1, nil, ClaimOverclaims, true, true},
		{"a contradicting claim taking no more is not acked", zsescrow.TicketPendingByOperator, amount - 1, otherDigest, ClaimContradicts, false, false},
		{"an open ticket gets the payer's half", zsescrow.TicketOpen, 0, nil, ClaimOpen, true, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			f.setTicket(t, c.status, c.pending, c.edit)
			res, err := f.handle(nil).AckSettle(t.Context(), f.receipt, "")
			if err != nil {
				t.Fatal(err)
			}
			if res.Claim != c.claim || res.PayerSettle != c.sent || res.Frozen != c.frozen {
				t.Fatalf("result %+v", res)
			}
			if n := len(f.cluster.acks); n != map[bool]int{true: 1}[c.sent] {
				t.Fatalf("%d acks sent", n)
			}
			if c.sent && (res.TxID != f.cluster.acks[0].Signatures[0].String() || res.FeeMicroalgos != solanaSignatureFee) {
				t.Fatalf("result %+v", res)
			}
			if n := f.readsOfTicket(); n != 1 {
				t.Fatalf("%d reads of the ticket", n)
			}
		})
	}
}

// After a delivery the node refused, or one that may have reached it, the
// payer reads the ticket on a budget of its own and sends its ack only where
// Algorand sends its settle: over an over-claim, to freeze it, and over an
// open ticket, as its first half. A claim matching the receipt is the node's
// to settle, and the delivery's error is returned.
func TestSolanaHandle_FollowsAFailedDelivery(t *testing.T) {
	f0 := newSolanaAckFixture(t)
	amount := f0.args.AmountCharged
	refused := errors.New("node answered 409")
	for _, c := range []struct {
		name    string
		status  zsescrow.TicketStatus
		pending uint64
		claim   ClaimVerdict
		sent    bool
		frozen  bool
	}{
		{"over-claim", zsescrow.TicketPendingByOperator, amount + 1, ClaimOverclaims, true, true},
		{"open ticket", zsescrow.TicketOpen, 0, ClaimOpen, true, false},
		{"matching claim", zsescrow.TicketPendingByOperator, amount, ClaimAgrees, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			f.setTicket(t, c.status, c.pending, nil)
			// The delivery spends the whole of its context, as a node holding
			// the request open until the deadline would.
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
			defer cancel()
			res, err := f.handle(func(ctx context.Context, _ wire.SettleAck) error {
				<-ctx.Done()
				return refused
			}).AckSettle(ctx, f.receipt, "7")
			if res.Claim != c.claim || res.PayerSettle != c.sent || res.Frozen != c.frozen {
				t.Fatalf("result %+v", res)
			}
			if c.sent {
				if err != nil || len(f.cluster.acks) != 1 {
					t.Fatalf("err = %v, %d acks sent", err, len(f.cluster.acks))
				}
				return
			}
			if !errors.Is(err, refused) || len(f.cluster.acks) != 0 {
				t.Fatalf("err = %v, %d acks sent", err, len(f.cluster.acks))
			}
		})
	}
}

// The payer's own ack that landed and failed reports its signature and the
// fee it paid beside the error.
func TestSolanaHandle_ReportsWhatAFailedAckPaid(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.cluster.ackLand = &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: json.RawMessage(`{"InstructionError":[0,{"Custom":6012}]}`)}
	res, err := f.handle(nil).AckSettle(t.Context(), f.receipt, "")
	if err == nil {
		t.Fatal("a failed ack reported no error")
	}
	if res.TxID != f.sig || res.FeeMicroalgos != solanaSignatureFee || !res.PayerSettle {
		t.Fatalf("result %+v", res)
	}
}

// With no ticket account to name there is no ack to send, and nothing is.
func TestSolanaHandle_SendsNoAckForAMissingTicket(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.cluster.accounts[f.ticketAddr] = nil
	res, err := f.handle(nil).AckSettle(t.Context(), f.receipt, "")
	if err == nil || res.Claim != ClaimNone || len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
		t.Fatalf("result %+v, err = %v, %d sent, %d signed", res, err, len(f.cluster.acks), f.signer.asked.Load())
	}
}
