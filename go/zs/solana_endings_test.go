/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// solanaProtestFixture is one of the program's own protest transactions, with
// the ack fixture's wallet and cluster. The ticket account is the fixture's
// pending ticket, moved to the protested ticket's address: the protest reads
// only its payer and the node key it took at open.
type solanaProtestFixture struct {
	*solanaAckFixture
	handle  *OpenHandle
	receipt *ticket.UsageReceipt
	wire    []byte
	sig     string
}

func newSolanaProtestFixture(t *testing.T, name string) *solanaProtestFixture {
	t.Helper()
	f := &solanaProtestFixture{solanaAckFixture: newSolanaAckFixture(t)}
	var tv struct {
		Transactions []struct {
			Name       string          `json:"name"`
			Program    string          `json:"program"`
			Wire       string          `json:"wire_base64"`
			Signatures []string        `json:"signatures"`
			Receipt    json.RawMessage `json:"receipt_value"`
		} `json:"transactions"`
	}
	readSolanaFixture(t, "solana_tx_vectors.json", &tv)
	for _, x := range tv.Transactions {
		if x.Name != name {
			continue
		}
		if x.Program != "ok" {
			t.Fatalf("the program refused %s: %s", name, x.Program)
		}
		f.wire, _ = base64.StdEncoding.DecodeString(x.Wire)
		f.sig = x.Signatures[0]
		var r ticket.UsageReceipt
		if err := json.Unmarshal(x.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		f.receipt = &r
	}
	if f.receipt == nil {
		t.Fatalf("no %s transaction in solana_tx_vectors.json", name)
	}
	id, err := base64.StdEncoding.DecodeString(f.receipt.TicketID)
	if err != nil || len(id) != 16 {
		t.Fatalf("ticket id %q", f.receipt.TicketID)
	}
	d := f.cluster.d
	f.cluster.accounts[d.Ticket(d.Node(f.operatorID, f.nodeID), [16]byte(id))] = f.ticketAcct
	f.handle = &OpenHandle{TicketID: f.receipt.TicketID, Operator: Operator{ID: f.operatorID, NodeID: f.nodeID}, solana: f.wallet}
	return f
}

func (f *solanaProtestFixture) protest(t *testing.T) (string, uint64, error) {
	t.Helper()
	return f.handle.Protest(t.Context(), f.receipt, []byte("no excerpt on Solana"), escrow.ProtestReasonBodyHash)
}

// The handle's protest is the program's own, byte for byte, of an open ticket
// and of a pending one: the compute limit, the node's signature over the
// receipt's digest by the key the ticket took at open, and the protest. It
// pays for two signatures, its own and the precompile's.
func TestSolanaHandle_ProtestsAsTheProgram(t *testing.T) {
	for _, name := range []string{"protest", "protest_pending"} {
		t.Run(name, func(t *testing.T) {
			f := newSolanaProtestFixture(t, name)
			sig, fee, err := f.protest(t)
			if err != nil {
				t.Fatal(err)
			}
			if len(f.cluster.acks) != 1 {
				t.Fatalf("%d transactions sent", len(f.cluster.acks))
			}
			got, err := f.cluster.acks[0].MarshalBinary()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, f.wire) {
				t.Fatal("the protest differs from the program's")
			}
			if sig != f.sig || fee != 2*solanaSignatureFee {
				t.Fatalf("sig %s, fee %d; want %s, %d", sig, fee, f.sig, 2*solanaSignatureFee)
			}
		})
	}
}

// A protest the program refuses past the settle window wraps
// ErrProtestAfterDeadline, whether its preflight refused it or it landed and
// failed, so the receipt check skips the freeze no settle could make either.
// Any other refusal doesn't.
func TestSolanaHandle_ProtestPastTheDeadline(t *testing.T) {
	custom := func(code string) json.RawMessage {
		return json.RawMessage(`{"InstructionError":[2,{"Custom":` + code + `}]}`)
	}
	preflight := func(code string) error {
		return &rpc.Error{Method: "sendTransaction", Code: rpc.CodePreflightFailure, Message: "m",
			Data: json.RawMessage(`{"err":` + string(custom(code)) + `,"logs":[]}`)}
	}
	for _, c := range []struct {
		name     string
		set      func(*solanaProtestFixture)
		deadline bool
		fee      uint64
	}{
		{"preflight past the deadline", func(f *solanaProtestFixture) { f.cluster.sendErr = preflight("6011") }, true, 0},
		{"landed past the deadline", func(f *solanaProtestFixture) {
			f.cluster.ackLand = &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: custom("6011")}
		}, true, 2 * solanaSignatureFee},
		{"preflight on another code", func(f *solanaProtestFixture) { f.cluster.sendErr = preflight("6052") }, false, 0},
		{"landed on another code", func(f *solanaProtestFixture) {
			f.cluster.ackLand = &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: custom("6052")}
		}, false, 2 * solanaSignatureFee},
		{"another preflight failure", func(f *solanaProtestFixture) {
			f.cluster.sendErr = &rpc.Error{Method: "sendTransaction", Code: rpc.CodePreflightFailure, Message: "m",
				Data: json.RawMessage(`{"err":"InsufficientFundsForFee"}`)}
		}, false, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaProtestFixture(t, "protest_pending")
			c.set(f)
			_, fee, err := f.protest(t)
			if err == nil {
				t.Fatal("the protest succeeded")
			}
			if errors.Is(err, escrow.ErrProtestAfterDeadline) != c.deadline {
				t.Fatalf("err = %v, past the deadline: %v", err, c.deadline)
			}
			if fee != c.fee {
				t.Fatalf("fee %d, want %d", fee, c.fee)
			}
		})
	}
}

// A protest that can't land asks the signer nothing: no ticket, a ticket
// that isn't the payer's, a receipt with no signature, a reason the program
// can't carry.
func TestSolanaHandle_ProtestRefusesBeforeSigning(t *testing.T) {
	for _, c := range []struct {
		name string
		set  func(*solanaProtestFixture)
		want string
	}{
		{"no ticket", func(f *solanaProtestFixture) {
			for k := range f.cluster.accounts {
				if k != f.wallet.payerUSDC {
					f.cluster.accounts[k] = nil
				}
			}
		}, "no ticket account"},
		{"another payer's ticket", func(f *solanaProtestFixture) {
			tk := *f.ticket(t)
			data := append([]byte(nil), f.ticketAcct.Data...)
			other := solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG")
			copy(data[bytes.Index(data, tk.Payer[:]):], other[:])
			for k, a := range f.cluster.accounts {
				if a == f.ticketAcct {
					f.cluster.accounts[k] = &rpc.Account{Owner: a.Owner, Data: data}
				}
			}
		}, "not this wallet's"},
		{"no receipt signature", func(f *solanaProtestFixture) { f.receipt.Sig = "" }, "receipt sig"},
		{"a reason past a byte", func(f *solanaProtestFixture) {}, "past the program's 255"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaProtestFixture(t, "protest_pending")
			c.set(f)
			reason := escrow.ProtestReasonBodyHash
			if c.name == "a reason past a byte" {
				reason = 256
			}
			_, _, err := f.handle.Protest(t.Context(), f.receipt, nil, reason)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %q", err, c.want)
			}
			if len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
				t.Fatalf("%d sent, %d signed", len(f.cluster.acks), f.signer.asked.Load())
			}
		})
	}

	// 255 is the last reason the program's u8 carries, so it goes out.
	f := newSolanaProtestFixture(t, "protest_pending")
	if _, _, err := f.handle.Protest(t.Context(), f.receipt, nil, 0xff); err != nil || len(f.cluster.acks) != 1 {
		t.Fatalf("reason 255: err %v, %d sent", err, len(f.cluster.acks))
	}
}

// refund_inactive and settle_lapsed go out as the payer's own transaction
// over the ticket account: its rent payer, the payer's token account, and the
// treasury's, writable, when the payer's can't take the refund.
func TestSolanaHandle_EndsTheTicket(t *testing.T) {
	cfg, err := zsescrow.DecodeConfig(newSolanaOpenFixture(t, 0, 3).cluster.config.Data)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		call func(*OpenHandle, *testing.T) (string, error)
		ix   func(zsescrow.Deployment, zsescrow.Ending) solana.Instruction
	}{
		{"refund_inactive", func(h *OpenHandle, t *testing.T) (string, error) { return h.RefundInactive(t.Context()) }, zsescrow.Deployment.RefundInactive},
		{"settle_lapsed", func(h *OpenHandle, t *testing.T) (string, error) { return h.SettleLapsed(t.Context()) }, zsescrow.Deployment.SettleLapsed},
	} {
		for _, forfeit := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s forfeit=%v", c.name, forfeit), func(t *testing.T) {
				f := newSolanaAckFixture(t)
				if forfeit {
					f.cluster.accounts[f.wallet.payerUSDC] = nil
				}
				tk := f.ticket(t)
				sig, err := c.call(f.handle(nil), t)
				if err != nil {
					t.Fatal(err)
				}
				if len(f.cluster.acks) != 1 {
					t.Fatalf("%d sent", len(f.cluster.acks))
				}
				e := zsescrow.Ending{Submitter: f.wallet.payer, OperatorID: f.operatorID, NodeID: f.nodeID, TicketID: f.ticketID,
					RentPayer: tk.RentPayer, Payer: f.wallet.payer}
				if forfeit {
					e.Treasury, e.Fallback = cfg.Treasury, zsescrow.FallbackWritable
				}
				want, err := solana.Compile(f.wallet.payer, f.cluster.blockhash, []solana.Instruction{c.ix(f.cluster.d, e)}, solana.Legacy)
				if err != nil {
					t.Fatal(err)
				}
				wantMsg, _ := want.MarshalBinary()
				gotMsg, _ := f.cluster.acks[0].Message.MarshalBinary()
				if !bytes.Equal(gotMsg, wantMsg) {
					t.Fatalf("the transaction is not %s over the ticket account (forfeit %v)", c.name, forfeit)
				}
				if sig != f.cluster.acks[0].Signatures[0].String() {
					t.Fatalf("returned %s, sent %s", sig, f.cluster.acks[0].Signatures[0])
				}
			})
		}
	}
}

// An ending of a ticket that isn't there, or isn't the payer's, sends
// nothing; one that landed and failed hands back its signature.
func TestSolanaHandle_EndingRefusesOrReports(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.cluster.accounts[f.ticketAddr] = nil
	if _, err := f.handle(nil).RefundInactive(t.Context()); err == nil || !strings.Contains(err.Error(), "no ticket account") {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.handle(nil).SettleLapsed(t.Context()); err == nil || !strings.Contains(err.Error(), "no ticket account") {
		t.Fatalf("err = %v", err)
	}
	if len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
		t.Fatalf("%d sent, %d signed", len(f.cluster.acks), f.signer.asked.Load())
	}

	f = newSolanaAckFixture(t)
	f.cluster.ackLand = &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: json.RawMessage(`{"InstructionError":[0,{"Custom":6010}]}`)}
	sig, err := f.handle(nil).SettleLapsed(t.Context())
	if err == nil || sig == "" || sig != f.cluster.acks[0].Signatures[0].String() {
		t.Fatalf("sig %q, err %v", sig, err)
	}
}

// freezeOverclaim sends the payer's ack at the receipt over a node claim
// above it, which freezes the ticket, and sends nothing over any other.
func TestSolanaHandle_FreezesOnlyAnOverclaim(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.setTicket(t, zsescrow.TicketPendingByOperator, f.args.AmountCharged+1, nil)
	txid, fee, claim, err := f.handle(nil).freezeOverclaim(t.Context(), f.receipt)
	if err != nil || claim != ClaimOverclaims {
		t.Fatalf("claim %v, err %v", claim, err)
	}
	if len(f.cluster.acks) != 1 || txid != f.cluster.acks[0].Signatures[0].String() || fee != solanaSignatureFee {
		t.Fatalf("%d sent, txid %q, fee %d", len(f.cluster.acks), txid, fee)
	}
	tk := f.ticket(t)
	e := zsescrow.Ending{Submitter: f.wallet.payer, OperatorID: f.operatorID, NodeID: f.nodeID, TicketID: f.ticketID,
		RentPayer: tk.RentPayer, Payer: f.wallet.payer}
	want, _ := solana.Compile(f.wallet.payer, f.cluster.blockhash, []solana.Instruction{f.cluster.d.Ack(e, solanaClaimFields(f.args))}, solana.Legacy)
	wantMsg, _ := want.MarshalBinary()
	gotMsg, _ := f.cluster.acks[0].Message.MarshalBinary()
	if !bytes.Equal(gotMsg, wantMsg) {
		t.Fatal("the freeze is not the payer's ack at the receipt")
	}

	for _, c := range []struct {
		name   string
		status zsescrow.TicketStatus
		amount uint64
		want   ClaimVerdict
	}{
		{"a matching claim", zsescrow.TicketPendingByOperator, f.args.AmountCharged, ClaimAgrees},
		{"a claim below", zsescrow.TicketPendingByOperator, f.args.AmountCharged - 1, ClaimContradicts},
		{"an open ticket", zsescrow.TicketOpen, 0, ClaimOpen},
	} {
		f := newSolanaAckFixture(t)
		f.setTicket(t, c.status, c.amount, nil)
		_, _, claim, err := f.handle(nil).freezeOverclaim(t.Context(), f.receipt)
		if err != nil || claim != c.want || len(f.cluster.acks) != 0 {
			t.Fatalf("%s: claim %v, err %v, %d sent", c.name, claim, err, len(f.cluster.acks))
		}
	}

	f = newSolanaAckFixture(t)
	f.cluster.accounts[f.ticketAddr] = nil
	if _, _, claim, err := f.handle(nil).freezeOverclaim(t.Context(), f.receipt); err != nil || claim != ClaimNone || len(f.cluster.acks) != 0 {
		t.Fatalf("no ticket: claim %v, err %v", claim, err)
	}
	f.cluster.accounts[f.ticketAddr] = &rpc.Account{Owner: f.cluster.d.Program, Data: f.ticketAcct.Data[:20]}
	if _, _, claim, err := f.handle(nil).freezeOverclaim(t.Context(), f.receipt); err == nil || claim != ClaimUnreadable {
		t.Fatalf("an unreadable ticket: claim %v, err %v", claim, err)
	}
}
