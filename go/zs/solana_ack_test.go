/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// solanaAckFixture is the program's own ack transaction from the shared
// transaction vectors, where the payer answers the node's pending claim, with
// the wallet and the cluster it was made on.
type solanaAckFixture struct {
	*solanaOpenFixture
	operatorID, nodeID uint64
	ticketID           [16]byte
	ticketAddr         solana.PublicKey
	ticketAcct         *rpc.Account
	args               SettleArgs
	// wire is the transaction as the program's payer sent it.
	wire []byte
	sig  string
}

func newSolanaAckFixture(t *testing.T) *solanaAckFixture {
	t.Helper()
	f := &solanaAckFixture{solanaOpenFixture: newSolanaOpenFixture(t, 1_000_000_000, 3)}
	var tv struct {
		Context struct {
			Blockhash string `json:"recent_blockhash"`
		} `json:"context"`
		Transactions []struct {
			Name       string          `json:"name"`
			Wire       string          `json:"wire_base64"`
			Signatures []string        `json:"signatures"`
			Receipt    json.RawMessage `json:"receipt_value"`
		} `json:"transactions"`
	}
	readSolanaFixture(t, "solana_tx_vectors.json", &tv)
	var av struct {
		Accounts []struct {
			Name    string `json:"name"`
			Address string `json:"address"`
			Data    string `json:"data_base64"`
		} `json:"accounts"`
	}
	readSolanaFixture(t, "solana_account_vectors.json", &av)

	for _, x := range tv.Transactions {
		if x.Name != "ack" {
			continue
		}
		f.wire, _ = base64.StdEncoding.DecodeString(x.Wire)
		f.sig = x.Signatures[0]
		var r ticket.UsageReceipt
		if err := json.Unmarshal(x.Receipt, &r); err != nil {
			t.Fatal(err)
		}
		f.args = settleArgsOf(&r)
		id, err := base64.StdEncoding.DecodeString(r.TicketID)
		if err != nil || len(id) != 16 {
			t.Fatalf("ticket id %q", r.TicketID)
		}
		f.ticketID = [16]byte(id)
	}
	if f.wire == nil {
		t.Fatal("no ack transaction in solana_tx_vectors.json")
	}
	// The ticket the program's payer answered: the node's pending claim.
	for _, a := range av.Accounts {
		if a.Name == "ticket_pending" {
			f.ticketAddr = solana.MustPublicKey(a.Address)
			data, _ := base64.StdEncoding.DecodeString(a.Data)
			f.ticketAcct = &rpc.Account{Owner: f.cluster.d.Program, Data: data}
		}
	}
	d := f.cluster.d
	for op := uint64(1); op < 8 && f.operatorID == 0; op++ {
		for n := uint64(1); n < 8; n++ {
			if d.Ticket(d.Node(op, n), f.ticketID) == f.ticketAddr {
				f.operatorID, f.nodeID = op, n
			}
		}
	}
	if f.operatorID == 0 {
		t.Fatal("the ack fixture's ticket is not at any node 1..7 of operators 1..7")
	}
	bh, err := solana.ParseHash(tv.Context.Blockhash)
	if err != nil {
		t.Fatal(err)
	}
	f.cluster.blockhash = bh
	f.cluster.accounts = map[solana.PublicKey]*rpc.Account{
		f.ticketAddr:       f.ticketAcct,
		f.wallet.payerUSDC: payerTokenAccount(d.Mint, f.wallet.payer, zsescrow.TokenInitialized),
	}
	return f
}

// payerTokenAccount is an SPL token account of mint held by owner.
func payerTokenAccount(mint, owner solana.PublicKey, state zsescrow.TokenAccountState) *rpc.Account {
	data := make([]byte, zsescrow.TokenAccountSize)
	copy(data, mint[:])
	copy(data[32:], owner[:])
	binary.LittleEndian.PutUint64(data[64:], 1_000_000)
	data[32+32+8+4+32] = byte(state)
	return &rpc.Account{Owner: solana.TokenProgramID, Data: data}
}

func (f *solanaAckFixture) ticket(t *testing.T) *zsescrow.Ticket {
	t.Helper()
	tk, err := f.wallet.readTicket(t.Context(), f.operatorID, f.nodeID, f.ticketID)
	if err != nil || tk == nil {
		t.Fatalf("readTicket = %v, %v", tk, err)
	}
	return tk
}

func (f *solanaAckFixture) ack(t *testing.T, tk *zsescrow.Ticket) (solanaAck, error) {
	t.Helper()
	return f.wallet.sendAck(t.Context(), tk, f.operatorID, f.nodeID, f.ticketID, f.args)
}

// The wallet's ack is the program's own, byte for byte: the payer signs and
// pays alone, the ending comes from the ticket account, and a payer whose
// token account can take the refund passes no treasury account.
func TestSolanaWallet_SendsTheProgramsAck(t *testing.T) {
	f := newSolanaAckFixture(t)
	res, err := f.ack(t, f.ticket(t))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.cluster.acks) != 1 {
		t.Fatalf("%d acks sent", len(f.cluster.acks))
	}
	got, err := f.cluster.acks[0].MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, f.wire) {
		t.Fatal("the ack differs from the program's ack transaction")
	}
	if res.Sig != f.sig || res.FeeLamports != solanaSignatureFee {
		t.Fatalf("result %+v, want %s and %d lamports", res, f.sig, solanaSignatureFee)
	}
	if o := f.cluster.sendOpts[len(f.cluster.sendOpts)-1]; o.PreflightCommitment != rpc.Confirmed {
		t.Fatalf("preflight at %q", o.PreflightCommitment)
	}
}

// A refund the payer's token account can't take is forfeited to the
// treasury's, which the ack then passes writable: the program's can_receive,
// case by case.
func TestSolanaWallet_AckForfeitsWhatThePayerCantTake(t *testing.T) {
	treasury, err := zsescrow.DecodeConfig(newSolanaOpenFixture(t, 0, 3).cluster.config.Data)
	if err != nil {
		t.Fatal(err)
	}
	other := solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG")
	for _, c := range []struct {
		name string
		acct func(f *solanaAckFixture) *rpc.Account
	}{
		{"no account", func(*solanaAckFixture) *rpc.Account { return nil }},
		{"frozen", func(f *solanaAckFixture) *rpc.Account {
			return payerTokenAccount(f.cluster.d.Mint, f.wallet.payer, zsescrow.TokenFrozen)
		}},
		{"uninitialized", func(f *solanaAckFixture) *rpc.Account {
			return payerTokenAccount(f.cluster.d.Mint, f.wallet.payer, zsescrow.TokenUninitialized)
		}},
		{"another mint", func(f *solanaAckFixture) *rpc.Account {
			return payerTokenAccount(other, f.wallet.payer, zsescrow.TokenInitialized)
		}},
		{"another owner", func(f *solanaAckFixture) *rpc.Account {
			return payerTokenAccount(f.cluster.d.Mint, other, zsescrow.TokenInitialized)
		}},
		{"not the token program's", func(f *solanaAckFixture) *rpc.Account {
			a := payerTokenAccount(f.cluster.d.Mint, f.wallet.payer, zsescrow.TokenInitialized)
			a.Owner = solana.SystemProgramID
			return a
		}},
		{"short", func(f *solanaAckFixture) *rpc.Account {
			a := payerTokenAccount(f.cluster.d.Mint, f.wallet.payer, zsescrow.TokenInitialized)
			a.Data = a.Data[:zsescrow.TokenAccountSize-1]
			return a
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			f.cluster.accounts[f.wallet.payerUSDC] = c.acct(f)
			tk := f.ticket(t)
			if _, err := f.ack(t, tk); err != nil {
				t.Fatal(err)
			}
			e := zsescrow.Ending{Submitter: f.wallet.payer, OperatorID: f.operatorID, NodeID: f.nodeID, TicketID: f.ticketID,
				RentPayer: tk.RentPayer, Payer: f.wallet.payer, Treasury: treasury.Treasury, Fallback: zsescrow.FallbackWritable}
			want, err := solana.Compile(f.wallet.payer, f.cluster.blockhash, []solana.Instruction{f.cluster.d.Ack(e, solanaClaimFields(f.args))}, solana.Legacy)
			if err != nil {
				t.Fatal(err)
			}
			wantMsg, _ := want.MarshalBinary()
			gotMsg, _ := f.cluster.acks[0].Message.MarshalBinary()
			if !bytes.Equal(gotMsg, wantMsg) {
				t.Fatal("the ack is not Ack with the treasury's account writable")
			}
		})
	}
}

// readTicket decodes the program's ticket account, and reads none where there
// is no account or one the program doesn't own.
func TestSolanaWallet_ReadsTheTicketAccount(t *testing.T) {
	f := newSolanaAckFixture(t)
	tk := f.ticket(t)
	if tk.Status != zsescrow.TicketPendingByOperator || tk.Payer != f.wallet.payer {
		t.Fatalf("ticket %+v", tk)
	}
	if f.cluster.accountReads[len(f.cluster.accountReads)-1] != f.ticketAddr {
		t.Fatal("readTicket read another address")
	}
	for _, c := range []struct {
		name string
		acct *rpc.Account
	}{
		{"no account", nil},
		{"another owner", &rpc.Account{Owner: solana.SystemProgramID, Data: f.ticketAcct.Data}},
	} {
		f.cluster.accounts[f.ticketAddr] = c.acct
		if tk, err := f.wallet.readTicket(t.Context(), f.operatorID, f.nodeID, f.ticketID); err != nil || tk != nil {
			t.Fatalf("%s: %v, %v", c.name, tk, err)
		}
	}
	f.cluster.accounts[f.ticketAddr] = &rpc.Account{Owner: f.cluster.d.Program, Data: f.ticketAcct.Data[:20]}
	if _, err := f.wallet.readTicket(t.Context(), f.operatorID, f.nodeID, f.ticketID); err == nil {
		t.Fatal("a truncated ticket decodes")
	}
}

// An ack for a ticket that isn't the payer's, or for none, asks the signer
// nothing and sends nothing: the program refuses it.
func TestSolanaWallet_AckRefusesATicketNotThePayers(t *testing.T) {
	f := newSolanaAckFixture(t)
	tk := f.ticket(t)
	tk.Payer = solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG")
	if _, err := f.ack(t, tk); err == nil || !strings.Contains(err.Error(), "not this wallet's") {
		t.Fatalf("err = %v", err)
	}
	if _, err := f.ack(t, nil); err == nil {
		t.Fatal("an ack of no ticket sent")
	}
	if len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
		t.Fatalf("%d sent, %d signed", len(f.cluster.acks), f.signer.asked.Load())
	}
}

// An ack that landed and failed paid its fee, which is reported beside the
// program's error with its code; one that never confirmed paid nothing it
// knows of, and hands back its signature to look for and the expiry that says
// it never can land.
func TestSolanaWallet_AckReportsWhereItLanded(t *testing.T) {
	f := newSolanaAckFixture(t)
	txErr := `{"InstructionError":[0,{"Custom":6012}]}`
	f.cluster.ackLand = &rpc.SignatureStatus{Slot: 5, ConfirmationStatus: rpc.Confirmed, Err: json.RawMessage(txErr)}
	res, err := f.ack(t, f.ticket(t))
	if err == nil || !strings.Contains(err.Error(), "failed") || !strings.Contains(err.Error(), "6012") {
		t.Fatalf("err = %v", err)
	}
	if res.Sig != f.sig || res.FeeLamports != solanaSignatureFee || string(res.TxErr) != txErr {
		t.Fatalf("result %+v", res)
	}

	f = newSolanaAckFixture(t)
	f.wallet.rpc = &walletClusterNoStatus{f.cluster}
	res, err = f.ack(t, f.ticket(t))
	if !errors.Is(err, rpc.ErrExpired) {
		t.Fatalf("err = %v, want rpc.ErrExpired", err)
	}
	if res.Sig != f.sig || res.FeeLamports != 0 || res.TxErr != nil {
		t.Fatalf("result %+v", res)
	}
}

// A forfeit needs the Config's treasury; without a Config to read it from the
// ack signs and sends nothing.
func TestSolanaWallet_AckForfeitNeedsTheConfig(t *testing.T) {
	for _, c := range []struct {
		name   string
		config func(*rpc.Account) *rpc.Account
	}{
		{"no account", func(*rpc.Account) *rpc.Account { return nil }},
		{"another owner", func(a *rpc.Account) *rpc.Account { return &rpc.Account{Owner: solana.SystemProgramID, Data: a.Data} }},
		{"truncated", func(a *rpc.Account) *rpc.Account { return &rpc.Account{Owner: a.Owner, Data: a.Data[:20]} }},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			f.cluster.accounts[f.wallet.payerUSDC] = nil
			tk := f.ticket(t)
			f.cluster.config = c.config(f.cluster.config)
			if _, err := f.ack(t, tk); err == nil {
				t.Fatal("an ack with no treasury to forfeit to was sent")
			}
			if len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
				t.Fatalf("%d sent, %d signed", len(f.cluster.acks), f.signer.asked.Load())
			}
		})
	}
}

// walletClusterNoStatus never reports a status, so a sent transaction expires
// once the height passes its blockhash.
type walletClusterNoStatus struct{ *walletCluster }

func (c *walletClusterNoStatus) GetSignatureStatuses(_ context.Context, sigs []solana.Signature, _ bool) ([]*rpc.SignatureStatus, error) {
	return make([]*rpc.SignatureStatus, len(sigs)), nil
}
