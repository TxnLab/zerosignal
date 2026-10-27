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
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/settle"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

// configFeeOffset is where the Config keeps fee_bps: after the discriminator
// and seven one-byte fields.
const configFeeOffset = 8 + 7

// The wallet's fee rate is the Config's, read each time, so a set_config
// reaches the next read.
func TestSolanaWallet_ProtocolFeeBpsIsTheConfigs(t *testing.T) {
	f := newSolanaOpenFixture(t, 0, 3)
	cfg, err := zsescrow.DecodeConfig(f.cluster.config.Data)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := f.wallet.ProtocolFeeBps(t.Context()); err != nil || got != uint64(cfg.FeeBps) || got == 0 {
		t.Fatalf("ProtocolFeeBps = %d, %v; the Config's is %d", got, err, cfg.FeeBps)
	}
	data := append([]byte(nil), f.cluster.config.Data...)
	binary.LittleEndian.PutUint16(data[configFeeOffset:], 1234)
	if c, err := zsescrow.DecodeConfig(data); err != nil || c.FeeBps != 1234 {
		t.Fatalf("configFeeOffset is off: %+v, %v", c, err)
	}
	f.cluster.config = &rpc.Account{Owner: f.cluster.config.Owner, Data: data}
	if got, err := f.wallet.ProtocolFeeBps(t.Context()); err != nil || got != 1234 {
		t.Fatalf("after set_config: ProtocolFeeBps = %d, %v; want 1234", got, err)
	}
	f.cluster.config = nil
	if _, err := f.wallet.ProtocolFeeBps(t.Context()); err == nil {
		t.Fatal("a program with no Config has a fee rate")
	}
}

// The serving path reaches the fee through feeRateCapable, so a Solana
// payer's catalog is priced and its reserve check bounded by the Config's
// fee rather than the cap.
func TestSolanaWallet_FeeRateReachesTheClient(t *testing.T) {
	f := newSolanaOpenFixture(t, 0, 3)
	c := &Client{wallet: f.wallet}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if fee, ok := c.feeRateNow(); ok {
			cfg, _ := zsescrow.DecodeConfig(f.cluster.config.Data)
			if fee != uint64(cfg.FeeBps) {
				t.Fatalf("feeRateNow = %d, the Config's is %d", fee, cfg.FeeBps)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the fee rate never warmed")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestSolanaWallet_EnsureUSDCAccount(t *testing.T) {
	f := newSolanaAckFixture(t)
	if sig, err := f.wallet.EnsureUSDCAccount(t.Context()); err != nil || sig != "" || len(f.cluster.acks) != 0 {
		t.Fatalf("with the account there: %q, %v; %d sent", sig, err, len(f.cluster.acks))
	}
	if f.wallet.USDCAccount() != f.wallet.payerUSDC.String() {
		t.Fatalf("USDCAccount %s", f.wallet.USDCAccount())
	}
	for _, absent := range []*rpc.Account{nil, {Owner: solana.SystemProgramID, Lamports: 1}} {
		f.cluster.accounts[f.wallet.payerUSDC] = absent
		n := len(f.cluster.acks)
		sig, err := f.wallet.EnsureUSDCAccount(t.Context())
		if err != nil || len(f.cluster.acks) != n+1 || sig != f.cluster.acks[n].Signatures[0].String() {
			t.Fatalf("with no token account: %q, %v; %d sent", sig, err, len(f.cluster.acks)-n)
		}
		want, err := solana.Compile(f.wallet.payer, f.cluster.blockhash,
			[]solana.Instruction{solana.CreateAssociatedTokenAccountIdempotent(f.wallet.payer, f.wallet.payer, f.cluster.d.Mint)}, solana.Legacy)
		if err != nil {
			t.Fatal(err)
		}
		wantMsg, _ := want.MarshalBinary()
		gotMsg, _ := f.cluster.acks[n].Message.MarshalBinary()
		if !bytes.Equal(gotMsg, wantMsg) {
			t.Fatal("the create is not the idempotent ATA create for the Config's mint, paid by the payer")
		}
	}
}

// RecoverTicket sends the ending the verdict on a fresh read names, and
// nothing for any other verdict. A deadline passed by less than the skew the
// cluster's clock may trail by still waits.
func TestSolanaWallet_RecoverTicket(t *testing.T) {
	past, inSkew := reconcileSkew+time.Second, reconcileSkew-time.Second
	for _, c := range []struct {
		name    string
		status  zsescrow.TicketStatus
		pending uint64
		ago     time.Duration
		verdict settle.Verdict
		ix      func(zsescrow.Deployment, zsescrow.Ending) solana.Instruction
	}{
		{"open past the deadline", zsescrow.TicketOpen, 0, past, settle.VerdictRefund, zsescrow.Deployment.RefundInactive},
		{"payer's half past the deadline", zsescrow.TicketPendingByPayer, 7, past, settle.VerdictRefund, zsescrow.Deployment.RefundInactive},
		{"node's claim past the deadline", zsescrow.TicketPendingByOperator, 7, past, settle.VerdictLapse, zsescrow.Deployment.SettleLapsed},
		{"node's claim in the window", zsescrow.TicketPendingByOperator, 7, -time.Hour, settle.VerdictWait, nil},
		{"open within the skew", zsescrow.TicketOpen, 0, inSkew, settle.VerdictWait, nil},
		{"node's claim within the skew", zsescrow.TicketPendingByOperator, 7, inSkew, settle.VerdictWait, nil},
		{"frozen", zsescrow.TicketFrozen, 7, past, settle.VerdictArbitrate, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newSolanaAckFixture(t)
			f.setTicket(t, c.status, c.pending, nil)
			f.setTicketDeadline(t, f.wallet.now().Add(-c.ago))
			tk := f.ticket(t)
			verdict, sig, err := f.wallet.RecoverTicket(t.Context(), f.operatorID, f.nodeID, f.ticketID)
			if err != nil || verdict != c.verdict {
				t.Fatalf("RecoverTicket = %s, %v; want %s", verdict, err, c.verdict)
			}
			if c.ix == nil {
				if sig != "" || len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
					t.Fatalf("sent %q: %d sent, %d signed", sig, len(f.cluster.acks), f.signer.asked.Load())
				}
				return
			}
			if len(f.cluster.acks) != 1 || sig != f.cluster.acks[0].Signatures[0].String() {
				t.Fatalf("sig %q, %d sent", sig, len(f.cluster.acks))
			}
			e := zsescrow.Ending{Submitter: f.wallet.payer, OperatorID: f.operatorID, NodeID: f.nodeID, TicketID: f.ticketID,
				RentPayer: tk.RentPayer, Payer: f.wallet.payer}
			want, err := solana.Compile(f.wallet.payer, f.cluster.blockhash, []solana.Instruction{c.ix(f.cluster.d, e)}, solana.Legacy)
			if err != nil {
				t.Fatal(err)
			}
			wantMsg, _ := want.MarshalBinary()
			gotMsg, _ := f.cluster.acks[0].Message.MarshalBinary()
			if !bytes.Equal(gotMsg, wantMsg) {
				t.Fatal("the ending is not the verdict's over the ticket account")
			}
		})
	}
}

// Closing the pool through the wallet clears the ready latch, as
// Wallet.CloseDeposit does, so the next open tops the pool up again rather
// than signing an offer the program refuses for want of a pool. A close that
// fails clears it too: it may have landed.
func TestSolanaWallet_CloseRentPoolClearsTheLatch(t *testing.T) {
	f := newSolanaOpenFixture(t, 1_000_000_000, 3)
	if f.wallet.RentPool() != f.wallet.pool {
		t.Fatal("RentPool is not the wallet's pool")
	}
	f.wallet.depositReady = true
	_, _, _ = f.wallet.CloseRentPool(t.Context())
	if f.wallet.depositReady {
		t.Fatal("the latch survived the close")
	}
}

// A ticket that is gone, or another payer's, sends nothing and asks the
// signer nothing.
func TestSolanaWallet_RecoverTicketRefuses(t *testing.T) {
	f := newSolanaAckFixture(t)
	f.cluster.accounts[f.ticketAddr] = nil
	if _, _, err := f.wallet.RecoverTicket(t.Context(), f.operatorID, f.nodeID, f.ticketID); !errors.Is(err, ErrSolanaTicketGone) {
		t.Fatalf("a gone ticket: %v", err)
	}

	f = newSolanaAckFixture(t)
	f.setTicketDeadline(t, f.wallet.now().Add(-time.Minute))
	tk := *f.ticket(t)
	data := append([]byte(nil), f.cluster.accounts[f.ticketAddr].Data...)
	other := solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG")
	copy(data[zsescrow.TicketPayerOffset:], other[:])
	if !bytes.Equal(f.cluster.accounts[f.ticketAddr].Data[zsescrow.TicketPayerOffset:][:32], tk.Payer[:]) {
		t.Fatal("TicketPayerOffset is off")
	}
	f.cluster.accounts[f.ticketAddr] = &rpc.Account{Owner: f.cluster.d.Program, Data: data}
	if _, _, err := f.wallet.RecoverTicket(t.Context(), f.operatorID, f.nodeID, f.ticketID); err == nil || !strings.Contains(err.Error(), "not this wallet's") {
		t.Fatalf("another payer's ticket: %v", err)
	}
	if len(f.cluster.acks) != 0 || f.signer.asked.Load() != 0 {
		t.Fatalf("%d sent, %d signed", len(f.cluster.acks), f.signer.asked.Load())
	}
}

// programAccounts is a cluster that answers getProgramAccounts by applying
// the filters it is sent, as an RPC does, and getAccountInfo from the same
// accounts.
type programAccounts struct {
	rpc.Client
	program  solana.PublicKey
	accounts map[solana.PublicKey]*rpc.Account
	filters  [][]rpc.Filter
	readErr  error
}

func (c *programAccounts) GetProgramAccounts(_ context.Context, program solana.PublicKey, cm rpc.Commitment, filters ...rpc.Filter) ([]rpc.KeyedAccount, error) {
	if program != c.program || cm != rpc.Confirmed {
		panic("program accounts of " + program.String() + " at " + string(cm))
	}
	c.filters = append(c.filters, filters)
	var out []rpc.KeyedAccount
	for k, a := range c.accounts {
		if a.Owner == program && matchesAll(a.Data, filters) {
			out = append(out, rpc.KeyedAccount{Key: k, Account: *a})
		}
	}
	return out, nil
}

func (c *programAccounts) GetAccountInfo(_ context.Context, k solana.PublicKey, cm rpc.Commitment) (*rpc.Account, error) {
	if cm != rpc.Confirmed {
		panic("read at " + string(cm))
	}
	if c.readErr != nil {
		return nil, c.readErr
	}
	a, ok := c.accounts[k]
	if !ok {
		return nil, rpc.ErrNotFound
	}
	cp := *a
	return &cp, nil
}

func matchesAll(data []byte, filters []rpc.Filter) bool {
	for _, f := range filters {
		var w struct {
			Memcmp *struct {
				Offset uint64 `json:"offset"`
				Bytes  string `json:"bytes"`
			} `json:"memcmp"`
		}
		b, _ := json.Marshal(f)
		if err := json.Unmarshal(b, &w); err != nil || w.Memcmp == nil {
			panic("filter " + string(b))
		}
		want, _ := base64.StdEncoding.DecodeString(w.Memcmp.Bytes)
		end := w.Memcmp.Offset + uint64(len(want))
		if end > uint64(len(data)) || !bytes.Equal(data[w.Memcmp.Offset:end], want) {
			return false
		}
	}
	return true
}

// payerTicketWorld is every account of the shared fixtures, keyed by address:
// five tickets of one payer at one node, the node, and the rest.
func payerTicketWorld(t *testing.T) (*programAccounts, zsescrow.Deployment, solana.PublicKey, map[string]solana.PublicKey) {
	t.Helper()
	var av struct {
		ProgramID solana.PublicKey `json:"program_id"`
		Accounts  []struct {
			Name    string           `json:"name"`
			Address solana.PublicKey `json:"address"`
			Owner   solana.PublicKey `json:"owner"`
			Data    string           `json:"data_base64"`
		} `json:"accounts"`
	}
	readSolanaFixture(t, "solana_account_vectors.json", &av)
	c := &programAccounts{program: av.ProgramID, accounts: map[solana.PublicKey]*rpc.Account{}}
	named := map[string]solana.PublicKey{}
	for _, a := range av.Accounts {
		data, _ := base64.StdEncoding.DecodeString(a.Data)
		c.accounts[a.Address] = &rpc.Account{Owner: a.Owner, Data: data}
		named[a.Name] = a.Address
	}
	tk, err := zsescrow.DecodeTicket(c.accounts[named["ticket_open"]].Data)
	if err != nil {
		t.Fatal(err)
	}
	return c, zsescrow.Deployment{Program: av.ProgramID}, tk.Payer, named
}

func TestFetchSolanaPayerTickets(t *testing.T) {
	c, d, payer, named := payerTicketWorld(t)
	node, err := zsescrow.DecodeNode(c.accounts[named["node_with_metrics"]].Data)
	if err != nil {
		t.Fatal(err)
	}
	tickets := []string{"ticket_open", "ticket_pending", "ticket_pending_by_payer", "ticket_frozen", "ticket_disputed"}
	// Another payer's ticket, which the filter leaves on the cluster.
	other := append([]byte(nil), c.accounts[named["ticket_open"]].Data...)
	copy(other[zsescrow.TicketPayerOffset:], solana.MustPublicKey("3Atsbq9N5EaCc9YWmqD2rUVedX4pqDe7hyk6JSyWRTrG").Bytes())
	c.accounts[solana.PublicKey{1}] = &rpc.Account{Owner: d.Program, Data: other}

	got, err := FetchSolanaPayerTickets(t.Context(), c, d, payer)
	if err != nil {
		t.Fatal(err)
	}
	// The read moves the payer's tickets alone: Tickets, by the
	// discriminator, of this payer, at its offset.
	disc := zsescrow.AccountDiscriminator("Ticket")
	wantFilters, _ := json.Marshal([]rpc.Filter{rpc.Memcmp(0, disc[:]), rpc.Memcmp(131, payer[:])})
	if sent, _ := json.Marshal(c.filters[0]); len(c.filters) != 1 || !bytes.Equal(sent, wantFilters) {
		t.Fatalf("filters %s, want %s", sent, wantFilters)
	}
	if len(got.Unreadable) != 0 || len(got.Tickets) != len(tickets) {
		t.Fatalf("%d tickets, %d unreadable: %+v", len(got.Tickets), len(got.Unreadable), got.Unreadable)
	}
	listed := map[solana.PublicKey]bool{}
	for _, pt := range got.Tickets {
		listed[pt.Address] = true
		if pt.OperatorID != node.OperatorID || pt.NodeID != node.NodeID || pt.Ticket.Payer != payer {
			t.Errorf("%s at %d/%d paid by %s", pt.Address, pt.OperatorID, pt.NodeID, pt.Ticket.Payer)
		}
	}
	for _, n := range tickets {
		if !listed[named[n]] {
			t.Errorf("%s not listed", n)
		}
	}
}

// The listing is ordered by deadline, the soonest first, and by address
// between equal deadlines. The fixtures share one deadline, so this moves
// them apart.
func TestFetchSolanaPayerTickets_SoonestFirst(t *testing.T) {
	c, d, payer, named := payerTicketWorld(t)
	const base = 1_790_000_000
	for n, at := range map[string]int64{"ticket_open": 500, "ticket_pending": 100, "ticket_pending_by_payer": 300, "ticket_frozen": 100, "ticket_disputed": 400} {
		data := c.accounts[named[n]].Data
		tk, err := zsescrow.DecodeTicket(data)
		if err != nil {
			t.Fatal(err)
		}
		binary.LittleEndian.PutUint64(data[ticketExpiresAtOffset:], uint64(base+at-int64(tk.Grace)))
		if tk, _ = zsescrow.DecodeTicket(data); tk.Deadline() != base+at {
			t.Fatalf("%s: deadline %d, want %d", n, tk.Deadline(), base+at)
		}
	}
	tied := []solana.PublicKey{named["ticket_pending"], named["ticket_frozen"]}
	if bytes.Compare(tied[0][:], tied[1][:]) > 0 {
		tied[0], tied[1] = tied[1], tied[0]
	}
	want := append(tied, named["ticket_pending_by_payer"], named["ticket_disputed"], named["ticket_open"])
	got, err := FetchSolanaPayerTickets(t.Context(), c, d, payer)
	if err != nil {
		t.Fatal(err)
	}
	var order []solana.PublicKey
	for _, pt := range got.Tickets {
		order = append(order, pt.Address)
	}
	if !slices.Equal(order, want) {
		t.Fatalf("order %v, want %v", order, want)
	}
}

// What matches the payer's filter but can't be read as one of its tickets is
// reported, not dropped; a node read that fails fails the listing.
func TestFetchSolanaPayerTickets_ReportsTheUnreadable(t *testing.T) {
	c, d, payer, named := payerTicketWorld(t)
	base := c.accounts[named["ticket_open"]].Data
	edit := func(off int, b []byte) []byte {
		data := append([]byte(nil), base...)
		copy(data[off:], b)
		return data
	}
	nodeless := solana.PublicKey{2}
	moved := solana.PublicKey{3}
	newer := solana.PublicKey{4}
	c.accounts[nodeless] = &rpc.Account{Owner: d.Program, Data: edit(zsescrow.TicketPayerOffset+32, bytes.Repeat([]byte{9}, 32))}
	c.accounts[moved] = &rpc.Account{Owner: d.Program, Data: base}
	c.accounts[newer] = &rpc.Account{Owner: d.Program, Data: edit(8, []byte{zsescrow.AccountVersion + 1})}
	// A Node account at a key its ids don't derive: placing the ticket by
	// those ids would list it at another node.
	impostorNode := solana.PublicKey{5}
	c.accounts[impostorNode] = &rpc.Account{Owner: d.Program, Data: c.accounts[named["node_with_metrics"]].Data}
	impostor := solana.PublicKey{6}
	c.accounts[impostor] = &rpc.Account{Owner: d.Program, Data: edit(zsescrow.TicketPayerOffset+32, impostorNode[:])}

	got, err := FetchSolanaPayerTickets(t.Context(), c, d, payer)
	if err != nil {
		t.Fatal(err)
	}
	why := map[solana.PublicKey]string{}
	for _, u := range got.Unreadable {
		why[u.Address] = u.Err.Error()
	}
	for k, want := range map[solana.PublicKey]string{nodeless: "not a readable node", moved: "doesn't derive its address", newer: "version", impostor: "not a readable node"} {
		if !strings.Contains(why[k], want) {
			t.Errorf("%s: %q, want %q", k, why[k], want)
		}
	}
	if len(got.Unreadable) != 4 || len(got.Tickets) != 5 {
		t.Fatalf("%d tickets, %d unreadable", len(got.Tickets), len(got.Unreadable))
	}

	c.readErr = errors.New("rpc down")
	if _, err := FetchSolanaPayerTickets(t.Context(), c, d, payer); err == nil || !strings.Contains(err.Error(), "rpc down") {
		t.Fatalf("a failed node read: %v", err)
	}
}
