/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// fakeChainReader is a ChainReader that counts its calls.
type fakeChainReader struct {
	ops           []Operator
	readErr       error
	deployment    ticket.DeploymentID
	deploymentErr error
	reads, derive int
}

func (f *fakeChainReader) ReadChain(context.Context) ([]Operator, error) {
	f.reads++
	return f.ops, f.readErr
}

func (f *fakeChainReader) ReadDeployment(context.Context) (ticket.DeploymentID, error) {
	f.derive++
	return f.deployment, f.deploymentErr
}

func TestFetchChain_ReadsThroughTheChainReader(t *testing.T) {
	chain := &fakeChainReader{
		ops:        []Operator{{ID: 1, NodeID: 1, SigningAddr: "signer"}},
		deployment: ticket.DeploymentID{1},
	}
	balanceReads := 0
	s := &ChainOperatorSource{
		Chain: chain,
		// Set, so only the Chain gate keeps the algod balance pass from
		// judging a signer that is not an Algorand account. This reader reads
		// no balance of its own, so the signer stays unread.
		readSpendable: func(context.Context, string) (uint64, error) { balanceReads++; return 0, nil },
	}
	ops, err := s.FetchChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if chain.reads != 1 || len(ops) != 1 || ops[0].ID != 1 {
		t.Fatalf("reads = %d, ops = %+v; want the reader's one node", chain.reads, ops)
	}
	if balanceReads != 0 || ops[0].SignerSpendableMicroAlgos != nil {
		t.Fatalf("balance reads = %d, spendable = %v; want no algod pass for another rail's signers", balanceReads, ops[0].SignerSpendableMicroAlgos)
	}
	if s.deployment() != chain.deployment {
		t.Fatalf("deployment = %x, want the reader's", s.deployment())
	}
	if _, err := s.FetchChain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if chain.derive != 1 {
		t.Fatalf("ReadDeployment called %d times, want once: a derived id is kept", chain.derive)
	}
}

func TestFetchChain_ChainReaderDeployment(t *testing.T) {
	t.Run("a supplied deployment is not read", func(t *testing.T) {
		chain := &fakeChainReader{deployment: ticket.DeploymentID{1}}
		s := &ChainOperatorSource{Chain: chain, Deployment: ticket.DeploymentID{2}}
		if _, err := s.FetchChain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if chain.derive != 0 || s.deployment() != (ticket.DeploymentID{2}) {
			t.Fatalf("derive = %d, deployment = %x; want the supplied id unread", chain.derive, s.deployment())
		}
	})
	t.Run("a failed read is retried on the next chain read", func(t *testing.T) {
		chain := &fakeChainReader{deploymentErr: errors.New("rpc down")}
		s := &ChainOperatorSource{Chain: chain}
		if _, err := s.FetchChain(context.Background()); err != nil {
			t.Fatalf("FetchChain = %v; a failed genesis read must not fail the chain read", err)
		}
		if !s.deployment().IsZero() {
			t.Fatal("deployment set from a failed read")
		}
		chain.deploymentErr, chain.deployment = nil, ticket.DeploymentID{3}
		if _, err := s.FetchChain(context.Background()); err != nil {
			t.Fatal(err)
		}
		if chain.derive != 2 || s.deployment() != (ticket.DeploymentID{3}) {
			t.Fatalf("derive = %d, deployment = %x; want the second read's id", chain.derive, s.deployment())
		}
	})
	t.Run("a failed chain read fails before the deployment read", func(t *testing.T) {
		chain := &fakeChainReader{readErr: errors.New("rpc down")}
		s := &ChainOperatorSource{Chain: chain}
		if _, err := s.FetchChain(context.Background()); err == nil || chain.derive != 0 {
			t.Fatalf("FetchChain = %v, derive = %d; want the read's error and no genesis read", err, chain.derive)
		}
	})
}

// The registry's source over a Solana reader: the chain read and the
// deployment the probes check, from one fake RPC.
func TestChainOperatorSource_SolanaReader(t *testing.T) {
	raw, err := os.ReadFile(solanaRegistryVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		ProgramID   string `json:"program_id"`
		GenesisHash string `json:"genesis_hash"`
		Cases       []solanaRegistryCase
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	c := v.Cases[0]
	genesis, err := solana.ParseHash(v.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	program := solana.MustPublicKey(v.ProgramID)
	srv := httptest.NewServer(&fakeSolanaRPC{genesis: genesis, operators: c.Operators, nodes: c.Nodes})
	t.Cleanup(srv.Close)
	client, err := rpc.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	s := &ChainOperatorSource{Chain: &SolanaChainReader{RPC: client, Program: program}}
	var _ OperatorSource = s
	ops, err := s.FetchChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(ops) != len(c.Want) {
		t.Fatalf("ops = %d, want %d", len(ops), len(c.Want))
	}
	want, err := ticket.SolanaDeploymentID(genesis[:], program[:])
	if err != nil {
		t.Fatal(err)
	}
	if s.deployment() != want {
		t.Fatalf("deployment = %x, want %x: the probes would check bound signatures against the wrong id", s.deployment(), want)
	}
}

func TestSolanaChainReader_RequiresRPC(t *testing.T) {
	var r SolanaChainReader
	if _, err := r.ReadChain(context.Background()); err == nil {
		t.Fatal("ReadChain with no RPC succeeded")
	}
	if _, err := r.ReadDeployment(context.Background()); err == nil {
		t.Fatal("ReadDeployment with no RPC succeeded")
	}
	if _, err := r.ReadSignerSpendableLamports(context.Background(), "11111111111111111111111111111111"); err == nil {
		t.Fatal("ReadSignerSpendableLamports with no RPC succeeded")
	}
}

// An address that is not a key fails its read, which keeps the last reading,
// rather than reading some other account's balance.
func TestSolanaChainReader_RefusesANonKeySigner(t *testing.T) {
	srv := httptest.NewServer(&fakeSolanaRPC{})
	t.Cleanup(srv.Close)
	client, err := rpc.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	r := &SolanaChainReader{RPC: client}
	if _, err := r.ReadSignerSpendableLamports(context.Background(), "not-a-key"); err == nil {
		t.Fatal("read a balance for an address that is not a key")
	}
}

// The floor is the cost of one open under the program, and the reserve the
// rent-exempt minimum of an empty account, both at the ceiling rate the
// floor's doc cites. Spelled out here so a change to the Ticket layout fails
// this test rather than leaving the floor priced on the old size.
func TestMinSignerSpendableLamports_IsOneOpen(t *testing.T) {
	const (
		lamportsPerSignature = 5_000
		offerSignatures      = 2
		cuPriceMicroLamports = 1_000
		cuLimit              = 120_000
		accountOverhead      = 128
		lamportsPerByte      = 6_960
	)
	priority := (cuPriceMicroLamports*cuLimit + 999_999) / 1_000_000
	rent := uint64(accountOverhead+zsescrow.TicketSize) * lamportsPerByte
	if want := uint64(offerSignatures*lamportsPerSignature+priority) + rent; selection.MinSignerSpendableLamports != want {
		t.Fatalf("MinSignerSpendableLamports = %d, want %d", selection.MinSignerSpendableLamports, want)
	}
	if want := uint64(accountOverhead * lamportsPerByte); solanaSignerReserveLamports != want {
		t.Fatalf("solanaSignerReserveLamports = %d, want %d", solanaSignerReserveLamports, want)
	}

	// Both must bound what the program's own run charged: the floor its
	// Tickets' rent plus the fees, and the reserve an empty account at that
	// run's rate.
	raw, err := os.ReadFile(solanaAccountFixturesPath)
	if err != nil {
		t.Fatal(err)
	}
	var fx solanaAccountFixtures
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	fees := uint64(offerSignatures*lamportsPerSignature + priority)
	tickets := 0
	for _, a := range fx.Accounts {
		if a.Type != "Ticket" {
			continue
		}
		tickets++
		lamports, err := strconv.ParseUint(a.Lamports, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		data, err := base64.StdEncoding.DecodeString(a.DataBase64)
		if err != nil || len(data) != zsescrow.TicketSize {
			t.Fatalf("%s: %d bytes (%v), want %d", a.Name, len(data), err, zsescrow.TicketSize)
		}
		if fees+lamports > selection.MinSignerSpendableLamports {
			t.Errorf("%s: fees %d + rent %d exceed the floor %d", a.Name, fees, lamports, selection.MinSignerSpendableLamports)
		}
		if rate := lamports / (accountOverhead + zsescrow.TicketSize); accountOverhead*rate > solanaSignerReserveLamports {
			t.Errorf("%s: an empty account at %d lamports a byte exceeds the reserve %d", a.Name, rate, solanaSignerReserveLamports)
		}
	}
	if tickets == 0 {
		t.Fatal("no Ticket accounts in the program's fixtures")
	}
}

// The funding log lines name a reading in its own rail's unit and floor, so
// a Solana node is never reported as short of ALGO.
func TestSignerReadingAttrs(t *testing.T) {
	lamports, micro := uint64(7), uint64(9)
	cases := []struct {
		name      string
		op        Operator
		spendable slog.Attr
		floor     slog.Attr
	}{
		{"lamports", Operator{SignerSpendableLamports: &lamports},
			slog.Uint64("signer_spendable_lamports", 7), slog.Uint64("floor_lamports", selection.MinSignerSpendableLamports)},
		{"microAlgos", Operator{SignerSpendableMicroAlgos: &micro},
			slog.Uint64("signer_spendable_microalgos", 9), slog.Uint64("floor_microalgos", selection.MinSignerSpendableMicroAlgos)},
		{"unread", Operator{},
			slog.Uint64("signer_spendable_microalgos", 0), slog.Uint64("floor_microalgos", selection.MinSignerSpendableMicroAlgos)},
	}
	for _, tc := range cases {
		spendable, floor := signerReadingAttrs(tc.op)
		if !spendable.Equal(tc.spendable) || !floor.Equal(tc.floor) {
			t.Errorf("%s: attrs = %v, %v; want %v, %v", tc.name, spendable, floor, tc.spendable, tc.floor)
		}
	}
}

// fakeLamportsReader is a fakeChainReader over Solana: it answers a balance
// per signer, or failErr.
type fakeLamportsReader struct {
	fakeChainReader
	lamports     map[string]uint64
	failErr      error
	balanceReads int
}

func (f *fakeLamportsReader) ReadSignerSpendableLamports(_ context.Context, addr string) (uint64, error) {
	f.balanceReads++
	if f.failErr != nil {
		return 0, f.failErr
	}
	return f.lamports[addr], nil
}

func TestFetchChain_ReadsSolanaSignersThroughTheReader(t *testing.T) {
	chain := &fakeLamportsReader{
		fakeChainReader: fakeChainReader{ops: []Operator{{ID: 1, NodeID: 1, SigningAddr: "signer"}}},
		lamports:        map[string]uint64{"signer": selection.MinSignerSpendableLamports - 1},
	}
	algodReads := 0
	s := &ChainOperatorSource{
		Chain:         chain,
		Log:           slog.New(slog.DiscardHandler),
		readSpendable: func(context.Context, string) (uint64, error) { algodReads++; return 0, nil },
	}
	ops, err := s.FetchChain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if algodReads != 0 || ops[0].SignerSpendableMicroAlgos != nil {
		t.Fatalf("algod reads = %d, microAlgos = %v; want the reader's pass alone", algodReads, ops[0].SignerSpendableMicroAlgos)
	}
	if v := ops[0].SignerSpendableLamports; v == nil || *v != selection.MinSignerSpendableLamports-1 || !ops[0].SignerUnderfunded() {
		t.Fatalf("lamports = %v, underfunded = %v; want the reading below the floor, held out", v, ops[0].SignerUnderfunded())
	}
	chain.failErr = errors.New("rpc down")
	ops, err = s.FetchChain(context.Background())
	if err != nil {
		t.Fatalf("FetchChain = %v; a failed balance read must not fail the chain read", err)
	}
	if chain.balanceReads != 2 || !ops[0].SignerUnderfunded() {
		t.Fatalf("balance reads = %d, underfunded = %v; want a failed re-read to keep the node held out", chain.balanceReads, ops[0].SignerUnderfunded())
	}
}
