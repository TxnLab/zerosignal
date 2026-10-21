/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
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
		// judging a signer that is not an Algorand account.
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
}
