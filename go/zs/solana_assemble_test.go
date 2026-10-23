/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"encoding/base64"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// solanaConfigAccount is the program's initialized Config, as its tests
// wrote it, at the Config address of program.
func solanaConfigAccount(t *testing.T, program solana.PublicKey) (string, solanaRegistryAccount, *zsescrow.Config) {
	t.Helper()
	var av struct {
		Accounts []struct {
			Name  string `json:"name"`
			Owner string `json:"owner"`
			Data  string `json:"data_base64"`
		} `json:"accounts"`
	}
	readSolanaFixture(t, "solana_account_vectors.json", &av)
	for _, a := range av.Accounts {
		if a.Name != "config_initialized" {
			continue
		}
		data, err := base64.StdEncoding.DecodeString(a.Data)
		if err != nil {
			t.Fatal(err)
		}
		c, err := zsescrow.DecodeConfig(data)
		if err != nil {
			t.Fatal(err)
		}
		addr := zsescrow.Deployment{Program: program}.Config().String()
		return addr, solanaRegistryAccount{Pubkey: addr, Owner: program.String(), Lamports: 1, DataBase64: a.Data}, c
	}
	t.Fatal("no config_initialized account in solana_account_vectors.json")
	return "", solanaRegistryAccount{}, nil
}

// New on a Solana Network builds every part from the network alone: the
// wallet on the Config's mint, the reserve client signing as the Solana payer
// with the deployment the genesis hash and program name, and discovery
// through the program.
func TestNew_BuildsTheSolanaParts(t *testing.T) {
	program := zsescrow.ProgramID
	addr, acct, config := solanaConfigAccount(t, program)
	genesis := solana.Hash{9}
	srv := httptest.NewServer(&fakeSolanaRPC{genesis: genesis, accounts: map[string]solanaRegistryAccount{addr: acct}})
	t.Cleanup(srv.Close)

	// A pointer, so the parts can be checked for this very signer.
	s := newTestSolanaSigner()
	signer := &s
	network := SolanaLocalnet()
	network.Solana.RPCEndpoint, network.Solana.Program = srv.URL, program
	c, err := New(t.Context(), Config{
		SolanaSigner: signer,
		Network:      network,
		DisableTEE:   true,
		Discovery:    Discovery{OperatorIDs: []uint64{4}},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	cfg := c.Config()

	w, ok := cfg.Wallet.(*SolanaWallet)
	if !ok {
		t.Fatalf("wallet is %T, want *SolanaWallet", cfg.Wallet)
	}
	if w.deployment != (zsescrow.Deployment{Program: program, Mint: config.USDCMint}) {
		t.Errorf("wallet deployment %+v, want the program and the Config's mint %s", w.deployment, config.USDCMint)
	}
	if w.signer != SolanaSigner(signer) || w.slots != DefaultDepositSlots {
		t.Errorf("wallet signer %v slots %d", w.signer, w.slots)
	}

	want, err := ticket.SolanaDeploymentID(genesis[:], program[:])
	if err != nil {
		t.Fatal(err)
	}
	rc, ok := cfg.ReserveClient.(*HTTPReserveClient)
	if !ok {
		t.Fatalf("reserve client is %T", cfg.ReserveClient)
	}
	if rc.Signer != ticket.BytesSigner(signer) || rc.Rail != ticket.RailSolana || rc.Deployment != want {
		t.Errorf("reserve client signer %v rail %d deployment %x, want the Solana payer, rail and %x", rc.Signer, rc.Rail, rc.Deployment, want)
	}

	src, ok := cfg.Stores.RelayReputation.(*ChainOperatorSource)
	if !ok {
		t.Fatalf("relay reputation is %T, want the built chain source", cfg.Stores.RelayReputation)
	}
	reader, ok := src.Chain.(*SolanaChainReader)
	if !ok {
		t.Fatalf("chain reader is %T, want *SolanaChainReader", src.Chain)
	}
	if reader.Program != program || !slices.Equal(reader.OperatorIDs, []uint64{4}) || src.Deployment != want {
		t.Errorf("reader program %s ids %v, source deployment %x", reader.Program, reader.OperatorIDs, src.Deployment)
	}
	if src.Algod != nil || src.EscrowAppID != 0 {
		t.Errorf("source reads Algorand too: algod %v app %d", src.Algod, src.EscrowAppID)
	}

	if got := cfg.Network.Solana; got.Cluster != "localnet" || got.RPCEndpoint != srv.URL || got.Program != program {
		t.Errorf("Config().Network.Solana = %+v, want the resolved network", got)
	}
	if c.networkName() != "localnet" || c.deployment.Key() != "solana-localnet-"+program.String() {
		t.Errorf("network name %q key %q", c.networkName(), c.deployment.Key())
	}
}

// A program with no Config fails New, as an unreadable escrow app does on
// Algorand: the wallet cannot check an offer without the mint.
func TestNew_SolanaFailsWithoutAConfig(t *testing.T) {
	srv := httptest.NewServer(&fakeSolanaRPC{genesis: solana.Hash{9}})
	t.Cleanup(srv.Close)
	network := SolanaLocalnet()
	network.Solana.RPCEndpoint = srv.URL
	_, err := New(t.Context(), Config{SolanaSigner: newTestSolanaSigner(), Network: network, DisableTEE: true})
	if err == nil || !strings.Contains(err.Error(), "has no Config") {
		t.Fatalf("err = %v, want the missing Config", err)
	}
}

// An endpoint that is not http(s) is the caller's config, refused as such.
func TestNew_SolanaRefusesABadEndpoint(t *testing.T) {
	network := SolanaLocalnet()
	network.Solana.RPCEndpoint = "ftp://rpc.example"
	_, err := New(t.Context(), Config{SolanaSigner: newTestSolanaSigner(), Network: network, DisableTEE: true})
	if zerr, ok := err.(*Error); !ok || zerr.Code != "invalid_config" {
		t.Fatalf("err = %v, want invalid_config", err)
	}
}
