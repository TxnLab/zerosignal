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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

func TestDiagnose_SolanaRefusesAnAlgorandAddress(t *testing.T) {
	_, err := Diagnose(context.Background(), Config{Network: SolanaDevnet()}, testPayerAddr)
	if e, ok := err.(*Error); !ok || e.Code != "invalid_config" || !strings.Contains(e.Message, "not a Solana address") {
		t.Fatalf("err = %v, want the Solana address refusal", err)
	}
}

// encodeTokenAccount writes an SPL token account with no delegate, native
// amount or close authority.
func encodeTokenAccount(mint, owner solana.PublicKey, amount uint64, state zsescrow.TokenAccountState) []byte {
	b := make([]byte, zsescrow.TokenAccountSize)
	copy(b, mint[:])
	copy(b[32:], owner[:])
	binary.LittleEndian.PutUint64(b[64:], amount)
	b[108] = byte(state)
	return b
}

// Diagnose on a Solana network reads each reading from the cluster: the
// genesis hash against the Config's, the rents the cluster quotes, the
// payer's lamports, its token account for the Config's mint, and its rent
// pool. An Algorand Signer left on the Config is ignored.
func TestDiagnose_SolanaReadsTheCluster(t *testing.T) {
	program := zsescrow.ProgramID
	configAddr, configAcct, config := solanaConfigAccount(t, program)
	s := newTestSolanaSigner()
	payer := s.pub()
	d := zsescrow.Deployment{Program: program, Mint: config.USDCMint}
	ticketRent := (128 + uint64(zsescrow.TicketSize)) * 6_960
	poolRent := (128 + uint64(zsescrow.RentPoolSize)) * 6_960
	poolLamports := poolRent + 4*ticketRent
	const lamports, usdc = 50_000_000, 2_500_000

	account := func(key solana.PublicKey, owner solana.PublicKey, lamports uint64, data []byte) (string, solanaRegistryAccount) {
		return key.String(), solanaRegistryAccount{Pubkey: key.String(), Owner: owner.String(), Lamports: lamports, DataBase64: base64.StdEncoding.EncodeToString(data)}
	}
	ata := d.TokenAccount(payer)
	pool := d.RentPool(payer)
	defaults := Config{}.withDefaults()
	want := SolanaDoctorReadings{
		Network: SolanaClusterLocalnet, Address: payer.String(), Slots: uint64(defaults.ConcurrentSlots),
		RelayRequired: defaults.Privacy == PrivacyRelayRequired,
		BlockHeight:   1_000, Genesis: config.GenesisHash.String(),
		Program: program.String(), ConfigGenesis: config.GenesisHash.String(), Mint: config.USDCMint.String(),
		TicketRent: ticketRent, PoolRent: poolRent,
		Lamports:    lamports,
		UsdcAccount: true, UsdcBalance: usdc,
		PoolExists: true, PoolLamports: poolLamports, OpenTickets: 1,
	}

	tests := []struct {
		name    string
		edit    func(f *fakeSolanaRPC)
		readout func(r *SolanaDoctorReadings)
	}{
		{name: "healthy"},
		{
			name: "frozen token account",
			edit: func(f *fakeSolanaRPC) {
				k, a := account(ata, solana.TokenProgramID, 1, encodeTokenAccount(config.USDCMint, payer, usdc, zsescrow.TokenFrozen))
				f.accounts[k] = a
			},
			readout: func(r *SolanaDoctorReadings) { r.UsdcFrozen = true },
		},
		{
			name: "an account at the token address the token program doesn't own",
			edit: func(f *fakeSolanaRPC) {
				k, a := account(ata, program, 1, encodeTokenAccount(config.USDCMint, payer, usdc, zsescrow.TokenInitialized))
				f.accounts[k] = a
			},
			readout: func(r *SolanaDoctorReadings) {
				r.UsdcAccount, r.UsdcBalance = false, 0
				r.UsdcErr = ata.String() + " is not a token account"
			},
		},
		{
			name: "lamports at the pool address before any deposit",
			edit: func(f *fakeSolanaRPC) {
				k, a := account(pool, solana.SystemProgramID, 5_000, nil)
				f.accounts[k] = a
			},
			readout: func(r *SolanaDoctorReadings) { r.PoolExists, r.PoolLamports, r.OpenTickets = false, 0, 0 },
		},
		{
			name: "a paused program",
			edit: func(f *fakeSolanaRPC) {
				data, err := base64.StdEncoding.DecodeString(configAcct.DataBase64)
				if err != nil {
					t.Fatal(err)
				}
				data[13] = 1 // Config.paused, after the discriminator and five u8s
				a := configAcct
				a.DataBase64 = base64.StdEncoding.EncodeToString(data)
				f.accounts[configAddr] = a
			},
			readout: func(r *SolanaDoctorReadings) { r.ConfigPaused = true },
		},
		{
			name: "an RPC on another cluster",
			edit: func(f *fakeSolanaRPC) { f.genesis = solana.Hash{9} },
			readout: func(r *SolanaDoctorReadings) {
				r.Genesis = solana.Hash{9}.String()
			},
		},
		{
			name: "an unreadable balance",
			edit: func(f *fakeSolanaRPC) { f.balances = nil },
			readout: func(r *SolanaDoctorReadings) {
				r.Lamports, r.AccountErr = 0, fmt.Sprintf("solana rpc getBalance: %d unreadable", solanaRPCError)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeSolanaRPC{genesis: config.GenesisHash, accounts: map[string]solanaRegistryAccount{configAddr: configAcct}, balances: map[string]*uint64{payer.String(): new(uint64(lamports))}}
			k, a := account(ata, solana.TokenProgramID, 1, encodeTokenAccount(config.USDCMint, payer, usdc, zsescrow.TokenInitialized))
			fake.accounts[k] = a
			k, a = account(pool, program, poolLamports, encodeRentPool(payer, 1))
			fake.accounts[k] = a
			if tc.edit != nil {
				tc.edit(fake)
			}
			srv := httptest.NewServer(fake)
			t.Cleanup(srv.Close)
			network := SolanaLocalnet()
			network.Solana.RPCEndpoint = srv.URL
			rep, err := Diagnose(t.Context(), Config{Network: network, Signer: readOnlySigner(testPayerAddr), DisableTEE: true}, payer.String())
			if err != nil {
				t.Fatal(err)
			}
			r := want
			if tc.readout != nil {
				tc.readout(&r)
			}
			if wantChecks := SolanaDoctorChecks(r); !reflect.DeepEqual(rep.Checks, wantChecks) {
				t.Errorf("checks =\n  %+v\nwant\n  %+v", rep.Checks, wantChecks)
			}
			if rep.Network != SolanaClusterLocalnet || rep.Address != payer.String() || !rep.Failed {
				t.Errorf("report = %+v; an empty fleet fails it", rep)
			}
		})
	}
}

type fakeSolanaDoctorChain struct {
	clusterErr, configErr, usdcErr, balanceErr, poolErr, nodesErr error
	usdc                                                          *zsescrow.TokenAccount
	pool                                                          rentPoolReading
	ops                                                           []Operator
	calls                                                         []string
	mint                                                          solana.PublicKey
}

func (f *fakeSolanaDoctorChain) cluster(context.Context) (uint64, solana.Hash, error) {
	f.calls = append(f.calls, "cluster")
	return 42, solana.Hash{1}, f.clusterErr
}

func (f *fakeSolanaDoctorChain) config(context.Context) (*zsescrow.Config, uint64, uint64, error) {
	f.calls = append(f.calls, "config")
	if f.configErr != nil {
		return nil, 0, 0, f.configErr
	}
	return &zsescrow.Config{GenesisHash: solana.Hash{2}, USDCMint: solana.PublicKey{3}, Paused: true}, 2_000_000, 1_000_000, nil
}

func (f *fakeSolanaDoctorChain) balance(context.Context) (uint64, error) {
	f.calls = append(f.calls, "balance")
	return 7_000_000, f.balanceErr
}

func (f *fakeSolanaDoctorChain) usdcAccount(_ context.Context, mint solana.PublicKey) (*zsescrow.TokenAccount, error) {
	f.calls = append(f.calls, "usdc")
	f.mint = mint
	return f.usdc, f.usdcErr
}

func (f *fakeSolanaDoctorChain) rentPool(context.Context) (rentPoolReading, error) {
	f.calls = append(f.calls, "pool")
	return f.pool, f.poolErr
}

func (f *fakeSolanaDoctorChain) nodes(context.Context) ([]Operator, error) { return f.ops, f.nodesErr }

func TestGatherSolanaDoctorReadings_MapsEachRead(t *testing.T) {
	lamports, microAlgos := uint64(20_000), uint64(6_000_000)
	f := &fakeSolanaDoctorChain{
		usdc: &zsescrow.TokenAccount{Amount: 2_500_000, State: zsescrow.TokenFrozen},
		pool: rentPoolReading{exists: true, lamports: 9_000_000, openTickets: 2},
		ops: []Operator{
			// A node carries its own rail's reading; the doctor reads the
			// Solana one.
			{OwnerAddr: "A", Reachable: true, ProtoVersion: "9.13", Staging: true, SignerSpendableLamports: &lamports, SignerSpendableMicroAlgos: &microAlgos},
			{OwnerAddr: "B"},
		},
	}
	r := gatherSolanaDoctorReadings(context.Background(), f, SolanaDoctorReadings{Program: "P"})
	want := SolanaDoctorReadings{
		Program: "P", BlockHeight: 42, Genesis: solana.Hash{1}.String(),
		ConfigGenesis: solana.Hash{2}.String(), Mint: solana.PublicKey{3}.String(), ConfigPaused: true, TicketRent: 2_000_000, PoolRent: 1_000_000,
		Lamports:    7_000_000,
		UsdcAccount: true, UsdcFrozen: true, UsdcBalance: 2_500_000,
		PoolExists: true, PoolLamports: 9_000_000, OpenTickets: 2,
		Nodes: []DoctorNode{
			{Owner: "A", Reachable: true, ProtoVersion: "9.13", Staging: true, SignerSpendableLamports: &lamports},
			{Owner: "B"},
		},
	}
	if !reflect.DeepEqual(r, want) {
		t.Errorf("readings =\n  %+v\nwant\n  %+v", r, want)
	}
	if f.mint != (solana.PublicKey{3}) {
		t.Errorf("token account read for mint %s, want the Config's", f.mint)
	}
}

func TestGatherSolanaDoctorReadings_ReadsWhatItCan(t *testing.T) {
	tests := []struct {
		name      string
		chain     *fakeSolanaDoctorChain
		wantCalls string
		check     func(*testing.T, SolanaDoctorReadings)
	}{
		{
			name:      "the RPC down reads nothing else",
			chain:     &fakeSolanaDoctorChain{clusterErr: errors.New("refused")},
			wantCalls: "cluster",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.RPCErr != "refused" || r.Genesis != "" || r.Nodes != nil {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "no token account read without the Config's mint",
			chain:     &fakeSolanaDoctorChain{configErr: errors.New("no Config")},
			wantCalls: "cluster,config,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.ConfigErr != "no Config" || r.Mint != "" || r.TicketRent != 0 || r.Lamports != 7_000_000 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "no token account",
			chain:     &fakeSolanaDoctorChain{},
			wantCalls: "cluster,config,usdc,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.UsdcAccount || r.UsdcErr != "" {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a failed token account read",
			chain:     &fakeSolanaDoctorChain{usdcErr: errors.New("HTTP 503"), usdc: &zsescrow.TokenAccount{Amount: 5}},
			wantCalls: "cluster,config,usdc,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.UsdcErr != "HTTP 503" || r.UsdcAccount || r.UsdcBalance != 0 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a failed balance read keeps no lamports",
			chain:     &fakeSolanaDoctorChain{balanceErr: errors.New("HTTP 500")},
			wantCalls: "cluster,config,usdc,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.AccountErr != "HTTP 500" || r.Lamports != 0 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a failed pool read keeps no pool",
			chain:     &fakeSolanaDoctorChain{poolErr: errors.New("HTTP 429"), pool: rentPoolReading{exists: true, lamports: 5}},
			wantCalls: "cluster,config,usdc,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.PoolErr != "HTTP 429" || r.PoolExists || r.PoolLamports != 0 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "an empty fleet is not a failed read",
			chain:     &fakeSolanaDoctorChain{nodesErr: fmt.Errorf("%w for zs_escrow program P", errNoOperators)},
			wantCalls: "cluster,config,usdc,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.OperatorsErr != "" || len(r.Nodes) != 0 {
					t.Errorf("readings = %+v", r)
				}
			},
		},
		{
			name:      "a failed fleet read is",
			chain:     &fakeSolanaDoctorChain{nodesErr: errors.New("getProgramAccounts: 503")},
			wantCalls: "cluster,config,usdc,balance,pool",
			check: func(t *testing.T, r SolanaDoctorReadings) {
				if r.OperatorsErr != "getProgramAccounts: 503" {
					t.Errorf("readings = %+v", r)
				}
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gatherSolanaDoctorReadings(context.Background(), tc.chain, SolanaDoctorReadings{})
			if got := strings.Join(tc.chain.calls, ","); got != tc.wantCalls {
				t.Errorf("calls = %s, want %s", got, tc.wantCalls)
			}
			tc.check(t, r)
		})
	}
}

// rpcDoctorChain's fleet goes through SolanaChainReader and its lamports
// balance pass, and the doctor keeps each node's lamports reading. The nodes
// point at a server that answers no probe, so the fleet reads unreachable.
func TestRPCDoctorChain_ReadsTheFleet(t *testing.T) {
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
	probe := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(probe.Close)
	nodes := make([]solanaRegistryAccount, len(c.Nodes))
	for i, a := range c.Nodes {
		data, err := base64.StdEncoding.DecodeString(a.DataBase64)
		if err != nil {
			t.Fatal(err)
		}
		n, err := zsescrow.DecodeNode(data)
		if err != nil {
			t.Fatal(err)
		}
		n.BaseURL = probe.URL
		a.DataBase64 = base64.StdEncoding.EncodeToString(encodeSolanaNode(n))
		nodes[i] = a
	}
	short := selection.MinSignerSpendableLamports - 1
	balances := map[string]*uint64{}
	for _, w := range c.Want {
		balances[w.SigningAddr] = new(solanaSignerReserveLamports + short)
	}
	srv := httptest.NewServer(&fakeSolanaRPC{genesis: genesis, operators: c.Operators, nodes: nodes, balances: balances})
	t.Cleanup(srv.Close)
	rc, err := rpc.NewClient(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{AllowPrivateHosts: new(true), DisableTEE: true}.withDefaults()
	r := gatherSolanaDoctorReadings(t.Context(), &rpcDoctorChain{cfg: cfg, rpc: rc, program: program}, SolanaDoctorReadings{})
	if r.OperatorsErr != "" || len(r.Nodes) != len(c.Want) {
		t.Fatalf("operators err %q, %d nodes, want %d", r.OperatorsErr, len(r.Nodes), len(c.Want))
	}
	for i, n := range r.Nodes {
		if n.Owner != c.Want[i].OwnerAddr || n.Staging != c.Want[i].Staging || n.Reachable || n.SignerSpendable != nil ||
			n.SignerSpendableLamports == nil || *n.SignerSpendableLamports != short {
			t.Errorf("node %d = %+v, want owner %s, staging %t, unreachable, %d lamports spendable", i, n, c.Want[i].OwnerAddr, c.Want[i].Staging, short)
		}
	}
}

// solanaDoctorBase maps the Config onto what decides which nodes a request
// could reach.
func TestSolanaDoctorBase(t *testing.T) {
	sn := SolanaNetwork{Cluster: SolanaClusterDevnet, Program: zsescrow.ProgramID}
	for _, tc := range []struct {
		cfg           Config
		relayRequired bool
		allowStaging  bool
		slots         uint64
	}{
		{Config{}, true, false, DefaultDepositSlots},
		{Config{Privacy: PrivacyRelayRequired, ConcurrentSlots: 3}, true, false, 3},
		{Config{Privacy: PrivacyDirect, AllowStaging: true}, false, true, DefaultDepositSlots},
	} {
		r := solanaDoctorBase(tc.cfg.withDefaults(), sn, "PAYER")
		want := SolanaDoctorReadings{
			Network: SolanaClusterDevnet, Address: "PAYER", Slots: tc.slots, Program: zsescrow.ProgramID.String(),
			RelayRequired: tc.relayRequired, AllowStaging: tc.allowStaging,
		}
		if !reflect.DeepEqual(r, want) {
			t.Errorf("solanaDoctorBase(%+v) =\n  %+v\nwant\n  %+v", tc.cfg.Privacy, r, want)
		}
	}
}

func TestLamportsSOL(t *testing.T) {
	for v, want := range map[uint64]string{0: "0", 1: "0.000000001", 1_000_000_000: "1", 2_282_880: "0.00228288", 12_500_000_000: "12.5"} {
		if got := lamportsSOL(v); got != want {
			t.Errorf("lamportsSOL(%d) = %q, want %q", v, got, want)
		}
	}
}
