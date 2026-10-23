/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/deployment_vectors.json: how a Network
// resolves to its deployment key, and which journal rows a deployment owns.
// The key names files and storage on disk, so two SDKs that disagree on it
// strand each other's journals.
//
//	cd proto/go && go test ./zs -run TestDeploymentVectors -update

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const deploymentVectorsPath = "../../testdata/deployment_vectors.json"

// solanaOtherProgram is a program id no preset has: the vote program's.
const solanaOtherProgram = "Vote111111111111111111111111111111111111111"

// solanaZeroProgram is the all-zero key in base58.
const solanaZeroProgram = "11111111111111111111111111111111"

// deploymentInput is a Network in the fixture's terms; rail is a RailName, or
// empty for the zero value. network is the preset on either rail, as the TS
// Network has one name field; endpoint, token and escrow_app_id are always
// Algorand's, and rpc_endpoint and program Solana's, so a vector can set the
// other rail's.
type deploymentInput struct {
	Rail        string `json:"rail,omitempty"`
	Network     string `json:"network,omitempty"`
	Endpoint    string `json:"endpoint,omitempty"`
	Token       string `json:"token,omitempty"`
	EscrowAppID uint64 `json:"escrow_app_id,omitempty"`
	RPCEndpoint string `json:"rpc_endpoint,omitempty"`
	Program     string `json:"program,omitempty"`
}

func (in deploymentInput) network(t *testing.T) Network {
	t.Helper()
	n := Network{Algod: algod.Config{Endpoint: in.Endpoint, Token: in.Token}, EscrowAppID: in.EscrowAppID}
	n.Solana.RPCEndpoint = in.RPCEndpoint
	if in.Program != "" {
		n.Solana.Program = solana.MustPublicKey(in.Program)
	}
	switch in.Rail {
	case "", "algorand":
		if in.Rail != "" {
			n.Rail = ticket.RailAlgorand
		}
		n.Algod.Network = in.Network
	case "solana":
		n.Rail = ticket.RailSolana
		n.Solana.Cluster = in.Network
	default:
		t.Fatalf("unknown rail %q", in.Rail)
	}
	return n
}

type deploymentResolveCase struct {
	Name  string          `json:"name"`
	Input deploymentInput `json:"input"`
	// Error is the error code when the Network is refused; the rest is then empty.
	Error     string `json:"error,omitempty"`
	Rail      string `json:"rail,omitempty"`
	Label     string `json:"label,omitempty"`
	Key       string `json:"key,omitempty"`
	LegacyKey string `json:"legacy_key,omitempty"`
	// RPCEndpoint and Program are a Solana deployment's, resolved.
	RPCEndpoint string `json:"rpc_endpoint,omitempty"`
	Program     string `json:"program,omitempty"`
}

type deploymentRow struct {
	Deployment  string `json:"deployment"`
	EscrowAppID uint64 `json:"escrow_app_id"`
	Owns        bool   `json:"owns"`
}

type deploymentScopeCase struct {
	Name  string          `json:"name"`
	Input deploymentInput `json:"input"`
	Rows  []deploymentRow `json:"rows"`
}

type deploymentVectors struct {
	Resolve []deploymentResolveCase `json:"resolve"`
	Scope   []deploymentScopeCase   `json:"scope"`
}

func buildDeploymentVectors(t *testing.T) deploymentVectors {
	t.Helper()
	inputs := []struct {
		name string
		in   deploymentInput
	}{
		{"zero network is mainnet", deploymentInput{}},
		{"explicit rail is the zero rail", deploymentInput{Rail: "algorand"}},
		{"testnet preset", deploymentInput{Network: "testnet"}},
		{"names are case-insensitive", deploymentInput{Network: "MainNet"}},
		{"mainnet's app by endpoint alone is mainnet", deploymentInput{Endpoint: "https://algod.example/", EscrowAppID: 3628061142}},
		{"a preset's app id wins over the named network", deploymentInput{Network: "localnet", EscrowAppID: 765860477}},
		{"another app on testnet keeps testnet", deploymentInput{Network: "testnet", EscrowAppID: 42}},
		{"the same app id on mainnet is another deployment", deploymentInput{Network: "mainnet", EscrowAppID: 42}},
		{"localnet with an app", deploymentInput{Network: "localnet", EscrowAppID: 1001}},
		{"an endpoint with an app is custom", deploymentInput{Endpoint: "http://localhost:4001", EscrowAppID: 1001}},
		{"localnet needs an app", deploymentInput{Network: "localnet"}},
		{"an endpoint needs an app", deploymentInput{Endpoint: "http://localhost:4001"}},
		{"an app id alone names no chain", deploymentInput{EscrowAppID: 7}},
		{"a token alone names no chain", deploymentInput{Token: "t"}},
		{"unknown network", deploymentInput{Network: "devnet"}},
		{"solana devnet preset", deploymentInput{Rail: "solana", Network: "devnet"}},
		{"solana localnet preset", deploymentInput{Rail: "solana", Network: "localnet"}},
		{"solana names are case-insensitive", deploymentInput{Rail: "solana", Network: "DevNet"}},
		{"another program on localnet keeps localnet", deploymentInput{Rail: "solana", Network: "localnet", Program: solanaOtherProgram}},
		{"a solana endpoint overriding a preset keeps the preset", deploymentInput{Rail: "solana", Network: "devnet", RPCEndpoint: "https://rpc.example/?api-key=k"}},
		{"a solana endpoint with a program is custom", deploymentInput{Rail: "solana", RPCEndpoint: "http://127.0.0.1:8899", Program: solanaOtherProgram}},
		{"a solana endpoint needs a program", deploymentInput{Rail: "solana", RPCEndpoint: "http://127.0.0.1:8899"}},
		{"the zero solana network names no cluster", deploymentInput{Rail: "solana"}},
		{"a program alone names no cluster", deploymentInput{Rail: "solana", Program: solanaOtherProgram}},
		// The all-zero key is Go's zero Program, so it reads as unset.
		{"the zero program takes the preset's", deploymentInput{Rail: "solana", Network: "devnet", Program: solanaZeroProgram}},
		{"the zero program is no program for an endpoint", deploymentInput{Rail: "solana", RPCEndpoint: "http://127.0.0.1:8899", Program: solanaZeroProgram}},
		{"testnet is no solana preset", deploymentInput{Rail: "solana", Network: "testnet"}},
		{"solana refuses an algod endpoint", deploymentInput{Rail: "solana", Network: "devnet", Endpoint: "http://localhost:4001"}},
		{"solana refuses an algod token", deploymentInput{Rail: "solana", Network: "devnet", Token: "t"}},
		{"solana refuses an app id", deploymentInput{Rail: "solana", Network: "devnet", EscrowAppID: 7}},
		{"algorand refuses a solana endpoint", deploymentInput{Network: "testnet", RPCEndpoint: "http://127.0.0.1:8899"}},
		{"algorand refuses a program", deploymentInput{Network: "testnet", Program: solanaOtherProgram}},
	}
	var v deploymentVectors
	for _, c := range inputs {
		rc := deploymentResolveCase{Name: c.name, Input: c.in}
		d, _, err := ResolveNetwork(c.in.network(t))
		if err != nil {
			var zerr *Error
			if !errors.As(err, &zerr) {
				t.Fatalf("%s: %v is not a *Error", c.name, err)
			}
			rc.Error = zerr.Code
		} else {
			rc.Rail, rc.Label, rc.Key, rc.LegacyKey = RailName(d.Rail), d.Network, d.Key(), d.LegacyKey()
			if d.Rail == ticket.RailSolana {
				rc.RPCEndpoint, rc.Program = d.Solana.RPCEndpoint, d.Solana.Program.String()
			}
		}
		v.Resolve = append(v.Resolve, rc)
	}

	scopes := []struct {
		name string
		in   deploymentInput
		rows []TicketRecord
	}{
		{"mainnet", deploymentInput{Network: "mainnet"}, []TicketRecord{
			{Deployment: "algorand-mainnet-3628061142", EscrowAppID: 3628061142},
			{EscrowAppID: 3628061142},
			{EscrowAppID: 765860477},
			{},
			// A named row is judged by its name, never its app id.
			{Deployment: "algorand-custom-3628061142", EscrowAppID: 3628061142},
			{Deployment: "algorand-mainnet-3628061142", EscrowAppID: 1},
			{Deployment: "solana-mainnet-ZsEscrow1111111111111111111111111111111111111"},
		}},
		{"testnet's app 42", deploymentInput{Network: "testnet", EscrowAppID: 42}, []TicketRecord{
			{Deployment: "algorand-testnet-42", EscrowAppID: 42},
			{Deployment: "algorand-mainnet-42", EscrowAppID: 42},
		}},
		{"localnet", deploymentInput{Network: "localnet", EscrowAppID: 1001}, []TicketRecord{
			{Deployment: "algorand-localnet-1001", EscrowAppID: 1001},
			{EscrowAppID: 1001},
			{Deployment: "algorand-custom-1001", EscrowAppID: 1001},
		}},
		// A Solana row always names its deployment: a row without one is
		// Algorand's, whatever its app id.
		{"solana devnet", deploymentInput{Rail: "solana", Network: "devnet"}, []TicketRecord{
			{Deployment: "solana-devnet-" + zsescrow.ProgramID.String()},
			{Deployment: "solana-localnet-" + zsescrow.ProgramID.String()},
			{Deployment: "solana-devnet-" + solanaOtherProgram},
			{},
			{EscrowAppID: 1001},
		}},
	}
	for _, s := range scopes {
		d, _, err := ResolveNetwork(s.in.network(t))
		if err != nil {
			t.Fatal(err)
		}
		sc := deploymentScopeCase{Name: s.name, Input: s.in}
		for _, r := range s.rows {
			sc.Rows = append(sc.Rows, deploymentRow{Deployment: r.Deployment, EscrowAppID: r.EscrowAppID, Owns: d.Owns(r)})
		}
		v.Scope = append(v.Scope, sc)
	}
	return v
}

func TestDeploymentVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildDeploymentVectors(t), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(deploymentVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(deploymentVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (run with -update to create it)", deploymentVectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s is stale; run: go test ./zs -run TestDeploymentVectors -update", deploymentVectorsPath)
	}
}

// The keys are file names on disk, so they are pinned as literals too: a
// change to the label rule must fail here, not only regenerate the fixture.
func TestDeploymentKeysPinned(t *testing.T) {
	for in, want := range map[deploymentInput]string{
		{}:                                     "algorand-mainnet-3628061142",
		{Network: "testnet"}:                   "algorand-testnet-765860477",
		{Network: "localnet", EscrowAppID: 5}:  "algorand-localnet-5",
		{Network: "testnet", EscrowAppID: 42}:  "algorand-testnet-42",
		{Endpoint: "http://x", EscrowAppID: 5}: "algorand-custom-5",
		{Rail: "solana", Network: "devnet"}:    "solana-devnet-2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1",
		{Rail: "solana", Network: "localnet"}:  "solana-localnet-2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1",
		{Rail: "solana", RPCEndpoint: "http://x", Program: solanaOtherProgram}: "solana-custom-" + solanaOtherProgram,
	} {
		d, _, err := ResolveNetwork(in.network(t))
		if err != nil {
			t.Fatal(err)
		}
		if d.Key() != want {
			t.Errorf("%+v: key %q, want %q", in, d.Key(), want)
		}
	}
}
