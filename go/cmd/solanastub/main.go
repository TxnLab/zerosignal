/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command solanastub serves the stub Solana node of internal/solanastub, so a
// payer in another language can run the end-to-end scenarios the Go tests run
// in-process. It serves a node, prints one JSON line naming it and its URL,
// then serves the node and its /stub/ control routes until it is killed.
//
//	go run ./cmd/solanastub -rpc http://127.0.0.1:8899 -mint-authority ~/.config/zs-solana/deployer.json
//
// A run is funded by the test mint's authority on a local validator, or by a
// -funder wallet holding SOL and test USDC on any cluster (see
// solanastub.Funding). It registers a fresh operator and node, or serves as
// the one an -identity file names, which a shared cluster's runs reuse.
//
// Two modes serve nothing and exit:
//   - -register-node URL registers a node at that base URL, for a real
//     zs-node or a later -identity run, writes its identity to
//     -identity-out, whose signing phrase zs-node reads as a
//     <NAME>_MNEMONIC and whose owner phrase unregisters it, and prints one
//     JSON line naming the node. zs-node has
//     no command that registers on Solana, since an owner registers through
//     the operator UI.
//   - -fund ADDRESS gives that address SOL and test USDC, for a payer a test
//     drives through another program, such as zs-proxy.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TxnLab/zerosignal/go/internal/solanastub"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

type flags struct {
	rpc, authority, funder, listen, identity string
	exitOnEOF                                bool
	registerNode, identityOut                string
	fund                                     string
	lamports, usdc                           uint64
}

func main() {
	var f flags
	flag.StringVar(&f.rpc, "rpc", "http://127.0.0.1:8899", "the cluster's JSON-RPC endpoint")
	flag.StringVar(&f.authority, "mint-authority", "", "keypair file of the test USDC mint's authority, also the Config's admin; a local validator only")
	flag.StringVar(&f.funder, "funder", "", "keypair file of a wallet holding SOL and test USDC, in place of -mint-authority")
	flag.StringVar(&f.listen, "listen", "127.0.0.1:0", "address to serve a fresh registration on")
	flag.StringVar(&f.identity, "identity", "", "serve as the registered node this identity file names, at its URL")
	flag.BoolVar(&f.exitOnEOF, "exit-on-stdin-eof", false, "exit when stdin closes, so a parent that dies, even killed, takes the stub with it")
	flag.StringVar(&f.registerNode, "register-node", "", "register a node at this base URL, write its identity to -identity-out, and exit")
	flag.StringVar(&f.identityOut, "identity-out", "", "with -register-node: new file to write the node's identity to")
	flag.StringVar(&f.fund, "fund", "", "give this address -lamports of SOL and -usdc of test USDC, and exit")
	flag.Uint64Var(&f.lamports, "lamports", 50_000_000, "with -fund: SOL to give, in lamports")
	flag.Uint64Var(&f.usdc, "usdc", solanastub.PayerUSDC, "with -fund: test USDC to give, in base units")
	flag.Parse()
	if err := f.run(); err != nil {
		fmt.Fprintln(os.Stderr, "solanastub:", err)
		os.Exit(1)
	}
}

func (f flags) run() error {
	set := map[string]bool{}
	flag.Visit(func(fl *flag.Flag) { set[fl.Name] = true })
	fund, err := f.funding()
	if err != nil {
		return err
	}
	// A flag the chosen mode doesn't read is a caller expecting something
	// this run won't do.
	serving := set["listen"] || set["identity"] || set["exit-on-stdin-eof"]
	amounts := set["lamports"] || set["usdc"]
	switch {
	case f.registerNode != "" && f.fund != "":
		return errors.New("-register-node and -fund are separate runs")
	case set["identity-out"] && f.registerNode == "":
		return errors.New("-identity-out goes with -register-node")
	case amounts && f.fund == "":
		return errors.New("-lamports and -usdc go with -fund")
	case f.registerNode != "":
		if serving {
			return errors.New("-register-node serves nothing; drop -listen, -identity and -exit-on-stdin-eof")
		}
		return f.register(fund)
	case f.fund != "":
		if serving {
			return errors.New("-fund serves nothing; drop -listen, -identity and -exit-on-stdin-eof")
		}
		return f.fundAddress(fund)
	case set["identity"] && set["listen"]:
		return errors.New("-identity serves at the identity's URL; drop -listen")
	}
	return f.serve(fund)
}

func (f flags) funding() (solanastub.Funding, error) {
	var out solanastub.Funding
	if (f.authority == "") == (f.funder == "") {
		return out, errors.New("name one of -mint-authority and -funder")
	}
	var err error
	if f.authority != "" {
		out.Authority, err = keystore.ReadSolanaKeypairFile(f.authority)
	} else {
		out.Funder, err = keystore.ReadSolanaKeypairFile(f.funder)
	}
	return out, err
}

func (f flags) register(funding solanastub.Funding) error {
	if f.identityOut == "" {
		return errors.New("-register-node needs -identity-out")
	}
	signing, signingPhrase, err := solanastub.NewIdentityKey()
	if err != nil {
		return err
	}
	owner, ownerPhrase, err := solanastub.NewIdentityKey()
	if err != nil {
		return err
	}
	// Written before anything is staked: an operator whose owner key is lost
	// can never be unregistered, its stake never returned.
	id := solanastub.Identity{URL: f.registerNode, SigningPhrase: signingPhrase, OwnerPhrase: ownerPhrase}
	if err := solanastub.WriteIdentity(f.identityOut, id); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	chain, opID, nodeID, err := solanastub.Register(ctx, f.rpc, funding, owner, signing, f.registerNode)
	if err != nil {
		return err
	}
	id.OperatorID, id.NodeID = opID, nodeID
	// Renamed over the first file, so the phrases are on disk throughout.
	next := f.identityOut + ".new"
	if err := solanastub.WriteIdentity(next, id); err != nil {
		return err
	}
	if err := os.Rename(next, f.identityOut); err != nil {
		return err
	}
	return printLine(map[string]any{
		"url": f.registerNode, "operator_id": opID, "node_id": nodeID,
		"signing": solanastub.PublicKey(signing).String(), "program": zsescrow.ProgramID.String(),
		"fee_bps": chain.Config.FeeBps, "default_grace": chain.Config.DefaultGrace,
	})
}

func (f flags) fundAddress(funding solanastub.Funding) error {
	to, err := solana.ParsePublicKey(f.fund)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	chain, err := solanastub.DialFunded(ctx, f.rpc, funding)
	if err != nil {
		return err
	}
	if err := chain.FundSOL(ctx, funding, to, f.lamports); err != nil {
		return err
	}
	return chain.FundUSDC(ctx, funding, to, f.usdc)
}

func (f flags) serve(funding solanastub.Funding) error {
	o := solanastub.Options{Endpoint: f.rpc, Funding: funding, Listen: f.listen}
	if f.identity != "" {
		id, err := solanastub.ReadIdentity(f.identity)
		if err != nil {
			return err
		}
		o.Identity = &id
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	s, err := solanastub.Start(ctx, o)
	cancel()
	if err != nil {
		return err
	}
	defer s.Close()
	// Everything a scenario in another language would otherwise copy from
	// this package by hand.
	if err := printLine(map[string]any{
		"url": s.URL, "operator_id": s.OperatorID, "node_id": s.NodeID,
		"program": zsescrow.ProgramID.String(), "fee_bps": s.Chain.Config.FeeBps,
		"default_grace": s.Chain.Config.DefaultGrace, "payer_usdc": solanastub.PayerUSDC,
		"model": solanastub.Model, "free_model": solanastub.FreeModel, "reply": solanastub.Reply,
		"credit_issuer": base64.StdEncoding.EncodeToString(s.Node.Issuer().Key()), "issuer_payer_header": solanastub.IssuerPayerHeader,
		"treasury": s.Chain.Config.Treasury.String(), "funds_source": funding.Source().String(),
		"resolves": funding.Admin() != nil,
	}); err != nil {
		return err
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	eof := make(chan struct{})
	if f.exitOnEOF {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			close(eof)
		}()
	}
	select {
	case <-stop:
	case <-eof:
	case err := <-s.ServeErr():
		return err
	}
	return nil
}

func printLine(v any) error {
	line, err := json.Marshal(v)
	if err != nil {
		return err
	}
	fmt.Println(string(line))
	return nil
}
