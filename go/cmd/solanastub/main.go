/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command solanastub serves the stub Solana node of internal/solanastub on a
// local validator, so a payer in another language can run the end-to-end
// scenarios the Go tests run in-process. It registers a fresh operator and
// node, prints one JSON line naming them and its URL, then serves the node
// and its /stub/ control routes until it is killed.
//
//	go run ./cmd/solanastub -rpc http://127.0.0.1:8899 -mint-authority ~/.config/zs-solana/deployer.json
//
// With -register-node it serves nothing: it registers a node at that base URL
// for a real zs-node to serve, writes the node's signing phrase to
// -signing-phrase-out, which zs-node reads as a <NAME>_MNEMONIC, prints one
// JSON line naming the node, and exits. zs-node has no command that registers
// on Solana, since an owner registers through the operator UI.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/tyler-smith/go-bip39"

	"github.com/TxnLab/zerosignal/go/internal/solanastub"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:8899", "the local validator's JSON-RPC endpoint")
	authority := flag.String("mint-authority", "", "keypair file of the test USDC mint's authority, also the Config's admin")
	listen := flag.String("listen", "127.0.0.1:0", "address to serve on")
	exitOnEOF := flag.Bool("exit-on-stdin-eof", false, "exit when stdin closes, so a parent that dies, even killed, takes the stub with it")
	registerNode := flag.String("register-node", "", "register a node at this base URL for a real zs-node, and exit")
	phraseOut := flag.String("signing-phrase-out", "", "with -register-node: new file to write the node's 24-word signing phrase to")
	flag.Parse()
	var err error
	if *registerNode != "" {
		// A registration serves nothing, so a serving flag beside it is a
		// caller expecting a stub that this run won't start.
		set := map[string]bool{}
		flag.Visit(func(f *flag.Flag) { set[f.Name] = true })
		if set["listen"] || set["exit-on-stdin-eof"] {
			fmt.Fprintln(os.Stderr, "solanastub: -register-node serves nothing; drop -listen and -exit-on-stdin-eof")
			os.Exit(2)
		}
		err = register(*rpcURL, *authority, *registerNode, *phraseOut)
	} else {
		err = run(*rpcURL, *authority, *listen, *exitOnEOF)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "solanastub:", err)
		os.Exit(1)
	}
}

func register(rpcURL, authorityPath, baseURL, phraseOut string) error {
	if authorityPath == "" || phraseOut == "" {
		return fmt.Errorf("-register-node needs -mint-authority and -signing-phrase-out")
	}
	key, err := keystore.ReadSolanaKeypairFile(authorityPath)
	if err != nil {
		return err
	}
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return err
	}
	phrase, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return err
	}
	signing, err := keystore.SolanaKeyFromPhrase(phrase)
	if err != nil {
		return err
	}
	// O_EXCL: the phrase is the node's key, so an existing file is someone's.
	f, err := os.OpenFile(phraseOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, phrase); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	chain, opID, nodeID, err := solanastub.RegisterLocalnetNode(ctx, rpcURL, key, signing, baseURL)
	if err != nil {
		return err
	}
	line, err := json.Marshal(map[string]any{
		"url": baseURL, "operator_id": opID, "node_id": nodeID,
		"signing": solanastub.PublicKey(signing).String(), "program": zsescrow.ProgramID.String(),
		"fee_bps": chain.Config.FeeBps, "default_grace": chain.Config.DefaultGrace,
	})
	if err != nil {
		return err
	}
	fmt.Println(string(line))
	return nil
}

func run(rpcURL, authorityPath, listen string, exitOnEOF bool) error {
	if authorityPath == "" {
		return fmt.Errorf("-mint-authority is required")
	}
	key, err := keystore.ReadSolanaKeypairFile(authorityPath)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	l, err := solanastub.StartLocalnet(ctx, rpcURL, key, listen)
	cancel()
	if err != nil {
		return err
	}
	defer l.Close()
	// Everything a scenario in another language would otherwise copy from
	// this package by hand.
	line, err := json.Marshal(map[string]any{
		"url": l.URL, "operator_id": l.OperatorID, "node_id": l.NodeID,
		"program": zsescrow.ProgramID.String(), "fee_bps": l.Chain.Config.FeeBps,
		"default_grace": l.Chain.Config.DefaultGrace, "payer_usdc": solanastub.PayerUSDC,
		"model": solanastub.Model, "free_model": solanastub.FreeModel, "reply": solanastub.Reply,
		"credit_issuer": base64.StdEncoding.EncodeToString(l.Node.Issuer().Key()), "issuer_payer_header": solanastub.IssuerPayerHeader,
	})
	if err != nil {
		return err
	}
	fmt.Println(string(line))

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	eof := make(chan struct{})
	if exitOnEOF {
		go func() {
			_, _ = io.Copy(io.Discard, os.Stdin)
			close(eof)
		}()
	}
	select {
	case <-stop:
	case <-eof:
	case err := <-l.ServeErr():
		return err
	}
	return nil
}
