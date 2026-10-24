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
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TxnLab/zerosignal/go/internal/solanastub"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
)

func main() {
	rpcURL := flag.String("rpc", "http://127.0.0.1:8899", "the local validator's JSON-RPC endpoint")
	authority := flag.String("mint-authority", "", "keypair file of the test USDC mint's authority, also the Config's admin")
	listen := flag.String("listen", "127.0.0.1:0", "address to serve on")
	exitOnEOF := flag.Bool("exit-on-stdin-eof", false, "exit when stdin closes, so a parent that dies, even killed, takes the stub with it")
	flag.Parse()
	if err := run(*rpcURL, *authority, *listen, *exitOnEOF); err != nil {
		fmt.Fprintln(os.Stderr, "solanastub:", err)
		os.Exit(1)
	}
}

func run(rpcURL, authorityPath, listen string, exitOnEOF bool) error {
	if authorityPath == "" {
		return fmt.Errorf("-mint-authority is required")
	}
	key, err := solanastub.ReadKeypair(authorityPath)
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
		"model": solanastub.Model, "reply": solanastub.Reply,
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
