/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command chatstream pays for one streamed chat completion and prints the
// answer as it arrives: the smallest program that runs a paid turn through
// the zs SDK. cmd/zschat is the fuller CLI, with the zs-proxy wallet and a
// journal that outlives the process.
//
//	ZS_MNEMONIC="word word …" go run ./examples/chatstream -model <model id> "hello"
//
// The payer key is a 25-word Algorand mnemonic (or a 24-word recovery phrase)
// in ZS_MNEMONIC, and the account must hold USDC and ALGO on the network.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/zs"
)

// settleBudget bounds the wait for escrow submits on the way out. Longer than
// the SDK's settle submit and confirm watch together, so the SDK decides when
// to give up.
const settleBudget = 45 * time.Second

func main() {
	model := flag.String("model", "", "model id (required)")
	network := flag.String("network", "mainnet", "mainnet, testnet or localnet")
	appID := flag.Uint64("app-id", 0, "escrow app id (default: the network's preset; required for localnet)")
	flag.Parse()

	if err := run(*model, *network, *appID, strings.Join(flag.Args(), " ")); err != nil {
		fmt.Fprintln(os.Stderr, "chatstream:", err)
		os.Exit(1)
	}
}

func run(model, network string, appID uint64, prompt string) error {
	if model == "" || prompt == "" {
		return errors.New("usage: chatstream -model <model id> <prompt>")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	signer, err := signerFromEnv(ctx, "ZS_MNEMONIC")
	if err != nil {
		return err
	}
	appID = cmp.Or(appID, algod.EscrowAppID(network))
	if appID == 0 {
		return fmt.Errorf("%s has no preset escrow app: pass -app-id", network)
	}
	// The journal is in memory, so a ticket this run leaves open is refunded
	// only by hand after it exits. Stores.JournalPath keeps it on disk.
	cfg := zs.Config{
		Signer:  signer,
		Network: zs.Network{Algod: algod.Config{Network: network}, EscrowAppID: appID},
	}
	client, err := zs.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		// Its own context: an interrupted turn still has a settle to finish.
		waitCtx, cancel := context.WithTimeout(context.Background(), settleBudget)
		defer cancel()
		if err := client.WaitSettles(waitCtx); err != nil {
			fmt.Fprintln(os.Stderr, "chatstream:", err)
		}
		client.Close()
	}()

	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
		"stream":   true,
	})
	if err != nil {
		return err
	}
	s := client.Stream(ctx, zs.Request{Endpoint: zs.EndpointChatCompletions, Body: body})
	for ev, err := range s.Events() {
		if err != nil {
			fmt.Println()
			return err
		}
		switch e := ev.(type) {
		case zs.TextDelta:
			fmt.Print(e.Delta)
		case zs.ReceiptVerified:
			r := e.Receipt
			fmt.Fprintf(os.Stderr, "\n[receipt] %d in / %d out tokens, %d µUSDC to node %d/%d\n",
				r.ActualInputCount, r.ActualOutputCount, r.AmountCharged, e.Target.Op, e.Target.Node)
		}
	}
	fmt.Println()

	// The answer is out, so an interrupt from here on means stop waiting.
	stop()
	waitCtx, cancel := context.WithTimeout(context.Background(), settleBudget)
	defer cancel()
	st, err := s.Wait(waitCtx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[settle] %s tx %s\n", st.Kind, st.TxID)
	return nil
}

// signerFromEnv loads the one key named by env. keystore.EnvProvider would
// load every *_MNEMONIC in the environment, and with more than one the payer
// would be a guess.
func signerFromEnv(ctx context.Context, env string) (keystore.AccountSigner, error) {
	ks, err := keystore.New(ctx, envMnemonic(env))
	if err != nil {
		return keystore.AccountSigner{}, err
	}
	addrs := ks.Addresses()
	if len(addrs) == 0 {
		return keystore.AccountSigner{}, fmt.Errorf("%s is not set", env)
	}
	return ks.Signer(addrs[0]), nil
}

// envMnemonic is a keystore.SecretProvider for one environment variable.
type envMnemonic string

func (e envMnemonic) Mnemonics(context.Context) ([]keystore.MnemonicEntry, error) {
	return []keystore.MnemonicEntry{{Name: string(e), Mnemonic: os.Getenv(string(e))}}, nil
}
