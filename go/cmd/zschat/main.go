/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command zschat sends one chat-completions prompt through the zs SDK and
// streams the answer to stdout: the smallest complete payer.
//
//	go run ./cmd/zschat -model gpt-4o-mini "hello"
//	echo "hello" | go run ./cmd/zschat -model gpt-4o-mini
//	ALGO_MNEMONIC="word word …" go run ./cmd/zschat -network testnet -model gpt-4o-mini "hello"
//
// Keys come from the zs-proxy wallet (`zs-proxy wallet new|import`) and from
// the environment (any <NAME>_MNEMONIC, or ZS_MNEMONIC_URLS). A wallet on the
// encrypted file asks for its passphrase on the terminal, or reads
// ZEROSIGNAL_KEYSTORE_PASSPHRASE; one in the macOS keychain asks for access on
// every `go run`, since the keychain trusts only the binary that stored it.
// The payer must hold USDC and ALGO on the chosen network.
//
// Open tickets are journaled beside the wallet. A run waits for its settle to
// be confirmed on chain before exiting, which removes the ticket from the
// journal; one that settles without the node's co-signed group, or that is
// not confirmed in time, stays journaled. Each run starts by sweeping the
// journal: it re-settles a ticket an earlier run left settling, and refunds
// one past its deadline.
package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/wallet"
	"github.com/TxnLab/zerosignal/go/zs"
)

// settleBudget bounds the wait on the way out for escrow submits and for the
// SDK to see a settle confirmed, which takes a few seconds. It is longer than
// the SDK's own watch, so the SDK, not this, decides when to give up.
const settleBudget = 30 * time.Second

type options struct {
	model, system string
	network       string // "": the wallet's recorded network
	appID         uint64 // 0: the network's preset escrow app
	payer         string // "": the only key loaded
	verbose       bool
	prompt        string
}

func main() {
	var o options
	flag.StringVar(&o.model, "model", "", "model id (required)")
	flag.StringVar(&o.system, "system", "", "optional system prompt")
	flag.StringVar(&o.network, "network", "", "mainnet, testnet or localnet (default: the wallet's network; required for an environment key)")
	flag.Uint64Var(&o.appID, "app-id", 0, "escrow app id (default: the network's preset; required for localnet)")
	flag.StringVar(&o.payer, "payer", "", "paying address, when more than one key is loaded")
	flag.BoolVar(&o.verbose, "v", false, "log SDK activity and print the receipt to stderr")
	flag.Parse()
	o.prompt = strings.Join(flag.Args(), " ")

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "zschat:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.model == "" {
		return errors.New("-model is required")
	}
	prompt := o.prompt
	if prompt == "" {
		if term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("no prompt: pass it as arguments or pipe it on stdin")
		}
		b, err := io.ReadAll(os.Stdin)
		if err != nil {
			return err
		}
		prompt = strings.TrimSpace(string(b))
	}
	if prompt == "" {
		return errors.New("no prompt: pass it as arguments or on stdin")
	}

	logger := slog.New(slog.DiscardHandler)
	if o.verbose {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	// keystore and wallet log through the default logger.
	slog.SetDefault(logger)

	// 1. A signer for the payer. Before the signal handler, so Ctrl-C at the
	// passphrase prompt quits.
	payer, err := wallet.LoadPayer(context.Background(), wallet.PayerOptions{
		Address:    o.payer,
		Passphrase: ttyPassphrase,
	})
	if err != nil {
		return err
	}
	// The same address exists on every network, so guessing one for a key
	// that records none could spend on the wrong chain.
	network := cmp.Or(o.network, payer.Network)
	if network == "" {
		return errors.New("-network is required: the paying key is not the wallet's, so it records no network")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	// 2. A client, with a journal that outlives the process.
	dir, err := wallet.DefaultDir()
	if err != nil {
		return err
	}
	appID := cmp.Or(o.appID, algod.EscrowAppID(network))
	if appID == 0 {
		return fmt.Errorf("%s has no preset escrow app: pass -app-id", network)
	}
	net := zs.Network{Algod: algod.Config{Network: network}, EscrowAppID: appID}
	dep, _, err := zs.ResolveNetwork(net)
	if err != nil {
		return err
	}
	journal, legacyJournal := zs.StateFile(dir, "zschat-ticket-journal", dep)
	client, err := zs.New(ctx, zs.Config{
		Signer:  payer.Signer,
		Network: net,
		Logger:  logger,
		Stores: zs.Stores{
			JournalPath:        journal,
			JournalLegacyPaths: []string{legacyJournal},
		},
	})
	if err != nil {
		return err
	}
	if !client.JournalDurable() {
		fmt.Fprintln(os.Stderr, "zschat: the ticket journal is in use or unreadable (run with -v for why) · a ticket this run leaves open is refunded only by hand")
	}
	// On every way out, ending an interrupted one: let the escrow submits
	// finish, unless a second Ctrl-C says not to wait.
	defer func() {
		stop()
		waitCtx, cancel := context.WithTimeout(context.Background(), settleBudget)
		defer cancel()
		if err := client.WaitSettles(waitCtx); err != nil {
			fmt.Fprintln(os.Stderr, "zschat:", err)
		}
		client.Close()
	}()

	// 3. An OpenAI-shaped request.
	var messages []map[string]string
	if o.system != "" {
		messages = append(messages, map[string]string{"role": "system", "content": o.system})
	}
	messages = append(messages, map[string]string{"role": "user", "content": prompt})
	body, err := json.Marshal(map[string]any{"model": o.model, "messages": messages, "stream": true})
	if err != nil {
		return err
	}

	// 4. Stream the answer.
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
			if o.verbose {
				r := e.Receipt
				fmt.Fprintf(os.Stderr, "\n[receipt] %d in / %d out tokens, charged %d µUSDC by node %s\n",
					r.ActualInputCount, r.ActualOutputCount, r.AmountCharged, e.Target)
			}
		}
	}
	fmt.Println()

	// 5. The settlement this turn submitted. The answer is out, so Ctrl-C
	// from here on means stop waiting.
	stop()
	waitCtx, cancel := context.WithTimeout(context.Background(), settleBudget)
	defer cancel()
	st, err := s.Wait(waitCtx)
	if o.verbose && err == nil && st.TxID != "" {
		fmt.Fprintf(os.Stderr, "[settle] %s tx %s\n", st.Kind, st.TxID)
	}
	return err
}

// ttyPassphrase unlocks a file-backed wallet. With the prompt piped in on
// stdin it reads the passphrase from the controlling terminal instead.
func ttyPassphrase(prompt string) (string, error) {
	if _, ok := os.LookupEnv(wallet.EnvPassphrase); ok || term.IsTerminal(int(os.Stdin.Fd())) {
		return wallet.EnvOrPromptPassphrase(prompt)
	}
	tty, err := os.Open("/dev/tty")
	if err != nil {
		return "", fmt.Errorf("stdin is not a terminal and there is none to ask on; set %s: %w", wallet.EnvPassphrase, err)
	}
	defer tty.Close()
	fmt.Fprint(os.Stderr, "Enter the passphrase for your zerosignal wallet: ")
	b, err := term.ReadPassword(int(tty.Fd()))
	fmt.Fprintln(os.Stderr)
	return string(b), err
}
