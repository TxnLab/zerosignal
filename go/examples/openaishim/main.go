/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command openaishim serves the zs SDK's OpenAI-compatible API on localhost,
// so an OpenAI client pointed at it pays for each request it sends. Any
// OpenAI SDK works; the API key is ignored.
//
//	ZS_MNEMONIC="word word …" go run ./examples/openaishim -addr 127.0.0.1:8080
//	OPENAI_BASE_URL=http://127.0.0.1:8080/v1 OPENAI_API_KEY=unused <your OpenAI client>
//
// With -ask it sends one chat completion to itself, prints the answer and
// exits:
//
//	ZS_MNEMONIC="word word …" go run ./examples/openaishim -model <model id> -ask "hello"
package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler"
)

// settleBudget bounds the wait for escrow submits on the way out. Longer than
// the SDK's settle submit and confirm watch together.
const settleBudget = 45 * time.Second

type options struct {
	addr, network, model, ask string
	appID, budget             uint64
}

func main() {
	var o options
	flag.StringVar(&o.addr, "addr", "127.0.0.1:8080", "address to serve on; keep it on loopback, since every request it accepts is paid")
	flag.StringVar(&o.network, "network", "mainnet", "mainnet, testnet or localnet")
	flag.Uint64Var(&o.appID, "app-id", 0, "escrow app id (default: the network's preset; required for localnet)")
	flag.StringVar(&o.model, "model", "", "model id for -ask")
	flag.StringVar(&o.ask, "ask", "", "send this prompt to the server, print the answer and exit")
	flag.Uint64Var(&o.budget, "budget", 1_000_000, "most this process may lock in escrow at once and spend in total, in µUSDC")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "openaishim:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	if o.ask != "" && o.model == "" {
		return errors.New("-ask needs -model")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	signer, err := signerFromEnv(ctx, "ZS_MNEMONIC")
	if err != nil {
		return err
	}
	appID := cmp.Or(o.appID, algod.EscrowAppID(o.network))
	if appID == 0 {
		return fmt.Errorf("%s has no preset escrow app: pass -app-id", o.network)
	}
	cfg := zs.Config{
		Signer:  signer,
		Network: zs.Network{Algod: algod.Config{Network: o.network}, EscrowAppID: appID},
		Logger:  log,
		// The server asks no credential and answers any origin, so a web page
		// open in this machine's browser can send it requests too. The guard
		// bounds what anyone reaching it can spend.
		SpendGuard: &budgetGuard{limit: o.budget, open: map[string]uint64{}},
	}
	client, err := zs.New(ctx, cfg)
	if err != nil {
		return err
	}
	defer func() {
		waitCtx, cancel := context.WithTimeout(context.Background(), settleBudget)
		defer cancel()
		if err := client.WaitSettles(waitCtx); err != nil {
			fmt.Fprintln(os.Stderr, "openaishim:", err)
		}
		client.Close()
	}()

	// Listening before serving means -ask can't race the server's start.
	ln, err := net.Listen("tcp", o.addr)
	if err != nil {
		return err
	}
	srv := handler.New(client, nil, log, nil, nil, handler.Options{}).HTTPServer(handler.ListenConfig{Addr: o.addr})
	served := make(chan error, 1)
	go func() { served <- srv.Serve(ln) }()
	log.Info("serving the OpenAI API", slog.String("base_url", "http://"+ln.Addr().String()+"/v1"))

	if o.ask != "" {
		err = ask(ctx, "http://"+ln.Addr().String()+"/v1", o.model, o.ask)
	} else {
		select {
		case <-ctx.Done():
		case err = <-served:
		}
	}
	// A request still running when the server stops has its own settle,
	// which the deferred WaitSettles finishes.
	shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutCtx)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// ask is what any OpenAI client does: a plain chat completion against
// baseURL. The X-Zs-* response headers carry what the turn cost.
func ask(ctx context.Context, baseURL, model, prompt string) error {
	body, err := json.Marshal(map[string]any{
		"model":    model,
		"messages": []map[string]string{{"role": "user", "content": prompt}},
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", resp.Status, raw)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return err
	}
	if len(out.Choices) == 0 {
		return errors.New("response has no choices")
	}
	fmt.Println(out.Choices[0].Message.Content)
	// The amount is in the currency's base units (Decimals places).
	fmt.Fprintf(os.Stderr, "[cost] %s base units of %s (%s), %s in / %s out tokens\n",
		resp.Header.Get("X-Zs-Inference-Amount"), resp.Header.Get("X-Zs-Inference-Currency"),
		resp.Header.Get("X-Zs-Inference-Amount-Usd"),
		resp.Header.Get("X-Zs-Actual-Input-Count"), resp.Header.Get("X-Zs-Actual-Output-Count"))
	return nil
}

// budgetGuard caps what the process spends: each open ticket counts at its
// ceiling until it settles, then at its charge. A ticket is resolved once,
// since the SDK can report a refund or settle for one more than once.
type budgetGuard struct {
	mu    sync.Mutex
	limit uint64
	spent uint64            // settled charges
	open  map[string]uint64 // ticket id → ceiling, until resolved
}

func (g *budgetGuard) exposure() uint64 {
	total := g.spent
	for _, p := range g.open {
		total += p
	}
	return total
}

func (g *budgetGuard) Admit(estimate uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.exposure()+estimate > g.limit {
		return fmt.Errorf("budget of %d µUSDC reached", g.limit)
	}
	return nil
}

func (g *budgetGuard) Reserve(ticketID string, maxPrice uint64) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, dup := g.open[ticketID]; dup {
		return zs.ErrDuplicateTicket
	}
	if g.exposure()+maxPrice > g.limit {
		return fmt.Errorf("budget of %d µUSDC reached", g.limit)
	}
	g.open[ticketID] = maxPrice
	return nil
}

func (g *budgetGuard) Settle(ticketID string, charged uint64) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if _, ok := g.open[ticketID]; ok {
		delete(g.open, ticketID)
		g.spent += charged
	}
}

func (g *budgetGuard) Release(ticketID string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.open, ticketID)
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
