/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Command discovery reads the fleet the way a payer does, and pays nothing:
// the operators and nodes registered in the escrow contract, each node's
// details probe (models, protocol version, reachability) and TEE verdict,
// and the models a payer would route to now.
//
//	go run ./examples/discovery
//	go run ./examples/discovery -network testnet -direct
//
// No key is needed. The chain read is a simulate, sent from the network's
// fee sink, which is always funded and never signs anything.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/tee"
)

// fetchBudget bounds the chain read and one probe of every node.
const fetchBudget = time.Minute

func main() {
	network := flag.String("network", "mainnet", "mainnet, testnet or localnet")
	appID := flag.Uint64("app-id", 0, "escrow app id (default: the network's preset; required for localnet)")
	sender := flag.String("sender", "", "funded account the chain read simulates from (default: the network's fee sink; required for localnet)")
	direct := flag.Bool("direct", false, "probe each node directly instead of through a relay, showing it this machine's IP")
	verbose := flag.Bool("v", false, "log discovery activity to stderr")
	flag.Parse()

	if err := run(*network, *appID, *sender, *direct, *verbose); err != nil {
		fmt.Fprintln(os.Stderr, "discovery:", err)
		os.Exit(1)
	}
}

func run(network string, appID uint64, sender string, direct, verbose bool) error {
	log := slog.New(slog.DiscardHandler)
	if verbose {
		log = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	ac := algod.Config{Network: network}
	if err := ac.Resolve(); err != nil {
		return err
	}
	appID = cmp.Or(appID, algod.EscrowAppID(network))
	sender = cmp.Or(sender, algod.FeeSink(network))
	if appID == 0 || sender == "" {
		return errors.New("localnet needs -app-id and -sender")
	}
	chain, err := algod.NewClient(ac.ResolvedEndpoint, ac.ResolvedToken)
	if err != nil {
		return err
	}

	// A node registers its own URL, so the probes get the dial guard a Client
	// gives them: a node naming a private address is never dialed. Localnet
	// nodes live on loopback.
	probe := httpx.Client(0, httpx.Options{BlockPrivateTargets: network != "localnet"})
	src := &zs.ChainOperatorSource{
		EscrowAppID:    appID,
		ProxyPayerAddr: sender,
		Algod:          chain,
		Details:        zs.NewDetailsClient(probe, 0),
		Attestation:    zs.NewAttestationClient(probe, 0),
		TEEVerifier:    tee.DefaultVerifier(log),
		Log:            log,
		Privacy:        !direct,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	fctx, cancel := context.WithTimeout(ctx, fetchBudget)
	ops, err := src.Fetch(fctx)
	cancel()
	if err != nil {
		return err
	}

	fmt.Printf("%d nodes on %s (escrow app %d)\n\n", len(ops), ac.ResolvedNetwork, appID)
	for _, op := range ops {
		fmt.Printf("%d/%d  %s\n", op.ID, op.NodeID, op.BaseURL)
		fmt.Printf("  reachable %t  protocol %s  node %s%s\n",
			op.Reachable, cmp.Or(op.ProtoVersion, "-"), cmp.Or(op.NodeVersion, "-"), stagingTag(op))
		fmt.Printf("  tee %s\n", teeLine(op.TEE))
		if len(op.Models) > 0 {
			fmt.Printf("  models %s\n", strings.Join(op.Models, ", "))
		}
	}

	// The registry is what a Client routes from. Without Start it never
	// refreshes on its own, and with the default cache age the snapshot just
	// built is fresh, so the reads below send nothing.
	reg, err := zs.NewDynamicRegistryProvider(src, ops, zs.DynamicRegistryConfig{MaxCacheAge: zs.DefaultMaxCacheAge}, log)
	if err != nil {
		return err
	}
	models := reg.AllModels(ctx)
	fmt.Printf("\n%d models a payer would route to now:\n", len(models))
	for _, m := range models {
		fmt.Println(" ", m)
	}
	return nil
}

func stagingTag(op zs.Operator) string {
	if op.Staging {
		return "  (staging)"
	}
	return ""
}

// teeLine is the attestation verdict as routing reads it: Attested needs a
// verified quote AND both measurement checks, not Verified alone.
func teeLine(s *zs.TEEStatus) string {
	switch {
	case s == nil:
		return "none advertised"
	case s.Attested():
		return fmt.Sprintf("attested (%s)", s.Mode)
	case s.Verified:
		return fmt.Sprintf("verified but not attested (%s): measurements unchecked", s.Mode)
	default:
		return fmt.Sprintf("not attested (%s): %s", s.Mode, s.FailureTag)
	}
}
