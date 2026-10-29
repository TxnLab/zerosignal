/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

const (
	// bootFetchTimeout bounds the first discovery: the chain read plus the
	// details probes. A failure is not fatal, so this only caps how long New
	// waits before routing from the saved catalog.
	bootFetchTimeout = 60 * time.Second
	// escrowConfigTimeout bounds the one read of the escrow's ticket MBR and
	// asset ids that every open needs.
	escrowConfigTimeout = 10 * time.Second
)

// networkParts are what New builds for the nil Registry, ReserveClient and
// Wallet. stop ends the work they started, and is nil when there is none.
type networkParts struct {
	registry RegistryProvider
	reserve  ReserveClient
	wallet   WalletOpener
	// source is the chain source behind a built registry, which is also the
	// store for every routing signal the caller left nil.
	source *ChainOperatorSource
	stop   func()
	// deploymentID is the id read off the chain, zero when no part was built
	// or the read failed; free credits are minted for it.
	deploymentID ticket.DeploymentID
}

// railChain is what buildNetworkParts reads one rail's chain through.
type railChain struct {
	wallet     func(context.Context) (WalletOpener, error)
	deployment func(context.Context) (ticket.DeploymentID, error)
	source     func(ticket.DeploymentID) *ChainOperatorSource
}

// buildNetworkParts builds each nil network part. The registry's refresh loop
// starts last; New, failing after this returns, calls the parts' stop, so a
// failed New leaves nothing running. The wallet goes first because its chain read is the one
// that fails New outright; it fails before the slow discovery, not after.
func buildNetworkParts(ctx context.Context, cfg Config, dep Deployment) (networkParts, error) {
	p := networkParts{registry: cfg.Registry, reserve: cfg.ReserveClient, wallet: cfg.Wallet}
	var chain *railChain
	if p.registry == nil || p.wallet == nil {
		var err error
		if dep.Rail == ticket.RailSolana {
			chain, err = solanaRailChain(cfg, dep.Solana)
		} else {
			chain, err = algorandRailChain(cfg, dep.Algod, dep.EscrowAppID)
		}
		if err != nil {
			return networkParts{}, err
		}
	}
	builtWallet := p.wallet == nil
	if builtWallet {
		w, err := chain.wallet(ctx)
		if err != nil {
			return networkParts{}, err
		}
		p.wallet = w
	}
	var deployment ticket.DeploymentID
	if chain != nil {
		d, err := chain.deployment(ctx)
		if deployment, err = deploymentOrFail(d, err, builtWallet, cfg.Logger); err != nil {
			return networkParts{}, err
		}
	}
	p.deploymentID = deployment
	if p.reserve == nil {
		p.reserve = newReserveClient(cfg, deployment)
	}
	if p.registry == nil {
		p.source = chain.source(deployment)
		reg, err := bootRegistry(ctx, cfg, p.source)
		if err != nil {
			return networkParts{}, err
		}
		// Not New's context: that one bounds construction, and the refresh
		// loop runs until Close.
		reg.Start(context.Background())
		p.registry, p.stop = reg, reg.Stop
	}
	return p, nil
}

// deploymentOrFail decides what a failed genesis read means. When the SDK
// built the wallet, that wallet just read the chain, so algod is up and the
// failure is not a blip worth starting unbound for. A host-supplied wallet
// means this payer may start without algod; it warns and keeps the legacy
// layouts until restarted.
func deploymentOrFail(d ticket.DeploymentID, err error, builtWallet bool, log *slog.Logger) (ticket.DeploymentID, error) {
	switch {
	case err == nil:
		return d, nil
	case builtWallet:
		return ticket.DeploymentID{}, err
	default:
		log.Warn("could not read the network genesis hash; reserving without a deployment binding", slog.Any("err", err))
		return ticket.DeploymentID{}, nil
	}
}

// algorandRailChain reads the escrow app through one algod client.
func algorandRailChain(cfg Config, ac algod.Config, appID uint64) (*railChain, error) {
	chain, err := algod.NewClient(ac.ResolvedEndpoint, ac.ResolvedToken, algod.WithTransport(cfg.algodTransport()))
	if err != nil {
		return nil, configError(err.Error())
	}
	return &railChain{
		wallet: func(ctx context.Context) (WalletOpener, error) {
			w, err := buildWallet(ctx, cfg, ac, appID, chain)
			if err != nil {
				return nil, err
			}
			return w, nil
		},
		deployment: func(ctx context.Context) (ticket.DeploymentID, error) { return readDeploymentID(ctx, chain, appID) },
		source:     func(d ticket.DeploymentID) *ChainOperatorSource { return newChainSource(cfg, appID, chain, d) },
	}, nil
}

// solanaRailChain reads the zs_escrow program through one RPC client, whose
// confirmations poll: a pubsub socket ends on its first drop, and a Client
// lives far longer than a public endpoint keeps an idle socket.
func solanaRailChain(cfg Config, sn SolanaNetwork) (*railChain, error) {
	rc, err := rpc.NewClient(sn.RPCEndpoint, rpc.WithTransport(cfg.solanaTransport()))
	if err != nil {
		return nil, configError(err.Error())
	}
	reader := &SolanaChainReader{RPC: rc, Program: sn.Program, OperatorIDs: cfg.Discovery.OperatorIDs, Log: cfg.Logger}
	return &railChain{
		wallet: func(ctx context.Context) (WalletOpener, error) {
			w, err := buildSolanaWallet(ctx, cfg, rc, sn.Program)
			if err != nil {
				return nil, err
			}
			return w, nil
		},
		deployment: reader.ReadDeployment,
		source: func(d ticket.DeploymentID) *ChainOperatorSource {
			s := newDiscoverySource(cfg, d)
			s.Chain = reader
			return s
		},
	}, nil
}

// buildSolanaWallet reads the program's Config for its mint, then builds the
// wallet, which checks every offer's transfer against that mint.
func buildSolanaWallet(ctx context.Context, cfg Config, rc rpc.Client, program solana.PublicKey) (*SolanaWallet, error) {
	rctx, cancel := context.WithTimeout(ctx, escrowConfigTimeout)
	defer cancel()
	c, err := readSolanaConfig(rctx, rc, zsescrow.Deployment{Program: program})
	if err != nil {
		return nil, fmt.Errorf("zs: read escrow config: %w", err)
	}
	return NewSolanaWallet(rctx, SolanaWalletConfig{
		RPC:          rc,
		Deployment:   zsescrow.Deployment{Program: program, Mint: c.USDCMint},
		Signer:       cfg.SolanaSigner,
		DepositSlots: uint64(cfg.ConcurrentSlots),
		Logger:       cfg.Logger,
	})
}

// buildWallet reads the escrow's config and builds the wallet that opens
// tickets against it.
func buildWallet(ctx context.Context, cfg Config, ac algod.Config, appID uint64, chain algod.Client) (*Wallet, error) {
	ec, err := escrow.NewClient(appID, chain)
	if err != nil {
		return nil, fmt.Errorf("zs: escrow client: %w", err)
	}
	rctx, cancel := context.WithTimeout(ctx, escrowConfigTimeout)
	defer cancel()
	if err := ec.RefreshConfig(rctx, simulateSender(ac, cfg.Signer.Address())); err != nil {
		return nil, fmt.Errorf("zs: read escrow config: %w", err)
	}
	return NewWallet(WalletConfig{
		Escrow:       ec,
		Keystore:     cfg.Signer,
		PayerAddr:    cfg.Signer.Address(),
		DepositSlots: uint64(cfg.ConcurrentSlots),
		Logger:       cfg.Logger,
	})
}

// simulateSender is the sender of the escrow config read. The network's fee
// sink, where there is one, so the read works before the payer holds any
// ALGO: an unfunded payer is not in the ledger, and a simulate from it
// fails. The MBR the read returns does not depend on the sender, and nothing
// signs for it. Localnet has no fixed fee sink; a dev localnet funds the
// payer.
func simulateSender(ac algod.Config, payer string) string {
	if fs := algod.FeeSink(string(ac.ResolvedNetwork)); fs != "" {
		return fs
	}
	return payer
}

// readDeploymentID derives the payer's deployment id from the network's
// genesis hash and the escrow app id: what a node's bound signatures must
// name.
func readDeploymentID(ctx context.Context, chain algod.Client, appID uint64) (ticket.DeploymentID, error) {
	rctx, cancel := context.WithTimeout(ctx, escrowConfigTimeout)
	defer cancel()
	sp, err := chain.SuggestedParams(rctx)
	if err != nil {
		return ticket.DeploymentID{}, fmt.Errorf("zs: read genesis hash: %w", err)
	}
	d, err := ticket.AlgorandDeploymentID(sp.GenesisHash, appID)
	if err != nil {
		return ticket.DeploymentID{}, fmt.Errorf("zs: %w", err)
	}
	return d, nil
}

// newReserveClient signs each reserve as the payer (SPEC §3a), and dials
// with the same guard as inference: a reserve goes to the same
// node-registered addresses.
func newReserveClient(cfg Config, deployment ticket.DeploymentID) *HTTPReserveClient {
	return &HTTPReserveClient{
		HTTPClient: cfg.nodeHTTPClient(cfg.ReserveTimeout, 0),
		Signer:     cfg.payerSigner(),
		Deployment: deployment,
		Rail:       cfg.Network.Rail,
	}
}

// newChainSource maps Config onto discovery of the escrow app on Algorand.
func newChainSource(cfg Config, appID uint64, chain algod.Client, deployment ticket.DeploymentID) *ChainOperatorSource {
	s := newDiscoverySource(cfg, deployment)
	s.EscrowAppID, s.Algod = appID, chain
	s.OperatorIDs = cfg.Discovery.OperatorIDs
	s.ProxyPayerAddr = cfg.Signer.Address()
	return s
}

// newDiscoverySource maps Config onto discovery, leaving the chain read to
// the rail. The details and attestation probes dial node-registered addresses
// too, so they get the dial guard.
func newDiscoverySource(cfg Config, deployment ticket.DeploymentID) *ChainOperatorSource {
	d := cfg.Discovery
	probe := cfg.nodeHTTPClient(0, 0)
	return &ChainOperatorSource{
		Deployment:         deployment,
		DetailsTimeout:     d.DetailsTimeout,
		DetailsConcurrency: d.DetailsConcurrency,
		LatencyStateMax:    d.LatencyStateMax,
		Details:            NewDetailsClient(probe, d.DetailsTimeout),
		Attestation:        NewAttestationClient(probe, d.DetailsTimeout),
		TEEVerifier:        cfg.TEEVerifier,
		Log:                cfg.Logger,
		Privacy:            cfg.Privacy == PrivacyRelayRequired,
	}
}

// bootRegistry runs the first discovery and seeds a registry with it. A
// failed fetch is logged, not returned: the saved catalog (or nothing) seeds
// the registry, and its refresh loop retries. A transient chain error should
// not stop a payer from starting.
func bootRegistry(ctx context.Context, cfg Config, src OperatorSource) (*DynamicRegistryProvider, error) {
	log := cfg.Logger
	d := cfg.Discovery
	var saved []Operator
	if d.CatalogPath != "" {
		ops, err := LoadCatalog(d.CatalogPath)
		switch {
		case err != nil:
			log.Warn("failed to load persisted operator catalog; starting without it",
				slog.Any("err", err), slog.String("path", d.CatalogPath))
		case len(ops) > 0:
			saved = ops
			log.Info("loaded persisted operator catalog", slog.Int("count", len(saved)))
		}
	}

	fctx, cancel := context.WithTimeout(ctx, bootFetchTimeout)
	ops, err := src.Fetch(fctx)
	cancel()
	switch {
	case err != nil:
		log.Warn("initial operator fetch failed — seeding from persisted catalog (empty if none); background refresh will retry",
			slog.Any("err", err), slog.Int("persisted", len(saved)))
		ops = seedFromCatalog(saved, d.MaxCarryAge, time.Now())
	case len(saved) > 0:
		// Nodes the first probe did not reach keep their saved
		// capabilities, so a restart routes to them at once.
		ops = MergeCatalog(saved, ops, d.MaxCarryAge)
	}
	log.Info("operators loaded", slog.Int("count", len(ops)), slog.Int("reachable", countReachable(ops)))

	reg, err := NewDynamicRegistryProvider(src, ops, registryConfig(cfg), log)
	if err != nil {
		return nil, fmt.Errorf("zs: registry: %w", err)
	}
	return reg, nil
}

// registryConfig maps Config onto the registry's tunables. Each field is a
// silent no-op when dropped: discovery still runs, and only the knob stops
// working. AllowStaging must be the Client's own, or the discovery aggregates
// and the per-request gate disagree about which nodes exist.
func registryConfig(cfg Config) DynamicRegistryConfig {
	d := cfg.Discovery
	return DynamicRegistryConfig{
		RefreshInterval: d.RefreshInterval,
		RefreshTimeout:  d.RefreshTimeout,
		MaxCacheAge:     d.MaxCacheAge,
		MaxCarryAge:     d.MaxCarryAge,
		ProbeBudget:     d.ProbeBudget,
		TargetTopK:      d.TargetTopK,
		CatalogPath:     d.CatalogPath,
		AllowStaging:    cfg.AllowStaging,
	}
}
