/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package algod

import (
	"fmt"
	"log/slog"
	"strings"
)

// Network is the typed enum for Config.Network. Keeping it a fixed set
// lets downstream code switch on it rather than compare freeform strings.
type Network string

const (
	NetworkLocalnet Network = "localnet"
	NetworkTestnet  Network = "testnet"
	NetworkMainnet  Network = "mainnet"
)

// networkDefaults maps a Network to its built-in identity: the algod
// (endpoint, token) and the canonical ZeroSignalEscrow application id. Keeping all
// three here makes this the single place that knows "what testnet / mainnet
// points at" — the same reason this type lives in proto rather than in each
// service, so proxy and node (and any future consumer) cannot drift on it.
//
// The localnet token is the standard algokit/sandbox value (64 × 'a'); the
// nodely.dev free tier doesn't require a token for testnet/mainnet. The
// localnet escrowAppID is 0 because it is deploy-specific (per-instance
// genesis) and must come from config there.
//
// There are deliberately NO embedded USDC/HAY asset ids: those are properties
// of the deployed contract, read from its on-chain global state
// (escrow.RefreshAssetIDs / RefreshConfig). The app id is the only embedded
// anchor; every asset id derives from the contract it points at.
var networkDefaults = map[Network]struct {
	endpoint    string
	token       string
	escrowAppID uint64
}{
	NetworkLocalnet: {endpoint: "http://localhost:4001", token: strings.Repeat("a", 64), escrowAppID: 0},
	NetworkTestnet:  {endpoint: "https://testnet-api.4160.nodely.dev", token: "", escrowAppID: 765860477},
	NetworkMainnet:  {endpoint: "https://mainnet-api.4160.nodely.dev", token: "", escrowAppID: 3628061142},
}

// EscrowAppID returns the canonical ZeroSignalEscrow application id embedded for a
// public network ("testnet" | "mainnet", case-insensitive). It returns 0 when
// none is shipped — localnet (deploy-specific) and any unknown/empty network —
// in which case the value must come from config (hayai.escrow_app_id). The
// lowercase normalization mirrors Resolve so the two agree on what "MainNet"
// means.
//
// Consumers (proxy, node) apply this only as a fallback when the operator
// hasn't pinned an explicit app id, so a self-hoster pointing at their own
// deployment keeps it.
func EscrowAppID(network string) uint64 {
	return networkDefaults[Network(strings.ToLower(strings.TrimSpace(network)))].escrowAppID
}

// Config selects the Algorand node (algod) connection. It is consumed
// by both proxy and node (via this module's shared algod wrapper) so
// the two services cannot drift on what "testnet" or "mainnet" points
// at.
//
// Setting Network alone is enough — it resolves to a built-in
// endpoint/token pair (nodely.dev for testnet/mainnet,
// http://localhost:4001 for localnet). Endpoint and Token are optional
// overrides for private nodes or paid API tiers.
//
// Resolve() runs resolution; the Resolved* fields are the post-override
// values callers should consume. Network="" with Endpoint="" leaves
// every Resolved* empty — callers that need algod (e.g. escrow payment
// mode) enforce their own required check.
//
// Config implements slog.LogValuer so that structured logging of the
// config redacts Token/ResolvedToken — don't bypass that by formatting
// the token with fmt/%+v directly.
type Config struct {
	Network  string `yaml:"network"`
	Endpoint string `yaml:"endpoint"`
	Token    string `yaml:"token"`

	ResolvedNetwork  Network `yaml:"-"`
	ResolvedEndpoint string  `yaml:"-"`
	ResolvedToken    string  `yaml:"-"`
}

// Resolve applies network defaults and per-field overrides onto
// c.Resolved*. Precedence (low → high): network preset → explicit
// endpoint/token. Leaving Network and Endpoint both empty yields empty
// Resolved* values — caller decides if that's fatal for its use case.
//
// Network matching is case-insensitive: "Testnet", "TESTNET", and
// "testnet" all resolve to NetworkTestnet.
//
// Resolved* fields are reset at entry so repeated calls (e.g. after a
// config reload that clears Network) don't retain stale values.
//
// Unknown Network values return an error that lists the valid set.
func (c *Config) Resolve() error {
	c.ResolvedNetwork = ""
	c.ResolvedEndpoint = ""
	c.ResolvedToken = ""
	if c.Network != "" {
		net := Network(strings.ToLower(c.Network))
		def, ok := networkDefaults[net]
		if !ok {
			return fmt.Errorf("algod.network must be one of localnet|testnet|mainnet (case-insensitive), got %q", c.Network)
		}
		c.ResolvedNetwork = net
		c.ResolvedEndpoint = def.endpoint
		c.ResolvedToken = def.token
	}
	if c.Endpoint != "" {
		c.ResolvedEndpoint = strings.TrimRight(c.Endpoint, "/")
	}
	if c.Token != "" {
		c.ResolvedToken = c.Token
	}
	return nil
}

// EndpointOverrides reports whether Endpoint would silently override a
// network preset — both Network and Endpoint are set. Useful for
// emitting a startup warning so operators don't unknowingly point at a
// different chain than their declared network.
//
// Token overrides are deliberately NOT flagged here: setting
// Network=testnet|mainnet plus a Token is the expected shape for paid
// tiers (e.g. nodely.dev paid plans) where the endpoint stays the
// same but the operator holds an API token. That's not a footgun, so
// it doesn't warrant a warning.
func (c Config) EndpointOverrides() bool {
	return c.Network != "" && c.Endpoint != ""
}

// LogValue implements slog.LogValuer so `slog.Any("algod", cfg)` redacts
// the token instead of leaking it into log aggregation. The localnet
// default token is a public value, but paid-tier operator tokens are
// real secrets — redacting unconditionally is simpler than a per-case
// rule and matches how we'd treat any credential field.
func (c Config) LogValue() slog.Value {
	return slog.GroupValue(
		slog.String("network", c.Network),
		slog.String("endpoint", c.Endpoint),
		slog.Bool("token_set", c.Token != ""),
		slog.String("resolved_network", string(c.ResolvedNetwork)),
		slog.String("resolved_endpoint", c.ResolvedEndpoint),
		slog.Bool("resolved_token_set", c.ResolvedToken != ""),
	)
}
