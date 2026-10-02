/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/algo"
	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// Signer holds the payer's key. It signs raw Ed25519 digests (the reserve
// request: not MX-prefixed, not ARC-1) and Algorand transactions (escrow
// open, settle, refund) for one address.
type Signer interface {
	Address() string
	ticket.BytesSigner
	algo.MultipleWalletSigner
}

// Network selects the chain and the escrow application. EscrowAppID 0 takes
// the id embedded for Algod.Network, which exists for testnet and mainnet
// only; a localnet or private deployment must set it. Asset ids are never
// configured: they are read from the contract's global state.
type Network struct {
	Algod       algod.Config
	EscrowAppID uint64
}

func Testnet() Network  { return Network{Algod: algod.Config{Network: string(algod.NetworkTestnet)}} }
func Mainnet() Network  { return Network{Algod: algod.Config{Network: string(algod.NetworkMainnet)}} }
func Localnet() Network { return Network{Algod: algod.Config{Network: string(algod.NetworkLocalnet)}} }

// Privacy is the transport-privacy mode. The zero value is PrivacyRelayRequired.
type Privacy string

const (
	// PrivacyRelayRequired routes every request through a relay node and
	// never falls back to a direct connection (SPEC §3f): a failed relay
	// rotates to another relay or fails the request.
	PrivacyRelayRequired Privacy = "relay_required"
	// PrivacyDirect connects to the target, which then sees the payer's IP.
	PrivacyDirect Privacy = "direct"
)

// AffinityPolicy controls how strictly a continuation returns to the node
// that served the turn it continues. previous_response_id continuations are
// always strict: their session state lives on that node.
type AffinityPolicy string

const (
	AffinityPrefer AffinityPolicy = "prefer"
	AffinityStrict AffinityPolicy = "strict"
	AffinityNone   AffinityPolicy = "none"
)

type Affinity struct {
	Policy AffinityPolicy
	TTL    time.Duration
	Max    int
}

// Discovery tunes operator discovery and the details probes behind routing.
type Discovery struct {
	RefreshInterval    time.Duration
	RefreshTimeout     time.Duration // one refresh cycle
	ProbeBudget        int           // details probes per cycle
	TargetTopK         int           // targets probed in full per model
	MaxCacheAge        time.Duration
	MaxCarryAge        time.Duration // how long a node missing from a cycle stays routable
	LatencyStateMax    int
	DetailsTimeout     time.Duration
	DetailsConcurrency int
}

// Stores are the stateful pieces a process may want to persist.
type Stores struct {
	// Journal records open tickets. The in-memory default forgets them on
	// exit, so a long-running process should supply a durable one.
	Journal TicketJournal
}

// Config configures a Client. Signer and Network are required; every other
// zero value means the default noted on the field.
type Config struct {
	Signer  Signer
	Network Network

	Privacy  Privacy  // PrivacyRelayRequired
	Affinity Affinity // AffinityPrefer, 10m, 1024 entries

	// MaxOutputCeiling caps the output reservation when the request omits
	// max_output_tokens and the node declares none
	// (selection.DefaultMaxOutputCeiling); MaxOutputByModel overrides it per
	// model. The client uses the shared default, so any other value routes
	// differently from it for the same request; the Client logs a warning.
	MaxOutputCeiling uint64
	MaxOutputByModel map[string]uint64
	// RequireMaxOutput refuses a request that omits max_output_tokens instead
	// of applying a ceiling.
	RequireMaxOutput bool

	// ConcurrentSlots is how many tickets the prepaid MBR pool is funded
	// for (10).
	ConcurrentSlots int

	Discovery Discovery

	ReserveTimeout time.Duration // per attempt (5s)

	// AllowStaging and AllowPrivateHosts admit staging nodes and nodes on
	// private addresses. Development only.
	AllowStaging      bool
	AllowPrivateHosts bool

	Stores     Stores
	SpendGuard SpendGuard // none: no cap

	Logger     *slog.Logger     // discards
	Clock      func() time.Time // time.Now
	HTTPClient *http.Client     // see defaultHTTPClient
}

// defaultHTTPClient has no timeout, because streams end by context, and no
// environment proxy: http.DefaultTransport honours HTTP_PROXY, which would
// route around the private-address dial guard and contradict "the SDK reads
// no environment".
func defaultHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return &http.Client{Transport: t}
}

const (
	defaultAffinityTTL        = 10 * time.Minute
	defaultAffinityMax        = 1024
	defaultConcurrentSlots    = 10
	defaultReserveTimeout     = 5 * time.Second
	defaultRefreshInterval    = 5 * time.Minute
	defaultRefreshTimeout     = 30 * time.Second
	defaultProbeBudget        = 96
	defaultTargetTopK         = 8
	defaultMaxCacheAge        = 15 * time.Minute
	defaultMaxCarryAge        = 90 * time.Minute
	defaultLatencyStateMax    = 4096
	defaultDetailsTimeout     = 2 * time.Second
	defaultDetailsConcurrency = 24
)

// withDefaults returns c with every zero field set to its default.
func (c Config) withDefaults() Config {
	if c.Privacy == "" {
		c.Privacy = PrivacyRelayRequired
	}
	if c.Affinity.Policy == "" {
		c.Affinity.Policy = AffinityPrefer
	}
	c.Affinity.TTL = orDefault(c.Affinity.TTL, defaultAffinityTTL)
	c.Affinity.Max = orDefault(c.Affinity.Max, defaultAffinityMax)
	c.MaxOutputCeiling = orDefault(c.MaxOutputCeiling, selection.DefaultMaxOutputCeiling)
	c.ConcurrentSlots = orDefault(c.ConcurrentSlots, defaultConcurrentSlots)
	c.ReserveTimeout = orDefault(c.ReserveTimeout, defaultReserveTimeout)

	d := &c.Discovery
	d.RefreshInterval = orDefault(d.RefreshInterval, defaultRefreshInterval)
	d.RefreshTimeout = orDefault(d.RefreshTimeout, defaultRefreshTimeout)
	d.ProbeBudget = orDefault(d.ProbeBudget, defaultProbeBudget)
	d.TargetTopK = orDefault(d.TargetTopK, defaultTargetTopK)
	d.MaxCacheAge = orDefault(d.MaxCacheAge, defaultMaxCacheAge)
	d.MaxCarryAge = orDefault(d.MaxCarryAge, defaultMaxCarryAge)
	d.LatencyStateMax = orDefault(d.LatencyStateMax, defaultLatencyStateMax)
	d.DetailsTimeout = orDefault(d.DetailsTimeout, defaultDetailsTimeout)
	d.DetailsConcurrency = orDefault(d.DetailsConcurrency, defaultDetailsConcurrency)

	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.HTTPClient == nil {
		c.HTTPClient = defaultHTTPClient()
	}
	return c
}

// orDefault treats any non-positive value as unset: a negative timeout or
// count is never a meaningful request.
func orDefault[T int | uint64 | time.Duration](v, def T) T {
	if v <= 0 {
		return def
	}
	return v
}

// validate checks a defaulted Config and returns the resolved algod
// connection and escrow app id, plus warnings for settings that work but
// are probably mistakes.
func (c Config) validate() (ac algod.Config, appID uint64, warnings []string, err error) {
	if c.Signer == nil {
		return ac, 0, nil, configError("Signer is required")
	}
	addr := c.Signer.Address()
	if addr == "" {
		return ac, 0, nil, configError("Signer has no address")
	}
	// Checked up front because the first transaction signature comes at
	// escrow open, after a node has already spent a reservation on us.
	if !c.Signer.HasAccount(addr) {
		return ac, 0, nil, configError(fmt.Sprintf("Signer cannot sign for its own address %s", addr))
	}
	switch c.Privacy {
	case PrivacyRelayRequired, PrivacyDirect:
	default:
		return ac, 0, nil, configError(fmt.Sprintf("unknown Privacy %q", c.Privacy))
	}
	switch c.Affinity.Policy {
	case AffinityPrefer, AffinityStrict, AffinityNone:
	default:
		return ac, 0, nil, configError(fmt.Sprintf("unknown Affinity.Policy %q", c.Affinity.Policy))
	}
	ac = c.Network.Algod
	if err := ac.Resolve(); err != nil {
		return algod.Config{}, 0, nil, configError(err.Error())
	}
	if ac.ResolvedEndpoint == "" {
		return algod.Config{}, 0, nil, configError("Network.Algod needs a Network or an Endpoint")
	}
	appID = c.Network.EscrowAppID
	if appID == 0 {
		appID = algod.EscrowAppID(string(ac.ResolvedNetwork))
		if ac.EndpointOverrides() {
			warnings = append(warnings, fmt.Sprintf(
				"Network.Algod.Endpoint overrides the %s preset but the escrow app id is still that preset's (%d); set Network.EscrowAppID if the endpoint is another chain",
				ac.ResolvedNetwork, appID))
		}
	}
	if appID == 0 {
		return algod.Config{}, 0, nil, configError("Network.EscrowAppID is required for this network")
	}
	if !c.RequireMaxOutput && c.MaxOutputCeiling != selection.DefaultMaxOutputCeiling {
		warnings = append(warnings, fmt.Sprintf(
			"MaxOutputCeiling %d differs from the shared default %d: requests that omit max_output_tokens route differently from the client",
			c.MaxOutputCeiling, selection.DefaultMaxOutputCeiling))
	}
	return ac, appID, warnings, nil
}

func configError(msg string) *Error {
	return &Error{Kind: KindInvalidRequest, Code: "invalid_config", Message: msg}
}
