/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"cmp"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/algo"
	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// Signer holds the payer's key. It signs raw Ed25519 digests (the reserve
// request: not MX-prefixed, not ARC-1) and Algorand transactions (escrow
// open, settle, refund) for one address.
type Signer interface {
	Address() string
	ticket.BytesSigner
	algo.MultipleWalletSigner
}

// Network selects the chain and the escrow application. The zero value is
// mainnet, the production network; a Network that sets a token or an app id
// must also name its chain with Algod.Network or Algod.Endpoint. EscrowAppID 0
// takes the id embedded for Algod.Network, which exists for testnet and
// mainnet only; a localnet or private deployment must set it. Asset ids are
// never configured: they are read from the contract's global state.
//
// Nothing here reads a wallet's recorded network (wallet.Metadata.Network):
// a caller holding a testnet wallet passes Testnet() itself.
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

// Affinity configures continuation pinning (see AffinityPolicy).
// previous_response_id continuations are always strict: their session state
// lives on one node.
type Affinity struct {
	Policy AffinityPolicy
	TTL    time.Duration
	Max    int
}

// Discovery tunes operator discovery and the details probes behind routing.
// Only the registry New builds reads it.
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

	// OperatorIDs, when set, limits discovery to these operators.
	OperatorIDs []uint64
	// CatalogPath, when set, is the file discovery saves each fleet snapshot
	// to and New reads back, so a restart routes at once instead of
	// rediscovering the fleet over several refresh cycles.
	CatalogPath string
}

// Stores are the stateful pieces a process may want to persist or share.
type Stores struct {
	// Journal records open tickets. The in-memory default forgets them on
	// exit, so a long-running process should supply a durable one. Rows are
	// finished and deleted only when the SDK builds the wallet; with a
	// caller's Wallet there is no default, and a supplied journal is the
	// caller's to drain.
	Journal TicketJournal

	// The routing signals: per-relay forward reputation, observed network
	// latency, per-target failure backoff, and nodes proven to have handed a
	// fraudulent settle group. A nil store keeps no such signal.
	RelayReputation RelayReputation
	RelayLatency    RelayLatency
	TargetBackoff   TargetBackoff
	NodeExclusions  NodeExcluder

	// ToolAffinity pins tool-call continuations by tool_call_id, and
	// ResponseAffinity pins previous_response_id continuations by response
	// id. Nil builds one from Config.Affinity.
	ToolAffinity     *IDAffinity
	ResponseAffinity *IDAffinity
}

// Config configures a Client. Signer and Network are required; every other
// zero value means the default noted on the field.
type Config struct {
	Signer  Signer
	Network Network

	Privacy Privacy // PrivacyRelayRequired
	// AllowPrivacyOverride lets a request's relay preference turn relaying
	// off (Request.Relay, or the body's provider.relay); without it such an
	// opt-out is ignored. Asking for a relay is always honored.
	AllowPrivacyOverride bool
	// RequireTEEModels route only to attested nodes.
	RequireTEEModels []string
	// TEEVerifier checks the attestation evidence nodes publish, in the
	// discovery New builds. Nil uses DefaultTEEVerifier, which fetches each
	// TEE node's evidence on every refresh and Intel's collateral to check it.
	TEEVerifier TEEVerifier
	// DisableTEE checks no attestation evidence: every node counts as
	// unattested, so RequireTEEModels have no route. It overrides
	// TEEVerifier.
	DisableTEE bool

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

	// RetryBudget bounds one request's retrying of transient failures, all
	// before payment (transient.OverallDeadline). The client app shares the
	// default, so the two ride out an outage for the same time.
	RetryBudget time.Duration
	// SweepDelay is the wait before the given retry sweep over the candidate
	// list (transient.SweepDelay). Set, it also replaces the wait before a
	// busy re-sweep, the node's Retry-After included.
	SweepDelay func(sweep int) time.Duration

	// AllowStaging and AllowPrivateHosts admit staging nodes and nodes on
	// private addresses. Development only.
	AllowStaging      bool
	AllowPrivateHosts bool

	Stores     Stores
	SpendGuard SpendGuard // none: no cap
	// Remedies is what errors and logs tell the payer to do about what only
	// they can fix, in the caller's own terms; see Remedies.
	Remedies Remedies

	// UseEnvProxy sends node traffic (discovery, reserve, inference) through
	// the proxy named by HTTPS_PROXY / HTTP_PROXY / NO_PROXY. The
	// private-address guard then checks only the proxy's own address: the
	// proxy dials the node, so a node on a private address is no longer
	// refused, and a proxy on a private address is, unless AllowPrivateHosts.
	// An HTTPClient the caller supplies keeps its own proxy setting.
	UseEnvProxy bool

	// Registry, ReserveClient and Wallet are the network-facing parts:
	// operator discovery, the reserve call, and escrow. New builds each nil
	// one from Signer and Network; a supplied one is used as is, so the
	// settings only a built part reads (Discovery, TEEVerifier, and
	// ReserveTimeout, UseEnvProxy and AllowPrivateHosts for the discovery
	// probes and the reserve) do not reach it. A supplied Registry must apply
	// the same staging gate as AllowStaging.
	Registry      RegistryProvider
	ReserveClient ReserveClient
	Wallet        WalletOpener
	// Tokenizer estimates input tokens and resolves the output reservation;
	// nil builds one from MaxOutputByModel, MaxOutputCeiling and
	// RequireMaxOutput.
	Tokenizer *tokenize.Registry

	// DebugLogBodies writes every plaintext request body and decrypted
	// response to stderr. It deliberately breaks the rule that prompt and
	// response content is never logged, so it is for local debugging only.
	DebugLogBodies bool

	Logger *slog.Logger     // discards
	Clock  func() time.Time // time.Now
	// HTTPClient carries inference (see defaultHTTPClient). The reserve and
	// discovery clients New builds are its own.
	HTTPClient *http.Client
}

// Remedies are the instructions an error or log line ends with when the fix is
// the payer's: a command in the caller's CLI, a settings page in its app. Each
// is a clause that reads after "to fix it, ". An empty field gets one that
// names no tool.
type Remedies struct {
	// Fund adds ALGO and USDC to the payer's wallet. It ends wallet_unfunded
	// and mbr_pool_underfunded.
	Fund string
	// RaiseSlots raises ConcurrentSlots and funds the larger pool.
	RaiseSlots string
	// RaiseSpendCap raises the SpendGuard's limits.
	RaiseSpendCap string
	// RecoverTicket inspects a ticket the SDK gave up settling or refunding,
	// and finishes it.
	RecoverTicket string
}

// The defaults name only what the SDK itself offers. It has no USDC opt-in, so
// Fund says to do it; ConcurrentSlots is read once, when New builds the wallet,
// so RaiseSlots says to rebuild; the log a RecoverTicket rides carries the
// ticket id, which ReadTicketBox takes.
func (r Remedies) withDefaults() Remedies {
	r.Fund = cmp.Or(r.Fund,
		"fund the payer address: ALGO for fees and the ticket pool, and USDC for requests once the address has opted in to the USDC asset")
	r.RaiseSlots = cmp.Or(r.RaiseSlots,
		"raise Config.ConcurrentSlots (WalletConfig.DepositSlots for a Wallet you built) and rebuild the Client; the next request funds the larger pool")
	r.RaiseSpendCap = cmp.Or(r.RaiseSpendCap, "raise the SpendGuard's limits")
	r.RecoverTicket = cmp.Or(r.RecoverTicket,
		"read its box with escrow.Client.ReadTicketBox and, once the deadline passes, call refundInactive on an open ticket or settleLapsed on an operator's claim")
	return r
}

// defaultHTTPClient has no overall timeout, because streams end by context;
// a response-header backstop, so a connected but silent node is given up on;
// and the dial rules of nodeHTTPClient.
func (c Config) defaultHTTPClient() *http.Client {
	return c.nodeHTTPClient(0, httpx.ForwardHeaderBackstop)
}

// nodeHTTPClient is a client for dialing node-registered addresses: the
// private-address guard unless AllowPrivateHosts, and no environment proxy
// unless UseEnvProxy. http.DefaultTransport honours HTTP_PROXY, which would
// route around the guard and contradict "the SDK reads no environment".
func (c Config) nodeHTTPClient(timeout, headerTimeout time.Duration) *http.Client {
	hc := httpx.Client(timeout, httpx.Options{
		ResponseHeaderTimeout: headerTimeout,
		BlockPrivateTargets:   !c.AllowPrivateHosts,
	})
	if !c.UseEnvProxy {
		hc.Transport.(*http.Transport).Proxy = nil
	}
	return hc
}

const (
	defaultAffinityTTL = 10 * time.Minute
	defaultAffinityMax = 1024
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
	c.Remedies = c.Remedies.withDefaults()
	c.MaxOutputCeiling = orDefault(c.MaxOutputCeiling, selection.DefaultMaxOutputCeiling)
	c.ConcurrentSlots = orDefault(c.ConcurrentSlots, DefaultDepositSlots)
	c.ReserveTimeout = orDefault(c.ReserveTimeout, DefaultReserveTimeout)

	d := &c.Discovery
	d.RefreshInterval = orDefault(d.RefreshInterval, DefaultRefreshInterval)
	d.RefreshTimeout = orDefault(d.RefreshTimeout, DefaultRefreshTimeout)
	d.ProbeBudget = orDefault(d.ProbeBudget, DefaultProbeBudget)
	d.TargetTopK = orDefault(d.TargetTopK, DefaultTargetTopK)
	d.MaxCacheAge = orDefault(d.MaxCacheAge, DefaultMaxCacheAge)
	d.MaxCarryAge = orDefault(d.MaxCarryAge, DefaultMaxCarryAge)
	d.LatencyStateMax = orDefault(d.LatencyStateMax, DefaultLatencyStateMax)
	d.DetailsTimeout = orDefault(d.DetailsTimeout, DefaultDetailsFetchTimeout)
	d.DetailsConcurrency = orDefault(d.DetailsConcurrency, DefaultDetailsConcurrency)

	if c.Logger == nil {
		c.Logger = slog.New(slog.DiscardHandler)
	}
	switch {
	case c.DisableTEE:
		c.TEEVerifier = nil
	case c.TEEVerifier == nil:
		c.TEEVerifier = DefaultTEEVerifier(c.Logger)
	}
	if c.Clock == nil {
		c.Clock = time.Now
	}
	if c.HTTPClient == nil {
		c.HTTPClient = c.defaultHTTPClient()
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
	if ac.Network == "" && ac.Endpoint == "" {
		// Only a Network left wholly unset means mainnet. A token or an app id
		// on its own was meant for some chain, and guessing mainnet for it
		// would pay there.
		if ac.Token != "" || c.Network.EscrowAppID != 0 {
			return algod.Config{}, 0, nil, configError("Network.Algod.Network or Endpoint is required when Token or EscrowAppID is set")
		}
		ac.Network = string(algod.NetworkMainnet)
	}
	if err := ac.Resolve(); err != nil {
		return algod.Config{}, 0, nil, configError(err.Error())
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
	if c.TEEVerifier == nil && len(c.RequireTEEModels) > 0 {
		warnings = append(warnings, fmt.Sprintf(
			"RequireTEEModels %v have no route: TEE verification is off, so no node counts as attested",
			c.RequireTEEModels))
	}
	return ac, appID, warnings, nil
}

func configError(msg string) *Error {
	return &Error{Kind: KindInvalidRequest, Code: "invalid_config", Message: msg}
}
