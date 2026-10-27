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
	"github.com/TxnLab/zerosignal/go/solana"
	"github.com/TxnLab/zerosignal/go/solana/rpc"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs/tee"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// PayerSigner is the half of the payer's key every rail uses: its address and
// raw Ed25519 over digests (the reserve request: not MX-prefixed, not ARC-1).
type PayerSigner interface {
	Address() string
	ticket.BytesSigner
}

// Signer holds the payer's key, for one address, on the Algorand rail: the
// PayerSigner half plus the signer of Algorand transactions (escrow open,
// settle, refund). Another rail pairs PayerSigner with its own transaction
// half.
type Signer interface {
	PayerSigner
	algo.MultipleWalletSigner
}

// SolanaSigner holds the payer's key, for one base58 address, on the Solana
// rail: the PayerSigner half plus the signer of Solana transactions. Like
// Algorand's, the transaction half signs any message: a node's offer or a
// relayer's ack reaches it only through zsescrow's CompleteOpenOffer and
// CompleteRelayedAck, which verify it first, and the payer's own
// transactions through Transaction.SignWith.
type SolanaSigner interface {
	PayerSigner
	solana.TransactionSigner
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
//
// Rail zero is Algorand, which reads Algod and EscrowAppID; ticket.RailSolana
// reads Solana instead. Each rail refuses the other's fields, so a Solana
// setting without the rail fails New rather than paying on Algorand mainnet.
type Network struct {
	Rail        ticket.Rail
	Algod       algod.Config
	EscrowAppID uint64
	Solana      SolanaNetwork
}

// SolanaNetwork selects the cluster and the zs_escrow program on the Solana
// rail. Naming a preset in Cluster ("devnet" or "localnet", case-insensitive)
// is enough; RPCEndpoint overrides its JSON-RPC endpoint, verbatim, since a
// provider's key may ride in its path or query. There is no zero-value
// cluster: a Solana Network names its cluster or its endpoint. A zero Program
// takes the preset's, so an endpoint alone must set it. The USDC mint is never
// configured: it is read from the program's Config.
type SolanaNetwork struct {
	Cluster     string
	RPCEndpoint string
	Program     solana.PublicKey
}

func Testnet() Network  { return Network{Algod: algod.Config{Network: string(algod.NetworkTestnet)}} }
func Mainnet() Network  { return Network{Algod: algod.Config{Network: string(algod.NetworkMainnet)}} }
func Localnet() Network { return Network{Algod: algod.Config{Network: string(algod.NetworkLocalnet)}} }

func SolanaDevnet() Network {
	return Network{Rail: ticket.RailSolana, Solana: SolanaNetwork{Cluster: SolanaClusterDevnet}}
}

func SolanaLocalnet() Network {
	return Network{Rail: ticket.RailSolana, Solana: SolanaNetwork{Cluster: SolanaClusterLocalnet}}
}

// Name is the preset a resolved Network names on its rail, as Client.Config
// returns it, and empty when only an endpoint named the chain.
func (n Network) Name() string {
	if n.Rail == ticket.RailSolana {
		return n.Solana.Cluster
	}
	return string(n.Algod.ResolvedNetwork)
}

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
	// CatalogLegacyPath is the name CatalogPath had before; New renames it to
	// CatalogPath when only it exists.
	CatalogLegacyPath string
}

// Stores are the stateful pieces a process may want to persist or share.
type Stores struct {
	// Journal records open tickets. The in-memory default forgets them on
	// exit, so a long-running process should supply a durable one. Rows are
	// finished and deleted only when the wallet is one of the SDK's own types,
	// *Wallet or *SolanaWallet, whoever built it; with any other Wallet there
	// is no default, and a supplied journal is the caller's to drain. A Client
	// that finishes rows needs a journal no other
	// open Client in the process writes for the same payer: New refuses a
	// second Client that finishes rows, but not one with a caller's Wallet,
	// whose live tickets the first would then race its watchdog to refund.
	Journal TicketJournal
	// JournalPath, instead of Journal, is a file New opens as the journal
	// (OpenFileJournal) and Close closes, after the reconciler has let go of
	// it. Name one file per deployment (StateFile), so a process on one
	// network never locks out a process on another. Another Client in this
	// process with the same file fails New. A file another process holds, or
	// one that will not open, is left untouched and this Client journals in
	// memory, with a warning logged; JournalDurable then reports false.
	JournalPath string
	// JournalLegacyPaths are files the journal had other names in before;
	// OpenFileJournal merges each into JournalPath and removes it.
	JournalLegacyPaths []string

	// CollateralDir is a state directory the TEE collateral cache persists
	// to, so a restart during an Intel PCS outage still has collateral to
	// verify against. Empty keeps it in memory. The cache is the process's
	// (see tee.PersistCollateral), so it persists to the first directory named;
	// New logs a later, different one and goes on. Use a state directory,
	// not a cache directory the OS may sweep.
	CollateralDir string

	// The routing signals: per-relay forward reputation, observed network
	// latency, per-target failure backoff, and nodes proven to have handed a
	// fraudulent settle group. A nil store keeps no such signal.
	RelayReputation RelayReputation
	RelayLatency    RelayLatency
	TargetBackoff   TargetBackoff
	NodeExclusions  NodeExcluder

	// ToolAffinity pins tool-call continuations by tool_call_id or Responses
	// call_id, and ResponseAffinity pins previous_response_id continuations by
	// response id. Nil builds one from Config.Affinity.
	ToolAffinity     *IDAffinity
	ResponseAffinity *IDAffinity
}

// Config configures a Client. Network and the payer's key on its rail are
// required: Signer on Algorand, SolanaSigner on Solana, and never the other
// rail's. Every other zero value means the default noted on the field.
type Config struct {
	Signer       Signer
	SolanaSigner SolanaSigner
	Network      Network

	Privacy Privacy // PrivacyRelayRequired
	// AllowPrivacyOverride lets a request's relay preference turn relaying
	// off (Request.Relay, or the body's provider.relay); without it such an
	// opt-out is ignored. Asking for a relay is always honored.
	AllowPrivacyOverride bool
	// RequireTEEModels route only to attested nodes.
	RequireTEEModels []string
	// TEEVerifier checks the attestation evidence nodes publish, in the
	// discovery New builds. Nil uses tee.DefaultVerifier, which fetches each
	// TEE node's evidence on every refresh and Intel's collateral to check it.
	// A custom verifier must report tee.Verdict.MeasurementChecks, or no node
	// it passes counts as attested.
	TEEVerifier tee.Verifier
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
	// StreamIdle is how long a streamed answer may go without a byte before
	// the turn ends stream_interrupted, caused by a *StreamIdleTimeoutError;
	// zero fields take DefaultStreamIdle, and Off sets no bound. The forward
	// client has no read timeout, so without one a node or relay that stops
	// sending without closing holds the turn until the caller's context ends.
	// A whole reply's body is held to MidStream, and ends read_upstream.
	StreamIdle StreamIdle
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
	// FreeCredits are the issuers a free Solana turn fetches a credit from,
	// which a node that trusts one may require of a payer before spending its
	// free budget on it (SPEC.md § 3a "Free credits"). None by default. Only
	// on Solana: an Algorand free ticket is rationed by the contract.
	FreeCredits FreeCredits
	// Remedies is what errors and logs tell the payer to do about what only
	// they can fix, in the caller's own terms; see Remedies.
	Remedies Remedies

	// UseEnvProxy sends node traffic (discovery, reserve, inference) and the
	// Algorand API calls through the proxy named by HTTPS_PROXY / HTTP_PROXY /
	// NO_PROXY. The private-address guard then checks only the proxy's own
	// address: the proxy dials the node, so a node on a private address is no
	// longer refused, and a proxy on a private address is, unless
	// AllowPrivateHosts. An HTTPClient the caller supplies keeps its own proxy
	// setting. Fetches of Intel's attestation collateral always honour those
	// variables: the collateral cache is shared by every Client in the
	// process, and the request names only Intel's own host.
	UseEnvProxy bool

	// Registry, ReserveClient and Wallet are the network-facing parts:
	// operator discovery, the reserve call, and escrow. New builds each nil
	// one from Network and the payer's key; a supplied one is used as is, so the
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
	// Fund adds the rail's coin (ALGO or SOL) and USDC to the payer's wallet.
	// It ends wallet_unfunded and mbr_pool_underfunded.
	Fund string
	// RaiseSlots raises ConcurrentSlots and funds the larger pool.
	RaiseSlots string
	// RaiseSpendCap raises the SpendGuard's limits.
	RaiseSpendCap string
	// RecoverTicket inspects a ticket the SDK gave up settling or refunding,
	// and finishes it.
	RecoverTicket string
}

// The defaults name only what the SDK itself offers, for the payer's rail. It
// has no USDC opt-in, so Algorand's Fund says to do it; Solana has no opt-in,
// and its pool holds ticket rent, not MBR. ConcurrentSlots is read once, when
// New builds the wallet, so RaiseSlots says to rebuild. The log a
// RecoverTicket rides carries the ticket id, which ReadTicketBox takes, and
// which names a Solana ticket account with its node.
func (r Remedies) withDefaults(rail ticket.Rail) Remedies {
	fund := "fund the payer address: ALGO for fees and the ticket pool, and USDC for requests once the address has opted in to the USDC asset"
	raiseSlots := "raise Config.ConcurrentSlots (WalletConfig.DepositSlots for a Wallet you built) and rebuild the Client; the next request funds the larger pool"
	recoverTicket := "read its box with escrow.Client.ReadTicketBox and, once the deadline passes, call refundInactive on an open ticket or settleLapsed on an operator's claim"
	if rail == ticket.RailSolana {
		fund = solanaFundRemedy
		raiseSlots = "raise Config.ConcurrentSlots (SolanaWalletConfig.DepositSlots for a SolanaWallet you built) and rebuild the Client; the next request funds the larger pool"
		recoverTicket = solanaRecoverTicketRemedy
	}
	r.Fund = cmp.Or(r.Fund, fund)
	r.RaiseSlots = cmp.Or(r.RaiseSlots, raiseSlots)
	r.RaiseSpendCap = cmp.Or(r.RaiseSpendCap, "raise the SpendGuard's limits")
	r.RecoverTicket = cmp.Or(r.RecoverTicket, recoverTicket)
	return r
}

// The Solana defaults, the TS twin's word for word.
const (
	solanaFundRemedy          = "fund the payer address: SOL for fees and the ticket rent pool, and USDC for requests"
	solanaRecoverTicketRemedy = "read its ticket account from the escrow program and, once the deadline passes, send refund_inactive on an open ticket or settle_lapsed on an operator's claim"
)

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

// algodTransport is algod's pooled, retrying transport, with no environment
// proxy unless UseEnvProxy, for the same reason as nodeHTTPClient.
func (c Config) algodTransport() *algod.RetryRoundTripper {
	rt := algod.DefaultTransport()
	if !c.UseEnvProxy {
		rt.Transport.Proxy = nil
	}
	return rt
}

// solanaTransport is the Solana RPC's pooled transport, with no environment
// proxy unless UseEnvProxy, as algodTransport.
func (c Config) solanaTransport() *http.Transport {
	t := rpc.DefaultTransport()
	if !c.UseEnvProxy {
		t.Proxy = nil
	}
	return t
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
	c.Remedies = c.Remedies.withDefaults(c.Network.Rail)
	c.MaxOutputCeiling = orDefault(c.MaxOutputCeiling, selection.DefaultMaxOutputCeiling)
	c.ConcurrentSlots = orDefault(c.ConcurrentSlots, DefaultDepositSlots)
	c.ReserveTimeout = orDefault(c.ReserveTimeout, DefaultReserveTimeout)
	c.StreamIdle = c.StreamIdle.withDefaults()
	c.FreeCredits.Batch = orDefault(c.FreeCredits.Batch, DefaultFreeCreditBatch)

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
		c.TEEVerifier = tee.DefaultVerifier(c.Logger)
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

// validate checks a defaulted Config and returns its resolved deployment,
// plus warnings for settings that work but are probably mistakes.
func (c Config) validate() (d Deployment, warnings []string, err error) {
	if err := c.validateSigner(); err != nil {
		return d, nil, err
	}
	switch c.Privacy {
	case PrivacyRelayRequired, PrivacyDirect:
	default:
		return d, nil, configError(fmt.Sprintf("unknown Privacy %q", c.Privacy))
	}
	switch c.Affinity.Policy {
	case AffinityPrefer, AffinityStrict, AffinityNone:
	default:
		return d, nil, configError(fmt.Sprintf("unknown Affinity.Policy %q", c.Affinity.Policy))
	}
	if c.Stores.Journal != nil && c.Stores.JournalPath != "" {
		return d, nil, configError("set Stores.Journal or Stores.JournalPath, not both")
	}
	if err := c.FreeCredits.validate(); err != nil {
		return d, nil, err
	}
	if d, warnings, err = ResolveNetwork(c.Network); err != nil {
		return Deployment{}, nil, err
	}
	if len(c.FreeCredits.Issuers) > 0 && d.Rail != ticket.RailSolana {
		warnings = append(warnings, "FreeCredits are used on the Solana rail only; this network's free tickets are rationed on chain")
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
	return d, warnings, nil
}

// validateSigner checks that the payer's key is the one Network's rail signs
// with. The other rail's signer is refused rather than ignored: a host that
// sets it has most likely left the rail unset.
func (c Config) validateSigner() error {
	if c.Network.Rail == ticket.RailSolana {
		if c.Signer != nil {
			return configError("Signer is the Algorand rail's; a Solana Network takes SolanaSigner")
		}
		if c.SolanaSigner == nil {
			return configError("SolanaSigner is required on the Solana rail")
		}
		addr := c.SolanaSigner.Address()
		if addr == "" {
			return configError("SolanaSigner has no address")
		}
		if _, err := solana.ParsePublicKey(addr); err != nil {
			return configError(fmt.Sprintf("SolanaSigner's address %q is not a Solana public key", addr))
		}
		return nil
	}
	if c.SolanaSigner != nil {
		return configError("SolanaSigner is the Solana rail's; set Network.Rail to ticket.RailSolana, or pass Signer")
	}
	if c.Signer == nil {
		return configError("Signer is required")
	}
	addr := c.Signer.Address()
	if addr == "" {
		return configError("Signer has no address")
	}
	// Checked up front because the first transaction signature comes at
	// escrow open, after a node has already spent a reservation on us.
	if !c.Signer.HasAccount(addr) {
		return configError(fmt.Sprintf("Signer cannot sign for its own address %s", addr))
	}
	return nil
}

// payerSigner is the payer's key on Network's rail, after validate.
func (c Config) payerSigner() PayerSigner {
	if c.Network.Rail == ticket.RailSolana {
		return c.SolanaSigner
	}
	return c.Signer
}

func configError(msg string) *Error {
	return &Error{Kind: KindInvalidRequest, Code: "invalid_config", Message: msg}
}
