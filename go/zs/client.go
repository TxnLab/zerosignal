/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs/tee"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// useCollateralLogger hands the process's collateral cache New's caller's
// logger; a variable so a test can watch what it hands over.
var useCollateralLogger = tee.UseCollateralLogger

// Client is the payer: routing, reserve, escrow, sealing and settlement. One
// Client serves every concurrent request, so per-request state never goes on
// it; a turn's state lives in its Stream.
type Client struct {
	cfg        Config
	log        *slog.Logger
	httpClient *http.Client
	// replyLimit is a test's cap on a buffered reply; zero is maxReplyBytes.
	replyLimit int64

	// Providers. The registry feeds operator selection, the reserve
	// client handles the pre-payment admission call, and the affinity cache
	// pins continuation requests to the same operator.
	registryProvider RegistryProvider
	reserveClient    ReserveClient
	// toolAffinity pins continuations of tool-calling conversations to the
	// operator that emitted the matching tool_call_id (chat) or call_id
	// (Responses). Honors the
	// configured affinity_policy (prefer/strict/none).
	toolAffinity *IDAffinity
	// responseAffinity pins /v1/responses continuations to the operator
	// that emitted the matching response_id. Keyed on response_id from
	// the upstream LLM (carried in the response body or response.created
	// SSE event) rather than tool_call_id.
	//
	// Match semantics differ from toolAffinity: a previous_response_id
	// hit is treated as STRICT regardless of the configured
	// affinity_policy (and on cache miss we block rather than fall
	// through). A continuation to the wrong operator is guaranteed to
	// 404 at upstream — the session state lives in a specific operator's
	// account.
	responseAffinity *IDAffinity
	// tokenizer resolves (model, body) → Estimate{InputTokens,
	// MaxOutputTokens} used to build ReserveRequest.
	tokenizer *tokenize.Registry

	// relayRep is the per-relay forward-reputation store (the
	// ChainOperatorSource backing the registry). relayHopFor consults it to
	// deprioritize a repeatedly-failing relay, and the inference forward path
	// reports each forward's outcome into it. Nil in tests / non-privacy
	// builds — every consult and report is then a no-op.
	relayRep RelayReputation

	// relayLatency is the per-process client-observed network-RTT store — the
	// same ChainOperatorSource that backs relayRep. The proxy is a localhost
	// single-user (payer) process, so this is genuinely the payer's own vantage
	// on the mesh, mirroring the client app's latency store. relayHopFor weights
	// relay selection by it and pickCandidates demotes confidently-slow targets;
	// the discovery probe + reserve POST record into it. Nil in tests /
	// non-privacy builds — every consult and record is then a no-op.
	relayLatency RelayLatency

	// targetBackoff is the per-target-node dispatch-failure memory (the same
	// ChainOperatorSource that backs relayRep/relayLatency). pickCandidates
	// demotes a currently-backed-off node to the tail so a persistently-failing
	// operator stops costing every request a doomed round-trip; the reserve loop
	// records target-attributable transient failures into it. Nil in tests —
	// every consult and record is then a no-op. Mirrors the TS SDK's
	// TargetBackoffStore.
	targetBackoff TargetBackoff

	// nodeExcluder is the write-once, never-reset set of nodes proven to have
	// handed a fraudulent atomic settle group (the same ChainOperatorSource that
	// backs relayRep/targetBackoff). runReceiptChecks records a rejection here
	// and pickCandidates / the relay pool hard-drop excluded nodes — the one
	// deliberately non-self-healing routing signal (proven misbehaviour, not a
	// transient fault). Nil in tests — every consult and record is then a no-op.
	// Mirrors the TS SDK's NodeExclusionStore.
	nodeExcluder NodeExcluder

	// weightsWarned dedupes the "digest contradicts peer consensus" WARN to one
	// line per (model, node) for the process lifetime. The demerit is recomputed
	// on EVERY pickCandidates — once per dispatch plus once per transient/busy
	// sweep — and a legitimately requantizing operator contradicts on all of
	// them, so an undeduped WARN would repeat forever on the hot path and train
	// the payer to ignore the level. The final candidate order is on logRanking
	// either way. Same shape as the node's provenanceWarned. See
	// weights_trust.go.
	weightsWarned sync.Map

	// spend is the aggregate USDC spend guard, checked before each escrow
	// open and credited after. Nil disables enforcement (tests / no caps
	// configured). See SpendGuard.
	spend SpendGuard

	// refunds recovers escrowed USDC for orphaned tickets — an open() that
	// committed but whose settlement never arrived (node burned the ticket on
	// a payment-verification failure, transport loss, operator death). Every
	// successful Open is tracked; a finalized atomic settle or a protest
	// resolves the entry; anything left fires refundInactive after
	// expires_at + grace. Nil-safe throughout (test fakes carry detached
	// handles the watchdog skips).
	refunds *RefundWatchdog

	// journal records each open ticket until its box is gone; reconcile
	// finishes the ones refunds is not watching. reconcile is nil when the
	// wallet is not a *Wallet, which is the only one that can act on chain.
	journal   TicketJournal
	reconcile *reconciler

	// settles counts background escrow work: submits still running after
	// their response was written (submitAfterResponse) and watches on atomic
	// settles (confirmSettled), so WaitSettles can drain them on shutdown;
	// settlesInFlight holds their ticket ids for its timeout report.
	settles         drain
	settlesInFlight sync.Map

	// life is cancelled by Close, ending background work that would
	// otherwise outlive the Client; nil for a Client built without New.
	life    context.Context
	endLife context.CancelFunc

	// wallet drives the escrow payment path. dispatch calls Open to compose +
	// sign + submit the Payment + escrow.open atomic group and returns the
	// app-call txid (OpenHandle.AppCallTxID — the real per-txn id the node
	// can look up via algod.PendingTransactionInformation). The group id is
	// carried alongside on the handle for audit logging.
	//
	// Interface rather than concrete type so tests can inject a fake
	// that returns deterministic txids without needing a running
	// algod.
	wallet WalletOpener

	// feeRate caches the proxy payer's live protocol-fee rate (feeBps) for the
	// payer-facing cost breakdown. Refreshed in the background off a direct
	// protocolFeeBps global read; the response path never blocks on it. Zero
	// value is a valid cold cache (see feeRateNow / feeRateCache).
	feeRate feeRateCache

	// retryBudget and sweepDelayFn are Config.RetryBudget and
	// Config.SweepDelay; zero takes the shared schedule (transientRetryBudget,
	// sweepDelay).
	retryBudget  time.Duration
	sweepDelayFn func(sweep int) time.Duration

	// debugLogBodies dumps the full plaintext request body sent to the node
	// AND the decrypted response (non-stream body / streaming frames) to
	// stderr (Config.DebugLogBodies). DELIBERATELY breaks the non-retention
	// rule (see AGENTS.md) — local debugging only, never enable in
	// production. See debug.go.
	debugLogBodies bool

	deployment Deployment

	// stop ends the background work New started; nil when it started none.
	stop func()
	// ownJournal is the journal New opened from Stores.JournalPath, which
	// Close closes; nil when the caller supplied or New defaulted it.
	ownJournal *FileJournal
	// durableJournal is what JournalDurable reports.
	durableJournal bool
}

// New builds a Client, and each nil Registry, ReserveClient and Wallet from
// Signer and Network. Building them reads the chain: the escrow's config,
// which must succeed, and a first discovery, which may fail and is retried in
// the background. That discovery is the chain read and a details probe of
// every node, and New waits for both, up to a minute. The TS Client waits only
// for the chain read; its probe runs in the background, and a request made
// before it finishes waits for it. ctx bounds those reads only. Close stops
// the background work.
func New(ctx context.Context, cfg Config) (*Client, error) {
	callerLogger := cfg.Logger
	cfg = cfg.withDefaults()
	dep, warnings, err := cfg.validate()
	if err != nil {
		return nil, err
	}
	ac, appID := dep.Algod, dep.EscrowAppID
	for _, w := range warnings {
		cfg.Logger.Warn(w)
	}
	// Only a Logger the caller set: the cache is the process's, so the
	// discard default would silence it for every later Client too.
	useCollateralLogger(callerLogger)
	// Another directory already in use still serves this Client: the
	// documents are the same, only where they persist differs.
	if err := tee.PersistCollateral(cfg.Stores.CollateralDir); err != nil {
		cfg.Logger.Warn("Stores.CollateralDir is not used", slog.Any("err", err))
	}
	cfg.Network = Network{Rail: dep.Rail, Algod: ac, EscrowAppID: appID}
	if d := cfg.Discovery; d.CatalogPath != "" {
		if err := AdoptLegacyFile(d.CatalogLegacyPath, d.CatalogPath); err != nil {
			cfg.Logger.Warn("could not rename the saved operator catalog; discovery starts without it",
				slog.String("from", d.CatalogLegacyPath), slog.String("to", d.CatalogPath), slog.Any("err", err))
		}
	}
	parts, err := buildNetworkParts(ctx, cfg, ac, appID)
	if err != nil {
		return nil, err
	}
	cfg.Registry, cfg.ReserveClient, cfg.Wallet = parts.registry, parts.reserve, parts.wallet
	st := cfg.Stores
	if src := parts.source; src != nil {
		if st.RelayReputation == nil {
			st.RelayReputation = src
		}
		if st.RelayLatency == nil {
			st.RelayLatency = src
		}
		if st.TargetBackoff == nil {
			st.TargetBackoff = src
		}
		if st.NodeExclusions == nil {
			st.NodeExclusions = src
		}
	}
	if st.ToolAffinity == nil {
		st.ToolAffinity = NewIDAffinity(cfg.Affinity.Max, cfg.Affinity.TTL, cfg.Clock)
	}
	if st.ResponseAffinity == nil {
		st.ResponseAffinity = NewIDAffinity(cfg.Affinity.Max, cfg.Affinity.TTL, cfg.Clock)
	}
	tok := cfg.Tokenizer
	if tok == nil {
		fallback := cfg.MaxOutputCeiling
		if cfg.RequireMaxOutput {
			fallback = 0
		}
		tok = tokenize.BuildRegistry(cfg.MaxOutputByModel, fallback)
	}
	// stopParts undoes what New has started so far, on a failure from here on.
	var ownJournal *FileJournal
	stopParts := func() {
		if parts.stop != nil {
			parts.stop()
		}
		if ownJournal != nil {
			_ = ownJournal.Close()
			releaseJournalPath(st.JournalPath)
		}
	}
	if st.JournalPath != "" {
		// Another Client in this process holding the file is a wiring
		// mistake, refused as a shared Stores.Journal is; another process
		// holding it, or a file that will not open, is not this caller's to
		// fix at startup, and the file is left as it is either way.
		if !claimJournalPath(st.JournalPath) {
			stopParts()
			return nil, configError("Stores.JournalPath is already open in another Client in this process: each Client needs its own journal file")
		}
		j, err := OpenFileJournal(st.JournalPath, st.JournalLegacyPaths...)
		if err != nil {
			releaseJournalPath(st.JournalPath)
			cfg.Logger.Warn("ticket journal file is not used: a ticket this Client leaves open after a crash is refunded only by hand",
				slog.String("path", st.JournalPath), slog.Any("err", err))
		} else {
			ownJournal, st.Journal = j, j
			for _, s := range j.MergeSkipped() {
				cfg.Logger.Warn("ticket journal under an earlier name is not merged yet; the next start tries again",
					slog.String("path", s.Path), slog.Any("err", s.Err))
			}
		}
	}
	// Only the SDK's own wallet runs a reconciler, which is what deletes rows;
	// with a caller's wallet a default journal would only grow.
	sdkWallet, _ := cfg.Wallet.(*Wallet)
	durableJournal := st.Journal != nil
	if st.Journal == nil && sdkWallet != nil {
		st.Journal = newMemJournal()
		if st.JournalPath == "" {
			cfg.Logger.Info("open tickets are journaled in memory: after a restart, a ticket this process opened is refunded only by hand. Set Stores.JournalPath to keep them")
		}
	}
	var release func()
	if sdkWallet != nil {
		var ok bool
		if release, ok = claimJournal(st.Journal); !ok {
			stopParts()
			return nil, configError("Stores.Journal is already swept by another Client in this process: each Client that builds or is handed a *Wallet needs its own journal")
		}
	}
	cfg.Stores, cfg.Tokenizer = st, tok
	c := &Client{
		cfg:              cfg,
		log:              cfg.Logger,
		httpClient:       cfg.HTTPClient,
		registryProvider: cfg.Registry,
		reserveClient:    cfg.ReserveClient,
		toolAffinity:     st.ToolAffinity,
		responseAffinity: st.ResponseAffinity,
		tokenizer:        tok,
		relayRep:         st.RelayReputation,
		relayLatency:     st.RelayLatency,
		targetBackoff:    st.TargetBackoff,
		nodeExcluder:     st.NodeExclusions,
		spend:            cfg.SpendGuard,
		refunds:          NewRefundWatchdog(cfg.Logger),
		journal:          st.Journal,
		wallet:           cfg.Wallet,
		retryBudget:      cfg.RetryBudget,
		sweepDelayFn:     cfg.SweepDelay,
		debugLogBodies:   cfg.DebugLogBodies,
		deployment:       dep,
		stop:             parts.stop,
		ownJournal:       ownJournal,
		durableJournal:   durableJournal,
	}
	c.life, c.endLife = context.WithCancel(context.Background())
	c.refunds.remedy = cfg.Remedies.RecoverTicket
	if cfg.SpendGuard != nil {
		// A ticket whose request failed after its escrow opened keeps its
		// reservation in dispatch; its refund is what frees it.
		guard, log := cfg.SpendGuard, c.log
		c.refunds.refunded = func(ticketID string) {
			recordSpend(log, "release", ticketID, func() { guard.Release(ticketID) })
		}
	}
	if c.nodeExcluder != nil {
		c.refunds.overclaimed = c.barOverclaimer
	}
	if sdkWallet != nil {
		c.reconcile = newReconciler(st.Journal, walletChain{sdkWallet}, sdkWallet.PayerAddr(), dep, c.refunds.watching, cfg.SpendGuard, cfg.Logger)
		if c.nodeExcluder != nil {
			c.reconcile.overclaimed = func(rec TicketRecord) { c.barOverclaimer(rec.TicketID, rec.Target) }
		}
		c.reconcile.remedy = cfg.Remedies.RecoverTicket
		c.reconcile.release = release
		// A memory journal dies with this Client, so its watchdog stays the
		// only thing that finishes its tickets.
		c.reconcile.handOff = durableJournal
		c.reconcile.start()
	}
	c.warmFeeRate()
	return c, nil
}

// barOverclaimer bars a node whose claim on a ticket's box exceeds the receipt
// it signed, found by the refund watchdog or the reconciler rather than by a
// turn's ack: a claim posted after the ack's read, or after the ack failed,
// or one a restart left. Both find it again on every read of the box, so only
// the first is logged.
func (s *Client) barOverclaimer(ticketID string, node NodeRef) {
	if s.nodeExcluder == nil || s.nodeExcluder.NodeExcluded(node) {
		return
	}
	s.nodeExcluder.ExcludeNode(node)
	s.log.Warn("node excluded: its on-chain settle claim exceeds the receipt it signed",
		slog.String("ticket_id", ticketID),
		slog.Uint64("operator_id", node.Op),
		slog.Uint64("node_id", node.Node))
}

// remedies fills the defaults here rather than trusting New to have, because a
// Client built in a test skips New.
func (s *Client) remedies() Remedies { return s.cfg.Remedies.withDefaults() }

// Close stops the discovery refresh and the ticket reconciler New started. It
// does not wait for settlements; see WaitSettles. It ends any watch on a
// settle still unconfirmed, leaving that ticket's journal row in place. When
// New built the wallet and Stores.Journal is set, Close also stops the refund
// watchdog, waiting out
// a refund it already sent, and leaves the tickets it watched to the next
// Client that sweeps that journal, or to the next process. A request still in
// flight on the closed Client is then not watched here, so WaitSettles before
// Close when no Client follows. A journal New opened from Stores.JournalPath
// is closed last. Safe to call more than once.
func (s *Client) Close() {
	if s.endLife != nil {
		s.endLife()
	}
	if s.stop != nil {
		s.stop()
	}
	if s.reconcile != nil {
		var handOff func()
		if s.reconcile.handOff {
			handOff = s.refunds.handOff
		}
		s.reconcile.close(handOff)
	}
	if s.ownJournal != nil && s.ownJournal.Close() == nil {
		releaseJournalPath(s.cfg.Stores.JournalPath)
	}
}

// JournalDurable reports whether this Client journals open tickets somewhere
// that outlives the process: a Stores.Journal the caller supplied, or the
// file Stores.JournalPath names. False is the in-memory default, after which
// a ticket left open by a crash is refunded only by hand.
func (s *Client) JournalDurable() bool { return s.durableJournal }

// Deployment is the deployment the Client pays on.
func (s *Client) Deployment() Deployment { return s.deployment }

// Config is the Client's configuration with every default applied and the
// parts New built filled in.
func (s *Client) Config() Config { return s.cfg }

// Registry is the operator catalog the Client routes from.
func (s *Client) Registry() RegistryProvider { return s.registryProvider }

// Refunds is the watchdog that recovers escrow for tickets whose settlement
// never arrived.
func (s *Client) Refunds() *RefundWatchdog { return s.refunds }

// FeeRate is the protocol fee rate, in basis points on top of an operator's
// charge, that this payer currently pays. It is read from chain in the
// background and never blocks; ok is false until the first read lands.
func (s *Client) FeeRate() (feeBps uint64, ok bool) { return s.feeRateNow() }

func (c *Config) relayByDefault() bool { return c.Privacy != PrivacyDirect }

func (c *Config) teeRequired(model string) bool { return slices.Contains(c.RequireTEEModels, model) }

// networkName names the chain in a funding error, spelled as the handler's
// funding hint compares it.
func (s *Client) networkName() string { return string(s.cfg.Network.Algod.ResolvedNetwork) }

// settlementHandle is the subset of *OpenHandle the response builders use to
// settle or dispute a ticket.
type settlementHandle interface {
	// AckSettle finalizes the ticket. When settleGroup is non-empty, it's
	// the operator's pre-signed atomic settle group from X-Zs-Settle-Group,
	// already checked to decode — the wallet signs the payer-ack member and
	// submits as a 2-tx group (payer pays 0 ALGO at settle). When empty,
	// falls back to the standalone path (payer pays ~5,000 µALGO outer fee).
	AckSettle(ctx context.Context, receipt *ticket.UsageReceipt, settleGroup string) (AckResult, error)
	// Protest freezes the ticket. The payer signs and pays for it, so the fee
	// is the payer's.
	Protest(ctx context.Context, receipt *ticket.UsageReceipt, excerpt []byte, reason escrow.ProtestReasonCode) (txid string, feeMicroalgos uint64, err error)
}

// WalletOpener is the escrow side of the payer: *Wallet, or a fake that
// returns deterministic txids without a running algod.
//
// Open takes the node's pre-signed open from the reserve response
// (ReservedTicket.PresignedOpen), completes it as the payer and submits it.
// On Algorand that is the 2-tx open group (gtxn[1] = open() AppCall signed
// by operator; gtxn[0] = usdcPayment template for the wallet to sign as the
// payer), and the per-ticket box MBR is drawn from the payer's prepaid MBR
// pool at open(), not a funding leg in this group. PayerAddr populates
// ReserveRequest.PayerAddr so the operator can pre-sign the open group
// bound to this address.
type WalletOpener interface {
	Open(ctx context.Context, ticket *ticket.Ticket, op Operator, presignedOpen string) (*OpenHandle, error)
	PayerAddr() string
}

// DepositPreparer is an optional WalletOpener method that dispatch calls
// before the first reserve. A node may refuse a reserve from a payer with no
// prepaid pool (403 payer_not_opted_in), and the pool is otherwise funded only
// inside Open, after a reserve has succeeded, so a new payer would never get
// past the reserve. *Wallet implements it.
type DepositPreparer interface {
	PrepareDeposit(ctx context.Context) error
}

// DepositRechecker is an optional WalletOpener method dispatch calls when a
// node refuses a reserve with payer_not_opted_in. The node saw no escrow-app
// opt-in for the payer: its MBR deposit was closed outside this wallet
// (another process, or another tab of the same payer), its first deposit
// hasn't confirmed yet, or the node's cache is stale. Only the first is
// lasting, and a wallet that has already checked the deposit skips the opt-in
// on later requests, so every one would be refused the same way. Rechecking is
// safe in the other cases: it costs one opt-in read. *Wallet implements it.
type DepositRechecker interface {
	RecheckDeposit()
}

// NodeOpener is an optional WalletOpener method dispatch uses for a target
// that submits the open itself (wire.SubmitsOpen). OpenForNode verifies and
// signs the group like Open but broadcasts nothing, and returns it on
// OpenHandle.OpenGroup for the sealed request. A wallet without it keeps
// submitting, which every node still accepts. *Wallet implements it.
type NodeOpener interface {
	OpenForNode(ctx context.Context, ticket *ticket.Ticket, op Operator, presignedOpen string) (*OpenHandle, error)
}
