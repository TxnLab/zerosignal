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

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// Client is the payer: routing, reserve, escrow, sealing and settlement. One
// Client serves every concurrent request, so per-request state never goes on
// it; a turn's state lives in its Stream.
type Client struct {
	cfg        Config
	log        *slog.Logger
	httpClient *http.Client

	// Hayai providers. The registry feeds operator selection, the reserve
	// client handles the pre-payment admission call, and the affinity cache
	// pins continuation requests to the same operator.
	registryProvider RegistryProvider
	reserveClient    ReserveClient
	// toolAffinity pins continuations of tool-calling chat conversations
	// to the operator that emitted the matching tool_call_id. Honors the
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
	// every consult and record is then a no-op. Mirrors the client's
	// target-backoff.ts.
	targetBackoff TargetBackoff

	// nodeExcluder is the write-once, never-reset set of nodes proven to have
	// handed a fraudulent atomic settle group (the same ChainOperatorSource that
	// backs relayRep/targetBackoff). runReceiptChecks records a rejection here
	// and pickCandidates / the relay pool hard-drop excluded nodes — the one
	// deliberately non-self-healing routing signal (proven misbehaviour, not a
	// transient fault). Nil in tests — every consult and record is then a no-op.
	// Mirrors the client's excluded-nodes.ts.
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

	// settles counts escrow submits still running after their response was
	// written (submitAfterResponse), so WaitSettles can drain them on
	// shutdown; settlesInFlight holds their ticket ids for its timeout
	// report.
	settles         sync.WaitGroup
	settlesInFlight sync.Map

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
}

// New builds a Client. For now it does not build Registry, ReserveClient or
// Wallet from Signer and Network, so a Client is usable only with all three
// supplied.
func New(ctx context.Context, cfg Config) (*Client, error) {
	cfg = cfg.withDefaults()
	st := cfg.Stores
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
	return &Client{
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
		wallet:           cfg.Wallet,
		retryBudget:      cfg.RetryBudget,
		sweepDelayFn:     cfg.SweepDelay,
		debugLogBodies:   cfg.DebugLogBodies,
	}, nil
}

// Refunds is the watchdog that recovers escrow for tickets whose settlement
// never arrived.
func (s *Client) Refunds() *RefundWatchdog { return s.refunds }

// FeeRate is the protocol fee rate, in basis points on top of an operator's
// charge, that this payer currently pays. It is read from chain in the
// background and never blocks; ok is false until the first read lands.
func (s *Client) FeeRate() (feeBps uint64, ok bool) { return s.feeRateNow() }

func (c *Config) relayByDefault() bool { return c.Privacy != PrivacyDirect }

func (c *Config) teeRequired(model string) bool { return slices.Contains(c.RequireTEEModels, model) }

// networkName names the chain in a funding error.
func (s *Client) networkName() string { return s.cfg.Network.Algod.Network }

// settlementHandle is the subset of *OpenHandle the response builders use to
// settle or dispute a ticket.
type settlementHandle interface {
	// AckSettle finalizes the ticket. When presignedSettleGroup is
	// non-empty, it's the operator's pre-signed atomic settle group
	// from X-Zs-Settle-Group — the wallet signs the payer-ack
	// member and submits as a 2-tx group (payer pays 0 ALGO at
	// settle). When empty, falls back to the standalone path
	// (payer pays ~5,000 µALGO outer fee).
	AckSettle(ctx context.Context, receipt *ticket.UsageReceipt, presignedSettleGroup []types.SignedTxn) (txid string, feeMicroalgos uint64, groupRejected bool, err error)
	Protest(ctx context.Context, receipt *ticket.UsageReceipt, excerpt []byte, reason escrow.ProtestReasonCode) (string, error)
}

// WalletOpener is the escrow side of the payer: *Wallet, or a fake that
// returns deterministic txids without a running algod.
//
// Open takes the operator's pre-signed 2-tx open group from the reserve
// response (gtxn[1] = open() AppCall signed by operator; gtxn[0] =
// usdcPayment template for the wallet to sign as the payer) and submits
// it. The per-ticket box MBR is drawn from the payer's prepaid MBR pool
// at open(), not a funding leg in this group. PayerAddr populates
// ReserveRequest.PayerAddr so the operator can pre-sign the open group
// bound to this address.
type WalletOpener interface {
	Open(ctx context.Context, ticket *ticket.Ticket, op Operator, presignedOpenGroup []types.SignedTxn) (*OpenHandle, error)
	PayerAddr() string
}
