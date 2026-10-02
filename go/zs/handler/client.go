/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"log/slog"
	"net/http"
	"sync"
	"time"

	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// client is the payer: routing, reserve, escrow, sealing and settlement, with
// no HTTP surface of its own. One client serves every concurrent request, so
// per-request state never goes on it. Server embeds it and adds the
// OpenAI-compatible routes.
type client struct {
	cfg        *Config
	log        *slog.Logger
	httpClient *http.Client

	// Hayai providers. The registry feeds operator selection, the reserve
	// client handles the pre-payment admission call, and the affinity cache
	// pins continuation requests to the same operator.
	registryProvider hayai.RegistryProvider
	reserveClient    hayai.ReserveClient
	// toolAffinity pins continuations of tool-calling chat conversations
	// to the operator that emitted the matching tool_call_id. Honors the
	// configured affinity_policy (prefer/strict/none).
	toolAffinity *hayai.IDAffinity
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
	responseAffinity *hayai.IDAffinity
	// tokenizer resolves (model, body) → Estimate{InputTokens,
	// MaxOutputTokens} used to build ReserveRequest.
	tokenizer *tokenize.Registry

	// relayRep is the per-relay forward-reputation store (the
	// ChainOperatorSource backing the registry). relayHopFor consults it to
	// deprioritize a repeatedly-failing relay, and the inference forward path
	// reports each forward's outcome into it. Nil in tests / non-privacy
	// builds — every consult and report is then a no-op.
	relayRep hayai.RelayReputation

	// relayLatency is the per-process client-observed network-RTT store — the
	// same ChainOperatorSource that backs relayRep. The proxy is a localhost
	// single-user (payer) process, so this is genuinely the payer's own vantage
	// on the mesh, mirroring the client app's latency store. relayHopFor weights
	// relay selection by it and pickCandidates demotes confidently-slow targets;
	// the discovery probe + reserve POST record into it. Nil in tests /
	// non-privacy builds — every consult and record is then a no-op.
	relayLatency hayai.RelayLatency

	// targetBackoff is the per-target-node dispatch-failure memory (the same
	// ChainOperatorSource that backs relayRep/relayLatency). pickCandidates
	// demotes a currently-backed-off node to the tail so a persistently-failing
	// operator stops costing every request a doomed round-trip; the reserve loop
	// records target-attributable transient failures into it. Nil in tests —
	// every consult and record is then a no-op. Mirrors the client's
	// target-backoff.ts.
	targetBackoff hayai.TargetBackoff

	// nodeExcluder is the write-once, never-reset set of nodes proven to have
	// handed a fraudulent atomic settle group (the same ChainOperatorSource that
	// backs relayRep/targetBackoff). runReceiptChecks records a rejection here
	// and pickCandidates / the relay pool hard-drop excluded nodes — the one
	// deliberately non-self-healing routing signal (proven misbehaviour, not a
	// transient fault). Nil in tests — every consult and record is then a no-op.
	// Mirrors the client's excluded-nodes.ts.
	nodeExcluder hayai.NodeExcluder

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
	refunds *hayai.RefundWatchdog

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

	// retryBudget overrides the wall-clock ceiling on transient-failure
	// retrying for one request (see transientRetryBudget). Zero — always, in
	// production — uses the shared transient.OverallDeadline so the proxy and
	// the client/ app ride out an outage identically. Tests set it small
	// because the real schedule deliberately sleeps for up to a minute.
	retryBudget time.Duration

	// fastSweeps zeros the inter-sweep backoff (transient.SweepDelay) so a test
	// can exercise the multi-sweep terminal-selection logic without the real
	// 4s/12s/30s waits. Never set in production. See sweepDelay.
	fastSweeps bool

	// debugLogBodies dumps the full plaintext request body sent to the node
	// AND the decrypted response (non-stream body / streaming frames) to
	// stderr. Opt-in via the proxy's -debug-bodies flag. DELIBERATELY breaks
	// the non-retention rule (see AGENTS.md) — local debugging only, never
	// enable in production. See debug.go.
	debugLogBodies bool
}
