/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"

	"github.com/TxnLab/zerosignal/go/escrow"
	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/keystore"
	"github.com/TxnLab/zerosignal/go/ticket"
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// Config is the payer policy the handler reads per request. It is a pointer
// field on Server, so a caller that changes it after New changes the running
// handler; nothing synchronizes that, so finish configuring before serving.
type Config struct {
	// Network names the chain ("mainnet", "testnet", …) in funding errors.
	// "mainnet" also switches the payer-facing hint to the web app.
	Network string
	// PayerAddr is the payer account, named in funding errors.
	PayerAddr string
	// FundingURL is the web app a mainnet funding error points the payer at.
	FundingURL string

	// Privacy is the default transport posture (SPEC §3f). The zero value
	// relays every reserve and inference; only zs.PrivacyDirect sends direct,
	// so an unrecognized value relays too. AllowPrivacyOverride lets a
	// request's provider.relay / X-Zs-Relay preference turn relaying off;
	// without it an opt-out is refused.
	Privacy              hayai.Privacy
	AllowPrivacyOverride bool

	// Affinity is the tool-call continuation policy. The zero value behaves
	// as prefer.
	Affinity hayai.AffinityPolicy

	// AllowStaging admits staging operators to routing and discovery.
	AllowStaging bool
	// AllowPrivateOperators turns off the SSRF dial guard so operators may
	// register loopback or RFC1918 BaseURLs. Localnet development only.
	AllowPrivateOperators bool

	// TEERequiredModels route only to attested operators.
	TEERequiredModels []string
}

func (c *Config) relayByDefault() bool {
	return c.Privacy != hayai.PrivacyDirect
}

func (c *Config) teeRequired(model string) bool {
	return slices.Contains(c.TEERequiredModels, model)
}

// ListenConfig is what HTTPServer needs beyond the handler itself.
type ListenConfig struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

type Server struct {
	cfg        *Config
	log        *slog.Logger
	httpClient *http.Client
	reqTx      transform.RequestTransformer
	respTx     transform.ResponseTransformer
	mux        *http.ServeMux

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

	// wallet drives the escrow payment path. dispatchHayai calls
	// Open to compose + sign + submit the Payment + escrow.open
	// atomic group and returns the app-call txid
	// (OpenHandle.AppCallTxID — the real per-txn id the node
	// can look up via algod.PendingTransactionInformation). The
	// group id is carried alongside on the handle for audit logging.
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

	// keystore holds Algorand mnemonics loaded at startup used to
	// sign payment transactions against operator pay-to addresses.
	keystore *keystore.KeyStore

	// trackCryptoTimes enables per-request encrypt/decrypt duration
	// accounting in the middleware and the hayai dispatch path. Opt-in via
	// the proxy's -times flag.
	trackCryptoTimes bool

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

	// shutdownToken / shutdown back the loopback POST /shutdown control channel
	// (the Windows graceful-stop path). shutdownToken is the required
	// X-Shutdown-Token value; shutdown triggers the graceful drain. Both unset
	// (foreground / service runs) ⇒ the route isn't registered. See shutdown.go.
	shutdownToken string
	shutdown      func()
}

// Options collects dependencies for New.
type Options struct {
	RegistryProvider hayai.RegistryProvider
	ReserveClient    hayai.ReserveClient
	// ToolAffinity is the IDAffinity instance keyed on tool_call_id for
	// chat-completions continuation routing.
	ToolAffinity *hayai.IDAffinity
	// ResponseAffinity is the IDAffinity instance keyed on response_id
	// for /v1/responses session routing. Optional; if nil, /v1/responses
	// behaves as a stateless pass-through (no response-id routing).
	// Wired in main.go.
	ResponseAffinity *hayai.IDAffinity
	// Tokenizer is the tokenize.Registry used by dispatchHayai to produce
	// input_tokens / max_output_tokens for the ReserveRequest.
	Tokenizer *tokenize.Registry
	// RelayReputation is the per-relay forward-reputation store, wired to the
	// ChainOperatorSource backing the registry in main.go. Optional; nil
	// disables relay downranking + outcome reporting (tests / non-privacy).
	RelayReputation hayai.RelayReputation
	// RelayLatency is the per-process client-observed latency store, wired to the
	// same ChainOperatorSource as RelayReputation in main.go. Optional; nil
	// disables latency-weighted relay selection + the slow-target demote.
	RelayLatency hayai.RelayLatency
	// TargetBackoff is the per-target-node dispatch-failure store, wired to the
	// same ChainOperatorSource as RelayReputation in main.go. Optional; nil
	// disables the demote + recording (tests).
	TargetBackoff hayai.TargetBackoff
	// NodeExcluder is the proven-malicious-node exclusion store, wired to the
	// same ChainOperatorSource as RelayReputation in main.go. Optional; nil
	// disables the hard-exclusion record + consult (tests).
	NodeExcluder hayai.NodeExcluder
	// Wallet composes + signs + submits the Payment + escrow.open
	// atomic group per request and threads the app-call txid through
	// the envelope. Assembled from hayai.NewWallet in main.go once the
	// algod + escrow clients are constructed. Tests pass a *fakeWallet.
	Wallet WalletOpener
	// SpendGuard bounds the aggregate USDC the auto-spending wallet can drain
	// (a runaway-agent backstop). Checked before each escrow open, credited
	// after. Optional; nil disables enforcement.
	SpendGuard SpendGuard
	// Keystore holds Algorand mnemonics loaded at startup used to sign
	// payment transactions against operator pay-to addresses.
	Keystore *keystore.KeyStore
	// TrackCryptoTimes turns on per-request encrypt/decrypt timing in the
	// "request" log line. Off by default.
	TrackCryptoTimes bool
	// DebugLogBodies dumps full plaintext request bodies sent to the node AND
	// decrypted responses (non-stream body / streaming frames) to stderr (the
	// proxy's -debug-bodies flag). Off by default. Deliberately breaks
	// non-retention — local debugging only. See debug.go.
	DebugLogBodies bool
	// ShutdownToken, when non-empty, registers the loopback-only POST /shutdown
	// control channel and is the token it requires (sent as X-Shutdown-Token).
	// The self-managed daemon parent generates it, forwards it to the serving
	// child via the environment, and records it in daemon.json so `proxy stop`
	// can reach it — the graceful-stop path on Windows (no SIGTERM). Empty
	// (foreground / service-managed runs) ⇒ the route is not registered.
	ShutdownToken string
	// Shutdown is invoked by the POST /shutdown handler to trigger the same
	// graceful drain a SIGTERM does (app.Run wires it to cancel the run ctx).
	Shutdown func()
}

// New builds a Server wired with the given config, logger, and
// request/response transformers. Pass Options to supply optional
// dependencies like the hayai recipient/tx-id providers.
func New(cfg *Config, log *slog.Logger, reqTx transform.RequestTransformer, respTx transform.ResponseTransformer, opts Options) *Server {
	s := &Server{
		cfg:    cfg,
		log:    log,
		reqTx:  reqTx,
		respTx: respTx,
		// 0 = no timeout; required for long SSE streams. Per-request
		// cancellation comes from the request context. The tuned transport
		// adds a short dial timeout (an unreachable operator fails over fast
		// instead of stalling for Go's 30s default) and a large per-host idle
		// pool (the proxy fans many concurrent requests at the same popular
		// operator; Go's default of 2 idle conns/host forces a re-dial +
		// re-TLS past the second). The header backstop bounds a
		// connected-but-silent node; it is sized to outlast the slowest
		// non-streaming forward (image generations/edits, whose headers wait
		// on the full upstream call), not just admission — see
		// httpx.ForwardHeaderBackstop.
		//
		// BlockPrivateTargets is the SSRF guard: the proxy is co-located with
		// the user, so its localhost is the user's machine, and it dials
		// operator-registered BaseURLs (the relay hop in privacy mode, or the
		// target directly). Without the guard a malicious operator could
		// register a loopback/RFC1918 BaseURL and make the proxy probe the
		// user's own LAN. Default on; allow_private_operators is the localnet
		// dev opt-out.
		httpClient:       httpx.Client(0, httpx.Options{ResponseHeaderTimeout: httpx.ForwardHeaderBackstop, BlockPrivateTargets: !cfg.AllowPrivateOperators}),
		mux:              http.NewServeMux(),
		registryProvider: opts.RegistryProvider,
		reserveClient:    opts.ReserveClient,
		toolAffinity:     opts.ToolAffinity,
		responseAffinity: opts.ResponseAffinity,
		tokenizer:        opts.Tokenizer,
		relayRep:         opts.RelayReputation,
		relayLatency:     opts.RelayLatency,
		targetBackoff:    opts.TargetBackoff,
		nodeExcluder:     opts.NodeExcluder,
		keystore:         opts.Keystore,
		trackCryptoTimes: opts.TrackCryptoTimes,
		debugLogBodies:   opts.DebugLogBodies,
		spend:            opts.SpendGuard,
		refunds:          hayai.NewRefundWatchdog(log),
		shutdownToken:    opts.ShutdownToken,
		shutdown:         opts.Shutdown,
	}
	s.wallet = opts.Wallet
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

	// Loopback-only graceful-stop control channel — registered only when the
	// daemon supplied a shutdown token (the Windows `proxy stop` path; unix uses
	// SIGTERM). Foreground / service-managed runs leave it unregistered.
	if s.shutdownToken != "" && s.shutdown != nil {
		s.mux.HandleFunc("POST /shutdown", s.handleShutdown)
	}

	// /v1/completions is the legacy OpenAI text-completion endpoint. The proxy
	// emulates it entirely by translating to/from /v1/chat/completions (see
	// handleCompletions / clientFormat) — no node, relay, or wire change needed.
	// /v1/embeddings stays disabled (no chat equivalent to emulate it with).
	// s.mux.HandleFunc("POST /v1/embeddings", s.handleEmbeddings)
	s.mux.HandleFunc("POST /v1/completions", s.handleCompletions)
	s.mux.HandleFunc("POST /v1/chat/completions", s.handleChatCompletions)
	s.mux.HandleFunc("POST /v1/responses", s.handleResponses)
	s.mux.HandleFunc("POST /v1/images/generations", s.handleImageGeneration)
	s.mux.HandleFunc("POST /v1/images/edits", s.handleImageEdits)

	s.mux.HandleFunc("GET /v1/models", s.handleListModels)
	// {id...} (trailing wildcard) not {id}: model ids carry an embedded
	// slash (e.g. "google/gemma-5.2"), which a single-segment {id} wildcard
	// won't match — net/http ServeMux would 404 before the handler runs.
	s.mux.HandleFunc("GET /v1/models/{id...}", s.handleGetModel)
	// Host-relative aliases for model discovery. Some clients derive the models
	// URL from the host rather than the configured API root and ask for /models —
	// JetBrains AI Assistant does, while sending chat to /v1/chat/completions in
	// the same session — and got Go's default "404 page not found", which is not
	// even JSON. Discovery is a read-only GET with no wire or payment surface, so
	// answering both spellings costs nothing and removes a whole class of
	// base-URL misconfiguration. POST endpoints deliberately get NO such alias:
	// there the version prefix is part of the protocol contract.
	s.mux.HandleFunc("GET /models", s.handleListModels)
	s.mux.HandleFunc("GET /models/{id...}", s.handleGetModel)

	// Aggregate hayai capability surface — union of built-in tools across
	// every operator the proxy knows about. Shape mirrors the node's
	// endpoint of the same name so downstream clients share a decoder.
	s.mux.HandleFunc("GET /v1/zs/details", s.handleHayaiDetails)
	// Per-operator view of the registry — complements /v1/zs/details
	// by surfacing each operator's own model list and capabilities
	// without unioning across operators. Lets clients render which
	// operator backs which model.
	s.mux.HandleFunc("GET /v1/zs/operators", s.handleHayaiOperators)
}

// HTTPServer returns a net/http Server configured with the middleware
// chain and the routes defined above. Call ListenAndServe/Shutdown on it.
func (s *Server) HTTPServer(lc ListenConfig) *http.Server {
	return &http.Server{
		Addr:              lc.Addr,
		Handler:           s.middleware(s.mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       lc.ReadTimeout,
		WriteTimeout:      lc.WriteTimeout,
		IdleTimeout:       lc.IdleTimeout,
	}
}

// middleware wraps the mux with a request logger and panic recoverer.
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", slog.Any("panic", rec), slog.String("path", r.URL.Path))
				writeOpenAIError(w, http.StatusInternalServerError, "proxy_error", "panic", "internal server error")
			}
		}()

		writeCORSHeaders(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		ctx := r.Context()
		var timer *cryptoTimer
		if s.trackCryptoTimes {
			ctx, timer = withCryptoTimer(ctx)
			r = r.WithContext(ctx)
		}

		start := time.Now()
		rw := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rw, r)

		attrs := []slog.Attr{
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rw.status),
			slog.Duration("duration", time.Since(start)),
		}
		attrs = append(attrs, timer.logAttrs()...)

		level := slog.LevelInfo
		if rw.status >= 400 {
			// Surface *why* on the request line itself so the single-user payer
			// running the proxy can see the reason for a 4xx/5xx — e.g. a 503
			// no_operator / no_ephemeral_capacity on /v1/responses — without
			// having to enable -debug-bodies. The captured body is the proxy's
			// own OpenAI-shaped error envelope (or a forwarded operator error
			// envelope), which is control-plane, never prompt/completion
			// content, so it sits inside the proxy's error-logging carve-out
			// (AGENTS.md). Full request/response dumps stay gated behind
			// -debug-bodies.
			level = slog.LevelWarn
			attrs = append(attrs, errorReasonAttrs(rw.errBody)...)
		}
		s.log.LogAttrs(ctx, level, "request", attrs...)
	})
}

// settlementHandle is the subset of *hayai.OpenHandle that
// runReceiptChecks drives after receipt verification completes. Tests
// inject a fake to assert which escrow method got called and with
// what receipt; production wiring passes the real handle unchanged.
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

// WalletOpener is the subset of *hayai.Wallet the dispatch path
// depends on. Extracting it as an interface lets tests inject a fake
// without requiring a live algod client or keystore; the production
// wiring in main.go passes a concrete *hayai.Wallet.
//
// Open takes the operator's pre-signed 2-tx open group from the reserve
// response (gtxn[1] = open() AppCall signed by operator; gtxn[0] =
// usdcPayment template for the wallet to sign as the payer) and submits
// it. The per-ticket box MBR is drawn from the payer's prepaid MBR pool
// at open(), not a funding leg in this group. PayerAddr is used by the
// dispatch composer to populate ReserveRequest.PayerAddr so the operator
// can pre-sign the open group bound to this address.
type WalletOpener interface {
	Open(ctx context.Context, ticket *ticket.Ticket, op hayai.Operator, presignedOpenGroup []types.SignedTxn) (*hayai.OpenHandle, error)
	PayerAddr() string
}

// SpendGuard is the subset of zs.SpendGuard the dispatch path uses: an atomic
// Reserve of the ticket's MaxPrice ceiling against the caller's USDC caps
// before the escrow open, then Settle (the signed receipt verified — record
// the actual charge, drop the ceiling) or Release (anything else — drop the
// ceiling, record nothing). Reserve folds check-and-add into one operation so
// the cap holds under concurrent requests. A Reserve refusal wrapping
// zs.ErrDuplicateTicket is an operator reusing a ticket id, not a cap breach,
// so a fake must return that same sentinel to exercise the mapping.
//
// Everything is keyed by ticket id, and Settle/Release are idempotent, so a
// ticket can be resolved from more than one place without double counting. Note
// what that does NOT do: a request whose escrow committed but which never
// produced a verified receipt (a stream its client cancelled, an upstream
// gateway timeout) reaches neither call, and its ceiling stays outstanding until
// the UTC day rolls. That is intentional — the operator can still claim up to
// MaxPrice via settleLapsed, so the exposure is real — but it is held at the
// full ceiling rather than the eventual charge. Reconciling it against the
// on-chain outcome is the refund watchdog's job, not the dispatch path's.
type SpendGuard interface {
	Reserve(ticketID string, maxPriceMicroUSDC uint64) error
	Settle(ticketID string, spentMicroUSDC uint64)
	Release(ticketID string)
}

// maxCapturedErrBody caps how many bytes of an error (status >= 400) response
// body statusRecorder buffers for the request log line. The proxy's own error
// envelopes are a few hundred bytes; a forwarded operator pre-envelope error
// can be larger, but the reason is always near the front, so 8 KiB is ample.
const maxCapturedErrBody = 8 << 10

type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	// errBody captures a capped prefix of the response body ONLY when the
	// status is an error (>= 400), so the request log line can report *why* a
	// request failed. Success (2xx) bodies — including long SSE streams — are
	// never buffered.
	errBody []byte
}

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status = code
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(code)
}

// Write passes through to the wrapped writer, capturing a capped prefix of the
// body only on error responses (status >= 400) for the request log line. The
// status defaults to 200 (set in middleware), so a normal streaming response
// that never calls WriteHeader is never buffered here.
func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status >= 400 && len(r.errBody) < maxCapturedErrBody {
		r.errBody = append(r.errBody, b[:min(len(b), maxCapturedErrBody-len(r.errBody))]...)
	}
	return r.ResponseWriter.Write(b)
}

// errorReasonAttrs turns an error response body captured by statusRecorder into
// log attributes describing the failure. It parses the OpenAI-shaped error
// envelope when present — the proxy's own writeOpenAIError output and forwarded
// operator errors both use it — and falls back to the raw (capped) body so a
// non-JSON error still surfaces something. Returns nil for an empty body.
func errorReasonAttrs(body []byte) []slog.Attr {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil
	}
	var env openAIErrorEnvelope
	if err := json.Unmarshal(body, &env); err == nil && (env.Error.Code != "" || env.Error.Message != "") {
		attrs := make([]slog.Attr, 0, 3)
		if env.Error.Type != "" {
			attrs = append(attrs, slog.String("err_type", env.Error.Type))
		}
		if env.Error.Code != "" {
			attrs = append(attrs, slog.String("err_code", env.Error.Code))
		}
		if env.Error.Message != "" {
			attrs = append(attrs, slog.String("err_message", env.Error.Message))
		}
		return attrs
	}
	// Non-JSON or non-OpenAI-shaped error body — surface the raw prefix.
	return []slog.Attr{slog.String("err_body", string(body))}
}

// Flush exposes http.Flusher from the wrapped writer so SSE still flushes.
func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// writeCORSHeaders sets permissive CORS headers so browser-based clients
// (LM Studio's web UI, local dev tools on arbitrary ports) can hit the
// proxy without tripping the same-origin policy.
//
// Allow-Origin is an unconditional "*", NOT a reflected request Origin.
// The proxy uses no cookies / HTTP auth (admission is the on-chain seal and
// the client Authorization is discarded), so no caller makes a credentialed
// cross-origin request and Access-Control-Allow-Credentials is omitted. With
// credentials mode unused, "*" is legal (the spec forbids "*" only alongside
// Allow-Credentials:true) and is the cache-safe choice: a reflected
// per-Origin value is poison behind any shared cache that ignores Vary,
// whereas "*" is correct for every origin so a cached copy can't break
// another site. Still echoes Access-Control-Request-Headers so any header a
// client asks for in preflight is accepted (cache-keyed by its own Vary).
func writeCORSHeaders(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", "*")
	h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
	if reqHdrs := r.Header.Get("Access-Control-Request-Headers"); reqHdrs != "" {
		h.Set("Access-Control-Allow-Headers", reqHdrs)
		h.Add("Vary", "Access-Control-Request-Headers")
	} else {
		h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Accept, X-Requested-With")
	}
	// Explicit list rather than `*` so the X-Zs-* response headers stay
	// readable off cross-origin responses by name. The X-Zs-* entries
	// mirror setHayaiUsageHeaders in hayai_dispatch.go — keep them in sync
	// when adding a new non-streaming response header.
	h.Set("Access-Control-Expose-Headers",
		"Content-Type, Retry-After, "+
			"X-Zs-Ticket-Id, X-Zs-Operator-Id, X-Zs-Node-Id, X-Zs-Operator-Owner-Addr, "+
			"X-Zs-Actual-Input-Count, X-Zs-Actual-Output-Count, "+
			"X-Zs-Inference-Amount, X-Zs-Inference-Currency, X-Zs-Inference-Decimals, "+
			"X-Zs-Inference-Amount-Usd, X-Zs-Max-Price-Amount, X-Zs-Min-Price-Amount, "+
			"X-Zs-Fees-Microalgos, X-Zs-Fees-Usd, X-Zs-Algo-Usd-Rate, "+
			"X-Zs-Max-Output-Clamped")
	h.Set("Access-Control-Max-Age", "600")
}
