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
	"time"

	"github.com/TxnLab/zerosignal/go/algod"
	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/keystore"
	hayai "github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
	"github.com/TxnLab/zerosignal/go/zs/internal/cryptotimer"
	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// Config is the payer policy. New copies the routing fields into the Client
// and keeps the pointer for the rest, so a change after New reaches some
// reads and not others: finish configuring before New.
type Config struct {
	// Network names the chain ("mainnet", "testnet", …) in funding errors.
	// "mainnet" also switches the payer-facing hint to the web app.
	Network string
	// PayerAddr is the payer account.
	//
	// Deprecated: unread. Funding errors name the Wallet's own address.
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

// ListenConfig is what HTTPServer needs beyond the handler itself.
type ListenConfig struct {
	Addr         string
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	IdleTimeout  time.Duration
}

// Server is the OpenAI-compatible HTTP surface over a zs.Client.
type Server struct {
	*hayai.Client

	cfg *Config
	log *slog.Logger
	// registryProvider backs the catalog routes (/v1/models, /v1/zs/details,
	// /v1/zs/operators); the Client holds the same one for routing.
	registryProvider hayai.RegistryProvider

	reqTx  transform.RequestTransformer
	respTx transform.ResponseTransformer
	mux    *http.ServeMux

	// keystore holds Algorand mnemonics loaded at startup used to
	// sign payment transactions against operator pay-to addresses.
	keystore *keystore.KeyStore

	// trackCryptoTimes enables per-request encrypt/decrypt duration
	// accounting in the middleware and the hayai dispatch path. Opt-in via
	// the proxy's -times flag.
	trackCryptoTimes bool

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
	// Tokenizer is the tokenize.Registry used by dispatch to produce
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
	// RetryBudget and SweepDelay are zs.Config's: zero takes the shared
	// transient-retry schedule.
	RetryBudget time.Duration
	SweepDelay  func(sweep int) time.Duration
}

// New builds a Server wired with the given config, logger, and
// request/response transformers. Pass Options to supply optional
// dependencies like the hayai recipient/tx-id providers.
func New(cfg *Config, log *slog.Logger, reqTx transform.RequestTransformer, respTx transform.ResponseTransformer, opts Options) *Server {
	var spend hayai.SpendGuard
	if opts.SpendGuard != nil {
		spend = admitAll{opts.SpendGuard}
	}
	c, err := hayai.New(context.Background(), hayai.Config{
		Network:              hayai.Network{Algod: algod.Config{Network: cfg.Network}},
		Privacy:              cfg.Privacy,
		AllowPrivacyOverride: cfg.AllowPrivacyOverride,
		RequireTEEModels:     cfg.TEERequiredModels,
		Affinity:             hayai.Affinity{Policy: cfg.Affinity},
		AllowStaging:         cfg.AllowStaging,
		AllowPrivateHosts:    cfg.AllowPrivateOperators,
		RetryBudget:          opts.RetryBudget,
		SweepDelay:           opts.SweepDelay,
		Stores: hayai.Stores{
			RelayReputation:  opts.RelayReputation,
			RelayLatency:     opts.RelayLatency,
			TargetBackoff:    opts.TargetBackoff,
			NodeExclusions:   opts.NodeExcluder,
			ToolAffinity:     opts.ToolAffinity,
			ResponseAffinity: opts.ResponseAffinity,
		},
		SpendGuard:     spend,
		Registry:       opts.RegistryProvider,
		ReserveClient:  opts.ReserveClient,
		Wallet:         opts.Wallet,
		Tokenizer:      opts.Tokenizer,
		DebugLogBodies: opts.DebugLogBodies,
		Logger:         log,
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
		//
		// It keeps http.DefaultTransport's environment proxy, which the SDK's
		// own default drops.
		HTTPClient: httpx.Client(0, httpx.Options{ResponseHeaderTimeout: httpx.ForwardHeaderBackstop, BlockPrivateTargets: !cfg.AllowPrivateOperators}),
	})
	if err != nil {
		// hayai.New refuses nothing this Config can hold.
		panic("handler.New: " + err.Error())
	}
	s := &Server{
		Client:           c,
		cfg:              cfg,
		log:              log,
		registryProvider: opts.RegistryProvider,
		reqTx:            reqTx,
		respTx:           respTx,
		mux:              http.NewServeMux(),
		keystore:         opts.Keystore,
		trackCryptoTimes: opts.TrackCryptoTimes,
		shutdownToken:    opts.ShutdownToken,
		shutdown:         opts.Shutdown,
	}
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
		var timer *cryptotimer.Timer
		if s.trackCryptoTimes {
			ctx, timer = cryptotimer.With(ctx)
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
		attrs = append(attrs, timer.LogAttrs()...)

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

// WalletOpener is the escrow side of the payer the Client opens tickets
// through.
type WalletOpener = hayai.WalletOpener

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

// admitAll is a SpendGuard as a zs.SpendGuard: its caps are checked at
// Reserve, against the signed max_price, and it admits every request before
// that.
type admitAll struct{ SpendGuard }

func (admitAll) Admit(uint64) error { return nil }

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
	// mirror setHayaiUsageHeaders in usage.go — keep them in sync
	// when adding a new non-streaming response header.
	h.Set("Access-Control-Expose-Headers",
		"Content-Type, Retry-After, X-Should-Retry, "+
			"X-Zs-Ticket-Id, X-Zs-Operator-Id, X-Zs-Node-Id, X-Zs-Operator-Owner-Addr, "+
			"X-Zs-Actual-Input-Count, X-Zs-Actual-Output-Count, "+
			"X-Zs-Inference-Amount, X-Zs-Inference-Currency, X-Zs-Inference-Decimals, "+
			"X-Zs-Inference-Amount-Usd, X-Zs-Max-Price-Amount, X-Zs-Min-Price-Amount, "+
			"X-Zs-Fees-Microalgos, X-Zs-Fees-Usd, X-Zs-Algo-Usd-Rate, "+
			"X-Zs-Max-Output-Clamped")
	h.Set("Access-Control-Max-Age", "600")
}
