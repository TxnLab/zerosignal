/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/TxnLab/zerosignal/go/zs"
	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
	"github.com/TxnLab/zerosignal/go/zs/internal/cryptotimer"
)

// Config is what the HTTP surface adds to the Client's own configuration.
type Config struct {
	// FundingURL is the web app a mainnet funding error points the payer at.
	FundingURL string
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
	*zs.Client

	cfg *Config
	log *slog.Logger
	// registryProvider is the Client's, read by the catalog routes
	// (/v1/models, /v1/zs/details, /v1/zs/operators).
	registryProvider zs.RegistryProvider
	// allowStaging and network are the Client's: whether staging nodes are
	// admitted, and the chain a funding error names.
	allowStaging bool
	network      string

	reqTx  transform.RequestTransformer
	respTx transform.ResponseTransformer
	mux    *http.ServeMux

	// trackCryptoTimes enables per-request encrypt/decrypt duration
	// accounting in the middleware and the dispatch path. Opt-in via
	// the proxy's -times flag.
	trackCryptoTimes bool
}

// Options are the handler's own switches.
type Options struct {
	// TrackCryptoTimes turns on per-request encrypt/decrypt timing in the
	// "request" log line. Off by default.
	TrackCryptoTimes bool
}

// New serves c over HTTP. cfg, reqTx and respTx may be nil.
func New(c *zs.Client, cfg *Config, log *slog.Logger, reqTx transform.RequestTransformer, respTx transform.ResponseTransformer, opts Options) *Server {
	if cfg == nil {
		cfg = &Config{}
	}
	zc := c.Config()
	s := &Server{
		Client:           c,
		cfg:              cfg,
		log:              log,
		registryProvider: c.Registry(),
		allowStaging:     zc.AllowStaging,
		network:          string(zc.Network.Algod.ResolvedNetwork),
		reqTx:            reqTx,
		respTx:           respTx,
		mux:              http.NewServeMux(),
		trackCryptoTimes: opts.TrackCryptoTimes,
	}
	s.routes()
	return s
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /healthz", s.handleHealth)

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

	// Aggregate zs capability surface — union of built-in tools across
	// every operator the proxy knows about. Shape mirrors the node's
	// endpoint of the same name so downstream clients share a decoder.
	s.mux.HandleFunc("GET /v1/zs/details", s.handleDetails)
	// Per-operator view of the registry — complements /v1/zs/details
	// by surfacing each operator's own model list and capabilities
	// without unioning across operators. Lets clients render which
	// operator backs which model.
	s.mux.HandleFunc("GET /v1/zs/operators", s.handleOperators)
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
			// (AGENTS.md "Privacy and logging"). Full request/response dumps stay gated behind
			// -debug-bodies.
			level = slog.LevelWarn
			attrs = append(attrs, errorReasonAttrs(rw.errBody)...)
		}
		s.log.LogAttrs(ctx, level, "request", attrs...)
	})
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
	// mirror setReceiptUsageHeaders in usage.go;
	// TestCORSExposesEveryUsageHeader fails when one is missing.
	h.Set("Access-Control-Expose-Headers",
		"Content-Type, Retry-After, X-Should-Retry, "+
			"X-Zs-Ticket-Id, X-Zs-Operator-Id, X-Zs-Node-Id, X-Zs-Operator-Owner-Addr, "+
			"X-Zs-Actual-Input-Count, X-Zs-Actual-Output-Count, "+
			"X-Zs-Inference-Amount, X-Zs-Inference-Currency, X-Zs-Inference-Decimals, "+
			"X-Zs-Inference-Amount-Usd, X-Zs-Max-Price-Amount, X-Zs-Min-Price-Amount, "+
			"X-Zs-Fees-Amount, X-Zs-Fees-Currency, X-Zs-Fees-Decimals, X-Zs-Fees-Usd, X-Zs-Fees-Usd-Rate, "+
			"X-Zs-Fees-Microalgos, X-Zs-Algo-Usd-Rate, "+
			"X-Zs-Fee-Bps, X-Zs-Discount-Bps, X-Zs-Platform-Fee-Microusdc, X-Zs-Refund-Microusdc, "+
			"X-Zs-Total-Debit-Microusdc, X-Zs-Total-Debit-Usd, "+
			"X-Zs-Max-Output-Clamped")
	h.Set("Access-Control-Max-Age", "600")
}
