/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"iter"
	"net/http"
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/zs"
)

// dispatchHayai answers an HTTP client with one turn of the Client. The
// request headers the turn honors are read here, so the Client never sees the
// request.
func (s *Server) dispatchHayai(w http.ResponseWriter, r *http.Request, endpoint string, body []byte, format clientFormat) {
	req := zs.Request{
		Endpoint:    zs.Endpoint(endpoint),
		Body:        body,
		ContentType: r.Header.Get("Content-Type"),
		RequireTEE:  strings.TrimSpace(r.Header.Get("X-Zs-Require-TEE")) != "",
		Relay:       r.Header.Get("X-Zs-Relay"),
		// The node's own frames are the response, error frames included.
		FramesOnly: true,
	}
	newHTTPEmitter(w, r, format, s.fundingHint()).serve(s.Client.Stream(r.Context(), req).Events())
}

// fundingHint is what a wallet_unfunded error tells the payer to do. The web
// app is offered only on mainnet: the hosted client is built for one network,
// so a testnet payer sent there would fund the wrong chain.
func (s *Server) fundingHint() string {
	if s.network == "mainnet" && s.cfg.FundingURL != "" {
		return "add funds in the web app (" + s.cfg.FundingURL + ") if this is your web account, " +
			"or run `zs-proxy fund` for a deposit address."
	}
	return "run `zs-proxy fund`."
}

// httpEmitter renders a Stream as an OpenAI-compatible HTTP response.
type httpEmitter struct {
	w http.ResponseWriter
	// clientCtx is the request's context: once it is done the client is gone,
	// and frames are swallowed (see clientAwareWriter).
	clientCtx context.Context
	flusher   http.Flusher
	// format is the shape the client called in; the node always answers in
	// chat shape.
	format clientFormat
	// usageFrame is the client's opt-in (X-Zs-Usage-Frame) to the non-OpenAI
	// zs.usage stream frame. Off by default: strict OpenAI clients
	// (JetBrains/Koog) fail on an event they cannot parse.
	usageFrame bool
	// fundingHint completes a wallet_unfunded message.
	fundingHint string
}

func newHTTPEmitter(w http.ResponseWriter, r *http.Request, format clientFormat, fundingHint string) *httpEmitter {
	return &httpEmitter{
		w:           w,
		clientCtx:   r.Context(),
		format:      format,
		usageFrame:  strings.TrimSpace(r.Header.Get(hayaiUsageFrameHeader)) != "",
		fundingHint: fundingHint,
	}
}

// serve writes a turn's events. A non-streaming reply is held until done,
// because its usage headers must precede its body. Returning before the
// events end stops the turn, which the Client treats as the client leaving.
func (e *httpEmitter) serve(events iter.Seq2[zs.Event, error]) {
	var (
		started *zs.ResponseStarted
		body    []byte
		usage   *zs.ReceiptVerified
	)
	for ev, err := range events {
		if err != nil {
			if started != nil && started.Streaming {
				e.interrupt()
				return
			}
			e.fail(err)
			return
		}
		switch ev := ev.(type) {
		case zs.MaxOutputClamped:
			e.clamped(ev.Ceiling)
		case zs.ResponseStarted:
			started = &ev
			if ev.Streaming && e.open(ev.Status) != nil {
				return
			}
		case zs.Frame:
			if started == nil || !started.Streaming {
				body = ev.Data
				continue
			}
			if e.frame(ev) != nil {
				return
			}
		case zs.ReceiptVerified:
			if started == nil || !started.Streaming {
				usage = &ev
				continue
			}
			if e.usageFrame && e.frame(usageFrame(ev)) != nil {
				return
			}
		case zs.Done:
			if started != nil && !started.Streaming {
				e.reply(started.Status, started.Header, body, usage)
			}
		}
	}
}

func (e *httpEmitter) clamped(ceiling uint64) {
	e.w.Header().Set("X-Zs-Max-Output-Clamped", strconv.FormatUint(ceiling, 10))
}

func (e *httpEmitter) fail(err error) {
	ze, ok := errors.AsType[*zs.Error](err)
	if !ok {
		writeOpenAIError(e.w, http.StatusInternalServerError, "proxy_error", "", err.Error())
		return
	}
	if up, ok := errors.AsType[*zs.NodeReply](ze.Err); ok {
		e.passThrough(up, shouldRetry(ze))
		return
	}
	if ze.Code == "wallet_unfunded" {
		c := *ze
		c.Message += " — " + e.fundingHint
		ze = &c
	}
	writeError(e.w, ze)
}

// passThrough writes an operator's error response. No node-set X-Zs-* header
// reaches the client (SPEC §5.2 step 4); the proxy's own are kept. The retry
// advice is the proxy's, set over any the node sent.
func (e *httpEmitter) passThrough(up *zs.NodeReply, retry bool) {
	h := e.w.Header()
	proxyHdrs := snapshotHayaiHeaders(h)
	copyResponseHeaders(h, up.Header)
	stripNodeHayaiHeaders(h, proxyHdrs)
	setShouldRetry(h, retry)
	h.Del("Content-Length")
	if up.ContentType != "" {
		h.Set("Content-Type", up.ContentType)
	}
	e.w.WriteHeader(up.Status)
	_, _ = e.w.Write(up.Body)
}

func (e *httpEmitter) reply(status int, header http.Header, body []byte, usage *zs.ReceiptVerified) {
	h := e.w.Header()
	// Captured before the copy: the X-Zs-* the proxy itself set earlier in
	// dispatch (the max_output clamp marker) would otherwise be deleted along
	// with the node's.
	proxyHdrs := snapshotHayaiHeaders(h)
	copyResponseHeaders(h, header)
	stripNodeHayaiHeaders(h, proxyHdrs)
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json")
	if status >= http.StatusBadRequest {
		// A reply comes after the open, so resending it pays again.
		setShouldRetry(h, false)
	}
	if usage != nil {
		setUsageHeaders(h, *usage)
	}
	// A pass-through for anything that isn't a chat completion (a sealed
	// error).
	if e.format == formatLegacyCompletions {
		body = completionsResponseFromChat(body)
	}
	e.w.WriteHeader(status)
	_, _ = e.w.Write(body)
}

func (e *httpEmitter) open(status int) error {
	flusher, ok := e.w.(http.Flusher)
	if !ok {
		writeError(e.w, &zs.Error{Kind: zs.KindInternal, Code: "no_flusher", Message: "streaming not supported by server writer"})
		return errors.New("response writer cannot flush")
	}
	e.flusher = flusher
	h := e.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	// Every stream is past the escrow open, and a node may open one under a
	// failed status, which an OpenAI SDK reads before the stream and resends.
	setShouldRetry(h, false)
	e.w.WriteHeader(status)
	flusher.Flush()
	return nil
}

func (e *httpEmitter) frame(f zs.Frame) error {
	if f.Sealed && e.format == formatLegacyCompletions {
		f.Data = completionsChunkFromChat(f.Data)
	}
	if _, err := (&clientAwareWriter{w: e.w, clientCtx: e.clientCtx}).Write(f.SSE()); err != nil {
		return err
	}
	e.flusher.Flush()
	return nil
}

func (e *httpEmitter) interrupt() {
	writeSSEError(e.w, e.flusher)
}

// clientAwareWriter forwards writes to the client until the client's request
// context is cancelled, after which it silently swallows them, so serve keeps
// ranging to the turn's end rather than stopping on a dead socket. It is not
// what saves the receipt tail: the turn runs on the request's context, so a
// departed client already reads to the forwarder as a disconnect, and a turn
// that serve stops reads the same way.
type clientAwareWriter struct {
	w         io.Writer
	clientCtx context.Context
}

func (cw *clientAwareWriter) Write(p []byte) (int, error) {
	if cw.clientCtx.Err() != nil {
		return len(p), nil
	}
	return cw.w.Write(p)
}

// writeSSEError emits an OpenAI-shaped error frame followed by [DONE].
// Safe to call after the stream has already started writing. The client
// sees a generic message only — the real cause is already in the log.
func writeSSEError(w io.Writer, flusher http.Flusher) {
	payload, _ := json.Marshal(openAIErrorEnvelope{
		Error: openAIError{
			Message: "stream interrupted",
			Type:    "proxy_error",
			Code:    "stream_error",
		},
	})
	_, _ = w.Write(zs.Frame{Data: payload}.SSE())
	_, _ = w.Write(zs.Frame{Data: []byte("[DONE]")}.SSE())
	flusher.Flush()
}
