/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/ticket"
	"github.com/TxnLab/zerosignal/go/zs"
)

// emitter receives what a dispatch produces for its caller. Dispatch decides
// what happened; the emitter decides how the caller sees it, so the dispatch
// core has no ResponseWriter to hand and can answer an SDK caller as well as
// an HTTP client.
//
// A request ends in exactly one of: fail, reply, or open followed by frames
// (and interrupt if the stream breaks). clamped may precede any of them.
type emitter interface {
	// clamped reports that the request's max_output was lowered to ceiling.
	clamped(ceiling uint64)
	// fail ends the request with e before any response has started.
	fail(e *zs.Error)
	// reply delivers a complete response. header is the node's response
	// header set; usage is nil when no receipt verified.
	reply(status int, header http.Header, body []byte, usage *usageReport)
	// open starts a stream. A non-nil error means it could not start and the
	// caller has already been told.
	open(status int) error
	// frame delivers one stream frame and returns the bytes written, for the
	// stream tally.
	frame(f outFrame) (int, error)
	// interrupt ends an open stream that broke before its end.
	interrupt()
}

// usageReport is what the payer is told a verified turn cost.
type usageReport struct {
	receipt      *ticket.UsageReceipt
	ticket       *ticket.Ticket
	op           zs.Operator
	openFees     uint64
	settleFees   uint64
	algoUSDPrice float64
	feeBps       uint64
	discountBps  uint64
	haveFee      bool
}

func (u *usageReport) setHeaders(h http.Header) {
	setHayaiUsageHeaders(h, u.receipt, u.ticket, u.op, u.openFees, u.settleFees, u.algoUSDPrice, u.feeBps, u.discountBps, u.haveFee)
}

// upstreamReply is an operator's own error response, kept as the cause of a
// zs.Error so the HTTP surface can pass it through with the node's status
// and body rather than a proxy-authored one.
type upstreamReply struct {
	status int
	header http.Header
	body   []byte
	// contentType replaces the node's when the body is one the proxy wrote
	// in place of a body it could not parse.
	contentType string
}

func (u *upstreamReply) Error() string {
	return fmt.Sprintf("operator returned HTTP %d", u.status)
}

// httpEmitter renders a dispatch as an OpenAI-compatible HTTP response.
type httpEmitter struct {
	w http.ResponseWriter
	// clientCtx is the request's context: once it is done the client is gone,
	// and frames are swallowed so the receipt tail can still be drained.
	clientCtx context.Context
	flusher   http.Flusher
	// format is the shape the client called in; the node always answers in
	// chat shape.
	format clientFormat
	// usageFrame is the client's opt-in (X-Zs-Usage-Frame) to the non-OpenAI
	// zs.usage stream frame. Off by default: strict OpenAI clients
	// (JetBrains/Koog) fail on an event they cannot parse.
	usageFrame bool
}

func newHTTPEmitter(w http.ResponseWriter, r *http.Request, format clientFormat) *httpEmitter {
	return &httpEmitter{
		w:          w,
		clientCtx:  r.Context(),
		format:     format,
		usageFrame: strings.TrimSpace(r.Header.Get(hayaiUsageFrameHeader)) != "",
	}
}

func (e *httpEmitter) clamped(ceiling uint64) {
	e.w.Header().Set("X-Zs-Max-Output-Clamped", strconv.FormatUint(ceiling, 10))
}

func (e *httpEmitter) fail(err *zs.Error) {
	if up, ok := errors.AsType[*upstreamReply](err.Err); ok {
		e.passThrough(up)
		return
	}
	writeError(e.w, err)
}

// passThrough writes an operator's error response. No node-set X-Zs-* header
// reaches the client (SPEC §5.2 step 4); the proxy's own are kept.
func (e *httpEmitter) passThrough(up *upstreamReply) {
	h := e.w.Header()
	proxyHdrs := snapshotHayaiHeaders(h)
	copyResponseHeaders(h, up.header)
	stripNodeHayaiHeaders(h, proxyHdrs)
	h.Del("Content-Length")
	if up.contentType != "" {
		h.Set("Content-Type", up.contentType)
	}
	e.w.WriteHeader(up.status)
	_, _ = e.w.Write(up.body)
}

func (e *httpEmitter) reply(status int, header http.Header, body []byte, usage *usageReport) {
	h := e.w.Header()
	// Captured before the copy: the X-Zs-* the proxy itself set earlier in
	// dispatch (the max_output clamp marker) would otherwise be deleted along
	// with the node's.
	proxyHdrs := snapshotHayaiHeaders(h)
	copyResponseHeaders(h, header)
	stripNodeHayaiHeaders(h, proxyHdrs)
	h.Del("Content-Length")
	h.Set("Content-Type", "application/json")
	if usage != nil {
		usage.setHeaders(h)
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
		writeError(e.w, newError("no_flusher", "streaming not supported by server writer"))
		return errors.New("response writer cannot flush")
	}
	e.flusher = flusher
	h := e.w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	e.w.WriteHeader(status)
	flusher.Flush()
	return nil
}

func (e *httpEmitter) frame(out outFrame) (int, error) {
	f := out.frame
	switch {
	case out.usage != nil:
		if !e.usageFrame {
			return 0, nil
		}
		u := out.usage
		f = hayaiUsageFrame(u.receipt, u.ticket, u.op, u.openFees, u.settleFees, u.algoUSDPrice, u.feeBps, u.discountBps, u.haveFee)
	case out.content && e.format == formatLegacyCompletions:
		f.Data = completionsChunkFromChat(f.Data)
	}
	n, err := writeSSEFrame(&clientAwareWriter{w: e.w, clientCtx: e.clientCtx}, f)
	if err != nil {
		return n, err
	}
	e.flusher.Flush()
	return n, nil
}

func (e *httpEmitter) interrupt() {
	writeSSEError(e.w, e.flusher)
}
