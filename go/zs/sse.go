/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TxnLab/zerosignal/go/transient"
)

// drainTailTimeout bounds how long the proxy keeps reading the upstream after
// the client has disconnected but the node already finished generating (so we
// can reach the zs-receipt/settle tail and pay the operator for content it
// already delivered). The tail normally lands in well under a second; the
// bound just stops a wedged or malicious node from pinning the reader open.
const drainTailTimeout = 10 * time.Second

// streamTally accumulates what a forward FORWARDED — counts and timings only,
// never frame contents (full bodies stay behind -debug-bodies).
//
// "Forwarded", not "delivered": once the client is gone the pump keeps reading
// so the receipt tail can still be drained, and the emitter drops those frames
// but they are still counted here. On a tail-drain the numbers therefore
// include frames nobody received. The sizes are the frames' SSE encoding.
//
// The gap timings are the point of it. A client that abandons a stream tells us
// nothing about why, and the two explanations need opposite responses: frames
// flowing steadily until the cut means a total-elapsed deadline on the client
// (nothing the proxy can fix), while a long silence before the cut means an idle
// timeout (fixable by keepalive cadence). Before this the proxy logged neither.
//
// It takes BOTH gap numbers to tell those apart, and only one of them is maxGap.
// maxGap spans frame→frame, so the gap it structurally cannot see is the last
// one: the silence between the final frame and the cut, which is precisely an
// idle timeout's signature. A stream that stalls mid-flight, recovers, and is
// then abandoned reports that earlier stall as maxGap and says nothing about the
// silence that actually preceded the disconnect. silenceBeforeCut closes that,
// and it is the attribute to read first on an abandoned stream — maxGap only
// characterizes the stream's worst hiccup, not how it ended.
//
// Not safe for concurrent use, and it does not need to be: every write comes
// from the pump goroutine and the only read happens after pumpSSE has returned.
// An earlier version read it from the disconnect watcher instead, which raced
// the pump — the watcher's read ran BEFORE the cancelUpstream that stops the
// pump, and the pump keeps recording swallowed writes across exactly that
// window. Keep the read where it is.
type streamTally struct {
	frames  uint64
	bytes   uint64
	firstAt time.Time
	lastAt  time.Time
	maxGap  time.Duration
}

// record notes one frame written toward the client (see the type doc on why that
// is not the same as delivered). Pump goroutine only.
func (t *streamTally) record(n int) {
	now := time.Now()
	t.frames++
	t.bytes += uint64(n)
	if t.firstAt.IsZero() {
		t.firstAt = now
	} else if gap := now.Sub(t.lastAt); gap > t.maxGap {
		t.maxGap = gap
	}
	t.lastAt = now
}

// attrs renders the tally for a log line.
//
// start is forwardStart, which is stamped AFTER http.Client.Do returns — i.e.
// once the operator's response headers are already in hand. So ttfb here is
// headers→first frame, which is the node's admission (including its mempool
// wait for the open txn) plus the upstream's prefill. It is NOT the client's
// wait: the proxy-side preamble (reserve + escrow open + seal + connect) all
// happens before start and is excluded. That preamble is still recoverable —
// it is the request line's `duration` minus this `elapsed`, both of which are
// emitted for the same request.
//
// Don't read ttfb as the operator's time-to-first-token either. It is the
// closest local approximation the proxy has, but it is a log-only diagnostic
// and is deliberately not recorded anywhere: target ordering uses the on-chain
// co-signed TTFT (Operator.Metrics.LatencyEwmaMs) and the app-side network-RTT
// EWMAs in proto/go/zs/relay_latency.go. Neither is fed from this.
func (t *streamTally) attrs(start time.Time) []any {
	var ttfb time.Duration
	if !t.firstAt.IsZero() {
		ttfb = t.firstAt.Sub(start)
	}
	// Silence between the last forwarded frame and now. attrs runs immediately
	// after pumpSSE returns, so on an abandoned stream "now" is the cut — see
	// the type doc on why this, not maxGap, is what separates an idle timeout
	// from a total-elapsed deadline. It carries the pump's teardown with it
	// (sub-millisecond, and far below the resolution the distinction needs).
	// Zero frames leaves lastAt unset, and 0 is the honest answer there: there
	// was never a frame for the silence to follow.
	var silenceBeforeCut time.Duration
	if !t.lastAt.IsZero() {
		silenceBeforeCut = time.Since(t.lastAt)
	}
	return []any{
		slog.Uint64("frames", t.frames),
		slog.Uint64("bytes", t.bytes),
		slog.Duration("elapsed", time.Since(start)),
		slog.Duration("ttfb", ttfb),
		slog.Duration("max_inter_frame_gap", t.maxGap),
		slog.Duration("silence_before_cut", silenceBeforeCut),
	}
}

// outFrame is what one upstream frame becomes for the caller: a frame to pass
// on (Sealed when it was decrypted from the node's sealed stream), or the
// verified usage the receipt frame carried, or neither.
type outFrame struct {
	frame Frame
	usage *usageReport
}

func (o outFrame) isEmpty() bool { return o.frame.isEmpty() && o.usage == nil }

// frameTransform is the per-frame hook used by pumpSSE. It
// decrypts frames tagged with `event: zs` under a per-request symmetric
// key.
type frameTransform func(Frame) (outFrame, error)

// frameTransformFactory builds the per-frame hook from the upstream response
// headers. It exists because the symmetric key used to AEAD-open each
// SSE frame is carried in an upstream header and must be unwrapped before
// the first frame is processed.
type frameTransformFactory func(upstreamResp *http.Response) (frameTransform, error)

// forwardRawStream is the low-level streaming forwarder used by the
// dispatcher. It sends the pre-built body, branches on the operator
// Content-Type, and either pumps SSE frames through frameFn or delegates
// the buffered body to nonStreamFallback.
//
// baseURL is the per-operator URL from the registry; it must be non-empty.
func (s *Client) forwardRawStream(
	ctx context.Context,
	em emitter,
	baseURL, endpoint string,
	body []byte,
	outboundContentType string,
	extraHeaders http.Header,
	hop *RelayHop,
	frameFnFactory frameTransformFactory,
	nonStreamFallback nonStreamResponder,
	genComplete *atomic.Bool,
	idle *idleWatchdog,
) {
	// Detach the upstream read from the client request. If the client
	// disconnects AFTER the node has finished generating (genComplete is set by
	// the frame factory on a generation-terminal frame), we keep reading
	// through the zs-receipt tail — where settlement runs — so the operator
	// is paid for content it already delivered; the node, still seeing the
	// proxy connected, completes normally and signs a real-usage receipt
	// instead of a disconnect receipt estimated from the frames it sent. A disconnect BEFORE
	// generation completes cancels promptly via the watcher below: we don't pin
	// a generating node to an abandoned request (the speculative-burst case).
	upstreamCtx, cancelUpstream := context.WithCancel(context.WithoutCancel(ctx))
	defer cancelUpstream()

	upstreamReq, err := s.buildOperatorRequest(upstreamCtx, baseURL, http.MethodPost, endpoint, body, outboundContentType, extraHeaders)
	if err != nil {
		em.fail(newError("build_request", err.Error()))
		return
	}
	upstreamReq.Header.Set("Accept", "text/event-stream")

	upstreamResp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		// Relayed mode: a transport error reaching the relay is a relay-hop
		// failure — attribute it (no-op for a direct route), don't flip the target.
		//
		// upstreamCtx, not ctx: it is the context this request actually rode, and
		// CallerAborted must describe THAT one. It is WithoutCancel and the
		// disconnect watcher below only starts once Do has returned, so a payer
		// hang-up cannot reach it and the abort arm is false here by
		// construction. Passing the payer's ctx instead would exonerate a relay
		// whose transport genuinely failed while the payer happened to be gone.
		s.attributeRelayHop(upstreamCtx, hop, transient.TransportFailureStatus, nil, nil)
		s.log.Error("upstream request failed", slog.String("endpoint", endpoint), relayAttr(hop), slog.Any("err", err))
		em.fail(newError("upstream_unreachable", err.Error()))
		return
	}
	defer upstreamResp.Body.Close()

	ct := upstreamResp.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "text/event-stream") {
		respBody, err := io.ReadAll(upstreamResp.Body)
		if err != nil {
			em.fail(newError("read_upstream", err.Error()))
			return
		}
		// Non-stream response on the streaming path: classify it as a relay
		// hop outcome (a relay-generated hop error deprioritizes the relay).
		s.attributeRelayHop(upstreamCtx, hop, upstreamResp.StatusCode, upstreamResp.Header, respBody)
		if err := nonStreamFallback(em, upstreamResp, respBody); err != nil {
			s.log.Error("non-stream fallback failed", slog.String("endpoint", endpoint), slog.Any("err", err))
			em.fail(newError("response_handler", "upstream response could not be processed"))
		}
		return
	}

	// A genuine forwarded SSE stream means the relay did its job — credit it
	// (clears any prior failure streak). A mid-stream drop after this point is
	// not cleanly relay-attributable, so we don't penalize the relay for it.
	s.recordRelayOutcome(hop, true)

	frameFn, err := frameFnFactory(upstreamResp)
	if err != nil {
		s.log.Error("frame transform setup failed", slog.String("endpoint", endpoint), slog.Any("err", err))
		em.fail(newError("stream_setup", "stream could not be initialized"))
		return
	}

	if em.open(upstreamResp.StatusCode, upstreamResp.Header) != nil {
		return
	}

	// Watch for a client disconnect. If the node already finished generating,
	// give it a bounded window to deliver the receipt/settle tail; otherwise
	// stop the upstream immediately so we don't keep a node generating for an
	// abandoned request. The pump's read lifetime is upstreamCtx, so cancelling
	// it here is what tears the pump down.
	// Delivered-volume tally feeding the disconnect diagnostic below. Written by
	// the pump goroutine ONLY, and read after pumpSSE returns — see the
	// streamTally type doc for why the read must not move into the watcher.
	var tally streamTally
	// Set by the watcher when the client left before any generation-terminal
	// frame; consumed after the pump returns, where the tally is race-free and
	// complete rather than truncated at the cancel instant.
	var abandonedPreGen atomic.Bool
	forwardStart := time.Now()
	pumpDone := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			if genComplete != nil && genComplete.Load() {
				// Node already finished; drain the receipt/settle tail so the
				// operator is paid for content it delivered. A non-zero
				// "zs request paid" after this line is the fix working.
				s.log.Debug("client disconnected after generation complete; draining receipt tail",
					slog.String("endpoint", endpoint), relayAttr(hop))
				t := time.NewTimer(drainTailTimeout)
				defer t.Stop()
				select {
				case <-t.C:
					s.log.Warn("receipt tail drain timed out; cancelling upstream",
						slog.String("endpoint", endpoint), relayAttr(hop))
					cancelUpstream()
				case <-pumpDone:
				}
			} else {
				// Disconnected before any generation-terminal frame — abandoned
				// before the node finished. Cancel promptly. The payer never sees
				// a receipt, so nothing is acked here: a node that had streamed
				// output claims its estimate of the work alone and is paid after
				// the grace period (capped at the reserved amount); one that had
				// not is refunded.
				//
				// Flag it and let the diagnostic be emitted after the pump returns.
				// Reading the tally HERE would race the pump: this runs before the
				// cancelUpstream below, which is the only thing that stops the pump,
				// and the pump keeps recording swallowed writes in the meantime.
				abandonedPreGen.Store(true)
				cancelUpstream()
			}
		case <-pumpDone:
		}
	}()

	// idle bounds the node's silences, the tail drain included: a silence past
	// its budget cancels the upstream, and the turn ends stream_interrupted
	// with the *StreamIdleTimeoutError as its cause.
	idle.start(func(err *StreamIdleTimeoutError) {
		s.log.Warn("upstream stream idle; cancelling upstream",
			slog.String("endpoint", endpoint), relayAttr(hop),
			slog.String("phase", err.Phase), slog.Int64("timeout_ms", err.Timeout.Milliseconds()))
		cancelUpstream()
	})
	// Deferred too, so a caller's loop body that panics through the pump
	// leaves no timer behind.
	defer idle.stop()
	var upstreamBody io.Reader = upstreamResp.Body
	timedFn, emit := frameFn, em.frame
	if idle != nil {
		upstreamBody = idleReader{r: upstreamBody, w: idle}
		// The hook settles a receipt inline, and the emitter runs the
		// caller's loop body inline; neither reads the node meanwhile.
		timedFn = func(f Frame) (outFrame, error) {
			return bracket(idle, func() (outFrame, error) { return frameFn(f) })
		}
		emit = func(o outFrame) (int, error) {
			return bracket(idle, func() (int, error) { return em.frame(o) })
		}
	}

	// The emitter swallows frames once the caller is gone, so a dead-socket
	// write error can't abort a tail drain before it reaches the receipt frame.
	// The pump itself stops on upstreamCtx (clean EOF, cancelUpstream from the
	// watcher, or the idle bound).
	pumpErr := pumpSSE(upstreamCtx, emit, upstreamBody, timedFn, &tally)
	// Every way the pump ends stops the watchdog first, so a timeout here is
	// what ended it.
	idleErr := idle.stop()
	close(pumpDone)
	// The pump has stopped, so the tally is settled and safe to read.
	//
	// Info, not Debug, on the abandoned case: escrow is already open, so this is a
	// request the payer committed money to and received nothing complete from. At
	// the default level the only trace used to be an unattributed
	// `sse pump ended with error err="context canceled"` next to an ordinary
	// `status=200`, which is how a client-side timeout stayed invisible.
	switch {
	case abandonedPreGen.Load():
		s.log.Info("client disconnected before generation complete; upstream cancelled",
			append([]any{slog.String("endpoint", endpoint), relayAttr(hop)},
				tally.attrs(forwardStart)...)...)
	case pumpErr == nil && s.log.Enabled(ctx, slog.LevelDebug):
		// Same profile on a clean stream, so the healthy gap distribution is on hand
		// to compare against without needing to reproduce a failure.
		s.log.Debug("stream complete",
			append([]any{slog.String("endpoint", endpoint), relayAttr(hop)},
				tally.attrs(forwardStart)...)...)
	}
	if pumpErr != nil {
		s.log.Warn("sse pump ended with error", slog.String("endpoint", endpoint), slog.Any("err", pumpErr))
		// Only surface a stream error to the client if it's still connected; a
		// drain that ended because the client left has nothing to write to.
		if ctx.Err() == nil {
			var cause error
			if idleErr != nil {
				cause = idleErr
			}
			em.interrupt(cause)
		}
	}
}

// pumpSSE reads SSE frames from upstream, passes each through frameFn, and
// hands the result to emit. Returns nil on clean EOF.
func pumpSSE(
	ctx context.Context,
	emit func(outFrame) (int, error),
	upstream io.Reader,
	frameFn frameTransform,
	tally *streamTally,
) error {
	// bufio.Reader.ReadBytes avoids the 64KB line-length cap that
	// bufio.Scanner would impose — tool-call chunks can exceed that.
	br := bufio.NewReaderSize(upstream, 64*1024)

	var frame Frame
	var dataBuf bytes.Buffer

	flushFrame := func() error {
		if dataBuf.Len() > 0 {
			frame.Data = append([]byte(nil), dataBuf.Bytes()...)
			dataBuf.Reset()
		}
		if frame.isEmpty() {
			frame = Frame{}
			return nil
		}
		out, err := frameFn(frame)
		frame = Frame{}
		if err != nil {
			return fmt.Errorf("transform stream chunk: %w", err)
		}
		if out.isEmpty() {
			return nil
		}
		n, err := emit(out)
		if err != nil {
			return err
		}
		// Zero bytes is a report rather than a frame (the verified usage), so
		// it isn't counted as forwarded.
		if n > 0 {
			tally.record(n)
		}
		return nil
	}

	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		line, err := br.ReadBytes('\n')
		if len(line) > 0 {
			line = trimLineEnd(line)

			if len(line) == 0 {
				// Blank line = frame boundary.
				if err := flushFrame(); err != nil {
					return err
				}
			} else if line[0] == ':' {
				// Comment line. Preserve only if there's no other frame content
				// accumulated yet; otherwise attach to the current frame.
				comment := string(line[1:])
				if len(comment) > 0 && comment[0] == ' ' {
					comment = comment[1:]
				}
				frame.Comment = comment
			} else {
				field, value := splitSSEField(line)
				switch field {
				case "event":
					frame.Event = value
				case "data":
					if dataBuf.Len() > 0 {
						dataBuf.WriteByte('\n')
					}
					dataBuf.WriteString(value)
				case "id":
					frame.ID = value
				case "retry":
					if n, perr := strconv.Atoi(value); perr == nil {
						frame.Retry = n
					}
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				// Flush any trailing frame that wasn't terminated by a blank line.
				if ferr := flushFrame(); ferr != nil {
					return ferr
				}
				return nil
			}
			return err
		}
	}
}

func trimLineEnd(b []byte) []byte {
	n := len(b)
	if n > 0 && b[n-1] == '\n' {
		n--
	}
	if n > 0 && b[n-1] == '\r' {
		n--
	}
	return b[:n]
}

// splitSSEField splits a line like "data: hello" into ("data", "hello").
// Per spec: a single optional leading space after the colon is stripped.
func splitSSEField(line []byte) (string, string) {
	i := bytes.IndexByte(line, ':')
	if i < 0 {
		return string(line), ""
	}
	field := string(line[:i])
	value := line[i+1:]
	if len(value) > 0 && value[0] == ' ' {
		value = value[1:]
	}
	return field, string(value)
}

// SSE returns the frame in Server-Sent Events wire form, terminated by its
// blank line, as an OpenAI-compatible endpoint would write it.
func (f Frame) SSE() []byte {
	var buf bytes.Buffer
	if f.Comment != "" {
		buf.WriteString(": ")
		buf.WriteString(f.Comment)
		buf.WriteByte('\n')
	}
	if f.Event != "" {
		buf.WriteString("event: ")
		buf.WriteString(f.Event)
		buf.WriteByte('\n')
	}
	if f.ID != "" {
		buf.WriteString("id: ")
		buf.WriteString(f.ID)
		buf.WriteByte('\n')
	}
	if f.Retry > 0 {
		buf.WriteString("retry: ")
		buf.WriteString(strconv.Itoa(f.Retry))
		buf.WriteByte('\n')
	}
	if len(f.Data) > 0 {
		// Preserve multi-line data by emitting one "data:" per line.
		for _, line := range bytes.Split(f.Data, []byte{'\n'}) {
			buf.WriteString("data: ")
			buf.Write(line)
			buf.WriteByte('\n')
		}
	}
	buf.WriteByte('\n')
	return buf.Bytes()
}
