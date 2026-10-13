/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// The read-side silence bound on a streamed answer, the TS SDK's idle.ts.
// http.Client.Timeout stays 0 on the forward client and TCP keepalive answers
// for a peer that is alive but has stopped writing, so without it a node or
// relay that stops sending, without closing, holds the request, its escrow
// and its spend reservation until the caller's context ends. The bound is on
// bytes, not frames: a node's keepalive comment proves the hop is alive.

// StreamIdle is the silence a streamed answer may keep, by phase. A whole
// reply's body is held to MidStream. A zero field takes DefaultStreamIdle's;
// Off turns the bound off.
type StreamIdle struct {
	// PreStream is before the first byte of the body. A reasoning model can
	// buffer its whole thinking window before the first frame.
	PreStream time.Duration
	// MidStream is between bytes once they flow.
	MidStream time.Duration
	// ToolActive is between bytes while the node runs an image tool, whose
	// round sends nothing until the image is done.
	ToolActive time.Duration
	// Off waits as long as the caller's context allows.
	Off bool
}

// DefaultStreamIdle is the chat app's budgets, which the TS SDK shares.
var DefaultStreamIdle = StreamIdle{PreStream: 5 * time.Minute, MidStream: time.Minute, ToolActive: 5 * time.Minute}

func (b StreamIdle) withDefaults() StreamIdle {
	if b.Off {
		return StreamIdle{Off: true}
	}
	b.PreStream = orDefault(b.PreStream, DefaultStreamIdle.PreStream)
	b.MidStream = orDefault(b.MidStream, DefaultStreamIdle.MidStream)
	b.ToolActive = orDefault(b.ToolActive, DefaultStreamIdle.ToolActive)
	return b
}

// Stream idle phases: which budget a silence was measured against.
const (
	IdlePreStream  = "pre-stream"
	IdleMidStream  = "mid-stream"
	IdleToolActive = "tool-active"
)

// StreamIdleTimeoutError is a node that sent nothing for longer than the
// phase allows. It is the cause (Error.Err) of the stream_interrupted error
// that ends the turn.
type StreamIdleTimeoutError struct {
	Phase   string
	Timeout time.Duration
}

func (e *StreamIdleTimeoutError) Error() string {
	return fmt.Sprintf("no bytes from the node for %dms (%s)", e.Timeout.Milliseconds(), e.Phase)
}

// imageTools are the built-in tools whose round leaves the stream silent.
var imageTools = map[string]bool{"zs_image_generation": true, "zs_image_edit": true}

// idleWatchdog times one stream's silences. start arms it, each chunk of the
// body re-arms it, and when a silence outlives its budget it calls onIdle
// once. While an image tool round is open, silences are measured against
// ToolActive; closing the last one re-arms against MidStream at once, so a
// node that hangs after the tool is still caught at the normal budget.
//
// pause and resume bracket the SDK's own work on a frame and the caller's on
// what it became, neither of which reads bytes meanwhile: a receipt's settle
// can take longer than a small budget, and Go's emitter runs the caller's
// loop body inline, so a slow consumer would otherwise read as the node's
// silence.
type idleWatchdog struct {
	budgets StreamIdle
	// after schedules f after d and returns its stop; time.AfterFunc's, or a
	// test's fake clock.
	after func(d time.Duration, f func()) func() bool

	mu         sync.Mutex
	onIdle     func(*StreamIdleTimeoutError)
	stopTimer  func() bool
	gen        uint64 // which arming a firing timer belongs to
	started    bool
	flowing    bool
	paused     bool
	stopped    bool
	fired      *StreamIdleTimeoutError
	toolRounds map[string]struct{}
}

// newIdleWatchdog returns nil when the bound is off; every method is safe on nil.
func newIdleWatchdog(b StreamIdle) *idleWatchdog {
	b = b.withDefaults()
	if b.Off {
		return nil
	}
	return &idleWatchdog{
		budgets: b,
		after: func(d time.Duration, f func()) func() bool {
			return time.AfterFunc(d, f).Stop
		},
		toolRounds: map[string]struct{}{},
	}
}

// start arms the pre-stream budget; onIdle runs at most once.
func (w *idleWatchdog) start(onIdle func(*StreamIdleTimeoutError)) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.started || w.stopped {
		return
	}
	w.started = true
	w.onIdle = onIdle
	w.arm()
}

// chunk is a read of the body that returned bytes.
func (w *idleWatchdog) chunk() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.flowing = true
	w.arm()
}

var toolCallNeedle = []byte("zs_tool_call")

// frame reads one opened frame for an image tool round opening or closing. A
// frame that can't be one is not decoded.
func (w *idleWatchdog) frame(plaintext []byte) {
	if w == nil || !bytes.Contains(plaintext, toolCallNeedle) {
		return
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(plaintext, &top) != nil {
		return
	}
	itemID, ok := jsonString(top["item_id"])
	if !ok {
		return
	}
	typ, _ := jsonString(top["type"])
	tool, _ := jsonString(top["tool"])
	w.mu.Lock()
	defer w.mu.Unlock()
	before := len(w.toolRounds)
	switch {
	case typ == "response.zs_tool_call.in_progress" && imageTools[tool]:
		w.toolRounds[itemID] = struct{}{}
	case typ == "response.zs_tool_call.completed":
		delete(w.toolRounds, itemID)
	default:
		return
	}
	// Entering re-arms too, though the chunk that carried this frame just did:
	// the budget that chunk armed was the one for outside a round.
	if (before == 0) != (len(w.toolRounds) == 0) {
		w.arm()
	}
}

// jsonString is raw as a JSON string, and false for anything else: a null
// would otherwise decode as "", which TS's typeof check refuses.
func jsonString(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

// pause disarms until resume.
func (w *idleWatchdog) pause() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.paused = true
	w.disarm()
}

// resume re-arms the whole budget of the current phase.
func (w *idleWatchdog) resume() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.paused = false
	w.arm()
}

// stop disarms for good, and returns the timeout if the watchdog fired first.
func (w *idleWatchdog) stop() *StreamIdleTimeoutError {
	if w == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.stopped = true
	w.disarm()
	return w.fired
}

func (w *idleWatchdog) disarm() {
	if w.stopTimer != nil {
		w.stopTimer()
		w.stopTimer = nil
	}
	w.gen++
}

func (w *idleWatchdog) arm() {
	if !w.started || w.paused || w.stopped {
		return
	}
	w.disarm()
	phase, d := IdlePreStream, w.budgets.PreStream
	switch {
	case !w.flowing:
	case len(w.toolRounds) > 0:
		phase, d = IdleToolActive, w.budgets.ToolActive
	default:
		phase, d = IdleMidStream, w.budgets.MidStream
	}
	gen := w.gen
	w.stopTimer = w.after(d, func() {
		w.mu.Lock()
		// A timer that fired as it was being replaced is not this arming's.
		if w.stopped || gen != w.gen {
			w.mu.Unlock()
			return
		}
		w.stopTimer = nil
		w.stopped = true
		w.fired = &StreamIdleTimeoutError{Phase: phase, Timeout: d}
		onIdle := w.onIdle
		w.mu.Unlock()
		onIdle(w.fired)
	})
}

// idleReader reports each read that returned bytes to the watchdog, and stops
// it on the read that ends the body: past that, a firing would be a silence
// after the end, and would be reported as the cause of whatever ended it.
type idleReader struct {
	r io.Reader
	w *idleWatchdog
}

func (r idleReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if n > 0 {
		r.w.chunk()
	}
	if err != nil {
		r.w.stop()
	}
	return n, err
}

// maxReplyBytes caps a buffered reply's body. The node puts generated media in
// the body, base64, and caps none of it, so without this a node or relay that
// never ends a body holds the turn, its escrow and the payer's memory.
const maxReplyBytes = 256 << 20

// readReply reads a buffered reply's body whole, refusing one over limit. The
// node writes a buffered reply's body with its headers, so every silence in
// it is measured against MidStream, unless the bound is off. A silence past
// that calls cancel, which must end the request, and the error is the
// *StreamIdleTimeoutError.
func readReply(body io.Reader, b StreamIdle, limit int64, cancel func()) ([]byte, error) {
	b = b.withDefaults()
	idle := newIdleWatchdog(StreamIdle{PreStream: b.MidStream, MidStream: b.MidStream, ToolActive: b.MidStream, Off: b.Off})
	idle.start(func(*StreamIdleTimeoutError) { cancel() })
	defer idle.stop()
	got, err := io.ReadAll(io.LimitReader(idleReader{r: body, w: idle}, limit+1))
	if idleErr := idle.stop(); idleErr != nil {
		return nil, idleErr
	}
	if err != nil {
		return nil, err
	}
	if int64(len(got)) > limit {
		return nil, fmt.Errorf("the node's reply is over %d bytes", limit)
	}
	return got, nil
}

// readUpstreamError is the turn's error for a buffered reply that couldn't be
// read, with why as its Err.
func readUpstreamError(err error) *Error {
	e := newError("read_upstream", err.Error())
	e.Err = err
	return e
}

// bracket runs f with the watchdog paused, and stops it if f fails, since the
// pump ends on that error.
func bracket[T any](w *idleWatchdog, f func() (T, error)) (T, error) {
	w.pause()
	v, err := f()
	if err != nil {
		w.stop()
	} else {
		w.resume()
	}
	return v, err
}
