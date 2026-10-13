/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// The idle watchdog, porting the TS SDK's test/idle.test.ts over a fake clock.

// idleClock fires timers when a test advances it, never on its own.
type idleClock struct {
	mu     sync.Mutex
	now    time.Duration
	timers []*idleTimer
	// stopFails models a timer already firing as it is stopped: the stop
	// reports false and the callback still runs.
	stopFails bool
}

type idleTimer struct {
	at   time.Duration
	f    func()
	done bool
}

func (c *idleClock) after(d time.Duration, f func()) func() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := &idleTimer{at: c.now + d, f: f}
	c.timers = append(c.timers, t)
	return func() bool {
		c.mu.Lock()
		defer c.mu.Unlock()
		if c.stopFails {
			return false
		}
		was := !t.done
		t.done = true
		return was
	}
}

// advance runs every timer due within d, in order, outside the lock: a timer
// may arm another.
func (c *idleClock) advance(d time.Duration) {
	c.mu.Lock()
	target := c.now + d
	for {
		var next *idleTimer
		for _, t := range c.timers {
			if !t.done && t.at <= target && (next == nil || t.at < next.at) {
				next = t
			}
		}
		if next == nil {
			break
		}
		next.done = true
		c.now = next.at
		c.mu.Unlock()
		next.f()
		c.mu.Lock()
	}
	c.now = target
	c.mu.Unlock()
}

var testIdleBudgets = StreamIdle{PreStream: 1000 * time.Millisecond, MidStream: 100 * time.Millisecond, ToolActive: 500 * time.Millisecond}

type idleFired struct {
	mu    sync.Mutex
	fired []*StreamIdleTimeoutError
}

func (f *idleFired) add(e *StreamIdleTimeoutError) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fired = append(f.fired, e)
}

func (f *idleFired) phases() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.fired {
		out = append(out, e.Phase)
	}
	return out
}

func watchIdle() (*idleWatchdog, *idleClock, *idleFired) {
	c := &idleClock{}
	w := newIdleWatchdog(testIdleBudgets)
	w.after = c.after
	f := &idleFired{}
	w.start(f.add)
	return w, c, f
}

func toolFrame(typ, itemID, tool string) []byte {
	b, _ := json.Marshal(map[string]string{"type": "response.zs_tool_call." + typ, "item_id": itemID, "tool": tool})
	return b
}

func wantPhases(t *testing.T, f *idleFired, want ...string) {
	t.Helper()
	if got := f.phases(); !slices.Equal(got, want) {
		t.Fatalf("fired %v, want %v", got, want)
	}
}

func TestStreamIdle_Defaults(t *testing.T) {
	want := StreamIdle{PreStream: 300 * time.Second, MidStream: 60 * time.Second, ToolActive: 300 * time.Second}
	if DefaultStreamIdle != want {
		t.Errorf("DefaultStreamIdle = %+v, want the chat app's %+v", DefaultStreamIdle, want)
	}
	if got := (Config{}).withDefaults().StreamIdle; got != want {
		t.Errorf("a zero Config's StreamIdle = %+v, want %+v", got, want)
	}
	if got := (Config{StreamIdle: StreamIdle{MidStream: time.Second}}).withDefaults().StreamIdle; got.MidStream != time.Second || got.PreStream != want.PreStream {
		t.Errorf("a partial StreamIdle became %+v, want MidStream kept and the rest defaulted", got)
	}
	if got := (Config{StreamIdle: StreamIdle{ToolActive: -1}}).withDefaults().StreamIdle.ToolActive; got != want.ToolActive {
		t.Errorf("a negative ToolActive became %v, want the default", got)
	}
	if newIdleWatchdog((Config{StreamIdle: StreamIdle{Off: true, MidStream: time.Second}}).withDefaults().StreamIdle) != nil {
		t.Error("Off still built a watchdog")
	}
	// A Client built without withDefaults must not cut every stream at once.
	if got := newIdleWatchdog(StreamIdle{}).budgets; got != want {
		t.Errorf("a zero StreamIdle's watchdog has %+v, want the defaults", got)
	}
}

func TestIdleWatchdog_FiresOnceOnThePreStreamBudget(t *testing.T) {
	_, c, f := watchIdle()
	c.advance(999 * time.Millisecond)
	wantPhases(t, f)
	c.advance(time.Millisecond)
	wantPhases(t, f, IdlePreStream)
	if e := f.fired[0]; e.Timeout != time.Second || e.Error() != "no bytes from the node for 1000ms (pre-stream)" {
		t.Errorf("fired %+v %q", e, e.Error())
	}
	c.advance(10 * time.Second)
	wantPhases(t, f, IdlePreStream)
}

func TestIdleWatchdog_MidStreamOnceBytesFlow(t *testing.T) {
	w, c, f := watchIdle()
	c.advance(900 * time.Millisecond)
	w.chunk()
	c.advance(99 * time.Millisecond)
	w.chunk()
	c.advance(99 * time.Millisecond)
	wantPhases(t, f)
	c.advance(time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_ToolBudgetWhileAnImageRoundIsOpen(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	c.advance(499 * time.Millisecond)
	wantPhases(t, f)
	w.chunk()
	w.frame(toolFrame("completed", "a", "zs_image_generation"))
	c.advance(99 * time.Millisecond)
	wantPhases(t, f)
	c.advance(time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_ToolBudgetForARoundThatNeverCloses(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_edit"))
	c.advance(500 * time.Millisecond)
	wantPhases(t, f, IdleToolActive)
}

func TestIdleWatchdog_ToolBudgetUntilTheLastRoundCloses(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	w.frame(toolFrame("in_progress", "b", "zs_image_generation"))
	w.chunk()
	w.frame(toolFrame("completed", "a", ""))
	c.advance(499 * time.Millisecond)
	wantPhases(t, f)
	w.chunk()
	w.frame(toolFrame("completed", "b", ""))
	c.advance(100 * time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

// A second round opening or closing while another is open leaves the running
// tool budget where it was.
func TestIdleWatchdog_AnotherRoundLeavesTheToolBudgetRunning(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	c.advance(300 * time.Millisecond)
	w.frame(toolFrame("in_progress", "b", "zs_image_generation"))
	c.advance(200 * time.Millisecond)
	wantPhases(t, f, IdleToolActive)

	w, c, f = watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	w.frame(toolFrame("in_progress", "b", "zs_image_generation"))
	c.advance(300 * time.Millisecond)
	w.frame(toolFrame("completed", "b", ""))
	c.advance(200 * time.Millisecond)
	wantPhases(t, f, IdleToolActive)
}

// The chunk carrying the round's opening frame armed the mid-stream budget.
func TestIdleWatchdog_ToolBudgetFromTheOpeningFrame(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	c.advance(50 * time.Millisecond)
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	c.advance(499 * time.Millisecond)
	wantPhases(t, f)
	c.advance(time.Millisecond)
	wantPhases(t, f, IdleToolActive)
}

func TestIdleWatchdog_ClosingTheLastRoundReArmsMidStream(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	c.advance(300 * time.Millisecond)
	w.frame(toolFrame("completed", "a", ""))
	c.advance(100 * time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_IgnoresOtherToolsFramesAndJunk(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_web_search"))
	w.frame([]byte(`{"type":"response.output_text.delta","item_id":"a","tool":"zs_image_generation"}`))
	w.frame([]byte(`{"type":"response.zs_tool_call.in_progress","tool":"zs_image_generation"}`))
	w.frame([]byte(`{"type":"response.zs_tool_call.in_progress","item_id":null,"tool":"zs_image_generation"}`))
	w.frame([]byte(`{"type":"response.zs_tool_call.in_progress","item_id":7,"tool":"zs_image_generation"}`))
	w.frame([]byte(`{"zs_tool_call"`))
	w.frame([]byte(`"zs_tool_call"`))
	c.advance(100 * time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

// A completed frame whose tool isn't a string still closes its round, as in TS.
func TestIdleWatchdog_CompletedClosesWhateverItsTool(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	w.frame([]byte(`{"type":"response.zs_tool_call.completed","item_id":"a","tool":null}`))
	c.advance(100 * time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_CompletedForAnUnseenRoundChangesNothing(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	c.advance(60 * time.Millisecond)
	w.frame(toolFrame("completed", "x", ""))
	c.advance(40 * time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_FiresOnceThoughBytesOrAResumeFollow(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	c.advance(100 * time.Millisecond)
	w.chunk()
	w.resume()
	c.advance(10 * time.Second)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_PausedThenResumesOnTheWholeBudget(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	c.advance(90 * time.Millisecond)
	w.pause()
	c.advance(10 * time.Second)
	wantPhases(t, f)
	w.resume()
	c.advance(99 * time.Millisecond)
	wantPhases(t, f)
	c.advance(time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_PausedThroughARoundOpening(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.pause()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	c.advance(10 * time.Second)
	wantPhases(t, f)
	w.resume()
	c.advance(500 * time.Millisecond)
	wantPhases(t, f, IdleToolActive)
}

func TestIdleWatchdog_StoppedStaysStopped(t *testing.T) {
	w, c, f := watchIdle()
	w.chunk()
	w.stop()
	w.resume()
	w.chunk()
	w.start(f.add)
	c.advance(10 * time.Second)
	wantPhases(t, f)
}

func TestIdleWatchdog_ArmsNothingBeforeStartAndKeepsTheFirstCallback(t *testing.T) {
	c := &idleClock{}
	w := newIdleWatchdog(testIdleBudgets)
	w.after = c.after
	first, second := &idleFired{}, &idleFired{}
	w.chunk()
	c.advance(10 * time.Second)
	w.start(first.add)
	w.start(second.add)
	c.advance(100 * time.Millisecond)
	wantPhases(t, first, IdleMidStream)
	wantPhases(t, second)
}

// A nil watchdog, the bound turned off, takes every call.
func TestIdleWatchdog_NilIsOff(t *testing.T) {
	var w *idleWatchdog
	w.start(func(*StreamIdleTimeoutError) { t.Error("fired") })
	w.chunk()
	w.frame(toolFrame("in_progress", "a", "zs_image_generation"))
	w.pause()
	w.resume()
	w.stop()
}

// A timer that fired as a chunk replaced it must not cut the stream: in real
// time that is a byte arriving at the deadline.
func TestIdleWatchdog_IgnoresATimerThatFiredAsItWasReplaced(t *testing.T) {
	c := &idleClock{stopFails: true}
	w := newIdleWatchdog(testIdleBudgets)
	w.after = c.after
	f := &idleFired{}
	w.start(f.add)
	c.advance(999 * time.Millisecond)
	w.chunk()
	c.advance(time.Millisecond)
	wantPhases(t, f)
	c.advance(98 * time.Millisecond)
	wantPhases(t, f)
	c.advance(time.Millisecond)
	wantPhases(t, f, IdleMidStream)
}

func TestIdleWatchdog_StopReportsTheTimeout(t *testing.T) {
	w, c, _ := watchIdle()
	if w.stop() != nil {
		t.Fatal("an unfired watchdog reported a timeout")
	}
	w, c, _ = watchIdle()
	c.advance(time.Second)
	if e := w.stop(); e == nil || e.Phase != IdlePreStream {
		t.Errorf("stop after firing = %v, want the pre-stream timeout", e)
	}
}

func sseWrite(w http.ResponseWriter, s string) {
	_, _ = io.WriteString(w, s)
	w.(http.Flusher).Flush()
}

// forwardThrough runs forwardRawStream against node, under idle, and fails
// the test if it hasn't returned in 5s. node's hold blocks until the request
// is cancelled or the test ends. It returns what forwardRawStream panicked
// with, if anything.
func forwardThrough(t *testing.T, ctx context.Context, node func(w http.ResponseWriter, hold func()), em emitter,
	factory frameTransformFactory, genComplete *atomic.Bool, idle *idleWatchdog,
) (panicked any) {
	t.Helper()
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		node(w, func() {
			select {
			case <-r.Context().Done():
			case <-release:
			}
		})
	}))
	t.Cleanup(upstream.Close)
	t.Cleanup(func() { close(release) })
	s := settleClient()
	s.httpClient = upstream.Client()
	if genComplete == nil {
		genComplete = &atomic.Bool{}
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() { panicked = recover() }()
		s.forwardRawStream(ctx, em, upstream.URL, "", []byte("{}"), "application/json", nil, nil,
			factory, func(emitter, *http.Response, []byte) error { return nil }, genComplete, idle)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forwardRawStream did not return")
	}
	return panicked
}

func idleBudgets(pre, mid time.Duration) *idleWatchdog {
	return newIdleWatchdog(StreamIdle{PreStream: pre, MidStream: mid, ToolActive: time.Minute})
}

func wantCut(t *testing.T, em *recEmitter, phase string, frames int) {
	t.Helper()
	em.mu.Lock()
	defer em.mu.Unlock()
	var idleErr *StreamIdleTimeoutError
	if !em.broken || !errors.As(em.cause, &idleErr) || idleErr.Phase != phase {
		t.Errorf("broken=%v cause=%v, want interrupted by the %s bound", em.broken, em.cause, phase)
	}
	if len(em.frames) != frames {
		t.Errorf("forwarded %d frames, want %d", len(em.frames), frames)
	}
}

func wantWhole(t *testing.T, em *recEmitter, frames int) {
	t.Helper()
	em.mu.Lock()
	defer em.mu.Unlock()
	if em.broken {
		t.Errorf("interrupted (cause %v), want the stream whole", em.cause)
	}
	if len(em.frames) != frames {
		t.Errorf("forwarded %d frames, want %d", len(em.frames), frames)
	}
}

// A node that opens a stream, sends a frame and then goes silent without
// closing is cut at the mid-stream budget, and the stream ends interrupted
// with the timeout as its cause. Without the bound it would hang until the
// caller's context ended.
func TestForwardRawStream_CutsASilentNode(t *testing.T) {
	em := &recEmitter{}
	forwardThrough(t, context.Background(), func(w http.ResponseWriter, hold func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		sseWrite(w, "data: hello\n\n")
		hold()
	}, em, passFrames, nil, idleBudgets(time.Minute, 50*time.Millisecond))
	wantCut(t, em, IdleMidStream, 1)
}

func TestForwardRawStream_CutsANodeThatNeverStarts(t *testing.T) {
	em := &recEmitter{}
	forwardThrough(t, context.Background(), func(w http.ResponseWriter, hold func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		hold()
	}, em, passFrames, nil, idleBudgets(50*time.Millisecond, time.Minute))
	wantCut(t, em, IdlePreStream, 0)
}

func TestForwardRawStream_KeepaliveIsAlive(t *testing.T) {
	em := &recEmitter{}
	forwardThrough(t, context.Background(), func(w http.ResponseWriter, _ func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		for range 10 {
			sseWrite(w, ": zs-keepalive\n\n")
			time.Sleep(20 * time.Millisecond)
		}
		sseWrite(w, "data: done\n\n")
	}, em, passFrames, nil, idleBudgets(100*time.Millisecond, 100*time.Millisecond))
	wantWhole(t, em, 11)
}

// slowEmitter is a caller whose loop body takes a while over each frame. Go's
// emitter runs it inline with the pump.
type slowEmitter struct {
	*recEmitter
	delay time.Duration
}

func (e slowEmitter) frame(out outFrame) (int, error) {
	time.Sleep(e.delay)
	return e.recEmitter.frame(out)
}

// twoFramesApart sends a frame, then another after gap. The pump must read
// again for the second, so a timer left running through the first frame's
// handling would have cut the stream by then.
func twoFramesApart(gap time.Duration) func(http.ResponseWriter, func()) {
	return func(w http.ResponseWriter, _ func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		sseWrite(w, "data: a\n\n")
		time.Sleep(gap)
		sseWrite(w, "data: b\n\n")
	}
}

func TestForwardRawStream_ASlowCallerIsNotTheNodesSilence(t *testing.T) {
	em := &recEmitter{}
	forwardThrough(t, context.Background(), twoFramesApart(100*time.Millisecond),
		slowEmitter{em, 300 * time.Millisecond}, passFrames, nil, idleBudgets(time.Minute, 50*time.Millisecond))
	wantWhole(t, em, 2)
}

func TestForwardRawStream_TheFrameHookIsNotTheNodesSilence(t *testing.T) {
	slow := func(*http.Response) (frameTransform, error) {
		return func(f Frame) (outFrame, error) {
			time.Sleep(300 * time.Millisecond)
			return outFrame{frame: f}, nil
		}, nil
	}
	em := &recEmitter{}
	forwardThrough(t, context.Background(), twoFramesApart(100*time.Millisecond),
		em, slow, nil, idleBudgets(time.Minute, 50*time.Millisecond))
	wantWhole(t, em, 2)
}

// A stream that breaks for another reason carries no cause: a nil
// *StreamIdleTimeoutError in the error interface would read as one.
func TestForwardRawStream_ABreakThatIsNotTheBoundHasNoCause(t *testing.T) {
	em := &recEmitter{}
	forwardThrough(t, context.Background(), func(w http.ResponseWriter, _ func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		sseWrite(w, "data: a\n\n")
		panic(http.ErrAbortHandler)
	}, em, passFrames, nil, idleBudgets(time.Minute, time.Minute))
	em.mu.Lock()
	defer em.mu.Unlock()
	if !em.broken || em.cause != nil {
		t.Errorf("broken=%v cause=%#v, want interrupted with no cause", em.broken, em.cause)
	}
}

func TestForwardRawStream_DisarmsWhenTheStreamEnds(t *testing.T) {
	idle := idleBudgets(time.Minute, time.Minute)
	forwardThrough(t, context.Background(), func(w http.ResponseWriter, _ func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		sseWrite(w, "data: a\n\n")
	}, &recEmitter{}, passFrames, nil, idle)
	idle.mu.Lock()
	defer idle.mu.Unlock()
	if !idle.stopped || idle.stopTimer != nil {
		t.Errorf("stopped=%v timer armed=%v after the stream ended", idle.stopped, idle.stopTimer != nil)
	}
}

// panickingEmitter is a caller whose loop body panics; Go's emitter runs it
// inline, so the panic unwinds through the forwarder.
type panickingEmitter struct{ *recEmitter }

func (panickingEmitter) frame(outFrame) (int, error) { panic("caller") }

func TestForwardRawStream_DisarmsWhenTheCallerPanics(t *testing.T) {
	idle := idleBudgets(time.Minute, time.Minute)
	got := forwardThrough(t, context.Background(), func(w http.ResponseWriter, hold func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		sseWrite(w, "data: a\n\n")
		hold()
	}, panickingEmitter{&recEmitter{}}, passFrames, nil, idle)
	if got != "caller" {
		t.Fatalf("panicked with %v, want the caller's panic", got)
	}
	idle.mu.Lock()
	defer idle.mu.Unlock()
	if !idle.stopped || idle.stopTimer != nil {
		t.Errorf("stopped=%v timer armed=%v after the caller panicked", idle.stopped, idle.stopTimer != nil)
	}
}

func TestForwardRawStream_DoesNotArmOnAReplyThatIsNotAStream(t *testing.T) {
	idle := idleBudgets(time.Minute, time.Minute)
	forwardThrough(t, context.Background(), func(w http.ResponseWriter, _ func()) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}, &recEmitter{}, passFrames, nil, idle)
	idle.mu.Lock()
	defer idle.mu.Unlock()
	if idle.started {
		t.Error("the watchdog was armed for a reply that isn't an event stream")
	}
}

// leavingEmitter is a caller that leaves on the first frame.
type leavingEmitter struct {
	*recEmitter
	leave context.CancelFunc
}

func (e leavingEmitter) frame(out outFrame) (int, error) {
	defer e.leave()
	return e.recEmitter.frame(out)
}

// The caller left after generation completed, so the SDK drains toward the
// receipt; a node silent through that drain is cut at the idle bound rather
// than the drain's 10s, and nobody is told, since nobody is listening.
func TestForwardRawStream_BoundsTheTailDrainAndTellsNobody(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var genComplete atomic.Bool
	genComplete.Store(true)
	em := &recEmitter{}
	start := time.Now()
	forwardThrough(t, ctx, func(w http.ResponseWriter, hold func()) {
		w.Header().Set("Content-Type", "text/event-stream")
		sseWrite(w, "data: a\n\n")
		hold()
	}, leavingEmitter{em, cancel}, passFrames, &genComplete, idleBudgets(time.Minute, 50*time.Millisecond))
	if took := time.Since(start); took >= drainTailTimeout/2 {
		t.Errorf("returned after %v, want the idle bound to end the drain", took)
	}
	wantWhole(t, em, 1)
}
