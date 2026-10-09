/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// frameSink collects what pumpSSE emits as SSE text, counting frames.
type frameSink struct {
	buf    bytes.Buffer
	frames int
}

func (s *frameSink) emit(out outFrame) (int, error) {
	s.frames++
	return s.buf.Write(out.frame.SSE())
}

func (s *frameSink) String() string { return s.buf.String() }

func identityFrame(f Frame) (outFrame, error) { return outFrame{frame: f}, nil }

func TestTrimLineEnd(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"", ""},
		{"\n", ""},
		{"\r\n", ""},
		{"abc", "abc"},
		{"abc\n", "abc"},
		{"abc\r\n", "abc"},
		{"\r", ""},
	}
	for _, c := range cases {
		if got := string(trimLineEnd([]byte(c.in))); got != c.want {
			t.Errorf("trimLineEnd(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSplitSSEField(t *testing.T) {
	cases := []struct {
		in, field, val string
	}{
		{"data: hi", "data", "hi"},
		{"data:hi", "data", "hi"},
		{"event:foo", "event", "foo"},
		{"nocolon", "nocolon", ""},
		{"data: ", "data", ""},
	}
	for _, c := range cases {
		f, v := splitSSEField([]byte(c.in))
		if f != c.field || v != c.val {
			t.Errorf("splitSSEField(%q) = (%q,%q), want (%q,%q)", c.in, f, v, c.field, c.val)
		}
	}
}

func TestFrameSSE_BasicData(t *testing.T) {
	if got := string(Frame{Data: []byte("hi")}.SSE()); got != "data: hi\n\n" {
		t.Errorf("got %q", got)
	}
}

func TestFrameSSE_MultiLineData(t *testing.T) {
	want := "data: line1\ndata: line2\n\n"
	if got := string(Frame{Data: []byte("line1\nline2")}.SSE()); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestFrameSSE_EventIDRetryComment(t *testing.T) {
	s := string(Frame{
		Comment: "hb",
		Event:   "message",
		ID:      "42",
		Retry:   1000,
		Data:    []byte("payload"),
	}.SSE())
	for _, sub := range []string{": hb\n", "event: message\n", "id: 42\n", "retry: 1000\n", "data: payload\n"} {
		if !strings.Contains(s, sub) {
			t.Errorf("missing %q in %q", sub, s)
		}
	}
	if !strings.HasSuffix(s, "\n\n") {
		t.Errorf("frame must end with blank line: %q", s)
	}
}

func TestPumpSSE_BasicFrames(t *testing.T) {
	in := strings.NewReader("data: one\n\ndata: two\n\ndata: three\n\n")
	var sink frameSink

	if err := pumpSSE(context.Background(), sink.emit, in, identityFrame, &streamTally{}); err != nil {
		t.Fatalf("pumpSSE: %v", err)
	}
	out := sink.String()
	for _, v := range []string{"data: one", "data: two", "data: three"} {
		if !strings.Contains(out, v) {
			t.Errorf("missing %q in %q", v, out)
		}
	}
	if sink.frames != 3 {
		t.Errorf("frames = %d, want 3", sink.frames)
	}
}

func TestPumpSSE_MultiLineData(t *testing.T) {
	in := strings.NewReader("data: l1\ndata: l2\n\n")
	var sink frameSink

	if err := pumpSSE(context.Background(), sink.emit, in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	out := sink.String()
	// Output should have two data lines (re-emitted) and a blank line.
	if !strings.Contains(out, "data: l1\ndata: l2\n\n") {
		t.Errorf("output = %q", out)
	}
}

func TestPumpSSE_EventAndID(t *testing.T) {
	in := strings.NewReader("event: msg\nid: 7\ndata: payload\n\n")
	var sink frameSink

	if err := pumpSSE(context.Background(), sink.emit, in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	out := sink.String()
	for _, sub := range []string{"event: msg", "id: 7", "data: payload"} {
		if !strings.Contains(out, sub) {
			t.Errorf("missing %q in %q", sub, out)
		}
	}
}

func TestPumpSSE_CommentLine(t *testing.T) {
	in := strings.NewReader(": keepalive\n\ndata: hi\n\n")
	var sink frameSink

	if err := pumpSSE(context.Background(), sink.emit, in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	if out := sink.String(); !strings.Contains(out, ": keepalive") {
		t.Errorf("comment missing: %q", out)
	}
}

func TestPumpSSE_LargeFrame(t *testing.T) {
	// 128 KB of data inside one frame — well past bufio.Scanner's 64 KB cap.
	big := strings.Repeat("x", 128*1024)
	in := strings.NewReader("data: " + big + "\n\n")
	var sink frameSink

	if err := pumpSSE(context.Background(), sink.emit, in, identityFrame, &streamTally{}); err != nil {
		t.Fatalf("pumpSSE large frame: %v", err)
	}
	if !strings.Contains(sink.String(), big) {
		t.Error("large frame dropped or truncated")
	}
}

func TestPumpSSE_FrameTransformDrops(t *testing.T) {
	in := strings.NewReader("data: one\n\ndata: drop-me\n\ndata: three\n\n")
	var sink frameSink

	drop := func(fr Frame) (outFrame, error) {
		if bytes.Equal(fr.Data, []byte("drop-me")) {
			return outFrame{}, nil
		}
		return outFrame{frame: fr}, nil
	}

	if err := pumpSSE(context.Background(), sink.emit, in, drop, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	if out := sink.String(); strings.Contains(out, "drop-me") {
		t.Errorf("dropped frame appeared in output: %q", out)
	}
	if sink.frames != 2 {
		t.Errorf("frames = %d, want 2", sink.frames)
	}
}

func TestPumpSSE_FrameTransformError(t *testing.T) {
	in := strings.NewReader("data: one\n\n")
	var sink frameSink

	fail := func(Frame) (outFrame, error) {
		return outFrame{}, errors.New("transform boom")
	}

	err := pumpSSE(context.Background(), sink.emit, in, fail, &streamTally{})
	if err == nil || !strings.Contains(err.Error(), "transform stream chunk") {
		t.Errorf("err = %v", err)
	}
}

func TestPumpSSE_ContextCancelled(t *testing.T) {
	in := strings.NewReader("data: one\n\n")
	var sink frameSink

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := pumpSSE(ctx, sink.emit, in, identityFrame, &streamTally{})
	if err == nil {
		t.Fatal("want ctx.Err()")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want context.Canceled", err)
	}
}

func TestPumpSSE_EOFFlushesTrailingFrame(t *testing.T) {
	// No trailing blank line.
	in := strings.NewReader("data: trailing")
	var sink frameSink

	if err := pumpSSE(context.Background(), sink.emit, in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(sink.String(), "data: trailing") {
		t.Errorf("trailing frame lost: %q", sink.String())
	}
}

// The tally is the disconnect diagnostic's whole value, so it has to measure the
// two things that distinguish a client's total-elapsed deadline from an idle
// timeout: how much actually got delivered, and the longest silence between
// frames. A wrong maxGap sends the next investigation at the wrong fix.
func TestStreamTally_RecordsVolumeAndLargestGap(t *testing.T) {
	var tally streamTally
	start := time.Now()

	// No frames yet: ttfb must read as zero rather than "the whole elapsed time",
	// which would make a stream that never produced anything look slow-but-alive.
	if tally.frames != 0 || tally.maxGap != 0 {
		t.Fatalf("fresh tally = %+v, want zero", tally)
	}

	// Without a pause, start and the first frame can share a clock reading.
	time.Sleep(2 * time.Millisecond)
	tally.record(10)
	tally.record(20)
	// A deliberate pause, then another frame: this gap must be the recorded max.
	time.Sleep(40 * time.Millisecond)
	tally.record(30)
	tally.record(40)

	if tally.frames != 4 {
		t.Errorf("frames = %d, want 4", tally.frames)
	}
	if tally.bytes != 100 {
		t.Errorf("bytes = %d, want 100", tally.bytes)
	}
	if tally.maxGap < 30*time.Millisecond {
		t.Errorf("maxGap = %s, want >= 30ms (the deliberate pause)", tally.maxGap)
	}
	// The gap must be an INTER-frame measure, not total elapsed: the two fast
	// frames after the pause must not have widened it.
	if tally.maxGap > 5*time.Second {
		t.Errorf("maxGap = %s; looks like total elapsed rather than an inter-frame gap", tally.maxGap)
	}

	// attrs must report a non-zero ttfb once a frame has landed, measured from the
	// forward start so it includes the reserve + escrow-open preamble the client
	// also waited through.
	if ttfb := durAttr(t, tally.attrs(start), "ttfb"); ttfb < 2*time.Millisecond {
		t.Errorf("ttfb attr = %s, want >= the 2ms before the first frame", ttfb)
	}
}

// A stream that delivered nothing must report ttfb=0, not the elapsed time —
// otherwise "we waited 25s and got nothing" reads as "first byte took 25s".
func TestStreamTally_NoFramesReportsZeroTTFB(t *testing.T) {
	var tally streamTally
	attrs := tally.attrs(time.Now().Add(-2 * time.Second))
	if d := durAttr(t, attrs, "ttfb"); d != 0 {
		t.Errorf("ttfb = %s, want 0 when no frame was delivered", d)
	}
	if d := durAttr(t, attrs, "elapsed"); d < time.Second {
		t.Errorf("elapsed = %s, want the real wall clock (>=1s)", d)
	}
}

// durAttr pulls a slog.Duration value out of the []any that streamTally.attrs
// returns, so the assertions below read as the log line does.
func durAttr(t *testing.T, attrs []any, key string) time.Duration {
	t.Helper()
	for _, a := range attrs {
		if sa, ok := a.(slog.Attr); ok && sa.Key == key {
			return sa.Value.Duration()
		}
	}
	t.Fatalf("attr %q not emitted; got %v", key, attrs)
	return 0
}

// The disconnect diagnostic exists to separate a client idle timeout from a
// client total-elapsed deadline, and maxGap alone cannot do it: it spans
// frame→frame, so the one gap it structurally cannot see is the trailing
// silence between the final frame and the cut — which is exactly an idle
// timeout's signature.
//
// This pins the discrimination on the shape that misleads: a stream that
// stalls mid-flight, RECOVERS, and is then abandoned during a longer silence.
// maxGap reports the earlier, shorter stall and understates how the stream
// actually ended; only silence_before_cut tells the truth. Reading a real
// disconnect off maxGap alone concluded "total-elapsed deadline, nothing the
// proxy can fix" for precisely this shape.
func TestStreamTally_SilenceBeforeCut_SeesWhatMaxGapCannot(t *testing.T) {
	var tally streamTally
	start := time.Now()

	// Frame, a mid-stream stall, then recovery — the stall becomes maxGap.
	tally.record(10)
	time.Sleep(30 * time.Millisecond)
	tally.record(10)

	// ...then the stream goes quiet for materially longer and the client cuts.
	time.Sleep(90 * time.Millisecond)
	attrs := tally.attrs(start)

	maxGap := durAttr(t, attrs, "max_inter_frame_gap")
	silence := durAttr(t, attrs, "silence_before_cut")

	// The trailing silence must not have leaked into maxGap: maxGap is the
	// recovered mid-stream stall, and staying frame→frame is what makes the
	// two numbers independent evidence rather than one number twice.
	if maxGap >= 80*time.Millisecond {
		t.Errorf("max_inter_frame_gap = %v; the trailing silence leaked into it, "+
			"collapsing the two signals the log line exists to separate", maxGap)
	}
	if silence < 80*time.Millisecond {
		t.Errorf("silence_before_cut = %v, want >= ~90ms; the trailing gap is "+
			"invisible, which is the blind spot this attribute closes", silence)
	}
	// The ordering IS the diagnosis — silence dominating maxGap is what says
	// "idle timeout" rather than "total-elapsed deadline".
	if silence <= maxGap {
		t.Errorf("silence_before_cut (%v) <= max_inter_frame_gap (%v); an idle-timeout "+
			"shape must read as trailing-silence-dominant", silence, maxGap)
	}
}

// The mirror case: frames flowing right up to the cut is the total-elapsed
// deadline signature, and it must report a near-zero trailing silence so it
// is not misread as an idle timeout (which would send someone tuning a
// keepalive cadence that cannot help).
func TestStreamTally_SilenceBeforeCut_NearZeroWhenFramesFlowToTheCut(t *testing.T) {
	var tally streamTally
	start := time.Now()
	tally.record(10)
	time.Sleep(40 * time.Millisecond)
	tally.record(10) // last frame lands immediately before the cut

	if silence := durAttr(t, tally.attrs(start), "silence_before_cut"); silence > 20*time.Millisecond {
		t.Errorf("silence_before_cut = %v, want ~0 when frames flow to the cut", silence)
	}
}

// A stream cut before any frame was forwarded leaves lastAt unset. Reporting
// time.Since(zero) there would emit a ~55-year duration and swamp the log line.
func TestStreamTally_SilenceBeforeCut_ZeroFramesReportsZero(t *testing.T) {
	var tally streamTally
	if silence := durAttr(t, tally.attrs(time.Now()), "silence_before_cut"); silence != 0 {
		t.Errorf("silence_before_cut = %v with no frames recorded, want 0", silence)
	}
}
