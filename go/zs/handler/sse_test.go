/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
)

// fakeFlusher is an http.Flusher that counts Flush calls.
type fakeFlusher struct {
	flushes int
}

func (f *fakeFlusher) Flush() { f.flushes++ }

func newFlushWriter() (*bytes.Buffer, *fakeFlusher) {
	return &bytes.Buffer{}, &fakeFlusher{}
}

func identityFrame(f transform.SSEFrame) (outFrame, error) { return outFrame{frame: f}, nil }

// emitTo is the frame sink an open httpEmitter hands pumpSSE, writing into buf.
func emitTo(buf *bytes.Buffer, f *fakeFlusher) func(outFrame) (int, error) {
	e := &httpEmitter{w: bufferWriter{buf}, clientCtx: context.Background(), flusher: f}
	return e.frame
}

type bufferWriter struct{ *bytes.Buffer }

func (bufferWriter) Header() http.Header { return http.Header{} }
func (bufferWriter) WriteHeader(int)     {}

// clientAwareWriter forwards while the client context is live and silently
// swallows once it's cancelled — so a tail drain after a client disconnect
// isn't torn down by a dead-socket write error.
func TestClientAwareWriter(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var sink bytes.Buffer
	cw := &clientAwareWriter{w: &sink, clientCtx: ctx}

	n, err := cw.Write([]byte("live"))
	if err != nil || n != 4 {
		t.Fatalf("live write: n=%d err=%v", n, err)
	}

	cancel() // client gone

	n, err = cw.Write([]byte("dropped"))
	if err != nil || n != 7 {
		// Reports the full length as written (no error) so writeSSEFrame keeps
		// going and the pump reaches the receipt frame.
		t.Fatalf("post-cancel write: n=%d err=%v, want n=7 err=nil", n, err)
	}
	if sink.String() != "live" {
		t.Errorf("sink = %q, want only the pre-cancel write %q", sink.String(), "live")
	}
}

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

func TestWriteSSEFrame_BasicData(t *testing.T) {
	var buf bytes.Buffer
	_, err := writeSSEFrame(&buf, transform.SSEFrame{Data: []byte("hi")})
	if err != nil {
		t.Fatal(err)
	}
	if buf.String() != "data: hi\n\n" {
		t.Errorf("got %q", buf.String())
	}
}

func TestWriteSSEFrame_MultiLineData(t *testing.T) {
	var buf bytes.Buffer
	_, err := writeSSEFrame(&buf, transform.SSEFrame{Data: []byte("line1\nline2")})
	if err != nil {
		t.Fatal(err)
	}
	want := "data: line1\ndata: line2\n\n"
	if buf.String() != want {
		t.Errorf("got %q, want %q", buf.String(), want)
	}
}

func TestWriteSSEFrame_EventIDRetryComment(t *testing.T) {
	var buf bytes.Buffer
	_, err := writeSSEFrame(&buf, transform.SSEFrame{
		Comment: "hb",
		Event:   "message",
		ID:      "42",
		Retry:   1000,
		Data:    []byte("payload"),
	})
	if err != nil {
		t.Fatal(err)
	}
	s := buf.String()
	for _, sub := range []string{": hb\n", "event: message\n", "id: 42\n", "retry: 1000\n", "data: payload\n"} {
		if !strings.Contains(s, sub) {
			t.Errorf("missing %q in %q", sub, s)
		}
	}
	if !strings.HasSuffix(s, "\n\n") {
		t.Errorf("frame must end with blank line: %q", s)
	}
}

func TestWriteSSEError_GenericMessage(t *testing.T) {
	buf, f := newFlushWriter()
	writeSSEError(buf, f)

	out := buf.String()
	if strings.Contains(out, "secret internal detail") {
		t.Errorf("internal err leaked: %q", out)
	}
	if !strings.Contains(out, "stream interrupted") {
		t.Errorf("generic msg missing: %q", out)
	}
	if !strings.Contains(out, "[DONE]") {
		t.Error("missing [DONE] sentinel")
	}
}

func TestPumpSSE_BasicFrames(t *testing.T) {
	in := strings.NewReader("data: one\n\ndata: two\n\ndata: three\n\n")
	buf, f := newFlushWriter()

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, identityFrame, &streamTally{}); err != nil {
		t.Fatalf("pumpSSE: %v", err)
	}
	out := buf.String()
	for _, v := range []string{"data: one", "data: two", "data: three"} {
		if !strings.Contains(out, v) {
			t.Errorf("missing %q in %q", v, out)
		}
	}
	if f.flushes != 3 {
		t.Errorf("flushes = %d, want 3", f.flushes)
	}
}

func TestPumpSSE_MultiLineData(t *testing.T) {
	in := strings.NewReader("data: l1\ndata: l2\n\n")
	buf, f := newFlushWriter()

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Output should have two data lines (re-emitted) and a blank line.
	if !strings.Contains(out, "data: l1\ndata: l2\n\n") {
		t.Errorf("output = %q", out)
	}
}

func TestPumpSSE_EventAndID(t *testing.T) {
	in := strings.NewReader("event: msg\nid: 7\ndata: payload\n\n")
	buf, f := newFlushWriter()

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, sub := range []string{"event: msg", "id: 7", "data: payload"} {
		if !strings.Contains(out, sub) {
			t.Errorf("missing %q in %q", sub, out)
		}
	}
}

func TestPumpSSE_CommentLine(t *testing.T) {
	in := strings.NewReader(": keepalive\n\ndata: hi\n\n")
	buf, f := newFlushWriter()

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, ": keepalive") {
		t.Errorf("comment missing: %q", out)
	}
}

func TestPumpSSE_LargeFrame(t *testing.T) {
	// 128 KB of data inside one frame — well past bufio.Scanner's 64 KB cap.
	big := strings.Repeat("x", 128*1024)
	in := strings.NewReader("data: " + big + "\n\n")
	buf, f := newFlushWriter()

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, identityFrame, &streamTally{}); err != nil {
		t.Fatalf("pumpSSE large frame: %v", err)
	}
	if !strings.Contains(buf.String(), big) {
		t.Error("large frame dropped or truncated")
	}
}

func TestPumpSSE_FrameTransformDrops(t *testing.T) {
	in := strings.NewReader("data: one\n\ndata: drop-me\n\ndata: three\n\n")
	buf, f := newFlushWriter()

	drop := func(fr transform.SSEFrame) (outFrame, error) {
		if bytes.Equal(fr.Data, []byte("drop-me")) {
			return outFrame{}, nil
		}
		return outFrame{frame: fr}, nil
	}

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, drop, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if strings.Contains(out, "drop-me") {
		t.Errorf("dropped frame appeared in output: %q", out)
	}
	if f.flushes != 2 {
		t.Errorf("flushes = %d, want 2", f.flushes)
	}
}

func TestPumpSSE_FrameTransformError(t *testing.T) {
	in := strings.NewReader("data: one\n\n")
	buf, f := newFlushWriter()

	fail := func(transform.SSEFrame) (outFrame, error) {
		return outFrame{}, errors.New("transform boom")
	}

	err := pumpSSE(context.Background(), emitTo(buf, f), in, fail, &streamTally{})
	if err == nil || !strings.Contains(err.Error(), "transform stream chunk") {
		t.Errorf("err = %v", err)
	}
}

func TestPumpSSE_ContextCancelled(t *testing.T) {
	in := strings.NewReader("data: one\n\n")
	buf, f := newFlushWriter()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := pumpSSE(ctx, emitTo(buf, f), in, identityFrame, &streamTally{})
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
	buf, f := newFlushWriter()

	if err := pumpSSE(context.Background(), emitTo(buf, f), in, identityFrame, &streamTally{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "data: trailing") {
		t.Errorf("trailing frame lost: %q", buf.String())
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
