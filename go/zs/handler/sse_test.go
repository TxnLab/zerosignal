/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

// fakeFlusher is an http.Flusher that counts Flush calls.
type fakeFlusher struct {
	flushes int
}

func (f *fakeFlusher) Flush() { f.flushes++ }

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
		// Reports the full length as written (no error) so serve keeps ranging.
		t.Fatalf("post-cancel write: n=%d err=%v, want n=7 err=nil", n, err)
	}
	if sink.String() != "live" {
		t.Errorf("sink = %q, want only the pre-cancel write %q", sink.String(), "live")
	}
}

func TestWriteSSEError_GenericMessage(t *testing.T) {
	var buf bytes.Buffer
	writeSSEError(&buf, &fakeFlusher{})

	out := buf.String()
	if !strings.Contains(out, "stream interrupted") {
		t.Errorf("generic msg missing: %q", out)
	}
	if !strings.Contains(out, "[DONE]") {
		t.Error("missing [DONE] sentinel")
	}
}
