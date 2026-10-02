/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"

	"github.com/TxnLab/zerosignal/go/zs/handler/transform"
	"testing"
	"time"
)

// TestForwardRawStream_TallyNoRaceOnMidStreamDisconnect drives the exact shape
// that used to race: a client that disconnects while the upstream is still
// emitting frames.
//
// Only meaningful under `-race` (which CI and `go test -race ./zs/handler/`
// run). The first version of the disconnect diagnostic read the tally from the
// watcher goroutine, on the line BEFORE the cancelUpstream that stops the pump —
// and because clientAwareWriter swallows rather than fails writes after the
// client is gone, the pump keeps calling tally.record across exactly that window.
// The race was on time.Time fields, so a torn read produced a nonsense ttfb /
// max_inter_frame_gap / silence_before_cut: the numbers the log line exists to
// produce. silence_before_cut is the most exposed of the three — it reads
// lastAt, the field the pump touches on every single frame.
//
// Guarding the scenario rather than the fix means any future move of the read
// back into a concurrent goroutine trips the detector here.
func TestForwardRawStream_TallyNoRaceOnMidStreamDisconnect(t *testing.T) {
	// Upstream keeps streaming well past the disconnect so the pump is
	// provably still recording while the request unwinds.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fl, _ := w.(http.Flusher)
		for i := 0; i < 400; i++ {
			if _, err := fmt.Fprintf(w, "data: {\"chunk\":%d}\n\n", i); err != nil {
				return
			}
			if fl != nil {
				fl.Flush()
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Millisecond):
			}
		}
	}))
	defer upstream.Close()

	s := &Server{
		log:        slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug})),
		httpClient: &http.Client{},
	}

	clientCtx, cancelClient := context.WithCancel(context.Background())
	r := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader("{}")).WithContext(clientCtx)
	w := httptest.NewRecorder()

	// genComplete stays false, so the watcher takes the pre-generation
	// (abandoned) branch — the one that emits the tally-bearing diagnostic.
	var genComplete atomic.Bool

	// Disconnect mid-stream, once frames are certainly flowing.
	go func() {
		time.Sleep(25 * time.Millisecond)
		cancelClient()
	}()

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.forwardRawStream(
			clientCtx, w, r,
			upstream.URL, "",
			[]byte("{}"), "application/json", nil,
			nil, // direct route: no relay hop
			func(*http.Response) (frameTransform, error) {
				return func(f transform.SSEFrame) (transform.SSEFrame, error) { return f, nil }, nil
			},
			func(http.ResponseWriter, *http.Response, []byte) error { return nil },
			&genComplete,
		)
	}()

	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("forwardRawStream did not return after the client disconnected")
	}
}
