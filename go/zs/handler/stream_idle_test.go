/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/zs"
)

// The stream idle bound end to end: from Config.StreamIdle, through the
// sealed frame factory, to the error a Stream's caller reads.

// streamTurn runs one streamed chat turn against a node that pauses before
// frame pauseAt, and returns how many frames reached the caller and the
// stream's error.
func streamTurn(t *testing.T, idle zs.StreamIdle, frames [][]byte, pauseAt int, pause time.Duration) (int, error) {
	t.Helper()
	node := newFakeNode(t, &nodeConfig{
		mode:         modeStreamEncrypted,
		streamFrames: frames,
		beforeFrame: func(i int) {
			if i == pauseAt {
				time.Sleep(pause)
			}
		},
	})
	cfg := testConfig()
	d := setup(t, cfg, node)
	d.StreamIdle = idle
	s := testServer(cfg, d)
	stream := s.Stream(context.Background(), zs.Request{
		Endpoint:   "/v1/chat/completions",
		Body:       []byte(`{"model":"gpt-test","stream":true}`),
		FramesOnly: true,
	})
	n := 0
	for ev := range stream.Events() {
		if _, ok := ev.(zs.Frame); ok {
			n++
		}
	}
	return n, stream.Err()
}

var twoDeltas = [][]byte{[]byte(`{"delta":"A"}`), []byte(`{"delta":"B"}`)}

func TestStreamIdle_ConfigCutsASilentNode(t *testing.T) {
	n, err := streamTurn(t, zs.StreamIdle{MidStream: 50 * time.Millisecond}, twoDeltas, 1, 500*time.Millisecond)
	var zerr *zs.Error
	var idleErr *zs.StreamIdleTimeoutError
	if !errors.As(err, &zerr) || zerr.Code != "stream_interrupted" {
		t.Fatalf("err = %v, want stream_interrupted", err)
	}
	if !errors.As(err, &idleErr) || idleErr.Phase != zs.IdleMidStream || idleErr.Timeout != 50*time.Millisecond {
		t.Errorf("cause = %v, want the configured mid-stream bound", errors.Unwrap(err))
	}
	if n != 1 {
		t.Errorf("caller got %d frames, want the one before the silence", n)
	}
}

func TestStreamIdle_OffWaitsOutTheSilence(t *testing.T) {
	n, err := streamTurn(t, zs.StreamIdle{Off: true, MidStream: 50 * time.Millisecond}, twoDeltas, 1, 300*time.Millisecond)
	if err != nil || n != 3 { // the two, then [DONE]
		t.Errorf("frames=%d err=%v, want the whole stream", n, err)
	}
}

// An image tool round is silent while the tool runs; the frames that open
// and close it, sealed, are read by the real frame factory.
func TestStreamIdle_WaitsOutAnImageRoundOnTheToolBudget(t *testing.T) {
	frames := [][]byte{
		[]byte(`{"type":"response.zs_tool_call.in_progress","item_id":"a","tool":"zs_image_generation"}`),
		[]byte(`{"type":"response.zs_tool_call.completed","item_id":"a","tool":"zs_image_generation"}`),
	}
	budgets := zs.StreamIdle{MidStream: 50 * time.Millisecond, ToolActive: 5 * time.Second}
	n, err := streamTurn(t, budgets, frames, 1, 300*time.Millisecond)
	if err != nil || n != 3 { // the two, then [DONE]
		t.Errorf("frames=%d err=%v, want the round waited out", n, err)
	}
}
