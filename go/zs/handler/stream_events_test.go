/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TxnLab/zerosignal/go/zs"
)

// The proxy passes the node's own response through, error included: an error
// the node reports inside its response is the node's bytes on the wire, not
// an error the proxy writes in their place. This is what Request.FramesOnly
// buys the handler.
func TestDispatch_NodeErrorInsideResponsePassesThrough(t *testing.T) {
	const nodeErr = `{"error":{"message":"rate limited","code":"rate_limit_exceeded"}}`
	t.Run("stream", func(t *testing.T) {
		node := newFakeNode(t, &nodeConfig{mode: modeStreamEncrypted, streamFrames: [][]byte{
			[]byte(`{"choices":[{"index":0,"delta":{"content":"Hi"}}]}`),
			[]byte(nodeErr),
		}})
		cfg := testConfig()
		s := testServer(cfg, setup(t, cfg, node))
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test","stream":true}`))

		body := w.Body.String()
		want := "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hi\"}}]}\n\ndata: " + nodeErr + "\n\ndata: [DONE]\n\n"
		if w.Code != http.StatusOK || body != want {
			t.Errorf("status %d body\n%q\nwant\n%q", w.Code, body, want)
		}
	})
	t.Run("single body", func(t *testing.T) {
		node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(nodeErr)})
		cfg := testConfig()
		s := testServer(cfg, setup(t, cfg, node))
		w := httptest.NewRecorder()
		s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/chat/completions", `{"model":"gpt-test"}`))

		if w.Code != http.StatusOK || w.Body.String() != nodeErr {
			t.Errorf("status %d body %q, want the node's 200 %q", w.Code, w.Body.String(), nodeErr)
		}
	})
}

// A paid turn against a node, read through the SDK rather than the HTTP
// adapter, yields content events decoded from the node's sealed frames, each
// after the Frame that carried it, and ends in a Done that saw the answer.
func TestClientStream_DecodesSealedFrames(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *nodeConfig
		body string
	}{
		{"stream", &nodeConfig{mode: modeStreamEncrypted, streamFrames: [][]byte{
			[]byte(`{"choices":[{"index":0,"delta":{"content":"Hel"}}]}`),
			[]byte(`{"choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}]}`),
		}}, `{"model":"gpt-test","stream":true}`},
		{"single body", &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(
			`{"choices":[{"index":0,"message":{"content":"Hello"},"finish_reason":"stop"}]}`,
		)}, `{"model":"gpt-test"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := newFakeNode(t, tc.cfg)
			cfg := testConfig()
			s := testServer(cfg, setup(t, cfg, node))
			req := zs.Request{Endpoint: zs.EndpointChatCompletions, Body: []byte(tc.body)}

			var text string
			var lastFrame, sawText bool
			var done *zs.Done
			for ev, err := range s.Client.Stream(context.Background(), req).Events() {
				if err != nil {
					t.Fatalf("turn failed: %v", err)
				}
				switch e := ev.(type) {
				case zs.Frame:
					lastFrame = e.Sealed
				case zs.TextDelta:
					if !lastFrame && !sawText {
						t.Error("a text delta arrived before the sealed Frame that carried it")
					}
					sawText = true
					text += e.Delta
				case zs.Done:
					done = &e
				}
			}
			if text != "Hello" {
				t.Errorf("text = %q, want Hello", text)
			}
			if done == nil || done.Empty || done.FinishReason != "stop" {
				t.Errorf("done = %+v, want a non-empty stop", done)
			}

			got, err := s.Client.Stream(context.Background(), req).Text()
			if err != nil || got != "Hello" {
				t.Errorf("Text() = %q, %v; want Hello", got, err)
			}
		})
	}
}

// A turn that breaks still hands back the text that arrived before it.
func TestClientStream_TextKeepsWhatArrivedBeforeAnError(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeStreamEncrypted, streamFrames: [][]byte{
		[]byte(`{"choices":[{"index":0,"delta":{"content":"Hel"}}]}`),
	}})
	cfg := testConfig()
	s := testServer(cfg, setup(t, cfg, node))
	req := zs.Request{Endpoint: zs.EndpointChatCompletions, Body: []byte(`{"model":"gpt-test","stream":true}`)}

	got, err := s.Client.Stream(context.Background(), req).Text()
	ze, ok := errors.AsType[*zs.Error](err)
	if got != "Hel" || !ok || ze.Code != "stream_interrupted" {
		t.Errorf("Text() = %q, %v; want Hel and stream_interrupted", got, err)
	}
}
