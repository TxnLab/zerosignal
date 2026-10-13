/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"

	"github.com/TxnLab/zerosignal/go/zs/tokenize"
)

// privacyMode maps the relay-on bool the routing tests are written in.
func privacyMode(relay bool) Privacy {
	if relay {
		return PrivacyRelayRequired
	}
	return PrivacyDirect
}

// testTokenizer registers "gpt-test" with fixed numbers so reserve sizing is
// stable; every other model takes the default estimator.
func testTokenizer() *tokenize.Registry {
	reg := tokenize.NewRegistry()
	reg.Register("gpt-test", fakeEstimate{input: 8, maxOut: 128})
	reg.SetDefaultMaxOutput("gpt-test", 128)
	return reg
}

type fakeEstimate struct {
	input  uint64
	maxOut uint64
}

func (f fakeEstimate) Estimate(_ tokenize.Request) (tokenize.Estimate, error) {
	return tokenize.Estimate{InputTokens: f.input, MaxOutputTokens: f.maxOut}, nil
}

// healingRegistry wraps a StaticRegistryProvider but models a successful live
// re-probe: ReprobeEphemeral returns heal(op) instead of the static no-op.
// calls counts the re-probes.
type healingRegistry struct {
	*StaticRegistryProvider
	heal  func(Operator) (Operator, bool)
	calls int
}

func (h *healingRegistry) ReprobeEphemeral(_ context.Context, op Operator) (Operator, bool) {
	h.calls++
	return h.heal(op)
}

// recEmitter records what a forwarder emits. It never fails a write, like the
// Stream's own emitter.
type recEmitter struct {
	mu      sync.Mutex
	notes   []Event
	frames  []Frame
	usages  []*usageReport
	failed  *Error
	replied *NodeReply
	opened  int
	broken  bool
	cause   error
}

func (e *recEmitter) note(ev Event) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.notes = append(e.notes, ev)
}
func (e *recEmitter) clamped(uint64)                     {}
func (e *recEmitter) reserved(*ReservedTicket, Operator) {}
func (e *recEmitter) committed(string, string, uint64)   {}
func (e *recEmitter) fail(err *Error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.failed = err
}
func (e *recEmitter) reply(status int, header http.Header, body []byte, usage *usageReport) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.replied = &NodeReply{Status: status, Header: header, Body: body}
	if usage != nil {
		e.usages = append(e.usages, usage)
	}
}
func (e *recEmitter) open(status int, _ http.Header) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.opened = status
	return nil
}
func (e *recEmitter) frame(out outFrame) (int, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if out.usage != nil {
		e.usages = append(e.usages, out.usage)
		return 0, nil
	}
	e.frames = append(e.frames, out.frame)
	return len(out.frame.SSE()), nil
}
func (e *recEmitter) interrupt(cause error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.broken = true
	e.cause = cause
}

// passFrames is a frameTransformFactory that forwards each frame unchanged.
func passFrames(*http.Response) (frameTransform, error) {
	return func(f Frame) (outFrame, error) { return outFrame{frame: f}, nil }, nil
}

// runTurn runs one chat-completions turn to its end and returns its events
// and terminal error.
func runTurn(t *testing.T, c *Client, body string) ([]Event, error) {
	t.Helper()
	return runRequest(t, c, Request{Endpoint: EndpointChatCompletions, Body: []byte(body)})
}

func runRequest(t *testing.T, c *Client, req Request) ([]Event, error) {
	t.Helper()
	st := c.Stream(context.Background(), req)
	var evs []Event
	for ev, err := range st.Events() {
		if err != nil {
			return evs, err
		}
		evs = append(evs, ev)
	}
	return evs, nil
}

// turnErr runs one turn and returns the *Error it failed with, failing the
// test if it succeeded or failed with anything else.
func turnErr(t *testing.T, c *Client, body string) *Error {
	t.Helper()
	return requestErr(t, c, Request{Endpoint: EndpointChatCompletions, Body: []byte(body)})
}

func requestErr(t *testing.T, c *Client, req Request) *Error {
	t.Helper()
	_, err := runRequest(t, c, req)
	ze, ok := errors.AsType[*Error](err)
	if !ok {
		t.Fatalf("turn error = %v (%T), want *Error", err, err)
	}
	return ze
}
