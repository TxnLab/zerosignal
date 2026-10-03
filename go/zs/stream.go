/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"errors"
	"iter"
	"strings"
	"sync/atomic"

	"github.com/TxnLab/zerosignal/go/selection"
)

// Endpoint names the OpenAI-compatible operation a Request performs.
type Endpoint string

const (
	EndpointChatCompletions Endpoint = "/v1/chat/completions"
	EndpointResponses       Endpoint = "/v1/responses"
	EndpointImages          Endpoint = "/v1/images/generations"
	EndpointImageEdits      Endpoint = "/v1/images/edits"
)

// The core compares endpoints as strings.
const (
	endpointChatCompletions = string(EndpointChatCompletions)
	endpointResponses       = string(EndpointResponses)
	endpointImages          = string(EndpointImages)
	endpointImageEdits      = string(EndpointImageEdits)
)

// Request is one turn: an OpenAI-shaped body for one endpoint, plus the
// routing preferences that don't travel in it. Routing preferences that do
// (the body's `provider` object) are read from Body and stripped before it is
// sealed.
type Request struct {
	Endpoint Endpoint
	Body     []byte
	// ContentType is Body's media type. Only an image edit, which is
	// multipart, needs it.
	ContentType string
	// RequireTEE routes this request only to attested nodes, on top of
	// Config.RequireTEEModels.
	RequireTEE bool
	// Relay is selection.RelayAuto, RelayOff or RelayRequired; "" defers to
	// Config.Privacy. A `provider.relay` in Body outranks it. RelayOff takes
	// effect only with Config.AllowPrivacyOverride.
	Relay string
	// FramesOnly skips decoding, for a caller that re-emits the node's bytes:
	// the Stream yields each Frame but no content events, an error the node
	// reports inside its response passes as a Frame, and Done's fields are
	// zero.
	FramesOnly bool
}

func (r Request) turn() turn {
	return turn{
		endpoint:    string(r.Endpoint),
		body:        r.Body,
		contentType: r.ContentType,
		requireTEE:  r.RequireTEE,
		relay:       selection.NormalizeRelay(r.Relay),
	}
}

// turn is one request as dispatch sees it.
type turn struct {
	endpoint    string
	body        []byte
	contentType string
	requireTEE  bool
	// relay is the caller's normalized relay preference; a `provider.relay`
	// in the body outranks it.
	relay string
}

// Stream is one turn in flight. It runs when Events is ranged over, so
// building one costs nothing and sends nothing.
type Stream struct {
	c       *Client
	ctx     context.Context
	req     Request
	started atomic.Bool
	err     error
}

// Stream returns req as a Stream bound to ctx. Cancelling ctx before the node
// finishes generating cancels the turn; after it, the receipt is still
// collected and the ticket settled.
func (c *Client) Stream(ctx context.Context, req Request) *Stream {
	return &Stream{c: c, ctx: ctx, req: req}
}

var errStreamReused = errors.New("zs: a Stream's events can be ranged over only once")

// Events runs the turn and yields its events in order. The last element
// carries the terminal error, if any; Err reports it too. A loop that stops
// ranging early is treated as a caller who left: before generation completes
// the node is told to stop, after it the receipt is still collected and the
// ticket settled. Events can be ranged over once.
func (s *Stream) Events() iter.Seq2[Event, error] {
	return func(yield func(Event, error) bool) {
		if !s.started.CompareAndSwap(false, true) {
			yield(nil, errStreamReused)
			return
		}
		ctx, cancel := context.WithCancel(s.ctx)
		defer cancel()
		em := &streamEmitter{yield: yield, cancel: cancel}
		if !s.req.FramesOnly {
			em.dec = newDecoder(string(s.req.Endpoint))
		}
		s.c.dispatch(ctx, em, s.req.turn())
		// A stream ends here, once the forwarder has read it all: only then is
		// there no sealed frame left to change the outcome.
		if !em.stopped {
			em.finish()
		}
		if em.err != nil {
			s.err = em.err
		}
	}
}

// Err is the terminal error of a stream whose Events loop has finished, or nil.
func (s *Stream) Err() error { return s.err }

// Text runs the turn and returns its answer text, ignoring every other event.
// On error it returns the text that arrived before it. With FramesOnly there
// is no decoded text, so it returns "".
func (s *Stream) Text() (string, error) {
	var b strings.Builder
	for ev, err := range s.Events() {
		if err != nil {
			return b.String(), err
		}
		if d, ok := ev.(TextDelta); ok {
			b.WriteString(d.Delta)
		}
	}
	return b.String(), nil
}
