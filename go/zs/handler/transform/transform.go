/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transform

import (
	"context"
	"net/http"
)

// SSEFrame is a single parsed Server-Sent Events frame.
// An empty Data with no Event/Comment means "swallow this frame".
type SSEFrame struct {
	Event   string
	Data    []byte
	ID      string
	Retry   int
	Comment string
}

// IsEmpty reports whether the frame has no content worth emitting.
func (f SSEFrame) IsEmpty() bool {
	return len(f.Data) == 0 && f.Event == "" && f.ID == "" && f.Retry == 0 && f.Comment == ""
}

// RequestTransformer mutates a request body + headers before the proxy
// sends it to the upstream. It is called exactly once per client request,
// regardless of whether the request is streaming.
type RequestTransformer interface {
	TransformRequest(
		ctx context.Context,
		endpoint string,
		body []byte,
		headers http.Header,
	) (newBody []byte, newHeaders http.Header, err error)
}

// ResponseTransformer mutates the upstream's response before it is returned
// to the client.
//
// TransformResponse is called once with the fully-buffered body for
// non-streaming responses.
//
// TransformStreamChunk is called once per parsed SSE frame from the upstream.
// Return an empty SSEFrame to drop the frame. For the sentinel
// `data: [DONE]` line, Data will be the literal bytes `[DONE]`.
type ResponseTransformer interface {
	TransformResponse(
		ctx context.Context,
		endpoint string,
		body []byte,
		headers http.Header,
	) (newBody []byte, err error)

	TransformStreamChunk(
		ctx context.Context,
		endpoint string,
		frame SSEFrame,
	) (SSEFrame, error)
}
