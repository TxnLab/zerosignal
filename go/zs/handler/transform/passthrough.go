/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transform

import (
	"context"
	"net/http"
)

// Passthrough is the default no-op transformer pair. It returns inputs
// verbatim so the proxy behaves as a straight reverse proxy until a real
// encrypt/decrypt implementation replaces it.
type Passthrough struct{}

func (Passthrough) TransformRequest(
	_ context.Context,
	_ string,
	body []byte,
	headers http.Header,
) ([]byte, http.Header, error) {
	return body, headers, nil
}

func (Passthrough) TransformResponse(
	_ context.Context,
	_ string,
	body []byte,
	_ http.Header,
) ([]byte, error) {
	return body, nil
}

func (Passthrough) TransformStreamChunk(
	_ context.Context,
	_ string,
	frame SSEFrame,
) (SSEFrame, error) {
	return frame, nil
}
