/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"
)

// InjectStreamOptionsIncludeUsage rewrites an OpenAI Chat Completions request
// body so that streaming responses include a final `usage` chunk. It ensures
// the body contains `stream_options.include_usage=true` when the field is
// absent, and otherwise respects whatever the client already set.
//
// The return value `injected` tells the caller whether this function added
// `include_usage=true`. Callers (the node) use that flag to decide whether
// to strip the extra usage frame from the client-facing SSE stream so that
// a client that did not request it still sees OpenAI-identical output.
//
// Rules:
//   - If the body is empty or not a JSON object, it is returned unchanged
//     with injected=false. Upstream will decide how to handle it.
//   - If `stream_options` is absent, a fresh object `{"include_usage": true}`
//     is added and injected=true.
//   - If `stream_options` is present and is a JSON object:
//   - If `include_usage` is already set (any value), the body is returned
//     unchanged with injected=false — the client's explicit choice wins.
//   - Otherwise, `include_usage: true` is added to the existing object
//     and injected=true.
//   - If `stream_options` is present but is not a JSON object, the body is
//     returned unchanged with injected=false.
//
// This helper is primarily for the /v1/chat/completions endpoint. The Responses
// API is specified to surface usage in its terminal SSE event and not to use
// `stream_options` at all, so callers must NOT inject it there by default —
// OpenAI rejects unrecognized arguments, and doing so would break conforming
// backends.
//
// It is not, however, universally true of OpenAI-compatible servers: Kronk made
// streaming usage opt-in on its Responses API in 1.30.3, so a Responses stream
// there reports no usage unless this field is set. That is handled per-runtime
// in the provider that needs it (node's llm.KronkProvider.ResponseStream), which
// is the right blast radius — keep it out of the shared serving path.
func InjectStreamOptionsIncludeUsage(body []byte) ([]byte, bool, error) {
	if len(body) == 0 {
		return body, false, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, false, nil
	}

	existing, hasStreamOptions := obj["stream_options"]
	if hasStreamOptions {
		var inner map[string]json.RawMessage
		if err := json.Unmarshal(existing, &inner); err != nil {
			return body, false, nil
		}
		if _, alreadySet := inner["include_usage"]; alreadySet {
			return body, false, nil
		}
		if inner == nil {
			inner = map[string]json.RawMessage{}
		}
		inner["include_usage"] = json.RawMessage(`true`)
		merged, err := json.Marshal(inner)
		if err != nil {
			return nil, false, fmt.Errorf("marshal stream_options: %w", err)
		}
		obj["stream_options"] = merged
	} else {
		obj["stream_options"] = json.RawMessage(`{"include_usage":true}`)
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, false, fmt.Errorf("remarshal body: %w", err)
	}
	return out, true, nil
}
