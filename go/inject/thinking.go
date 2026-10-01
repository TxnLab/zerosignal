/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"
)

// PreserveThinking opts an upstream request into cross-turn reasoning
// retention on the dialects that gate it behind a request field.
//
// z.ai is the case this exists for. GLM carries its plan in the reasoning
// channel across a tool-calling task, and its "Preserved Thinking" mode — the
// mode in which prior assistant turns' reasoning is honored — is DISABLED by
// default on the standard API endpoint. Without it the model loses its
// reasoning state after every action: observed in the wild as a model that
// completes two tool rounds fine and then, on the third, stops emitting
// structured tool calls and instead narrates the tool protocol as prose and
// fabricates the results it never received.
//
// Echoing reasoning_content back (ChatToolCallStitcher.AssistantMessage) is
// necessary but not sufficient — the upstream ignores those blocks unless
// clear_thinking is false. Both halves are required.
//
// Note the nesting: the flag lives at thinking.clear_thinking, NOT as a
// top-level clear_thinking.
//
// An explicit caller-supplied `thinking` object is preserved untouched, on the
// same principle as DefaultStoreFalse: this is a default for callers who did
// not express a preference, not an override of one that did.
//
// Every other dialect is returned unchanged — an unknown field is a 400 on a
// strict upstream, so this must never fire outside the dialect it was written
// for. Non-JSON bodies and non-object JSON are returned unchanged (an upstream
// rejects them anyway). The returned slice is a fresh copy when modified.
func PreserveThinking(body []byte, d Dialect) ([]byte, error) {
	if d != DialectZAI || len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}
	if _, ok := obj["thinking"]; ok {
		return body, nil
	}
	obj["thinking"] = json.RawMessage(`{"type":"enabled","clear_thinking":false}`)

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}
