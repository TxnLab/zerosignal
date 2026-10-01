/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// reasoningStatusCompleted is the status xAI stamps on a finished
// reasoning item, and the value it expects to see again when that item is
// replayed. A reasoning item arriving in `input[]` is by definition
// finished — the client only has it because the model already emitted it.
const reasoningStatusCompleted = `"completed"`

// NormalizeReasoningItems repairs replayed Responses-API `input[]`
// reasoning items so an upstream that binds its encrypted reasoning blob
// to the surrounding item still accepts them.
//
// The problem this exists for: with `include: ["reasoning.encrypted_content"]`
// the provider returns a reasoning item carrying an opaque
// `encrypted_content` blob, and the client replays that item verbatim on
// the next turn so the model can recall its own reasoning without the
// plaintext ever being retained. xAI refuses the whole request when the
// item it gets back is not shaped the way it emitted it:
//
//	{"code":"invalid-argument","error":"Could not decode the compaction
//	 blob. Ensure it is unmodified from the compact response."}
//
// Codex is the observed offender: xAI emits
// `{id, summary, type, status:"completed", encrypted_content}` and Codex
// replays `{type, id, summary, content:null, encrypted_content}` — it drops
// `status` and adds a null `content`. The blob itself is byte-identical, so
// only the wrapper is wrong. That reliably kills the SECOND turn of any
// tool-calling conversation (the first has no reasoning item to replay yet),
// which is what makes it look intermittent.
//
// Two surgical repairs, both idempotent:
//
//   - add `status: "completed"` when absent
//   - drop `content` when it is explicitly null (the provider distinguishes
//     "absent" from "null"; it never emits the latter)
//
// Only items that actually carry a non-empty `encrypted_content` are
// touched — a plain reasoning item has no blob to invalidate, so rewriting
// it would be churn with no upside. Everything else about the item,
// including fields this code has never heard of, is passed through
// untouched.
//
// Fail-soft by construction: a non-JSON body, a body with no `input`, an
// `input` that isn't an array, or an item that isn't an object all return
// the input unchanged. This is a compatibility fixup, not a validator —
// letting the upstream reject a malformed body is strictly better than
// this function inventing an opinion about it.
func NormalizeReasoningItems(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	rawInput, ok := obj["input"]
	if !ok {
		return body
	}
	var input []json.RawMessage
	if err := json.Unmarshal(rawInput, &input); err != nil {
		return body
	}

	changed := false
	for i, item := range input {
		repaired, ok := normalizeReasoningItem(item)
		if !ok {
			continue
		}
		input[i] = repaired
		changed = true
	}
	if !changed {
		return body
	}

	newInput, err := json.Marshal(input)
	if err != nil {
		return body
	}
	obj["input"] = newInput
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// normalizeReasoningItem repairs one `input[]` entry, reporting whether it
// rewrote anything. A false return means "leave the original bytes alone",
// which covers every not-our-business case: a non-object, a non-reasoning
// item, a reasoning item with no blob, and one that is already correct.
func normalizeReasoningItem(item json.RawMessage) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(item, &fields); err != nil {
		return nil, false
	}
	if !isJSONString(fields["type"], "reasoning") {
		return nil, false
	}
	// No blob ⇒ nothing the upstream can fail to decode.
	if blob, ok := fields["encrypted_content"]; !ok || isJSONNull(blob) || isJSONString(blob, "") {
		return nil, false
	}

	repaired := false
	if _, ok := fields["status"]; !ok {
		fields["status"] = json.RawMessage(reasoningStatusCompleted)
		repaired = true
	}
	if content, ok := fields["content"]; ok && isJSONNull(content) {
		delete(fields, "content")
		repaired = true
	}
	if !repaired {
		return nil, false
	}

	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false
	}
	return out, true
}

// reasoningDirectiveKeys are the fields OpenRouter's unified `reasoning`
// object actually reads. A caller who set any of them said something about
// reasoning — including, deliberately, disabling it — so
// StripNonDirectiveReasoning leaves that request alone.
//
// PRESENCE, not value: `{"effort":null}` keeps the object too. A client that
// serializes an unset depth as null is describing its own state, and guessing
// that the null "doesn't count" would delete a key the caller wrote. Upstream
// gets to have the opinion; this mutator does not.
//
// This is a DENY-list — it names what blocks the strip, so a key OpenRouter
// adds later that this list hasn't learned is strip-eligible. That is the
// deliberate posture: an unrecognized key does not make reasoning enabled, so
// an object carrying only unrecognized keys still reads upstream as a disable
// and still 400s a mandatory-reasoning endpoint. Keeping it would preserve the
// bug for the sake of a field neither side acts on.
var reasoningDirectiveKeys = []string{"effort", "max_tokens", "enabled", "exclude", "context", "mode"}

// StripNonDirectiveReasoning drops a request's top-level `reasoning` object when
// it carries no directive OpenRouter recognizes, because such an object reads
// to OpenRouter as an explicit "reasoning disabled" and an endpoint whose model
// mandates reasoning refuses the whole request:
//
//	{"error":{"message":"Reasoning is mandatory for this endpoint and cannot
//	 be disabled.","code":400}}
//
// The client's "Auto" reasoning depth is what produces that object: it sends
// `reasoning: {"summary":"auto"}` — a summary is wanted, and no `effort`,
// precisely so the model reasons at its own default depth. Harmless on every
// upstream that reads `effort` and ignores the rest; fatal through OpenRouter,
// where the node forwards /v1/responses bodies verbatim.
//
// Measured against openrouter.ai/api/v1/responses on google/gemini-3.7-flash:
// `{"summary":"auto"}` 400s, `{"summary":"auto","effort":"low"}` 200s, and no
// `reasoning` key at all 200s AND still streams reasoning items. That last
// result is why dropping the object is the whole fix rather than half of one —
// the summary field was never what produced those items, so Auto keeps its
// thinking display.
//
// Only DialectOpenRouter is touched. Elsewhere the object is either honored or
// harmlessly ignored, and stripping it would silently cost a client the
// reasoning summaries it asked for.
//
// Fail-soft, like the rest of this package: a non-JSON body, no `reasoning`
// key, a null or non-object `reasoning`, or one carrying any recognized
// directive all return the input unchanged. Idempotent — a second pass finds
// no object to strip.
func StripNonDirectiveReasoning(body []byte, d Dialect) ([]byte, error) {
	if d != DialectOpenRouter || len(body) == 0 {
		return body, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}
	raw, ok := obj["reasoning"]
	if !ok || isJSONNull(raw) {
		return body, nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return body, nil
	}
	for _, k := range reasoningDirectiveKeys {
		if _, ok := fields[k]; ok {
			return body, nil
		}
	}

	delete(obj, "reasoning")
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}

// isJSONNull reports whether raw is the JSON literal null.
func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// isJSONString reports whether raw is a JSON string equal to want.
func isJSONString(raw json.RawMessage, want string) bool {
	if len(raw) == 0 {
		return false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return false
	}
	return s == want
}
