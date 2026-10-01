/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"

	"github.com/TxnLab/zerosignal/go/tools"
)

// BodyDrivesServerSideToolGrowth reports whether a request body carries a tool
// that will grow the SERVING side's context within the reserve's lifetime — the
// signal a caller uses to add tool-loop headroom to input_count.
//
// It is deliberately narrower than tokenize.BodyHasTools ("are there any tools
// at all"), which over-reserves the common agent case. Two kinds of tool grow
// the context the reserve has to cover, and one kind does not:
//
//   - A node zs_ built-in: the NODE runs the chat→tool→chat loop in-process, so
//     the conversation grows across iterations inside one reserve.
//   - A vendor-hosted tool (web_search, code_interpreter, mcp, …): the UPSTREAM
//     executes it inside a single completion and re-prefills each result into
//     the context, so the input grows without the node ever seeing a new
//     request. Free-of-charge hosted tools (mcp) inflate context exactly like
//     billed ones — the per-call fee is a separate axis.
//   - A caller-executed tool ({"type":"function"}, and the hosted-shaped types
//     the harness actually runs: local_shell, apply_patch, computer_use,
//     Anthropic's bash / text_editor) grows NOTHING here. The caller runs the
//     tool and re-issues a fresh request, which is measured — and paid for — on
//     its own. This is the MCP-via-a-coding-agent case: Claude Code, Codex and
//     opencode expand their MCP servers into plain function tools client-side,
//     so a 40-tool request would otherwise reserve max_tool_iterations ×
//     tool_headroom_per_iteration for a loop that structurally cannot run.
//
// A malformed body reports false; the node's inference-time input-budget check
// backstops any surprise growth.
func BodyDrivesServerSideToolGrowth(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var peek struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return false
	}
	for _, entry := range peek.Tools {
		name, class := ClassifyToolEntry(entry)
		// A zs_ built-in classifies ToolClassClient (it is never vendor-billed),
		// so the loop signal has to come from the name, not the class.
		if tools.IsBuiltinToolType(name) {
			return true
		}
		if class != ToolClassClient && !IsClientExecutedToolName(name) {
			return true
		}
	}
	return false
}

// DropEmptyTools rewrites an OpenAI-compatible request body to remove a
// `tools` field that is an empty array, plus a now-meaningless `tool_choice`.
//
// OpenAI itself tolerates `tools: []` (it means "no tools available", same as
// omitting the field), but stricter upstreams — vLLM / SGLang and friends,
// which validate the body with pydantic — reject it outright with
// "`tools` must not be an empty array. Either provide at least one tool or
// omit the field entirely." Clients like JetBrains/Koog send `tools: []` on a
// plain chat turn (e.g. commit-message generation), so the node forwards it,
// the backend 422s, and the request fails for no good reason. Normalizing the
// empty array away — semantically a no-op, since empty tools ≡ no tools —
// makes those requests succeed against any upstream.
//
// `tool_choice` is dropped alongside it: with no tools it has nothing to act
// on, and strict backends reject a dangling tool_choice the same way.
//
// Non-JSON bodies and JSON whose top level isn't an object are returned
// unchanged (the upstream rejects them anyway). A non-array or non-empty
// `tools` is left untouched. The returned slice is a freshly-marshaled copy
// only when the body was modified.
func DropEmptyTools(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}

	raw, ok := obj["tools"]
	if !ok {
		return body, nil
	}
	var arr []json.RawMessage
	if err := json.Unmarshal(raw, &arr); err != nil || len(arr) > 0 {
		// Not an array, or a non-empty tools array — leave the body alone.
		return body, nil
	}

	delete(obj, "tools")
	delete(obj, "tool_choice") // no-op if absent; meaningless without tools

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}
