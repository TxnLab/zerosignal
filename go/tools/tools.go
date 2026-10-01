/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"math"
)

// BuiltinToolType is the `type` value that marks a tool entry as a hayai
// built-in tool in an OpenAI-compatible request body's tools[] array.
// Values are always prefixed `zs_` so a node can cheaply distinguish
// them from user-supplied function tools and provider-native tools.
//
// Per SPEC §3d the client's opt-in payload is the bare object
// `{"type": "<zs_*>"}` — no name/description/parameters. The node's
// rewriter (RewriteBuiltinToolsChat / RewriteBuiltinToolsResponses)
// substitutes the full BuiltinToolDef from its local registry before
// forwarding upstream, and is the single source of truth for the
// function-tool shape the LLM actually sees.
type BuiltinToolType string

// Built-in hayai tool type strings shared across packages. Search tools
// keep their type strings local to their implementation packages; the
// image tools declare theirs here because the node's tool loop
// must distinguish zs_image_generation from zs_image_edit (to pick
// the right per-tool budget counter and image-model binding) without
// importing the tool implementation packages.
const (
	ToolTypeImageGeneration BuiltinToolType = "zs_image_generation"
	ToolTypeImageEdit       BuiltinToolType = "zs_image_edit"
)

// IsBuiltinToolType reports whether a tool entry's `type` value identifies
// a ZeroSignal built-in tool. A value is a built-in type iff it starts with
// the literal prefix `zs_`. Callers use this as the cheap pre-filter before
// consulting a registry, and it is the rule by which the request-side
// rewriter (SPEC §3d) decides whether to substitute an entry.
func IsBuiltinToolType(t string) bool {
	const prefix = "zs_"
	if len(t) < len(prefix) {
		return false
	}
	return t[:len(prefix)] == prefix
}

// BuiltinToolDef describes one hayai built-in tool the node offers. It is
// the node's node-internal, authoritative descriptor — the source of
// `Name`, `Description`, and `Parameters` for the wire-level function tool
// the upstream LLM sees. Clients MUST NOT echo those fields back on the
// request body's `tools[]` opt-in entry (which is bare `{type}`); see SPEC
// §3d ("Authority") for the rationale and the rewrite rules.
//
// Note this is NOT the /v1/zs/details advertisement shape — that is the
// type-only BuiltinToolAdvert below. Name/Description/Parameters are
// deliberately not advertised: they are identical across every node on the
// same proto version, so any human-readable surface resolves them locally
// by type, and keeping the discovery payload to bare types matters because
// it is polled (SPEC §3c, §3d "Discovery").
//
// Name is the function name the LLM will call back with when it decides
// to invoke the tool. In practice Name == string(Type) — the rewriter
// sets the function name to the hayai type string so the response
// interceptor can match tool_calls[i].function.name against the hayai
// type set without extra bookkeeping.
type BuiltinToolDef struct {
	Type        BuiltinToolType `json:"type"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// BuiltinToolAdvert is the type-only wire shape advertised under
// `builtin_tools[]` on GET /v1/zs/details. Only `type` — the client
// opt-in surface (SPEC §3d) — is published; the node's local
// BuiltinToolDef stays authoritative for name/description/parameters and
// those are intentionally NOT advertised (see BuiltinToolDef's note). The
// entry stays a single-key object rather than a bare string so consumers
// reading `.type` keep working and the discovery shape only narrows.
type BuiltinToolAdvert struct {
	Type BuiltinToolType `json:"type"`
}

// Advert projects a full node-internal definition down to its type-only
// advertised form for /v1/zs/details.
func (d BuiltinToolDef) Advert() BuiltinToolAdvert {
	return BuiltinToolAdvert{Type: d.Type}
}

// ToolCall is a single tool invocation extracted from a model response.
// Chat Completions and Responses share this shape because the information
// the node needs to act is identical: an ID to correlate the result, a
// function name to dispatch on, and a JSON-encoded argument string.
//
// ID is choice[].message.tool_calls[i].id on Chat Completions and
// function_call.call_id on Responses — both opaque tokens the API expects
// echoed back in the tool-result message.
type ToolCall struct {
	ID        string
	Name      string
	Arguments string
	// Extra carries provider-specific opaque per-tool-call data that the
	// upstream requires echoed back on the assistant turn during the
	// tool-call loop. It is the verbatim JSON value of the streamed
	// tool_call's `extra_content` object (Chat Completions) — most notably
	// Gemini 3's mandatory `extra_content.google.thought_signature`, which
	// the model rejects (400) on the next iteration if it is not replayed.
	// We carry the whole object rather than modelling thought_signature
	// specifically so other providers' opaque per-call data round-trips too.
	// omitempty so providers that attach nothing produce byte-identical
	// replays and existing tool-loop tests stay green.
	Extra json.RawMessage `json:"extra_content,omitempty"`
}

// ToolResult carries one executed tool's output back to the loop so it
// can be appended to the next iteration's request. Content is the string
// the model will see as the tool message's content (chat) or
// function_call_output.output (responses) — most tools marshal a JSON
// object to give the model structured fields to cite.
type ToolResult struct {
	ToolCallID string
	Content    string
}

// ImageAttachment is one image a built-in image tool produced
// (zs_image_generation / zs_image_edit). B64 is the raw
// base64 image (no data-URL prefix); MIME is the content type (e.g.
// "image/png", defaulted by the append helper when empty). The Responses
// tool loop turns each attachment into an `input_image` content part on
// the next iteration so the model can reference the image it just
// produced (AppendImageToolOutputsResponses). The base64 is response
// content — never log it.
type ImageAttachment struct {
	B64  string
	MIME string
}

// FrameClassification is the return type of the streaming stitchers'
// Observe method. The streaming tool loop uses it to decide, frame by
// frame, whether to stay buffered (still deciding) or flip live (this
// iteration is the final answer).
type FrameClassification int

const (
	// FrameUnknown means the frame was metadata, an empty delta, or an
	// event that doesn't disambiguate between "tool round" and "final
	// answer" yet. The loop should keep buffering.
	FrameUnknown FrameClassification = iota

	// FrameContent means the frame carried assistant-visible content
	// (a text delta). OpenAI never mixes content and tool_call deltas
	// inside the same iteration, so observing one commits this
	// iteration to being the final answer — flush buffered frames and
	// go live.
	FrameContent

	// FrameToolCallBuiltin means the frame carried a tool-call fragment
	// whose function name maps to a ZeroSignal built-in tool. The streaming
	// tool loop SUPPRESSES these frames from the client wire and
	// executes them server-side; the client never observes them.
	FrameToolCallBuiltin

	// FrameToolCallClient means the frame carried a tool-call fragment
	// for a client-defined function tool (not a hayai built-in). The
	// streaming tool loop FORWARDS these frames to the client so the
	// standard OpenAI client-executes-tool pattern still works for
	// mixed requests (client tools alongside hayai built-ins).
	FrameToolCallClient

	// FrameTerminal means the frame was the stream's end-of-iteration
	// marker (chat: `[DONE]` or `finish_reason` on an empty-choices
	// chunk; responses: `response.completed` / `response.error` /
	// `response.failed`). The loop decides what to do with buffered
	// frames based on whether any tool calls were stitched.
	FrameTerminal

	// FrameStatus means the frame is a node-originated hayai tool-round
	// status event (response.zs_tool_call.in_progress / .completed).
	// Status frames are emitted by the node's tool loop itself during
	// server-side tool execution; if the upstream provider ever echoes
	// one we drop it defensively.
	FrameStatus
)

// ChatUsage mirrors the `usage` object OpenAI emits on the terminal
// streaming chunk of a /v1/chat/completions response when
// stream_options.include_usage=true, and on the non-streaming response
// body. Both the cached-read and the reasoning breakdowns are decoded:
// cached pricing reads the first downstream, and the second is
// load-bearing for the OUTPUT leg because providers disagree about
// whether completion_tokens already contains it — see
// GeneratedOutputTokens.
type ChatUsage struct {
	PromptTokens     uint64 `json:"prompt_tokens"`
	CompletionTokens uint64 `json:"completion_tokens"`
	TotalTokens      uint64 `json:"total_tokens"`
	// Cache-read breakdown. OpenAI/vLLM/SGLang/z.ai/Gemini report it under
	// prompt_tokens_details.cached_tokens; DeepSeek reports it at the top
	// level (prompt_cache_hit_tokens). CachedTokens() normalizes the two.
	PromptTokensDetails  *PromptTokensDetails `json:"prompt_tokens_details,omitempty"`
	PromptCacheHitTokens uint64               `json:"prompt_cache_hit_tokens,omitempty"`
	// Reasoning breakdown. Read only by GeneratedOutputTokens, and only to
	// decide whether CompletionTokens already includes it.
	CompletionTokensDetails *CompletionTokensDetails `json:"completion_tokens_details,omitempty"`
}

// PromptTokensDetails is the cached-read sub-object on a chat usage block.
type PromptTokensDetails struct {
	CachedTokens uint64 `json:"cached_tokens"`
}

// CompletionTokensDetails is the generated-output breakdown on a chat usage
// block. Only the reasoning count is decoded; the audio and
// accepted/rejected-prediction siblings are not billed separately.
type CompletionTokensDetails struct {
	ReasoningTokens uint64 `json:"reasoning_tokens"`
}

// CachedTokens returns the normalized cache-read count across provider
// shapes (prompt_tokens_details.cached_tokens vs. DeepSeek's top-level
// prompt_cache_hit_tokens). 0 when neither is present.
func (u ChatUsage) CachedTokens() uint64 {
	if u.PromptTokensDetails != nil {
		return u.PromptTokensDetails.CachedTokens
	}
	return u.PromptCacheHitTokens
}

// ReasoningTokens returns the reported reasoning-token count (0 when absent).
func (u ChatUsage) ReasoningTokens() uint64 {
	if u.CompletionTokensDetails != nil {
		return u.CompletionTokensDetails.ReasoningTokens
	}
	return 0
}

// GeneratedOutputTokens is the billable output count: every token the model
// generated, reasoning included. Use it instead of CompletionTokens anywhere
// a charge, a receipt, or an output metric is derived.
func (u ChatUsage) GeneratedOutputTokens() uint64 {
	return GeneratedOutputTokens(u.PromptTokens, u.CompletionTokens, u.ReasoningTokens(), u.TotalTokens)
}

// ResponsesUsage mirrors the `usage` object on /v1/responses bodies and
// on the terminal `response.completed` SSE event. The Responses API
// renames prompt/completion to input/output but the intent is the same;
// the loop converts between the two shapes where needed.
type ResponsesUsage struct {
	InputTokens  uint64 `json:"input_tokens"`
	OutputTokens uint64 `json:"output_tokens"`
	TotalTokens  uint64 `json:"total_tokens"`
	// Cache-read breakdown (input_tokens_details.cached_tokens). Decoded so
	// the tool loop carries it like the chat shape.
	InputTokensDetails *InputTokensDetails `json:"input_tokens_details,omitempty"`
	// Reasoning breakdown, the Responses spelling of the chat shape's
	// completion_tokens_details. See GeneratedOutputTokens.
	OutputTokensDetails *OutputTokensDetails `json:"output_tokens_details,omitempty"`
}

// InputTokensDetails is the cached-read sub-object on a responses usage block.
type InputTokensDetails struct {
	CachedTokens uint64 `json:"cached_tokens"`
}

// OutputTokensDetails is the generated-output breakdown on a responses usage
// block — the Responses spelling of CompletionTokensDetails.
type OutputTokensDetails struct {
	ReasoningTokens uint64 `json:"reasoning_tokens"`
}

// CachedTokens returns the cache-read count (0 when absent).
func (u ResponsesUsage) CachedTokens() uint64 {
	if u.InputTokensDetails != nil {
		return u.InputTokensDetails.CachedTokens
	}
	return 0
}

// ReasoningTokens returns the reported reasoning-token count (0 when absent).
func (u ResponsesUsage) ReasoningTokens() uint64 {
	if u.OutputTokensDetails != nil {
		return u.OutputTokensDetails.ReasoningTokens
	}
	return 0
}

// GeneratedOutputTokens is the billable output count — see the ChatUsage
// method of the same name. Prefer it over the OutputTokens field.
func (u ResponsesUsage) GeneratedOutputTokens() uint64 {
	return GeneratedOutputTokens(u.InputTokens, u.OutputTokens, u.ReasoningTokens(), u.TotalTokens)
}

// GeneratedOutputTokens returns the number of tokens the model actually
// generated, which is what the operator spent GPU time on and therefore what
// the output leg of a receipt must bill.
//
// It exists because OpenAI-compatible providers disagree about the meaning of
// completion_tokens on a reasoning model:
//
//   - OpenAI (and vLLM, SGLang, DeepSeek) INCLUDE reasoning in
//     completion_tokens, so total == prompt + completion.
//   - xAI/grok's chat-completions surface EXCLUDES it, reporting visible
//     output only, so total == prompt + completion + reasoning. Billing
//     completion verbatim there charges for a fraction of the work: an
//     observed grok-4.5 turn reported completion_tokens=7 alongside
//     reasoning_tokens=153.
//
// Provider identity can't drive the choice, for two independent reasons. A
// reasoning model reached through the openai_passthrough backend names no
// dialect; and more fundamentally, a vendor does not necessarily agree with
// ITSELF across surfaces — the same xAI account whose chat surface excludes
// reasoning serves a /v1/responses surface that includes it (an observed turn:
// input 12205 + output 529 == total 12734, with reasoning_tokens=27 already
// inside output_tokens). A per-provider allow-list would therefore be wrong on
// one of the two surfaces no matter which way it was set. So the decision is
// made from the provider's own arithmetic instead, per response. Reasoning is added only when the
// reported total corroborates that completion excludes it; absent or
// inconsistent totals leave completion untouched, so an unfamiliar or sloppy
// upstream under-bills rather than over-bills. Only the reasoning count is
// ever added, never the raw total-minus-prompt gap, so a bogus total can't
// inflate a charge.
//
// The rule is idempotent: re-applying it to an already-credited count fails
// the corroboration test and returns the input unchanged.
func GeneratedOutputTokens(prompt, completion, reasoning, total uint64) uint64 {
	if reasoning == 0 || total < prompt {
		return completion
	}
	// Guard the addition before comparing — a saturating sum would make the
	// corroboration test meaningless on absurd inputs.
	if completion > math.MaxUint64-reasoning {
		return completion
	}
	if total-prompt >= completion+reasoning {
		return completion + reasoning
	}
	return completion
}
