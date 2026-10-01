/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// ErrUnknownBuiltinTool is returned by the rewriters when a request body
// references a `zs_*` tool type that the node's registry does not
// enable. Handlers surface this as a 400 so the client can see the
// offending type name in the reason string.
var ErrUnknownBuiltinTool = errors.New("unknown hayai builtin tool type")

// RewriteBuiltinToolsChat walks body.tools[] and replaces every
// {"type":"zs_*", "zs_*":{...}} entry with a Chat-Completions-flavor
// function tool {"type":"function","function":{"name":..., "description":...,
// "parameters":...}}.
//
// This is the node-side enforcement point of the SPEC §3d contract for
// the Chat Completions endpoint: the client's opt-in payload is the bare
// {"type":"zs_*"}, and this rewriter is the single place name /
// description / parameters are populated from the node's authoritative
// registry (defs). Each matching entry is replaced wholesale, so any
// extra fields the client may have set are implicitly dropped.
//
// Non-hayai entries (`{"type":"function"}`, etc.) pass through byte-
// identical via json.RawMessage. When body does not contain a tools[]
// array (or contains no zs_* entries), the original body is returned
// unchanged and builtinNames is an empty map — this is the zero-regression
// guarantee for non-tool requests.
//
// builtinNames maps the rewritten function name to the originating hayai
// type, so the response interceptor can filter tool_calls efficiently.
func RewriteBuiltinToolsChat(body []byte, defs map[BuiltinToolType]BuiltinToolDef) (rewritten []byte, builtinNames map[string]BuiltinToolType, err error) {
	return rewriteBuiltinTools(body, defs, marshalChatFunctionTool)
}

func marshalChatFunctionTool(def BuiltinToolDef) (json.RawMessage, error) {
	inner := map[string]json.RawMessage{}
	nameJSON, err := json.Marshal(def.Name)
	if err != nil {
		return nil, err
	}
	inner["name"] = nameJSON
	if def.Description != "" {
		descJSON, err := json.Marshal(def.Description)
		if err != nil {
			return nil, err
		}
		inner["description"] = descJSON
	}
	if len(def.Parameters) > 0 {
		inner["parameters"] = def.Parameters
	}
	innerJSON, err := json.Marshal(inner)
	if err != nil {
		return nil, err
	}
	outer := map[string]json.RawMessage{
		"type":     json.RawMessage(`"function"`),
		"function": innerJSON,
	}
	return json.Marshal(outer)
}

// ExtractToolCallsChat parses a non-streaming /v1/chat/completions response
// and returns the first choice's assistant message (byte-exact for
// re-append), its tool_calls array, and finish_reason. A response with no
// tool_calls returns an empty slice — callers decide whether that means
// the loop terminates.
//
// Only the first choice is inspected: OpenAI-compatible APIs return at
// most one choice when `n` is unset (the default), and the tool loop
// semantics only makes sense for a single choice anyway.
func ExtractToolCallsChat(resp []byte) (assistantMsg json.RawMessage, calls []ToolCall, finishReason string, err error) {
	var top struct {
		Choices []struct {
			Index        int             `json:"index"`
			Message      json.RawMessage `json:"message"`
			FinishReason string          `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(resp, &top); err != nil {
		return nil, nil, "", fmt.Errorf("parse chat response: %w", err)
	}
	if len(top.Choices) == 0 {
		return nil, nil, "", nil
	}
	c := top.Choices[0]
	var msg struct {
		ToolCalls []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if len(c.Message) > 0 {
		if err := json.Unmarshal(c.Message, &msg); err != nil {
			return nil, nil, "", fmt.Errorf("parse assistant message: %w", err)
		}
	}
	for _, tc := range msg.ToolCalls {
		// Extra (extra_content) is intentionally omitted here: the
		// non-streaming path re-appends c.Message verbatim (see
		// AppendToolMessagesChat), so any opaque per-call state is already
		// preserved byte-exact. These ToolCalls are used only for dispatch.
		calls = append(calls, ToolCall{
			ID:        tc.ID,
			Name:      tc.Function.Name,
			Arguments: tc.Function.Arguments,
		})
	}
	return c.Message, calls, c.FinishReason, nil
}

// SanitizeIncompleteBuiltinCallsChat removes built-in function calls that
// cannot be dispatched as written from a non-streaming Chat response. See
// CompleteToolArguments for the two defects and why `truncated` only governs
// one of them.
//
// Only calls whose names are present in builtinNames are considered. Client-
// defined calls and complete built-in calls are preserved byte-for-byte inside
// message.tool_calls. Callers should re-run ExtractToolCallsChat on the
// returned body before dispatch and replay so a dropped call cannot leave an
// orphaned tool result in the next request.
func SanitizeIncompleteBuiltinCallsChat(resp []byte, builtinNames map[string]BuiltinToolType, truncated bool) (rewritten []byte, dropped int, err error) {
	if len(resp) == 0 || len(builtinNames) == 0 {
		return resp, 0, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &obj); err != nil {
		return nil, 0, fmt.Errorf("parse chat response: %w", err)
	}
	var choices []map[string]json.RawMessage
	rawChoices, ok := obj["choices"]
	if !ok {
		return resp, 0, nil
	}
	if err := json.Unmarshal(rawChoices, &choices); err != nil {
		return nil, 0, fmt.Errorf("parse chat choices: %w", err)
	}
	changed := false
	for _, choice := range choices {
		rawMessage, ok := choice["message"]
		if !ok {
			continue
		}
		var message map[string]json.RawMessage
		if err := json.Unmarshal(rawMessage, &message); err != nil {
			return nil, 0, fmt.Errorf("parse assistant message: %w", err)
		}
		rawCalls, ok := message["tool_calls"]
		if !ok {
			continue
		}
		var calls []json.RawMessage
		if err := json.Unmarshal(rawCalls, &calls); err != nil {
			return nil, 0, fmt.Errorf("parse assistant tool_calls: %w", err)
		}
		kept := make([]json.RawMessage, 0, len(calls))
		for _, rawCall := range calls {
			var shaped struct {
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			}
			if json.Unmarshal(rawCall, &shaped) == nil {
				if _, builtin := builtinNames[shaped.Function.Name]; builtin && !CompleteToolArguments(shaped.Function.Arguments, truncated) {
					dropped++
					changed = true
					continue
				}
			}
			kept = append(kept, rawCall)
		}
		if len(kept) == len(calls) {
			continue
		}
		if len(kept) == 0 {
			// Drop the key rather than shipping `"tool_calls": []`. OpenAI omits
			// it when there are no calls, and an assistant message carrying
			// content:null beside an empty array is a shape clients are not
			// obliged to understand.
			delete(message, "tool_calls")
		} else {
			encodedCalls, err := json.Marshal(kept)
			if err != nil {
				return nil, 0, fmt.Errorf("remarshal assistant tool_calls: %w", err)
			}
			message["tool_calls"] = encodedCalls
		}
		encodedMessage, err := json.Marshal(message)
		if err != nil {
			return nil, 0, fmt.Errorf("remarshal assistant message: %w", err)
		}
		choice["message"] = encodedMessage
	}
	if !changed {
		return resp, 0, nil
	}
	encodedChoices, err := json.Marshal(choices)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal chat choices: %w", err)
	}
	obj["choices"] = encodedChoices
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal chat response: %w", err)
	}
	return out, dropped, nil
}

// completeToolArguments reports whether a built-in call's accumulated
// arguments can be dispatched. Two different defects, two different rules:
//
//   - UNPARSEABLE arguments are never dispatchable, so they fail here whatever
//     `truncated` says. The response body or stream has terminated, so no
//     completing fragment can still arrive.
//   - EMPTY arguments fail only on a TRUNCATED round, where they mean an
//     announce delta (id + name, arguments:"") whose completion never came.
//     On any other stop "" is a zero-argument call the model FINISHED asking
//     for, from a backend that writes "" where OpenAI writes {}. Those must
//     dispatch: the tool's own validation is the model's feedback channel
//     (zs_get_time.Execute is written for exactly this invocation), and
//     dropping instead strands the caller with a finish_reason "tool_calls"
//     and no calls in it.
func CompleteToolArguments(arguments string, truncated bool) bool {
	trimmed := strings.TrimSpace(arguments)
	if trimmed == "" {
		return !truncated
	}
	return json.Valid([]byte(trimmed))
}

// AppendToolMessagesChat takes a /v1/chat/completions request body,
// appends the assistant tool-call message (verbatim), and then one
// {"role":"tool","tool_call_id":X,"content":Y} message per result.
// Returns the rewritten body ready for the next upstream call.
func AppendToolMessagesChat(body, assistantMsg json.RawMessage, results []ToolResult) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("parse body: %w", err)
	}
	var messages []json.RawMessage
	if raw, ok := obj["messages"]; ok {
		if err := json.Unmarshal(raw, &messages); err != nil {
			return nil, fmt.Errorf("parse messages: %w", err)
		}
	}
	if len(assistantMsg) > 0 {
		messages = append(messages, assistantMsg)
	}
	for _, r := range results {
		toolMsg := map[string]json.RawMessage{}
		toolMsg["role"] = json.RawMessage(`"tool"`)
		idJSON, err := json.Marshal(r.ToolCallID)
		if err != nil {
			return nil, err
		}
		toolMsg["tool_call_id"] = idJSON
		contentJSON, err := json.Marshal(r.Content)
		if err != nil {
			return nil, err
		}
		toolMsg["content"] = contentJSON
		encoded, err := json.Marshal(toolMsg)
		if err != nil {
			return nil, err
		}
		messages = append(messages, encoded)
	}
	newMessages, err := json.Marshal(messages)
	if err != nil {
		return nil, fmt.Errorf("remarshal messages: %w", err)
	}
	obj["messages"] = newMessages
	return json.Marshal(obj)
}

// ClampChatInputImages caps the number of image_url content parts a
// /v1/chat/completions request body's messages[] carries to at most max,
// removing the OLDEST images first so the most recent one — the latest user
// upload — is always retained. It is the Chat sibling of
// ClampResponsesInputImages (tools_responses.go).
//
// Vision upstreams cap images per prompt (vLLM's limit_mm_per_prompt — "At most
// N image(s) may be provided in one prompt."), so a request can 400 when it
// carries more images than the cap. Unlike the Responses tool loop, the Chat
// path never feeds tool-produced images back — the accumulation here is purely
// the caller's own image_url parts (a single request with many uploads, or a
// multi-turn client that replays prior-turn images).
//
// max <= 0 means "no cap": body is returned byte-for-byte unchanged. The body
// is likewise returned unchanged when it already fits, when messages[] is
// absent, or when a message's content is a bare string (which carries no
// image). dropped reports how many image_url parts were actually removed.
//
// Only images in role:"user" messages are shed (and only a user message may be
// removed when its content becomes empty). Images in tool / assistant messages
// are structurally load-bearing — a tool message is bound to a preceding
// assistant tool_call by id, and removing it would orphan that call and draw a
// *different* 400 from strict upstreams — so they are counted toward the cap but
// never touched. When an image is dropped, its sibling parts (a message's text)
// are preserved. If the user images alone can't cover the surplus (the rare
// case where the cap is exceeded by non-user images), the body may still exceed
// max after the drop — the caller's single retry then forwards the upstream 400,
// no worse than the un-clamped case.
func ClampChatInputImages(body []byte, max int) (out []byte, dropped int, err error) {
	// userTurnsOnly is a REQUIRED argument, not an option with a permissive
	// default: shedding a tool or assistant message here would orphan a
	// tool_call and draw a different 400.
	return clampInputImages(body, max, "messages", "image_url", userTurnsOnly)
}

// chatMessageRole reads the "role" of a chat message, "" on malformed JSON.
func chatMessageRole(msg json.RawMessage) string {
	var m struct {
		Role string `json:"role"`
	}
	if json.Unmarshal(msg, &m) != nil {
		return ""
	}
	return m.Role
}

// SetChatUsage rewrites the `usage` field on a non-streaming
// /v1/chat/completions response body so it reports the aggregate totals
// across every tool-loop iteration. The proxy sees this body when it
// extracts usage for the receipt, so the aggregate has to land on the
// final response we ship — not just in-memory on the node.
func SetChatUsage(resp []byte, input, output, cached uint64) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &obj); err != nil {
		return resp
	}
	usage := map[string]any{
		"prompt_tokens":     input,
		"completion_tokens": output,
		"total_tokens":      input + output,
	}
	if cached > 0 {
		usage["prompt_tokens_details"] = map[string]uint64{"cached_tokens": cached}
	}
	b, err := json.Marshal(usage)
	if err != nil {
		return resp
	}
	obj["usage"] = b
	out, err := json.Marshal(obj)
	if err != nil {
		return resp
	}
	return out
}

// MarshalChatCitationsContentDelta produces a synthetic Chat Completions
// SSE chunk that carries the rendered citations bundle as a single
// `delta.content` string. The streaming tool loop emits this chunk on
// the final iteration immediately before the upstream's terminal
// (finish_reason or usage chunk) so the Sources block lands as ordinary
// content the client renders alongside the model's answer.
//
// Returns ok=false (and a nil payload) when there are no citations to
// render — callers skip emission. The synthetic frame intentionally
// omits id / model / created / object fields: the stitcher classifies
// it as FrameContent purely on the non-empty delta.content, and
// downstream sealers don't care about envelope metadata.
//
// Uses the same renderer as SpliceEffectsChatBody so streaming and non-
// streaming Chat paths produce byte-identical Sources blocks.
func MarshalChatCitationsContentDelta(effects []ToolEffect) ([]byte, bool, error) {
	if len(effects) == 0 {
		return nil, false, nil
	}
	md := renderCitationsMarkdown(flattenCitations(effects))
	if md == "" {
		return nil, false, nil
	}
	contentJSON, err := json.Marshal(md)
	if err != nil {
		return nil, false, err
	}
	delta := map[string]json.RawMessage{
		"content": contentJSON,
	}
	deltaJSON, err := json.Marshal(delta)
	if err != nil {
		return nil, false, err
	}
	choice := map[string]json.RawMessage{
		"index": json.RawMessage(`0`),
		"delta": deltaJSON,
	}
	choiceJSON, err := json.Marshal(choice)
	if err != nil {
		return nil, false, err
	}
	choicesJSON, err := json.Marshal([]json.RawMessage{choiceJSON})
	if err != nil {
		return nil, false, err
	}
	frame := map[string]json.RawMessage{
		"choices": choicesJSON,
	}
	out, err := json.Marshal(frame)
	if err != nil {
		return nil, false, err
	}
	return out, true, nil
}

// TrimChatContentDeltaLeadingSpace inspects a Chat Completions SSE chunk
// and, when it carries a `choices[0].delta.content` string, either
// returns it with leading whitespace removed (trimmed != nil, drop=false)
// or signals that the entire content is whitespace and the frame should
// be dropped (drop=true). Frames the helper doesn't understand — non-
// JSON, no choices, no delta, non-string content, no content field —
// pass through unchanged with trimmed=nil, drop=false.
//
// The streaming tool loop calls this once per iteration on the FIRST
// FrameContent so that leading-whitespace artifacts emitted by some
// models (notably Qwen3 thinking-mode continuing after a tool turn
// where the prior assistant message was content:null) don't surface to
// the client. The wire trim does not mutate the stitcher's contentBuf
// or AssistantMessage reconstruction, so the upstream conversation
// context (next iteration's body) sees the exact bytes the model
// generated.
func TrimChatContentDeltaLeadingSpace(frame []byte) (trimmed []byte, drop bool, err error) {
	var obj map[string]json.RawMessage
	if uerr := json.Unmarshal(frame, &obj); uerr != nil {
		return nil, false, nil
	}
	rawChoices, ok := obj["choices"]
	if !ok {
		return nil, false, nil
	}
	var choices []json.RawMessage
	if uerr := json.Unmarshal(rawChoices, &choices); uerr != nil {
		return nil, false, nil
	}
	if len(choices) == 0 {
		return nil, false, nil
	}
	var ch map[string]json.RawMessage
	if uerr := json.Unmarshal(choices[0], &ch); uerr != nil {
		return nil, false, nil
	}
	rawDelta, ok := ch["delta"]
	if !ok {
		return nil, false, nil
	}
	var delta map[string]json.RawMessage
	if uerr := json.Unmarshal(rawDelta, &delta); uerr != nil {
		return nil, false, nil
	}
	rawContent, ok := delta["content"]
	if !ok {
		return nil, false, nil
	}
	var content string
	if uerr := json.Unmarshal(rawContent, &content); uerr != nil {
		// Non-string content (null, structured array). Leave alone.
		return nil, false, nil
	}
	if content == "" {
		return nil, false, nil
	}
	trimmedContent := strings.TrimLeftFunc(content, unicode.IsSpace)
	if trimmedContent == content {
		return nil, false, nil
	}
	if trimmedContent == "" {
		return nil, true, nil
	}
	newContent, mErr := json.Marshal(trimmedContent)
	if mErr != nil {
		return nil, false, mErr
	}
	delta["content"] = newContent
	newDelta, mErr := json.Marshal(delta)
	if mErr != nil {
		return nil, false, mErr
	}
	ch["delta"] = newDelta
	newCh, mErr := json.Marshal(ch)
	if mErr != nil {
		return nil, false, mErr
	}
	choices[0] = newCh
	newChoices, mErr := json.Marshal(choices)
	if mErr != nil {
		return nil, false, mErr
	}
	obj["choices"] = newChoices
	out, mErr := json.Marshal(obj)
	if mErr != nil {
		return nil, false, mErr
	}
	return out, false, nil
}

// ChatToolCallStitcher accumulates streaming tool_calls deltas and text
// content deltas across frames of a /v1/chat/completions stream. One
// stitcher instance is used per upstream SSE session; the tool loop
// creates a fresh one per iteration.
type ChatToolCallStitcher struct {
	// tool_calls indexed by the delta's `index` field. OpenAI guarantees
	// the same index refers to the same tool call across deltas; the
	// name + arguments grow over time.
	byIndex    map[int]*chatStitchEntry
	contentBuf bytes.Buffer
	// reasoningBuf accumulates the model's chain-of-thought so
	// AssistantMessage can echo it back on the next iteration. Reasoning
	// models that carry state across tool calls require this: z.ai documents
	// that the "complete, unmodified reasoning_content" must be returned and
	// that consecutive blocks "must exactly match the original sequence", and
	// GLM loses its plan mid-task without it. Held separately from contentBuf
	// because reasoning is NOT visible output — it never reaches the client
	// through this buffer, only the upstream on the replayed assistant turn.
	reasoningBuf  bytes.Buffer
	finishReason  string
	usage         ChatUsage
	sawUsage      bool
	sawUsageChunk bool
	// builtinNames is the map from function name to hayai built-in type,
	// as populated by RewriteBuiltinToolsChat. The stitcher uses it to
	// classify each tool-call frame as FrameToolCallBuiltin or
	// FrameToolCallClient so the streaming tool loop can suppress or
	// forward the frame accordingly. nil / empty map means "no hayai
	// tools registered" — every tool call is classified as client.
	builtinNames map[string]BuiltinToolType
}

type chatStitchEntry struct {
	ID          string
	Name        string
	ArgsBuf     bytes.Buffer
	SawAny      bool
	SentinelIdx int // stable insertion order
	// Extra is the verbatim `extra_content` object from whichever delta
	// first carried it for this tool_call index — provider-opaque per-call
	// state (Gemini's extra_content.google.thought_signature) the upstream
	// requires echoed back. First-non-empty wins because OpenAI-shape
	// streaming can fragment a tool call across deltas and the signature may
	// not ride the same delta as the args.
	Extra json.RawMessage
}

// NewChatToolCallStitcher returns a fresh stitcher. The zero value is
// intentionally unusable — callers must use this constructor so the
// internal maps are ready.
// builtinNames is the name→type map from RewriteBuiltinToolsChat; pass
// nil or an empty map when no hayai built-ins are registered.
func NewChatToolCallStitcher(builtinNames map[string]BuiltinToolType) *ChatToolCallStitcher {
	return &ChatToolCallStitcher{
		byIndex:      map[int]*chatStitchEntry{},
		builtinNames: builtinNames,
	}
}

// classifyToolCall returns FrameToolCallBuiltin when name is a known hayai
// built-in and FrameToolCallClient otherwise.
func (s *ChatToolCallStitcher) classifyToolCall(name string) FrameClassification {
	if name == "" {
		// First fragment hasn't carried the name yet. For OpenAI itself
		// this is extremely rare — function.name lands in the first
		// tool_calls[i] delta — but llama.cpp / some tool-call modes
		// defer the name to a later fragment. Return FrameUnknown so
		// the tool-loop buffers the fragment until the name arrives.
		// Suppressing-then-replaying is safer than forwarding a hayai
		// fragment to the client before we know it's hayai.
		return FrameUnknown
	}
	if _, ok := s.builtinNames[name]; ok {
		return FrameToolCallBuiltin
	}
	// Defense-in-depth: the `zs_` prefix is a reserved namespace for
	// node-owned transport tools. Any call with that prefix MUST NOT
	// reach the client — if the rewriter was skipped or the names map
	// is stale, suppressing still preserves the wire invariant.
	if IsBuiltinToolType(name) {
		return FrameToolCallBuiltin
	}
	return FrameToolCallClient
}

// Observe feeds one SSE data-payload frame (minus the `data:` prefix)
// into the stitcher and returns how the tool loop should react.
//
// The classification is deliberately coarse. The loop uses it only to
// decide "flush-and-go-live" vs. "keep buffering" — fine-grained delta
// handling happens inside the stitcher where it belongs.
func (s *ChatToolCallStitcher) Observe(frame []byte) FrameClassification {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 {
		return FrameUnknown
	}
	if bytes.Equal(trimmed, []byte("[DONE]")) {
		return FrameTerminal
	}
	var chunk struct {
		Choices []struct {
			Index int `json:"index"`
			Delta struct {
				Content   *string         `json:"content"`
				ToolCalls []chatToolCallD `json:"tool_calls"`
				// The two spellings reasoning-capable OpenAI-compatible
				// upstreams use for chain-of-thought: reasoning_content
				// (vLLM's older name / SGLang / DeepSeek / z.ai) and
				// reasoning (current vLLM, OpenRouter). Captured so the
				// tool loop can replay them; see reasoningBuf.
				ReasoningContent *string         `json:"reasoning_content"`
				Reasoning        json.RawMessage `json:"reasoning"`
			} `json:"delta"`
			FinishReason *string `json:"finish_reason"`
		} `json:"choices"`
		Usage *ChatUsage `json:"usage"`
	}
	if err := json.Unmarshal(trimmed, &chunk); err != nil {
		return FrameUnknown
	}
	// Authoritative usage arrives one of two ways. OpenAI emits a
	// standalone "usage-only" chunk: empty choices[] + a populated usage
	// object — droppable from the client-visible stream when the node
	// injected include_usage. GLM/z.ai and some other OpenAI-compatible
	// providers instead bundle usage onto the FINAL content chunk
	// (non-empty choices + finish_reason); that chunk also carries content
	// + the terminal finish, so it must NOT be dropped. Capture both for
	// billing (sawUsage); flag only the standalone shape as droppable
	// (sawUsageChunk). A mid-stream chunk carrying a partial usage object
	// with no finish_reason is ignored so the receipt never bills off an
	// interim count. The loop only treats a frame as authoritative
	// end-of-iteration on [DONE] or an observed finish_reason, but
	// emitStreamReceipt downstream wants the usage captured either way.
	if chunk.Usage != nil && len(chunk.Choices) == 0 {
		s.usage = *chunk.Usage
		s.sawUsage = true
		s.sawUsageChunk = true
		return FrameTerminal
	}
	sawToolCall := false
	sawBuiltinCall := false
	sawClientCall := false
	sawContent := false
	frameHasFinish := false
	for _, ch := range chunk.Choices {
		if ch.FinishReason != nil && *ch.FinishReason != "" {
			s.finishReason = *ch.FinishReason
			frameHasFinish = true
		}
		if ch.Delta.Content != nil && *ch.Delta.Content != "" {
			s.contentBuf.WriteString(*ch.Delta.Content)
			sawContent = true
		}
		// Deliberately does NOT set sawContent: reasoning is not visible
		// output, and a reasoning-only delta must keep classifying exactly
		// as it did before (FrameUnknown) so the streaming tool loop's
		// buffer/forward behavior is unchanged. Capture is state-only.
		s.reasoningBuf.WriteString(chatDeltaReasoning(ch.Delta.ReasoningContent, ch.Delta.Reasoning))
		for _, tcd := range ch.Delta.ToolCalls {
			sawToolCall = true
			entry, ok := s.byIndex[tcd.Index]
			if !ok {
				entry = &chatStitchEntry{SentinelIdx: len(s.byIndex)}
				s.byIndex[tcd.Index] = entry
			}
			if tcd.ID != "" {
				entry.ID = tcd.ID
			}
			if tcd.Function.Name != "" {
				entry.Name = tcd.Function.Name
			}
			if tcd.Function.Arguments != "" {
				entry.ArgsBuf.WriteString(tcd.Function.Arguments)
			}
			// First-non-empty wins: the signature may ride a different
			// delta than the args/name for this same tool_call index.
			if len(entry.Extra) == 0 && len(tcd.ExtraContent) > 0 {
				entry.Extra = tcd.ExtraContent
			}
			entry.SawAny = true
			// Classify this fragment by its stored name. If we haven't
			// seen the name yet (this delta only carried an id or an
			// arguments chunk), treat as client — conservative choice
			// since hayai names appear in the first fragment by spec.
			if s.classifyToolCall(entry.Name) == FrameToolCallBuiltin {
				sawBuiltinCall = true
			} else {
				sawClientCall = true
			}
		}
	}
	// GLM/z.ai combined content+usage final chunk: capture the usage for
	// billing but fall through to the switch so the frame still classifies
	// on its content / tool calls / finish_reason and reaches the client
	// intact (sawUsageChunk stays false — this chunk is not droppable).
	if chunk.Usage != nil && frameHasFinish {
		s.usage = *chunk.Usage
		s.sawUsage = true
	}
	switch {
	case sawContent:
		return FrameContent
	case sawToolCall:
		// If ANY tool call in this frame is hayai, treat the whole frame
		// as hayai (suppress). In practice providers stream one call's
		// fragments per frame so this is unambiguous; if a rare mixed
		// frame appears, suppressing is the safer default than
		// forwarding an unredacted hayai payload to the client.
		if sawBuiltinCall {
			return FrameToolCallBuiltin
		}
		_ = sawClientCall
		return FrameToolCallClient
	case s.finishReason != "":
		// An empty-delta chunk with finish_reason set is the end of
		// choice[0] — mark terminal so the loop can decide.
		return FrameTerminal
	default:
		return FrameUnknown
	}
}

// chatDeltaReasoning returns the reasoning fragment carried by one chat delta,
// or "" when it carries none.
//
// Only STRING-shaped payloads are accepted. The replay contract is
// byte-exactness — z.ai requires the echoed blocks to "exactly match the
// original sequence generated by the model" — and an object/array payload
// (OpenRouter's reasoning_details, an encrypted blob) has no faithful string
// rendering. Flattening one to text would produce an echo that does not match
// what the model emitted, which is worse than replaying nothing: the upstream
// either rejects it or is fed altered thinking. So those shapes are skipped
// here and the turn replays without reasoning, exactly as it did before.
func chatDeltaReasoning(reasoningContent *string, reasoning json.RawMessage) string {
	if reasoningContent != nil && *reasoningContent != "" {
		return *reasoningContent
	}
	raw := bytes.TrimSpace(reasoning)
	if len(raw) == 0 || raw[0] != '"' {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

type chatToolCallD struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
	// ExtraContent is a sibling of function/id/index/type on the tool_call
	// object (Gemini via Vertex's openai surface puts the mandatory
	// thought_signature under .google here). Captured opaquely and replayed.
	ExtraContent json.RawMessage `json:"extra_content"`
}

// FinishReason returns the latest finish_reason observed on choice[0]
// of the stream. Empty until the upstream emits one.
func (s *ChatToolCallStitcher) FinishReason() string { return s.finishReason }

// Content returns the visible assistant text accumulated across this
// iteration's content deltas. The tool loop reads it to detect native
// tool-call markup the upstream failed to parse into structured calls (see
// ScanLeakedToolCalls) — the buffer is already maintained for
// AssistantMessage(), so this only exposes it.
func (s *ChatToolCallStitcher) Content() string { return s.contentBuf.String() }

// Usage returns the totals captured from the terminal usage object —
// whether it rode a standalone usage-only chunk (OpenAI) or the final
// content chunk (GLM/z.ai). Zero when upstream didn't emit one (e.g.
// include_usage wasn't set, or a backend omits it).
func (s *ChatToolCallStitcher) Usage() ChatUsage { return s.usage }

// SawUsage reports whether the stitcher captured an authoritative usage
// object from EITHER shape (standalone usage-only chunk, or the final
// content chunk that GLM/z.ai bundle usage onto). Gate receipt billing on
// this — billing must follow the tokens regardless of provider shape.
func (s *ChatToolCallStitcher) SawUsage() bool { return s.sawUsage }

// SawUsageChunk reports whether a *standalone* usage-only chunk (empty
// choices) was observed — the only shape that is safe to strip from the
// client-facing stream when the node injected include_usage. A combined
// content+usage chunk (GLM/z.ai) sets SawUsage but NOT this, because
// dropping it would also drop the final content + finish_reason. Gate the
// strip decision on this; gate billing on SawUsage.
func (s *ChatToolCallStitcher) SawUsageChunk() bool { return s.sawUsageChunk }

// ToolCalls returns the stitched tool calls in the order their indices
// first appeared on the stream. Arguments are the full concatenated JSON
// strings the LLM emitted; the tool dispatcher parses them per-tool.
func (s *ChatToolCallStitcher) ToolCalls() []ToolCall {
	if len(s.byIndex) == 0 {
		return nil
	}
	ordered := make([]*chatStitchEntry, 0, len(s.byIndex))
	for _, e := range s.byIndex {
		ordered = append(ordered, e)
	}
	// Stable sort by first-seen index.
	for i := 1; i < len(ordered); i++ {
		for j := i; j > 0 && ordered[j-1].SentinelIdx > ordered[j].SentinelIdx; j-- {
			ordered[j-1], ordered[j] = ordered[j], ordered[j-1]
		}
	}
	out := make([]ToolCall, 0, len(ordered))
	for _, e := range ordered {
		out = append(out, ToolCall{
			ID:        e.ID,
			Name:      e.Name,
			Arguments: e.ArgsBuf.String(),
			Extra:     e.Extra,
		})
	}
	return out
}

// AssistantMessage renders an OpenAI-shaped assistant message from the
// stitched deltas so the tool loop can re-append it to the next
// iteration's messages[] before running the tool results. The model sees
// the same conversational history it produced, with tool_calls embedded.
//
// We construct this rather than re-playing the upstream's last
// choices[0].message because streaming responses don't carry that field;
// the stitcher is the authoritative reconstructor.
func (s *ChatToolCallStitcher) AssistantMessage() json.RawMessage {
	obj := map[string]json.RawMessage{
		"role": json.RawMessage(`"assistant"`),
	}
	// Replay the model's own chain-of-thought on the echoed turn. Reasoning
	// models that carry state across tool calls need it: without it GLM/z.ai
	// loses its plan after every action and starts narrating the tool protocol
	// as prose instead of emitting structured calls. Omitted entirely when the
	// upstream sent none, so a non-reasoning provider's replay stays
	// byte-identical — the same discipline extra_content follows below.
	if s.reasoningBuf.Len() > 0 {
		rJSON, _ := json.Marshal(s.reasoningBuf.String())
		obj["reasoning_content"] = rJSON
	}
	if s.contentBuf.Len() > 0 {
		cJSON, _ := json.Marshal(s.contentBuf.String())
		obj["content"] = cJSON
	} else {
		// Chat Completions expects content to be either a string or null.
		// Passing null is safer than omitting the field when tool_calls
		// are present — some strict backends validate the shape.
		obj["content"] = json.RawMessage(`null`)
	}
	calls := s.ToolCalls()
	if len(calls) > 0 {
		arr := make([]json.RawMessage, 0, len(calls))
		for _, c := range calls {
			tc := map[string]json.RawMessage{
				"type": json.RawMessage(`"function"`),
			}
			idJSON, _ := json.Marshal(c.ID)
			tc["id"] = idJSON
			fn := map[string]json.RawMessage{}
			nameJSON, _ := json.Marshal(c.Name)
			fn["name"] = nameJSON
			argsJSON, _ := json.Marshal(c.Arguments)
			fn["arguments"] = argsJSON
			fnJSON, _ := json.Marshal(fn)
			tc["function"] = fnJSON
			// Replay provider-opaque per-call state verbatim (Gemini 3's
			// extra_content.google.thought_signature is mandatory on the
			// echoed tool_call or the next iteration 400s). Absent for
			// every other provider, so the replay stays byte-identical.
			if len(c.Extra) > 0 {
				tc["extra_content"] = c.Extra
			}
			enc, _ := json.Marshal(tc)
			arr = append(arr, enc)
		}
		tcJSON, _ := json.Marshal(arr)
		obj["tool_calls"] = tcJSON
	}
	out, _ := json.Marshal(obj)
	return out
}
