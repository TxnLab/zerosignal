/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func sampleWebSearchDef() BuiltinToolDef {
	return BuiltinToolDef{
		Type:        "zs_web_search",
		Name:        "zs_web_search",
		Description: "Search the web via DuckDuckGo.",
		Parameters:  json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"}},"required":["query"],"additionalProperties":false}`),
	}
}

func sampleDefs() map[BuiltinToolType]BuiltinToolDef {
	d := sampleWebSearchDef()
	return map[BuiltinToolType]BuiltinToolDef{d.Type: d}
}

func TestRewriteBuiltinToolsChat_RewritesBuiltin(t *testing.T) {
	body := []byte(`{"model":"gpt-4","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"zs_web_search"}]}`)
	got, names, err := RewriteBuiltinToolsChat(body, sampleDefs())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if names["zs_web_search"] != "zs_web_search" {
		t.Fatalf("expected builtinNames map populated, got %+v", names)
	}
	var out struct {
		Tools []struct {
			Type     string `json:"type"`
			Function struct {
				Name        string          `json:"name"`
				Description string          `json:"description"`
				Parameters  json.RawMessage `json:"parameters"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal rewritten: %v", err)
	}
	if len(out.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(out.Tools))
	}
	tool := out.Tools[0]
	if tool.Type != "function" {
		t.Fatalf("expected type=function, got %q", tool.Type)
	}
	if tool.Function.Name != "zs_web_search" {
		t.Fatalf("expected function name=zs_web_search, got %q", tool.Function.Name)
	}
	if tool.Function.Description == "" {
		t.Fatalf("expected description preserved")
	}
	if len(tool.Function.Parameters) == 0 {
		t.Fatalf("expected parameters preserved")
	}
}

func TestRewriteBuiltinToolsChat_PassesThroughUserFunctions(t *testing.T) {
	body := []byte(`{"tools":[{"type":"function","function":{"name":"my_fn","description":"custom","parameters":{}}}]}`)
	got, names, err := RewriteBuiltinToolsChat(body, sampleDefs())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no hayai names, got %+v", names)
	}
	// Byte-identical when no rewrite occurs.
	if string(got) != string(body) {
		t.Fatalf("expected body unchanged; got %s", got)
	}
}

func TestRewriteBuiltinToolsChat_UnknownTypeErrors(t *testing.T) {
	body := []byte(`{"tools":[{"type":"zs_bogus"}]}`)
	_, _, err := RewriteBuiltinToolsChat(body, sampleDefs())
	if !errors.Is(err, ErrUnknownBuiltinTool) {
		t.Fatalf("expected ErrUnknownBuiltinTool, got %v", err)
	}
}

func TestRewriteBuiltinToolsChat_NoToolsArrayIsNoop(t *testing.T) {
	body := []byte(`{"model":"x","messages":[]}`)
	got, names, err := RewriteBuiltinToolsChat(body, sampleDefs())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no names")
	}
	if string(got) != string(body) {
		t.Fatalf("expected noop; got %s", got)
	}
}

func TestRewriteBuiltinToolsChat_MixedEntriesRewriteOnlyBuiltin(t *testing.T) {
	body := []byte(`{"tools":[{"type":"function","function":{"name":"u"}},{"type":"zs_web_search"}]}`)
	got, names, err := RewriteBuiltinToolsChat(body, sampleDefs())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("expected 1 hayai name, got %+v", names)
	}
	// Both tools should be function-typed after rewrite.
	var out struct {
		Tools []struct {
			Type     string `json:"type"`
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Tools) != 2 || out.Tools[0].Type != "function" || out.Tools[1].Type != "function" {
		t.Fatalf("unexpected tool list: %s", got)
	}
	if out.Tools[0].Function.Name != "u" || out.Tools[1].Function.Name != "zs_web_search" {
		t.Fatalf("unexpected rewrite: %+v", out.Tools)
	}
}

func TestExtractToolCallsChat_NoTools(t *testing.T) {
	resp := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}]}`)
	msg, calls, reason, err := ExtractToolCallsChat(resp)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(calls) != 0 {
		t.Fatalf("expected no calls")
	}
	if reason != "stop" {
		t.Fatalf("expected stop, got %q", reason)
	}
	if len(msg) == 0 {
		t.Fatalf("expected assistant message preserved")
	}
}

func TestExtractToolCallsChat_MultipleCalls(t *testing.T) {
	resp := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call_1","type":"function","function":{"name":"zs_web_search","arguments":"{\"query\":\"algo\"}"}},{"id":"call_2","type":"function","function":{"name":"zs_web_read","arguments":"{\"url\":\"https://x\"}"}}]},"finish_reason":"tool_calls"}]}`)
	msg, calls, reason, err := ExtractToolCallsChat(resp)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("expected 2 calls, got %d", len(calls))
	}
	if reason != "tool_calls" {
		t.Fatalf("expected tool_calls, got %q", reason)
	}
	if calls[0].ID != "call_1" || calls[0].Name != "zs_web_search" {
		t.Fatalf("bad call 0: %+v", calls[0])
	}
	if calls[1].ID != "call_2" || calls[1].Name != "zs_web_read" {
		t.Fatalf("bad call 1: %+v", calls[1])
	}
	if len(msg) == 0 {
		t.Fatalf("expected message bytes preserved")
	}
}

func TestSanitizeIncompleteBuiltinCallsChat(t *testing.T) {
	resp := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[` +
		`{"id":"drop_empty","type":"function","function":{"name":"zs_web_search","arguments":""}},` +
		`{"id":"keep_complete","type":"function","function":{"name":"zs_web_search","arguments":"{}"}},` +
		`{"id":"drop_partial","type":"function","function":{"name":"zs_web_search","arguments":"{\"query\":"}},` +
		`{"id":"keep_client","type":"function","function":{"name":"client_tool","arguments":""}}]}` +
		`,"finish_reason":"length"}]}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsChat(resp, names, true)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	msg, calls, _, err := ExtractToolCallsChat(got)
	if err != nil {
		t.Fatalf("extract sanitized response: %v", err)
	}
	if len(calls) != 2 || calls[0].ID != "keep_complete" || calls[1].ID != "keep_client" {
		t.Fatalf("calls = %+v, want complete builtin + client call", calls)
	}
	if strings.Contains(string(msg), "drop_empty") || strings.Contains(string(msg), "drop_partial") {
		t.Fatalf("dropped calls remain in replay message: %s", msg)
	}
}

// On a round the model finished, empty arguments are a zero-argument call and
// must survive; only the unparseable one is undispatchable.
func TestSanitizeIncompleteBuiltinCallsChat_UntruncatedKeepsEmptyArguments(t *testing.T) {
	resp := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[` +
		`{"id":"keep_empty","type":"function","function":{"name":"zs_web_search","arguments":""}},` +
		`{"id":"drop_partial","type":"function","function":{"name":"zs_web_search","arguments":"{\"query\":"}}]}` +
		`,"finish_reason":"tool_calls"}]}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsChat(resp, names, false)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1 — only the unparseable call", dropped)
	}
	_, calls, _, err := ExtractToolCallsChat(got)
	if err != nil {
		t.Fatalf("extract sanitized response: %v", err)
	}
	if len(calls) != 1 || calls[0].ID != "keep_empty" {
		t.Fatalf("calls = %+v, want the zero-argument call kept", calls)
	}
}

// When every call in a choice is dropped the key goes away entirely rather
// than shipping `"tool_calls": []` beside a null content.
func TestSanitizeIncompleteBuiltinCallsChat_DropsEmptiedToolCallsKey(t *testing.T) {
	resp := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":null,"tool_calls":[` +
		`{"id":"drop","type":"function","function":{"name":"zs_web_search","arguments":"{\"query\":"}}]}` +
		`,"finish_reason":"length"}]}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsChat(resp, names, true)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if strings.Contains(string(got), `"tool_calls"`) {
		t.Fatalf("emptied tool_calls key survived: %s", got)
	}
}

func TestAppendToolMessagesChat_AppendsAssistantAndTool(t *testing.T) {
	body := []byte(`{"model":"x","messages":[{"role":"user","content":"hi"}]}`)
	assistantMsg := json.RawMessage(`{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"t","arguments":"{}"}}]}`)
	results := []ToolResult{{ToolCallID: "c1", Content: `{"ok":true}`}}
	got, err := AppendToolMessagesChat(body, assistantMsg, results)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	var out struct {
		Messages []struct {
			Role       string `json:"role"`
			ToolCallID string `json:"tool_call_id"`
			Content    string `json:"content"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Messages) != 3 {
		t.Fatalf("expected 3 messages, got %d: %s", len(out.Messages), got)
	}
	if out.Messages[1].Role != "assistant" {
		t.Fatalf("expected assistant at index 1, got %q", out.Messages[1].Role)
	}
	if out.Messages[2].Role != "tool" || out.Messages[2].ToolCallID != "c1" {
		t.Fatalf("expected tool result at index 2, got %+v", out.Messages[2])
	}
}

func TestSetChatUsage(t *testing.T) {
	resp := []byte(`{"id":"x","usage":{"prompt_tokens":1,"completion_tokens":2,"total_tokens":3}}`)
	got := SetChatUsage(resp, 100, 50, 30)
	var out struct {
		Usage ChatUsage `json:"usage"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Usage.PromptTokens != 100 || out.Usage.CompletionTokens != 50 || out.Usage.TotalTokens != 150 {
		t.Fatalf("unexpected usage: %+v", out.Usage)
	}
	if out.Usage.CachedTokens() != 30 {
		t.Fatalf("cached = %d, want 30 (prompt_tokens_details.cached_tokens)", out.Usage.CachedTokens())
	}
	// cached == 0 must omit prompt_tokens_details entirely (no regression).
	var out0 struct {
		Usage ChatUsage `json:"usage"`
	}
	if err := json.Unmarshal(SetChatUsage(resp, 100, 50, 0), &out0); err != nil {
		t.Fatalf("unmarshal cached=0: %v", err)
	}
	if out0.Usage.PromptTokensDetails != nil {
		t.Errorf("cached=0 should omit prompt_tokens_details: %+v", out0.Usage.PromptTokensDetails)
	}
}

func TestChatStitcher_ToolCallOnlyIteration(t *testing.T) {
	builtinNames := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	s := NewChatToolCallStitcher(builtinNames)
	frames := []string{
		`{"choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"zs_web_search"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"query\":"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"\"algo\"}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	}
	classes := []FrameClassification{}
	for _, f := range frames {
		classes = append(classes, s.Observe([]byte(f)))
	}
	// Expect: unknown (empty delta), tool_call_hayai (x3), terminal.
	// The name "zs_web_search" is in builtinNames so all three tool-call
	// fragments (including argument-only ones, which look up the stored
	// name from the first fragment) classify as hayai.
	wantTailClass := []FrameClassification{FrameUnknown, FrameToolCallBuiltin, FrameToolCallBuiltin, FrameToolCallBuiltin, FrameTerminal}
	for i, w := range wantTailClass {
		if classes[i] != w {
			t.Fatalf("frame %d: expected %v got %v", i, w, classes[i])
		}
	}
	if s.FinishReason() != "tool_calls" {
		t.Fatalf("expected finish_reason tool_calls, got %q", s.FinishReason())
	}
	calls := s.ToolCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].ID != "c1" || calls[0].Name != "zs_web_search" {
		t.Fatalf("bad call: %+v", calls[0])
	}
	if !strings.Contains(calls[0].Arguments, `"query":"algo"`) {
		t.Fatalf("bad arguments: %q", calls[0].Arguments)
	}
	// Assistant message must round-trip for re-append.
	am := s.AssistantMessage()
	if !strings.Contains(string(am), `"tool_calls"`) {
		t.Fatalf("assistant msg missing tool_calls: %s", am)
	}
}

// Kronk emits ONE of two streaming tool-call shapes, and which one depends on
// the parser family behind the served model — so a live model only ever
// exercises whichever its own family uses.
//
// The familiar shape is announce (id+name, empty args) → reconcile (id/type/name
// CLEARED, complete args) → terminal, covered by
// TestChatStitcher_ToolCallOnlyIteration above. But as of Kronk 1.30.4 the
// `mistral` and `toolcall` parser families no longer implement
// ToolCallDeltaStreamer, so they emit no announce at all; Kronk compensates by
// keeping the full identity on the single reconcile delta
// (reconcileStartedToolCalls' startAt == -1 branch). This pins that shape: the
// stitcher must reassemble a call from one self-contained delta, with no
// preceding announce to seed the accumulator.
func TestChatStitcher_ToolCallWithoutAnnounceDelta(t *testing.T) {
	builtinNames := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	s := NewChatToolCallStitcher(builtinNames)
	frames := []string{
		`{"choices":[{"index":0,"delta":{"role":"assistant"}}]}`,
		// One delta carrying id, index, type, name AND the complete arguments.
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"zs_web_search","arguments":"{\"query\":\"algo\"}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	}
	for i, f := range frames {
		if got := s.Observe([]byte(f)); i == 1 && got != FrameToolCallBuiltin {
			t.Fatalf("frame %d: classification = %v, want FrameToolCallBuiltin", i, got)
		}
	}
	calls := s.ToolCalls()
	if len(calls) != 1 {
		t.Fatalf("stitched %d calls, want 1", len(calls))
	}
	if calls[0].ID != "c1" {
		t.Errorf("ID = %q, want c1 — nothing announced it, so the reconcile delta is the only source", calls[0].ID)
	}
	if calls[0].Name != "zs_web_search" {
		t.Errorf("Name = %q, want zs_web_search", calls[0].Name)
	}
	if calls[0].Arguments != `{"query":"algo"}` {
		t.Errorf("Arguments = %q, want the complete JSON", calls[0].Arguments)
	}
	if s.FinishReason() != "tool_calls" {
		t.Errorf("FinishReason = %q, want tool_calls", s.FinishReason())
	}
}

func TestChatStitcher_ContentIterationFlipsLive(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	// First frame is content — loop should flip live immediately.
	c := s.Observe([]byte(`{"choices":[{"index":0,"delta":{"role":"assistant","content":"Hel"}}]}`))
	if c != FrameContent {
		t.Fatalf("expected FrameContent, got %v", c)
	}
	c = s.Observe([]byte(`{"choices":[{"index":0,"delta":{"content":"lo"}}]}`))
	if c != FrameContent {
		t.Fatalf("expected FrameContent, got %v", c)
	}
	c = s.Observe([]byte(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`))
	if c != FrameTerminal {
		t.Fatalf("expected FrameTerminal, got %v", c)
	}
	c = s.Observe([]byte(`[DONE]`))
	if c != FrameTerminal {
		t.Fatalf("expected FrameTerminal for [DONE], got %v", c)
	}
}

func TestChatStitcher_UsageChunkCaptured(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	frame := []byte(`{"choices":[],"usage":{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}}`)
	c := s.Observe(frame)
	if c != FrameTerminal {
		t.Fatalf("expected FrameTerminal for usage chunk, got %v", c)
	}
	// Standalone usage-only chunk: captured for billing AND droppable.
	if !s.SawUsage() {
		t.Fatalf("expected SawUsage true")
	}
	if !s.SawUsageChunk() {
		t.Fatalf("expected SawUsageChunk true")
	}
	u := s.Usage()
	if u.PromptTokens != 10 || u.CompletionTokens != 20 || u.TotalTokens != 30 {
		t.Fatalf("bad usage: %+v", u)
	}
}

// TestChatStitcher_UsageOnFinalContentChunk covers GLM/z.ai's shape: usage
// is bundled onto the final content chunk (non-empty choices + finish_reason),
// with NO standalone empty-choices usage chunk. The stitcher must capture the
// usage for billing (SawUsage) WITHOUT marking the chunk droppable
// (SawUsageChunk) — dropping it would strip the client's final content +
// finish. Previously the empty-choices guard left usage at zero, zeroing the
// receipt and refunding the operator in full.
func TestChatStitcher_UsageOnFinalContentChunk(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	// Content streams first, no usage yet.
	if c := s.Observe([]byte(`{"choices":[{"index":0,"delta":{"content":"Hi"}}]}`)); c != FrameContent {
		t.Fatalf("content frame: got %v, want FrameContent", c)
	}
	if s.SawUsage() {
		t.Fatalf("usage captured before any usage object arrived")
	}
	// Final content chunk carries content + finish_reason + usage.
	c := s.Observe([]byte(`{"choices":[{"index":0,"delta":{"content":"!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	if c != FrameContent {
		t.Fatalf("combined chunk with content: got %v, want FrameContent (must stay on the wire)", c)
	}
	if !s.SawUsage() {
		t.Fatalf("expected SawUsage true on combined chunk")
	}
	if s.SawUsageChunk() {
		t.Fatalf("combined content+usage chunk must NOT be droppable (SawUsageChunk should be false)")
	}
	if u := s.Usage(); u.PromptTokens != 10 || u.CompletionTokens != 5 || u.TotalTokens != 15 {
		t.Fatalf("bad usage from combined chunk: %+v", u)
	}
}

// TestChatStitcher_UsageCarriesCachedTokens guards the tool-loop cached path:
// the stitcher must decode the cache-read count so the node's per-iteration
// usage log and aggregate reflect it. Before this the ChatUsage struct dropped
// the breakdown, so every tools-enabled request logged cached=0 even when the
// upstream (e.g. z.ai/GLM at ~96% hit) reported it.
func TestChatStitcher_UsageCarriesCachedTokens(t *testing.T) {
	// z.ai/GLM combined chunk with prompt_tokens_details.cached_tokens.
	s := NewChatToolCallStitcher(nil)
	s.Observe([]byte(`{"choices":[{"index":0,"delta":{"content":"!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":2981,"completion_tokens":139,"total_tokens":3120,"prompt_tokens_details":{"cached_tokens":2880}}}`))
	if got := s.Usage().CachedTokens(); got != 2880 {
		t.Fatalf("cached = %d, want 2880", got)
	}
	// DeepSeek top-level shape.
	ds := NewChatToolCallStitcher(nil)
	ds.Observe([]byte(`{"choices":[],"usage":{"prompt_tokens":100,"completion_tokens":10,"total_tokens":110,"prompt_cache_hit_tokens":80,"prompt_cache_miss_tokens":20}}`))
	if got := ds.Usage().CachedTokens(); got != 80 {
		t.Fatalf("deepseek cached = %d, want 80", got)
	}
}

// TestChatStitcher_UsageOnFinishOnlyChunk is the GLM variant where the final
// chunk carries finish_reason + usage but no content delta. It still must be
// captured (SawUsage) yet stay non-droppable (SawUsageChunk false), because
// the chunk is the client's terminal finish_reason — stripping it would leave
// the client without a stop signal.
func TestChatStitcher_UsageOnFinishOnlyChunk(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	c := s.Observe([]byte(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`))
	if c != FrameTerminal {
		t.Fatalf("finish-only chunk: got %v, want FrameTerminal", c)
	}
	if !s.SawUsage() {
		t.Fatalf("expected SawUsage true on finish-only combined chunk")
	}
	if s.SawUsageChunk() {
		t.Fatalf("finish-only combined chunk must NOT be droppable")
	}
	if u := s.Usage(); u.PromptTokens != 7 || u.CompletionTokens != 3 {
		t.Fatalf("bad usage: %+v", u)
	}
}

// TestChatStitcher_InterimUsageIgnored guards the billing invariant: a
// mid-stream content chunk that carries a partial usage object but no
// finish_reason must NOT be captured, or the receipt could bill off an
// interim count.
func TestChatStitcher_InterimUsageIgnored(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	c := s.Observe([]byte(`{"choices":[{"index":0,"delta":{"content":"x"}}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`))
	if c != FrameContent {
		t.Fatalf("interim chunk: got %v, want FrameContent", c)
	}
	if s.SawUsage() {
		t.Fatalf("interim usage (no finish_reason) must not be captured")
	}
	if u := s.Usage(); u.PromptTokens != 0 || u.CompletionTokens != 0 {
		t.Fatalf("interim usage leaked into totals: %+v", u)
	}
}

func TestIsBuiltinToolType(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"zs_web_search", true},
		{"zs_", true},
		{"function", false},
		{"web_search", false},
		{"zs", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsBuiltinToolType(c.in); got != c.want {
			t.Fatalf("IsBuiltinToolType(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

// chatDeltaContent decodes a synthetic chat delta frame produced by
// MarshalChatCitationsContentDelta and returns the
// choices[0].delta.content string. Useful for assertions that need
// post-JSON-decode bytes (so HTML-escaped `<` / `>` round-trip cleanly).
func chatDeltaContent(t *testing.T, payload []byte) string {
	t.Helper()
	var out struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("unmarshal chat delta: %v", err)
	}
	if len(out.Choices) == 0 {
		t.Fatalf("no choices in payload: %s", payload)
	}
	return out.Choices[0].Delta.Content
}

func TestMarshalChatCitationsContentDelta_Empty(t *testing.T) {
	payload, ok, err := MarshalChatCitationsContentDelta(nil)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if ok || payload != nil {
		t.Fatalf("expected ok=false on nil effects, got ok=%v payload=%s", ok, payload)
	}

	payload, ok, err = MarshalChatCitationsContentDelta([]ToolEffect{{}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if ok || payload != nil {
		t.Fatalf("expected ok=false on empty effect, got ok=%v payload=%s", ok, payload)
	}
}

func TestMarshalChatCitationsContentDelta_Shape(t *testing.T) {
	effects := []ToolEffect{{
		Citations: []CitationEffect{
			{URL: "https://a.example", Title: "Alpha"},
			{URL: "https://b.example", Title: "Beta"},
		},
	}}
	payload, ok, err := MarshalChatCitationsContentDelta(effects)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !ok {
		t.Fatalf("expected ok=true, got ok=false")
	}
	var out struct {
		Choices []struct {
			Index int `json:"index"`
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(payload, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Choices) != 1 {
		t.Fatalf("expected 1 choice, got %d", len(out.Choices))
	}
	if out.Choices[0].Index != 0 {
		t.Fatalf("expected index=0, got %d", out.Choices[0].Index)
	}
	body := out.Choices[0].Delta.Content
	if !strings.Contains(body, "**Sources:**") {
		t.Fatalf("expected Sources heading: %q", body)
	}
	if !strings.Contains(body, "1. [Alpha](<https://a.example>)") {
		t.Fatalf("expected first citation in body: %q", body)
	}
	if !strings.Contains(body, "2. [Beta](<https://b.example>)") {
		t.Fatalf("expected second citation in body: %q", body)
	}
	if !strings.HasPrefix(body, "\n\n**Sources:**") {
		t.Fatalf("expected leading separator before Sources heading: %q", body)
	}
}

func TestMarshalChatCitationsContentDelta_TitleFallback(t *testing.T) {
	effects := []ToolEffect{{
		Citations: []CitationEffect{{URL: "https://x.example/page"}},
	}}
	payload, ok, err := MarshalChatCitationsContentDelta(effects)
	if err != nil || !ok {
		t.Fatalf("marshal: ok=%v err=%v", ok, err)
	}
	// Inspect the post-decode content. `<` / `>` in the JSON wire form
	// are HTML-escaped to `<` / `>` by encoding/json's default
	// marshaler; clients see the raw chars after decode either way.
	content := chatDeltaContent(t, payload)
	if !strings.Contains(content, "[https://x.example/page](<https://x.example/page>)") {
		t.Fatalf("expected URL used as link text when title empty: %q", content)
	}
}

func TestMarshalChatCitationsContentDelta_DedupByURL(t *testing.T) {
	effects := []ToolEffect{
		{Citations: []CitationEffect{{URL: "https://x", Title: "First"}}},
		{Citations: []CitationEffect{{URL: "https://x", Title: "Second"}}},
		{Citations: []CitationEffect{{URL: "https://y", Title: "Y"}}},
	}
	payload, ok, err := MarshalChatCitationsContentDelta(effects)
	if err != nil || !ok {
		t.Fatalf("marshal: ok=%v err=%v", ok, err)
	}
	content := chatDeltaContent(t, payload)
	// First-seen title preserved.
	if !strings.Contains(content, "[First](<https://x>)") {
		t.Fatalf("expected first-seen title preserved: %q", content)
	}
	if strings.Contains(content, "[Second](<https://x>)") {
		t.Fatalf("expected duplicate URL dropped: %q", content)
	}
	// Second URL still present.
	if !strings.Contains(content, "[Y](<https://y>)") {
		t.Fatalf("expected second unique URL present: %q", content)
	}
	// Numbered sequentially after dedup.
	if !strings.Contains(content, "1. [First](<https://x>)") || !strings.Contains(content, "2. [Y](<https://y>)") {
		t.Fatalf("expected sequential numbering after dedup: %q", content)
	}
}

func TestMarshalChatCitationsContentDelta_EscapesParensAndBrackets(t *testing.T) {
	effects := []ToolEffect{{
		Citations: []CitationEffect{
			{URL: "https://en.wikipedia.org/wiki/Python_(programming_language)", Title: "[Updated] Python"},
		},
	}}
	payload, ok, err := MarshalChatCitationsContentDelta(effects)
	if err != nil || !ok {
		t.Fatalf("marshal: ok=%v err=%v", ok, err)
	}
	content := chatDeltaContent(t, payload)
	// Angle-bracket form preserves inner parens that would otherwise
	// terminate the link destination.
	if !strings.Contains(content, "(<https://en.wikipedia.org/wiki/Python_(programming_language)>)") {
		t.Fatalf("expected angle-bracket URL preserving parens: %q", content)
	}
	// `[` and `]` in title must both be escaped so the bracketed
	// prefix doesn't open a nested link or close the text segment.
	if !strings.Contains(content, `[\[Updated\] Python]`) {
		t.Fatalf("expected escaped brackets in title: %q", content)
	}
	// Sanity: the un-escaped form (would mis-parse) must not appear.
	if strings.Contains(content, "(https://en.wikipedia.org/wiki/Python_(programming_language))") {
		t.Fatalf("found bare-paren URL form — would break parsing: %q", content)
	}
}

func TestMarshalChatCitationsContentDelta_AllEmptyURLs(t *testing.T) {
	effects := []ToolEffect{{
		Citations: []CitationEffect{{URL: "", Title: "no-url"}},
	}}
	payload, ok, err := MarshalChatCitationsContentDelta(effects)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if ok || payload != nil {
		t.Fatalf("expected empty result when no usable URLs, got ok=%v payload=%s", ok, payload)
	}
}

func TestTrimChatContentDeltaLeadingSpace_NoLeadingSpace(t *testing.T) {
	frame := []byte(`{"choices":[{"index":0,"delta":{"content":"hello"}}]}`)
	trimmed, drop, err := TrimChatContentDeltaLeadingSpace(frame)
	if err != nil {
		t.Fatalf("trim: %v", err)
	}
	if drop || trimmed != nil {
		t.Fatalf("expected no-op for non-whitespace prefix, got trimmed=%s drop=%v", trimmed, drop)
	}
}

func TestTrimChatContentDeltaLeadingSpace_TrimsLeading(t *testing.T) {
	frame := []byte(`{"choices":[{"index":0,"delta":{"content":"\n\n  Hello"}}]}`)
	trimmed, drop, err := TrimChatContentDeltaLeadingSpace(frame)
	if err != nil {
		t.Fatalf("trim: %v", err)
	}
	if drop {
		t.Fatalf("expected drop=false on partial-whitespace content")
	}
	if trimmed == nil {
		t.Fatalf("expected trimmed bytes, got nil")
	}
	var out struct {
		Choices []struct {
			Delta struct {
				Content string `json:"content"`
			} `json:"delta"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(trimmed, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Choices[0].Delta.Content != "Hello" {
		t.Fatalf("expected trimmed content 'Hello', got %q", out.Choices[0].Delta.Content)
	}
}

func TestTrimChatContentDeltaLeadingSpace_DropsAllWhitespace(t *testing.T) {
	frame := []byte(`{"choices":[{"index":0,"delta":{"content":"\n\n  "}}]}`)
	trimmed, drop, err := TrimChatContentDeltaLeadingSpace(frame)
	if err != nil {
		t.Fatalf("trim: %v", err)
	}
	if !drop {
		t.Fatalf("expected drop=true on all-whitespace content, got drop=%v trimmed=%s", drop, trimmed)
	}
}

func TestTrimChatContentDeltaLeadingSpace_Tolerates(t *testing.T) {
	cases := []struct {
		name  string
		frame []byte
	}{
		{"malformed", []byte(`not json`)},
		{"no choices", []byte(`{}`)},
		{"empty choices", []byte(`{"choices":[]}`)},
		{"no delta", []byte(`{"choices":[{"index":0}]}`)},
		{"no content field", []byte(`{"choices":[{"index":0,"delta":{"role":"assistant"}}]}`)},
		{"null content", []byte(`{"choices":[{"index":0,"delta":{"content":null}}]}`)},
		{"empty content", []byte(`{"choices":[{"index":0,"delta":{"content":""}}]}`)},
		{"non-string content", []byte(`{"choices":[{"index":0,"delta":{"content":[{"type":"text","text":"x"}]}}]}`)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			trimmed, drop, err := TrimChatContentDeltaLeadingSpace(c.frame)
			if err != nil {
				t.Fatalf("trim: %v", err)
			}
			if drop {
				t.Fatalf("expected drop=false for tolerated frame")
			}
			if trimmed != nil {
				t.Fatalf("expected trimmed=nil for tolerated frame, got %s", trimmed)
			}
		})
	}
}

// TestChatStitcher_ExtraContentRoundTrips covers the Gemini-via-Vertex
// thought_signature passthrough: the opaque extra_content rides one delta,
// the args ride another (OpenAI-shape fragmentation), and the reconstructed
// assistant message must replay extra_content verbatim on the tool_call or
// Gemini 3 rejects the next iteration with a 400 "missing thought_signature".
func TestChatStitcher_ExtraContentRoundTrips(t *testing.T) {
	s := NewChatToolCallStitcher(nil) // exercises AssistantMessage() directly — the reconstruction path the loop uses on a hayai-tool round
	frames := []string{
		`{"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"function-call-1","type":"function","function":{"name":"web_search"},"extra_content":{"google":{"thought_signature":"CjIBjz1rXz<opaque>"}}}]}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"q\":\"algo\"}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	}
	for _, f := range frames {
		s.Observe([]byte(f))
	}
	calls := s.ToolCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if len(calls[0].Extra) == 0 {
		t.Fatalf("ToolCall.Extra not captured")
	}
	if !strings.Contains(string(calls[0].Extra), "thought_signature") {
		t.Fatalf("Extra missing thought_signature: %s", calls[0].Extra)
	}
	// The reconstructed assistant message must carry extra_content back.
	am := s.AssistantMessage()
	var msg struct {
		ToolCalls []struct {
			Function struct {
				Name string `json:"name"`
			} `json:"function"`
			ExtraContent struct {
				Google struct {
					ThoughtSignature string `json:"thought_signature"`
				} `json:"google"`
			} `json:"extra_content"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(am, &msg); err != nil {
		t.Fatalf("assistant message did not parse: %v\n%s", err, am)
	}
	if len(msg.ToolCalls) != 1 {
		t.Fatalf("expected 1 tool_call in assistant msg, got %d", len(msg.ToolCalls))
	}
	if msg.ToolCalls[0].ExtraContent.Google.ThoughtSignature != "CjIBjz1rXz<opaque>" {
		t.Fatalf("thought_signature not replayed: %s", am)
	}
}

// TestChatStitcher_NoExtraContentByteIdentical guards the regression promise:
// a tool call with no extra_content must produce an assistant message that
// does NOT carry the key (byte-identical replay for every non-Gemini provider).
func TestChatStitcher_NoExtraContentByteIdentical(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	frames := []string{
		`{"choices":[{"index":0,"delta":{"role":"assistant","tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	}
	for _, f := range frames {
		s.Observe([]byte(f))
	}
	if c := s.ToolCalls(); len(c) != 1 || len(c[0].Extra) != 0 {
		t.Fatalf("expected 1 call with empty Extra, got %+v", c)
	}
	am := s.AssistantMessage()
	if strings.Contains(string(am), "extra_content") {
		t.Fatalf("assistant msg must not carry extra_content when none was seen: %s", am)
	}
}

func TestClampChatInputImages_NoOpCases(t *testing.T) {
	twoImages := []byte(`{"messages":[{"role":"user","content":[` +
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}},` +
		`{"type":"image_url","image_url":{"url":"data:image/png;base64,BBBB"}}]}]}`)

	cases := []struct {
		name string
		body []byte
		max  int
	}{
		{"max<=0 is uncapped", twoImages, 0},
		{"already within cap", twoImages, 2},
		{"cap above count", twoImages, 5},
		{"string content carries no image", []byte(`{"messages":[{"role":"user","content":"just text"}]}`), 1},
		{"absent messages", []byte(`{"model":"m"}`), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, dropped, err := ClampChatInputImages(tc.body, tc.max)
			if err != nil {
				t.Fatalf("clamp: %v", err)
			}
			if dropped != 0 {
				t.Errorf("dropped = %d, want 0", dropped)
			}
			if string(out) != string(tc.body) {
				t.Errorf("body changed:\n got %s\nwant %s", out, tc.body)
			}
		})
	}
}

func TestClampChatInputImages_DropsOldestKeepsNewest(t *testing.T) {
	// Three images across two user turns; cap 2 ⇒ drop the single oldest (OLD1).
	body := []byte(`{"messages":[` +
		`{"role":"user","content":[{"type":"text","text":"first"},{"type":"image_url","image_url":{"url":"data:image/png;base64,OLD1"}}]},` +
		`{"role":"user","content":[{"type":"text","text":"second"},{"type":"image_url","image_url":{"url":"data:image/png;base64,MID2"}},{"type":"image_url","image_url":{"url":"data:image/png;base64,NEW3"}}]}]}`)

	out, dropped, err := ClampChatInputImages(body, 2)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	s := string(out)
	if n := strings.Count(s, `"type":"image_url"`); n != 2 {
		t.Fatalf("image part count = %d, want 2:\n%s", n, s)
	}
	if strings.Contains(s, "OLD1") {
		t.Errorf("oldest image OLD1 should be dropped:\n%s", s)
	}
	if !strings.Contains(s, "MID2") || !strings.Contains(s, "NEW3") {
		t.Errorf("newer images MID2/NEW3 should be kept:\n%s", s)
	}
	// Sibling text on the trimmed first turn must survive (it's not an image).
	if !strings.Contains(s, `"first"`) || !strings.Contains(s, `"second"`) {
		t.Errorf("sibling text dropped:\n%s", s)
	}
}

func TestClampChatInputImages_RemovesEmptiedMessage(t *testing.T) {
	// First turn is image-only — dropping its image empties the message, so the
	// whole message is removed rather than left with an empty content array.
	body := []byte(`{"messages":[` +
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,OLD"}}]},` +
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,NEW"}}]}]}`)

	out, dropped, err := ClampChatInputImages(body, 1)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	var parsed struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Messages) != 1 {
		t.Fatalf("messages = %d, want 1 (emptied message removed): %s", len(parsed.Messages), out)
	}
	if strings.Contains(string(out), "OLD") || !strings.Contains(string(out), "NEW") {
		t.Errorf("expected only NEW to remain: %s", out)
	}
}

func TestClampChatInputImages_PreservesToolMessageImages(t *testing.T) {
	// A tool-role message carries an image (a client-executed multimodal tool
	// result replayed in history). Images are counted across all roles, but only
	// user images are shed — so the surplus is covered by dropping the oldest
	// USER image (OLD), and the tool message (MID) plus its assistant tool_call
	// adjacency survive untouched.
	body := []byte(`{"messages":[` +
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,OLD"}}]},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"c1","type":"function","function":{"name":"foo","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"c1","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,MID"}}]},` +
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,NEW"}}]}]}`)

	out, dropped, err := ClampChatInputImages(body, 2)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	s := string(out)
	if strings.Contains(s, "OLD") {
		t.Errorf("oldest USER image should be dropped:\n%s", s)
	}
	if !strings.Contains(s, "MID") {
		t.Errorf("tool-message image must be preserved (never shed):\n%s", s)
	}
	if !strings.Contains(s, "NEW") {
		t.Errorf("newest user image should be kept:\n%s", s)
	}
	// The tool message and its assistant tool_call binding must survive so the
	// upstream doesn't reject on tool-call adjacency.
	if !strings.Contains(s, `"tool_call_id":"c1"`) || !strings.Contains(s, `"role":"tool"`) {
		t.Errorf("tool message / tool_call adjacency broken:\n%s", s)
	}
}

func TestClampChatInputImages_OnlyToolImages_NoDrop(t *testing.T) {
	// Both over-cap images live in tool messages — there is nothing user-side to
	// shed, so dropped is 0 (the caller won't retry, and the upstream 400 is
	// forwarded, no worse than the un-clamped case).
	body := []byte(`{"messages":[` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"a","type":"function","function":{"name":"f","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"a","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]},` +
		`{"role":"assistant","content":null,"tool_calls":[{"id":"b","type":"function","function":{"name":"f","arguments":"{}"}}]},` +
		`{"role":"tool","tool_call_id":"b","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,BBBB"}}]}]}`)

	_, dropped, err := ClampChatInputImages(body, 1)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0 (no user images to shed)", dropped)
	}
}

func TestClampChatInputImages_PreservesSystemAndText(t *testing.T) {
	// A leading system message (string content) and a text-only user turn must
	// survive untouched; only the oldest image is shed.
	body := []byte(`{"messages":[` +
		`{"role":"system","content":"be helpful"},` +
		`{"role":"user","content":[{"type":"text","text":"look"},{"type":"image_url","image_url":{"url":"data:image/png;base64,OLD"}}]},` +
		`{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,NEW"}}]}]}`)

	out, dropped, err := ClampChatInputImages(body, 1)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	s := string(out)
	if !strings.Contains(s, "be helpful") {
		t.Errorf("system message dropped:\n%s", s)
	}
	if !strings.Contains(s, `"look"`) {
		t.Errorf("text sibling on trimmed turn dropped:\n%s", s)
	}
	if strings.Contains(s, "OLD") || !strings.Contains(s, "NEW") {
		t.Errorf("expected only NEW image to remain:\n%s", s)
	}
}

// A reasoning model that carries state across tool calls needs its own
// chain-of-thought echoed back on the replayed assistant turn. z.ai documents
// that the "complete, unmodified reasoning_content" must be returned; without
// it GLM loses its plan after every action and narrates the tool protocol as
// prose instead of emitting structured calls.
func TestChatStitcher_ReasoningContentReplayed(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	frames := []string{
		`{"choices":[{"index":0,"delta":{"role":"assistant","reasoning_content":"The user wants weather. "}}]}`,
		`{"choices":[{"index":0,"delta":{"reasoning_content":"I should call the tool."}}]}`,
		`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{}"}}]}}]}`,
		`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
	}
	for _, f := range frames {
		s.Observe([]byte(f))
	}
	var msg struct {
		ReasoningContent string `json:"reasoning_content"`
	}
	am := s.AssistantMessage()
	if err := json.Unmarshal(am, &msg); err != nil {
		t.Fatalf("assistant message did not parse: %v\n%s", err, am)
	}
	// Fragments must concatenate in order and byte-exactly — the echo has to
	// match the sequence the model generated.
	if want := "The user wants weather. I should call the tool."; msg.ReasoningContent != want {
		t.Fatalf("reasoning_content = %q, want %q", msg.ReasoningContent, want)
	}
}

// Current vLLM and OpenRouter spell the same string field `reasoning`.
func TestChatStitcher_ReasoningFieldReplayed(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	s.Observe([]byte(`{"choices":[{"index":0,"delta":{"role":"assistant","reasoning":"step one"}}]}`))
	s.Observe([]byte(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`))
	var msg struct {
		ReasoningContent string `json:"reasoning_content"`
	}
	if err := json.Unmarshal(s.AssistantMessage(), &msg); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if msg.ReasoningContent != "step one" {
		t.Fatalf("reasoning_content = %q, want %q", msg.ReasoningContent, "step one")
	}
}

// Byte-identical-replay guard: a provider that sends no reasoning must produce
// an assistant message with no reasoning_content key at all.
func TestChatStitcher_NoReasoningByteIdentical(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	s.Observe([]byte(`{"choices":[{"index":0,"delta":{"role":"assistant","content":"hello"}}]}`))
	s.Observe([]byte(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`))
	am := string(s.AssistantMessage())
	if strings.Contains(am, "reasoning") {
		t.Fatalf("non-reasoning provider gained a reasoning key: %s", am)
	}
}

// The replay contract is byte-exactness, so a shape with no faithful string
// rendering (OpenRouter's reasoning_details array, an encrypted blob) is
// skipped rather than flattened — echoing altered thinking is worse than
// echoing none.
func TestChatStitcher_StructuredReasoningNotReplayed(t *testing.T) {
	for name, frame := range map[string]string{
		"array":     `{"choices":[{"index":0,"delta":{"reasoning":[{"type":"reasoning.text","text":"x"}]}}]}`,
		"object":    `{"choices":[{"index":0,"delta":{"reasoning":{"text":"x"}}}]}`,
		"encrypted": `{"choices":[{"index":0,"delta":{"reasoning":{"type":"reasoning.encrypted","data":"AAAA"}}}]}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := NewChatToolCallStitcher(nil)
			s.Observe([]byte(frame))
			s.Observe([]byte(`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`))
			if am := string(s.AssistantMessage()); strings.Contains(am, "reasoning_content") {
				t.Fatalf("structured reasoning was flattened into the echo: %s", am)
			}
		})
	}
}

// Capture must not perturb frame classification. A reasoning-only delta
// carries no visible output, so it has to keep classifying exactly as it did
// before this capture existed — the streaming tool loop's buffer/forward
// behavior hangs off these values.
func TestChatStitcher_ReasoningDeltaClassificationUnchanged(t *testing.T) {
	s := NewChatToolCallStitcher(nil)
	if got := s.Observe([]byte(`{"choices":[{"index":0,"delta":{"reasoning_content":"thinking"}}]}`)); got != FrameUnknown {
		t.Fatalf("reasoning-only delta classified %v, want FrameUnknown", got)
	}
	// A delta carrying both still classifies on its visible content.
	if got := s.Observe([]byte(`{"choices":[{"index":0,"delta":{"reasoning_content":"more","content":"hi"}}]}`)); got != FrameContent {
		t.Fatalf("content+reasoning delta classified %v, want FrameContent", got)
	}
}
