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

func TestRewriteBuiltinToolsResponses_RewritesBuiltin(t *testing.T) {
	body := []byte(`{"model":"gpt-4","input":"hi","tools":[{"type":"zs_web_search"}]}`)
	got, names, err := RewriteBuiltinToolsResponses(body, sampleDefs())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(names) != 1 {
		t.Fatalf("expected 1 hayai name, got %+v", names)
	}
	var out struct {
		Tools []struct {
			Type        string          `json:"type"`
			Name        string          `json:"name"`
			Description string          `json:"description"`
			Parameters  json.RawMessage `json:"parameters"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Tools) != 1 {
		t.Fatalf("expected 1 tool, got %d", len(out.Tools))
	}
	tool := out.Tools[0]
	if tool.Type != "function" {
		t.Fatalf("expected type=function, got %q", tool.Type)
	}
	if tool.Name != "zs_web_search" {
		t.Fatalf("expected name hoisted to top level, got %q", tool.Name)
	}
	if tool.Description == "" {
		t.Fatalf("expected description present")
	}
	if len(tool.Parameters) == 0 {
		t.Fatalf("expected parameters present")
	}
}

func TestRewriteBuiltinToolsResponses_UnknownTypeErrors(t *testing.T) {
	body := []byte(`{"tools":[{"type":"zs_bogus"}]}`)
	_, _, err := RewriteBuiltinToolsResponses(body, sampleDefs())
	if !errors.Is(err, ErrUnknownBuiltinTool) {
		t.Fatalf("expected ErrUnknownBuiltinTool, got %v", err)
	}
}

func TestRewriteBuiltinToolsResponses_NoToolsIsNoop(t *testing.T) {
	body := []byte(`{"input":"hi"}`)
	got, names, err := RewriteBuiltinToolsResponses(body, sampleDefs())
	if err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if len(names) != 0 {
		t.Fatalf("expected no names")
	}
	if string(got) != string(body) {
		t.Fatalf("expected noop")
	}
}

func TestExtractToolCallsResponses_FunctionCallItems(t *testing.T) {
	resp := []byte(`{"status":"completed","output":[{"id":"item_a","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]},{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":"{\"query\":\"x\"}"}]}`)
	items, calls, status, err := ExtractToolCallsResponses(resp)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if status != "completed" {
		t.Fatalf("expected status completed, got %q", status)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 output items, got %d", len(items))
	}
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].ID != "call_1" || calls[0].Name != "zs_web_search" {
		t.Fatalf("bad call: %+v", calls[0])
	}
}

func TestSanitizeIncompleteBuiltinCallsResponses(t *testing.T) {
	resp := []byte(`{"status":"incomplete","output":[` +
		`{"id":"msg","type":"message","role":"assistant","content":[]},` +
		`{"id":"drop_empty","type":"function_call","call_id":"drop_empty","name":"zs_web_search","arguments":""},` +
		`{"id":"keep_complete","type":"function_call","call_id":"keep_complete","name":"zs_web_search","arguments":"{}"},` +
		`{"id":"drop_partial","type":"function_call","call_id":"drop_partial","name":"zs_web_search","arguments":"{\"query\":"},` +
		`{"id":"keep_client","type":"function_call","call_id":"keep_client","name":"client_tool","arguments":""}]}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsResponses(resp, names, true)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	items, calls, _, err := ExtractToolCallsResponses(got)
	if err != nil {
		t.Fatalf("extract sanitized response: %v", err)
	}
	if len(items) != 3 || len(calls) != 2 || calls[0].ID != "keep_complete" || calls[1].ID != "keep_client" {
		t.Fatalf("items/calls = %d/%+v, want message + complete builtin + client call", len(items), calls)
	}
	if strings.Contains(string(got), "drop_empty") || strings.Contains(string(got), "drop_partial") {
		t.Fatalf("dropped calls remain in replay output: %s", got)
	}
}

// A terminal event repeats the round's whole output snapshot, so the dropped
// call has to be stripped there too — while status/usage/incomplete_details,
// which describe a legitimate outcome, survive untouched.
func TestSanitizeIncompleteBuiltinCallsResponsesEvent(t *testing.T) {
	frame := []byte(`{"type":"response.incomplete","response":{"status":"incomplete",` +
		`"incomplete_details":{"reason":"max_output_tokens"},` +
		`"usage":{"input_tokens":20,"output_tokens":10,"total_tokens":30},"output":[` +
		`{"id":"msg","type":"message","role":"assistant","content":[]},` +
		`{"id":"drop","type":"function_call","call_id":"drop","name":"zs_web_search","arguments":""},` +
		`{"id":"keep_client","type":"function_call","call_id":"keep_client","name":"client_tool","arguments":""}]}}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsResponsesEvent(frame, names, true)
	if err != nil {
		t.Fatalf("sanitize event: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	if strings.Contains(string(got), "zs_web_search") {
		t.Fatalf("built-in call survived in the terminal snapshot: %s", got)
	}
	for _, keep := range []string{`"status":"incomplete"`, `"reason":"max_output_tokens"`, `"total_tokens":30`, "client_tool", `"type":"response.incomplete"`} {
		if !strings.Contains(string(got), keep) {
			t.Errorf("sanitizing the snapshot lost %s: %s", keep, got)
		}
	}
}

// A terminal with nothing to drop must come back byte-identical, so the
// ordinary path never pays a re-marshal or risks reordering keys.
func TestSanitizeIncompleteBuiltinCallsResponsesEvent_NoOpIsByteIdentical(t *testing.T) {
	frame := []byte(`{"type":"response.completed","response":{"status":"completed","output":[` +
		`{"id":"fc","type":"function_call","call_id":"fc","name":"zs_web_search","arguments":"{}"}]}}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsResponsesEvent(frame, names, true)
	if err != nil {
		t.Fatalf("sanitize event: %v", err)
	}
	if dropped != 0 {
		t.Fatalf("dropped = %d, want 0", dropped)
	}
	if string(got) != string(frame) {
		t.Fatalf("no-op rewrote the frame:\n got %s\nwant %s", got, frame)
	}
}

// The Responses twin of the untruncated case: status "completed" means the
// model finished, so an empty-argument call is a zero-argument call.
func TestSanitizeIncompleteBuiltinCallsResponses_UntruncatedKeepsEmptyArguments(t *testing.T) {
	resp := []byte(`{"status":"completed","output":[` +
		`{"id":"keep_empty","type":"function_call","call_id":"keep_empty","name":"zs_web_search","arguments":""},` +
		`{"id":"drop_partial","type":"function_call","call_id":"drop_partial","name":"zs_web_search","arguments":"{\"query\":"}]}`)
	names := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	got, dropped, err := SanitizeIncompleteBuiltinCallsResponses(resp, names, false)
	if err != nil {
		t.Fatalf("sanitize: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1 — only the unparseable call", dropped)
	}
	_, calls, _, err := ExtractToolCallsResponses(got)
	if err != nil {
		t.Fatalf("extract sanitized response: %v", err)
	}
	if len(calls) != 1 || calls[0].ID != "keep_empty" {
		t.Fatalf("calls = %+v, want the zero-argument call kept", calls)
	}
}

func TestAppendFunctionCallOutputsResponses_AppendsItems(t *testing.T) {
	body := []byte(`{"model":"x","input":[{"role":"user","content":"hi"}]}`)
	assistantItem := json.RawMessage(`{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":"{}"}`)
	results := []ToolResult{{ToolCallID: "call_1", Content: `{"results":[]}`}}
	got, err := AppendFunctionCallOutputsResponses(body, []json.RawMessage{assistantItem}, results)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	var out struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Input) != 3 {
		t.Fatalf("expected 3 input items, got %d: %s", len(out.Input), got)
	}
	var last struct {
		Type   string `json:"type"`
		CallID string `json:"call_id"`
		Output string `json:"output"`
	}
	if err := json.Unmarshal(out.Input[2], &last); err != nil {
		t.Fatalf("unmarshal last item: %v", err)
	}
	if last.Type != "function_call_output" || last.CallID != "call_1" {
		t.Fatalf("bad last item: %+v", last)
	}
	if last.Output != `{"results":[]}` {
		t.Fatalf("bad output: %q", last.Output)
	}
}

func TestAppendFunctionCallOutputsResponses_StringInputNormalized(t *testing.T) {
	body := []byte(`{"input":"hi"}`)
	results := []ToolResult{{ToolCallID: "c", Content: "ok"}}
	got, err := AppendFunctionCallOutputsResponses(body, nil, results)
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	var out struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Input) != 2 {
		t.Fatalf("expected 2 input items, got %d", len(out.Input))
	}
}

func TestClampResponsesInputImages_NoOpCases(t *testing.T) {
	twoImages := []byte(`{"input":[{"role":"user","content":[` +
		`{"type":"input_image","image_url":"data:image/png;base64,AAAA"},` +
		`{"type":"input_image","image_url":"data:image/png;base64,BBBB"}]}]}`)

	cases := []struct {
		name string
		body []byte
		max  int
	}{
		{"max<=0 is uncapped", twoImages, 0},
		{"already within cap", twoImages, 2},
		{"cap above count", twoImages, 5},
		{"string input carries no image", []byte(`{"input":"just text"}`), 1},
		{"absent input", []byte(`{"model":"m"}`), 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, dropped, err := ClampResponsesInputImages(tc.body, tc.max)
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

func TestClampResponsesInputImages_DropsOldestKeepsNewest(t *testing.T) {
	// Three images across two user turns; cap 2 ⇒ drop the single oldest (OLD1).
	body := []byte(`{"input":[` +
		`{"role":"user","content":[{"type":"input_text","text":"first"},{"type":"input_image","image_url":"data:image/png;base64,OLD1"}]},` +
		`{"role":"user","content":[{"type":"input_text","text":"second"},{"type":"input_image","image_url":"data:image/png;base64,MID2"},{"type":"input_image","image_url":"data:image/png;base64,NEW3"}]}]}`)

	out, dropped, err := ClampResponsesInputImages(body, 2)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	s := string(out)
	if n := strings.Count(s, `"input_image"`); n != 2 {
		t.Fatalf("input_image count = %d, want 2:\n%s", n, s)
	}
	if strings.Contains(s, "OLD1") {
		t.Errorf("oldest image OLD1 should be dropped:\n%s", s)
	}
	if !strings.Contains(s, "MID2") || !strings.Contains(s, "NEW3") {
		t.Errorf("newer images MID2/NEW3 should be kept:\n%s", s)
	}
	// Sibling text on the trimmed first turn must survive (it's not an image).
	if !strings.Contains(s, `"first"`) || !strings.Contains(s, `"second"`) {
		t.Errorf("sibling input_text dropped:\n%s", s)
	}
}

func TestClampResponsesInputImages_RemovesEmptiedMessage(t *testing.T) {
	// First turn is image-only — dropping its image empties the message, so the
	// whole item is removed rather than left with an empty content array.
	body := []byte(`{"input":[` +
		`{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,OLD"}]},` +
		`{"role":"user","content":[{"type":"input_image","image_url":"data:image/png;base64,NEW"}]}]}`)

	out, dropped, err := ClampResponsesInputImages(body, 1)
	if err != nil {
		t.Fatalf("clamp: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1", dropped)
	}
	var parsed struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Input) != 1 {
		t.Fatalf("input items = %d, want 1 (emptied message removed): %s", len(parsed.Input), out)
	}
	if strings.Contains(string(out), "OLD") || !strings.Contains(string(out), "NEW") {
		t.Errorf("expected only NEW to remain: %s", out)
	}
}

func TestSetResponsesUsage(t *testing.T) {
	resp := []byte(`{"id":"x","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3}}`)
	got := SetResponsesUsage(resp, 42, 17, 12)
	var out struct {
		Usage ResponsesUsage `json:"usage"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Usage.InputTokens != 42 || out.Usage.OutputTokens != 17 || out.Usage.TotalTokens != 59 {
		t.Fatalf("bad usage: %+v", out.Usage)
	}
	if out.Usage.CachedTokens() != 12 {
		t.Fatalf("cached = %d, want 12 (input_tokens_details.cached_tokens)", out.Usage.CachedTokens())
	}
}

// TestResponsesStitcher_UsageCarriesCachedTokens guards the responses tool-loop
// cached path: the stitcher must decode input_tokens_details.cached_tokens from
// the terminal response.completed event so the node carries it (this is the
// exact z.ai/GLM /v1/responses path that logged cached=0 before the fix).
func TestResponsesStitcher_UsageCarriesCachedTokens(t *testing.T) {
	s := NewResponsesToolCallStitcher(nil)
	s.Observe([]byte(`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":2981,"output_tokens":139,"total_tokens":3120,"input_tokens_details":{"cached_tokens":2880}},"output":[]}}`))
	if got := s.Usage().CachedTokens(); got != 2880 {
		t.Fatalf("cached = %d, want 2880", got)
	}
}

func TestResponsesStitcher_ToolCallOnlyIteration(t *testing.T) {
	builtinNames := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	s := NewResponsesToolCallStitcher(builtinNames)
	events := []string{
		`{"type":"response.created"}`,
		`{"type":"response.output_item.added","item":{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":""}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"item_b","delta":"{\"query\":"}`,
		`{"type":"response.function_call_arguments.delta","item_id":"item_b","delta":"\"algo\"}"}`,
		`{"type":"response.function_call_arguments.done","item_id":"item_b","arguments":"{\"query\":\"algo\"}"}`,
		`{"type":"response.output_item.done","item":{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":"{\"query\":\"algo\"}"}}`,
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15},"output":[{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":"{\"query\":\"algo\"}"}]}}`,
	}
	classes := make([]FrameClassification, len(events))
	for i, e := range events {
		classes[i] = s.Observe([]byte(e))
	}
	if classes[0] != FrameUnknown {
		t.Fatalf("response.created expected FrameUnknown, got %v", classes[0])
	}
	if classes[1] != FrameToolCallBuiltin {
		t.Fatalf("output_item.added(function_call hayai) expected FrameToolCallBuiltin, got %v", classes[1])
	}
	if classes[2] != FrameToolCallBuiltin || classes[3] != FrameToolCallBuiltin || classes[4] != FrameToolCallBuiltin {
		t.Fatalf("arg deltas expected FrameToolCallBuiltin, got %+v", classes[2:5])
	}
	if classes[5] != FrameToolCallBuiltin {
		t.Fatalf("output_item.done(function_call hayai) expected FrameToolCallBuiltin, got %v", classes[5])
	}
	if classes[6] != FrameTerminal {
		t.Fatalf("response.completed expected FrameTerminal, got %v", classes[6])
	}
	if s.Status() != "completed" {
		t.Fatalf("expected status=completed, got %q", s.Status())
	}
	u := s.Usage()
	if u.InputTokens != 10 || u.OutputTokens != 5 {
		t.Fatalf("bad usage: %+v", u)
	}
	calls := s.ToolCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}
	if calls[0].ID != "call_1" || calls[0].Name != "zs_web_search" {
		t.Fatalf("bad call: %+v", calls[0])
	}
	if !strings.Contains(calls[0].Arguments, `"query":"algo"`) {
		t.Fatalf("bad arguments: %q", calls[0].Arguments)
	}
	items := s.OutputItems()
	if len(items) != 1 {
		t.Fatalf("expected 1 output item, got %d", len(items))
	}
}

// TestResponsesStitcher_TerminalReidentifiesToolCall pins the de-dupe for a
// backend that regenerates a tool call's id AND call_id between its
// streaming events and response.completed (observed with a llama.cpp-based
// /v1/responses engine: a chatcmpl-tool-* engine id leaks into the terminal
// event). The same logical call must NOT be re-appended twice — the second
// copy has no function_call_output and orphans the next input[].
func TestResponsesStitcher_TerminalReidentifiesToolCall(t *testing.T) {
	builtinNames := map[string]BuiltinToolType{"zs_image_generation": "zs_image_generation"}
	s := NewResponsesToolCallStitcher(builtinNames)
	events := []string{
		`{"type":"response.output_item.added","item":{"id":"b3f48e58bdd01d74","type":"function_call","call_id":"call_87f2bafc2b2f4c29","name":"zs_image_generation","arguments":""}}`,
		`{"type":"response.function_call_arguments.done","item_id":"b3f48e58bdd01d74","arguments":"{\"prompt\":\"a crab\"}"}`,
		`{"type":"response.output_item.done","item":{"id":"b3f48e58bdd01d74","type":"function_call","call_id":"call_87f2bafc2b2f4c29","name":"zs_image_generation","arguments":"{\"prompt\":\"a crab\"}"}}`,
		// Terminal event re-identifies the SAME call under a fresh id +
		// call_id (the chatcmpl-tool-* engine id leaking through).
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15},"output":[{"id":"fc_9c470684a82cc568","type":"function_call","call_id":"chatcmpl-tool-aa4cced3138ee317","name":"zs_image_generation","arguments":"{\"prompt\":\"a crab\"}"}]}}`,
	}
	for _, e := range events {
		s.Observe([]byte(e))
	}
	calls := s.ToolCalls()
	if len(calls) != 1 || calls[0].ID != "call_87f2bafc2b2f4c29" {
		t.Fatalf("expected 1 executable call (call_87f2bafc2b2f4c29), got %+v", calls)
	}
	items := s.OutputItems()
	if len(items) != 1 {
		t.Fatalf("expected 1 output item (the terminal re-id must not duplicate), got %d: %s", len(items), items)
	}
	// The kept item is the one the tool loop executed and will emit an
	// output for — not the orphaned terminal copy.
	if !strings.Contains(string(items[0]), "call_87f2bafc2b2f4c29") {
		t.Fatalf("kept the wrong item; want the executed call_87f2bafc2b2f4c29: %s", items[0])
	}
}

// TestResponsesStitcher_TerminalRegeneratedReasoningId pins the de-dupe for a
// backend that regenerates a REASONING item's id between its streaming event
// and response.completed (observed with vLLM/Gemma: the same reasoning text is
// streamed under e.g. a92c… and re-emitted on the terminal event under rs_…).
// Without the skip the terminal copy lands at the tail of the order — after the
// already-stitched function_call — duplicating the reasoning and breaking the
// reasoning→call→output order the model expects, which makes it loop.
func TestResponsesStitcher_TerminalRegeneratedReasoningId(t *testing.T) {
	builtinNames := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	s := NewResponsesToolCallStitcher(builtinNames)
	events := []string{
		// Streamed reasoning (no rs_ prefix) BEFORE the call.
		`{"type":"response.output_item.added","item":{"id":"a92c62b240024809","type":"reasoning","summary":[{"type":"summary_text","text":"I should web-search"}]}}`,
		`{"type":"response.output_item.added","item":{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":""}}`,
		`{"type":"response.function_call_arguments.done","item_id":"item_b","arguments":"{\"query\":\"June 2 2026\"}"}`,
		`{"type":"response.output_item.done","item":{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":"{\"query\":\"June 2 2026\"}"}}`,
		// Terminal event re-emits the SAME reasoning text under a fresh,
		// rs_-prefixed id, in correct position before the call in output[].
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":10,"output_tokens":5,"total_tokens":15},"output":[{"id":"rs_ad7b602299b67283","type":"reasoning","status":null,"summary":[{"type":"summary_text","text":"I should web-search"}]},{"id":"item_b","type":"function_call","call_id":"call_1","name":"zs_web_search","arguments":"{\"query\":\"June 2 2026\"}"}]}}`,
	}
	for _, e := range events {
		s.Observe([]byte(e))
	}
	items := s.OutputItems()
	if len(items) != 2 {
		t.Fatalf("expected 2 output items (streamed reasoning + call; the terminal re-id must not duplicate), got %d: %s", len(items), items)
	}
	// Order must be reasoning → function_call, and the duplicate rs_ id must
	// never appear (the streamed a92c… copy is authoritative).
	if !strings.Contains(string(items[0]), "a92c62b240024809") || !strings.Contains(string(items[0]), "reasoning") {
		t.Fatalf("item[0] should be the streamed reasoning a92c…, got %s", items[0])
	}
	if !strings.Contains(string(items[1]), "function_call") {
		t.Fatalf("item[1] should be the function_call, got %s", items[1])
	}
	for _, it := range items {
		if strings.Contains(string(it), "rs_ad7b602299b67283") {
			t.Fatalf("regenerated-id reasoning leaked into output items: %s", it)
		}
	}
}

// TestResponsesStitcher_TerminalOnlyMessageKept guards the other side of the
// overlay skip: a NON-function_call item appearing for the first time on the
// terminal event (a message a backend only emits in response.completed) must
// still be captured for the assistant re-append.
func TestResponsesStitcher_TerminalOnlyMessageKept(t *testing.T) {
	s := NewResponsesToolCallStitcher(nil)
	s.Observe([]byte(`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"output":[{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi","annotations":[]}]}]}}`))
	items := s.OutputItems()
	if len(items) != 1 {
		t.Fatalf("expected the terminal-only message to be captured, got %d items", len(items))
	}
	if !strings.Contains(string(items[0]), "msg_1") {
		t.Fatalf("terminal-only message not captured: %s", items[0])
	}
}

func TestResponsesStitcher_ContentIterationFlipsLive(t *testing.T) {
	s := NewResponsesToolCallStitcher(nil)
	classes := []FrameClassification{
		s.Observe([]byte(`{"type":"response.output_item.added","item":{"id":"m","type":"message","role":"assistant","content":[]}}`)),
		s.Observe([]byte(`{"type":"response.output_text.delta","item_id":"m","delta":"Hel"}`)),
		s.Observe([]byte(`{"type":"response.output_text.delta","item_id":"m","delta":"lo"}`)),
		s.Observe([]byte(`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":2,"total_tokens":3},"output":[]}}`)),
	}
	if classes[0] != FrameUnknown {
		t.Fatalf("output_item.added(message) expected FrameUnknown, got %v", classes[0])
	}
	if classes[1] != FrameContent || classes[2] != FrameContent {
		t.Fatalf("text.delta expected FrameContent, got %+v", classes[1:3])
	}
	if classes[3] != FrameTerminal {
		t.Fatalf("response.completed expected FrameTerminal, got %v", classes[3])
	}
	if len(s.ToolCalls()) != 0 {
		t.Fatalf("expected no tool calls, got %+v", s.ToolCalls())
	}
}

func TestResponsesStitcher_ErrorIsTerminal(t *testing.T) {
	s := NewResponsesToolCallStitcher(nil)
	c := s.Observe([]byte(`{"type":"response.error","error":{"message":"boom"}}`))
	if c != FrameTerminal {
		t.Fatalf("expected FrameTerminal, got %v", c)
	}
}

// TestResponsesStitcher_ExtraContentPreserved covers the Responses-path
// passthrough of provider-opaque per-tool-call state (Gemini's
// extra_content.google.thought_signature). The real mechanism is byte-exact
// re-append of the raw function_call item via OutputItems; this asserts the
// extra_content survives that path and is captured onto ToolCall.Extra.
func TestResponsesStitcher_ExtraContentPreserved(t *testing.T) {
	s := NewResponsesToolCallStitcher(nil) // client tool
	events := []string{
		`{"type":"response.output_item.added","item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"web_search","arguments":"","extra_content":{"google":{"thought_signature":"SIG<opaque>"}}}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"q\":\"algo\"}"}`,
		`{"type":"response.output_item.done","item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"web_search","arguments":"{\"q\":\"algo\"}","extra_content":{"google":{"thought_signature":"SIG<opaque>"}}}}`,
		`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1,"output_tokens":1,"total_tokens":2},"output":[{"id":"fc_1","type":"function_call","call_id":"call_1","name":"web_search","arguments":"{\"q\":\"algo\"}","extra_content":{"google":{"thought_signature":"SIG<opaque>"}}}]}}`,
	}
	for _, e := range events {
		s.Observe([]byte(e))
	}
	calls := s.ToolCalls()
	if len(calls) != 1 || !strings.Contains(string(calls[0].Extra), "thought_signature") {
		t.Fatalf("Extra not captured on ToolCall: %+v", calls)
	}
	items := s.OutputItems()
	if len(items) != 1 {
		t.Fatalf("expected 1 output item, got %d", len(items))
	}
	if !strings.Contains(string(items[0]), "thought_signature") {
		t.Fatalf("re-appended item dropped extra_content: %s", items[0])
	}
}
