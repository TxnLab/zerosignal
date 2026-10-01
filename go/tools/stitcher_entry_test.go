/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"testing"
)

// feed pushes a sequence of Responses SSE frame bodies through the stitcher.
func feed(s *ResponsesToolCallStitcher, frames ...string) {
	for _, f := range frames {
		s.Observe([]byte(f))
	}
}

// TestResponsesStitcher_ArgumentsOnlyCallIsStitched covers the backend that
// skips response.output_item.added entirely and publishes a function call only
// through function_call_arguments.delta/.done — the case the delta handler's
// "function_call" seed exists for.
//
// entryFor seeds ItemType on CREATION ONLY, so if the delta seed were empty the
// entry would keep an empty type forever: .done does not repair it, ToolCalls()
// filters it out (never dispatched), and the OutputItems() synthesis branch
// skips it too (`e.ItemType != "function_call"`). The tool call vanishes
// silently and the loop reports zero iterations. Nothing exercised this path —
// the whole synthesis branch was uncovered.
// Each subtest feeds ONE argument frame and nothing else. That isolation is the
// point: any later output_item.added/.done writes ItemType directly and repairs
// the entry, so a fixture that includes one cannot tell what the seed was.
func TestResponsesStitcher_ArgumentsOnlyCallIsStitched(t *testing.T) {
	for _, c := range []struct {
		name  string
		frame string
	}{
		{"delta seeds the type", `{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"query\":\"cats\"}"}`},
		{"done seeds the type", `{"type":"response.function_call_arguments.done","item_id":"fc_1","arguments":"{\"query\":\"cats\"}"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := NewResponsesToolCallStitcher(map[string]BuiltinToolType{})
			feed(s, c.frame)

			calls := s.ToolCalls()
			if len(calls) != 1 {
				t.Fatalf("ToolCalls() = %d, want 1 — the entry must be typed function_call from the seed alone, "+
					"or the call is filtered out of both ToolCalls() and OutputItems() and vanishes", len(calls))
			}
			if calls[0].Arguments != `{"query":"cats"}` {
				t.Errorf("arguments = %q, want the stitched value", calls[0].Arguments)
			}
		})
	}
}

// TestResponsesStitcher_ArgumentsOnlyCall_SynthesizesOutputItem is the same
// backend shape with NO terminal item at all, which is the only way to reach
// the OutputItems() synthesis branch. It needs a name and call_id, which for
// this shape can only come from the delta stream's own item id.
func TestResponsesStitcher_ArgumentsOnlyCall_SynthesizesOutputItem(t *testing.T) {
	s := NewResponsesToolCallStitcher(map[string]BuiltinToolType{})
	feed(s,
		`{"type":"response.output_item.added","item":{"call_id":"call_9","type":"function_call","name":"lookup"}}`,
		`{"type":"response.function_call_arguments.delta","item_id":"call_9","delta":"{\"q\":1}"}`,
	)
	items := s.OutputItems()
	if len(items) != 1 {
		t.Fatalf("OutputItems() = %d, want 1", len(items))
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(items[0], &got); err != nil {
		t.Fatalf("parse synthesized item: %v", err)
	}
	if string(got["type"]) != `"function_call"` {
		t.Errorf("synthesized type = %s, want \"function_call\"", got["type"])
	}
}

// TestResponsesStitcher_TerminalOnlyItemIsNotAToolCall pins that an item first
// seen on the terminal overlay is NOT typed as a function call.
//
// The overlay's entryFor seed is deliberately "" — a message or reasoning item
// surfacing only at response.completed must be replayed but never dispatched.
// Seeding "function_call" there emits a phantom call with an empty Name and
// empty CallID, and the existing terminal-only test passes anyway because it
// only checks the item survives in OutputItems(), never that it stayed out of
// ToolCalls().
func TestResponsesStitcher_TerminalOnlyItemIsNotAToolCall(t *testing.T) {
	s := NewResponsesToolCallStitcher(map[string]BuiltinToolType{})
	feed(s, `{"type":"response.completed","response":{"output":[`+
		`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"output_text","text":"hello"}]}`+
		`]}}`)

	if calls := s.ToolCalls(); len(calls) != 0 {
		t.Errorf("ToolCalls() = %+v, want none — a terminal-only message is not a tool call", calls)
	}
	if len(s.OutputItems()) != 1 {
		t.Errorf("OutputItems() = %d, want 1 — the message must still be replayed", len(s.OutputItems()))
	}
}

// TestResponsesStitcher_DoneItemOverwritesAddedItem pins the "latest wins"
// precedence documented on responsesStitchEntry.Raw. Only the terminal-overlay
// leg of that ordering was tested.
//
// A backend that emits output_item.added with empty arguments and then
// output_item.done with the complete ones is ordinary; a first-wins Raw replays
// the PARTIAL item on the next turn — no arguments, and no provider-opaque
// extra_content (Gemini's thought_signature) — which is a silent wrong-replay
// rather than a crash.
func TestResponsesStitcher_DoneItemOverwritesAddedItem(t *testing.T) {
	s := NewResponsesToolCallStitcher(map[string]BuiltinToolType{})
	feed(s,
		`{"type":"response.output_item.added","item":{"id":"fc_2","type":"function_call","call_id":"call_2","name":"lookup","arguments":""}}`,
		`{"type":"response.output_item.done","item":{"id":"fc_2","type":"function_call","call_id":"call_2","name":"lookup","arguments":"{\"q\":\"final\"}"}}`,
	)
	items := s.OutputItems()
	if len(items) != 1 {
		t.Fatalf("OutputItems() = %d, want 1", len(items))
	}
	var got struct {
		Arguments string `json:"arguments"`
	}
	if err := json.Unmarshal(items[0], &got); err != nil {
		t.Fatalf("parse replayed item: %v", err)
	}
	if got.Arguments != `{"q":"final"}` {
		t.Errorf("replayed arguments = %q, want the .done value — Raw must be latest-wins", got.Arguments)
	}
}
