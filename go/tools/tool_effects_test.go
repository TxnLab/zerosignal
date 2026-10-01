/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSpliceEffectsResponsesBody_AnnotationsOnLastMessage(t *testing.T) {
	body := []byte(`{"id":"r","output":[` +
		`{"id":"f","type":"function_call","call_id":"c1","name":"zs_web_search","arguments":"{}"},` +
		`{"id":"m","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}` +
		`]}`)
	effects := []ToolEffect{{
		Citations: []CitationEffect{
			{URL: "https://example.com/a", Title: "A"},
			{URL: "https://example.com/b", Title: "B"},
		},
	}}
	got, err := SpliceEffectsResponsesBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Output []struct {
			ID      string `json:"id"`
			Type    string `json:"type"`
			Content []struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Annotations []struct {
					Type  string `json:"type"`
					URL   string `json:"url"`
					Title string `json:"title"`
				} `json:"annotations"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Output) != 2 {
		t.Fatalf("expected 2 items, got %d: %s", len(out.Output), got)
	}
	msg := out.Output[1]
	if msg.Type != "message" || len(msg.Content) != 1 {
		t.Fatalf("bad message item: %+v", msg)
	}
	if len(msg.Content[0].Annotations) != 2 {
		t.Fatalf("expected 2 annotations, got %d: %s", len(msg.Content[0].Annotations), got)
	}
	if msg.Content[0].Annotations[0].URL != "https://example.com/a" || msg.Content[0].Annotations[1].Title != "B" {
		t.Fatalf("bad annotations: %+v", msg.Content[0].Annotations)
	}
	if msg.Content[0].Annotations[0].Type != "url_citation" {
		t.Fatalf("expected url_citation type, got %q", msg.Content[0].Annotations[0].Type)
	}
}

func TestSpliceEffectsResponsesBody_InsertsMarkerBeforeMessage(t *testing.T) {
	body := []byte(`{"id":"r","output":[` +
		`{"id":"f","type":"function_call","call_id":"c1","name":"zs_web_search","arguments":"{}"},` +
		`{"id":"m","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}` +
		`]}`)
	marker, err := MarshalMarkerItem(MarkerTypeWebSearchCall, "hycall_aaa", MarkerStatusCompleted)
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	got, err := SpliceEffectsResponsesBody(body, []ToolEffect{{CallItem: marker}})
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Output []struct {
			ID     string `json:"id"`
			Type   string `json:"type"`
			Status string `json:"status"`
		} `json:"output"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Output) != 3 {
		t.Fatalf("expected 3 items after marker insertion, got %d: %s", len(out.Output), got)
	}
	if out.Output[1].Type != MarkerTypeWebSearchCall {
		t.Fatalf("expected marker before message, got order: %+v", out.Output)
	}
	if out.Output[1].ID != "hycall_aaa" || out.Output[1].Status != MarkerStatusCompleted {
		t.Fatalf("bad marker: %+v", out.Output[1])
	}
	if out.Output[2].Type != "message" {
		t.Fatalf("expected message last, got %+v", out.Output[2])
	}
}

func TestSpliceEffectsResponsesBody_FailedMarkerNoCitations(t *testing.T) {
	body := []byte(`{"output":[{"id":"m","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]}]}`)
	marker, _ := MarshalMarkerItem(MarkerTypeWebSearchCall, "hycall_x", MarkerStatusFailed)
	got, err := SpliceEffectsResponsesBody(body, []ToolEffect{{CallItem: marker}})
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Output []struct {
			Type    string `json:"type"`
			Status  string `json:"status"`
			Content []struct {
				Annotations []json.RawMessage `json:"annotations"`
			} `json:"content"`
		} `json:"output"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Output) != 2 {
		t.Fatalf("expected 2 items, got %d", len(out.Output))
	}
	if out.Output[0].Status != MarkerStatusFailed {
		t.Fatalf("expected failed status, got %q", out.Output[0].Status)
	}
	if len(out.Output[1].Content[0].Annotations) != 0 {
		t.Fatalf("expected no annotations for failed marker, got %+v", out.Output[1].Content[0].Annotations)
	}
}

func TestSpliceEffectsResponsesBody_NoEffectsIsNoop(t *testing.T) {
	body := []byte(`{"output":[{"type":"message","content":[{"type":"output_text","text":"hi"}]}]}`)
	got, err := SpliceEffectsResponsesBody(body, nil)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("expected verbatim, got %s", got)
	}
}

func TestSpliceEffectsResponsesBody_NoMessageStillInsertsMarker(t *testing.T) {
	// Pathological: final iteration produced only function_calls and no
	// message. Marker still appended; no annotation work done.
	body := []byte(`{"output":[{"id":"f","type":"function_call","call_id":"c1","name":"x","arguments":"{}"}]}`)
	marker, _ := MarshalMarkerItem(MarkerTypeWebSearchCall, "hycall_x", MarkerStatusCompleted)
	got, err := SpliceEffectsResponsesBody(body, []ToolEffect{{CallItem: marker, Citations: []CitationEffect{{URL: "u", Title: "t"}}}})
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Output []struct {
			Type string `json:"type"`
		} `json:"output"`
	}
	_ = json.Unmarshal(got, &out)
	if len(out.Output) != 2 {
		t.Fatalf("expected marker appended, got %+v", out.Output)
	}
}

func TestStripBuiltinCallMarkers_RemovesFromInput(t *testing.T) {
	body := []byte(`{"model":"x","input":[` +
		`{"role":"user","content":"hi"},` +
		`{"id":"hycall_a","type":"zs_web_search_call","status":"completed"},` +
		`{"id":"m","type":"message","role":"assistant","content":[{"type":"output_text","text":"hi"}]},` +
		`{"id":"hycall_b","type":"zs_image_search_call","status":"completed"}` +
		`]}`)
	got := StripBuiltinCallMarkers(body)
	var out struct {
		Input []struct {
			Type string `json:"type"`
			Role string `json:"role"`
		} `json:"input"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(out.Input) != 2 {
		t.Fatalf("expected 2 items after strip, got %d: %s", len(out.Input), got)
	}
	if out.Input[0].Role != "user" || out.Input[1].Type != "message" {
		t.Fatalf("expected user+message remaining, got %+v", out.Input)
	}
	// Tool definitions on the request side (zs_web_search) must NOT
	// be affected — different shape and meaning.
	if strings.Contains(string(got), "zs_web_search_call") || strings.Contains(string(got), "zs_image_search_call") {
		t.Fatalf("markers leaked through: %s", got)
	}
}

func TestStripBuiltinCallMarkers_NoMarkersIsNoop(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":"hi"}]}`)
	got := StripBuiltinCallMarkers(body)
	if string(got) != string(body) {
		t.Fatalf("expected verbatim, got %s", got)
	}
}

func TestStripBuiltinCallMarkers_PreservesToolDefinitions(t *testing.T) {
	// zs_web_search (without _call suffix) is a TOOL definition —
	// belongs in tools[], not input[]. Even if a confused client puts
	// it in input[], we don't strip it because the request would fail
	// upstream anyway and stripping would mask the bug.
	body := []byte(`{"input":[{"type":"zs_web_search"}]}`)
	got := StripBuiltinCallMarkers(body)
	if !strings.Contains(string(got), "zs_web_search") {
		t.Fatalf("tool definition was stripped: %s", got)
	}
}

func TestMarshalAnnotationAddedFrame_Shape(t *testing.T) {
	frame, err := MarshalAnnotationAddedFrame("msg_1", 1, 0, 2, CitationEffect{URL: "https://x", Title: "X"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out struct {
		Type            string `json:"type"`
		ItemID          string `json:"item_id"`
		OutputIndex     int    `json:"output_index"`
		ContentIndex    int    `json:"content_index"`
		AnnotationIndex int    `json:"annotation_index"`
		Annotation      struct {
			Type  string `json:"type"`
			URL   string `json:"url"`
			Title string `json:"title"`
		} `json:"annotation"`
	}
	if err := json.Unmarshal(frame, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Type != "response.output_text.annotation.added" {
		t.Fatalf("bad type: %q", out.Type)
	}
	if out.ItemID != "msg_1" || out.OutputIndex != 1 || out.AnnotationIndex != 2 {
		t.Fatalf("bad fields: %+v", out)
	}
	if out.Annotation.Type != "url_citation" || out.Annotation.URL != "https://x" || out.Annotation.Title != "X" {
		t.Fatalf("bad annotation: %+v", out.Annotation)
	}
}

func TestMarshalAnnotationAddedFrame_RequiresItemID(t *testing.T) {
	_, err := MarshalAnnotationAddedFrame("", 0, 0, 0, CitationEffect{URL: "u"})
	if err == nil {
		t.Fatalf("expected error for empty item_id")
	}
}

func TestMarshalMarkerItemFrames_AddedAndDone(t *testing.T) {
	item, err := MarshalMarkerItem(MarkerTypeWebSearchCall, "hycall_z", MarkerStatusCompleted)
	if err != nil {
		t.Fatalf("marker: %v", err)
	}
	added, err := MarshalMarkerItemAddedFrame(2, item)
	if err != nil {
		t.Fatalf("added: %v", err)
	}
	done, err := MarshalMarkerItemDoneFrame(2, item)
	if err != nil {
		t.Fatalf("done: %v", err)
	}
	for _, f := range [][]byte{added, done} {
		var probe struct {
			Type        string `json:"type"`
			OutputIndex int    `json:"output_index"`
			Item        struct {
				Type   string `json:"type"`
				ID     string `json:"id"`
				Status string `json:"status"`
			} `json:"item"`
		}
		if err := json.Unmarshal(f, &probe); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if probe.OutputIndex != 2 {
			t.Fatalf("bad output_index: %d", probe.OutputIndex)
		}
		if probe.Item.Type != MarkerTypeWebSearchCall || probe.Item.ID != "hycall_z" || probe.Item.Status != MarkerStatusCompleted {
			t.Fatalf("bad marker item: %+v", probe.Item)
		}
	}
	var addedType struct {
		Type string `json:"type"`
	}
	var doneType struct {
		Type string `json:"type"`
	}
	_ = json.Unmarshal(added, &addedType)
	_ = json.Unmarshal(done, &doneType)
	if addedType.Type != "response.output_item.added" || doneType.Type != "response.output_item.done" {
		t.Fatalf("bad frame types: added=%q done=%q", addedType.Type, doneType.Type)
	}
}

func TestNewMarkerCallID_HasPrefix(t *testing.T) {
	id := NewMarkerCallID()
	if !strings.HasPrefix(id, "hycall_") {
		t.Fatalf("expected hycall_ prefix, got %q", id)
	}
	if len(id) <= len("hycall_") {
		t.Fatalf("id too short: %q", id)
	}
}

func TestSpliceEffectsChatBody_AppendsSourcesToContent(t *testing.T) {
	body := []byte(`{"id":"x","choices":[{"index":0,"message":{"role":"assistant","content":"The answer is 42."}}]}`)
	effects := []ToolEffect{{
		Citations: []CitationEffect{
			{URL: "https://a.example", Title: "Alpha"},
			{URL: "https://b.example", Title: "Beta"},
		},
	}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := out.Choices[0].Message.Content
	if !strings.HasPrefix(c, "The answer is 42.") {
		t.Fatalf("original content not preserved at head: %q", c)
	}
	if !strings.Contains(c, "**Sources:**") {
		t.Fatalf("expected Sources heading: %q", c)
	}
	if !strings.Contains(c, "1. [Alpha](<https://a.example>)") {
		t.Fatalf("expected first citation: %q", c)
	}
	if !strings.Contains(c, "2. [Beta](<https://b.example>)") {
		t.Fatalf("expected second citation: %q", c)
	}
}

func TestSpliceEffectsChatBody_NullContentBecomesSources(t *testing.T) {
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":null}}]}`)
	effects := []ToolEffect{{
		Citations: []CitationEffect{{URL: "https://a", Title: "A"}},
	}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := out.Choices[0].Message.Content
	if strings.HasPrefix(c, "\n\n") {
		t.Fatalf("expected leading separator stripped when no prior content: %q", c)
	}
	if !strings.HasPrefix(c, "**Sources:**") {
		t.Fatalf("expected Sources heading at start: %q", c)
	}
}

func TestSpliceEffectsChatBody_DropsCallItem(t *testing.T) {
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`)
	marker, _ := MarshalMarkerItem(MarkerTypeWebSearchCall, "hycall_q", MarkerStatusCompleted)
	effects := []ToolEffect{{
		Citations: []CitationEffect{{URL: "https://a"}},
		CallItem:  marker,
	}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if strings.Contains(string(got), "zs_web_search_call") {
		t.Fatalf("marker leaked into chat body: %s", got)
	}
	if strings.Contains(string(got), "hycall_q") {
		t.Fatalf("marker id leaked into chat body: %s", got)
	}
}

func TestSpliceEffectsChatBody_DedupAcrossEffects(t *testing.T) {
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`)
	effects := []ToolEffect{
		{Citations: []CitationEffect{{URL: "https://x", Title: "X1"}}},
		{Citations: []CitationEffect{{URL: "https://x", Title: "X2"}, {URL: "https://y", Title: "Y"}}},
	}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := out.Choices[0].Message.Content
	if strings.Count(c, "https://x") != 1 {
		t.Fatalf("expected URL dedup across effects: %q", c)
	}
	// First-seen title wins.
	if !strings.Contains(c, "[X1](<https://x>)") {
		t.Fatalf("expected first-seen title preserved: %q", c)
	}
}

func TestSpliceEffectsChatBody_NoEffectsIsNoop(t *testing.T) {
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`)
	got, err := SpliceEffectsChatBody(body, nil)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("expected verbatim, got %s", got)
	}
}

func TestSpliceEffectsChatBody_NoCitationsIsNoop(t *testing.T) {
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`)
	marker, _ := MarshalMarkerItem(MarkerTypeWebSearchCall, "hycall_q", MarkerStatusCompleted)
	effects := []ToolEffect{{CallItem: marker}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("expected verbatim when only marker (no citations), got %s", got)
	}
}

func TestSpliceEffectsChatBody_OnlyFirstChoiceMutated(t *testing.T) {
	body := []byte(`{"choices":[` +
		`{"index":0,"message":{"role":"assistant","content":"first"}},` +
		`{"index":1,"message":{"role":"assistant","content":"second"}}` +
		`]}`)
	effects := []ToolEffect{{Citations: []CitationEffect{{URL: "https://a"}}}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Choices []struct {
			Index   int `json:"index"`
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !strings.Contains(out.Choices[0].Message.Content, "Sources") {
		t.Fatalf("first choice should have sources: %+v", out.Choices[0])
	}
	if out.Choices[1].Message.Content != "second" {
		t.Fatalf("second choice should be untouched, got %q", out.Choices[1].Message.Content)
	}
}

func TestSpliceEffectsChatBody_NoChoicesIsNoop(t *testing.T) {
	body := []byte(`{"id":"x"}`)
	effects := []ToolEffect{{Citations: []CitationEffect{{URL: "https://a"}}}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if string(got) != string(body) {
		t.Fatalf("expected verbatim when no choices, got %s", got)
	}
}

func TestSpliceEffectsChatBody_EscapesParenURLAndBracketTitle(t *testing.T) {
	// Wikipedia URLs and "[Updated]"-style titles are common in
	// real web_search output and would shred a naive `[t](u)` render.
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"hi"}}]}`)
	effects := []ToolEffect{{
		Citations: []CitationEffect{
			{URL: "https://en.wikipedia.org/wiki/Python_(programming_language)", Title: "[Updated] Python"},
		},
	}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	var out struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(got, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c := out.Choices[0].Message.Content
	// URL must be wrapped in angle brackets so the inner `)` doesn't
	// terminate the link destination prematurely.
	if !strings.Contains(c, "(<https://en.wikipedia.org/wiki/Python_(programming_language)>)") {
		t.Fatalf("expected angle-bracket-wrapped URL preserving parens: %q", c)
	}
	// Title must escape `]` so the bracketed prefix doesn't close the
	// link text early.
	if !strings.Contains(c, `[\[Updated\] Python]`) {
		t.Fatalf("expected escaped brackets in title: %q", c)
	}
	// Sanity: the un-escaped (broken) form must not be present.
	if strings.Contains(c, "(https://en.wikipedia.org/wiki/Python_(programming_language))") {
		t.Fatalf("found bare-paren URL form — would break parsing: %q", c)
	}
}

func TestSpliceEffectsChatBody_PreservesToolCalls(t *testing.T) {
	body := []byte(`{"choices":[{"index":0,"message":{"role":"assistant","content":"summary","tool_calls":[{"id":"c","type":"function","function":{"name":"x","arguments":"{}"}}]}}]}`)
	effects := []ToolEffect{{Citations: []CitationEffect{{URL: "https://a"}}}}
	got, err := SpliceEffectsChatBody(body, effects)
	if err != nil {
		t.Fatalf("splice: %v", err)
	}
	if !strings.Contains(string(got), `"tool_calls"`) {
		t.Fatalf("tool_calls dropped during splice: %s", got)
	}
	if !strings.Contains(string(got), `"id":"c"`) {
		t.Fatalf("tool_calls payload mutated during splice: %s", got)
	}
}

func TestResponsesStitcher_CurrentMessageItem(t *testing.T) {
	s := NewResponsesToolCallStitcher(nil)
	if _, _, ok := s.CurrentMessageItem(); ok {
		t.Fatalf("expected ok=false before any message item")
	}
	s.Observe([]byte(`{"type":"response.output_item.added","output_index":1,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`))
	id, idx, ok := s.CurrentMessageItem()
	if !ok {
		t.Fatalf("expected ok=true after message item.added")
	}
	if id != "msg_1" || idx != 1 {
		t.Fatalf("bad current message item: id=%q idx=%d", id, idx)
	}
}
