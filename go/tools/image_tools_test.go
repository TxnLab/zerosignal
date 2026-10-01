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

type imageMarker struct {
	Type         string   `json:"type"`
	ID           string   `json:"id"`
	Status       string   `json:"status"`
	Result       string   `json:"result"`
	Results      []string `json:"results"`
	OutputFormat string   `json:"output_format"`
}

func TestMarshalImageMarkerItem_WithResults(t *testing.T) {
	raw, err := MarshalImageMarkerItem(MarkerTypeImageGenerationCall, "hycall_x", MarkerStatusCompleted, []string{"QUJD", "REVG"}, "image/png")
	if err != nil {
		t.Fatalf("MarshalImageMarkerItem: %v", err)
	}
	var m imageMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Type != MarkerTypeImageGenerationCall || m.Status != MarkerStatusCompleted {
		t.Errorf("marker = %+v", m)
	}
	// result = first image (OpenAI-compat / fallback); results = all images.
	if m.Result != "QUJD" {
		t.Errorf("result = %q, want first image QUJD", m.Result)
	}
	if len(m.Results) != 2 || m.Results[0] != "QUJD" || m.Results[1] != "REVG" {
		t.Errorf("results = %v, want [QUJD REVG]", m.Results)
	}
	if m.OutputFormat != "image/png" {
		t.Errorf("output_format = %q", m.OutputFormat)
	}
}

func TestMarshalImageMarkerItem_FailedOmitsResults(t *testing.T) {
	raw, err := MarshalImageMarkerItem(MarkerTypeImageEditCall, "hycall_y", MarkerStatusFailed, nil, "")
	if err != nil {
		t.Fatalf("MarshalImageMarkerItem: %v", err)
	}
	var m imageMarker
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m.Result != "" || len(m.Results) != 0 {
		t.Errorf("failed marker should omit result/results, got %+v", m)
	}
	if m.Type != MarkerTypeImageEditCall || m.Status != MarkerStatusFailed {
		t.Errorf("marker = %+v", m)
	}
}

func TestMarshalImageMarkerItem_RejectsEmptyFields(t *testing.T) {
	if _, err := MarshalImageMarkerItem("", "id", "completed", []string{"x"}, ""); err == nil {
		t.Error("expected error on empty type")
	}
}

func TestIsBuiltinCallMarkerType_IncludesImageTools(t *testing.T) {
	for _, ty := range []string{MarkerTypeImageGenerationCall, MarkerTypeImageEditCall} {
		if !isBuiltinCallMarkerType(ty) {
			t.Errorf("isBuiltinCallMarkerType(%q) = false, want true", ty)
		}
	}
}

func TestStripBuiltinCallMarkers_StripsImageMarkers(t *testing.T) {
	body := []byte(`{"input":[` +
		`{"role":"user","content":"hi"},` +
		`{"type":"zs_image_generation_call","id":"a","status":"completed","result":"QUJD"},` +
		`{"type":"zs_image_edit_call","id":"b","status":"completed","result":"REVG"}` +
		`]}`)
	out := StripBuiltinCallMarkers(body)
	var parsed struct {
		Input []map[string]json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(parsed.Input) != 1 {
		t.Fatalf("input length = %d, want 1 (markers stripped): %s", len(parsed.Input), out)
	}
	if string(out) == "" || strings.Contains(string(out), "zs_image") {
		t.Errorf("image markers not stripped: %s", out)
	}
}

func TestAppendImageToolOutputsResponses_AppendsInputImage(t *testing.T) {
	body := []byte(`{"model":"gpt-4o","input":[{"role":"user","content":"draw a cat"}]}`)
	assistantItems := []json.RawMessage{
		json.RawMessage(`{"type":"function_call","call_id":"call_1","name":"zs_image_generation","arguments":"{}"}`),
	}
	results := []ToolResult{{ToolCallID: "call_1", Content: `{"status":"completed","images":1}`}}
	attachments := [][]ImageAttachment{{{B64: "QUJD", MIME: "image/png"}}}

	out, err := AppendImageToolOutputsResponses(body, assistantItems, results, attachments)
	if err != nil {
		t.Fatalf("AppendImageToolOutputsResponses: %v", err)
	}
	var parsed struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// user turn + function_call + function_call_output + input_image user message
	if len(parsed.Input) != 4 {
		t.Fatalf("input length = %d, want 4: %s", len(parsed.Input), out)
	}

	// 3rd item: function_call_output with the status STRING.
	var fco struct {
		Type   string          `json:"type"`
		CallID string          `json:"call_id"`
		Output json.RawMessage `json:"output"`
	}
	if err := json.Unmarshal(parsed.Input[2], &fco); err != nil {
		t.Fatalf("fco unmarshal: %v", err)
	}
	if fco.Type != "function_call_output" || fco.CallID != "call_1" {
		t.Errorf("function_call_output = %+v", fco)
	}
	if len(fco.Output) == 0 || fco.Output[0] != '"' {
		t.Errorf("function_call_output.output must be a JSON string, got %s", fco.Output)
	}

	// 4th item: synthetic user message carrying a framing note + the image.
	var msg struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type     string `json:"type"`
			Text     string `json:"text"`
			ImageURL string `json:"image_url"`
			Detail   string `json:"detail"`
		} `json:"content"`
	}
	if err := json.Unmarshal(parsed.Input[3], &msg); err != nil {
		t.Fatalf("image msg unmarshal: %v", err)
	}
	if msg.Type != "message" || msg.Role != "user" {
		t.Errorf("image feed-back message shape = %+v", msg)
	}
	// Content leads with the framing note so the model knows the image is
	// its own tool result (not a user upload), then the image itself.
	if len(msg.Content) != 2 {
		t.Fatalf("content parts = %d, want 2 (framing text + image): %+v", len(msg.Content), msg.Content)
	}
	if msg.Content[0].Type != "input_text" || msg.Content[0].Text != ImageToolFeedbackNote {
		t.Errorf("first part = %+v, want the framing input_text note", msg.Content[0])
	}
	if msg.Content[1].Type != "input_image" {
		t.Fatalf("second part type = %q, want input_image", msg.Content[1].Type)
	}
	if want := "data:image/png;base64,QUJD"; msg.Content[1].ImageURL != want {
		t.Errorf("image_url = %q, want %q", msg.Content[1].ImageURL, want)
	}
	// `detail` is Required on the SDK's ResponseInputImageParam — vLLM-served
	// /v1/responses backends reject an input_image without it (the 400 with a
	// pile of union-member validation errors). Pin "auto" so it can't regress.
	if msg.Content[1].Detail != "auto" {
		t.Errorf("input_image detail = %q, want %q", msg.Content[1].Detail, "auto")
	}
}

func TestAppendImageToolOutputsResponses_NoAttachmentsNoExtraMessage(t *testing.T) {
	body := []byte(`{"input":[{"role":"user","content":"hi"}]}`)
	assistantItems := []json.RawMessage{
		json.RawMessage(`{"type":"function_call","call_id":"c","name":"zs_image_generation","arguments":"{}"}`),
	}
	results := []ToolResult{{ToolCallID: "c", Content: `{"error":"image budget exhausted: requested 1 but only 0 remaining for this request"}`}}
	// nil attachments for the single result — over-budget refusal produced no image.
	attachments := [][]ImageAttachment{nil}

	out, err := AppendImageToolOutputsResponses(body, assistantItems, results, attachments)
	if err != nil {
		t.Fatalf("AppendImageToolOutputsResponses: %v", err)
	}
	var parsed struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// user turn + function_call + function_call_output (NO trailing image message)
	if len(parsed.Input) != 3 {
		t.Fatalf("input length = %d, want 3 (no image message): %s", len(parsed.Input), out)
	}
}

func TestLatestResponsesInputImage(t *testing.T) {
	// Most recent input_image across items wins (newest-first).
	body := []byte(`{"input":[
		{"role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,OLD"}]},
		{"role":"assistant","content":[{"type":"output_text","text":"ok"}]},
		{"role":"user","content":[{"type":"input_text","text":"and"},{"type":"input_image","image_url":"data:image/png;base64,NEW"}]},
		{"role":"user","content":"make it blue"}
	]}`)
	url, ok := LatestResponsesInputImage(body)
	if !ok || url != "data:image/png;base64,NEW" {
		t.Errorf("LatestResponsesInputImage = (%q,%v), want the NEW data URL", url, ok)
	}
}

func TestLatestResponsesInputImage_NoneOrString(t *testing.T) {
	if _, ok := LatestResponsesInputImage([]byte(`{"input":[{"role":"user","content":"just text"}]}`)); ok {
		t.Error("text-only input should yield ok=false")
	}
	if _, ok := LatestResponsesInputImage([]byte(`{"input":"a string prompt"}`)); ok {
		t.Error("string input should yield ok=false")
	}
	if _, ok := LatestResponsesInputImage([]byte(`not json`)); ok {
		t.Error("non-json should yield ok=false")
	}
}
