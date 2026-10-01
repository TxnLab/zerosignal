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

// The back-compat pin: a status frame with no action must marshal to
// exactly the shape peers built before actions existed already parse.
func TestMarshalToolCallStatus_NoActionOmitsField(t *testing.T) {
	b, err := MarshalToolCallStatus(StatusEventToolCallInProgress, "zstc_ab12", "zs_web_search", "call_1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "action") {
		t.Fatalf("action key leaked into an action-less frame: %s", b)
	}

	var got ToolCallStatusFrame
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Type != StatusEventToolCallInProgress || got.ItemID != "zstc_ab12" ||
		got.Tool != "zs_web_search" || got.CallID != "call_1" || got.OutputIndex != 0 {
		t.Fatalf("field round-trip broke: %+v", got)
	}
	if got.Action != nil {
		t.Fatalf("want nil action, got %+v", got.Action)
	}
}

// MarshalToolCallStatus must stay byte-identical to the WithAction form
// passed nil, or the two emit paths would produce different receipt
// body_hash inputs for the same logical frame.
func TestMarshalToolCallStatus_EquivalentToNilAction(t *testing.T) {
	plain, err := MarshalToolCallStatus(StatusEventToolCallCompleted, "zstc_1", "zs_web_search", "call_1", 2)
	if err != nil {
		t.Fatal(err)
	}
	withNil, err := MarshalToolCallStatusWithAction(StatusEventToolCallCompleted, "zstc_1", "zs_web_search", "call_1", 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(plain) != string(withNil) {
		t.Fatalf("nil action diverged:\n plain: %s\n  nil:  %s", plain, withNil)
	}
}

func TestMarshalToolCallStatusWithAction_SearchShape(t *testing.T) {
	action := ActionForCall("zs_web_search", json.RawMessage(`{"query":"algorand tps"}`))
	b, err := MarshalToolCallStatusWithAction(StatusEventToolCallInProgress, "zstc_1", "zs_web_search", "call_1", 0, action)
	if err != nil {
		t.Fatal(err)
	}

	var got ToolCallStatusFrame
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Action == nil {
		t.Fatal("action missing from the frame")
	}
	if got.Action.Type != ActionTypeSearch {
		t.Fatalf("want type %q, got %q", ActionTypeSearch, got.Action.Type)
	}
	if got.Action.Query != "algorand tps" {
		t.Fatalf("want query %q, got %q", "algorand tps", got.Action.Query)
	}
	// in_progress has no results yet.
	if len(got.Action.Sources) != 0 {
		t.Fatalf("in_progress must not carry sources, got %+v", got.Action.Sources)
	}
	if got.Action.URL != "" {
		t.Fatalf("search action must not carry a url, got %q", got.Action.URL)
	}
}

func TestMarshalToolCallStatusWithAction_CompletedCarriesSources(t *testing.T) {
	action := ActionForCall("zs_web_search", json.RawMessage(`{"query":"algorand tps"}`))
	action.Sources = SourcesFromCitations([]CitationEffect{
		{URL: "https://a.example", Title: "Title A"},
		{URL: "https://b.example", Title: "Title B"},
	})
	b, err := MarshalToolCallStatusWithAction(StatusEventToolCallCompleted, "zstc_1", "zs_web_search", "call_1", 0, action)
	if err != nil {
		t.Fatal(err)
	}

	var got ToolCallStatusFrame
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Action == nil || len(got.Action.Sources) != 2 {
		t.Fatalf("want 2 sources, got %+v", got.Action)
	}
	if got.Action.Sources[0].URL != "https://a.example" || got.Action.Sources[1].URL != "https://b.example" {
		t.Fatalf("source urls wrong: %+v", got.Action.Sources)
	}
	// OpenAI's source shape is {type,url} — no title. Titles reach the
	// client as url_citation annotations instead.
	if strings.Contains(string(b), "Title A") || strings.Contains(string(b), `"title"`) {
		t.Fatalf("scraped title leaked onto the frame: %s", b)
	}
}

func TestMarshalToolCallStatusWithAction_OpenPageShape(t *testing.T) {
	action := ActionForCall("zs_web_read", json.RawMessage(`{"url":"https://example.com/doc"}`))
	b, err := MarshalToolCallStatusWithAction(StatusEventToolCallCompleted, "zstc_1", "zs_web_read", "call_1", 1, action)
	if err != nil {
		t.Fatal(err)
	}

	var got ToolCallStatusFrame
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Action == nil {
		t.Fatal("action missing")
	}
	if got.Action.Type != ActionTypeOpenPage {
		t.Fatalf("want type %q, got %q", ActionTypeOpenPage, got.Action.Type)
	}
	if got.Action.URL != "https://example.com/doc" {
		t.Fatalf("want url %q, got %q", "https://example.com/doc", got.Action.URL)
	}
	if got.Action.Query != "" {
		t.Fatalf("open_page action must not carry a query, got %q", got.Action.Query)
	}
}
