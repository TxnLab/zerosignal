/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools_test

// Cross-impl vectors for what a payer reads off a tool-bearing stream: the
// sealed status and image frames, the icon host key and mime sniff, and the
// usage arithmetic a receipt's output leg depends on.
// proto/ts/test/tools-vectors.test.ts replays them against proto/ts/src/tools.
//
// The frames are produced by the node-side Marshal* functions, so the TS
// parser is pinned to exactly what a node emits.
//
// Regenerate after an intentional change:
//
//	cd proto/go && go test ./tools -run TestPayerToolsVectors -update

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"testing"

	"github.com/TxnLab/zerosignal/go/tools"
)

var updatePayerToolsVectors = flag.Bool("update", false, "regenerate proto/testdata/tools_vectors.json")

const payerToolsVectorsPath = "../../testdata/tools_vectors.json"

type frameCase struct {
	Name  string          `json:"name"`
	Frame json.RawMessage `json:"frame"`
}

// WHATWGRefuses marks a URL Go accepts and the URL Standard does not, so the
// TS side, built on the standard, refuses it. They are listed rather than left
// out so a change on either side shows up here.
type hostKeyCase struct {
	URL           string `json:"url"`
	OK            bool   `json:"ok"`
	Want          string `json:"want"`
	WHATWGRefuses bool   `json:"whatwg_refuses,omitempty"`
}

type linkableCase struct {
	URL           string `json:"url"`
	OK            bool   `json:"ok"`
	WHATWGRefuses bool   `json:"whatwg_refuses,omitempty"`
}

type mimeCase struct {
	BytesHex string `json:"bytes_hex"`
	Want     string `json:"want"`
}

type generatedCase struct {
	Prompt     string `json:"prompt"`
	Completion string `json:"completion"`
	Reasoning  string `json:"reasoning"`
	Total      string `json:"total"`
	Want       string `json:"want"`
}

type usageCase struct {
	Name      string          `json:"name"`
	Kind      string          `json:"kind"`
	Usage     json.RawMessage `json:"usage"`
	Cached    string          `json:"cached_tokens"`
	Reasoning string          `json:"reasoning_tokens"`
	Generated string          `json:"generated_output_tokens"`
}

type payerToolsVectorsFile struct {
	Version   int             `json:"version"`
	Comment   string          `json:"comment"`
	Constants map[string]any  `json:"constants"`
	Frames    []frameCase     `json:"frames"`
	HostKeys  []hostKeyCase   `json:"icon_host_keys"`
	Linkable  []linkableCase  `json:"linkable_urls"`
	Mimes     []mimeCase      `json:"icon_mimes"`
	Generated []generatedCase `json:"generated_output_tokens"`
	Usage     []usageCase     `json:"usage"`
}

func u(v uint64) string { return strconv.FormatUint(v, 10) }

func buildFrames(t *testing.T) []frameCase {
	t.Helper()
	mustFrame := func(b []byte, err error) json.RawMessage {
		t.Helper()
		if err != nil {
			t.Fatalf("marshal frame: %v", err)
		}
		return b
	}
	search := &tools.ToolAction{
		Type:  tools.ActionTypeSearch,
		Query: "algorand state proofs",
		Sources: []tools.ActionSource{
			{Type: "url", URL: "https://developer.algorand.org/docs/state-proofs"},
			{Type: "url", URL: "https://münchen.de/x"},
		},
	}
	search.AttachIcons([]string{"developer.algorand.org", "xn--mnchen-3ya.de"}, map[string]*tools.SourceIcon{
		"developer.algorand.org": {Mime: tools.IconMimePNG, DataB64: "iVBORw0KGgo="},
		"xn--mnchen-3ya.de":      {Mime: tools.IconMimeICO, DataB64: "AAABAA=="},
	})
	openPage := &tools.ToolAction{Type: tools.ActionTypeOpenPage, URL: "https://example.com/a?b=c"}

	// Icons are keyed by IconHostKey of each source, which keeps "www." and
	// brackets an IPv6 literal; the TS test checks every key joins a source.
	imageSources := []string{"https://www.example.com/cat.jpg", "https://[2001:db8::1]:8443/dog.png"}
	imageSearch := tools.ActionForCall("zs_image_search", json.RawMessage(`{"query":"  cats and dogs  "}`))
	if imageSearch == nil {
		t.Fatal("ActionForCall(zs_image_search) returned nil")
	}
	icons := map[string]*tools.SourceIcon{}
	var hosts []string
	for _, s := range imageSources {
		imageSearch.Sources = append(imageSearch.Sources, tools.ActionSource{Type: "url", URL: s})
		h, ok := tools.IconHostKey(s)
		if !ok {
			t.Fatalf("IconHostKey(%q) refused", s)
		}
		hosts = append(hosts, h)
		icons[h] = &tools.SourceIcon{Mime: tools.IconMimeGIF, DataB64: "R0lGODlhAQABAAAAACw="}
	}
	imageSearch.AttachIcons(hosts, icons)

	return []frameCase{
		{"status_in_progress_bare", mustFrame(tools.MarshalToolCallStatus(
			tools.StatusEventToolCallInProgress, "zstc_0001", "zs_get_time", "", 0))},
		{"status_in_progress_search", mustFrame(tools.MarshalToolCallStatusWithAction(
			tools.StatusEventToolCallInProgress, "zstc_0002", "zs_web_search", "call_7", 1,
			&tools.ToolAction{Type: tools.ActionTypeSearch, Query: "algorand state proofs"}))},
		{"status_completed_search_with_sources_and_icons", mustFrame(tools.MarshalToolCallStatusWithAction(
			tools.StatusEventToolCallCompleted, "zstc_0002", "zs_web_search", "call_7", 1, search))},
		{"status_completed_image_search_www_and_ipv6_icons", mustFrame(tools.MarshalToolCallStatusWithAction(
			tools.StatusEventToolCallCompleted, "zstc_0006", "zs_image_search", "call_9", 3, imageSearch))},
		{"status_completed_open_page", mustFrame(tools.MarshalToolCallStatusWithAction(
			tools.StatusEventToolCallCompleted, "zstc_0003", "zs_web_read", "call_8", 2, openPage))},
		{"image_progress", mustFrame(tools.MarshalImageProgress("zstc_0004", 12, 20, "KSampler"))},
		{"image_progress_no_node", mustFrame(tools.MarshalImageProgress("zstc_0004", 0, 20, ""))},
		{"image_partial", mustFrame(tools.MarshalImagePartial("zstc_0004", "/9j/4AAQ", tools.IconMimeJPEG))},
		{"image_partial_no_mime", mustFrame(tools.MarshalImagePartial("zstc_0004", "iVBORw0KGgo=", ""))},
		{"image_completed", mustFrame(tools.MarshalImageCompleted("zstc_0005",
			[]byte(`{"created":1800000000,"data":[{"b64_json":"iVBORw0KGgo=","revised_prompt":"x"}]}`)))},
	}
}

func buildHostKeys() []hostKeyCase {
	urls := []string{
		// TestIconHostKey_MatchesWHATWG's table.
		"https://Algorand.CO/path",
		"https://www.example.com/x",
		"https://example.com:8443/x",
		"https://example.com:443/x",
		"http://example.com/",
		"https://example.com./x",
		"https://my_host.example.com/x",
		"https://münchen.de/x",
		"https://例え.jp/x",
		"https://xn--mnchen-3ya.de/x",
		"https://[2001:db8::1]:8443/x",
		"https://[2001:db8:0:0:0:0:0:1]/x",
		"https://[::1]/x",
		"https://user:pw@Example.com/x",
		// Refused: not an http(s) URL with a host.
		"",
		"example.com",
		"//example.com/x",
		"ftp://example.com/x",
		"javascript:alert(1)",
		"data:image/png;base64,AAAA",
		"https://",
		// IPv6 forms where RFC 5952 and WHATWG serialize differently.
		"https://[::ffff:1.2.3.4]/x",
		"https://[::ffff:102:304]/x",
		"https://[::1.2.3.4]/x",
		"https://[1:0:0:2:0:0:0:3]/x",
		"https://[::]/x",
		// A zone identifier, which WHATWG refuses and Go now does too.
		"https://[fe80::1%25eth0]/x",
	}
	out := make([]hostKeyCase, 0, len(urls)+len(whatwgRefuses))
	for _, raw := range urls {
		got, ok := tools.IconHostKey(raw)
		out = append(out, hostKeyCase{URL: raw, OK: ok, Want: got})
	}
	for _, raw := range whatwgRefuses {
		got, ok := tools.IconHostKey(raw)
		out = append(out, hostKeyCase{URL: raw, OK: ok, Want: got, WHATWGRefuses: true})
	}
	return out
}

// URLs Go's parser accepts and the URL Standard refuses. Honest nodes can emit
// them, but no browser could open one, so the TS side refusing them costs a
// consumer nothing it could have used. tool_icon.go's IconHostKey lists them.
var whatwgRefuses = []string{
	"https://example.com:99999/x",
	"https://256.1.1.1/x",
	"https://example.123/x",
	"https://1.2.3.4.5/x",
	"https://xn--a.com/x",
	"https://a<b.com/x",
}

// buildLinkable pins the rule for which URLs a consumer may render as a link.
// The TS side is stricter in one direction only: it refuses URLs WHATWG would
// quietly rewrite (a backslash read as a slash, a tab stripped) instead of
// handing back a string that no longer names what the node fetched.
func buildLinkable() []linkableCase {
	bs := "\x5c" // a backslash, spelled so no tool can reinterpret it
	urls := []string{
		"https://example.com/a?b=c#d",
		"http://example.com",
		"HTTPS://Example.com/x",
		"https://münchen.de/x",
		"https://[2001:db8::1]:8443/x",
		"https://example.com/a b",
		"https://example.com/%41",
		"https://example.com/\xef\xbb\xbf",
		"https://user:pw@example.com/",
		"",
		"example.com/x",
		"//example.com/x",
		"ftp://example.com/x",
		"javascript:alert(1)",
		"data:text/html,x",
		"vbscript:x",
		"https://",
		"https:example.com/x",
		"https://example.com/%zz",
		"https://example.com/\x00",
		"https://exa\tmple.com/x",
		"https://example.com/\x7f",
		" https://example.com/x",
		"https:" + bs + bs + "example.com" + bs + "x",
		"https://example.com" + bs + "@evil.com/x",
	}
	out := make([]linkableCase, 0, len(urls)+len(whatwgRefuses))
	for _, raw := range urls {
		out = append(out, linkableCase{URL: raw, OK: tools.LinkableURLForTest(raw)})
	}
	for _, raw := range whatwgRefuses {
		out = append(out, linkableCase{URL: raw, OK: tools.LinkableURLForTest(raw), WHATWGRefuses: true})
	}
	return out
}

func buildMimes() []mimeCase {
	inputs := [][]byte{
		{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A, 0x00},
		{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A},
		{0xFF, 0xD8, 0xFF, 0xE0},
		{0xFF, 0xD8},
		[]byte("GIF87a..."),
		[]byte("GIF89a"),
		[]byte("GIF88a"),
		[]byte("RIFF\x00\x00\x00\x00WEBPVP8 "),
		[]byte("RIFF\x00\x00\x00\x00WEBP"),
		[]byte("RIFF\x00\x00\x00\x00WAVE"),
		[]byte("RIFF\x00\x00\x00\x00WEB"),
		{0x00, 0x00, 0x01, 0x00, 0x01},
		{0x00, 0x00, 0x02, 0x00, 0x01},
		[]byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>"),
		{},
	}
	out := make([]mimeCase, 0, len(inputs))
	for _, b := range inputs {
		out = append(out, mimeCase{BytesHex: hex.EncodeToString(b), Want: tools.IconMimeFromBytes(b)})
	}
	return out
}

func buildGenerated() []generatedCase {
	// prompt, completion, reasoning, total.
	inputs := [][4]uint64{
		{100, 50, 0, 150},       // no reasoning reported
		{100, 50, 20, 150},      // completion already includes reasoning (OpenAI shape)
		{100, 7, 153, 260},      // completion excludes it (xAI chat shape)
		{100, 50, 20, 170},      // total exactly corroborates exclusion
		{100, 50, 20, 169},      // total one short: not corroborated
		{100, 50, 20, 0},        // no total
		{100, 50, 20, 99},       // total below prompt
		{100, 70, 20, 170},      // already credited: idempotent
		{0, 0, 20, 20},          // reasoning only
		{12205, 529, 27, 12734}, // xAI responses shape: included
	}
	out := make([]generatedCase, 0, len(inputs))
	for _, c := range inputs {
		out = append(out, generatedCase{
			Prompt: u(c[0]), Completion: u(c[1]), Reasoning: u(c[2]), Total: u(c[3]),
			Want: u(tools.GeneratedOutputTokens(c[0], c[1], c[2], c[3])),
		})
	}
	return out
}

func buildUsage(t *testing.T) []usageCase {
	t.Helper()
	chat := []struct{ name, body string }{
		{"chat_bare", `{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}`},
		{"chat_cached_details", `{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":4}}`},
		{"chat_cached_deepseek", `{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"prompt_cache_hit_tokens":6}`},
		{"chat_details_win_over_deepseek", `{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15,"prompt_tokens_details":{"cached_tokens":0},"prompt_cache_hit_tokens":6}`},
		{"chat_reasoning_excluded", `{"prompt_tokens":100,"completion_tokens":7,"total_tokens":260,"completion_tokens_details":{"reasoning_tokens":153}}`},
		{"chat_reasoning_included", `{"prompt_tokens":100,"completion_tokens":50,"total_tokens":150,"completion_tokens_details":{"reasoning_tokens":20}}`},
	}
	responses := []struct{ name, body string }{
		{"responses_bare", `{"input_tokens":10,"output_tokens":5,"total_tokens":15}`},
		{"responses_cached", `{"input_tokens":10,"output_tokens":5,"total_tokens":15,"input_tokens_details":{"cached_tokens":3}}`},
		{"responses_reasoning_included", `{"input_tokens":12205,"output_tokens":529,"total_tokens":12734,"output_tokens_details":{"reasoning_tokens":27}}`},
		{"responses_reasoning_excluded", `{"input_tokens":100,"output_tokens":7,"total_tokens":260,"output_tokens_details":{"reasoning_tokens":153}}`},
	}
	var out []usageCase
	for _, c := range chat {
		var cu tools.ChatUsage
		if err := json.Unmarshal([]byte(c.body), &cu); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		out = append(out, usageCase{Name: c.name, Kind: "chat", Usage: json.RawMessage(c.body),
			Cached: u(cu.CachedTokens()), Reasoning: u(cu.ReasoningTokens()), Generated: u(cu.GeneratedOutputTokens())})
	}
	for _, c := range responses {
		var ru tools.ResponsesUsage
		if err := json.Unmarshal([]byte(c.body), &ru); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		out = append(out, usageCase{Name: c.name, Kind: "responses", Usage: json.RawMessage(c.body),
			Cached: u(ru.CachedTokens()), Reasoning: u(ru.ReasoningTokens()), Generated: u(ru.GeneratedOutputTokens())})
	}
	return out
}

func buildPayerToolsVectors(t *testing.T) payerToolsVectorsFile {
	t.Helper()
	return payerToolsVectorsFile{
		Version: 1,
		Comment: "Cross-impl vectors for the payer-facing half of proto/go/tools: sealed status and image " +
			"frames as a node emits them, icon host keys and mime sniffing, and the usage arithmetic. " +
			"Generated by proto/go/tools/payer_vectors_test.go; regenerate with " +
			"`cd proto/go && go test ./tools -run TestPayerToolsVectors -update`.",
		Constants: map[string]any{
			"STATUS_EVENT_TOOL_CALL_IN_PROGRESS": tools.StatusEventToolCallInProgress,
			"STATUS_EVENT_TOOL_CALL_COMPLETED":   tools.StatusEventToolCallCompleted,
			"STATUS_EVENT_IMAGE_PROGRESS":        tools.StatusEventImageProgress,
			"STATUS_EVENT_IMAGE_PARTIAL":         tools.StatusEventImagePartial,
			"STATUS_EVENT_IMAGE_COMPLETED":       tools.StatusEventImageCompleted,
			"ACTION_TYPE_SEARCH":                 tools.ActionTypeSearch,
			"ACTION_TYPE_OPEN_PAGE":              tools.ActionTypeOpenPage,
			"ICON_MIME_ICO":                      tools.IconMimeICO,
			"ICON_MIME_PNG":                      tools.IconMimePNG,
			"ICON_MIME_GIF":                      tools.IconMimeGIF,
			"ICON_MIME_JPEG":                     tools.IconMimeJPEG,
			"ICON_MIME_WEBP":                     tools.IconMimeWebP,
			"MAX_ICON_RAW_BYTES":                 tools.MaxIconRawBytes,
			"MAX_ICON_HOSTS":                     tools.MaxIconHosts,
			"MAX_ICONS_TOTAL_B64_BYTES":          tools.MaxIconsTotalB64BytesForTest,
			"MAX_ACTION_SOURCES":                 tools.MaxActionSourcesForTest,
			"MAX_ACTION_QUERY_BYTES":             tools.MaxActionQueryBytesForTest,
			"MAX_ACTION_URL_BYTES":               tools.MaxActionURLBytesForTest,
		},
		Frames:    buildFrames(t),
		HostKeys:  buildHostKeys(),
		Linkable:  buildLinkable(),
		Mimes:     buildMimes(),
		Generated: buildGenerated(),
		Usage:     buildUsage(t),
	}
}

func TestPayerToolsVectors(t *testing.T) {
	encoded, err := json.MarshalIndent(buildPayerToolsVectors(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')
	if *updatePayerToolsVectors {
		if err := os.WriteFile(payerToolsVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", payerToolsVectorsPath)
		return
	}
	onDisk, err := os.ReadFile(payerToolsVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(onDisk, encoded) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./tools -run TestPayerToolsVectors -update, "+
			"and port the change to proto/ts/src/tools", payerToolsVectorsPath)
	}
}
