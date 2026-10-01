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

// leakNames / leakDefs mirror the node registry's web tools closely enough to
// exercise schema-driven argument coercion: web_read takes one string url,
// web_search takes a string query plus an integer max_results.
var leakNames = map[string]BuiltinToolType{
	"zs_web_read":   BuiltinToolType("zs_web_read"),
	"zs_web_search": BuiltinToolType("zs_web_search"),
}

var leakDefs = map[BuiltinToolType]BuiltinToolDef{
	BuiltinToolType("zs_web_read"): {
		Type: BuiltinToolType("zs_web_read"), Name: "zs_web_read",
		Parameters: json.RawMessage(`{"type":"object","properties":{"url":{"type":"string"}}}`),
	},
	BuiltinToolType("zs_web_search"): {
		Type: BuiltinToolType("zs_web_search"), Name: "zs_web_search",
		Parameters: json.RawMessage(`{"type":"object","properties":{"query":{"type":"string"},"max_results":{"type":"integer"}}}`),
	},
}

func scanOne(t *testing.T, content string) LeakedToolCall {
	t.Helper()
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	if len(scan.Calls) != 1 {
		t.Fatalf("want exactly 1 recovered call, got %d (%+v)", len(scan.Calls), scan.Calls)
	}
	return scan.Calls[0]
}

// The literal string from the incident report: glm-4.7-flash emitted its whole
// final answer as one unparsed zs_web_read call.
func TestScanLeakedToolCalls_GLMXML(t *testing.T) {
	const content = `<tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://shuntool.com/article/will-sektion-cabinets-support-concrete-countertops</arg_value></tool_call>`
	got := scanOne(t, content)
	if got.Syntax != LeakSyntaxGLMXML {
		t.Errorf("syntax = %q, want %q", got.Syntax, LeakSyntaxGLMXML)
	}
	if got.Call.Name != "zs_web_read" {
		t.Errorf("name = %q", got.Call.Name)
	}
	want := `{"url":"https://shuntool.com/article/will-sektion-cabinets-support-concrete-countertops"}`
	if got.Call.Arguments != want {
		t.Errorf("arguments = %s, want %s", got.Call.Arguments, want)
	}
	if !ScanLeakedToolCalls(content, leakNames, leakDefs).SoleOutput {
		t.Error("SoleOutput = false, want true — the markup was the entire answer")
	}
}

// The chat template emits one tag per line; a markdown renderer collapses it.
// Both must parse or the fix only works on whichever form we happened to see.
func TestScanLeakedToolCalls_GLMXMLMultiline(t *testing.T) {
	const content = "<tool_call>zs_web_search\n<arg_key>query</arg_key>\n<arg_value>concrete countertops</arg_value>\n<arg_key>max_results</arg_key>\n<arg_value>5</arg_value>\n</tool_call>"
	got := scanOne(t, content)
	if got.Call.Name != "zs_web_search" {
		t.Fatalf("name = %q", got.Call.Name)
	}
	// max_results is declared integer, so it must NOT arrive as "5" — the
	// tool unmarshals it into an int and a string would fail to execute.
	if !strings.Contains(got.Call.Arguments, `"max_results":5`) {
		t.Errorf("arguments = %s, want max_results as a number", got.Call.Arguments)
	}
	if !strings.Contains(got.Call.Arguments, `"query":"concrete countertops"`) {
		t.Errorf("arguments = %s, want query as a string", got.Call.Arguments)
	}
}

// A numeric-looking value for a string-declared param must stay a string, or
// a search for "2026" becomes a JSON number the tool rejects.
func TestScanLeakedToolCalls_NumericQueryStaysString(t *testing.T) {
	got := scanOne(t, `<tool_call>zs_web_search<arg_key>query</arg_key><arg_value>2026</arg_value></tool_call>`)
	if !strings.Contains(got.Call.Arguments, `"query":"2026"`) {
		t.Errorf("arguments = %s, want query quoted", got.Call.Arguments)
	}
}

// Qwen/Hermes share GLM's <tool_call> opener with a JSON body. Dispatching on
// the tag instead of the body sends this down the GLM branch and loses it.
func TestScanLeakedToolCalls_HermesJSON(t *testing.T) {
	got := scanOne(t, `<tool_call>{"name":"zs_web_read","arguments":{"url":"https://example.com/a"}}</tool_call>`)
	if got.Syntax != LeakSyntaxHermesJSON {
		t.Errorf("syntax = %q, want %q", got.Syntax, LeakSyntaxHermesJSON)
	}
	if !strings.Contains(got.Call.Arguments, `"url":"https://example.com/a"`) {
		t.Errorf("arguments = %s", got.Call.Arguments)
	}
}

func TestScanLeakedToolCalls_HermesJSONStringArguments(t *testing.T) {
	got := scanOne(t, `<tool_call>{"name":"zs_web_read","arguments":"{\"url\":\"https://example.com/b\"}"}</tool_call>`)
	if !strings.Contains(got.Call.Arguments, `"url":"https://example.com/b"`) {
		t.Errorf("arguments = %s — JSON-encoded-string arguments must be unwrapped", got.Call.Arguments)
	}
}

func TestScanLeakedToolCalls_FunctionCallsInvoke(t *testing.T) {
	const content = `<function_calls><invoke name="zs_web_read"><parameter name="url">https://example.com/c</parameter></invoke></function_calls>`
	got := scanOne(t, content)
	if got.Syntax != LeakSyntaxFunctionXML {
		t.Errorf("syntax = %q", got.Syntax)
	}
	if !strings.Contains(got.Call.Arguments, `"url":"https://example.com/c"`) {
		t.Errorf("arguments = %s", got.Call.Arguments)
	}
}

// The GLM-5 shape from the 0.13.2 incident. It carries no tool name, so it can
// only resolve when the request offered the web search built-in.
func TestScanLeakedToolCalls_FunctionQueries(t *testing.T) {
	const content = `<function_queries><search_query>sektion cabinet load</search_query></function_queries>`
	got := scanOne(t, content)
	if got.Call.Name != "zs_web_search" {
		t.Errorf("name = %q, want zs_web_search", got.Call.Name)
	}
	if !strings.Contains(got.Call.Arguments, `"query":"sektion cabinet load"`) {
		t.Errorf("arguments = %s", got.Call.Arguments)
	}
	// ...and must NOT resolve when search was not offered.
	only := map[string]BuiltinToolType{"zs_web_read": BuiltinToolType("zs_web_read")}
	if n := len(ScanLeakedToolCalls(content, only, leakDefs).Calls); n != 0 {
		t.Errorf("recovered %d calls without zs_web_search offered, want 0", n)
	}
}

// The delimiters are U+FF5C / U+2581. Written as escapes so an ASCII
// "normalization" of the source breaks this test instead of silently
// disabling the branch.
func TestScanLeakedToolCalls_DeepSeekControlTokens(t *testing.T) {
	content := "<｜tool▁calls▁begin｜><｜tool▁call▁begin｜>function<｜tool▁sep｜>zs_web_read\n```json\n{\"url\":\"https://example.com/d\"}\n```<｜tool▁call▁end｜><｜tool▁calls▁end｜>"
	got := scanOne(t, content)
	if got.Syntax != LeakSyntaxDeepSeek {
		t.Errorf("syntax = %q", got.Syntax)
	}
	if !strings.Contains(got.Call.Arguments, `"url":"https://example.com/d"`) {
		t.Errorf("arguments = %s", got.Call.Arguments)
	}
}

// THE load-bearing gate. Without it, any model narrating any tool protocol
// gets calls executed on its behalf.
func TestScanLeakedToolCalls_UnregisteredNameIgnored(t *testing.T) {
	const content = `<tool_call>get_weather<arg_key>city</arg_key><arg_value>Denver</arg_value></tool_call>`
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	if len(scan.Calls) != 0 {
		t.Fatalf("recovered %d calls for an unoffered tool, want 0", len(scan.Calls))
	}
	if StripLeakedToolCallMarkup(content, leakNames, leakDefs) != content {
		t.Error("an unrecognized span must be left in the text, not silently eaten")
	}
}

// A partial in-flight span, or a bare mention, must stay inert — and must not
// swallow the rest of the answer.
func TestScanLeakedToolCalls_IncompleteSpanIgnored(t *testing.T) {
	const content = `here is the answer <tool_call>zs_web_read<arg_key>url</arg_key>`
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	if len(scan.Calls) != 0 {
		t.Fatalf("recovered %d calls from an unclosed span, want 0", len(scan.Calls))
	}
	if got := StripLeakedToolCallMarkup(content, leakNames, leakDefs); got != content {
		t.Errorf("residue = %q, want the input unchanged", got)
	}
}

// The false-positive case that matters: a user asking about the syntax.
func TestScanLeakedToolCalls_ProseAroundSpanIsNotSoleOutput(t *testing.T) {
	const content = `A call looks like this: <tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com</arg_value></tool_call> and that is all.`
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	if len(scan.Calls) != 1 {
		t.Fatalf("want the span parsed, got %d", len(scan.Calls))
	}
	if scan.SoleOutput {
		t.Error("SoleOutput = true, want false — there is real prose around the span")
	}
}

func TestScanLeakedToolCalls_CleanAnswerIsUntouched(t *testing.T) {
	const content = "Yes, SEKTION cabinets support concrete countertops with proper bracing."
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	if len(scan.Calls) != 0 || scan.SoleOutput {
		t.Fatalf("clean answer produced %+v", scan)
	}
}

func TestStripLeakedToolCallMarkup_RemovesOnlyTheSpan(t *testing.T) {
	const content = `Before. <tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com</arg_value></tool_call> After.`
	got := StripLeakedToolCallMarkup(content, leakNames, leakDefs)
	if strings.Contains(got, "tool_call") {
		t.Errorf("residue still carries markup: %q", got)
	}
	if !strings.Contains(got, "Before.") || !strings.Contains(got, "After.") {
		t.Errorf("residue lost surrounding prose: %q", got)
	}
}

// ---------- length-terminated rounds ----------
//
// A backend that discards every structured tool call when generation hits the
// token cap (Kronk >=1.30.4) hands us the raw syntax as assistant content. The
// ordinary stripper deliberately keeps an unclosed span as prose; these helpers
// are the length-terminated exception.

func TestHasTruncatedToolCallMarkup(t *testing.T) {
	cases := []struct {
		name    string
		content string
		want    bool
	}{
		{"cut mid-arguments", `Looking that up. <tool_call>{"name":"zs_web_read","arguments":{"url":"https://exa`, true},
		{"cut right after the opener", `<tool_call>`, true},
		{"cut mid tool name", `<tool_call>zs_web_re`, true},
		{"closed span is not truncated", `<tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com</arg_value></tool_call>`, false},
		{"closed span then a truncated one", `<tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com</arg_value></tool_call> then <tool_call>{"name":"zs_web_sea`, true},
		{"no markup at all", "A perfectly ordinary answer that ran out of room", false},
		{"empty", "", false},

		// GLM's template is MULTI-LINE — a newline sits between the tool name
		// and the first <arg_key>, and only a markdown renderer collapses it
		// into the single-line form above. Trimming the name at `<` but not of
		// whitespace made every one of these read as prose, so the canonical
		// shape shipped to the payer as the answer while the collapsed one was
		// caught. All the single-line cases stayed green throughout.
		{"multi-line, cut mid arg_value", "<tool_call>zs_web_search\n<arg_key>query</arg_key>\n<arg_value>concrete counter", true},
		{"multi-line, cut right after the name", "<tool_call>zs_web_search\n", true},
		{"multi-line, cut mid arg_key", "<tool_call>zs_web_read\n<arg_ke", true},
		{"multi-line closed span is not truncated", "<tool_call>zs_web_read\n<arg_key>url</arg_key>\n<arg_value>https://example.com</arg_value>\n</tool_call>", false},
		{"multi-line, unoffered tool", "<tool_call>get_weather\n<arg_key>city", false},

		// The false positives that cost a payer their answer. An opener
		// mentioned in prose has no closer either, so only the body shape
		// separates these from a genuine truncation.
		{
			"prose mentioning an opener mid-sentence",
			"You will see a raw <tool_call> tag in the assistant text when the runtime has no parser configured.",
			false,
		},
		{
			"prose mentioning an opener at the very end",
			"The marker you are looking for is <tool_call>",
			true, // indistinguishable from a cut — see looksLikeTruncatedToolCallBody
		},
		{
			"unclosed opener naming a tool we never offered",
			`<tool_call>get_weather<arg_key>city`,
			false,
		},
		{
			// The counterpart to the multi-line cases: trimming the name of
			// whitespace must not turn "opener, newline, prose" into a match.
			// Interior whitespace is still what separates the two.
			"prose on the line after an opener",
			"The syntax is:\n<tool_call>\nfollowed by the tool name, then arg pairs.",
			false,
		},
		{
			"function_calls opener in prose",
			"The other format is <function_calls> which wraps invoke elements.",
			false,
		},
		{
			"function_calls genuinely cut",
			`<function_calls><invoke name="zs_web_read"><parameter name="url">htt`,
			true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasTruncatedToolCallMarkup(tc.content, leakNames, leakDefs); got != tc.want {
				t.Errorf("HasTruncatedToolCallMarkup(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

func TestHasTruncatedToolCallMarkup_RequiresOfferedName(t *testing.T) {
	offered := map[string]BuiltinToolType{"zs_web_search": "zs_web_search"}
	cases := []struct {
		name    string
		content string
		names   map[string]BuiltinToolType
		want    bool
	}{
		{"hermes offered partial", `<tool_call>{"name":"zs_web_sea`, offered, true},
		{"hermes unoffered partial", `<tool_call>{"name":"get_wea`, offered, false},
		{"hermes offered full", `<tool_call>{"name":"zs_web_search","arguments":`, offered, true},
		{"hermes unoffered full", `<tool_call>{"name":"get_weather","arguments":`, offered, false},
		{"hermes opener only remains detectable", `<tool_call>{`, offered, true},
		{"function xml offered partial", `<function_calls><invoke name="zs_web_sea`, offered, true},
		{"function xml unoffered partial", `<function_calls><invoke name="get_wea`, offered, false},
		{"function xml offered full", `<function_calls><invoke name="zs_web_search"><parameter`, offered, true},
		{"function xml unoffered full", `<function_calls><invoke name="get_weather"><parameter`, offered, false},
		{"function xml opener only remains detectable", `<function_calls><invoke`, offered, true},
		{"query xml offered", `<function_queries><search_que`, offered, true},
		{"query xml unoffered", `<function_queries><search_que`, map[string]BuiltinToolType{"zs_web_read": "zs_web_read"}, false},
		{"query outer opener only remains detectable", `<function_queries>`, offered, true},
		{"deepseek offered partial", deepSeekCallsBegin + deepSeekCallBegin + `function` + deepSeekSep + `zs_web_sea`, offered, true},
		{"deepseek unoffered partial", deepSeekCallsBegin + deepSeekCallBegin + `function` + deepSeekSep + `get_wea`, offered, false},
		{"deepseek offered full", deepSeekCallsBegin + deepSeekCallBegin + `function` + deepSeekSep + "zs_web_search\n```json", offered, true},
		{"deepseek unoffered full", deepSeekCallsBegin + deepSeekCallBegin + `function` + deepSeekSep + "get_weather\n```json", offered, false},
		{"deepseek opener only remains detectable", deepSeekCallsBegin, offered, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasTruncatedToolCallMarkup(tc.content, tc.names, leakDefs); got != tc.want {
				t.Errorf("HasTruncatedToolCallMarkup(%q) = %v, want %v", tc.content, got, tc.want)
			}
		})
	}
}

// The regression that made this function dangerous: it trimmed from the FIRST
// unclosed opener anywhere in the content, so a length-terminated answer that
// merely discussed the syntax lost everything after the mention.
func TestStripTruncatedToolCallMarkup_KeepsProseThatMentionsAnOpener(t *testing.T) {
	const content = "When a runtime has no tool-call parser you will see a raw <tool_call> tag " +
		"in the assistant text. The fix is to pass --tool-call-parser matching the chat template."

	if got := StripTruncatedToolCallMarkup(content, leakNames, leakDefs); got != content {
		t.Errorf("prose was eaten.\n got: %q\nwant: %q", got, content)
	}
}

// The common truncation shape: the cap lands mid-arguments, so no closer ever
// arrives and the ordinary stripper has nothing to remove.
func TestStripTruncatedToolCallMarkup_DropsUnclosedSpan(t *testing.T) {
	const content = `Let me look that up. <tool_call>{"name":"zs_web_read","arguments":{"url":"https://exa`

	if got := StripLeakedToolCallMarkup(content, leakNames, leakDefs); got != content {
		t.Fatalf("precondition: the ordinary stripper should leave an unclosed span alone, got %q", got)
	}

	got := StripTruncatedToolCallMarkup(content, leakNames, leakDefs)
	if strings.Contains(got, "tool_call") {
		t.Errorf("truncated span survived: %q", got)
	}
	if !strings.Contains(got, "Let me look that up.") {
		t.Errorf("prose before the span was lost: %q", got)
	}
}

// GLM-4.x's own template, unrendered. The equivalent single-line test above
// passed the whole time this one would have failed — the name carried a
// trailing newline and read as prose, so the markup went to the payer as the
// answer. Exact comparison: a Contains check on "tool_call" also passes when
// the trim eats the leading prose along with the span.
func TestStripTruncatedToolCallMarkup_DropsUnclosedMultiLineGLMSpan(t *testing.T) {
	const content = "Let me look that up.\n<tool_call>zs_web_search\n<arg_key>query</arg_key>\n<arg_value>concrete counter"

	if got := StripLeakedToolCallMarkup(content, leakNames, leakDefs); got != content {
		t.Fatalf("precondition: the ordinary stripper should leave an unclosed span alone, got %q", got)
	}

	const want = "Let me look that up.\n"
	if got := StripTruncatedToolCallMarkup(content, leakNames, leakDefs); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// The shape that silently dropped a call: one span completed, a second was cut
// off. Both have to go — the completed one is not dispatched on a void round,
// so leaving its markup in the answer would just be protocol text.
func TestStripTruncatedToolCallMarkup_DropsCompletedAndTruncatedSpans(t *testing.T) {
	const content = `Sure. <tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com</arg_value></tool_call> and also <tool_call>{"name":"zs_web_sea`

	// Exact, not Contains: the prose BETWEEN the two spans is what distinguishes
	// "trim the unterminated tail, then strip the closed span" from "trim
	// everything from the first opener onward". A Contains check passes under
	// both.
	const want = `Sure.  and also `
	if got := StripTruncatedToolCallMarkup(content, leakNames, leakDefs); got != want {
		t.Errorf("got  %q\nwant %q", got, want)
	}
}

// ---------- body-level strip ----------
//
// StripTruncated{Chat,Responses}BodyMarkup are what the node actually calls;
// the string-level helper above is only their inner half. The Responses twin
// silently returned the body UNCHANGED when stripping emptied a message item,
// which is the canonical void-round shape.

func TestStripTruncatedChatBodyMarkup_EmptiesAllMarkupContent(t *testing.T) {
	const markup = `<tool_call>{"name":"zs_web_read","arguments":{"url":"https://exa`
	msg, _ := json.Marshal(map[string]any{"role": "assistant", "content": markup})
	body, _ := json.Marshal(map[string]any{
		"choices": []any{map[string]any{"index": 0, "message": json.RawMessage(msg), "finish_reason": "length"}},
	})

	got, err := StripTruncatedChatBodyMarkup(body, leakNames, leakDefs)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	assertNoToolCallMarkup(t, got)
}

func TestStripTruncatedResponsesBodyMarkup_EmptiesAllMarkupItem(t *testing.T) {
	const markup = `<tool_call>{"name":"zs_web_read","arguments":{"url":"https://exa`
	body, _ := json.Marshal(map[string]any{
		"status":             "incomplete",
		"incomplete_details": map[string]any{"reason": "max_output_tokens"},
		"output": []any{map[string]any{
			"type": "message", "role": "assistant", "id": "msg_1",
			"content": []any{map[string]any{"type": "output_text", "text": markup}},
		}},
	})

	got, err := StripTruncatedResponsesBodyMarkup(body, leakNames, leakDefs)
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	assertNoToolCallMarkup(t, got)

	// The item itself must survive — a consumer indexing output[] still expects
	// the assistant message to be there.
	var shaped struct {
		Output []struct {
			Type string `json:"type"`
			ID   string `json:"id"`
		} `json:"output"`
	}
	if err := json.Unmarshal(got, &shaped); err != nil {
		t.Fatalf("result is not JSON: %v", err)
	}
	if len(shaped.Output) != 1 || shaped.Output[0].Type != "message" || shaped.Output[0].ID != "msg_1" {
		t.Errorf("emptied item was dropped or mangled: %s", got)
	}
}

// assertNoToolCallMarkup fails if any string ANYWHERE in the decoded body
// still carries a tool-call opener.
//
// It walks decoded values rather than the raw bytes on purpose. encoding/json
// escapes `<` to `<`, so the `strings.Contains(raw, "tool_call>")` idiom
// used elsewhere in this package cannot match a re-marshalled body at all — a
// strip that did nothing and a strip that worked both look identical to it.
// Trying to undo that with a string replacer is how the first version of this
// helper became a no-op.
func assertNoToolCallMarkup(t *testing.T, raw []byte) {
	t.Helper()
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, raw)
	}
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			for _, opener := range []string{"<tool_call>", "<function_calls>", "<function_queries>", deepSeekCallsBegin} {
				if strings.Contains(x, opener) {
					t.Errorf("markup survived the strip, in %q", x)
				}
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(decoded)
}

// The stripper must not eat an answer that merely ran out of room.
func TestStripTruncatedToolCallMarkup_LeavesCleanTruncatedProse(t *testing.T) {
	const content = "Concrete countertops need bracing because the span between"
	if got := StripTruncatedToolCallMarkup(content, leakNames, leakDefs); got != content {
		t.Errorf("got %q, want the input unchanged", got)
	}
}

// The orphan-tool-message fix: the repaired assistant turn must CLAIM the
// call, with the same id the loop will dispatch.
func TestRepairChatAssistantWithRecoveredCalls(t *testing.T) {
	const content = `<tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com/e</arg_value></tool_call>`
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	msg, _ := json.Marshal(map[string]any{"role": "assistant", "content": content})

	repaired, dispatch, err := RepairChatAssistantWithRecoveredCalls(msg, scan, leakNames, leakDefs)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if len(dispatch) != 1 || dispatch[0].ID == "" {
		t.Fatalf("dispatch = %+v, want one call with an id", dispatch)
	}
	var got struct {
		Content   *string `json:"content"`
		ToolCalls []struct {
			ID       string `json:"id"`
			Type     string `json:"type"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		} `json:"tool_calls"`
	}
	if err := json.Unmarshal(repaired, &got); err != nil {
		t.Fatalf("unmarshal repaired: %v", err)
	}
	if len(got.ToolCalls) != 1 {
		t.Fatalf("repaired assistant carries %d tool_calls, want 1 — without it the next iteration sends an orphan tool message", len(got.ToolCalls))
	}
	if got.ToolCalls[0].ID != dispatch[0].ID {
		t.Errorf("assistant id %q != dispatched id %q", got.ToolCalls[0].ID, dispatch[0].ID)
	}
	if got.ToolCalls[0].Function.Name != "zs_web_read" {
		t.Errorf("name = %q", got.ToolCalls[0].Function.Name)
	}
	if got.Content != nil {
		t.Errorf("content = %q, want null once the markup is stripped", *got.Content)
	}
}

func TestRepairChatAssistantWithRecoveredCalls_KeepsSurvivingProse(t *testing.T) {
	const content = `Let me look that up. <tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com/f</arg_value></tool_call>`
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	msg, _ := json.Marshal(map[string]any{"role": "assistant", "content": content})
	repaired, _, err := RepairChatAssistantWithRecoveredCalls(msg, scan, leakNames, leakDefs)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	var got struct {
		Content *string `json:"content"`
	}
	_ = json.Unmarshal(repaired, &got)
	if got.Content == nil || *got.Content != "Let me look that up." {
		t.Errorf("content = %v, want the prose kept and the markup gone", got.Content)
	}
}

func TestRepairResponsesItemsWithRecoveredCalls(t *testing.T) {
	const content = `<tool_call>zs_web_read<arg_key>url</arg_key><arg_value>https://example.com/g</arg_value></tool_call>`
	scan := ScanLeakedToolCalls(content, leakNames, leakDefs)
	msgItem, _ := json.Marshal(map[string]any{
		"type":    "message",
		"role":    "assistant",
		"content": []any{map[string]any{"type": "output_text", "text": content}},
	})

	items, dispatch, err := RepairResponsesItemsWithRecoveredCalls([]json.RawMessage{msgItem}, scan, leakNames, leakDefs)
	if err != nil {
		t.Fatalf("repair: %v", err)
	}
	if len(dispatch) != 1 || dispatch[0].ID == "" {
		t.Fatalf("dispatch = %+v", dispatch)
	}
	var sawFunctionCall bool
	for _, it := range items {
		var shaped struct {
			Type   string `json:"type"`
			CallID string `json:"call_id"`
			Name   string `json:"name"`
		}
		_ = json.Unmarshal(it, &shaped)
		if shaped.Type == "function_call" {
			sawFunctionCall = true
			if shaped.CallID != dispatch[0].ID {
				t.Errorf("call_id %q != dispatched id %q", shaped.CallID, dispatch[0].ID)
			}
			if shaped.Name != "zs_web_read" {
				t.Errorf("name = %q", shaped.Name)
			}
		}
		if strings.Contains(string(it), "tool_call>") {
			t.Errorf("item still carries markup: %s", it)
		}
	}
	if !sawFunctionCall {
		t.Fatal("no synthesized function_call item — the function_call_output would have nothing to bind to")
	}
}

func TestStitchers_ContentAccessors(t *testing.T) {
	chat := NewChatToolCallStitcher(leakNames)
	chat.Observe([]byte(`{"choices":[{"delta":{"content":"hello "}}]}`))
	chat.Observe([]byte(`{"choices":[{"delta":{"content":"world"}}]}`))
	if got := chat.Content(); got != "hello world" {
		t.Errorf("chat Content() = %q", got)
	}

	resp := NewResponsesToolCallStitcher(leakNames)
	resp.Observe([]byte(`{"type":"response.output_text.delta","delta":"abc"}`))
	if got := resp.Content(); got != "abc" {
		t.Errorf("responses Content() = %q", got)
	}
}
