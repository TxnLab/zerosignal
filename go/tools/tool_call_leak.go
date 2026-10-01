/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"strings"
)

// A model asks for a tool by emitting its chat template's tool-call tokens.
// The SERVING RUNTIME is what turns those tokens into a structured
// `tool_calls` delta — vLLM/SGLang only do it with a `--tool-call-parser`
// matching the template, and a managed API only does it when the request is
// actually asking for tool calls. When that parsing does not happen the tokens
// are not lost: they arrive verbatim in the visible content channel, and the
// tool loop, which decides "another round or done?" purely on whether any
// STRUCTURED call was stitched, reads the round as a finished answer and ships
// the raw markup to the user as the reply. The call never runs, so the answer
// is silently incomplete as well as ugly.
//
// This file is the detector for that. It is deliberately a CONTENT-side
// recovery path and not a general-purpose tool-call parser: everything here
// exists to answer one question — "did this round actually want a tool we
// offer, and just fail to say so structurally?"
//
// Observed in the wild against glm-4.7-flash on a long `zs_web_search` /
// `zs_web_read` research turn, where the whole visible answer was a single
// `<tool_call>zs_web_read<arg_key>url</arg_key>…</tool_call>`.

// LeakSyntax names the chat-template vocabulary a leaked call was written in.
// Carried on the scan result so the metric can tell an operator WHICH family
// their backend is failing to parse, which is the difference between a useful
// bug report to their provider and a shrug.
type LeakSyntax string

const (
	// LeakSyntaxGLMXML is GLM-4.x's template:
	// `<tool_call>NAME<arg_key>k</arg_key><arg_value>v</arg_value></tool_call>`.
	LeakSyntaxGLMXML LeakSyntax = "glm_xml"
	// LeakSyntaxHermesJSON is the Qwen / Hermes / NousResearch template:
	// `<tool_call>{"name":…,"arguments":{…}}</tool_call>`. Note it shares its
	// OPENER with GLM — the two are told apart by the body, never the tag.
	LeakSyntaxHermesJSON LeakSyntax = "hermes_json"
	// LeakSyntaxFunctionXML is the GLM-4.5/5.x family:
	// `<function_calls><invoke name="X"><parameter name="k">v</parameter>…`,
	// and its search-flavoured sibling `<function_queries><search_query>…`.
	LeakSyntaxFunctionXML LeakSyntax = "function_calls"
	// LeakSyntaxDeepSeek is DeepSeek-R1's control-token span. The delimiters
	// use U+FF5C (fullwidth vertical line) and U+2581 (lower one eighth
	// block), NOT ASCII `|` / `_` — see the consts below.
	LeakSyntaxDeepSeek LeakSyntax = "deepseek"
)

// DeepSeek-R1's tool-call control tokens, written as explicit escapes.
// Spelling these as pasted glyphs invites a well-meaning "normalize to ASCII"
// edit that would silently disable the whole branch while every test that
// feeds the same escapes keeps passing.
const (
	deepSeekCallsBegin = "<｜tool▁calls▁begin｜>"
	deepSeekCallsEnd   = "<｜tool▁calls▁end｜>"
	deepSeekSep        = "<｜tool▁sep｜>"
	deepSeekCallBegin  = "<｜tool▁call▁begin｜>"
	deepSeekCallEnd    = "<｜tool▁call▁end｜>"
)

// queryLeakTool is the one tool `<function_queries><search_query>` can mean —
// that syntax carries no name, so the name gate resolves to this constant on
// both the closed-span path (parseQueryBody) and the truncated one
// (looksLikeTruncatedToolCallBody). Shared so the two cannot drift.
const queryLeakTool = "zs_web_search"

// LeakedToolCall is one call recovered from the content channel.
type LeakedToolCall struct {
	// Call carries Name and canonical JSON Arguments. ID is empty until one
	// of the Repair* helpers mints it — the id must be identical on the
	// assistant turn and on the tool result, so only they may assign it.
	Call   ToolCall
	Syntax LeakSyntax
}

// LeakScan is the result of scanning one round's visible content.
type LeakScan struct {
	// Calls is every recovered call, in emission order. Empty means nothing
	// recognizable was found, which is the overwhelmingly common case.
	Calls []LeakedToolCall
	// SoleOutput reports that the recognized spans were the ENTIRE
	// non-whitespace visible content — i.e. this round produced no prose at
	// all, only markup.
	//
	// It is doing two jobs at once, deliberately. It is the strongest
	// false-positive gate: a user who asks "show me what a zs_web_search call
	// looks like" gets prose around the example, so SoleOutput is false and
	// nothing is recovered. And it is the honest test of "did this round
	// answer the user" — a round that produced real prose is worth shipping
	// whatever else it contains, and a round that produced only markup is not.
	SoleOutput bool
}

// ScanLeakedToolCalls finds native tool-call markup that the upstream failed
// to parse into structured tool calls, in any of the templates above.
//
// names is the request's offered built-in tools (function name → type) and is
// the LOAD-BEARING GATE: a parsed call whose name is not a key here is
// ignored entirely, so a model narrating some other system's tool protocol is
// never acted on. defs supplies each tool's JSON Schema, used only to give
// argument values their declared types (see coerceArgValue); a missing def
// degrades to string-valued arguments rather than failing.
//
// Callers must additionally only consult this when the round produced ZERO
// structured tool calls. Between that entry condition, the name gate, and
// SoleOutput, a legitimate mention of tool-call syntax in an answer cannot
// trigger recovery.
func ScanLeakedToolCalls(content string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) LeakScan {
	if content == "" || len(names) == 0 {
		return LeakScan{}
	}
	// Cheap early-out: the hot path is every ordinary answer, which contains
	// none of these openers.
	if !strings.Contains(content, "<tool_call>") &&
		!strings.Contains(content, "<function_calls>") &&
		!strings.Contains(content, "<function_queries>") &&
		!strings.Contains(content, deepSeekCallsBegin) {
		return LeakScan{}
	}

	calls, residue := scanLeakSpans(content, names, defs)
	if len(calls) == 0 {
		return LeakScan{}
	}
	return LeakScan{Calls: calls, SoleOutput: strings.TrimSpace(residue) == ""}
}

// StripLeakedToolCallMarkup removes every span ScanLeakedToolCalls recognized,
// returning what a user should have seen. Spans that did NOT resolve to an
// offered tool are left in place — they are the model's prose, not our
// protocol, and silently eating them would be a different bug.
func StripLeakedToolCallMarkup(content string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) string {
	if content == "" || len(names) == 0 {
		return content
	}
	_, residue := scanLeakSpans(content, names, defs)
	return residue
}

// scanLeakSpans walks content once, returning the recovered calls and the
// content with each recovered span removed. A span that fails to parse, or
// that names no offered tool, is left in the residue and the walk resumes
// after its opener — so an incomplete `<tool_call>` mention can never swallow
// the rest of an answer.
func scanLeakSpans(content string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]LeakedToolCall, string) {
	var (
		calls   []LeakedToolCall
		residue strings.Builder
		i       int
	)
	for i < len(content) {
		opener, at := nextLeakOpener(content[i:])
		if at < 0 {
			residue.WriteString(content[i:])
			break
		}
		residue.WriteString(content[i : i+at])
		spanStart := i + at
		found, spanEnd := parseLeakSpan(content, spanStart, opener, names, defs)
		if len(found) == 0 {
			// Unrecognized or incomplete: keep the opener as literal text and
			// resume immediately after it.
			residue.WriteString(opener)
			i = spanStart + len(opener)
			continue
		}
		calls = append(calls, found...)
		i = spanEnd
	}
	return calls, residue.String()
}

// nextLeakOpener returns the earliest known opener in s and its offset, or
// ("", -1). Earliest-wins matters because the vocabularies can nest textually
// (a `<function_calls>` block may quote a `<tool_call>`), and processing them
// out of order would mis-slice the span.
func nextLeakOpener(s string) (string, int) {
	openers := []string{"<tool_call>", "<function_calls>", "<function_queries>", deepSeekCallsBegin}
	best, bestAt := "", -1
	for _, o := range openers {
		if at := strings.Index(s, o); at >= 0 && (bestAt < 0 || at < bestAt) {
			best, bestAt = o, at
		}
	}
	return best, bestAt
}

// leakCloserFor maps a known opener to its closer.
func leakCloserFor(opener string) (string, bool) {
	switch opener {
	case "<tool_call>":
		return "</tool_call>", true
	case "<function_calls>":
		return "</function_calls>", true
	case "<function_queries>":
		return "</function_queries>", true
	case deepSeekCallsBegin:
		return deepSeekCallsEnd, true
	default:
		return "", false
	}
}

// trimTruncatedToolCallSpan drops a tool-call span that generation stopped in
// the middle of, returning the content up to its opener.
//
// ONLY correct on a round the upstream terminated for length. In the general
// case an unclosed opener is prose — a model describing the syntax — and
// scanLeakSpans deliberately keeps it as literal text.
//
// Two gates keep this off ordinary prose, and both are load-bearing:
//
//  1. The walk mirrors scanLeakSpans exactly — same parseLeakSpan, same
//     resume-after-the-opener when a span yields nothing — so the trim can
//     never disagree with the scan about where a span ends. An earlier version
//     re-implemented the closer search and drifted: it would borrow a LATER
//     span's closer and declare an unterminated span complete.
//  2. An unterminated opener counts as truncation only when what follows it
//     looks like the START of a tool-call body. `<tool_call> tag in the docs`
//     is a model talking about the syntax; `<tool_call>{"name":"zs_web_sea` is
//     a model that ran out of tokens. Without this, a length-terminated answer
//     that merely MENTIONS an opener loses everything after it — which is
//     exactly the false positive SoleOutput exists to prevent, and the
//     truncated path does not get to consult SoleOutput because a span that
//     never closed produces no scan result at all.
func trimTruncatedToolCallSpan(content string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) (string, bool) {
	for i := 0; i < len(content); {
		opener, at := nextLeakOpener(content[i:])
		if at < 0 {
			return content, false
		}
		spanStart := i + at
		found, spanEnd := parseLeakSpan(content, spanStart, opener, names, defs)
		if len(found) > 0 {
			i = spanEnd
			continue
		}
		// No calls came out. Either the span never closed — a truncation
		// candidate — or it closed and did not resolve to an offered tool, in
		// which case scanLeakSpans leaves it in the residue and so must we.
		if !leakSpanClosed(content, spanStart, opener) &&
			looksLikeTruncatedToolCallBody(content[spanStart+len(opener):], opener, names) {
			return content[:spanStart], true
		}
		i = spanStart + len(opener)
	}
	return content, false
}

// leakSpanClosed reports whether the span opening at start has its closer
// anywhere after it.
func leakSpanClosed(content string, start int, opener string) bool {
	closer, ok := leakCloserFor(opener)
	if !ok {
		return false
	}
	return strings.Contains(content[start+len(opener):], closer)
}

// looksLikeTruncatedToolCallBody reports whether body — the text after an
// unterminated opener — is plausibly the beginning of a tool-call body rather
// than prose. Deliberately conservative: a false negative leaves markup in an
// answer, a false positive deletes the rest of a real one.
func looksLikeTruncatedToolCallBody(body, opener string, names map[string]BuiltinToolType) bool {
	body = strings.TrimLeft(body, " \t\r\n")
	if body == "" {
		// Generation stopped on the opener itself.
		return true
	}
	switch opener {
	case "<tool_call>":
		// Hermes / Qwen put a JSON object here.
		if strings.HasPrefix(body, "{") {
			return looksLikeTruncatedHermesBody(body, names)
		}
		// GLM puts a bare tool name. It may itself be cut short, so match it as
		// a PREFIX of something we offered — which restores a form of the name
		// gate that a truncated span would otherwise escape.
		//
		// TrimSpace, not just the leading trim above: the template's multi-line
		// form puts a newline between the name and the first <arg_key>, and
		// parseGLMBody trims it the same way. Testing the untrimmed name for
		// interior whitespace made every multi-line GLM truncation read as
		// prose — i.e. the canonical shape went undetected while the collapsed
		// single-line one worked.
		name := body
		if j := strings.IndexByte(name, '<'); j >= 0 {
			name = name[:j]
		}
		name = strings.TrimSpace(name)
		// Interior whitespace still means prose: `<tool_call> tag in the docs`
		// is a model describing the syntax, not one that ran out of tokens.
		if name == "" || strings.ContainsAny(name, " \t\r\n") {
			return false
		}
		return isOfferedToolNamePrefix(name, names)
	case "<function_calls>":
		return looksLikeTruncatedInvokeBody(body, names)
	case "<function_queries>":
		// This syntax has no explicit function name: search_query itself names
		// the one tool it can mean. Once that child opener is visible, restore
		// the same offered-tool gate every explicit-name syntax applies.
		if body == "" {
			return true
		}
		// Exact membership, not a prefix match: the name is a fixed constant
		// here, so this is the same lookup parseQueryBody does on a closed span.
		_, offered := names[queryLeakTool]
		return offered &&
			(strings.HasPrefix("<search_query", body) || strings.HasPrefix(body, "<search_query"))
	case deepSeekCallsBegin:
		return looksLikeTruncatedDeepSeekBody(body, names)
	}
	return false
}

// looksLikeTruncatedHermesBody recognizes the beginning of
// {"name":"TOOL",...}. An opener or object before the name value is
// inherently ambiguous and remains detectable; once any name bytes are
// visible, they must prefix a tool offered on this request.
func looksLikeTruncatedHermesBody(body string, names map[string]BuiltinToolType) bool {
	body = strings.TrimSpace(body)
	if body == "{" {
		return true
	}
	nameKey := strings.Index(body, `"name"`)
	if nameKey < 0 {
		// A partial key is still before the tool name itself.
		return strings.HasPrefix(`{"name"`, body)
	}
	rest := strings.TrimSpace(body[nameKey+len(`"name"`):])
	if rest == "" || rest == ":" {
		return true
	}
	if rest[0] != ':' {
		return false
	}
	rest = strings.TrimSpace(rest[1:])
	if rest == "" || rest == `"` {
		return true
	}
	if rest[0] != '"' {
		return false
	}
	name := rest[1:]
	if end := strings.IndexByte(name, '"'); end >= 0 {
		name = name[:end]
	}
	return name != "" && isOfferedToolNamePrefix(name, names)
}

// looksLikeTruncatedInvokeBody recognizes <invoke name="TOOL"... with the
// same rule: the opener alone is ambiguous, but exposed name bytes are gated.
func looksLikeTruncatedInvokeBody(body string, names map[string]BuiltinToolType) bool {
	if body == "" || strings.HasPrefix("<invoke", body) {
		return true
	}
	if !strings.HasPrefix(body, "<invoke") {
		return false
	}
	rest := body[len("<invoke"):]
	nameAt := strings.Index(rest, "name=")
	if nameAt < 0 {
		return !strings.ContainsAny(rest, ">\n\r")
	}
	rest = strings.TrimSpace(rest[nameAt+len("name="):])
	if rest == "" || rest == `"` || rest == `'` {
		return true
	}
	quote := rest[0]
	if quote != '"' && quote != '\'' {
		return false
	}
	name := rest[1:]
	if end := strings.IndexByte(name, quote); end >= 0 {
		name = name[:end]
	} else if end := strings.IndexAny(name, " >\t\r\n"); end >= 0 {
		name = name[:end]
	}
	return name != "" && isOfferedToolNamePrefix(name, names)
}

// looksLikeTruncatedDeepSeekBody recognizes the control-token prefix and, once
// function<sep> exposes a name, requires it to prefix an offered tool.
func looksLikeTruncatedDeepSeekBody(body string, names map[string]BuiltinToolType) bool {
	if body == "" || strings.HasPrefix(deepSeekCallBegin, body) {
		return true
	}
	if !strings.HasPrefix(body, deepSeekCallBegin) {
		return false
	}
	rest := strings.TrimSpace(body[len(deepSeekCallBegin):])
	if rest == "" || strings.HasPrefix("function", rest) {
		return true
	}
	if !strings.HasPrefix(rest, "function") {
		return false
	}
	rest = strings.TrimSpace(rest[len("function"):])
	if rest == "" || strings.HasPrefix(deepSeekSep, rest) {
		return true
	}
	if !strings.HasPrefix(rest, deepSeekSep) {
		return false
	}
	name := strings.TrimSpace(rest[len(deepSeekSep):])
	if name == "" {
		return true
	}
	if end := strings.IndexAny(name, "\r\n< \t"); end >= 0 {
		name = name[:end]
	}
	return name != "" && isOfferedToolNamePrefix(name, names)
}

func isOfferedToolNamePrefix(s string, names map[string]BuiltinToolType) bool {
	for name := range names {
		if strings.HasPrefix(name, s) {
			return true
		}
	}
	return false
}

// HasTruncatedToolCallMarkup reports whether content carries a tool-call span
// that generation stopped inside. See trimTruncatedToolCallSpan for why this is
// only meaningful on a length-terminated round.
func HasTruncatedToolCallMarkup(content string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) bool {
	_, found := trimTruncatedToolCallSpan(content, names, defs)
	return found
}

// StripTruncatedToolCallMarkup is StripLeakedToolCallMarkup for a round the
// upstream cut off for length: it additionally drops a span generation stopped
// inside, which the ordinary stripper leaves in place as prose.
//
// Both halves are needed. A backend that discards every structured call on a
// token-capped round (Kronk ≥1.30.4) can leave behind a completed span AND a
// partial one, and shipping either to the payer as the answer is protocol text
// presented as prose.
func StripTruncatedToolCallMarkup(content string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) string {
	trimmed, _ := trimTruncatedToolCallSpan(content, names, defs)
	return StripLeakedToolCallMarkup(trimmed, names, defs)
}

// parseLeakSpan parses the span opening at start and returns its calls plus
// the offset just past its closer. A missing closer yields no calls, which is
// how a partial in-flight span (or a bare mention) stays inert.
func parseLeakSpan(content string, start int, opener string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]LeakedToolCall, int) {
	closer, ok := leakCloserFor(opener)
	if !ok {
		return nil, start + len(opener)
	}
	bodyStart := start + len(opener)
	rel := strings.Index(content[bodyStart:], closer)
	if rel < 0 {
		return nil, bodyStart
	}
	body := content[bodyStart : bodyStart+rel]
	end := bodyStart + rel + len(closer)

	var calls []LeakedToolCall
	switch opener {
	case "<tool_call>":
		// One opener, two templates. Dispatch on the BODY (a JSON object means
		// Hermes/Qwen), never on the tag — GLM and Qwen share `<tool_call>`.
		if strings.HasPrefix(strings.TrimSpace(body), "{") {
			calls = parseHermesBody(body, names, defs)
		} else {
			calls = parseGLMBody(body, names, defs)
		}
	case "<function_calls>":
		calls = parseInvokeBody(body, names, defs)
	case "<function_queries>":
		calls = parseQueryBody(body, names, defs)
	case deepSeekCallsBegin:
		calls = parseDeepSeekBody(body, names, defs)
	}
	if len(calls) == 0 {
		return nil, end
	}
	return calls, end
}

// parseGLMBody reads GLM-4.x's form: a bare tool name, then repeated
// <arg_key>/<arg_value> pairs. Whitespace between tags is insignificant, so
// both the template's multi-line form and the single-line form a markdown
// renderer collapses it into parse identically.
func parseGLMBody(body string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) []LeakedToolCall {
	name := body
	if at := strings.Index(body, "<arg_key>"); at >= 0 {
		name = body[:at]
	}
	name = strings.TrimSpace(name)
	props, ok := toolProperties(name, names, defs)
	if !ok {
		return nil
	}
	args := map[string]json.RawMessage{}
	rest := body
	for {
		ks := strings.Index(rest, "<arg_key>")
		if ks < 0 {
			break
		}
		ke := strings.Index(rest[ks:], "</arg_key>")
		if ke < 0 {
			break
		}
		key := strings.TrimSpace(rest[ks+len("<arg_key>") : ks+ke])
		rest = rest[ks+ke+len("</arg_key>"):]

		vs := strings.Index(rest, "<arg_value>")
		if vs < 0 {
			break
		}
		ve := strings.Index(rest[vs:], "</arg_value>")
		if ve < 0 {
			break
		}
		val := strings.TrimSpace(rest[vs+len("<arg_value>") : vs+ve])
		rest = rest[vs+ve+len("</arg_value>"):]
		if key != "" {
			args[key] = coerceArgValue(props, key, val)
		}
	}
	return oneCall(name, args, LeakSyntaxGLMXML)
}

// parseHermesBody reads `{"name":…,"arguments":{…}}`. `arguments` is accepted
// both as an object and as a JSON-encoded string, because both are emitted in
// the wild by templates in this family.
func parseHermesBody(body string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) []LeakedToolCall {
	var shaped struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if json.Unmarshal([]byte(strings.TrimSpace(body)), &shaped) != nil {
		return nil
	}
	name := strings.TrimSpace(shaped.Name)
	if _, ok := toolProperties(name, names, defs); !ok {
		return nil
	}
	argsJSON := shaped.Arguments
	if len(argsJSON) > 0 && argsJSON[0] == '"' {
		var inner string
		if json.Unmarshal(argsJSON, &inner) == nil {
			argsJSON = json.RawMessage(inner)
		}
	}
	if len(argsJSON) == 0 || !json.Valid(argsJSON) {
		argsJSON = json.RawMessage(`{}`)
	}
	return []LeakedToolCall{{
		Call:   ToolCall{Name: name, Arguments: string(argsJSON)},
		Syntax: LeakSyntaxHermesJSON,
	}}
}

// parseInvokeBody reads `<invoke name="X"><parameter name="k">v</parameter>…`.
func parseInvokeBody(body string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) []LeakedToolCall {
	var out []LeakedToolCall
	rest := body
	for {
		is := strings.Index(rest, "<invoke")
		if is < 0 {
			break
		}
		ie := strings.Index(rest[is:], "</invoke>")
		if ie < 0 {
			break
		}
		block := rest[is : is+ie]
		rest = rest[is+ie+len("</invoke>"):]

		name := attrValue(block, "name")
		props, ok := toolProperties(name, names, defs)
		if !ok {
			continue
		}
		args := map[string]json.RawMessage{}
		inner := block
		for {
			ps := strings.Index(inner, "<parameter")
			if ps < 0 {
				break
			}
			pe := strings.Index(inner[ps:], "</parameter>")
			if pe < 0 {
				break
			}
			pblock := inner[ps : ps+pe]
			inner = inner[ps+pe+len("</parameter>"):]
			key := attrValue(pblock, "name")
			gt := strings.Index(pblock, ">")
			if key == "" || gt < 0 {
				continue
			}
			args[key] = coerceArgValue(props, key, strings.TrimSpace(pblock[gt+1:]))
		}
		out = append(out, oneCall(name, args, LeakSyntaxFunctionXML)...)
	}
	return out
}

// parseQueryBody reads GLM-5's search-flavoured
// `<function_queries><search_query>…</search_query>…` shape. It carries no
// tool name, so it can only be resolved when the request offered the web
// search built-in — the sole tool whose contract is "take a query string".
func parseQueryBody(body string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) []LeakedToolCall {
	props, ok := toolProperties(queryLeakTool, names, defs)
	if !ok {
		return nil
	}
	var out []LeakedToolCall
	rest := body
	for {
		qs := strings.Index(rest, "<search_query>")
		if qs < 0 {
			break
		}
		qe := strings.Index(rest[qs:], "</search_query>")
		if qe < 0 {
			break
		}
		q := strings.TrimSpace(rest[qs+len("<search_query>") : qs+qe])
		rest = rest[qs+qe+len("</search_query>"):]
		if q == "" {
			continue
		}
		out = append(out, oneCall(queryLeakTool,
			map[string]json.RawMessage{"query": coerceArgValue(props, "query", q)},
			LeakSyntaxFunctionXML)...)
	}
	return out
}

// parseDeepSeekBody reads the control-token span, whose per-call payload is
// `function<sep>NAME\n```json\n{…}\n````.
func parseDeepSeekBody(body string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) []LeakedToolCall {
	var out []LeakedToolCall
	rest := body
	for {
		cs := strings.Index(rest, deepSeekCallBegin)
		if cs < 0 {
			break
		}
		rest = rest[cs+len(deepSeekCallBegin):]
		block := rest
		if ce := strings.Index(rest, deepSeekCallEnd); ce >= 0 {
			block = rest[:ce]
			rest = rest[ce+len(deepSeekCallEnd):]
		} else {
			rest = ""
		}
		sep := strings.Index(block, deepSeekSep)
		if sep < 0 {
			continue
		}
		after := block[sep+len(deepSeekSep):]
		nl := strings.IndexAny(after, "\n\r")
		if nl < 0 {
			nl = len(after)
		}
		name := strings.TrimSpace(after[:nl])
		if _, ok := toolProperties(name, names, defs); !ok {
			continue
		}
		args := strings.TrimSpace(after[nl:])
		args = strings.TrimPrefix(args, "```json")
		args = strings.TrimPrefix(args, "```")
		args = strings.TrimSuffix(strings.TrimSpace(args), "```")
		args = strings.TrimSpace(args)
		if args == "" || !json.Valid([]byte(args)) {
			args = "{}"
		}
		out = append(out, LeakedToolCall{
			Call:   ToolCall{Name: name, Arguments: args},
			Syntax: LeakSyntaxDeepSeek,
		})
	}
	return out
}

// oneCall marshals a parsed argument map into a single LeakedToolCall.
func oneCall(name string, args map[string]json.RawMessage, syntax LeakSyntax) []LeakedToolCall {
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil
	}
	return []LeakedToolCall{{
		Call:   ToolCall{Name: name, Arguments: string(argsJSON)},
		Syntax: syntax,
	}}
}

// attrValue pulls `name="…"` (or single-quoted) out of an XML-ish open tag.
func attrValue(block, attr string) string {
	for _, q := range []string{`"`, `'`} {
		needle := attr + "=" + q
		at := strings.Index(block, needle)
		if at < 0 {
			continue
		}
		rest := block[at+len(needle):]
		if end := strings.Index(rest, q); end >= 0 {
			return strings.TrimSpace(rest[:end])
		}
	}
	return ""
}

// toolProperties resolves a parsed name to the offered tool's JSON Schema
// `properties` object. The bool result IS the name gate — false means the
// request never offered a tool by that name and the span must be ignored.
// A tool with no usable schema still gates true (recovery is about the call,
// not the schema); its arguments simply stay string-typed.
func toolProperties(name string, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) (map[string]json.RawMessage, bool) {
	if name == "" {
		return nil, false
	}
	typ, ok := names[name]
	if !ok {
		return nil, false
	}
	def, ok := defs[typ]
	if !ok || len(def.Parameters) == 0 {
		return nil, true
	}
	var schema struct {
		Properties map[string]json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(def.Parameters, &schema) != nil {
		return nil, true
	}
	return schema.Properties, true
}

// coerceArgValue gives a raw XML-extracted argument its schema-declared JSON
// type. The tools unmarshal their arguments into typed Go structs — websearch's
// max_results is an `int` — so handing every value across as a string would
// make a recovered call fail to execute for a reason that has nothing to do
// with the model. Equally, guessing types from the text alone would turn a
// numeric search query into a number. So: coerce ONLY when the schema asks for
// a non-string type and the text actually parses as it; otherwise a string.
func coerceArgValue(props map[string]json.RawMessage, key, raw string) json.RawMessage {
	declared := ""
	if schema, ok := props[key]; ok {
		var p struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(schema, &p) == nil {
			declared = p.Type
		}
	}
	switch declared {
	case "integer", "number", "boolean", "object", "array":
		trimmed := strings.TrimSpace(raw)
		if json.Valid([]byte(trimmed)) && !strings.HasPrefix(trimmed, `"`) {
			return json.RawMessage(trimmed)
		}
	}
	out, err := json.Marshal(raw)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return out
}

// ChatAssistantContent reads the visible text off a Chat assistant message —
// the string the leak scanner inspects on the non-streaming path, where there
// is no stitcher to have accumulated it.
func ChatAssistantContent(msg json.RawMessage) string {
	if len(msg) == 0 {
		return ""
	}
	var shaped struct {
		Content json.RawMessage `json:"content"`
	}
	if json.Unmarshal(msg, &shaped) != nil {
		return ""
	}
	var s string
	if json.Unmarshal(shaped.Content, &s) == nil {
		return s
	}
	// Array-of-parts form: concatenate the text parts.
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(shaped.Content, &parts) != nil {
		return ""
	}
	var b strings.Builder
	for _, p := range parts {
		if p.Type == "text" || p.Type == "output_text" {
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

// ResponsesOutputText concatenates the visible text across a Responses
// output[]'s message items — the ChatAssistantContent twin.
func ResponsesOutputText(items []json.RawMessage) string {
	var b strings.Builder
	for _, raw := range items {
		var shaped struct {
			Type    string `json:"type"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		}
		if json.Unmarshal(raw, &shaped) != nil || shaped.Type != "message" {
			continue
		}
		for _, p := range shaped.Content {
			if p.Type == "output_text" {
				b.WriteString(p.Text)
			}
		}
	}
	return b.String()
}

// StripChatBodyMarkup removes recognized leak markup from a non-streaming Chat
// response body's choices[].message.content. Used on the ignore path, where
// the round produced a real answer and only the stray markup has to go. A body
// that does not parse, or that carries no markup, is returned unchanged.
func StripChatBodyMarkup(resp []byte, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]byte, error) {
	return stripChatBody(resp, func(c string) string {
		return StripLeakedToolCallMarkup(c, names, defs)
	})
}

// StripTruncatedChatBodyMarkup is StripChatBodyMarkup for a length-terminated
// round, additionally dropping a trailing unterminated span.
func StripTruncatedChatBodyMarkup(resp []byte, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]byte, error) {
	return stripChatBody(resp, func(c string) string {
		return StripTruncatedToolCallMarkup(c, names, defs)
	})
}

func stripChatBody(resp []byte, strip func(string) string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &obj); err != nil {
		return resp, nil
	}
	var choices []map[string]json.RawMessage
	raw, ok := obj["choices"]
	if !ok || json.Unmarshal(raw, &choices) != nil {
		return resp, nil
	}
	changed := false
	for _, ch := range choices {
		msgRaw, ok := ch["message"]
		if !ok {
			continue
		}
		var msg map[string]json.RawMessage
		if json.Unmarshal(msgRaw, &msg) != nil {
			continue
		}
		var content string
		if c, ok := msg["content"]; !ok || json.Unmarshal(c, &content) != nil {
			continue
		}
		stripped := strip(content)
		if stripped == content {
			continue
		}
		cJSON, err := json.Marshal(strings.TrimSpace(stripped))
		if err != nil {
			return nil, err
		}
		msg["content"] = cJSON
		msgJSON, err := json.Marshal(msg)
		if err != nil {
			return nil, err
		}
		ch["message"] = msgJSON
		changed = true
	}
	if !changed {
		return resp, nil
	}
	choicesJSON, err := json.Marshal(choices)
	if err != nil {
		return nil, err
	}
	obj["choices"] = choicesJSON
	return json.Marshal(obj)
}

// StripResponsesBodyMarkup is StripChatBodyMarkup's Responses twin, walking
// output[]'s message items' output_text parts.
func StripResponsesBodyMarkup(resp []byte, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]byte, error) {
	return stripResponsesBody(resp, func(c string) string {
		return StripLeakedToolCallMarkup(c, names, defs)
	})
}

// StripTruncatedResponsesBodyMarkup is StripResponsesBodyMarkup for a
// length-terminated round, additionally dropping a trailing unterminated span.
func StripTruncatedResponsesBodyMarkup(resp []byte, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]byte, error) {
	return stripResponsesBody(resp, func(c string) string {
		return StripTruncatedToolCallMarkup(c, names, defs)
	})
}

func stripResponsesBody(resp []byte, strip func(string) string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &obj); err != nil {
		return resp, nil
	}
	var items []json.RawMessage
	raw, ok := obj["output"]
	if !ok || json.Unmarshal(raw, &items) != nil {
		return resp, nil
	}
	out := make([]json.RawMessage, 0, len(items))
	changed := false
	for _, it := range items {
		stripped, err := stripResponsesItemMarkup(it, strip)
		if err != nil {
			return nil, err
		}
		// Unlike the recovery path, an emptied message item is KEPT here: the
		// client is receiving this body as the answer, and dropping the item
		// would change output[]'s shape under a consumer that indexes it.
		//
		// KEPT means kept with its text emptied, not kept as it arrived. Simply
		// re-appending `it` puts the markup we just stripped straight back on
		// the wire and leaves `changed` false, so the whole body returns
		// untouched — which is what happened here until a round whose output
		// was ENTIRELY markup made that branch the common case rather than an
		// unreachable one. The Chat twin empties `content` to "", so this
		// matches it.
		if len(stripped) == 0 {
			emptied, eerr := emptyResponsesMessageItem(it)
			if eerr != nil {
				return nil, eerr
			}
			if string(emptied) != string(it) {
				changed = true
			}
			out = append(out, emptied)
			continue
		}
		if string(stripped) != string(it) {
			changed = true
		}
		out = append(out, stripped)
	}
	if !changed {
		return resp, nil
	}
	outJSON, err := json.Marshal(out)
	if err != nil {
		return nil, err
	}
	obj["output"] = outJSON
	return json.Marshal(obj)
}

// NewRecoveredToolCallID mints the id shared by a recovered call's assistant
// turn and its tool result. The `zsrc_` prefix (ZeroSignal recovered call)
// makes a recovered round identifiable in an upstream's own request logs
// without carrying any prompt-derived content.
func NewRecoveredToolCallID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "zsrc_" + hex.EncodeToString(b[:])
}

// RepairChatAssistantWithRecoveredCalls rewrites a Chat assistant message so
// it actually CLAIMS the calls that leaked into its content, and returns the
// calls (ids populated) for the loop to dispatch.
//
// This is not cosmetic. AppendToolMessagesChat appends the assistant message
// verbatim and then one {"role":"tool","tool_call_id":…} per result. An
// assistant turn with no tool_calls followed by tool messages is an orphan,
// and strict upstreams reject the next iteration outright — z.ai answers the
// opaque `400 1210 Invalid API parameter`, which is the same upstream this
// recovery path exists for. Minting the id here, in the one place that also
// produces the dispatch list, is what keeps the two sides from disagreeing.
func RepairChatAssistantWithRecoveredCalls(assistantMsg json.RawMessage, scan LeakScan, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) (json.RawMessage, []ToolCall, error) {
	obj := map[string]json.RawMessage{}
	if len(assistantMsg) > 0 {
		if err := json.Unmarshal(assistantMsg, &obj); err != nil {
			return nil, nil, err
		}
	}
	obj["role"] = json.RawMessage(`"assistant"`)

	// Strip the markup from the replayed content: the model must not be shown
	// its own unparsed call as if it were prose it had written.
	content := ""
	if raw, ok := obj["content"]; ok {
		_ = json.Unmarshal(raw, &content)
	}
	if stripped := strings.TrimSpace(StripLeakedToolCallMarkup(content, names, defs)); stripped != "" {
		cJSON, err := json.Marshal(stripped)
		if err != nil {
			return nil, nil, err
		}
		obj["content"] = cJSON
	} else {
		// Chat Completions wants content string-or-null; null is the safer
		// shape alongside tool_calls, matching AssistantMessage().
		obj["content"] = json.RawMessage(`null`)
	}

	dispatch := make([]ToolCall, 0, len(scan.Calls))
	arr := make([]json.RawMessage, 0, len(scan.Calls))
	for _, lc := range scan.Calls {
		call := lc.Call
		call.ID = NewRecoveredToolCallID()
		dispatch = append(dispatch, call)

		fn, err := json.Marshal(map[string]string{"name": call.Name, "arguments": call.Arguments})
		if err != nil {
			return nil, nil, err
		}
		idJSON, err := json.Marshal(call.ID)
		if err != nil {
			return nil, nil, err
		}
		tcJSON, err := json.Marshal(map[string]json.RawMessage{
			"id":       idJSON,
			"type":     json.RawMessage(`"function"`),
			"function": fn,
		})
		if err != nil {
			return nil, nil, err
		}
		arr = append(arr, tcJSON)
	}
	callsJSON, err := json.Marshal(arr)
	if err != nil {
		return nil, nil, err
	}
	obj["tool_calls"] = callsJSON

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, err
	}
	return out, dispatch, nil
}

// RepairResponsesItemsWithRecoveredCalls is the Responses-shaped twin: it
// strips the markup from the assistant message item's output_text parts and
// appends a synthesized `function_call` item per recovered call, so the
// `function_call_output` that AppendFunctionCallOutputsResponses adds next has
// a matching call_id to bind to.
func RepairResponsesItemsWithRecoveredCalls(items []json.RawMessage, scan LeakScan, names map[string]BuiltinToolType, defs map[BuiltinToolType]BuiltinToolDef) ([]json.RawMessage, []ToolCall, error) {
	out := make([]json.RawMessage, 0, len(items)+len(scan.Calls))
	for _, raw := range items {
		stripped, err := stripResponsesItemMarkup(raw, func(c string) string {
			return StripLeakedToolCallMarkup(c, names, defs)
		})
		if err != nil {
			return nil, nil, err
		}
		if len(stripped) > 0 {
			out = append(out, stripped)
		}
	}

	dispatch := make([]ToolCall, 0, len(scan.Calls))
	for _, lc := range scan.Calls {
		call := lc.Call
		call.ID = NewRecoveredToolCallID()
		dispatch = append(dispatch, call)

		itemJSON, err := json.Marshal(map[string]string{
			"type":      "function_call",
			"call_id":   call.ID,
			"name":      call.Name,
			"arguments": call.Arguments,
		})
		if err != nil {
			return nil, nil, err
		}
		out = append(out, itemJSON)
	}
	return out, dispatch, nil
}

// stripResponsesItemMarkup removes recognized markup from a message item's
// output_text parts. A message item left with no text at all is dropped
// entirely — an empty message item is not something to replay. Non-message
// items pass through byte-identical.
// emptyResponsesMessageItem returns item with a single empty output_text part,
// preserving its id/type/role so a consumer indexing output[] still finds the
// assistant message where it expects it. Non-message items pass through.
func emptyResponsesMessageItem(item json.RawMessage) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil {
		return item, nil
	}
	var typ string
	if raw, ok := obj["type"]; ok {
		_ = json.Unmarshal(raw, &typ)
	}
	if typ != "message" {
		return item, nil
	}
	obj["content"] = json.RawMessage(`[{"type":"output_text","text":""}]`)
	return json.Marshal(obj)
}

func stripResponsesItemMarkup(item json.RawMessage, strip func(string) string) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil {
		return item, nil
	}
	var typ string
	if raw, ok := obj["type"]; ok {
		_ = json.Unmarshal(raw, &typ)
	}
	if typ != "message" {
		return item, nil
	}
	var parts []map[string]json.RawMessage
	if raw, ok := obj["content"]; ok {
		if json.Unmarshal(raw, &parts) != nil {
			return item, nil
		}
	}
	kept := make([]map[string]json.RawMessage, 0, len(parts))
	anyText := false
	for _, p := range parts {
		var ptype, text string
		if raw, ok := p["type"]; ok {
			_ = json.Unmarshal(raw, &ptype)
		}
		if ptype != "output_text" {
			kept = append(kept, p)
			continue
		}
		if raw, ok := p["text"]; ok {
			_ = json.Unmarshal(raw, &text)
		}
		stripped := strings.TrimSpace(strip(text))
		if stripped == "" {
			continue
		}
		tJSON, err := json.Marshal(stripped)
		if err != nil {
			return nil, err
		}
		p["text"] = tJSON
		kept = append(kept, p)
		anyText = true
	}
	if !anyText && len(kept) == 0 {
		return nil, nil
	}
	cJSON, err := json.Marshal(kept)
	if err != nil {
		return nil, err
	}
	obj["content"] = cJSON
	return json.Marshal(obj)
}
