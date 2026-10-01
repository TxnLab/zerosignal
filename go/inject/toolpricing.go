/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"

	"github.com/TxnLab/zerosignal/go/tools"
)

// Vendor server-side tools ("hosted tools", "built-in tools") are tools the
// upstream LLM vendor executes inside a single completion request and bills
// the operator per call — xAI web_search / x_search / code_interpreter, OpenAI
// web_search / file_search / code_interpreter, Kimi's $web_search, etc. They
// are distinct from the node's own zs_* built-ins (which the node executes and
// already prices) and from client function tools ({"type":"function"}, which
// the caller executes).
//
// Not every hosted tool carries a per-call fee, though, and the distinction is
// what this file's three-tier classification exists for: a remote MCP connector,
// OpenAI's freeform "custom" tools, local_shell and apply_patch all cost tokens
// rather than calls, so default-denying them would break a caller's harness for
// no billing reason. See ToolClass and notBilledTools.
//
// This file is the provider-agnostic core the node uses to (1) sort each tools[]
// entry into its billing class, (2) strip the billable ones the operator hasn't
// priced and cap the ones it has (SanitizeToolPricing), and (3) count how many
// the vendor actually ran, per tool, from a completed response
// (CountServerSideToolCalls) so the node can bill them. It is pure JSON
// manipulation — no node/config imports — so it lives beside the other body
// mutators and is unit-testable in isolation. See the node's tool_pricing config
// and SPEC.md "Per-call tool pricing".

// Dialect identifies an upstream vendor's server-side-tool conventions — how
// tools are declared, how the per-request call cap is expressed, and where the
// executed-call counts appear in a response — and, for the vendors that need
// it, its request-body quirks (PreserveThinking, StripNonDirectiveReasoning).
// DialectGeneric is the catch-all fallback that works against any
// OpenAI-compatible upstream by counting tool-call items in the response and
// injecting the OpenAI-standard cap field.
type Dialect string

const (
	DialectGeneric  Dialect = "generic"
	DialectOpenAI   Dialect = "openai"
	DialectXAI      Dialect = "xai"
	DialectMoonshot Dialect = "moonshot"
	DialectZAI      Dialect = "zai"
	// DialectOpenRouter exists for request shaping alone: OpenRouter's
	// server-side-tool conventions are the generic ones (it is a router, not a
	// vendor), but its unified `reasoning` object has to be shaped before a
	// mandatory-reasoning endpoint behind it sees the request. Every branch
	// that keys off the tool conventions must therefore treat it exactly as it
	// treats DialectGeneric.
	DialectOpenRouter Dialect = "openrouter"
)

// knownDialects is every Dialect this package defines. It exists so a consumer
// validating an operator's dialect override enumerates the set from here rather
// than hand-maintaining its own copy: a copy forks the moment a dialect is
// added, and the failure lands on the one knob an operator reaches for when
// auto-inference is wrong — as a boot failure whose error message lists the
// stale set as if it were the whole set.
var knownDialects = []Dialect{
	DialectGeneric,
	DialectOpenAI,
	DialectXAI,
	DialectMoonshot,
	DialectZAI,
	DialectOpenRouter,
}

// KnownDialects returns every Dialect this package defines, for a consumer that
// needs to enumerate them (validating a config value, rendering the valid set
// in an error). The returned slice is the caller's own.
func KnownDialects() []Dialect {
	return slices.Clone(knownDialects)
}

// IsKnownDialect reports whether s names a Dialect this package defines. It is
// the membership test that belongs beside the constants, so no consumer has to
// spell the set out a second time.
func IsKnownDialect(s string) bool {
	return slices.Contains(knownDialects, Dialect(s))
}

// dialectDomains maps each vendor's registrable domain to its Dialect. A host
// matches on DNS label boundaries (HostMatchesDomain), never by substring.
//
// This is a security boundary rather than request shaping, and it is easy to
// treat as shaping: DialectXAI is what makes a node demand xAI's per-response
// zero-retention header, and under tee.dataflow=attested_passthrough that is
// what admits the node at all. A substring match let an operator point a
// measured image at https://api.x.ai.attacker.example (or put api.x.ai in the
// path, query or userinfo), answer with the header itself, and read every
// prompt under an attested-passthrough verdict. The TypeScript inferDialect
// mirrors this table, and the dialect golden vectors pin the two together.
var dialectDomains = []struct {
	domain  string
	dialect Dialect
}{
	{"x.ai", DialectXAI},
	{"openai.com", DialectOpenAI},
	{"moonshot.ai", DialectMoonshot},
	{"moonshot.cn", DialectMoonshot},
	{"kimi.ai", DialectMoonshot},
	{"kimi.com", DialectMoonshot},
	{"z.ai", DialectZAI},
	{"bigmodel.cn", DialectZAI},
	{"openrouter.ai", DialectOpenRouter},
}

// InferDialect maps an upstream base_url to its Dialect by the host net/http
// will actually dial: url.Parse's Hostname(), the same parse the request is
// built from, so the host classified here and the host connected to cannot
// disagree. An unrecognized host, a URL that does not parse to a host
// (including a scheme-less "api.x.ai/v1"), and a URL carrying userinfo all
// fall back to DialectGeneric, which still meters via response tool-call items
// and injects the OpenAI-standard max_tool_calls cap.
//
// The scheme is deliberately not consulted. Whether plain http is acceptable
// is a question about the transport, answered where it matters (the node's
// attested_passthrough validation), not a property of which vendor this is.
func InferDialect(baseURL string) Dialect {
	_, host, ok := upstreamOrigin(baseURL)
	if !ok {
		return DialectGeneric
	}
	for _, e := range dialectDomains {
		if HostMatchesDomain(host, e.domain) {
			return e.dialect
		}
	}
	return DialectGeneric
}

// HostMatchesDomain reports whether host is domain or a subdomain of it,
// compared case-insensitively on DNS label boundaries, with one trailing dot
// (the fully-qualified spelling) ignored. "api.x.ai" matches "x.ai";
// "api.x.ai.attacker.example" and "notx.ai" do not.
//
// host must already be a bare hostname (url.URL.Hostname()), not a URL. A
// non-ASCII host or domain never matches: Go's strings.ToLower and JS
// toLowerCase fold some non-ASCII letters differently (U+0130), and an IDN
// has no business here unconverted.
func HostMatchesDomain(host, domain string) bool {
	if !isASCII(host) || !isASCII(domain) {
		return false
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	domain = strings.ToLower(domain)
	if host == "" || domain == "" {
		return false
	}
	return host == domain || strings.HasSuffix(host, "."+domain)
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// hasMalformedEscape reports a '%' not followed by two hex digits anywhere
// in s. url.Parse refuses one in the path or fragment but not in the query;
// the TypeScript mirror parses only the scheme and authority, so the rule is
// stated here over the whole string for both sides to apply identically.
func hasMalformedEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i+2 >= len(s) || !isHex(s[i+1]) || !isHex(s[i+2])) {
			return true
		}
	}
	return false
}

func isHex(c byte) bool {
	return '0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F'
}

// HTTPSUpstreamHost is the host an https base_url dials, or false when the
// URL is not https or falls outside the subset upstreamOrigin accepts. It is
// the transport half of NamedUpstreamAdmissible, exported so the node's
// attested_passthrough validation applies the same parse a verifier does.
func HTTPSUpstreamHost(baseURL string) (string, bool) {
	scheme, host, ok := upstreamOrigin(baseURL)
	if !ok || scheme != "https" {
		return "", false
	}
	return host, true
}

// upstreamOrigin is the lowercased scheme and the host a base_url names, or
// false when it names none a dialect may be inferred from.
//
// It accepts a deliberately narrow subset — a scheme, no userinfo, a plain
// letters-digits-dots-hyphens host with no escapes, and no control byte or
// malformed escape anywhere in the URL — because the
// TypeScript verifier must reach the same answer with a different URL parser.
// Go's url.Parse and WHATWG URL disagree at the edges (a backslash, a
// percent-escaped host, a scheme-relative "//host"), and a verifier that read
// such a URL as xAI while the node dialed something else would admit exactly
// the lookalike this exists to refuse. Everything outside the subset is
// generic on both sides, so the disagreement has nowhere to land.
//
// Userinfo is refused even alongside a genuine host: it has no legitimate use
// in an API root, and "https://api.x.ai@attacker.example" is the classic way
// to make a URL read as one host and dial another.
func upstreamOrigin(raw string) (scheme, host string, ok bool) {
	// ASCII whitespace only: strings.TrimSpace and JS String.trim disagree on
	// Unicode spaces (U+FEFF is trimmed by one and not the other).
	s := strings.Trim(raw, " \t\n\r\v\f")
	// url.Parse checks for control bytes only before the '#', so a fragment
	// could carry one; both sides refuse it anywhere.
	if hasMalformedEscape(s) || strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return "", "", false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme == "" || u.User != nil || strings.ContainsAny(u.Host, `%\`) {
		return "", "", false
	}
	h := u.Hostname()
	if h == "" || strings.Trim(h, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != "" {
		return "", "", false
	}
	// url.Parse already lowercases the scheme; restated so the TypeScript
	// mirror's explicit toLowerCase has a visible twin.
	return strings.ToLower(u.Scheme), h, true
}

// ToolClass is the per-call BILLING class of one tools[] entry. It is what
// decides whether SanitizeToolPricing may strip the entry.
type ToolClass uint8

const (
	// ToolClassClient — the CALLER executes it: {"type":"function"}, a bare
	// {"function":{…}}, or a node zs_ built-in. Never a vendor per-call fee.
	ToolClassClient ToolClass = iota
	// ToolClassNotBilled — a hosted or caller-executed tool type no upstream
	// charges a per-call fee for. It costs tokens, not calls, so stripping it
	// would break a caller's harness for no billing reason. Passes through
	// untouched unless the operator prices it BY NAME.
	ToolClassNotBilled
	// ToolClassVendorBillable — the upstream executes it and bills the operator
	// per call (web_search, x_search, code_interpreter, file_search, …). This is
	// the fallback for any unrecognized type string, so an unknown hosted tool
	// stays default-denied.
	ToolClassVendorBillable
)

// toolBilling is a notBilledTools entry: WHY a canonical name carries no
// per-call fee. The distinction matters on the response side — see
// IsClientExecutedToolName.
type toolBilling uint8

const (
	// billingClientExecuted — the caller runs it and returns the result, so a
	// matching *_call item in a response is the CALLER's work, not the vendor's,
	// and must never be counted as a vendor server-side call.
	billingClientExecuted toolBilling = iota + 1
	// billingVendorFree — the upstream really does execute it (and may report a
	// count), it just charges no per-call fee. Counting it is truthful; billing
	// it requires an explicit named rate.
	billingVendorFree
)

// notBilledTools is the SINGLE source of truth for canonical tool names that
// carry no vendor per-call fee by default. It drives three sites and must not be
// duplicated: the request-side pass-through tier (ClassifyToolEntry), the
// response-side metering exclusion (CountServerSideToolCalls), and the node
// config's catch-all guard (ResolvedToolPricing.VendorRate). Anything absent
// here is billable-by-default — the default-deny posture is unchanged.
//
// Names are POST-NormalizeToolName, so a request spelling ({"type":"mcp"}) and a
// response spelling ("mcp_call") land on the same key.
var notBilledTools = map[string]toolBilling{
	// Caller-executed. The first three preserve the exclusions the response-side
	// counter has always had for function_call / tool_call / custom_tool_call.
	"function":    billingClientExecuted,
	"tool":        billingClientExecuted,
	"custom":      billingClientExecuted, // OpenAI freeform tool ("custom_tool_call")
	"local_shell": billingClientExecuted, // OpenAI local shell — the harness runs it
	"apply_patch": billingClientExecuted, // OpenAI apply_patch — the harness applies it
	// computer_use: the model emits click/type/scroll actions and the CALLER's
	// harness performs them against its own browser or VM, returning a
	// screenshot — so a computer_call item is the caller's work, not the
	// vendor's. Declaring the tool is mandatory for the computer-use models, so
	// stripping it doesn't save money, it just 400s the request.
	"computer_use": billingClientExecuted,
	// Anthropic's caller-executed tools, same category as local_shell: the
	// harness runs the command / applies the edit. The _YYYYMMDD version suffix
	// is normalized away (bash_20250124 → bash).
	"bash":                        billingClientExecuted,
	"text_editor":                 billingClientExecuted,
	"str_replace_editor":          billingClientExecuted,
	"str_replace_based_edit_tool": billingClientExecuted,

	// Vendor-hosted but free: the upstream really executes it and may report a
	// count, it just charges no per-call fee. NB OpenAI's hosted "shell" tool
	// (vendor-managed containers) is deliberately NOT here — it bills per
	// container session. Only its environment.type:"local" mode is exempt, and
	// ClassifyToolEntry folds that onto local_shell above.
	"mcp": billingVendorFree, // remote MCP connector (OpenAI, Anthropic, xAI)
}

// IsNotBilledToolName reports whether a canonical tool name carries no vendor
// per-call fee by default — either because the caller executes it or because the
// upstream hosts it for free. An operator whose upstream DOES bill per call
// re-enables billing by naming it in tool_pricing.tools; the blanket catch-all
// deliberately never reaches this set.
func IsNotBilledToolName(canonical string) bool {
	_, ok := notBilledTools[canonical]
	return ok
}

// IsClientExecutedToolName reports whether a canonical tool name is executed by
// the CALLER, so a matching *_call item in a response is the caller's own work
// and is not a vendor server-side call at all. Narrower than
// IsNotBilledToolName: mcp is hosted-but-free, so the upstream really runs it
// and may legitimately report counts for it.
//
// A caller-executed tool can never be vendor-billed no matter what the operator
// configures, so pricing one is a config error rather than a promotion — see the
// node's tool_pricing validation.
func IsClientExecutedToolName(canonical string) bool {
	return notBilledTools[canonical] == billingClientExecuted
}

// NormalizeToolName reduces a vendor's tool identifier to a canonical billing
// key so one operator-config rate (e.g. "web_search") covers the same logical
// tool across vendors and across request/response spellings. It strips a
// Moonshot "$" prefix, an OpenAI "_call" / xAI "_calls" suffix, and an
// Anthropic "_YYYYMMDD" version suffix, then folds known aliases
// (web_search_preview → web_search, computer* → computer_use, custom_tool →
// custom). Canonical names: web_search, x_search, code_interpreter, file_search,
// document_search, image_generation, computer_use, mcp, plus the not-billed set
// above.
func NormalizeToolName(raw string) string {
	n := strings.ToLower(strings.TrimSpace(raw))
	n = strings.TrimPrefix(n, "$")
	// Trailing usage-field / output-item suffix.
	switch {
	case strings.HasSuffix(n, "_calls"):
		n = strings.TrimSuffix(n, "_calls")
	case strings.HasSuffix(n, "_call"):
		n = strings.TrimSuffix(n, "_call")
	}
	// Anthropic dated tool version: web_search_20250305 → web_search.
	if i := strings.LastIndex(n, "_"); i > 0 {
		if suf := n[i+1:]; len(suf) == 8 && isAllDigits(suf) {
			n = n[:i]
		}
	}
	switch n {
	case "web_search_preview":
		return "web_search"
	case "computer", "computer_use_preview", "computer_use":
		return "computer_use"
	case "custom_tool":
		// {"type":"custom"} on the request, "custom_tool_call" in the response
		// (which the _call trim above leaves as "custom_tool") — one billing key.
		return "custom"
	case "code_execution":
		// xAI's primary name for what OpenAI calls code_interpreter. Fold so one
		// operator rate covers both spellings; xAI accepts either on its REST API.
		return "code_interpreter"
	case "collections_search":
		// xAI's primary name for its file_search alias (Collections Search).
		// Its pricier sibling attachment_search is a DIFFERENT tool — don't fold.
		return "file_search"
	default:
		return n
	}
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}

// ClassifyToolEntry inspects one tools[] entry and reports the canonical tool
// name and its billing class. A client function tool ({"type":"function"}) and a
// node zs_* built-in are ToolClassClient — the caller keeps them untouched. A
// type in notBilledTools (mcp, custom, local_shell, …) is ToolClassNotBilled and
// is likewise kept, since no upstream charges per call for it. Moonshot's
// {"type":"builtin_function","function":{"name":"$web_search"}} and every other
// type string are ToolClassVendorBillable, so an unrecognized hosted tool stays
// default-denied. A non-object entry classifies as ("", ToolClassClient) so it
// is left alone.
func ClassifyToolEntry(entry json.RawMessage) (name string, class ToolClass) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(entry, &obj); err != nil {
		return "", ToolClassClient
	}
	var typ string
	if raw, ok := obj["type"]; ok {
		_ = json.Unmarshal(raw, &typ)
	}
	typ = strings.ToLower(strings.TrimSpace(typ))

	// Node's own built-ins and client function tools are never vendor tools.
	if tools.IsBuiltinToolType(typ) {
		return typ, ToolClassClient
	}

	fnName := funcName(obj)

	switch typ {
	case "function":
		return fnName, ToolClassClient
	case "builtin_function":
		// Moonshot: the identifying name is the function name ($web_search).
		return NormalizeToolName(fnName), ToolClassVendorBillable
	case "":
		// No type: a bare {"function":{...}} or a "$"-named builtin.
		if strings.HasPrefix(fnName, "$") {
			return NormalizeToolName(fnName), ToolClassVendorBillable
		}
		return fnName, ToolClassClient
	case "shell":
		// OpenAI's shell tool is billable in its hosted modes (container_auto /
		// container_reference bill per container session), but environment.type
		// "local" runs the command on the CALLER's machine — and that mode is the
		// documented successor to the now-deprecated local_shell, so treating it
		// as billable would strip the very thing a migrated Codex harness sends.
		// Fold it onto local_shell so one canonical key covers both spellings.
		if shellEnvironment(obj) == "local" {
			return "local_shell", ToolClassNotBilled
		}
		return "shell", ToolClassVendorBillable
	default:
		// Any other type string is a hosted/server-side tool. Billable (the
		// default-deny fallback) unless it is one of the known-free types.
		n := NormalizeToolName(typ)
		if IsNotBilledToolName(n) {
			return n, ToolClassNotBilled
		}
		return n, ToolClassVendorBillable
	}
}

// shellEnvironment reads a shell tool entry's environment.type discriminator,
// which decides whether the command runs in a vendor-managed container (billed)
// or on the caller's machine (free). An absent or malformed environment is
// reported as "" so it falls to the billable default.
func shellEnvironment(obj map[string]json.RawMessage) string {
	raw, ok := obj["environment"]
	if !ok {
		return ""
	}
	var env struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(env.Type))
}

func funcName(obj map[string]json.RawMessage) string {
	raw, ok := obj["function"]
	if !ok {
		return ""
	}
	var fn struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(raw, &fn)
	return fn.Name
}

// VendorRateFunc reports the operator's per-call price, in microUSDC, for a
// vendor server-side tool by canonical name:
//
//	ok == false           → not priced: strip it (default-deny).
//	ok == true, rate > 0  → priced: kept on Responses; stripped under strict chat
//	                        (its count can't be capped there, so the operator
//	                        could be forced to eat an uncapped overage).
//	ok == true, rate == 0 → explicitly free: kept on BOTH endpoints. At a rate of
//	                        zero there is no per-call overage for strict chat to
//	                        protect against.
//
// It returns the rate rather than a bool because the sanitizer needs that
// zero-vs-positive distinction, and because the shape lets the node hand it
// ResolvedToolPricing.VendorRate directly with no adapter.
type VendorRateFunc func(canonicalName string) (microUSDCPerCall uint64, ok bool)

// StripReason says WHY SanitizeToolPricing removed something, so an operator can
// be told the remedy that actually applies. Without it every strip reads as
// "you didn't price this", which is wrong (and unactionable) for the other two.
type StripReason uint8

const (
	// StripUnpriced — a billable vendor tool the operator hasn't priced.
	// Remedy: price it, set a catch-all, or opt out.
	StripUnpriced StripReason = iota
	// StripStrictChat — a vendor tool the operator DID price above zero, removed
	// only because /v1/chat/completions has no call-cap knob. Remedy:
	// chat_server_tools: allow, use the Responses API, or price it at zero.
	StripStrictChat
	// StripChatSearchField — a top-level chat search field (search_parameters,
	// web_search_options), not a tools[] entry. It is governed by the web_search
	// rate, so naming IT in tool_pricing.tools does nothing.
	StripChatSearchField
)

// StrippedTool is one thing SanitizeToolPricing removed: a canonical tool name
// (or, for StripChatSearchField, a top-level field name) and why it went.
type StrippedTool struct {
	Name   string
	Reason StripReason
}

// SanitizeOpts configures SanitizeToolPricing for one request.
type SanitizeOpts struct {
	Dialect Dialect
	// IsChat is true for /v1/chat/completions, false for /v1/responses. The
	// per-request call cap (max_tool_calls / max_turns) is a Responses-API
	// concept, so it is injected only when IsChat is false. On chat there is no
	// vendor cap knob to enforce CallCap upstream — see AllowChatServerTools.
	IsChat bool
	// AllowChatServerTools controls what happens to a PRICED vendor server-side
	// tool on the chat endpoint, where its call count cannot be capped upstream:
	//   - false (default, "strict chat"): strip vendor server-side tools on chat
	//     even when priced at a POSITIVE rate. The operator can't be forced to eat
	//     uncapped vendor calls, and legacy search_parameters is neutralized. A tool
	//     priced at exactly 0 survives — there is no per-call overage to protect
	//     against. Unpriced vendor tools are stripped on both endpoints regardless
	//     of this flag.
	//   - true ("allow"): keep priced vendor tools on chat (uncapped) — the operator
	//     accepts that a chat request may run more vendor calls than CallCap and eat
	//     the overage beyond the reserve. The capped, recommended surface is the
	//     Responses API. Ignored when IsChat is false.
	AllowChatServerTools bool
	// CallCap is the operator's per-request vendor server-side call budget. When
	// >0 and a priced vendor tool survives, it is injected as the dialect's cap
	// field so the vendor cannot exceed the reserved count (Responses only). 0
	// disables injection.
	CallCap int
}

// SanitizeToolPricing rewrites an OpenAI-compatible request body so the operator
// is never billed for a vendor server-side tool it did not price:
//
//   - Every tools[] entry classified ToolClassVendorBillable whose canonical name
//     is NOT priced is removed. Client function tools, node zs_* tools, not-billed
//     tool types (mcp, custom, local_shell, …), and priced vendor tools are all
//     preserved verbatim.
//   - Under strict chat (opts.IsChat && !opts.AllowChatServerTools, the default),
//     a vendor server-side tool priced at a POSITIVE rate is removed too — it
//     can't be capped on the chat endpoint, so it is not offered there at all. A
//     rate of exactly 0 survives: there is no per-call overage to protect against.
//   - An explicit named rate on a normally not-billed type promotes it to the
//     billable tier, for an upstream that really does charge for it.
//   - If the tools[] array is emptied, it and a now-meaningless tool_choice are
//     dropped (same rule as DropEmptyTools).
//   - On chat, top-level server-side web-search fields (xAI's legacy
//     search_parameters, OpenAI's web_search_options) are removed under the same
//     rule applied to web_search — they aren't tools[] entries.
//   - When any priced vendor tool remains and CallCap>0 (Responses only), the
//     dialect's per-request cap field is injected/lowered to CallCap.
//
// It returns the sorted canonical names of everything it removed (tool names plus
// the two top-level chat field names — never arguments or body content), so the
// caller can tell an operator which tool vanished from a request. Non-JSON bodies
// and JSON whose top level isn't an object are returned unchanged. The returned
// body is a freshly-marshaled copy only when it was modified. A nil vendorRate is
// treated as "nothing priced" (strip all billable vendor server-side tools).
func SanitizeToolPricing(body []byte, vendorRate VendorRateFunc, opts SanitizeOpts) ([]byte, []StrippedTool, error) {
	if len(body) == 0 {
		return body, nil, nil
	}
	if vendorRate == nil {
		vendorRate = func(string) (uint64, bool) { return 0, false }
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil, nil
	}

	changed := false
	// keptHostedVendor drives cap injection. It tracks whether any VENDOR-HOSTED
	// tool survived — billable or free — because the cap bounds two costs, and
	// only one of them is the per-call fee: every hosted call also re-prefills
	// its results into the context, and that token inflation is unbounded
	// without a cap regardless of the rate. Caller-executed tools never set it:
	// they cost the operator nothing and the upstream's cap knob doesn't govern
	// them anyway.
	keptHostedVendor := false
	stripped := map[string]StripReason{}
	// Strict chat: on /v1/chat/completions with AllowChatServerTools=false, a
	// vendor server-side tool priced above zero is dropped — its call count can't
	// be capped upstream there, so offering it would let a request run (and bill
	// the operator for) uncapped vendor calls.
	stripVendorOnChat := opts.IsChat && !opts.AllowChatServerTools

	if raw, ok := obj["tools"]; ok {
		var arr []json.RawMessage
		if err := json.Unmarshal(raw, &arr); err == nil {
			kept := make([]json.RawMessage, 0, len(arr))
			for _, entry := range arr {
				name, class := ClassifyToolEntry(entry)
				var (
					rate   uint64
					priced bool
				)
				// An entry we couldn't name (e.g. {"type":"builtin_function"} with
				// no function) can never be metered, so it can never be legitimately
				// priced either — don't consult the rate table and let a catch-all
				// keep it.
				if class != ToolClassClient && name != "" {
					rate, priced = vendorRate(name)
				}
				switch {
				case class == ToolClassClient:
					// The caller's own tool (function / zs_ / bare function object).
				case class == ToolClassNotBilled && IsClientExecutedToolName(name):
					// The CALLER runs it, so it can never be vendor-billed however the
					// operator configures it — a rate cannot promote it, and it does
					// not count toward the hosted call cap.
				case class == ToolClassNotBilled && !priced:
					// Hosted by the upstream but free of per-call fees, and the
					// operator hasn't said otherwise. Keep it — but it DOES count
					// toward the cap: a hosted call re-prefills its results into the
					// context, and that inflation is unbounded at any rate, zero
					// included.
					keptHostedVendor = true
				default:
					// Billable, by type or by an explicit rate on a hosted-but-free
					// type. The blanket catch-all deliberately never reaches the
					// not-billed set.
					if !priced {
						changed = true
						stripped[name] = StripUnpriced
						continue
					}
					if stripVendorOnChat && rate > 0 {
						changed = true
						stripped[name] = StripStrictChat
						continue
					}
					keptHostedVendor = true
				}
				kept = append(kept, entry)
			}
			if len(kept) == 0 {
				delete(obj, "tools")
				delete(obj, "tool_choice")
				changed = true
			} else {
				if changed {
					remarshaled, err := json.Marshal(kept)
					if err != nil {
						return nil, nil, fmt.Errorf("remarshal tools: %w", err)
					}
					obj["tools"] = remarshaled
				}
				// A partial strip can leave a tool_choice pointing at a tool we
				// just removed (e.g. tool_choice:{"type":"web_search"} with
				// web_search stripped) — a strict upstream 400s on the dangling
				// reference. Drop such a tool_choice; a string ("auto"/"required")
				// or a function/kept-tool choice is left untouched.
				if tcRaw, ok := obj["tool_choice"]; ok {
					name, class := ClassifyToolEntry(tcRaw)
					if _, gone := stripped[name]; class != ToolClassClient && gone {
						delete(obj, "tool_choice")
						changed = true
					}
				}
			}
		}
	}

	// Top-level chat-only server-side web-search triggers/config. Neutralized when
	// web_search isn't priced, or under strict chat when it is priced above zero —
	// the same rule the strip loop applies, since these aren't tools[] entries and
	// the loop above never sees them:
	//   - search_parameters: xAI's legacy live-search trigger (retiring 2026-01-12).
	//   - web_search_options: configures OpenAI's chat search-preview models. NB a
	//     dedicated *-search-preview model still searches WITHOUT this field, so
	//     removing it caps a client's escalation of the search (e.g.
	//     search_context_size) rather than stopping the model's baseline search —
	//     price such a model to cover that (its search is part of the model, not a
	//     tool we can strip).
	//
	// Both are governed by the WEB_SEARCH rate specifically, not by any rate the
	// operator might set for the field name itself. A web_search priced at
	// exactly 0 is the operator asserting "my upstream charges me nothing per
	// search", so the triggers survive chat too.
	wsRate, wsPriced := vendorRate("web_search")
	if opts.IsChat && (!wsPriced || (stripVendorOnChat && wsRate > 0)) {
		for _, f := range []string{"search_parameters", "web_search_options"} {
			if _, ok := obj[f]; ok {
				delete(obj, f)
				stripped[f] = StripChatSearchField
				changed = true
			}
		}
	}

	// Inject the vendor cap knob when a hosted vendor tool survives (Responses).
	if keptHostedVendor && opts.CallCap > 0 && !opts.IsChat {
		if injectCapFields(obj, opts.Dialect, opts.CallCap) {
			changed = true
		}
	}

	// Sorted by name so the caller's log lines and the tests are deterministic.
	var names []StrippedTool
	if len(stripped) > 0 {
		names = make([]StrippedTool, 0, len(stripped))
		for n, reason := range stripped {
			names = append(names, StrippedTool{Name: n, Reason: reason})
		}
		sort.Slice(names, func(i, j int) bool { return names[i].Name < names[j].Name })
	}

	if !changed {
		return body, names, nil
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, names, nil
}

// injectCapFields sets the dialect's per-request server-side-tool cap field(s)
// to cap, only when absent or currently larger than cap (never raise a caller's
// tighter limit). Returns whether it changed anything.
func injectCapFields(obj map[string]json.RawMessage, d Dialect, cap int) bool {
	fields := []string{"max_tool_calls"}
	if d == DialectXAI {
		// xAI honors max_turns for its agentic server-side loop as well.
		fields = append(fields, "max_turns")
	}
	changed := false
	for _, f := range fields {
		if setCapField(obj, f, cap) {
			changed = true
		}
	}
	return changed
}

func setCapField(obj map[string]json.RawMessage, field string, cap int) bool {
	if raw, ok := obj[field]; ok {
		var cur int
		if err := json.Unmarshal(raw, &cur); err == nil && cur >= 0 && cur <= cap {
			// Caller's limit is already at or below ours — keep it, INCLUDING an
			// explicit 0 (the caller forbidding server-side tool calls); never
			// raise a caller's tighter cap.
			return false
		}
	}
	obj[field] = json.RawMessage(fmt.Sprintf("%d", cap))
	return true
}

// CountServerSideToolCalls extracts the per-tool count of successfully executed
// vendor server-side tool calls from a completed response, keyed by canonical
// tool name. It prefers a structured usage field where the dialect provides one
// (xAI usage.server_side_tool_usage_details; Anthropic usage.server_tool_use)
// and otherwise counts tool-call items in the Responses output[] array
// (web_search_call, file_search_call, ...). usage may be nil (chat has no
// output[]); output may be nil (chat / structured-usage dialects). Only
// successful calls are billed, which is exactly what these fields report.
func CountServerSideToolCalls(d Dialect, usage json.RawMessage, output []json.RawMessage) map[string]int {
	counts := map[string]int{}

	// Structured usage fields first (authoritative when present).
	if len(usage) > 0 {
		var u struct {
			// xAI
			ServerSideToolUsageDetails map[string]int `json:"server_side_tool_usage_details"`
			// Anthropic (designed-for; harmless when absent)
			ServerToolUse map[string]int `json:"server_tool_use"`
		}
		// Deliberately NOT filtered against notBilledTools: these counts are the
		// vendor's own report (xAI really does report mcp_calls) and should stay
		// truthful. Whether a count is BILLED is decided downstream by the
		// operator's rate lookup, which is the single gate for that.
		if err := json.Unmarshal(usage, &u); err == nil {
			for k, v := range u.ServerSideToolUsageDetails {
				if v > 0 {
					counts[NormalizeToolName(k)] += v
				}
			}
			for k, v := range u.ServerToolUse {
				if v > 0 {
					// web_search_requests → web_search
					name := NormalizeToolName(strings.TrimSuffix(k, "_requests"))
					counts[name] += v
				}
			}
		}
	}
	if len(counts) > 0 {
		return counts
	}

	// Fallback: count tool-call items in the Responses output[].
	for _, item := range output {
		var it struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(item, &it); err != nil {
			continue
		}
		t := strings.ToLower(it.Type)
		if !strings.HasSuffix(t, "_call") {
			continue
		}
		name := NormalizeToolName(t)
		// Client-executed items (function_call, tool_call, custom_tool_call,
		// local_shell_call, apply_patch_call, computer_call, and Anthropic's
		// bash_call / text_editor_call) are the CALLER's work, not a vendor
		// server-side call. Same table that decides the request-side pass-through
		// tier, so the two can't drift. Hosted-but-free items — mcp_call — ARE
		// counted, truthfully; billing them still requires an explicit rate.
		if IsClientExecutedToolName(name) {
			continue
		}
		counts[name]++
	}
	return counts
}
