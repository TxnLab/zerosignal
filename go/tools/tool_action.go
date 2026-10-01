/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"net/url"
	"strings"
	"unicode/utf8"
)

// Action type strings. These mirror OpenAI's Responses-API
// `web_search_call.action` vocabulary so a client that already renders
// OpenAI's native web search renders ours with the same code path.
// OpenAI also defines "find_in_page"; no ZeroSignal built-in produces it.
const (
	ActionTypeSearch   = "search"
	ActionTypeOpenPage = "open_page"
)

// Wire-hygiene caps. The query is model-chosen and the sources come from a
// third-party search backend, so both are unbounded at the source. A status
// action rides TWO sealed frames per call, is folded into the receipt
// body_hash, and lands in the client's in-memory diagnostics buffer — so
// bound them here, at the one place every emitter goes through. These are
// display budgets, not a security boundary.
const (
	maxActionQueryBytes = 512
	maxActionSources    = 20
	// URLs are bounded but NEVER truncated. A query is display text, so
	// clipping it is cosmetic; a URL is actionable — consumers render it as
	// a link — so a clipped one points at a different resource than the node
	// actually fetched. An over-long URL is therefore dropped (the round
	// falls back to its generic label) rather than shortened. 2048 is the
	// long-standing practical URL ceiling; anything past it is pathological.
	maxActionURLBytes = 2048
)

// ToolAction describes what a ZeroSignal built-in tool round is actually
// doing, so a streaming client can render "Searching for X" instead of a
// bare "Searching the web". It rides the `action` field of a
// ToolCallStatusFrame (see tool_status.go).
//
// The shape deliberately mirrors OpenAI's `web_search_call.action`:
// {"type":"search","query":…,"sources":[…]} and
// {"type":"open_page","url":…}. Sources carry a URL and nothing else —
// OpenAI's shape has no title, and ours must not either: the title a search
// backend returns is scraped third-party HTML, and the URL/title pairs
// already reach the client as url_citation annotations
// (MarshalAnnotationAddedFrame) where a renderer can join them by URL.
//
// The query is prompt-derived content. It is safe on the wire — the frame is
// sealed to the caller, who wrote the prompt, and a relay cannot read it —
// but it MUST NOT be written to logs, traces, or metrics on either the node
// or the proxy.
//
// Icons is a ZeroSignal extension with no OpenAI counterpart: the favicon of
// each source's site, inlined so the consumer renders a real site mark
// without ever contacting the site. It is keyed by host rather than nested
// under each source so the several results a search routinely returns from
// one site collapse to one copy of the bytes. See tool_icon.go.
type ToolAction struct {
	Type    string         `json:"type"`
	Query   string         `json:"query,omitempty"`
	URL     string         `json:"url,omitempty"`
	Sources []ActionSource `json:"sources,omitempty"`

	Icons map[string]*SourceIcon `json:"icons,omitempty"`
}

// ActionSource is one URL a tool round consulted. Type is always "url",
// matching OpenAI's source shape (which reserves the field for future
// non-URL source kinds).
type ActionSource struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Built-in tool type names this package maps to actions. The search tools
// keep their canonical type strings in their node-side impl packages, so
// they're restated here rather than imported (proto must not depend on
// node/internal).
const (
	toolTypeWebSearch   = "zs_web_search"
	toolTypeImageSearch = "zs_image_search"
	toolTypeWebRead     = "zs_web_read"
)

// searchArgs / readArgs are deliberately tolerant: they pick out the one
// field we surface and ignore everything else, so an added tool parameter
// never breaks extraction.
type searchArgs struct {
	Query string `json:"query"`
}

type readArgs struct {
	URL string `json:"url"`
}

// ActionForCall maps a built-in tool call to the action it represents, or
// nil when the tool has nothing meaningful to show (zs_get_time, the image
// tools) or the arguments don't yield a value.
//
// It is tolerant by contract and returns nil on ANY problem — args is the
// raw accumulated tool-call delta buffer straight off the stitcher
// (ResponsesToolCallStitcher.ToolCalls sets Arguments to ArgsBuf.String()
// with no JSON validation anywhere in the stitch path), so an empty string,
// a truncated object from a cut-off stream, a wrong-typed value, or a key
// the model invented are all routine. Callers treat nil as "omit the field".
func ActionForCall(toolName string, args json.RawMessage) *ToolAction {
	switch toolName {
	case toolTypeWebSearch, toolTypeImageSearch:
		var a searchArgs
		if err := json.Unmarshal(args, &a); err != nil {
			return nil
		}
		q := truncateRunes(strings.TrimSpace(a.Query), maxActionQueryBytes)
		if q == "" {
			return nil
		}
		return &ToolAction{Type: ActionTypeSearch, Query: q}
	case toolTypeWebRead:
		var a readArgs
		if err := json.Unmarshal(args, &a); err != nil {
			return nil
		}
		u := strings.TrimSpace(a.URL)
		// Drop, never truncate — see maxActionURLBytes.
		if u == "" || len(u) > maxActionURLBytes || !linkableURL(u) {
			return nil
		}
		return &ToolAction{Type: ActionTypeOpenPage, URL: u}
	default:
		return nil
	}
}

// ActionForCallPreflight is ActionForCall restricted to what is safe to
// advertise BEFORE the tool has run.
//
// It exists as its own function — rather than a conditional at the emit
// site — because the reason is easy to "simplify" away and expensive to get
// wrong. The streaming loop emits in_progress frames for every call in an
// iteration before any of them execute, while zs_web_read's provenance gate
// runs later, per-call, inside executeBuiltinCalls. Advertising the URL up
// front would therefore render "Reading <attacker URL>" in the caller's UI
// for a read the node then refuses — handing attacker-chosen text a
// trusted-looking surface, which is the very indirect-prompt-injection the
// gate exists to stop. The gate cannot be hoisted: its allow-set accrues
// from search citations mid-batch, so a read-after-search in the same
// iteration is not yet decidable when the in_progress frames go out.
//
// So: search tools advertise their query up front (the model's own words,
// no gate applies); zs_web_read advertises nothing until it has actually
// fetched, at which point the completed frame carries the URL via
// ToolEffect.Action, which executeBuiltinCalls sets on the success path only
// — gate-passed AND returned without error, so a read that cleared the
// gate and then failed advertises nothing either.
func ActionForCallPreflight(toolName string, args json.RawMessage) *ToolAction {
	if toolName == toolTypeWebRead {
		return nil
	}
	return ActionForCall(toolName, args)
}

// SourcesFromCitations projects a tool round's citations onto the action's
// source list: URL only, de-duplicated in first-seen order (matching
// renderCitationsMarkdown's numbering), empties skipped, capped.
func SourcesFromCitations(cs []CitationEffect) []ActionSource {
	if len(cs) == 0 {
		return nil
	}
	out := make([]ActionSource, 0, len(cs))
	seen := make(map[string]struct{}, len(cs))
	for _, c := range cs {
		u := strings.TrimSpace(c.URL)
		// Same rule as the open_page URL: bound, never truncate, and only
		// schemes a consumer can render as a link.
		if u == "" || len(u) > maxActionURLBytes || !linkableURL(u) {
			continue
		}
		if _, dup := seen[u]; dup {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, ActionSource{Type: "url", URL: u})
		if len(out) == maxActionSources {
			break
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// linkableURL reports whether u is a URL a consumer can safely turn into a
// link: syntactically valid, http(s), with a host. Anything else
// (javascript:, data:, vbscript:, scheme-relative junk) is dropped at the
// source so an honest node never advertises it.
//
// This is hygiene, NOT the security boundary. Consumers receive these from
// an operator they don't control, so each must refuse non-http(s) schemes on
// its own before rendering an href — the reference client does this in
// linkableSourceHost. Tightening here doesn't relieve them of that.
func linkableURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return false
	}
	return parsed.Host != ""
}

// truncateRunes clips s to at most max bytes without splitting a rune, so
// the result is always valid UTF-8 (a byte-wise slice could cut a
// multi-byte character and produce a replacement char on the client).
func truncateRunes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
