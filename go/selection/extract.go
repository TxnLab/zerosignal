/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection

import (
	"encoding/json"
	"strings"
)

// Body-parsing helpers for affinity-key derivation and tool-aware routing.
// These live in proto — rather than per-app — so the proxy and the client/
// chat app derive the *same* affinity keys and tool sets from a request body.
// If they parsed differently, a continuation that the proxy pins to operator X
// could be pinned elsewhere by the client, and the privacy/routing behavior
// would diverge between the two "user" endpoints.
//
// All of these are advisory: a parse failure returns the zero value, never an
// error — selection input must never be a reason to fail a request.

// ExtractModel pulls the top-level "model" string from a request body.
func ExtractModel(body []byte) string {
	var peek struct {
		Model string `json:"model"`
	}
	_ = json.Unmarshal(body, &peek)
	return peek.Model
}

// ExtractRequestedBuiltinTools returns every built-in `zs_*` tool type named
// in the request body's tools[] array, in order. nil when there are none.
func ExtractRequestedBuiltinTools(body []byte) []string {
	var peek struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return nil
	}
	var out []string
	for _, raw := range peek.Tools {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &typed); err != nil {
			continue
		}
		// Must match the TS mirror's `type.startsWith('zs_')` exactly
		// (proto/ts/src/selection/extract.ts) so the proxy and the client/
		// app derive identical tool sets — see the package doc. A bare
		// "zs_" prefix is enough; don't reintroduce a length>3 guard,
		// which would silently diverge from TS on a "zs_"-only type.
		if strings.HasPrefix(typed.Type, "zs_") {
			out = append(out, typed.Type)
		}
	}
	return out
}

// ImageToolBudgets carries the per-request image-tool budgets a client
// declares on a /v1/responses body to opt the hayai image tools in:
//
//	"tool_budgets": {
//	  "zs_image_generation": { "max_n": 4 },
//	  "zs_image_edit":       { "max_n": 2 }
//	}
//
// max_n is the maximum number of images that tool may produce over the
// whole request. Omitted ⇒ 0 ⇒ the tool is unusable for the request even
// if the operator advertises a factor and the model decides to call it —
// the proxy sizes the reserve from these counts and the node enforces them
// in the tool loop.
type ImageToolBudgets struct {
	GenerationMaxN uint64
	EditMaxN       uint64
}

// ParseToolBudgets reads the tool_budgets object from a request body.
// Advisory: a missing or malformed object yields the zero value (both
// budgets 0). Keyed by tool type so it stays aligned with the
// zs_image_generation / zs_image_edit tool names on the wire.
func ParseToolBudgets(body []byte) ImageToolBudgets {
	var peek struct {
		ToolBudgets map[string]struct {
			MaxN uint64 `json:"max_n"`
		} `json:"tool_budgets"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return ImageToolBudgets{}
	}
	var b ImageToolBudgets
	if v, ok := peek.ToolBudgets["zs_image_generation"]; ok {
		b.GenerationMaxN = v.MaxN
	}
	if v, ok := peek.ToolBudgets["zs_image_edit"]; ok {
		b.EditMaxN = v.MaxN
	}
	return b
}

// ExtractInputToolCallIDs scans a chat-completions request body for role:tool
// messages and returns their tool_call_id values in order. These are the keys
// the affinity cache is keyed on for continuation routing.
func ExtractInputToolCallIDs(body []byte) []string {
	var peek struct {
		Messages []struct {
			Role       string `json:"role"`
			ToolCallID string `json:"tool_call_id"`
		} `json:"messages"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return nil
	}
	var out []string
	for _, m := range peek.Messages {
		if m.Role == "tool" && m.ToolCallID != "" {
			out = append(out, m.ToolCallID)
		}
	}
	return out
}

// ExtractResponseToolCallIDs scans a chat-completions response body for
// tool_calls[].id values across every choice. These are recorded into the
// affinity cache after a successful response decrypt.
func ExtractResponseToolCallIDs(body []byte) []string {
	var peek struct {
		Choices []struct {
			Message struct {
				ToolCalls []struct {
					ID string `json:"id"`
				} `json:"tool_calls"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return nil
	}
	var out []string
	for _, ch := range peek.Choices {
		for _, tc := range ch.Message.ToolCalls {
			if tc.ID != "" {
				out = append(out, tc.ID)
			}
		}
	}
	return out
}

// ExtractPreviousResponseID pulls "previous_response_id" from a /v1/responses
// request body. Empty when absent or on parse failure. This is the Responses
// API's stateful-continuation reference: the request must route back to the
// operator that emitted the matching response_id, since the session state
// lives in that operator's upstream account.
func ExtractPreviousResponseID(body []byte) string {
	var peek struct {
		PreviousResponseID string `json:"previous_response_id"`
	}
	_ = json.Unmarshal(body, &peek)
	return peek.PreviousResponseID
}

// ExtractResponseID pulls top-level "id" from a /v1/responses non-streaming
// response body. Guards against picking up a non-Response object that happens
// to carry an "id" (e.g. an error envelope) via the object discriminator.
func ExtractResponseID(body []byte) string {
	var peek struct {
		ID     string `json:"id"`
		Object string `json:"object"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return ""
	}
	if peek.Object != "" && peek.Object != "response" {
		return ""
	}
	return peek.ID
}

// Sort values for RoutingPreferences.Sort — the caller's base-ordering choice.
// "price" is the policy default (the shared price sort); "throughput" and
// "latency" are honored by each caller's app-side post-pass (they need runtime
// metrics the golden-vectored policy deliberately omits). Mirror of the ts
// SORT_* constants.
const (
	SortPrice      = "price"
	SortThroughput = "throughput"
	SortLatency    = "latency"
)

// Relay values for RoutingPreferences.Relay — the caller's per-request
// transport-privacy override. "auto" defers to the process config default;
// "off" sends direct (no relay hop, lower latency, target sees the caller);
// "required" forces a relay (hard-fail if none is eligible). Consumed app-side
// (relay selection is not part of the golden-vectored policy). Mirror of the ts
// RELAY_* constants.
const (
	RelayAuto     = "auto"
	RelayOff      = "off"
	RelayRequired = "required"
)

// RoutingPreferences holds the caller's OpenRouter-style provider-selection
// inputs, parsed from a request body's `provider` object by
// ExtractRoutingPreferences. Living in proto guarantees the proxy and the
// client/ app derive identical preferences from the same body. Most fields map
// straight onto selection.Constraints (the golden-vectored policy consumes
// them); Sort and Relay are app-side signals (throughput/latency ordering and
// the relay/privacy override) the policy deliberately leaves to each process.
type RoutingPreferences struct {
	// Order / Only / Ignore copy onto the same-named Constraints fields.
	Order  []OperatorRef
	Only   []OperatorRef
	Ignore []OperatorRef
	// AllowFallbacks is nil unless the caller explicitly sent
	// "allow_fallbacks". Governs Order strictness in Constraints; copied
	// straight onto Constraints.AllowFallbacks, which is a pointer for the same
	// reason — the meaningful default is true and Go's zero value is false, so
	// a plain bool made a hand-built literal that omitted the field hard-exclude
	// the previous_response_id continuation target via AllowsOperator. Read it
	// through FallbacksAllowed, never directly.
	AllowFallbacks *bool
	// MaxInputUSDPer1M / MaxOutputUSDPer1M are the caller's price ceilings from
	// max_price.{input,output}; 0 ⇒ no ceiling on that axis.
	MaxInputUSDPer1M  float64
	MaxOutputUSDPer1M float64
	// RequireTools promotes the requested-tool partition to a hard filter.
	RequireTools bool
	// Sort is one of "" / SortPrice / SortThroughput / SortLatency (app-side).
	Sort string
	// Relay is one of "" / RelayAuto / RelayOff / RelayRequired (app-side).
	Relay string
}

// ExtractRoutingPreferences parses the `provider` object from a request body
// into RoutingPreferences. Advisory like every extractor here: a missing or
// malformed `provider` yields the defaults (notably AllowFallbacks=true, so an
// absent object never silently pins). Individual malformed refs are skipped
// (ParseOperatorRef ok=false), an unrecognized sort/relay normalizes to "",
// and a non-positive ceiling means "no ceiling". The caller is responsible for
// stripping `provider` from the body before sealing it to the node — it is a
// proxy/client-only routing hint, not part of the upstream request.
//
// Parsing is field-by-field (and element-by-element within the ref arrays and
// max_price), NOT one typed unmarshal: a single mistyped field or array element
// must only discard ITSELF, never the whole object. This is what keeps the Go
// and ts extractors in lockstep on a malformed `provider` — a typed struct
// unmarshal bails on the first type error and would drop every other (valid)
// field, diverging from the resilient ts extractRoutingPreferences and breaking
// the "proxy and client/ derive identical preferences" guarantee.
func ExtractRoutingPreferences(body []byte) RoutingPreferences {
	// AllowFallbacks is left nil — FallbacksAllowed reads that as true, so an
	// absent or malformed `provider` never silently pins.
	var prefs RoutingPreferences
	var top struct {
		Provider json.RawMessage `json:"provider"`
	}
	if json.Unmarshal(body, &top) != nil || len(top.Provider) == 0 {
		return prefs
	}
	var prov map[string]json.RawMessage
	if json.Unmarshal(top.Provider, &prov) != nil {
		// provider present but not an object (string / array / number / etc.):
		// no fields to read → defaults. Matches the ts non-object short-circuit.
		return prefs
	}
	prefs.Order = parseRefField(prov["order"])
	prefs.Only = parseRefField(prov["only"])
	prefs.Ignore = parseRefField(prov["ignore"])
	if v, ok := unmarshalField[bool](prov["allow_fallbacks"]); ok {
		prefs.AllowFallbacks = &v
	}
	if mp, ok := unmarshalField[map[string]json.RawMessage](prov["max_price"]); ok {
		if in, ok := unmarshalField[float64](mp["input"]); ok && in > 0 {
			prefs.MaxInputUSDPer1M = in
		}
		if out, ok := unmarshalField[float64](mp["output"]); ok && out > 0 {
			prefs.MaxOutputUSDPer1M = out
		}
	}
	if v, ok := unmarshalField[bool](prov["require_tools"]); ok {
		prefs.RequireTools = v
	}
	if v, ok := unmarshalField[string](prov["sort"]); ok {
		prefs.Sort = normalizeSort(v)
	}
	if v, ok := unmarshalField[string](prov["relay"]); ok {
		prefs.Relay = NormalizeRelay(v)
	}
	return prefs
}

// unmarshalField decodes a single provider field into T, returning ok=false when
// the field is absent or its JSON type doesn't fit T. Advisory: a wrong-typed
// field is ignored, never fatal — the per-field isolation that keeps the Go
// extractor as resilient as the ts mirror.
func unmarshalField[T any](raw json.RawMessage) (T, bool) {
	var v T
	if len(raw) == 0 {
		return v, false
	}
	if json.Unmarshal(raw, &v) != nil {
		return v, false
	}
	return v, true
}

// parseRefField decodes a provider field expected to be an array of ref strings
// (order / only / ignore), skipping any non-string element AND any malformed ref
// string. A non-array or absent field yields nil. Element-level skipping (not a
// whole-array []string unmarshal) is required for ts parity: ts skips non-string
// elements one at a time, so e.g. [3,"5"] must yield just the "5" ref on both
// sides, not nil.
func parseRefField(raw json.RawMessage) []OperatorRef {
	if len(raw) == 0 {
		return nil
	}
	var elems []json.RawMessage
	if json.Unmarshal(raw, &elems) != nil {
		return nil // not an array
	}
	strs := make([]string, 0, len(elems))
	for _, el := range elems {
		if s, ok := unmarshalField[string](el); ok {
			strs = append(strs, s)
		}
	}
	return parseOperatorRefs(strs)
}

// parseOperatorRefs parses a list of ref strings, skipping malformed entries.
// Returns nil (not an empty slice) when nothing parses, so an absent/garbage
// list reads as "no preference" and marshals away under omitempty.
func parseOperatorRefs(in []string) []OperatorRef {
	if len(in) == 0 {
		return nil
	}
	out := make([]OperatorRef, 0, len(in))
	for _, s := range in {
		if ref, ok := ParseOperatorRef(s); ok {
			out = append(out, ref)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeSort(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case SortPrice:
		return SortPrice
	case SortThroughput:
		return SortThroughput
	case SortLatency:
		return SortLatency
	default:
		return ""
	}
}

// NormalizeRelay maps a raw relay-preference string to one of "" / RelayAuto /
// RelayOff / RelayRequired (case-insensitive, trimmed); an unrecognized value
// normalizes to "". Exported (unlike normalizeSort) so the proxy can apply the
// same normalization to the `X-Zs-Relay` header it reads as a convenience
// alongside the body `provider.relay`, keeping the two surfaces in lockstep.
func NormalizeRelay(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case RelayAuto:
		return RelayAuto
	case RelayOff:
		return RelayOff
	case RelayRequired:
		return RelayRequired
	default:
		return ""
	}
}

// AllowsOperator reports whether a single, already-chosen operator — e.g. a
// Responses-API previous_response_id continuation target the caller resolved
// OUTSIDE SelectTargets — survives the caller's HARD routing constraints: the
// Only allowlist, the Ignore denylist, and a no-fallback Order pin. It mirrors
// exactly the constraints that would hard-exclude an operator from
// SelectTargets' output, and deliberately ignores the soft (fallbacks-allowed)
// Order, price, tools, and sizing — a continuation pin overrides those, since
// the session lives in that operator's account. Use it to detect a caller-pin
// vs continuation conflict before bypassing SelectTargets. Mirror of the ts
// routingPreferencesAllowOperator.
func (p RoutingPreferences) AllowsOperator(op Operator) bool {
	// Exactly the hard exclusions SelectTargets binds the affinity-preferred
	// continuation target by (passesRefFilters + orderHardExcludes), so the
	// response-id and tool-call continuation paths agree on what a caller pin
	// excludes. A no-fallback Order is a hard pin to the named set; an Only/Ignore
	// exclusion always blocks; a fallbacks-allowed Order is soft and never blocks.
	return passesRefFilters(op, p.Only, p.Ignore) &&
		!orderHardExcludes(op, p.Order, p.FallbacksAllowed())
}

// FallbacksAllowed resolves RoutingPreferences.AllowFallbacks: an unset (nil)
// field means the caller said nothing, which is "fallbacks allowed". Same rule
// and same reason as Constraints.FallbacksAllowed, which this value is copied
// onto.
func (p RoutingPreferences) FallbacksAllowed() bool {
	return p.AllowFallbacks == nil || *p.AllowFallbacks
}

// ExtractResponseIDFromFrame pulls response.id from a decrypted SSE data
// payload when the frame's type is "response.created" or "response.completed".
// Empty otherwise. Used by the streaming pipeline to record affinity once per
// stream.
func ExtractResponseIDFromFrame(frameData []byte) string {
	var peek struct {
		Type     string `json:"type"`
		Response struct {
			ID string `json:"id"`
		} `json:"response"`
	}
	if err := json.Unmarshal(frameData, &peek); err != nil {
		return ""
	}
	switch peek.Type {
	case "response.created", "response.completed":
		return peek.Response.ID
	}
	return ""
}
