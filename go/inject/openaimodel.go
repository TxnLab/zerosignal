/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"math"
	"strconv"
	"strings"
)

// OpenAIModel is the GET /v1/models entry shape the proxy and the node both
// serve. It lives here, beside OperatorDetailsModel, because it is derived
// wholly from that type and BOTH repos serve it — a hand-mirrored copy on each
// side would be two independent decisions about field names and about the
// USD/1M → USD-per-token conversion, and the first divergence would be silent.
//
// The first four fields are OpenAI's entire official Model object; there is no
// official field for a context window, pricing, or capabilities. Everything
// past them follows OpenRouter's model object, which is the de-facto schema any
// client reading more than `id` actually parses — and which the proxy had
// already half-adopted in `architecture.{input,output}_modalities`.
//
// What is deliberately NOT emitted:
//
//   - `supported_parameters`. OpenRouter's is exhaustive, so a client answers
//     "does this model take tools?" with `includes("tools")`. Ours could only
//     ever be partial — the node verifies tool and reasoning support and
//     nothing else — and a partial list read as exhaustive says every model
//     rejects `temperature`. An ABSENT field degrades to "assume supported";
//     a short one does not. ToolUse and Reasoning carry the two signals we
//     actually hold, under the spellings /v1/zs/details already uses so one
//     client struct decodes both surfaces.
//   - `top_provider.is_moderated`, `architecture.{modality,tokenizer,
//     instruct_type}`, `name`, `description`. No operator advertises any of
//     them, and a fabricated value is worse than an absent one.
//   - The long-context surcharge tier. OpenRouter's pricing object has no
//     shape for a threshold, and flattening a two-tier price into one number
//     would understate what a long request costs. A tiered model therefore
//     advertises only its BASE rate here; `long_context_*` lives on
//     /v1/zs/details alone.
//   - Per-image and per-tool-call pricing — `image_rate_micro_usdc`, the
//     in-loop image-tool rates, `tool_call_rates_micro_usdc`. Together with
//     the tier above this makes `pricing` a strict SUBSET of what
//     /v1/zs/details publishes: it describes the TOKEN terms and nothing
//     else. A subset is safe only while it never contradicts the whole, so
//     the object drops out entirely for a model whose token rates would
//     misdescribe the cost — see pricedOffThisShape.
type OpenAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`

	// CanonicalSlug / HuggingFaceID are the cross-operator identity keys, in
	// OpenRouter's spelling. They are mutually exclusive by construction:
	// OperatorDetailsModel.CanonicalID is populated only for a model with no
	// Source, since for a sourced model the repo IS the canonical identity.
	CanonicalSlug string `json:"canonical_slug,omitempty"`
	HuggingFaceID string `json:"hugging_face_id,omitempty"`

	ContextLength uint64 `json:"context_length,omitempty"`

	Architecture *OpenAIModelArchitecture `json:"architecture,omitempty"`
	Pricing      *OpenAIModelPricing      `json:"pricing,omitempty"`
	TopProvider  *OpenAIModelTopProvider  `json:"top_provider,omitempty"`

	// Reasoning reuses OperatorDetailsModel's own type rather than OpenRouter's
	// (`supported_efforts` / `mandatory`): matching /v1/zs/details exactly is
	// worth more here than matching a field few clients read, and inventing a
	// `mandatory` we never advertise would be a claim.
	Reasoning *ModelReasoning `json:"reasoning,omitempty"`

	// ToolUse: nil = unadvertised, distinct from an explicit false. See
	// OperatorDetailsModel.ToolUse.
	ToolUse *bool `json:"tool_use,omitempty"`
}

// OpenAIModelList is the GET /v1/models envelope. Build it with
// NewOpenAIModelList — a nil Data marshals to `"data":null`, which a client
// iterating the list sees as null/None rather than an empty array.
type OpenAIModelList struct {
	Object string        `json:"object"`
	Data   []OpenAIModel `json:"data"`
}

// NewOpenAIModelList returns an envelope whose Data is non-nil, so a catalog
// that ends up empty marshals to `[]`.
//
// It exists because "zero models advertised" is a documented steady state, not
// an error: a node whose backend is unreachable advertises none (SPEC § 3c),
// and the proxy advertises none while every operator is unreachable. Left to
// each caller, one repo would seed the slice and the other would not, and the
// two would answer that state differently — the divergence this file's builder
// exists to prevent.
func NewOpenAIModelList(capacity int) OpenAIModelList {
	return OpenAIModelList{Object: "list", Data: make([]OpenAIModel, 0, capacity)}
}

// OpenAIModelArchitecture carries the modality lists. Field names and shape are
// OpenRouter's, minus the fields no operator advertises.
type OpenAIModelArchitecture struct {
	InputModalities  []string `json:"input_modalities,omitempty"`
	OutputModalities []string `json:"output_modalities,omitempty"`
}

// OpenAIModelPricing is USD **per token**, as a decimal string — OpenRouter's
// units and OpenRouter's type. The string is not incidental: it is how a
// consumer gets the advertised rate back without float-formatting noise, and a
// client written against that schema parses these with parseFloat and chokes on
// a bare JSON number.
//
// Prompt and Completion are always emitted, including "0": a free side is a
// real advertised rate, matching OperatorDetailsModel's always-present rates.
// InputCacheRead follows the opposite (nil-vs-zero) rule — omitted when cached
// reads carry no discount, "0" when they are free. `omitempty` is safe on it
// only because the zero value it elides is "", which the builder never sets.
type OpenAIModelPricing struct {
	Prompt         string `json:"prompt"`
	Completion     string `json:"completion"`
	InputCacheRead string `json:"input_cache_read,omitempty"`
}

// OpenAIModelTopProvider mirrors OpenRouter's object of the same name. Only
// `max_completion_tokens` justifies it — OpenRouter's schema puts the output
// ceiling nowhere else — so it is populated from the same values as the entry
// itself rather than describing a *selected* provider. On the node that is
// exactly true (the node IS the provider); on the proxy it is the same
// cross-operator floor as ContextLength. Neither side knows a "top" provider at
// list time, and naming one would be a fabrication.
type OpenAIModelTopProvider struct {
	ContextLength       uint64 `json:"context_length,omitempty"`
	MaxCompletionTokens uint64 `json:"max_completion_tokens,omitempty"`
}

// OpenAIModelFromDetails projects one advertised model onto the /v1/models
// entry shape. ownedBy and created are the caller's, because they differ by
// surface: the node speaks for one operator and knows when it started, the
// proxy speaks for a whole registry that carries no creation time.
//
// Every field is advisory. On the proxy, d is the cross-operator UNION — its
// sizing fields are the MINIMUM across declaring operators and its rates the
// lowest, so ContextLength and Pricing read as a floor ("at least this window",
// "from $X"), not as one operator's terms. The authoritative per-request price
// is the microUSDC value the chosen node signs into the reserve ticket.
//
// The result ALIASES d's Reasoning, ToolUse and modality slices rather than
// cloning them, so treat it as read-only. No in-tree provider memoizes an
// aggregate today — the proxy rebuilds one per call and allocates every rate
// pointer fresh — but one that did would have a mutation here write through to
// its own cache, so callers must not rely on the copy being theirs.
func OpenAIModelFromDetails(d OperatorDetailsModel, ownedBy string, created int64) OpenAIModel {
	m := OpenAIModel{
		ID:            d.ID,
		Object:        "model",
		Created:       created,
		OwnedBy:       ownedBy,
		HuggingFaceID: huggingFaceRepo(d.Source),
		ContextLength: d.ContextWindow,
		Reasoning:     d.Reasoning,
		ToolUse:       d.ToolUse,
	}
	if m.HuggingFaceID == "" {
		m.CanonicalSlug = d.CanonicalID
	}
	if len(d.InputModalities) > 0 || len(d.OutputModalities) > 0 {
		m.Architecture = &OpenAIModelArchitecture{
			InputModalities:  d.InputModalities,
			OutputModalities: d.OutputModalities,
		}
	}
	if !pricedOffThisShape(d) {
		m.Pricing = &OpenAIModelPricing{
			Prompt:     usdPerToken(d.InputRateUSDPer1M),
			Completion: usdPerToken(d.OutputRateUSDPer1M),
		}
		if d.CacheReadRateUSDPer1M != nil {
			m.Pricing.InputCacheRead = usdPerToken(*d.CacheReadRateUSDPer1M)
		}
	}
	if d.ContextWindow > 0 || d.MaxOutputTokens > 0 {
		m.TopProvider = &OpenAIModelTopProvider{
			ContextLength:       d.ContextWindow,
			MaxCompletionTokens: d.MaxOutputTokens,
		}
	}
	return m
}

// pricedOffThisShape reports whether emitting token rates for this model would
// misdescribe what it costs, so no pricing object may be emitted at all.
//
// Two shapes qualify, and they fail for different reasons.
//
// **A dedicated image route** (ServesImageGen / ServesImageEdit) is billed per
// image via image_rate_micro_usdc and never per token. Whatever token rates it
// carries are inert — and it does carry them: ResolveModelPricing returns an
// explicit `pricing:` block BEFORE it reaches the tokenless branch for an
// `image:` model, and nothing in the node's validator forbids declaring both.
// So the guard cannot key off the rates being zero; the advertised entry is
// already `output_modalities: ["image"]`, and per-token prices on it describe a
// charge that will never be made.
//
// **A free-token model carrying a per-call surcharge.** An explicit
// `{input_rate: 0, output_rate: 0}` is a supported "deliberately free" chat
// model, and on a node an emitted "0" is a real advertised rate — an
// affirmative claim of free. That claim is false the moment the model also
// charges per in-loop image (image_tools mandates a non-zero rate) or per tool
// call, neither of which this shape can carry. Those models do NOT set
// ServesImageGen — that flag is the dedicated-route signal and an in-loop tool
// deliberately leaves it clear — so they need the second branch.
//
// A model with REAL token rates plus a surcharge is not in either set: the
// rates describe the token side truthfully, and OpenRouter's own pricing object
// likewise carries per-call keys beside the per-token ones. Only a price that
// is entirely elsewhere, or a "free" that is not free, is a lie.
func pricedOffThisShape(d OperatorDetailsModel) bool {
	if d.ServesImageGen || d.ServesImageEdit {
		return true
	}
	if d.InputRateUSDPer1M != 0 || d.OutputRateUSDPer1M != 0 {
		return false
	}
	return d.ImageToolRateMicroUSDC > 0 || d.ImageEditToolRateMicroUSDC > 0 ||
		len(d.ToolCallRatesMicroUSDC) > 0
}

// usdPerToken renders a USD-per-1M rate as OpenRouter's USD-per-token decimal
// string.
//
// The divide by 1e6 is done in DECIMAL, by shifting the point six places across
// the formatted digits, and that is not a stylistic choice: `0.1/1e6` in float64
// is not the float64 nearest 1e-7, so the shortest round-tripping form of the
// quotient is "0.00000010000000000000001". A consumer would read that as the
// operator's advertised rate. Formatting the operator's own value first and
// shifting the point reproduces exactly what they declared.
//
// FormatFloat with precision -1 gives the shortest form that round-trips to the
// same float64 and, under 'f', never uses an exponent — so the digits below are
// always a plain decimal and "1e-07" can never reach the wire, scientific
// notation being parseable but not what a consumer of that schema has seen.
//
// Anything not strictly positive renders "0". Zero is a real advertised rate;
// negative and non-finite are impossible from a validated node config, and
// folding them here means a malformed advertisement degrades to "free" rather
// than emitting "-0.0000001" or the unparseable "NaN".
func usdPerToken(usdPer1M float64) string {
	if !(usdPer1M > 0) || math.IsInf(usdPer1M, 0) {
		return "0"
	}
	intPart, fracPart, _ := strings.Cut(strconv.FormatFloat(usdPer1M, 'f', -1, 64), ".")
	digits := intPart + fracPart

	// Where the point lands after moving it six places left. <= 0 means the
	// value is under 1 microdollar per token and needs leading zero padding.
	const shift = 6
	point := len(intPart) - shift
	whole, frac := "0", ""
	if point > 0 {
		whole, frac = digits[:point], digits[point:]
	} else {
		frac = strings.Repeat("0", -point) + digits
	}

	frac = strings.TrimRight(frac, "0")
	if frac == "" {
		return whole
	}
	return whole + "." + frac
}

// huggingFaceRepo converts a source pointer ("hf:org/model[@revision]") to the
// bare "org/model" repo id OpenRouter's hugging_face_id carries, and returns ""
// for anything else. The revision is dropped because identity is the repo, not
// the pinned commit.
//
// It is deliberately STRICTER than node/internal/provenance.ParseRef, which it
// otherwise follows and cannot import (that package is node-internal). ParseRef
// checks only the scheme and the org/model split, which is enough where it
// runs: on the node a malformed source is a hard config error caught long
// before advertising. This function also runs on the PROXY, where the string
// arrives inside a remote operator's /v1/zs/details and nothing has validated
// it — and a consumer renders the result as a huggingface.co link. So each
// segment must additionally match HuggingFace's own id charset, which rejects
// the embedded whitespace, newline and query-string forms ParseRef lets
// through. Rejecting produces no field, never a broken or misleading link.
//
// Two more copies of the scheme-stripping exist — the proxy's
// sourceIdentityKey and the client's stripSourceScheme — but they are NOT this
// function's twins: they only strip (and the proxy lowercases) to build a
// grouping key, so tightening them would change which operators cluster.
func huggingFaceRepo(source string) string {
	rest, ok := strings.CutPrefix(strings.TrimSpace(source), "hf:")
	if !ok {
		return ""
	}
	if i := strings.IndexByte(rest, '@'); i >= 0 {
		rest = rest[:i]
	}
	org, model, hasSlash := strings.Cut(rest, "/")
	if !hasSlash || !isHuggingFaceSegment(org) || !isHuggingFaceSegment(model) {
		return ""
	}
	return org + "/" + model
}

// isHuggingFaceSegment reports whether s is a non-empty HuggingFace org or
// repo name: letters, digits, and the three punctuation marks the Hub allows.
// A "/" fails here too, which is what rejects a three-segment path.
func isHuggingFaceSegment(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
