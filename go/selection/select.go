/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection

import (
	"errors"
	"math"
	"net"
	"net/url"
	"sort"

	"github.com/TxnLab/zerosignal/go/wire"
)

// Endpoint identifiers, equal to the proxy's request paths so callers can pass
// their endpoint constant through unchanged. Only the image endpoints alter
// selection (they require a per-operator synthetic-token factor).
const (
	EndpointChatCompletions = "/v1/chat/completions"
	EndpointResponses       = "/v1/responses"
	EndpointImages          = "/v1/images/generations"
	EndpointImageEdits      = "/v1/images/edits"
)

// Affinity policy values, equal to the proxy's hayai.AffinityPolicy strings.
const (
	AffinityPrefer = "prefer"
	AffinityStrict = "strict"
	AffinityNone   = "none"
)

// ErrNoRelay is returned by SelectRelay when no operator satisfies the relay
// diversity rules. Callers MUST hard-fail the request rather than fall back to
// a direct (un-relayed) route — silently routing direct would defeat the
// privacy guarantee the relay exists to provide.
var ErrNoRelay = errors.New("selection: no eligible relay operator")

// Constraints carries the per-request inputs SelectTargets needs that aren't
// derivable from the operator set alone.
type Constraints struct {
	Model           string `json:"model"`
	InputTokens     uint64 `json:"input_tokens"`
	MaxOutputTokens uint64 `json:"max_output_tokens"`
	// InputTokensV2 is the same request measured with tokenize bound version 2,
	// used for the fit check against operators that advertise proto_version >=
	// 9.2. Zero (omitted) means "no v2 measurement supplied" and every operator
	// is filtered on InputTokens, which is the pre-9.2 behaviour.
	//
	// It exists because the two bounds disagree most on exactly the requests
	// where the fit check bites: v1 prices every image at a flat 2048x2048
	// fallback (2805 tokens) while v2 reads the real dimensions, so a 512x512
	// paste is 2805 under v1 and 255 under v2. Filtering an image request on the
	// v1 number excludes small-window operators that would comfortably serve it,
	// and the reserve leg then sizes the SAME request with v2 — so the filter and
	// the escrow would disagree about what fits. Same shape as
	// MaxOutputUnspecified: a per-operator refinement of the sizing filter that
	// the reserve leg re-derives identically.
	InputTokensV2 uint64 `json:"input_tokens_v2,omitempty"`
	// MaxOutputUnspecified switches the sizing filter from the flat
	// MaxOutputTokens to a per-operator derived ceiling: when set, each
	// operator's effective max_output for the fit check is
	// DeriveMaxOutput(mc.ContextWindow, mc.MaxOutputTokens, MaxOutputCeiling)
	// instead of the request-level MaxOutputTokens. The
	// caller sets it when the request body omitted max_tokens /
	// max_completion_tokens / max_output_tokens and no flat default applies, so a
	// small-window operator isn't excluded on a guessed ceiling it never has to
	// honor. The reserve leg re-derives the SAME value per operator (pure
	// function), so filter and reserve agree. MaxOutputTokens is ignored while
	// this is set. omitempty: absent reads as false (flat behavior, unchanged).
	MaxOutputUnspecified bool `json:"max_output_unspecified,omitempty"`
	// MaxOutputCeiling is the base ceiling DeriveMaxOutput clamps to (the proxy's
	// fallback_max_output_tokens; the flat fallback for an operator that declares
	// neither a window nor a max_output). Ignored unless MaxOutputUnspecified is
	// set. omitempty: absent reads as 0.
	MaxOutputCeiling uint64 `json:"max_output_ceiling,omitempty"`
	// Endpoint is one of the Endpoint* constants. Only the image endpoints
	// change selection; any other value (chat / responses) is treated alike.
	Endpoint string `json:"endpoint"`
	// RequireTEE drops operators without a current passing attestation.
	RequireTEE bool `json:"require_tee"`
	// AllowStaging includes nodes whose on-chain `staging` flag is set (see
	// Operator.Staging) in target selection. Default false: staging nodes are
	// dropped, so the standard routing path never targets a node its operator is
	// still testing. The proxy sets it from `hayai.allow_staging` (config /
	// --allow-staging); the client from the Model Routing "allow staging" toggle.
	// omitempty is correct — the false default matches the Go zero value, and the
	// TS mirror reads an absent field as false.
	AllowStaging bool `json:"allow_staging,omitempty"`
	// RequestedTools is the set of zs_* tool types the request asks for.
	// Operators advertising all of them are partitioned ahead of the rest.
	RequestedTools []string `json:"requested_tools"`
	// ImageToolGenBudget / ImageToolEditBudget are the per-request hayai
	// image-tool budgets (max_n) the caller declared (proxy: from the body's
	// tool_budgets; client: from its image-tool setting). When > 0, operators
	// whose chosen model publishes the matching in-loop image-tool factor are
	// partitioned AHEAD of those that don't — a ranking preference, not a hard
	// filter (a model served only by toolless operators stays selectable; the
	// tool is simply not offered). See SelectTargets step 7b.
	ImageToolGenBudget  uint64 `json:"image_tool_gen_budget"`
	ImageToolEditBudget uint64 `json:"image_tool_edit_budget"`
	// AffinityPolicy is one of Affinity*. With a non-nil preferred operator,
	// "strict" pins to it (or blocks) and "prefer" re-ranks it to the front;
	// "none" ignores affinity entirely.
	AffinityPolicy string `json:"affinity_policy"`

	// --- Caller routing preferences (OpenRouter-style provider selection) ---
	// These come from the request body's `provider` object via
	// ExtractRoutingPreferences. They are advisory inputs the caller sets to
	// guide selection; an empty value (nil slice / 0 / false) means "no
	// preference" and leaves the base policy unchanged.

	// Only is an allowlist: when non-empty, only operators/nodes matching at
	// least one ref survive (a hard filter, applied right after model
	// eligibility, independent of AllowFallbacks). Mirrors OpenRouter `only`.
	Only []OperatorRef `json:"only,omitempty"`
	// Ignore is a denylist: operators/nodes matching any ref are dropped (hard
	// filter, deny-wins over Only). Mirrors OpenRouter `ignore`.
	Ignore []OperatorRef `json:"ignore,omitempty"`
	// Order is the caller's explicit preference order: matching candidates are
	// floated to the front in this order (after any continuation-affinity pin),
	// with unmatched candidates following — unless AllowFallbacks is false, in
	// which case the unmatched tail is dropped (pin to exactly the named set).
	// Mirrors OpenRouter `order`.
	Order []OperatorRef `json:"order,omitempty"`
	// AllowFallbacks governs Order strictness only. When false with a non-empty
	// Order, candidates not named by Order are dropped; an empty result then
	// sets ProviderPinBlocked. It does NOT loosen Only / Ignore (those are
	// always hard). Mirrors OpenRouter `allow_fallbacks`.
	//
	// A POINTER because the meaningful default is true and Go's zero value is
	// false — the opposite. Read it through FallbacksAllowed, never directly.
	// As a plain bool, a caller who set Order and forgot the field silently
	// converted a preference into a hard pin, surfacing as ProviderPinBlocked →
	// 503 no_pinned_operator rather than a route; nothing caught it, because
	// the vectors only cover cases where the field was written explicitly. nil
	// now means "caller said nothing" and resolves to true, matching the TS
	// mirror's `?? true`.
	//
	// omitempty drops only the nil pointer, so an explicit false still
	// serializes into the golden vectors — which is required, or the TS mirror
	// would read the absent field as true and flip a strict pin into a
	// fallback.
	AllowFallbacks *bool `json:"allow_fallbacks,omitempty"`
	// MaxInputUSDPer1M / MaxOutputUSDPer1M are caller price ceilings (USD/1M).
	// 0 ⇒ no ceiling on that axis. An operator whose advertised rate for the
	// model exceeds a set ceiling is filtered out; an undeclared (0) operator
	// rate is treated as exceeding any ceiling (priceRank → +Inf — unknown
	// price is not assumed cheap, consistent with the price sort). An all-out
	// result sets PriceBlocked. Mirrors OpenRouter `max_price`. Comparison-only
	// (no arithmetic), so it stays golden-vector-parity-safe with the ts mirror.
	MaxInputUSDPer1M  float64 `json:"max_input_usd_per_1m,omitempty"`
	MaxOutputUSDPer1M float64 `json:"max_output_usd_per_1m,omitempty"`
	// RequireTools promotes the built-in-tool partition from a ranking
	// preference to a HARD filter: when set with a non-empty RequestedTools,
	// operators not advertising every requested zs_* tool are dropped (an
	// all-out result sets ToolUnsupported). Mirrors OpenRouter
	// `require_parameters`. No effect when RequestedTools is empty.
	RequireTools bool `json:"require_tools,omitempty"`
}

// FallbacksAllowed resolves Constraints.AllowFallbacks: an unset (nil) field
// means the caller said nothing, which is "fallbacks allowed". This is the ONE
// place the default lives on the Go side; the TS mirror spells the same rule
// as `?? true` at its two read sites.
func (c Constraints) FallbacksAllowed() bool {
	return c.AllowFallbacks == nil || *c.AllowFallbacks
}

// SizingMiss records why one operator failed the sizing filter. ContextWindow
// and MaxOutputTokens come straight from the operator's declared ModelCapacity;
// a zero limit means "undeclared" (Fits treats it as unbounded) and should not
// be blamed.
type SizingMiss struct {
	OperatorID      uint64 `json:"operator_id"`
	ContextWindow   uint64 `json:"context_window"`
	MaxOutputTokens uint64 `json:"max_output_tokens"`
	// EffectiveMaxOutput is the max_output the fit check actually charged this
	// operator: the flat request-level MaxOutputTokens, or — in derive mode
	// (Constraints.MaxOutputUnspecified) — the per-operator value from
	// DeriveMaxOutput. It is the number Fits was called with, so a caller
	// rendering a "why didn't this fit" message reports the true gap (input +
	// EffectiveMaxOutput vs ContextWindow) instead of the flat display ceiling,
	// which in derive mode the caller never sent.
	EffectiveMaxOutput uint64 `json:"effective_max_output"`
}

// Diagnostics explains an empty candidate list. Exactly one of the boolean
// flags (or, when none is set and Operators is empty, the SizingMisses path)
// describes the failure, so callers can map it to a precise HTTP status. The
// struct is a superset of what SelectTargets itself sets: callers may add
// their own reasons (e.g. a Responses-API previous_response_id miss they
// resolved before calling) when surfacing the final error.
type Diagnostics struct {
	// RegistryCount is the number of operators serving the requested model
	// (post model-eligibility, pre sizing). 0 ⇒ nobody advertises the model.
	RegistryCount int `json:"registry_count"`
	// SizingMisses is populated when operators serve the model but none fit
	// the requested token sizing.
	SizingMisses []SizingMiss `json:"sizing_misses,omitempty"`
	// VersionBlocked ⇒ fitting operators exist but none advertise a
	// wire-protocol major matching this build.
	VersionBlocked bool `json:"version_blocked"`
	// TEEBlocked ⇒ TEE was required and no fitting operator is attested.
	TEEBlocked bool `json:"tee_blocked"`
	// StagingBlocked ⇒ every otherwise-eligible node serving the model is a
	// staging node and AllowStaging was not set. Distinct from RegistryCount==0:
	// the model IS served, just only by nodes held out of production routing
	// (enable allow_staging to reach them).
	StagingBlocked bool `json:"staging_blocked"`
	// SignerUnderfundedBlocked ⇒ every otherwise-eligible node serving the model
	// has a signing account known to hold less than MinSignerSpendableMicroAlgos
	// spendable — it could not pay the fees of the open/settle it would be asked
	// to sign. Also set when strict affinity pins to such a node. A pool-
	// availability failure (it clears when the operator tops up), distinct from
	// AffinityBlocked, which the proxy reports as a sizing conflict.
	SignerUnderfundedBlocked bool `json:"signer_underfunded_blocked"`
	// ImageEndpointUnsupported ⇒ an image endpoint was requested and no
	// operator serving the model publishes the matching synthetic-token factor.
	ImageEndpointUnsupported bool `json:"image_endpoint_unsupported"`
	// AffinityBlocked ⇒ strict affinity pinned to an operator that can no
	// longer serve this request.
	AffinityBlocked bool `json:"affinity_blocked"`
	// ProviderPinBlocked ⇒ a caller routing preference matched no operator that
	// could serve the request: an Only allowlist that excluded every
	// model-serving operator, or an Order with AllowFallbacks=false whose refs
	// matched none of the eligible candidates. Distinct from RegistryCount==0
	// (operators DO advertise the model; the caller's pin excluded them).
	ProviderPinBlocked bool `json:"provider_pin_blocked"`
	// PriceBlocked ⇒ a caller max_price ceiling excluded every otherwise-eligible
	// operator (including operators with an undeclared rate, treated as too
	// expensive). Mirrors OpenRouter's "no provider meets the price cap".
	PriceBlocked bool `json:"price_blocked"`
	// ToolUnsupported ⇒ RequireTools was set and no operator serving/fitting the
	// model advertises every requested zs_* tool.
	ToolUnsupported bool `json:"tool_unsupported"`
}

// TargetResult is the SelectTargets output: the ordered candidate targets to
// try (empty when the request can't be served), plus diagnostics.
type TargetResult struct {
	Operators   []Operator  `json:"operators"`
	Diagnostics Diagnostics `json:"diagnostics"`
}

// SelectTargets reproduces the proxy's candidate-selection policy as a pure
// function. Order of operations matches proxy/internal/server/hayai_dispatch.go
// ::pickCandidates exactly: model eligibility → caller only/ignore filter →
// sizing → image-factor → wire-version → TEE → staging exclusion → signer
// funding → caller max_price filter → price sort → built-in-tool partition (or hard filter when RequireTools) →
// in-loop image-tool partition → caller order reorder → affinity reorder. The
// price sort is the base order; the stable partitions preserve price order
// within each bucket. Net precedence: affinity > caller-order > image-tool >
// built-in-tool > price > id. The caller filters (only/ignore/max_price/
// require_tools) prune the pool before ranking, so a routing-preference miss
// (ProviderPinBlocked / PriceBlocked / ToolUnsupported) is surfaced distinctly
// rather than masked as a sizing failure.
//
// What it deliberately does NOT do (these stay caller-side because they need
// live runtime state): the Responses-API previous_response_id strict pin and
// the affinity *cache lookup*. The caller resolves the affinity-preferred
// operator (cache → registry) and passes it as preferred (nil when there is
// none); SelectTargets then applies the same serves/fits/strict/prefer rules
// the proxy applies today.
func SelectTargets(ops []Operator, c Constraints, preferred *Operator) TargetResult {
	var res TargetResult

	// 1. Model eligibility. Defensive (callers usually pass a model-filtered
	//    set); idempotent on an already-filtered list. RegistryCount counts
	//    the model-serving operators, matching the proxy's len(registry).
	registry := make([]Operator, 0, len(ops))
	for _, op := range ops {
		if op.ServesModel(c.Model) {
			registry = append(registry, op)
		}
	}
	res.Diagnostics.RegistryCount = len(registry)

	// 2. Caller ref filters (Only allowlist + Ignore denylist). Hard filters
	//    applied before sizing so a caller-pin miss isn't masked by a later
	//    price/sizing diagnostic. RegistryCount stays the pre-filter
	//    model-serving count, so the proxy can tell "your allowlist matched
	//    nobody" (ProviderPinBlocked) apart from "nobody advertises this model"
	//    (RegistryCount==0).
	if len(c.Only) > 0 || len(c.Ignore) > 0 {
		filtered := make([]Operator, 0, len(registry))
		for _, op := range registry {
			if passesRefFilters(op, c.Only, c.Ignore) {
				filtered = append(filtered, op)
			}
		}
		if len(filtered) == 0 {
			res.Diagnostics.ProviderPinBlocked = true
			return res
		}
		registry = filtered
	}

	// 3. Sizing filter (records misses for the actionable error body). In derive
	//    mode (MaxOutputUnspecified) the fit check charges each operator its own
	//    per-operator derived max_output, not the flat request value, so a
	//    small-window operator that a guessed flat ceiling would exclude survives
	//    — the reserve leg re-derives the identical number.
	fitList := make([]Operator, 0, len(registry))
	for _, op := range registry {
		eff := effectiveMaxOutput(op, c)
		if Fits(op, c.Model, effectiveInputTokens(op, c), eff) {
			fitList = append(fitList, op)
			continue
		}
		mc := op.ModelCapacities[c.Model]
		res.Diagnostics.SizingMisses = append(res.Diagnostics.SizingMisses, SizingMiss{
			OperatorID:         op.ID,
			ContextWindow:      mc.ContextWindow,
			MaxOutputTokens:    mc.MaxOutputTokens,
			EffectiveMaxOutput: eff,
		})
	}
	if len(fitList) == 0 {
		return res
	}

	// 4. Image-endpoint factor filter. A missing capacity entry counts as
	//    "no factor" (reserve sizing isn't optional for image routes).
	switch c.Endpoint {
	case EndpointImages:
		eligible := make([]Operator, 0, len(fitList))
		for _, op := range fitList {
			if op.ModelCapacities[c.Model].ServesImageGen {
				eligible = append(eligible, op)
			}
		}
		fitList = eligible
	case EndpointImageEdits:
		eligible := make([]Operator, 0, len(fitList))
		for _, op := range fitList {
			if op.ModelCapacities[c.Model].ServesImageEdit {
				eligible = append(eligible, op)
			}
		}
		fitList = eligible
	}
	if (c.Endpoint == EndpointImages || c.Endpoint == EndpointImageEdits) && len(fitList) == 0 {
		res.Diagnostics.ImageEndpointUnsupported = true
		return res
	}

	// 5. Wire-protocol compatibility (runs after sizing, before TEE).
	compatList := make([]Operator, 0, len(fitList))
	for _, op := range fitList {
		if wire.ProtoVersionCompatible(op.ProtoVersion) {
			compatList = append(compatList, op)
		}
	}
	if len(compatList) == 0 {
		res.Diagnostics.VersionBlocked = true
		return res
	}
	fitList = compatList

	// 6. TEE requirement.
	if c.RequireTEE {
		attested := make([]Operator, 0, len(fitList))
		for _, op := range fitList {
			if op.TEEAttested {
				attested = append(attested, op)
			}
		}
		if len(attested) == 0 {
			res.Diagnostics.TEEBlocked = true
			return res
		}
		fitList = attested
	}

	// 6b. Staging exclusion. A node-level on-chain attribute (Operator.Staging,
	//     from NodeRecord.staging) like TEE above: drop nodes their operator
	//     flagged as staging unless the caller opted in via AllowStaging. The
	//     model-serving RegistryCount is unchanged, so an all-staging model
	//     reports StagingBlocked (served, but only by held-out nodes) rather than
	//     RegistryCount==0.
	if !c.AllowStaging {
		production := make([]Operator, 0, len(fitList))
		for _, op := range fitList {
			if !op.Staging {
				production = append(production, op)
			}
		}
		if len(production) == 0 {
			res.Diagnostics.StagingBlocked = true
			return res
		}
		fitList = production
	}

	// 6c. Signer funding. Unconditional — no caller can opt into a node that
	//     can't pay the fees of the group it would sign. An unknown balance
	//     (nil) passes.
	funded := make([]Operator, 0, len(fitList))
	for _, op := range fitList {
		if !op.SignerUnderfunded() {
			funded = append(funded, op)
		}
	}
	if len(funded) == 0 {
		res.Diagnostics.SignerUnderfundedBlocked = true
		return res
	}
	fitList = funded

	// 7. Caller price ceiling (max_price). Drop operators whose advertised rate
	//    for the model exceeds a set ceiling. An undeclared (0) rate is treated
	//    as exceeding any ceiling (exceedsCeiling → priceRank maps 0 to +Inf),
	//    so an unknown-priced operator is never assumed to fit the cap. An
	//    all-out result is PriceBlocked (vs OpenRouter's "no provider meets the
	//    price cap" hard-fail). Runs before the sort, but order-independent — a
	//    filter, not a reorder.
	//
	//    Skipped entirely on the dedicated image endpoints: the ceiling is
	//    denominated in USD per 1M TOKENS, and an image route bills per image.
	//    Applying it there would reject every image operator on the strength of
	//    its (necessarily zero) token rates. PriceBlocked is therefore never set
	//    on those endpoints; a per-image ceiling would need its own field.
	if !isImageEndpoint(c.Endpoint) && (c.MaxInputUSDPer1M > 0 || c.MaxOutputUSDPer1M > 0) {
		within := make([]Operator, 0, len(fitList))
		for _, op := range fitList {
			mc := op.ModelCapacities[c.Model]
			if exceedsCeiling(mc.InputUSDPer1M, c.MaxInputUSDPer1M) ||
				exceedsCeiling(mc.OutputUSDPer1M, c.MaxOutputUSDPer1M) {
				continue
			}
			within = append(within, op)
		}
		if len(within) == 0 {
			res.Diagnostics.PriceBlocked = true
			return res
		}
		fitList = within
	}

	// 8. Price base sort. Establishes the baseline order (cheapest first — token
	//    USD/1M off-route, the per-image microUSDC rate on the image endpoints).
	//    The stable partitions below preserve this order within each bucket, so
	//    price is the tiebreaker once tool capability is equal. Mirrors the
	//    client's former compareForDefault price axis, now shared.
	sort.SliceStable(fitList, func(i, j int) bool {
		return lessByPrice(fitList[i], fitList[j], c)
	})

	// 9. Built-in tool partition: operators advertising every requested
	//    zs_* tool rank first; unknown-capability operators stay second.
	//    When the caller sets RequireTools, this becomes a HARD filter instead
	//    — operators not advertising every requested tool are dropped, and an
	//    all-out result is ToolUnsupported (OpenRouter require_parameters).
	if len(c.RequestedTools) > 0 {
		if c.RequireTools {
			capable := make([]Operator, 0, len(fitList))
			for _, op := range fitList {
				if op.SupportsAllBuiltinTools(c.RequestedTools) {
					capable = append(capable, op)
				}
			}
			if len(capable) == 0 {
				res.Diagnostics.ToolUnsupported = true
				return res
			}
			fitList = capable
		} else {
			primary := make([]Operator, 0, len(fitList))
			secondary := make([]Operator, 0, len(fitList))
			for _, op := range fitList {
				if op.SupportsAllBuiltinTools(c.RequestedTools) {
					primary = append(primary, op)
				} else {
					secondary = append(secondary, op)
				}
			}
			fitList = append(primary, secondary...)
		}
	}

	// 9b. In-loop image-tool partition. When the request budgets a hayai image
	//     tool, partition operators whose chosen model publishes the matching
	//     in-loop factor AHEAD of those that don't. PREFER, not filter — a model
	//     served only by toolless operators stays selectable for a text turn.
	//     OR-of-budgeted-tools: an operator offering EITHER budgeted tool
	//     outranks a wholly-toolless peer (matches the client's
	//     modelInfoOffersImageTools). Runs after the operator-level tool
	//     partition so the precise per-model signal dominates it, and after the
	//     price sort so price still orders within each bucket. The proxy's
	//     per-tool reserve-skip is the precise correctness gate behind this.
	if c.ImageToolGenBudget > 0 || c.ImageToolEditBudget > 0 {
		primary := make([]Operator, 0, len(fitList))
		secondary := make([]Operator, 0, len(fitList))
		for _, op := range fitList {
			mc := op.ModelCapacities[c.Model]
			capable := (c.ImageToolGenBudget > 0 && mc.OffersImageGenTool) ||
				(c.ImageToolEditBudget > 0 && mc.OffersImageEditTool)
			if capable {
				primary = append(primary, op)
			} else {
				secondary = append(secondary, op)
			}
		}
		fitList = append(primary, secondary...)
	}

	// 10. Caller order reorder. Float candidates named by Order to the front in
	//     the caller's ref order (an operator-only ref pulls all its nodes, in
	//     their current price/id order); unmatched candidates follow. When
	//     AllowFallbacks is false the unmatched tail is dropped — a hard pin to
	//     exactly the named set — and an all-out result is ProviderPinBlocked.
	//     Runs after the partitions (so the caller's explicit order dominates
	//     the price/tool ranking).
	//
	//     Interaction with the affinity pin below depends on AllowFallbacks:
	//     with fallbacks (the default) the order is a soft reorder, so the
	//     affinity step still floats the continuation target ahead of it — the
	//     pin leads. With AllowFallbacks=false the order is a HARD pin to the
	//     named set, which binds the continuation too: if it names nothing
	//     eligible the pool empties here (ProviderPinBlocked); if it names other
	//     candidates but NOT the affinity-preferred one, step 11 surfaces the
	//     conflict (AffinityBlocked under strict, yields the soft pin under
	//     prefer) rather than resurrecting the excluded preferred. Either way a
	//     no-fallback order is never silently overridden by a hidden
	//     continuation. (The proxy turns the strict conflict into a clear error.)
	if len(c.Order) > 0 {
		type nodeKey struct{ id, node uint64 }
		matched := make([]Operator, 0, len(fitList))
		seen := make(map[nodeKey]bool, len(fitList))
		for _, ref := range c.Order {
			for _, op := range fitList {
				k := nodeKey{op.ID, op.NodeID}
				if seen[k] {
					continue
				}
				if ref.Matches(op) {
					matched = append(matched, op)
					seen[k] = true
				}
			}
		}
		if c.FallbacksAllowed() {
			rest := make([]Operator, 0, len(fitList))
			for _, op := range fitList {
				if !seen[nodeKey{op.ID, op.NodeID}] {
					rest = append(rest, op)
				}
			}
			fitList = append(matched, rest...)
		} else {
			if len(matched) == 0 {
				res.Diagnostics.ProviderPinBlocked = true
				return res
			}
			fitList = matched
		}
	}

	// 11. Affinity reorder. preferred is the caller-resolved affinity target
	//     (nil ⇒ none). Note: like the proxy, the tool-affinity path does NOT
	//     re-check wire-version / TEE on the preferred operator — only serves,
	//     fits, and signer funding — so a preferred operator resolved from the
	//     full registry is honored on those axes alone (plus the caller's own
	//     Only/Ignore/Order below). Funding is re-checked because a pinned node
	//     can drain mid-loop, and every paid request sent to a signer that can't
	//     cover its fees fails.
	if c.AffinityPolicy == AffinityNone || preferred == nil {
		res.Operators = fitList
		return res
	}
	if !preferred.ServesModel(c.Model) {
		res.Operators = fitList
		return res
	}
	// The caller's HARD constraints bind the continuation target too: an
	// Only/Ignore exclusion OR a no-fallback Order that doesn't name the
	// preferred must not be silently overridden by resurrecting the
	// affinity-preferred operator. This mirrors RoutingPreferences.AllowsOperator
	// — the same predicate the proxy applies to the previous_response_id pin — so
	// the tool-call and response-id continuation paths agree on what a caller pin
	// excludes. Under strict affinity an excluded preferred is a hard conflict
	// (AffinityBlocked — the continuation can't be served within the caller's
	// constraints); under prefer it yields (drop the soft pin, keep the filtered
	// fitList, which already honors the order/filters).
	//
	// A *soft* (fallbacks-allowed) Order does NOT bind the preferred — it's only
	// a reorder, so the continuation pin still leads it (the affinity step floats
	// the preferred ahead, below). Net: a continuation pin leads over a soft
	// order, but a hard (no-fallback) Order or an Only/Ignore exclusion blocks it.
	if !passesRefFilters(*preferred, c.Only, c.Ignore) ||
		orderHardExcludes(*preferred, c.Order, c.FallbacksAllowed()) {
		if c.AffinityPolicy == AffinityStrict {
			res.Diagnostics.AffinityBlocked = true
			return res
		}
		res.Operators = fitList
		return res
	}
	preferredFits := Fits(*preferred, c.Model, effectiveInputTokens(*preferred, c), effectiveMaxOutput(*preferred, c))
	// A broke preferred node yields under prefer (fitList already excludes it)
	// and blocks under strict — with its own diagnostic, since AffinityBlocked
	// reads as "the continuation no longer fits" and this is "top-up pending".
	// The fit check goes first: a request that has outgrown the node is a
	// permanent answer, and reporting the retryable one ahead of it sends the
	// caller into a backoff that ends in the same refusal.
	if c.AffinityPolicy == AffinityStrict {
		if !preferredFits {
			res.Diagnostics.AffinityBlocked = true
			return res
		}
		if preferred.SignerUnderfunded() {
			res.Diagnostics.SignerUnderfundedBlocked = true
			return res
		}
		res.Operators = []Operator{*preferred}
		return res
	}
	if preferred.SignerUnderfunded() {
		res.Operators = fitList
		return res
	}
	// "prefer": preferred first (when it fits), then everyone else. Dedup the
	// preferred entry from the tail by (id, node_id), NOT id alone — under the
	// operator/node split an operator runs many nodes, and skipping by id would
	// drop the preferred operator's *sibling* nodes from the fallback pool.
	// Only the exact preferred node is the dupe; its siblings stay eligible.
	out := make([]Operator, 0, len(fitList)+1)
	if preferredFits {
		out = append(out, *preferred)
	}
	for _, op := range fitList {
		if op.ID != preferred.ID || op.NodeID != preferred.NodeID {
			out = append(out, op)
		}
	}
	res.Operators = out
	return res
}

// effectiveInputTokens / effectiveMaxOutput adapt this package's Operator +
// Constraints onto the exported scalar rules, which the proxy's reserve leg
// calls with its own types. The rules live there so the filter and the escrow
// cannot drift; these are the local shorthand, nothing more.
//
// Note the miss handling: the map read yields a ZERO ModelCapacity for an
// operator that declares none, and (0, 0) is passed on deliberately — it
// resolves to the flat ceiling. Skipping the call on a miss would be a
// different answer.
func effectiveInputTokens(op Operator, c Constraints) uint64 {
	return EffectiveInputTokens(op.ProtoVersion, c.InputTokens, c.InputTokensV2)
}

func effectiveMaxOutput(op Operator, c Constraints) uint64 {
	mc := op.ModelCapacities[c.Model]
	return EffectiveMaxOutput(mc.ContextWindow, mc.MaxOutputTokens, MaxOutputSpec{
		Unspecified: c.MaxOutputUnspecified,
		Flat:        c.MaxOutputTokens,
		Ceiling:     c.MaxOutputCeiling,
	})
}

// priceRank maps an advertised USD/1M rate onto its sort key: 0 ("undeclared")
// sorts last. Mirror of the ts `rate === 0 ? Infinity : rate`.
func priceRank(r float64) float64 {
	if r == 0 {
		return math.Inf(1)
	}
	return r
}

// isImageEndpoint reports whether e is a dedicated image endpoint — one priced
// per produced image (microUSDC) rather than per token, so the token rates and
// the caller's per-1M-token price ceiling are both meaningless there.
func isImageEndpoint(e string) bool {
	return e == EndpointImages || e == EndpointImageEdits
}

// outputNormTokens is the response length the token-price comparison weighs an
// operator's OUTPUT rate by when the caller didn't state a max_output. The output
// side has no measurement available before the response exists, so it needs a
// stand-in for a typical assistant turn.
//
// NOT effectiveMaxOutput in the derived case: that value is per-operator, so
// using it would charge a large-window node more than a small-window one for the
// identical request and systematically rank capable nodes last — in the common
// case where the caller omits max_tokens entirely. When the caller DID state a
// max_output that's their own bound on what they'll pay for, and it's what escrow
// locks, so requestCost uses it directly.
//
// A zero MaxOutputTokens falls back here too, whatever MaxOutputUnspecified says.
// Weighing the output axis by zero would price every operator's output rate at
// nothing and quietly reduce the comparison to input rates alone — the exact
// behavior this replaced.
const outputNormTokens = 1000

// inputNormTokens is the same stand-in for the INPUT axis, used only when the
// caller measured nothing (both InputTokens and InputTokensV2 zero). Unlike the
// output side that is not an inherent limit — input IS measurable, and the proxy
// always measures it — but two callers deliberately don't: the client builds both
// its model picker and its dispatch candidate list with `input_tokens: 0`, since
// neither knows the request size and the per-attempt context gate is
// authoritative (client/src/operators/catalog.ts, dispatch-candidates.ts).
// Leaving the term at zero there would drop input pricing entirely and reduce
// those lists to output-rate-only ordering, so the client would rank a
// cheap-output/ruinous-input operator first on an input-heavy turn while the
// proxy — measuring the same request — ranked it last. Identical proxy/client
// routing is the requirement that makes the fallback mandatory, not cosmetic.
//
// Equal to outputNormTokens on purpose: with no measurement, weighing the two
// axes equally degrades the comparison to the SUM of the advertised rates, which
// is the neutral answer. Any other ratio would encode a claim about the traffic
// mix that nothing here can support. Keep them equal unless a real measurement of
// that mix says otherwise.
const inputNormTokens = outputNormTokens

// requestCost is what this request is expected to cost at op's advertised token
// rates, in USD·tokens/1e6 — a relative figure for ordering, never a quote.
//
// An undeclared (0) rate on EITHER axis yields +Inf: we can't price the request
// at all, and an unknown price is treated as too expensive, consistent with
// exceedsCeiling and with the pre-cost behavior of ranking undeclared rates last.
// (As elsewhere, 0 can't be distinguished from a genuinely free token model; that
// conflation is documented and accepted, and a free model is vanishingly rare.)
//
// Both token weights are REQUEST-level, never per-operator — deliberately, and
// for the same reason outputNormTokens isn't effectiveMaxOutput. In particular
// the input weight is NOT effectiveInputTokens: that returns the bound the
// operator's own proto version will be sized against, and v2 is not a uniform
// shrink of v1 — tokenize/bound.go calls it "tighter on prose, tool schemas and
// images, but deliberately LARGER on the classes v1 under-counts (base64, hex,
// emoji, embedded JSON)". Weighing by it prices the identical request differently
// for two operators advertising identical rates, ranking a 9.2+ node cheaper on a
// prose body and dearer on a base64 one, on a number that is a reserve bound
// rather than a charge — the bill is the real consumed tokens either way.
// effectiveInputTokens stays the right call for the FIT filter, where agreeing
// per-operator with what escrow locks is the whole point.
//
// Parity: this is the only arithmetic in the price comparison, so the operand
// order and the uint64→float64 conversion points must stay IDENTICAL to the ts
// mirror (proto/ts/src/selection/select.ts). Both sides are IEEE-754 doubles and
// token counts are far below 2^53, so the results are bit-identical as long as
// nobody reassociates the expression.
func requestCost(op Operator, c Constraints) float64 {
	mc := op.ModelCapacities[c.Model]
	if mc.InputUSDPer1M == 0 || mc.OutputUSDPer1M == 0 {
		return math.Inf(1)
	}
	// v2 first: it's the calibrated measurement of this request, so it's the
	// better cost estimate wherever the caller computed one. Which operators can
	// be SIZED against it is a separate question, answered by effectiveInputTokens.
	inputTokens := c.InputTokensV2
	if inputTokens == 0 {
		inputTokens = c.InputTokens
	}
	if inputTokens == 0 {
		inputTokens = inputNormTokens
	}
	outputTokens := c.MaxOutputTokens
	if c.MaxOutputUnspecified || outputTokens == 0 {
		outputTokens = outputNormTokens
	}
	return mc.InputUSDPer1M*float64(inputTokens) +
		mc.OutputUSDPer1M*float64(outputTokens)
}

// lessByPrice orders two operators for the request's model and endpoint.
//
// On the dedicated image endpoints it orders by the route's microUSDC rate,
// where 0 means free and ranks first (the serves-image eligibility filter has
// already dropped non-serving operators, so 0 can't mean "undeclared" here).
//
// On every other endpoint it orders by the request's expected COST at each
// operator's advertised token rates (requestCost), cheapest first. It used to
// compare axis-by-axis — lowest input rate, then lowest output rate — which
// returns on the first differing axis and therefore ranks in $0.01 / out $50.00
// ahead of in $0.02 / out $0.05 on every request, including the output-heavy ones
// where the second is a thousand times cheaper to actually run. Weighing both
// axes by how many tokens the request will use them for is what makes "cheapest"
// mean what a payer reading their bill means by it.
//
// Ties break by operator id, then node id.
func lessByPrice(a, b Operator, c Constraints) bool {
	ca := a.ModelCapacities[c.Model]
	cb := b.ModelCapacities[c.Model]
	switch c.Endpoint {
	case EndpointImages:
		if ca.ImageRateMicroUSDC != cb.ImageRateMicroUSDC {
			return ca.ImageRateMicroUSDC < cb.ImageRateMicroUSDC
		}
	case EndpointImageEdits:
		if ca.ImageEditRateMicroUSDC != cb.ImageEditRateMicroUSDC {
			return ca.ImageEditRateMicroUSDC < cb.ImageEditRateMicroUSDC
		}
	default:
		if pa, pb := requestCost(a, c), requestCost(b, c); pa != pb {
			return pa < pb
		}
	}
	if a.ID != b.ID {
		return a.ID < b.ID
	}
	// Same operator, different nodes — stable tiebreak by node id.
	return a.NodeID < b.NodeID
}

// passesRefFilters reports whether op survives the caller's Only allowlist and
// Ignore denylist. Deny wins: an op matching any Ignore ref is rejected even if
// it also matches Only. An empty Only is "no allowlist" (everyone passes the
// allowlist gate); a non-empty Only requires a match. Mirror of the ts
// passesRefFilters.
func passesRefFilters(op Operator, only, ignore []OperatorRef) bool {
	for _, r := range ignore {
		if r.Matches(op) {
			return false
		}
	}
	if len(only) > 0 {
		for _, r := range only {
			if r.Matches(op) {
				return true
			}
		}
		return false
	}
	return true
}

// orderHardExcludes reports whether a no-fallback Order hard-excludes op. A
// non-empty Order with AllowFallbacks=false names exactly the legal set, so an
// op the Order doesn't name is excluded just as Only/Ignore would exclude it. An
// empty Order, or a fallbacks-allowed (default) Order, is a soft reorder and
// never excludes. This is the Order half of RoutingPreferences.AllowsOperator;
// SelectTargets applies it (with passesRefFilters) to bind the affinity-preferred
// continuation target, matching the proxy's previous_response_id pin check.
func orderHardExcludes(op Operator, order []OperatorRef, allowFallbacks bool) bool {
	if len(order) == 0 || allowFallbacks {
		return false
	}
	for _, ref := range order {
		if ref.Matches(op) {
			return false
		}
	}
	return true
}

// exceedsCeiling reports whether an advertised USD/1M rate breaches a caller
// price ceiling. A ceiling <= 0 means "no ceiling on this axis" (never
// exceeded). An undeclared (0) rate maps to priceRank +Inf, so it exceeds every
// finite ceiling — an unknown price is treated as too expensive, consistent
// with the price sort treating 0 as last. Comparison-only, parity-safe with the
// ts mirror.
func exceedsCeiling(rate, ceiling float64) bool {
	if ceiling <= 0 {
		return false
	}
	return priceRank(rate) > ceiling
}

// SelectRelay picks the single-hop relay operator for a request whose target
// is already chosen. Eligibility:
//
//   - id != target.ID                       (never relay through the target's
//     own operator — excludes all of that operator's nodes)
//   - OwnerAddr != target.OwnerAddr         (hard owner-diversity rule; the
//     authoritative resolved-owner check)
//   - ProtoVersionCompatible(ProtoVersion)  (relay must speak this generation,
//     i.e. actually expose the /v1/zs/relay route)
//   - /16 subnet diversity                  (best-effort; skipped for hostnames)
//
// Reachability is a soft *preference*, not a hard requirement: a relay known to
// be Reachable is always chosen over a not-known-reachable one, but when none of
// the eligible relays are known-reachable the pick falls back to the full
// eligible set rather than failing. This keeps a down operator from being chosen
// as a relay in steady state (its forward would just connection-refuse) without
// reintroducing the cold-start deadlock that a hard Reachable requirement caused
// — at cold start nothing is known-reachable yet, so the fallback still picks a
// relay and lets discovery bootstrap. (Note: under privacy mode a relayed-probe
// failure is ambiguous — target-down vs relay-down — so Reachable is a hint that
// self-corrects across cycles via rotation, never a guarantee; that's exactly
// why it's a preference and not an exclusion.)
//
// Operator.Reachable here means "the CALLER can use this node AS A RELAY", which
// is not the same thing as "this node is reachable as a target". For a server
// caller (the proxy) the two coincide — it reaches every node directly, so its
// own target-probe outcome is a fine relay-reachability signal. For a browser
// caller (client/) they DIVERGE: a node can be reachable as a target via the
// relay mesh yet be a dead relay from the browser (localhost-resolving, CORS-
// blocked, firewalled), and vice-versa. Such a caller MUST feed Reachable from
// its OWN direct evidence of forwarding through the node — never from target
// reachability alone — or the preferred tier fills with un-relay-able nodes and
// the genuinely-usable relays sink into the fallback tier. See the client's
// relay-health verdict (operators/relay-health.ts) for that derivation.
//
// Determinism for golden vectors comes from sorting the chosen pool by id and
// indexing with seed: pool[seed % len]. In production the caller supplies a
// fresh crypto-random seed per request, which IS the per-request rotation: no
// single relay accumulates a session-long profile of one client (see SPEC.md
// § 3f "Anonymity & trust model"). Returns ErrNoRelay when no operator
// qualifies; the caller must hard-fail rather than route direct.
func SelectRelay(ops []Operator, target Operator, seed uint64) (*Operator, error) {
	pool := EligibleRelays(ops, target)
	if len(pool) == 0 {
		return nil, ErrNoRelay
	}
	pick := pool[seed%uint64(len(pool))]
	return &pick, nil
}

// EligibleRelays returns the relay candidates for target that SelectRelay would
// index into — the same eligibility (id/owner/version/ /16) filtering, the same
// reachable-preferred tier, and the same (id, node_id) ordering — but WITHOUT the
// final seed pick. It is a pure extraction of SelectRelay's pool step (SelectRelay
// is now EligibleRelays(...)[seed % len]), so its output is unchanged and the
// golden vectors stay green.
//
// It exists for a caller that wants to rank the eligible pool by a signal the
// shared policy deliberately omits — client-observed network latency — without
// duplicating the diversity rules (and risking drift from the /16 + owner-key
// guards). Latency is a stateful, per-process, vantage-specific signal: it isn't a
// pure function of the static inputs the golden vectors pin, so it can't live in
// this shared policy at all. Each caller measures it from its own position
// (the proxy and the client are both single-payer processes reaching the mesh)
// and applies it as an app-side refinement over this pool. The pool is already in
// preferred-tier order: when any relay is Reachable only reachables are returned,
// else the full eligible set (the cold-start fallback), matching SelectRelay.
func EligibleRelays(ops []Operator, target Operator) []Operator {
	var reachable, fallback []Operator
	for _, op := range ops {
		if op.ID == target.ID {
			continue
		}
		if op.OwnerAddr == target.OwnerAddr {
			continue
		}
		if !wire.ProtoVersionCompatible(op.ProtoVersion) {
			continue
		}
		if !diverseSubnet(op.BaseURL, target.BaseURL) {
			continue
		}
		if op.Reachable {
			reachable = append(reachable, op)
		} else {
			fallback = append(fallback, op)
		}
	}
	pool := reachable
	if len(pool) == 0 {
		pool = fallback
	}
	sort.Slice(pool, func(i, j int) bool {
		if pool[i].ID != pool[j].ID {
			return pool[i].ID < pool[j].ID
		}
		return pool[i].NodeID < pool[j].NodeID
	})
	return pool
}

// diverseSubnet reports whether two base URLs are in different /16 networks.
// This is a best-effort, defense-in-depth signal against an adversary
// co-locating relay and target in the same *public* hosting subnet. It is
// deliberately conservative about excluding relays:
//
//   - DNS-name hosts (the common case — operator base URLs are NFD-derived
//     hostnames) are unverifiable, so they're treated as diverse, never excluded.
//   - Non-public addresses (loopback / private / link-local) are treated as
//     diverse too: sharing a /16 is the *norm* among them in local and test
//     deployments (e.g. every node on 127.0.0.1 or a 10.x LAN), so applying the
//     rule there would exclude every relay and break privacy mode on a localnet
//     for no security benefit.
//   - Only when BOTH hosts are public IPv4 addresses sharing the first two
//     octets do we exclude.
func diverseSubnet(a, b string) bool {
	ipA := hostIP(a)
	ipB := hostIP(b)
	if ipA == nil || ipB == nil {
		return true // hostnames: subnet unknowable → diverse
	}
	a4 := ipA.To4()
	b4 := ipB.To4()
	if a4 == nil || b4 == nil {
		return true // IPv6 / mixed families: no /16 notion we trust
	}
	if !isPublicIPv4(ipA) || !isPublicIPv4(ipB) {
		return true // loopback/private/etc.: same-/16 is meaningless
	}
	return !(a4[0] == b4[0] && a4[1] == b4[1])
}

// isPublicIPv4 reports whether ip is a globally-routable IPv4 address — not
// loopback, private (RFC1918), link-local, unspecified, or multicast. Mirror
// of the ts isPublicIPv4 (proto/ts/src/selection/select.ts); the two must agree
// or relay /16 diversity would differ between the proxy and the client.
func isPublicIPv4(ip net.IP) bool {
	return !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast())
}

// hostIP parses baseURL and returns its host as a literal IP, or nil when the
// URL can't be parsed or the host is a DNS name.
func hostIP(baseURL string) net.IP {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	return net.ParseIP(u.Hostname())
}
