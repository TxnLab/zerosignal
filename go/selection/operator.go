/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package selection holds the shared, transport-agnostic operator- and
// path-selection policy used by every hayai "user" endpoint (the proxy and
// the client/ chat app). Lifting the policy here — rather than letting each
// app reimplement it — is what guarantees they pick the same target and the
// same relay hop, so the network's privacy and routing behavior is uniform.
//
// The package is pure: no logger, no config, no HTTP, no clock, no global
// state. Each app populates the Operator descriptors from its own on-chain
// enumeration + /v1/zs/details enrichment (the I/O stays per-app) and
// hands them to SelectTargets / SelectRelay. The deterministic parts are
// pinned across the Go and TypeScript implementations by the golden vectors
// in proto/testdata/selection_vectors.json.
package selection

import (
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/wire"
)

// Operator is the enriched, transport-agnostic descriptor the policy ranks.
// Since the operator/node split it describes a single NODE belonging to an
// operator: ID is the operator id, NodeID identifies the node within it, and
// BaseURL / capabilities are that node's. It carries only the fields routing
// actually consults — deliberately *not* the reliability metrics (latency /
// revenue), which are observability-only and would introduce float
// comparisons that threaten Go↔TS byte parity.
type Operator struct {
	// ID is the stable on-chain operator id. Combined with NodeID it is the
	// routing primary key (selection input, relay-target header, affinity
	// cache). Multiple descriptors can share an ID — one per node the
	// operator runs.
	ID uint64 `json:"id"`

	// NodeID is the node's id within ID (the per-operator node counter).
	// Addresses the specific endpoint for the relay-target header / affinity
	// cache. Zero for legacy single-node inputs.
	NodeID uint64 `json:"node_id"`

	// OwnerAddr is the operator's on-chain owner address (shared by all of an
	// operator's nodes). Relay selection uses owner inequality as the hard
	// diversity rule (a client must not relay through a node under the same
	// custody as its target) — this is why nodes of the same operator are
	// never chosen as relays for one another.
	OwnerAddr string `json:"owner_addr"`

	// BaseURL is the node root (e.g. "https://node.example"). Relay selection
	// parses it for best-effort /16 diversity; the relay hop is addressed by
	// (id, node_id), never by this URL directly.
	BaseURL string `json:"base_url"`

	// ProtoVersion is the wire-protocol generation the operator advertises
	// on /v1/zs/details, "<major>.<minor>". Both target and relay
	// filtering require major-equality with this build (wire.ProtoVersion);
	// an empty value is treated as the legacy version.
	ProtoVersion string `json:"proto_version"`

	// Reachable reports whether the most recent /v1/zs/details probe
	// succeeded. It is the RELAY-eligibility signal (SelectRelay prefers
	// reachable relays — see select.go), NOT a target-model gate: ServesModel no
	// longer consults it (an empty Models list means "serves nothing" regardless
	// of reachability). Neither target nor relay selection hard-requires it —
	// both attempt operators that aren't currently reachable and let the
	// request's failure path handle a genuinely-down node.
	Reachable bool `json:"reachable"`

	// TEEAttested reports a current, passing confidential-mode attestation
	// verdict. Only consulted when Constraints.RequireTEE is set.
	TEEAttested bool `json:"tee_attested"`

	// Staging mirrors the node's on-chain `staging` flag (NodeRecord.staging):
	// a node its operator brought up for testing and wants held out of
	// production target selection. SelectTargets drops staging nodes unless
	// Constraints.AllowStaging is set, so the default routing path never targets
	// one. App-side adapters set it from the node record (proxy:
	// escrow.NodeRecord.Staging; client: the generated record's staging byte) and
	// default it to false for any descriptor predating the field. Like the other
	// node-attribute gates it is consulted for TARGET selection only, not relay
	// eligibility.
	Staging bool `json:"staging,omitempty"`

	// SignerSpendableMicroAlgos is the node signing account's spendable ALGO
	// (amount − min-balance), read by each app from algod. That account pays the
	// pooled fees for every payer's open() group and atomic settle, so a node that
	// can't cover them can't serve a request no matter what else it advertises;
	// SelectTargets drops a node below MinSignerSpendableMicroAlgos. nil means
	// "never successfully read" and is ELIGIBLE: the absence of a reading is not
	// evidence of a broke node, and failing closed would let an algod outage empty
	// every picker. (A failed re-read keeps the last-known value, so nil is only
	// ever the first-read state.) A pointer because 0 is a real, disqualifying
	// reading.
	// Target-only, like Staging: a relay forwards bytes and pays no fee.
	SignerSpendableMicroAlgos *uint64 `json:"signer_spendable_microalgos,omitempty"`

	// Models is the operator's advertised model list — the node's
	// /v1/zs/details set, which is exactly what it will accept reserves for.
	// Empty means "serves nothing": not a routing candidate for any model (see
	// ServesModel).
	Models []string `json:"models"`

	// ModelCapacities is the per-model sizing envelope keyed by model id.
	// A missing entry is treated as unbounded by Fits.
	ModelCapacities map[string]ModelCapacity `json:"model_capacities"`

	// BuiltinTools is the set of hayai built-in tool type names the
	// operator advertises. nil means unknown capability — the tool
	// partition treats such operators as "don't prefer, don't exclude".
	BuiltinTools []string `json:"builtin_tools"`
}

// ModelCapacity declares an operator's capability envelope for one model.
// Only the fields the selection policy reads are carried here; modalities live
// on the per-app descriptors and never influence selection, so they are
// intentionally omitted. Advertised USD rates ARE carried (see InputUSDPer1M):
// they feed the price sort in SelectTargets. The only float operation is
// comparison on values that came verbatim off the same JSON wire numbers (no
// arithmetic / accumulation), and the golden vectors pin it — so Go↔TS byte
// parity holds.
type ModelCapacity struct {
	// ContextWindow bounds input_tokens + max_output_tokens (0 = unbounded).
	ContextWindow uint64 `json:"context_window"`
	// MaxOutputTokens bounds max_output_tokens on its own (0 = no separate cap).
	MaxOutputTokens uint64 `json:"max_output_tokens"`
	// ServesImageGen is true when the operator serves /v1/images/generations for
	// this model — the eligibility signal for that endpoint. The authoritative
	// per-image SIZING still reads the rate off the app-side catalog, not this
	// routing descriptor; ImageRateMicroUSDC below exists only to ORDER
	// candidates.
	ServesImageGen bool `json:"serves_image_gen"`
	// ServesImageEdit is the sibling flag for /v1/images/edits.
	ServesImageEdit bool `json:"serves_image_edit"`
	// OffersImageGenTool / OffersImageEditTool are the in-loop image-tool
	// eligibility flags (a chat model's zs_image_generation / zs_image_edit
	// on /v1/responses). DELIBERATELY separate from ServesImageGen / ServesImageEdit
	// (the dedicated /v1/images/* route signal): true here means this chat model
	// offers the in-loop tool. The in-loop image-tool partition in SelectTargets
	// prefers operators that offer the matching tool when the request budgets it
	// (a ranking preference, not an eligibility filter — see step 7b).
	OffersImageGenTool  bool `json:"offers_image_gen_tool"`
	OffersImageEditTool bool `json:"offers_image_edit_tool"`
	// InputUSDPer1M / OutputUSDPer1M are the operator's advertised USD/1M
	// inference rates for this model, copied verbatim from /v1/zs/details.
	// SelectTargets price-sorts candidates by InputUSDPer1M then OutputUSDPer1M
	// (lowest first). 0 is the "undeclared" sentinel and sorts LAST (there is no
	// JSON undefined to distinguish it from a real $0 rate; a genuinely free
	// model is vanishingly rare and the conservative choice is to not float it
	// to the top of every list). Comparison-only — never accumulated — so this
	// does not threaten Go↔TS golden-vector parity.
	InputUSDPer1M  float64 `json:"input_usd_per_1m"`
	OutputUSDPer1M float64 `json:"output_usd_per_1m"`
	// ReasoningSupported mirrors the operator's advertised reasoning.supported
	// flag (details ModelReasoning.Supported).
	//
	// DORMANT: it used to raise DeriveMaxOutput's ceiling for a reasoning model,
	// on the theory that chain-of-thought spends output budget before the visible
	// answer. That raise is now the ONLY ceiling (DefaultMaxOutputCeiling), so
	// nothing reads this field and no selection outcome depends on it. Kept
	// rather than removed because it is a serialized field of the descriptor the
	// golden vectors pin and the proxy still populates it
	// (proxy/internal/hayai/operator.go) — deprecate, don't remove.
	// omitempty (like Staging on Operator): absent reads as false.
	ReasoningSupported bool `json:"reasoning_supported,omitempty"`
	// ImageRateMicroUSDC / ImageEditRateMicroUSDC are the microUSDC price of one
	// 1024²-standard image on the dedicated /v1/images/generations and
	// /v1/images/edits routes. SelectTargets price-sorts by these instead of the
	// token rates on those endpoints, where an image model's token rates are 0
	// and would otherwise rank every candidate as "undeclared".
	//
	// Unlike the token rates, 0 here means FREE, not "undeclared": the
	// ServesImageGen / ServesImageEdit eligibility filter has already dropped
	// every non-serving operator before the sort runs, so a survivor's 0 is a
	// deliberately-free route and ranks CHEAPEST. No +Inf sentinel.
	//
	// Sorting on the base rate is order-equivalent to sorting on the actual
	// charge: CostMicroUSDC = n × ceil(rate × Factor(size, quality)), and Factor
	// depends only on the request, so it is a shared monotone multiplier across
	// candidates. That is why size/quality never enter selection.
	//
	// Integer microUSDC, compared and never accumulated — parity with the ts
	// mirror is exact, unlike the float64 token rates above.
	ImageRateMicroUSDC     uint64 `json:"image_rate_micro_usdc"`
	ImageEditRateMicroUSDC uint64 `json:"image_edit_rate_micro_usdc"`
}

// ServesModel reports whether this operator's published model list includes
// model. An empty Models list means "serves nothing" — a node advertising zero
// models is not a routing candidate for ANY model, matching the node's own
// /v1/zs/details contract (that list is the exact set of reservable models,
// so an empty list means every reserve would be refused).
//
// This deliberately does NOT wildcard on Reachable. A reachable node with an
// empty catalog (e.g. every model dropped by the node's provenance gate for
// lack of a source) was previously treated as "serves everything", which made
// it a tried-then-rejected candidate for every model — wasted reserve
// round-trips plus a misleading operators_busy masking the real no_operator.
//
// This mirrors proxy/internal/hayai/operator.go::ServesModel byte-for-byte;
// the two must agree or the proxy and client would disagree on eligibility.
func (o Operator) ServesModel(model string) bool {
	for _, m := range o.Models {
		if m == model {
			return true
		}
	}
	return false
}

// MinSignerSpendableMicroAlgos is the routing floor for a node signing account's
// spendable ALGO: 5 ALGO. Sized as a staleness budget, not a fee estimate — at
// ~7,000 µALGO of pooled fees per paid request it covers ~700 requests, so a node
// that read as just-funded can't run dry between two of the apps' balance reads
// (one catalog refresh, 5 minutes by default) unless it sustains more than ~2.3
// paid requests per second.
const MinSignerSpendableMicroAlgos uint64 = 5_000_000

// SignerUnderfunded reports whether a spendable-ALGO reading is known and below
// MinSignerSpendableMicroAlgos. nil (never read) is not underfunded.
func SignerUnderfunded(spendable *uint64) bool {
	return spendable != nil && *spendable < MinSignerSpendableMicroAlgos
}

// SignerUnderfunded reports whether this node's signing account is known to be
// below the routing floor. See SignerSpendableMicroAlgos.
func (o Operator) SignerUnderfunded() bool {
	return SignerUnderfunded(o.SignerSpendableMicroAlgos)
}

// SupportsBuiltinTool reports whether the operator advertises toolType.
// An operator with no declared tools (nil) returns false — selection only
// "prefers" operators that positively advertise a capability.
func (o Operator) SupportsBuiltinTool(toolType string) bool {
	for _, t := range o.BuiltinTools {
		if t == toolType {
			return true
		}
	}
	return false
}

// SupportsAllBuiltinTools returns true only if every tool in needed appears
// in BuiltinTools. An empty need set trivially holds.
func (o Operator) SupportsAllBuiltinTools(needed []string) bool {
	if len(needed) == 0 {
		return true
	}
	for _, n := range needed {
		if !o.SupportsBuiltinTool(n) {
			return false
		}
	}
	return true
}

// Fits reports whether op can serve a request for model under its declared
// ModelCapacity. Operators with no declared capacity for model are treated as
// unbounded. The context-window check delegates to inject.FitsContextWindow so
// proxy, node, and client agree byte-for-byte on what "fits" means.
//
// Mirrors proxy/internal/hayai/sizing.go::Fits.
func Fits(op Operator, model string, inputTokens, maxOutputTokens uint64) bool {
	mc, ok := op.ModelCapacities[model]
	if !ok {
		return true
	}
	if !inject.FitsContextWindow(inputTokens, maxOutputTokens, mc.ContextWindow) {
		return false
	}
	if mc.MaxOutputTokens > 0 && maxOutputTokens > mc.MaxOutputTokens {
		return false
	}
	return true
}

// MaxOutputSpec is the request-level half of the effective-max_output rule:
// what the caller asked for, and what to fall back on when they asked for
// nothing. The operator-level half (its declared window and cap) is passed
// alongside it to EffectiveMaxOutput.
//
// A small value struct rather than three loose parameters, so the two uint64s
// cannot be transposed at a call site, and scalar-only so it never allocates
// on the reserve leg's per-operator loop.
type MaxOutputSpec struct {
	// Unspecified is true when the caller omitted max_output_tokens and no
	// per-model default applied — the signal to derive PER OPERATOR from
	// declared capacity rather than charge everyone one guessed ceiling.
	// Mirrors Constraints.MaxOutputUnspecified / the proxy's
	// SizingRequest.DeriveMaxOutput.
	Unspecified bool
	// Flat is the caller's max_output_tokens, used verbatim unless
	// Unspecified. Ignored while Unspecified is set.
	Flat uint64
	// Ceiling is DeriveMaxOutput's baseCeiling. Every caller passes
	// DefaultMaxOutputCeiling — see that constant for why a per-caller ceiling
	// was a routing bug.
	Ceiling uint64
}

// EffectiveMaxOutput resolves the max_output_tokens a request charges ONE
// operator, from that operator's declared capacity for the model.
//
// This is the number the sizing filter admits on AND the number the reserve
// leg escrows, and they must be the same number: a disagreement is discovered
// only after escrow.open, where there is no failover. It was previously held
// by three independently-edited implementations — this one, the proxy's
// reserve leg, and the client's — kept in step by prose cross-references, with
// the golden vectors pinning SelectTargets rather than the reserve leg. The Go
// halves now share this function; the TS mirror still has its own copy and is
// pinned by the vectors.
//
// contextWindow / declaredMax are the operator's declared ModelCapacity for
// the model, or (0, 0) when it declares none. Pass (0, 0) on a lookup miss
// rather than skipping the call: it resolves to the flat ceiling, which is the
// "unbounded operator gets the flat fallback" behavior from before per-operator
// derivation. (Fits short-circuits such an operator to "unbounded" before the
// value is consulted, so the branch is unobservable there — but the reserve leg
// does consult it.)
//
// Scalar arguments deliberately: the proxy's reserve leg holds its own operator
// type, and converting it to a selection.Operator allocates a map and a slice
// per call.
func EffectiveMaxOutput(contextWindow, declaredMax uint64, spec MaxOutputSpec) uint64 {
	if !spec.Unspecified {
		return spec.Flat
	}
	return DeriveMaxOutput(contextWindow, declaredMax, spec.Ceiling)
}

// EffectiveInputTokens picks which input measurement an operator is filtered
// and sized on: the tighter v2 bound where the operator advertises support for
// it, else v1.
//
// The two bounds disagree most on exactly the requests where the sizing filter
// bites — v1 prices every image at a flat 2048x2048 fallback while v2 reads the
// real dimensions — so filtering on the v1 number routes an image request away
// from small-window operators that would serve it comfortably. The filter and
// the escrow must therefore agree on the same number for the same operator,
// which is why this is one function and not a rule each leg restates.
//
// inputTokensV2 == 0 means "not supplied" and every operator is measured on
// inputTokens.
//
// protoVersion is the operator's ADVERTISED version, gated through
// wire.UsesTightInputBound. Scalar arguments for the same reason as
// EffectiveMaxOutput.
func EffectiveInputTokens(protoVersion string, inputTokens, inputTokensV2 uint64) uint64 {
	if inputTokensV2 > 0 && wire.UsesTightInputBound(protoVersion) {
		return inputTokensV2
	}
	return inputTokens
}

// Constants for DeriveMaxOutput's proportionate fallback. They mirror the
// client's deriveMaxOutputTokens (client/src/stream/config.ts) so the two
// implementations produce the same reservation for the same operator.
const (
	// MinDerivedMaxOutput floors the proportionate branch: the admission layer
	// rejects max_output_tokens <= 0, so a degenerate context window (e.g. 32)
	// must still produce a positive reservation. 256 is small enough to leave
	// room for input on a tiny window and large enough to be a usable completion
	// budget.
	MinDerivedMaxOutput uint64 = 256
	// MaxOutputContextFractionDenom is the divisor for the proportionate branch:
	// reserve ContextWindow / N for output when a window is declared but a
	// max_output_tokens is not. N=4 tracks where declared max_output_tokens
	// clusters on real operator catalogs (at or below ctx/4).
	MaxOutputContextFractionDenom uint64 = 4
	// DefaultMaxOutputCeiling is the base ceiling every caller passes unless it
	// has a specific reason not to: the proxy's fallback_max_output_tokens
	// default and the client's DEFAULT_MAX_OUTPUT_TOKENS are both this value.
	//
	// It used to differ per caller (proxy 32000, client 4096), with a separate
	// raise to 32768 for reasoning-capable models. That split was a routing bug,
	// not a policy: because Fits() is evaluated against the DERIVED number, the
	// proxy and the client disagreed about which operators were eligible for the
	// same request whenever ContextWindow > 16384 — e.g. at ctx 32768 with 28000
	// input, the client derived 4096 and kept the operator while the proxy
	// derived 8192 and filtered it out. The proxy is meant to route identically
	// to the client, so there is now one ceiling, set at the value the reasoning
	// branch already used. The larger reservation is LOCKED, not charged —
	// settlement bills actual tokens and refunds the rest.
	DefaultMaxOutputCeiling uint64 = 32768
)

// DeriveMaxOutput computes a per-operator worst-case completion reservation for a
// request that did NOT specify max_output_tokens, from the operator's declared
// capacity. It mirrors the client's deriveMaxOutputTokens, and is the single
// source of truth both the sizing filter (Constraints.MaxOutputUnspecified) and
// the caller's reserve leg use — so what the filter admits and what the ticket
// escrows never disagree. Three branches:
//
//   - declaredMax > 0 → returned unchanged (the operator's advertised cap is
//     authoritative; requesting more would just bounce off its own reserve gate);
//   - else, contextWindow > 0 → a proportionate slice
//     clamp(contextWindow/MaxOutputContextFractionDenom, MinDerivedMaxOutput, baseCeiling).
//     So a small-window operator (e.g. a ~2K local node) isn't hard-blocked by a
//     flat guessed ceiling it never has to honor;
//   - else (neither declared) → baseCeiling, the flat fallback.
//
// baseCeiling is still a parameter rather than a constant because it travels
// through Constraints.MaxOutputCeiling from the caller's own configuration, but
// every caller passes DefaultMaxOutputCeiling — see that constant for why a
// per-caller ceiling was a routing bug. There is deliberately no reasoning-capable special case: the
// single ceiling IS the value the reasoning branch used, so a thinking model
// still gets room for its chain-of-thought AND the answer.
//
// The derived reservation is LOCKED in escrow, not charged — settlement bills
// actual tokens and refunds the rest.
func DeriveMaxOutput(contextWindow, declaredMax, baseCeiling uint64) uint64 {
	if declaredMax > 0 {
		return declaredMax
	}
	if contextWindow > 0 {
		ceiling := baseCeiling
		proportionate := contextWindow / MaxOutputContextFractionDenom
		if proportionate < MinDerivedMaxOutput {
			proportionate = MinDerivedMaxOutput
		}
		if proportionate > ceiling {
			proportionate = ceiling
		}
		return proportionate
	}
	return baseCeiling
}

// OperatorRef is a caller-supplied reference to an operator or a specific node,
// the unit of the routing-preference allowlist / denylist / order lists
// (Constraints.Only / Ignore / Order). It mirrors OpenRouter's base-slug vs
// full-slug matching: a ref naming only an operator matches ALL of that
// operator's nodes (MatchAllNodes), while a ref naming a node matches just that
// (OperatorID, NodeID) pair — the same routing primary key everything else in a
// routing path uses. The wire form (in the request body's `provider` object) is
// a string parsed by ParseOperatorRef; this struct is the internal/JSON shape
// the golden vectors pin.
type OperatorRef struct {
	// OperatorID is the on-chain operator id the ref names.
	OperatorID uint64 `json:"operator_id"`
	// NodeID is the node within OperatorID. Ignored when MatchAllNodes is set.
	NodeID uint64 `json:"node_id"`
	// MatchAllNodes is true for an operator-only ref ("<operatorId>"): it
	// matches every node of OperatorID regardless of NodeID. False for a
	// node-specific ref ("<operatorId>:<nodeId>"). The explicit flag avoids the
	// node-0 ambiguity (node id 0 is a real, legacy node id, not "any node").
	MatchAllNodes bool `json:"match_all_nodes"`
}

// Matches reports whether op is the operator/node this ref names. An
// operator-only ref matches any node of the operator; a node-specific ref
// matches only the exact (operator id, node id) pair.
func (r OperatorRef) Matches(op Operator) bool {
	if r.OperatorID != op.ID {
		return false
	}
	if r.MatchAllNodes {
		return true
	}
	return r.NodeID == op.NodeID
}

// ParseOperatorRef parses a caller ref string into an OperatorRef. The forms are
//
//	"<operatorId>"            → MatchAllNodes (any node of the operator)
//	"<operatorId>:<nodeId>"   → that exact node
//
// Both components are unsigned decimal integers. Surrounding whitespace is
// trimmed. Returns ok=false on any malformed input (empty, non-numeric, extra
// colons, negative); callers treat a bad ref as advisory and skip it rather
// than failing the request. Mirror of the ts parseOperatorRef — the two must
// agree or the proxy and client would resolve a pin differently.
func ParseOperatorRef(s string) (OperatorRef, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return OperatorRef{}, false
	}
	opPart, nodePart, hasNode := strings.Cut(s, ":")
	opID, err := strconv.ParseUint(strings.TrimSpace(opPart), 10, 64)
	if err != nil {
		return OperatorRef{}, false
	}
	if !hasNode {
		return OperatorRef{OperatorID: opID, MatchAllNodes: true}, true
	}
	nodeID, err := strconv.ParseUint(strings.TrimSpace(nodePart), 10, 64)
	if err != nil {
		return OperatorRef{}, false
	}
	return OperatorRef{OperatorID: opID, NodeID: nodeID}, true
}
