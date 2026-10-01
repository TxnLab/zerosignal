/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"time"

	"github.com/TxnLab/zerosignal/go/tools"
)

// DetailsContentType is the Content-Type for the GET /v1/zs/details
// response body. Plaintext JSON — details is a public capability
// advertisement, not a payment-gated request.
const DetailsContentType = "application/json"

// OperatorDetails is the response shape of GET /v1/zs/details. It tells a
// discoverer everything they need to decide whether to reserve against this
// operator: identity, the per-model capacity envelope, the advertised USD rate
// card, oracle health, and the set of built-in tools the node serves.
//
// SPEC.md § 3c "Response" is authoritative for every field's wire contract and
// documents each one in full. The notes below are the short form — the units,
// the nil-vs-zero rule, and the traps — for someone editing this struct. When
// the two disagree, SPEC wins and this file is the bug.
//
// Authority: the per-model context_window, max_output_tokens, and USD rates
// here are *advertised* values (USD per 1M tokens) — the operator is not bound
// by them for any specific request. The authoritative per-request pricing is
// the microUSDC/1M rates pinned into the signed ticket at reserve time (§ 3a
// "Rate derivation"); the authoritative per-request capacity gate is the node's
// reserve check. A mismatch between this advertisement and the eventual ticket
// is not a slashable offense — it just means the operator changed config
// between the discovery probe and reserve. Clients that need a guaranteed price
// must hit /v1/zs/reserve. Individual fields below are called out only where
// they DEPART from this default.
type OperatorDetails struct {
	OperatorID uint64 `json:"operator_id,omitempty"`
	// NodeID identifies this endpoint within OperatorID. One node process
	// advertises exactly one (operator_id, node_id); SigningAddr is this node's.
	NodeID      uint64 `json:"node_id,omitempty"`
	OwnerAddr   string `json:"owner_addr,omitempty"`
	SigningAddr string `json:"signing_addr,omitempty"`

	// The signed short-lived age recipient (forward secrecy by key-erasure).
	// Mirrors ticket.EphemeralAdvertisement's JSON fields verbatim so the block
	// can be reconstructed straight from /v1/zs/details, and EphemeralIssuedAt
	// is required to recompute the v2 signed canonical bytes.
	//
	// There is NO long-lived anchor recipient and no fallback: absent fields
	// mean "no seal target", and a sealing party fails closed onto another
	// operator rather than downgrading.
	EphemeralAgePubkey string `json:"ephemeral_age_pubkey,omitempty"`
	EphemeralExpiry    int64  `json:"ephemeral_expiry,omitempty"`
	EphemeralIssuedAt  int64  `json:"ephemeral_issued_at,omitempty"`
	EphemeralSig       string `json:"ephemeral_sig,omitempty"`

	Models []OperatorDetailsModel `json:"models"`

	// Oracle health and the last ALGO/USD quote. The quote prices ALGO network
	// fees for display only — it is NOT in the inference-pricing path, which
	// converts USD → microUSDC directly. Price/At populate whenever the cache has
	// ever been warmed (even if stale); OracleHealthy is true only when the quote
	// is fresh. An unhealthy oracle does not block reserve.
	OracleSource  string    `json:"oracle_source,omitempty"`
	OracleHealthy bool      `json:"oracle_healthy"`
	AlgoUSDPrice  float64   `json:"algo_usd_price,omitempty"`
	AlgoUSDAt     time.Time `json:"algo_usd_at,omitempty"`

	// MinChargeOutputTokens is the reference output-token count for the token
	// component of the per-request minimum charge. Default 1000; 0 disables it.
	MinChargeOutputTokens uint64 `json:"min_charge_output_tokens,omitempty"`

	// MinChargeAlgoTxns is the µALGO-recovery component, counted in Algorand
	// minTxnFee units (1,000 µALGO each). 0 disables it — the default;
	// recommended enabled value is 7.
	MinChargeAlgoTxns uint64 `json:"min_charge_algo_txns,omitempty"`

	// MinChargeMicroUSDC is the current USD value of the µALGO component at this
	// operator's most-recent oracle reading. ONE component of the floor, not the
	// whole floor — the token component is per-model. 0 when the component is
	// disabled or the oracle is stale.
	MinChargeMicroUSDC uint64 `json:"min_charge_microusdc,omitempty"`

	// BuiltinTools lists this node's built-in tools as TYPE-ONLY entries
	// (`{"type":"zs_*"}`). name/description/parameters are node-internal and
	// deliberately not advertised — identical across nodes on the same proto
	// version, so consumers resolve them locally by type. This endpoint is
	// polled, which is why the list stays bare.
	BuiltinTools []tools.BuiltinToolAdvert `json:"builtin_tools,omitempty"`

	// MaxToolIterations caps chat→tool→chat loops for tool-bearing requests.
	// Callers size max_price from it so escrow doesn't underfund a tool-heavy run.
	MaxToolIterations int `json:"max_tool_iterations,omitempty"`

	// ToolHeadroomPerIteration is the per-iteration input-token headroom the
	// operator RECOMMENDS a caller add to a tool-carrying reserve. Absent/0 on
	// pre-field nodes — callers fall back to a built-in default.
	ToolHeadroomPerIteration uint64 `json:"tool_headroom_per_iteration,omitempty"`

	// Version is the node's build id, "<release>+<commit>[-dirty] [<commit-time>]"
	// — e.g. "0.21.0+5f344de [2026-09-03T06:05:20Z]". <commit> is an abbreviated
	// git SHA; <release> is the published version, or "dev" when the build could
	// not determine one.
	//
	// Two CLEAN tails that match were built from the same source, whichever way
	// each was built — that is what the shape is for. A "-dirty" tail is not:
	// it names the commit its build departed from and carries nothing about the
	// departure, so two of them can match over different source.
	//
	// Informational: clients MUST NOT parse it to drive routing or settlement.
	// Reading two tails side by side is the intended use; nothing may be gated
	// on the result. It is also unsigned and uncorroborated — a node's claim
	// about itself. Produced by node/internal/build.DetailsVersion.
	Version string `json:"version,omitempty"`

	// ProtoVersion is the wire-protocol generation, "<major>.<minor>". Unlike
	// Version, this IS parsed: a peer filters out operators whose advertised
	// major differs from its own wire.ProtoVersion. Absent decodes as "1.0", so
	// the pre-field fleet filters out. See wire/version.go.
	ProtoVersion string `json:"proto_version,omitempty"`

	// ConfigHash is a "sha256:<hex>" fingerprint of the operator's POLICY config
	// — the deployment-independent subset governing what the node serves and at
	// what price. It excludes identity, infra, secrets, and operational tuning,
	// so two nodes running the same policy hash identically. Informational:
	// clients MUST NOT drive routing or settlement from it.
	ConfigHash string `json:"config_hash,omitempty"`

	// TEE advertises confidential-computing mode. nil for non-TEE nodes, keeping
	// the wire shape compatible with pre-TEE consumers. See proto/TEE.md for the
	// threat model and SPEC.md § 3e for the wire rationale.
	TEE *TEEAdvertisement `json:"tee,omitempty"`
}

// OperatorDetailsModel is one model entry in OperatorDetails.Models. USD rates
// are per 1,000,000 tokens; see the OperatorDetails godoc on why they are
// advisory, and SPEC.md § 3c for each field's full contract.
//
// ContextWindow and MaxOutputTokens are the operator's defense-in-depth
// ceilings — the node's reserve handler enforces input_tokens +
// max_output_tokens ≤ context_window via FitsContextWindow.
type OperatorDetailsModel struct {
	// InputRateUSDPer1M / OutputRateUSDPer1M are emitted even when zero — a 0 is
	// a real, advertisable rate (that side is free), so it must not be elided.
	// Nodes pre-dating this may still omit a zero rate; decode absent as 0.
	ID                 string  `json:"id"`
	InputRateUSDPer1M  float64 `json:"input_rate_usd_per_1m"`
	OutputRateUSDPer1M float64 `json:"output_rate_usd_per_1m"`

	// CacheReadRateUSDPer1M is the discounted rate for the cache-read subset of
	// input tokens.
	//
	// DELIBERATELY DIFFERENT nil-vs-zero semantics from the always-present rates
	// above: advertised ONLY when cached reads are actually discounted (resolved
	// rate strictly below the input rate). Absent decodes as "not discounted",
	// NOT as 0 — a non-nil 0 means FREE cached reads, the maximum discount.
	CacheReadRateUSDPer1M *float64 `json:"cache_read_rate_usd_per_1m,omitempty"`

	// The long-context (high) pricing tier — the context-size cliff xAI prices
	// with. All four travel together:
	//
	//   - LongContextThresholdTokens == 0 is the PRESENCE SENTINEL: no tier, flat
	//     pricing. Consumers key tier presence off it, never off the rates.
	//   - The input/output rates are present (even at 0) whenever a threshold is
	//     advertised, and are >= their base counterparts (a surcharge; the node
	//     validator rejects a tier undercutting the base).
	//   - LongContextCacheReadRateUSDPer1M mirrors CacheReadRateUSDPer1M's
	//     nil-vs-zero rule for the high tier.
	LongContextThresholdTokens       uint64   `json:"long_context_threshold_tokens,omitempty"`
	LongContextInputRateUSDPer1M     *float64 `json:"long_context_input_rate_usd_per_1m,omitempty"`
	LongContextOutputRateUSDPer1M    *float64 `json:"long_context_output_rate_usd_per_1m,omitempty"`
	LongContextCacheReadRateUSDPer1M *float64 `json:"long_context_cache_read_rate_usd_per_1m,omitempty"`

	ContextWindow    uint64   `json:"context_window,omitempty"`
	MaxOutputTokens  uint64   `json:"max_output_tokens,omitempty"`
	InputModalities  []string `json:"input_modalities,omitempty"`
	OutputModalities []string `json:"output_modalities,omitempty"`

	// Reasoning / ToolUse: nil means "unknown / unadvertised", distinct from an
	// explicit {Supported:false} or false ("does not"). Auto-discovered where the
	// runner exposes it, else operator-declared; config wins over discovery.
	Reasoning *ModelReasoning `json:"reasoning,omitempty"`
	ToolUse   *bool           `json:"tool_use,omitempty"`

	// Tags are free-form classification labels ("nsfw", "code", …) — an open
	// string list, not an enum. UNION of the model author's HuggingFace
	// cardData.tags and any operator-config tags. Never participates in routing.
	Tags []string `json:"tags,omitempty"`

	// Coordinates is the model-taxonomy descriptor (what a model *is*). nil =
	// unadvertised.
	//
	// Hot vs deep: on the bare list this carries only the FREE, in-memory signal
	// (config-declared plus runner-reported). The egress-bearing
	// HuggingFace-discovered coordinates ride `?expand=coordinates&model={id}`,
	// lazily, so the often-polled list never pays for them.
	Coordinates *ModelCoordinates `json:"coordinates,omitempty"`

	// Source is the canonical source pointer ("hf:org/model[@revision]") and the
	// cross-operator IDENTITY key: two operators declaring the same Source
	// resolve to one model in the picker however each spelled the wire id. Rides
	// the hot list — it is a free operator-declared string.
	//
	// Advisory + operator-ATTESTED: it does not prove the served bytes match the
	// referenced artifact. The wire `model` string remains the
	// routing/billing/signing key.
	Source string `json:"source,omitempty"`

	// CanonicalID covers the case Source cannot: a CLOSED-weights frontier model
	// with no public repo that still needs one name across operators spelling the
	// wire id differently. Filled from the frontier whitelist, e.g. "xai/grok-4.5".
	//
	// Surfaced ONLY when Source is empty — for a sourced model the canonical
	// identity IS the Source repo. Consumers key on Source first and fall back to
	// CanonicalID, never both.
	CanonicalID string `json:"canonical_id,omitempty"`

	// Retention is this model's upstream data-retention tier — whether the
	// prompt is retained ANYWHERE once it leaves the payer, and on what
	// evidence. One of the Retention* consts (retention.go), strongest evidence
	// first: tee_attested, upstream_confirmed, upstream_enforced, no_upstream,
	// operator_declared.
	//
	// It rides the BARE list rather than `?expand=`: it is one short string and
	// a payer needs it while choosing a model, not after.
	//
	// EMPTY MEANS UNKNOWN, NEVER "RETAINS" — a node predating the field, or one
	// whose upstream offers no retention guarantee the node can pin or check.
	// That is the honest state of most hosted passthroughs, so a consumer that
	// renders empty as a warning is making a claim the wire did not.
	// An UNRECOGNIZED value is also unknown; see IsKnownRetention.
	//
	// TRUST CEILING, because the ordering is by evidence and reads stronger than
	// it is on the axis most people mean. Every tier below tee_attested is a
	// statement about the DESTINATION, not about this node: upstream_confirmed
	// says xAI will not retain the prompt, and says nothing whatever about
	// whether the node logged it on the way past. Node-side non-retention is an
	// unconditional operator obligation (SPEC.md "Prompt and response
	// non-retention") that only a TEE turns into evidence — which is why
	// no_upstream, the tier where the prompt never leaves the box at all, sorts
	// BELOW two tiers that ship it to a third party. Pair this field with TEE,
	// never read it alone.
	//
	// AND THE DESTINATION IS THE ENDPOINT, not necessarily every party in the
	// path. upstream_enforced in particular is a constraint the node sends and
	// never sees confirmed, scoped to whichever endpoint answers; where the
	// upstream is a broker, what sits in front of that endpoint reads the prompt
	// under settings the constraint does not set. Its own godoc carries both
	// limits. So the ceiling is two-sided — the node on one end, an
	// intermediary on the other — and this field describes neither.
	//
	// EVERY TIER DESCRIBES THE INFERENCE ROUTE — the path the node takes to
	// produce an answer. "The prompt never leaves the box" above is that
	// route, not a promise that a caller cannot cause an egress of its own:
	// built-in tools are caller-initiated and a node at ANY tier may serve
	// them (SPEC § 3d), so this field and a BuiltinTools list naming
	// zs_web_search are not in conflict and a consumer must not demote on the
	// pair. The condition is wider than the zs_ types — a remote mcp entry and
	// a provider-native web_search are caller-supplied egress too. Everything
	// the OPERATOR chooses is in scope, image route included; see
	// retentionStaysLocal and TEEPosture.
	//
	// GATES NOTHING, and must not. It is node-authored with no peer
	// corroboration — unlike WeightsDigest, where a cross-operator majority
	// supplies the evidence — so letting it raise an operator's placement would
	// reward the boldest claim rather than the truest one, and demoting on its
	// absence would penalize every honest passthrough. Display and payer choice
	// only. A payer who wants it enforced asks for it explicitly, the way
	// X-Zs-Require-TEE works — which picks the NODE and does nothing about the
	// caller's own tools[].
	Retention string `json:"retention,omitempty"`

	// WeightsDigest / WeightsUnverifiable are the COMPACT weights-integrity
	// signal and ride the bare list (hot): detecting a cross-operator mismatch
	// needs every operator's digest at once, so they cannot be a lazy per-node
	// fetch. Both absent = pre-feature node ("unknown"), distinct from an
	// explicit WeightsUnverifiable. A mismatch is "weights differ" (legitimate
	// for a quant/repack), not fraud, and never gates admission or settlement.
	//
	// WeightsDigest is the ONE field in this block with a routing consequence,
	// and only a payer-side, soft one: where two or more distinct operator
	// OWNERS advertise the same digest for a model, the reference proxy and
	// client demote a candidate advertising a different digest to the tail of
	// that request's candidate list. Never an exclusion, never a penalty for
	// advertising no digest (the honest state of every hosted passthrough), and
	// never a promotion off a self-reported field — see SPEC.md § 3c "Routing
	// consequence" for the rules a consumer must follow.
	//
	// Two of those rules are about where the demotion silently fails to apply
	// rather than misapplies, and both bit the reference consumers: a routing
	// PREFERENCE (KV-cache affinity, last-used operator) is not a continuation
	// pin and must not be exempted, and any fallback path that represents a
	// model by ONE pre-chosen operator has to apply the ordering when choosing
	// it — a demotion pass cannot reorder a list of one.
	WeightsDigest       string `json:"weights_digest,omitempty"`
	WeightsUnverifiable bool   `json:"weights_unverifiable,omitempty"`

	// WeightsUnverifiableReason and WeightsDigestTrust are the VERBOSE/rare
	// counterparts and ride ONLY `?expand=digest&model={id}` — never the bare
	// list, so both are empty there even when WeightsUnverifiable is set.
	// Reason is the enum behind an unverifiable model; Trust is the provenance
	// tier behind a verifiable digest (node_supervised / runtime_attested /
	// operator_declared / operator_pinned). See SPEC.md § 3c "Deep model
	// details" for the tiers and their trust ceiling — no tier is
	// cryptographically unforgeable.
	WeightsUnverifiableReason string `json:"weights_unverifiable_reason,omitempty"`
	WeightsDigestTrust        string `json:"weights_digest_trust,omitempty"`

	// WeightsRegistryMatch is the third deep field, and it is ORTHOGONAL to
	// WeightsDigestTrust: Trust answers "how was this digest produced", this
	// answers "does a third party corroborate it". A node holding a digest looks
	// the model's Source repo up on the public registry and reports whether that
	// exact content digest is among the artifacts the repo publishes:
	//
	//	matched   — the digest IS a published artifact of the declared repo.
	//	mismatch  — the repo was read and the digest is NOT among its artifacts.
	//	unchecked — no lookup happened or it could not conclude (no Source, HF
	//	            discovery disabled, gated/private repo, network failure).
	//
	// Empty means the node predates the field OR has no digest at all — read it
	// only alongside WeightsDigest, never on its own.
	//
	// The match is CONTENT-ADDRESSED and must stay that way: filenames diverge
	// legitimately and often (a Kronk install serves HF's "Qwen3.6-35B-A3B-Q8_0.gguf"
	// as "mtp-Qwen3.6-35B-A3B-Q8_0.gguf", and its "mmproj-F16.gguf" under the
	// weights file's own name), so a filename-keyed compare reports mismatch on
	// honest nodes. Only the digest is compared; the artifact's published name is
	// incidental.
	//
	// WeightsDeclarationConflict reports that the operator DECLARED a weights
	// digest (a `weights.digest` pin, or a `weights.files` set the node hashed)
	// and the serving runtime independently reported loading a DIFFERENT
	// artifact. When it is set, WeightsDigest carries the runtime's value, not
	// the operator's: a declaration is an assertion, while the runtime's report
	// is evidence about the artifact actually loaded, and advertising the
	// assertion over the evidence would make the node a party to the
	// misstatement. WeightsDigestTrust is `runtime_attested` accordingly.
	//
	// This is the sharpest signal in the weights block, and the reason is
	// economic rather than cryptographic. Copying a well-known model's real
	// digest off its public registry page is the cheapest possible way to claim
	// weights you do not serve — it needs no code, just a config line, and it
	// defeats a registry cross-check by construction, since claim and
	// corroboration then come from the same page. It is exactly that attack this
	// field catches, because the liar's own runtime disagrees with them.
	//
	// It is still NOT proof of dishonesty, and consumers must not present it as
	// such: an operator who pins the digest of a model's ORIGINAL repo while
	// serving a legitimate quantization of it conflicts honestly, as does one
	// whose declared file set is a sibling of the artifact actually loaded.
	// Treat it as "this operator's own runtime contradicts them, ask why".
	WeightsDeclarationConflict bool `json:"weights_declaration_conflict,omitempty"`

	// Trust ceiling, because "matched" reads stronger than it is: it proves the
	// bytes behind the digest are the declared repo's bytes ONLY to the extent
	// the digest itself is trustworthy, which is what Trust qualifies. Pair
	// them — `node_supervised` + `matched` is the node hashing its own served
	// file and an independent registry agreeing; `operator_pinned` + `matched`
	// is an operator pasting a digest they could equally have copied off that
	// same registry page, and corroborates nothing. A `mismatch` is a flag for
	// a human, not a fraud finding: a requantized or repacked local copy
	// legitimately mismatches, as does a repo that re-uploaded the file after
	// the operator pulled it.
	//
	// This field itself gates nothing and MUST NOT: it is node-authored, so
	// letting a `matched` claim raise an operator's placement would reward the
	// boldest claim rather than the truest one. The routing consequence in this
	// block hangs off WeightsDigest alone, where peers supply the evidence.
	WeightsRegistryMatch string `json:"weights_registry_match,omitempty"`

	// WeightsRegistryPath is the repo-relative path of the artifact that
	// produced a `matched` verdict — empty for every other verdict, and empty on
	// a node that predates the field.
	//
	// It exists so a consumer can DEEP-LINK to that artifact's own page on the
	// registry, which prints the same content digest being claimed. Everything
	// else in this block is the operator's node reporting on itself; this is the
	// one field that hands the reader somewhere to go check, which is worth more
	// than any additional self-assertion could be.
	//
	// It is a DISPLAY pointer, not an identity, and consumers must not match on
	// it: the artifact's local filename legitimately differs from the published
	// one (see the content-addressing note on WeightsRegistryMatch), so this
	// names the file in the REPO, never the file on the operator's disk.
	WeightsRegistryPath string `json:"weights_registry_path,omitempty"`

	// WeightsMismatch is PROXY-AGGREGATE-ONLY: set on the reference proxy's
	// cross-operator aggregate when >=2 distinct non-empty digests appear for
	// this id. A single NODE never sets it (no cross-operator view). On that
	// aggregate WeightsDigest carries the CONSENSUS digest — the single agreed
	// value, empty on mismatch — so one struct decodes both shapes.
	WeightsMismatch bool `json:"weights_mismatch,omitempty"`

	// In-loop image tools. Rate is the worst-case CAP (base × Factor(max_size,
	// max_quality)) and is the reserve-sizing figure; Base is the
	// REPRESENTATIVE price when the model names no size/quality. Carrying both
	// lets a client show a price, or a range up to the cap, instead of anchoring
	// on a resolution the model may never produce; an operator pinning one tier
	// reports base == cap. 0 means the chat model does not offer that tool.
	ImageToolRateMicroUSDC     uint64 `json:"image_tool_rate_micro_usdc,omitempty"`
	ImageEditToolRateMicroUSDC uint64 `json:"image_edit_tool_rate_micro_usdc,omitempty"`
	ImageToolBaseMicroUSDC     uint64 `json:"image_tool_base_micro_usdc,omitempty"`
	ImageEditToolBaseMicroUSDC uint64 `json:"image_edit_tool_base_micro_usdc,omitempty"`

	// Dedicated /v1/images/{generations,edits} route pricing. Rate is the
	// per-1024²-standard BASE (reserve sizing and cross-operator price ordering
	// key off it); Default is what a caller sending no size/quality actually
	// pays; Cap is base × Factor(max_size, max_quality).
	//
	// Default/Cap are display only and each omits for its own reason: Default
	// when the operator configures no knobs (the base already IS representative),
	// Cap when the operator sets NO ceiling — an uncapped dedicated route scales
	// without bound because the CALLER picks the size, so there is no honest cap
	// to quote. A 0 Rate on a served route means FREE, not "no rate" — see
	// ServesImageGen.
	ImageRateMicroUSDC        uint64 `json:"image_rate_micro_usdc,omitempty"`
	ImageEditRateMicroUSDC    uint64 `json:"image_edit_rate_micro_usdc,omitempty"`
	ImageDefaultMicroUSDC     uint64 `json:"image_default_micro_usdc,omitempty"`
	ImageEditDefaultMicroUSDC uint64 `json:"image_edit_default_micro_usdc,omitempty"`
	ImageCapMicroUSDC         uint64 `json:"image_cap_micro_usdc,omitempty"`
	ImageEditCapMicroUSDC     uint64 `json:"image_edit_cap_micro_usdc,omitempty"`

	// ServesImageGen / ServesImageEdit are the authoritative eligibility signal
	// for the dedicated routes, INDEPENDENT of price. They exist because a
	// deliberately-free route advertises rate 0, which omitempty drops — making
	// it indistinguishable from a non-image model. Routing keys eligibility off
	// these and sizing off the rate.
	ServesImageGen  bool `json:"serves_image_gen,omitempty"`
	ServesImageEdit bool `json:"serves_image_edit,omitempty"`

	// Per-call tool pricing (SPEC.md "Per-call tool pricing"). Advisory even by
	// the standards of this struct: these rates are NOT signed into the ticket —
	// tool fees ride the receipt's extra microUSDC and clamp to max_price, so the
	// reserve only has to be large enough.

	// ToolCallRatesMicroUSDC is the per-call price of each PRICED tool, keyed by
	// canonical tool name (NormalizeToolName) — both vendor server-side tools and
	// node built-ins the operator opted into pricing. Absent ⇒ no tool is priced
	// by name (zs_ tools are then free; vendor tools are stripped unless the
	// catch-all is set).
	ToolCallRatesMicroUSDC map[string]uint64 `json:"tool_call_rates_micro_usdc,omitempty"`

	// VendorToolCatchAllMicroUSDC is the blanket price for any vendor tool with
	// no explicit entry, so a harness can use a tool the operator didn't
	// enumerate and be billed rather than stripped. It NEVER applies to node zs_
	// tools — setting it cannot accidentally start charging for the node's own
	// search. 0 ⇒ an unnamed vendor tool is stripped.
	VendorToolCatchAllMicroUSDC uint64 `json:"vendor_tool_catchall_micro_usdc,omitempty"`

	// VendorToolCallCap is the per-request cap on vendor tool calls, injected as
	// the upstream's cap knob. Callers size the vendor fee reserve as
	// cap × max(rate). 0 ⇒ the model offers no priced vendor tools.
	VendorToolCallCap uint64 `json:"vendor_tool_call_cap,omitempty"`

	// VendorToolTokensPerCall estimates the input-token inflation each vendor
	// call adds (search results re-prefilled into context). Callers size extra
	// input headroom as VendorToolCallCap × this × input_rate.
	VendorToolTokensPerCall uint64 `json:"vendor_tool_tokens_per_call,omitempty"`
}

// ModelReasoning is the reasoning-capability descriptor on
// OperatorDetailsModel.Reasoning. Non-nil means the capability is known;
// Supported then says whether the model reasons at all. AllowedEfforts is an
// open string list (not an enum) so new tiers need no wire change.
// DefaultEffort, when set, is one of AllowedEfforts; the proxy drops it from
// the cross-operator aggregate (a single default has no clean meaning across
// operators) but keeps it on any per-operator view.
type ModelReasoning struct {
	Supported      bool     `json:"supported"`
	AllowedEfforts []string `json:"allowed_efforts,omitempty"`
	DefaultEffort  string   `json:"default_effort,omitempty"`
}

// ModelCoordinates is the taxonomy descriptor on
// OperatorDetailsModel.Coordinates — what a model *is*, for grouping, display,
// search, and family fallback. Advisory only; nil means unadvertised. The node
// auto-fills what the runner exposes and — on `?expand=coordinates` — what
// HuggingFace reports for the model's Source; operators declare the rest via
// config, and config wins over discovery.
type ModelCoordinates struct {
	// Family is the canonical lineage/grouping key — the base model this id
	// belongs to, org-prefixed and quant/variant-stripped, e.g.
	// "google/gemma-4-26b". Two ids sharing a Family render as siblings; it is
	// NOT a claim that they are interchangeable (that is WeightsDigest's job).
	Family string `json:"family,omitempty"`
	// Parameters is the total parameter count. On the deep path it is OBSERVED
	// from HuggingFace's safetensors.total (falling back to gguf.total on a
	// GGUF-only repo) — not merely name-parsed.
	Parameters uint64 `json:"parameters,omitempty"`
	// ActiveParameters is the per-token active count for MoE models — the "a4b"
	// in gemma-4-26b-a4b. Equal to Parameters (or omitted) for dense models.
	ActiveParameters uint64 `json:"active_parameters,omitempty"`
	// Quantization is the weight format, runner-reported where available
	// ("Q4_K_M", "bf16", "fp8", "awq", …). "" = unknown.
	Quantization string `json:"quantization,omitempty"`
	// Variant is the finetune/lineage label distinguishing this id from the base
	// within its Family ("instruct", "abliterated", a finetuner's name).
	// Distinct from Tags: a model can be Variant "uncensored" AND tagged "nsfw".
	Variant string `json:"variant,omitempty"`
}
