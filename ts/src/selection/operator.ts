/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Operator descriptor + eligibility predicates for the shared selection
// policy. Mirror of proto/go/selection/operator.go — keep in lockstep; the
// golden vectors in proto/testdata/selection_vectors.json fail on both sides
// if the two drift.
//
// Field names are snake_case to match the Go JSON encoding (and the rest of
// proto/ts); numeric fields are `number` since real operator ids / token
// counts stay within JS's safe-integer range.

export interface ModelCapacity {
    // bounds input_tokens + max_output_tokens (0 = unbounded).
    context_window: number
    // bounds max_output_tokens on its own (0 = no separate cap).
    max_output_tokens: number
    // serves /v1/images/generations for this model (eligibility flag). The
    // authoritative per-image SIZING still reads the rate off the app-side
    // catalog, not this routing descriptor; image_rate_micro_usdc below exists
    // only to ORDER candidates.
    serves_image_gen: boolean
    // sibling flag for /v1/images/edits.
    serves_image_edit: boolean
    // In-loop image-tool eligibility flags (a chat model's
    // zs_image_generation / zs_image_edit on /v1/responses). DELIBERATELY
    // separate from serves_image_gen (the dedicated /v1/images/* signal): true
    // here means this chat model offers the in-loop tool. The image-tool partition
    // prefers operators that offer the matching tool when the request budgets it.
    offers_image_gen_tool: boolean
    offers_image_edit_tool: boolean
    // advertised USD/1M inference rates for this model. selectTargets price-sorts
    // candidates by input_usd_per_1m then output_usd_per_1m (lowest first); 0 is
    // the "undeclared" sentinel and sorts LAST. Comparison-only — never
    // accumulated — so Go↔TS golden-vector parity holds.
    input_usd_per_1m: number
    output_usd_per_1m: number
    // advertised reasoning.supported flag (details ModelReasoning.Supported).
    // DORMANT: it used to raise deriveMaxOutput's ceiling for a reasoning model.
    // That raise is now the ONLY ceiling (DEFAULT_MAX_OUTPUT_CEILING), so nothing
    // reads this field and no selection outcome depends on it. Kept rather than
    // removed because it is a serialized field of the descriptor the golden
    // vectors pin — deprecate, don't remove.
    reasoning_supported?: boolean
    // microUSDC price of one 1024²-standard image on the dedicated
    // /v1/images/generations and /v1/images/edits routes. selectTargets
    // price-sorts by these instead of the token rates on those endpoints, where
    // an image model's token rates are 0 and would rank every candidate
    // "undeclared".
    //
    // Unlike the token rates, 0 here means FREE, not "undeclared": the
    // serves_image_gen / serves_image_edit eligibility filter has already dropped
    // every non-serving operator before the sort runs, so a survivor's 0 is a
    // deliberately-free route and ranks CHEAPEST. No Infinity sentinel.
    //
    // Integer microUSDC, compared and never accumulated — parity with the Go
    // mirror is exact, unlike the float token rates above.
    image_rate_micro_usdc: number
    image_edit_rate_micro_usdc: number
}

export interface Operator {
    // stable on-chain operator id. Combined with node_id it is the routing
    // primary key; multiple descriptors can share an id (one per node).
    id: number
    // node id within id (per-operator node counter). Addresses the specific
    // endpoint for the relay-target header / affinity. 0 for legacy inputs.
    node_id: number
    // on-chain owner address (shared by all of an operator's nodes); relay
    // diversity keys on owner inequality, so sibling nodes never relay for
    // each other.
    owner_addr: string
    // node root URL; relay selection parses it for best-effort /16 diversity.
    base_url: string
    // advertised wire-protocol generation "<major>.<minor>".
    proto_version: string
    // most recent /v1/zs/details probe succeeded. Relay-eligibility signal
    // only — servesModel no longer consults it.
    reachable: boolean
    // current passing confidential-mode attestation verdict.
    tee_attested: boolean
    // on-chain `staging` flag (NodeRecord.staging): a node held out of
    // production target selection. selectTargets drops it unless
    // Constraints.allow_staging is set. Absent ⇒ false (Go omitempty), so any
    // descriptor predating the field routes as production. Target-only, like the
    // other node-attribute gates — never consulted for relay eligibility.
    staging?: boolean
    // the node signing account's spendable ALGO (amount − min-balance) in
    // microAlgos, read by each app from algod. That account pays the pooled fees
    // of every payer's open()/settle, so selectTargets drops a node below
    // MIN_SIGNER_SPENDABLE_MICROALGOS. Absent ⇒ never read ⇒ ELIGIBLE (Go nil
    // pointer, omitempty). 0 is a real, disqualifying reading. Target-only.
    signer_spendable_microalgos?: number
    // advertised model list (the node's /v1/zs/details set). Empty = "serves
    // nothing" — not a candidate for any model.
    models: string[]
    // per-model sizing envelope keyed by model id.
    model_capacities: Record<string, ModelCapacity>
    // advertised hayai built-in tool type names.
    builtin_tools: string[]
}

/**
 * Reports whether the operator's published model list includes model. An empty
 * list means "serves nothing" — a node advertising zero models is not a routing
 * candidate for any model (matching the node's authoritative /v1/zs/details
 * contract). Deliberately does NOT wildcard on reachability. Mirrors
 * proxy/internal/hayai/operator.go::ServesModel.
 */
export function servesModel(op: Operator, model: string): boolean {
    return (op.models ?? []).includes(model)
}

/** Routing floor for a node signing account's spendable ALGO: 5 ALGO in
 *  microAlgos. Mirror of selection.MinSignerSpendableMicroAlgos (sized as a
 *  staleness budget — see the Go doc). */
export const MIN_SIGNER_SPENDABLE_MICROALGOS = 5_000_000

/**
 * Reports whether a spendable-ALGO reading is known and below the routing floor.
 * `null`/`undefined` (never read) is NOT underfunded; `0` IS — so this must stay
 * an explicit nullish check, never a truthiness one. Mirror of
 * selection.SignerUnderfunded.
 */
export function signerSpendableBelowFloor(spendable: number | null | undefined): boolean {
    return spendable != null && spendable < MIN_SIGNER_SPENDABLE_MICROALGOS
}

/** Reports whether op's signing account is known to be below the routing floor.
 *  Mirror of selection.Operator.SignerUnderfunded. */
export function signerUnderfunded(op: Operator): boolean {
    return signerSpendableBelowFloor(op.signer_spendable_microalgos)
}

/** Reports whether the operator advertises every tool in needed. */
export function supportsAllBuiltinTools(op: Operator, needed: string[]): boolean {
    if (needed.length === 0) return true
    const have = new Set(op.builtin_tools ?? [])
    return needed.every((n) => have.has(n))
}

/**
 * Reports whether input+maxOutput is within window without overflow. A window
 * of 0 means "no cap declared" → true. Mirror of
 * proto/go/inject/sizing.go::FitsContextWindow (proto/ts has no inject module).
 */
export function fitsContextWindow(input: number, maxOutput: number, window: number): boolean {
    if (window === 0) return true
    return input + maxOutput <= window
}

/**
 * Reports whether op can serve a request for model under its declared
 * capacity. No declared capacity for model ⇒ unbounded ⇒ true. Mirror of
 * proxy/internal/hayai/sizing.go::Fits.
 */
export function fits(op: Operator, model: string, inputTokens: number, maxOutputTokens: number): boolean {
    const mc = op.model_capacities?.[model]
    if (mc === undefined) return true
    if (!fitsContextWindow(inputTokens, maxOutputTokens, mc.context_window)) return false
    if (mc.max_output_tokens > 0 && maxOutputTokens > mc.max_output_tokens) return false
    return true
}

// Constants for deriveMaxOutput's proportionate fallback. Mirror of
// proto/go/selection/operator.go (and the client's own config.ts constants).
/** Floors the proportionate branch so a degenerate context window still yields a
 *  positive reservation (the admission layer rejects max_output <= 0). */
export const MIN_DERIVED_MAX_OUTPUT = 256
/** Divisor for the proportionate branch: reserve context_window/N for output when
 *  a window is declared but a max_output_tokens is not. */
export const MAX_OUTPUT_CONTEXT_FRACTION_DENOM = 4
/** The base ceiling every caller passes unless it has a specific reason not to:
 *  the proxy's `fallback_max_output_tokens` default and the client's
 *  `DEFAULT_MAX_OUTPUT_TOKENS` are both this value.
 *
 *  It used to differ per caller (proxy 32000, client 4096), with a separate raise
 *  to 32768 for reasoning-capable models. That split was a routing bug, not a
 *  policy: because `fits()` is evaluated against the DERIVED number, proxy and
 *  client disagreed about which operators were eligible for the same request
 *  whenever context_window > 16384. There is now one ceiling, set at the value the
 *  reasoning branch already used. The larger reservation is LOCKED, not charged. */
export const DEFAULT_MAX_OUTPUT_CEILING = 32768

/**
 * deriveMaxOutput computes a per-operator worst-case completion reservation for a
 * request that did NOT specify max_output_tokens, from the operator's declared
 * capacity. Mirror of proto/go/selection/operator.go::DeriveMaxOutput (and
 * behaviorally the client's deriveMaxOutputTokens) — the single source of truth
 * the sizing filter (Constraints.max_output_unspecified) and the caller's reserve
 * leg both use. Three branches:
 *   - declaredMax > 0 → returned unchanged (the operator's advertised cap is
 *     authoritative);
 *   - else contextWindow > 0 → clamp(contextWindow/DENOM, MIN, baseCeiling);
 *   - else (neither declared) → baseCeiling, the flat fallback.
 *
 * baseCeiling stays a parameter because the sizing filter reads it off the wire
 * (Constraints.max_output_ceiling), but every caller passes
 * DEFAULT_MAX_OUTPUT_CEILING. There is deliberately no reasoning-capable special
 * case: the single ceiling IS the value the reasoning branch used, so a thinking
 * model still gets room for its chain-of-thought AND the answer.
 * Comparison/clamp only — Go↔TS golden-vector-parity-safe.
 */
export function deriveMaxOutput(contextWindow: number, declaredMax: number, baseCeiling: number): number {
    if (declaredMax > 0) return declaredMax
    if (contextWindow > 0) {
        const ceiling = baseCeiling
        let proportionate = Math.floor(contextWindow / MAX_OUTPUT_CONTEXT_FRACTION_DENOM)
        if (proportionate < MIN_DERIVED_MAX_OUTPUT) proportionate = MIN_DERIVED_MAX_OUTPUT
        if (proportionate > ceiling) proportionate = ceiling
        return proportionate
    }
    return baseCeiling
}

/**
 * A caller-supplied reference to an operator or a specific node — the unit of
 * the routing-preference allowlist / denylist / order lists (Constraints.only /
 * ignore / order). Mirrors OpenRouter base-slug vs full-slug matching: an
 * operator-only ref (match_all_nodes) matches every node of the operator; a
 * node ref matches just the (operator_id, node_id) pair. The wire form (in the
 * body `provider` object) is a string parsed by parseOperatorRef; this is the
 * internal/JSON shape the golden vectors pin. Mirror of
 * proto/go/selection/operator.go::OperatorRef.
 */
export interface OperatorRef {
    operator_id: number
    node_id: number
    // true for an operator-only ref ("<operatorId>"): matches every node
    // regardless of node_id. The explicit flag avoids the node-0 ambiguity
    // (node id 0 is a real, legacy node id, not "any node").
    match_all_nodes: boolean
}

/** Reports whether op is the operator/node this ref names. Mirror of OperatorRef.Matches. */
export function operatorRefMatches(ref: OperatorRef, op: Operator): boolean {
    if (ref.operator_id !== op.id) return false
    if (ref.match_all_nodes) return true
    return ref.node_id === op.node_id
}

/**
 * Parses a caller ref string into an OperatorRef:
 *   "<operatorId>"           → match_all_nodes (any node of the operator)
 *   "<operatorId>:<nodeId>"  → that exact node
 * Both components are unsigned decimal integers; surrounding whitespace is
 * trimmed. Returns null on any malformed input (empty, non-numeric, extra
 * colons, out of safe-integer range) — callers skip a bad ref rather than fail.
 * Mirror of proto/go/selection/operator.go::ParseOperatorRef (Go splits on the
 * FIRST ':' too, so "1:2:3" fails on the non-numeric "2:3" node part).
 */
export function parseOperatorRef(s: string): OperatorRef | null {
    const trimmed = s.trim()
    if (trimmed === '') return null
    const colon = trimmed.indexOf(':')
    const opPart = colon === -1 ? trimmed : trimmed.slice(0, colon)
    const nodePart = colon === -1 ? null : trimmed.slice(colon + 1)
    const opID = parseUintExact(opPart)
    if (opID === null) return null
    if (nodePart === null) return { operator_id: opID, node_id: 0, match_all_nodes: true }
    const nodeID = parseUintExact(nodePart)
    if (nodeID === null) return null
    return { operator_id: opID, node_id: nodeID, match_all_nodes: false }
}

/** Parses a trimmed unsigned decimal integer, or null if not all-digits / out of safe range. */
function parseUintExact(s: string): number | null {
    const t = s.trim()
    if (!/^\d+$/.test(t)) return null
    const n = Number(t)
    return Number.isSafeInteger(n) ? n : null
}
