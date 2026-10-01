/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Operator/relay selection policy. Mirror of proto/go/selection/select.go —
// keep in lockstep; pinned by proto/testdata/selection_vectors.json.

import { protoVersionCompatible, usesTightInputBound } from '../wire/version.js'
import {
    type Operator,
    type OperatorRef,
    deriveMaxOutput,
    fits,
    operatorRefMatches,
    servesModel,
    signerUnderfunded,
    supportsAllBuiltinTools,
} from './operator.js'

// Endpoint identifiers, equal to the proxy's request paths. Only the image
// endpoints alter selection.
export const ENDPOINT_CHAT_COMPLETIONS = '/v1/chat/completions' as const
export const ENDPOINT_RESPONSES = '/v1/responses' as const
export const ENDPOINT_IMAGES = '/v1/images/generations' as const
export const ENDPOINT_IMAGE_EDITS = '/v1/images/edits' as const

// Affinity policy values, equal to the proxy's hayai.AffinityPolicy strings.
export const AFFINITY_PREFER = 'prefer' as const
export const AFFINITY_STRICT = 'strict' as const
export const AFFINITY_NONE = 'none' as const

export interface Constraints {
    model: string
    input_tokens: number
    /**
     * The same request measured with tokenize bound version 2, used for the fit
     * check against operators advertising proto_version >= 9.2. Absent/0 means
     * "no v2 measurement supplied" and every operator is filtered on
     * input_tokens — the pre-9.2 behaviour.
     *
     * The two bounds disagree most on exactly the requests where the fit check
     * bites: v1 prices every image at a flat 2048x2048 fallback (2805 tokens)
     * while v2 reads the real dimensions, so a 512x512 paste is 2805 under v1
     * and 255 under v2. Filtering an image request on the v1 number excludes
     * small-window operators that would comfortably serve it, while the reserve
     * leg sizes the SAME request with v2 — filter and escrow would disagree
     * about what fits.
     */
    input_tokens_v2?: number
    max_output_tokens: number
    // switches the sizing filter from the flat max_output_tokens to a
    // per-operator derived ceiling (deriveMaxOutput(mc.context_window,
    // mc.max_output_tokens, max_output_ceiling)). The
    // caller sets it when the request body omitted max_tokens /
    // max_completion_tokens / max_output_tokens and no flat default applies, so a
    // small-window operator isn't excluded on a guessed ceiling it never has to
    // honor; the reserve leg re-derives the same value. max_output_tokens is
    // ignored while set. Optional/omitempty: absent reads as false (flat).
    max_output_unspecified?: boolean
    // base ceiling deriveMaxOutput clamps to (the proxy's
    // fallback_max_output_tokens; the flat fallback when an operator declares
    // neither a window nor a max_output). Ignored unless max_output_unspecified.
    max_output_ceiling?: number
    // one of the ENDPOINT_* values.
    endpoint: string
    // drop operators without a current passing attestation.
    require_tee: boolean
    // include nodes whose on-chain `staging` flag is set (Operator.staging) in
    // target selection. Default/absent ⇒ false: staging nodes are dropped, so
    // the standard routing path never targets a node still being tested. Set
    // from the Model Routing "allow staging" toggle (client) / hayai.allow_staging
    // (proxy). Optional + omitempty: absent reads as false (Go omits the zero).
    allow_staging?: boolean
    // zs_* tool types the request asks for; operators advertising all of
    // them are partitioned ahead of the rest. null/undefined ⇒ none.
    requested_tools: string[] | null
    // per-request hayai image-tool budgets (max_n). When > 0, operators whose
    // chosen model publishes the matching in-loop image-tool factor are
    // partitioned ahead of those that don't — a ranking preference, not a hard
    // filter (a model served only by toolless operators stays selectable). See
    // selectTargets step 7b.
    image_tool_gen_budget: number
    image_tool_edit_budget: number
    // one of AFFINITY_*.
    affinity_policy: string

    // --- Caller routing preferences (OpenRouter-style provider selection) ---
    // From the request body's `provider` object via extractRoutingPreferences.
    // Optional/undefined ⇒ "no preference"; Go omits the zero values under
    // omitempty (except allow_fallbacks, whose default is true). Mirror of the
    // same-named selection.Constraints fields.

    // allowlist: when non-empty, only operators/nodes matching a ref survive
    // (hard filter, independent of allow_fallbacks).
    only?: OperatorRef[]
    // denylist: operators/nodes matching any ref are dropped (deny-wins).
    ignore?: OperatorRef[]
    // explicit preference order: matched candidates float to the front (after
    // any continuation-affinity pin); the rest follow unless allow_fallbacks is
    // false, which drops them (pin to exactly the named set).
    order?: OperatorRef[]
    // governs `order` strictness only (default true). Never widened to loosen
    // only/ignore. Always present in the vectors (Go drops omitempty here).
    allow_fallbacks?: boolean
    // caller price ceilings (USD/1M); 0 / undefined ⇒ no ceiling on that axis.
    max_input_usd_per_1m?: number
    max_output_usd_per_1m?: number
    // promote the requested-tool partition to a hard filter.
    require_tools?: boolean
}

export interface SizingMiss {
    operator_id: number
    context_window: number
    max_output_tokens: number
    // the max_output the fit check actually charged this operator: the flat
    // request-level max_output_tokens, or — in derive mode (max_output_unspecified)
    // — the per-operator value from deriveMaxOutput. It is the number `fits` was
    // called with, so a caller rendering a "why didn't this fit" message reports
    // the true gap instead of the flat display ceiling the caller never sent.
    effective_max_output: number
}

export interface Diagnostics {
    registry_count: number
    sizing_misses?: SizingMiss[]
    version_blocked: boolean
    tee_blocked: boolean
    // every otherwise-eligible node serving the model is a staging node and
    // allow_staging was not set (served, but only by held-out nodes).
    staging_blocked: boolean
    // every otherwise-eligible node serving the model has a signing account known
    // to be below MIN_SIGNER_SPENDABLE_MICROALGOS; also set when strict affinity
    // pins to such a node. Pool availability (clears on top-up), not a conflict.
    signer_underfunded_blocked: boolean
    image_endpoint_unsupported: boolean
    affinity_blocked: boolean
    // a caller routing preference matched nobody serving the request: an only
    // allowlist that excluded everyone, or order+allow_fallbacks:false whose
    // refs matched no eligible candidate.
    provider_pin_blocked: boolean
    // a max_price ceiling excluded every otherwise-eligible operator.
    price_blocked: boolean
    // require_tools was set and no operator advertises every requested tool.
    tool_unsupported: boolean
}

export interface TargetResult {
    operators: Operator[]
    diagnostics: Diagnostics
}

/**
 * selectTargets reproduces the proxy's candidate-selection policy as a pure
 * function, in the same order as proxy pickCandidates: model eligibility →
 * caller only/ignore filter → sizing → image-factor → wire-version → TEE →
 * staging exclusion → signer funding → caller max_price filter → price sort → built-in-tool partition (or hard
 * filter when require_tools) → in-loop image-tool partition → caller order
 * reorder → affinity reorder. The price sort is the base order; the stable
 * partitions preserve price order within each bucket. Net precedence: affinity
 * > caller-order > image-tool > built-in-tool > price > id. The caller filters
 * (only/ignore/max_price/require_tools) prune before ranking, so a
 * routing-preference miss (provider_pin_blocked / price_blocked /
 * tool_unsupported) surfaces distinctly rather than as a sizing failure.
 *
 * It does NOT do the Responses-API previous_response_id strict pin or the
 * affinity *cache lookup* — those need live runtime state and stay caller-side.
 * The caller resolves the affinity-preferred operator and passes it as
 * `preferred` (null when none).
 */
export function selectTargets(ops: Operator[], c: Constraints, preferred: Operator | null): TargetResult {
    const diagnostics: Diagnostics = {
        registry_count: 0,
        version_blocked: false,
        tee_blocked: false,
        staging_blocked: false,
        signer_underfunded_blocked: false,
        image_endpoint_unsupported: false,
        affinity_blocked: false,
        provider_pin_blocked: false,
        price_blocked: false,
        tool_unsupported: false,
    }

    // 1. Model eligibility (defensive/idempotent on a pre-filtered set).
    const registry = ops.filter((op) => servesModel(op, c.model))
    diagnostics.registry_count = registry.length

    // 2. Caller ref filters (only allowlist + ignore denylist). Hard filters
    //    applied before sizing so a caller-pin miss isn't masked by a later
    //    price/sizing diagnostic. registry_count stays the pre-filter
    //    model-serving count, so "your allowlist matched nobody"
    //    (provider_pin_blocked) is distinct from "nobody advertises this model".
    const only = c.only ?? []
    const ignore = c.ignore ?? []
    let pool = registry
    if (only.length > 0 || ignore.length > 0) {
        pool = registry.filter((op) => passesRefFilters(op, only, ignore))
        if (pool.length === 0) {
            diagnostics.provider_pin_blocked = true
            return { operators: [], diagnostics }
        }
    }

    // 3. Sizing filter. In derive mode (max_output_unspecified) the fit check
    //    charges each operator its own per-operator derived max_output, not the
    //    flat request value, so a small-window operator a guessed flat ceiling
    //    would exclude survives — the reserve leg re-derives the identical number.
    let fitList: Operator[] = []
    const sizingMisses: SizingMiss[] = []
    for (const op of pool) {
        const eff = effectiveMaxOutput(op, c)
        if (fits(op, c.model, effectiveInputTokens(op, c), eff)) {
            fitList.push(op)
            continue
        }
        const mc = op.model_capacities?.[c.model]
        sizingMisses.push({
            operator_id: op.id,
            context_window: mc?.context_window ?? 0,
            max_output_tokens: mc?.max_output_tokens ?? 0,
            effective_max_output: eff,
        })
    }
    if (sizingMisses.length > 0) diagnostics.sizing_misses = sizingMisses
    if (fitList.length === 0) return { operators: [], diagnostics }

    // 4. Image-endpoint factor filter.
    if (c.endpoint === ENDPOINT_IMAGES) {
        fitList = fitList.filter((op) => op.model_capacities?.[c.model]?.serves_image_gen === true)
    } else if (c.endpoint === ENDPOINT_IMAGE_EDITS) {
        fitList = fitList.filter((op) => op.model_capacities?.[c.model]?.serves_image_edit === true)
    }
    if ((c.endpoint === ENDPOINT_IMAGES || c.endpoint === ENDPOINT_IMAGE_EDITS) && fitList.length === 0) {
        diagnostics.image_endpoint_unsupported = true
        return { operators: [], diagnostics }
    }

    // 5. Wire-protocol compatibility.
    fitList = fitList.filter((op) => protoVersionCompatible(op.proto_version))
    if (fitList.length === 0) {
        diagnostics.version_blocked = true
        return { operators: [], diagnostics }
    }

    // 6. TEE requirement.
    if (c.require_tee) {
        fitList = fitList.filter((op) => op.tee_attested)
        if (fitList.length === 0) {
            diagnostics.tee_blocked = true
            return { operators: [], diagnostics }
        }
    }

    // 6b. Staging exclusion. A node-level on-chain attribute (op.staging, from
    //     NodeRecord.staging) like TEE above: drop nodes their operator flagged
    //     as staging unless the caller opted in via allow_staging. registry_count
    //     is unchanged, so an all-staging model reports staging_blocked (served,
    //     but only by held-out nodes) rather than registry_count===0. Mirror of
    //     select.go step 6b.
    if (!c.allow_staging) {
        fitList = fitList.filter((op) => !op.staging)
        if (fitList.length === 0) {
            diagnostics.staging_blocked = true
            return { operators: [], diagnostics }
        }
    }

    // 6c. Signer funding. Unconditional — no caller can opt into a node that
    //     can't pay the fees of the group it would sign. An absent balance
    //     passes. Mirror of select.go step 6c.
    fitList = fitList.filter((op) => !signerUnderfunded(op))
    if (fitList.length === 0) {
        diagnostics.signer_underfunded_blocked = true
        return { operators: [], diagnostics }
    }

    // 7. Caller price ceiling (max_price). Drop operators whose advertised rate
    //    for the model exceeds a set ceiling; an undeclared (0) rate exceeds any
    //    ceiling (unknown price not assumed cheap). An all-out result is
    //    price_blocked. Mirror of select.go step 7.
    //
    //    Skipped entirely on the dedicated image endpoints: the ceiling is
    //    denominated in USD per 1M TOKENS, and an image route bills per image.
    //    Applying it there would reject every image operator on the strength of
    //    its (necessarily zero) token rates. price_blocked is therefore never set
    //    on those endpoints; a per-image ceiling would need its own field.
    const maxIn = c.max_input_usd_per_1m ?? 0
    const maxOut = c.max_output_usd_per_1m ?? 0
    if (!isImageEndpoint(c.endpoint) && (maxIn > 0 || maxOut > 0)) {
        fitList = fitList.filter((op) => {
            const mc = op.model_capacities?.[c.model]
            return (
                !exceedsCeiling(mc?.input_usd_per_1m ?? 0, maxIn) &&
                !exceedsCeiling(mc?.output_usd_per_1m ?? 0, maxOut)
            )
        })
        if (fitList.length === 0) {
            diagnostics.price_blocked = true
            return { operators: [], diagnostics }
        }
    }

    // 8. Price base sort. Cheapest first — token USD/1M off-route, the per-image
    //    microUSDC rate on the image endpoints. The stable partitions below
    //    preserve this order within each bucket, so price is the tiebreaker once
    //    tool capability is equal. Mirrors the client's former compareForDefault
    //    price axis, now shared. Array.sort is not guaranteed stable across
    //    engines for >10 elements in older specs, but is required stable in
    //    ES2019+ (all our targets) — and the id tiebreaker makes lessByPrice a
    //    total order anyway.
    fitList = [...fitList].sort((a, b) => lessByPrice(a, b, c))

    // 9. Built-in tool partition: operators advertising every requested zs_*
    //    tool rank first. With require_tools set this becomes a HARD filter
    //    instead — non-advertising operators are dropped, all-out is
    //    tool_unsupported. Mirror of select.go step 9.
    const requested = c.requested_tools ?? []
    if (requested.length > 0) {
        if (c.require_tools) {
            fitList = fitList.filter((op) => supportsAllBuiltinTools(op, requested))
            if (fitList.length === 0) {
                diagnostics.tool_unsupported = true
                return { operators: [], diagnostics }
            }
        } else {
            const primary: Operator[] = []
            const secondary: Operator[] = []
            for (const op of fitList) {
                if (supportsAllBuiltinTools(op, requested)) primary.push(op)
                else secondary.push(op)
            }
            fitList = [...primary, ...secondary]
        }
    }

    // 9b. In-loop image-tool partition. When the request budgets a hayai image
    //     tool, partition operators whose chosen model publishes the matching
    //     in-loop factor ahead of those that don't. PREFER, not filter (a model
    //     served only by toolless operators stays selectable). OR-of-budgeted-
    //     tools: an operator offering EITHER budgeted tool outranks a wholly-
    //     toolless peer. Runs after the operator-level tool partition (so the
    //     per-model signal dominates) and after the price sort (so price orders
    //     within each bucket).
    if (c.image_tool_gen_budget > 0 || c.image_tool_edit_budget > 0) {
        const primary: Operator[] = []
        const secondary: Operator[] = []
        for (const op of fitList) {
            const mc = op.model_capacities?.[c.model]
            const capable =
                (c.image_tool_gen_budget > 0 && mc?.offers_image_gen_tool === true) ||
                (c.image_tool_edit_budget > 0 && mc?.offers_image_edit_tool === true)
            if (capable) primary.push(op)
            else secondary.push(op)
        }
        fitList = [...primary, ...secondary]
    }

    // 10. Caller order reorder. Float candidates named by `order` to the front
    //     in the caller's ref order (an operator-only ref pulls all its nodes in
    //     their current price/id order); the rest follow. With allow_fallbacks
    //     false the unmatched tail is dropped (hard pin), all-out is
    //     provider_pin_blocked. Runs after the partitions (caller order
    //     dominates price/tool ranking). A continuation pin leads over a SOFT
    //     (fallbacks-allowed) order — the affinity step floats it ahead below.
    //     A no-fallback order is a HARD pin that binds the continuation too: if
    //     it names nothing eligible the pool empties here (provider_pin_blocked);
    //     if it names other candidates but not the affinity-preferred one, step
    //     11 surfaces the conflict (affinity_blocked under strict, yields under
    //     prefer) rather than resurrecting the excluded preferred. Mirror of
    //     select.go step 10.
    const order = c.order ?? []
    if (order.length > 0) {
        const matched: Operator[] = []
        const seen = new Set<string>()
        for (const ref of order) {
            for (const op of fitList) {
                const k = `${op.id}:${op.node_id}`
                if (seen.has(k)) continue
                if (operatorRefMatches(ref, op)) {
                    matched.push(op)
                    seen.add(k)
                }
            }
        }
        const allowFallbacks = c.allow_fallbacks ?? true
        if (allowFallbacks) {
            const rest = fitList.filter((op) => !seen.has(`${op.id}:${op.node_id}`))
            fitList = [...matched, ...rest]
        } else {
            if (matched.length === 0) {
                diagnostics.provider_pin_blocked = true
                return { operators: [], diagnostics }
            }
            fitList = matched
        }
    }

    // 11. Affinity reorder. Like the proxy, the tool-affinity path checks only
    //     serves + fits + signer funding on the preferred operator (NOT
    //     wire-version / TEE), plus the caller's own only/ignore/order below.
    //     Funding is re-checked because a pinned node can drain mid-loop.
    //     Mirror of select.go step 11.
    if (c.affinity_policy === AFFINITY_NONE || preferred === null) {
        return { operators: fitList, diagnostics }
    }
    if (!servesModel(preferred, c.model)) {
        return { operators: fitList, diagnostics }
    }
    // The caller's HARD constraints bind the continuation target too: an
    // only/ignore exclusion OR a no-fallback `order` that doesn't name the
    // preferred must not be silently overridden by resurrecting it. This mirrors
    // routingPreferencesAllowOperator — the same predicate the proxy applies to
    // the previous_response_id pin — so both continuation paths agree on what a
    // caller pin excludes. Strict → affinity_blocked (hard conflict); prefer →
    // yield (keep fitList, which already honors the order/filters). A SOFT
    // (fallbacks-allowed) order does NOT bind it: the pin still leads it below.
    // Mirror of select.go step 11.
    if (!passesRefFilters(preferred, only, ignore) || orderHardExcludes(preferred, order, c.allow_fallbacks ?? true)) {
        if (c.affinity_policy === AFFINITY_STRICT) {
            diagnostics.affinity_blocked = true
            return { operators: [], diagnostics }
        }
        return { operators: fitList, diagnostics }
    }
    const preferredFits = fits(
        preferred,
        c.model,
        effectiveInputTokens(preferred, c),
        effectiveMaxOutput(preferred, c),
    )
    // A broke preferred node yields under prefer (fitList already excludes it)
    // and blocks under strict with the funding cause, not affinity_blocked. The
    // permanent fit refusal outranks the retryable funding one.
    if (c.affinity_policy === AFFINITY_STRICT) {
        if (!preferredFits) {
            diagnostics.affinity_blocked = true
            return { operators: [], diagnostics }
        }
        if (signerUnderfunded(preferred)) {
            diagnostics.signer_underfunded_blocked = true
            return { operators: [], diagnostics }
        }
        return { operators: [preferred], diagnostics }
    }
    if (signerUnderfunded(preferred)) {
        return { operators: fitList, diagnostics }
    }
    // "prefer": preferred first (when it fits), then everyone else. Dedup the
    // preferred entry from the tail by (id, node_id), NOT id alone — under the
    // operator/node split an operator runs many nodes, and skipping by id would
    // drop the preferred operator's sibling nodes from the fallback pool. Only
    // the exact preferred node is the dupe; its siblings stay eligible.
    const out: Operator[] = []
    if (preferredFits) out.push(preferred)
    for (const op of fitList) {
        if (op.id !== preferred.id || op.node_id !== preferred.node_id) out.push(op)
    }
    return { operators: out, diagnostics }
}

/**
 * effectiveMaxOutput is the max_output the sizing filter charges op with: the
 * flat request-level max_output_tokens, unless the caller left it unspecified
 * (max_output_unspecified), in which case it's the per-operator derivation from
 * op's declared capacity (deriveMaxOutput). An operator with no declared capacity
 * derives from zero window/max (i.e. the flat ceiling), but `fits` short-circuits
 * such operators to "unbounded" before the value is consulted. The caller's
 * reserve leg computes the identical value per operator, so the filter and the
 * escrowed max_output never disagree. Mirror of select.go::effectiveMaxOutput.
 */
/**
 * Picks the input measurement to filter `op` on. v2 only where the operator
 * advertises support for it, mirroring the caller-side gate in the reserve leg
 * (usesTightInputBound) so the filter and the escrow agree on the same number
 * for the same operator.
 */
function effectiveInputTokens(op: Operator, c: Constraints): number {
    const v2 = c.input_tokens_v2 ?? 0
    if (v2 > 0 && usesTightInputBound(op.proto_version)) return v2
    return c.input_tokens
}

function effectiveMaxOutput(op: Operator, c: Constraints): number {
    if (!c.max_output_unspecified) return c.max_output_tokens
    const mc = op.model_capacities?.[c.model]
    return deriveMaxOutput(mc?.context_window ?? 0, mc?.max_output_tokens ?? 0, c.max_output_ceiling ?? 0)
}

/** Sort key for an advertised USD/1M rate: 0 ("undeclared") sorts last. Mirror
 *  of the go `r == 0 ? +Inf : r`. */
function priceRank(r: number): number {
    return r === 0 ? Infinity : r
}

/** Reports whether `e` is a dedicated image endpoint — one priced per produced
 *  image (microUSDC) rather than per token, so the token rates and the caller's
 *  per-1M-token price ceiling are both meaningless there. Mirror of
 *  select.go::isImageEndpoint. */
function isImageEndpoint(e: string | undefined): boolean {
    return e === ENDPOINT_IMAGES || e === ENDPOINT_IMAGE_EDITS
}

/** The response length the token-price comparison weighs an operator's OUTPUT
 *  rate by when the caller didn't state a max_output. The output side has no
 *  measurement available before the response exists, so it needs a stand-in for
 *  a typical assistant turn.
 *
 *  NOT effectiveMaxOutput in the derived case: that value is per-operator, so
 *  using it would charge a large-window node more than a small-window one for the
 *  identical request and systematically rank capable nodes last — in the common
 *  case where the caller omits max_tokens entirely. When the caller DID state a
 *  max_output that's their own bound on what they'll pay for, and it's what
 *  escrow locks, so requestCost uses it directly.
 *
 *  A zero max_output_tokens falls back here too, whatever max_output_unspecified
 *  says. Weighing the output axis by zero would price every operator's output
 *  rate at nothing and quietly reduce the comparison to input rates alone — the
 *  exact behavior this replaced. Mirror of the go `outputNormTokens`. */
const OUTPUT_NORM_TOKENS = 1000

/** The same stand-in for the INPUT axis, used only when the caller measured
 *  nothing (both input_tokens and input_tokens_v2 zero). Unlike the output side
 *  that is not an inherent limit — input IS measurable, and the proxy always
 *  measures it — but two callers deliberately don't: the client builds both its
 *  model picker and its dispatch candidate list with `input_tokens: 0`, since
 *  neither knows the request size and the per-attempt context gate is
 *  authoritative (client/src/operators/catalog.ts, dispatch-candidates.ts).
 *  Leaving the term at zero there would drop input pricing entirely and reduce
 *  those lists to output-rate-only ordering, so the client would rank a
 *  cheap-output/ruinous-input operator first on an input-heavy turn while the
 *  proxy — measuring the same request — ranked it last. Identical proxy/client
 *  routing is the requirement that makes the fallback mandatory, not cosmetic.
 *
 *  Equal to OUTPUT_NORM_TOKENS on purpose: with no measurement, weighing the two
 *  axes equally degrades the comparison to the SUM of the advertised rates, which
 *  is the neutral answer. Any other ratio would encode a claim about the traffic
 *  mix that nothing here can support. Keep them equal unless a real measurement
 *  of that mix says otherwise. Mirror of the go `inputNormTokens`. */
const INPUT_NORM_TOKENS = OUTPUT_NORM_TOKENS

/** What this request is expected to cost at `op`'s advertised token rates, in
 *  USD·tokens/1e6 — a relative figure for ordering, never a quote.
 *
 *  An undeclared (0) rate on EITHER axis yields Infinity: we can't price the
 *  request at all, and an unknown price is treated as too expensive, consistent
 *  with exceedsCeiling and with the pre-cost behavior of ranking undeclared rates
 *  last. (As elsewhere, 0 can't be distinguished from a genuinely free token
 *  model; that conflation is documented and accepted, and a free model is
 *  vanishingly rare.)
 *
 *  Both token weights are REQUEST-level, never per-operator — deliberately, and
 *  for the same reason OUTPUT_NORM_TOKENS isn't effectiveMaxOutput. In particular
 *  the input weight is NOT effectiveInputTokens: that returns the bound the
 *  operator's own proto version will be sized against, and v2 is not a uniform
 *  shrink of v1 — tokenize/bound.go calls it "tighter on prose, tool schemas and
 *  images, but deliberately LARGER on the classes v1 under-counts (base64, hex,
 *  emoji, embedded JSON)". Weighing by it prices the identical request
 *  differently for two operators advertising identical rates, ranking a 9.2+ node
 *  cheaper on a prose body and dearer on a base64 one, on a number that is a
 *  reserve bound rather than a charge — the bill is the real consumed tokens
 *  either way. effectiveInputTokens stays the right call for the FIT filter,
 *  where agreeing per-operator with what escrow locks is the whole point.
 *
 *  Parity: this is the only arithmetic in the price comparison, so the operand
 *  order must stay IDENTICAL to the go mirror (proto/go/selection/select.go).
 *  Both sides are IEEE-754 doubles and token counts are far below 2^53, so the
 *  results are bit-identical as long as nobody reassociates the expression.
 *
 *  Exported (the go side keeps it private) for callers that must order candidates
 *  CONSISTENTLY with selectTargets outside a single selectTargets call — the
 *  client's cross-spelling pooled merge is the one such caller. Reimplementing
 *  the comparison there is what let it drift from this one. */
export function requestCost(op: Operator, c: Constraints): number {
    const mc = op.model_capacities?.[c.model]
    const inRate = mc?.input_usd_per_1m ?? 0
    const outRate = mc?.output_usd_per_1m ?? 0
    if (inRate === 0 || outRate === 0) return Infinity
    // v2 first: it's the calibrated measurement of this request, so it's the
    // better cost estimate wherever the caller computed one. Which operators can
    // be SIZED against it is a separate question, answered by effectiveInputTokens.
    let inputTokens = c.input_tokens_v2 ?? 0
    if (inputTokens === 0) inputTokens = c.input_tokens
    if (inputTokens === 0) inputTokens = INPUT_NORM_TOKENS
    let outputTokens = c.max_output_tokens
    if (c.max_output_unspecified || outputTokens === 0) outputTokens = OUTPUT_NORM_TOKENS
    return inRate * inputTokens + outRate * outputTokens
}

/**
 * Comparator ordering two operators for the request's model and endpoint.
 *
 * On the dedicated image endpoints it orders by the route's microUSDC rate,
 * where 0 means free and ranks first (the serves-image eligibility filter has
 * already dropped non-serving operators, so 0 can't mean "undeclared" here).
 *
 * On every other endpoint it orders by the request's expected COST at each
 * operator's advertised token rates (requestCost), cheapest first. It used to
 * compare axis-by-axis — lowest input rate, then lowest output rate — which
 * returns on the first differing axis and therefore ranks in $0.01 / out $50.00
 * ahead of in $0.02 / out $0.05 on every request, including the output-heavy ones
 * where the second is a thousand times cheaper to actually run. Weighing both
 * axes by how many tokens the request will use them for is what makes "cheapest"
 * mean what a payer reading their bill means by it.
 *
 * Ties break by operator id, then node id.
 *
 * Parity with proto/go/selection/select.go::lessByPrice now rests on requestCost
 * (see its note on operand order) rather than on this being arithmetic-free.
 * Returns a `sort`-style number; the id tiebreak makes it a total order.
 */
function lessByPrice(a: Operator, b: Operator, c: Constraints): number {
    const ca = a.model_capacities?.[c.model]
    const cb = b.model_capacities?.[c.model]
    if (c.endpoint === ENDPOINT_IMAGES) {
        const ra = ca?.image_rate_micro_usdc ?? 0
        const rb = cb?.image_rate_micro_usdc ?? 0
        if (ra !== rb) return ra - rb
    } else if (c.endpoint === ENDPOINT_IMAGE_EDITS) {
        const ra = ca?.image_edit_rate_micro_usdc ?? 0
        const rb = cb?.image_edit_rate_micro_usdc ?? 0
        if (ra !== rb) return ra - rb
    } else {
        const pa = requestCost(a, c)
        const pb = requestCost(b, c)
        if (pa !== pb) return pa - pb
    }
    if (a.id !== b.id) return a.id - b.id
    // Same operator, different nodes — stable tiebreak by node id.
    return a.node_id - b.node_id
}

/**
 * Reports whether op survives the caller's only allowlist and ignore denylist.
 * Deny wins: an op matching any ignore ref is rejected even if it also matches
 * only. An empty only is "no allowlist". Mirror of select.go::passesRefFilters.
 * Exported for routingPreferencesAllowOperator (the continuation-conflict check).
 */
export function passesRefFilters(op: Operator, only: OperatorRef[], ignore: OperatorRef[]): boolean {
    for (const r of ignore) {
        if (operatorRefMatches(r, op)) return false
    }
    if (only.length > 0) {
        return only.some((r) => operatorRefMatches(r, op))
    }
    return true
}

/**
 * Reports whether a no-fallback `order` hard-excludes op. A non-empty order with
 * allowFallbacks=false names exactly the legal set, so an op the order doesn't
 * name is excluded just as only/ignore would exclude it. An empty order, or a
 * fallbacks-allowed (default) order, is a soft reorder and never excludes. This
 * is the order half of routingPreferencesAllowOperator; selectTargets applies it
 * (with passesRefFilters) to bind the affinity-preferred continuation target,
 * matching the proxy's previous_response_id pin check. Mirror of
 * select.go::orderHardExcludes.
 */
export function orderHardExcludes(op: Operator, order: OperatorRef[], allowFallbacks: boolean): boolean {
    if (order.length === 0 || allowFallbacks) return false
    return !order.some((ref) => operatorRefMatches(ref, op))
}

/**
 * Reports whether an advertised USD/1M rate breaches a caller price ceiling. A
 * ceiling <= 0 means "no ceiling" (never exceeded). An undeclared (0) rate maps
 * to priceRank Infinity, so it exceeds every finite ceiling — unknown price is
 * treated as too expensive, consistent with the price sort. Mirror of
 * select.go::exceedsCeiling.
 */
function exceedsCeiling(rate: number, ceiling: number): boolean {
    if (ceiling <= 0) return false
    return priceRank(rate) > ceiling
}

/**
 * selectRelay picks the single-hop relay operator for a request whose target
 * is already chosen. Eligibility: id !== target, owner_addr !== target's
 * (hard), version-compatible (so it actually exposes /v1/zs/relay), /16
 * diverse (best-effort). Sorts eligible relays by id and indexes with seed
 * (relays[seed % len]); the caller supplies a fresh random seed per request
 * (= the per-request rotation, so no single relay profiles a client over a
 * session).
 *
 * Reachability is a soft preference, not a requirement: a known-reachable relay
 * is always chosen over a not-known-reachable one, but when none are
 * known-reachable the pick falls back to the full eligible set rather than
 * failing — so a down operator isn't chosen as a relay in steady state, yet
 * cold-start still bootstraps (nothing is reachable yet → fallback). A
 * relayed-probe failure is ambiguous (target-down vs relay-down), so Reachable
 * self-corrects across cycles and is a preference, never an exclusion.
 *
 * `op.reachable` here means "the CALLER can use this node AS A RELAY", NOT "this
 * node is reachable as a target". For a server caller (the proxy) the two
 * coincide (it reaches every node directly). For a browser caller (client/) they
 * DIVERGE: a node can be reachable as a target via the mesh yet a dead relay from
 * the browser (localhost-resolving, CORS-blocked, firewalled), and vice-versa.
 * Such a caller MUST feed `reachable` from its OWN direct evidence of forwarding
 * through the node — never from target reachability alone — or the preferred tier
 * fills with un-relay-able nodes and the usable relays sink into the fallback
 * tier. See client `operators/relay-health.ts` (the sticky verdict) and
 * `operators/relay-decision.ts` (where it overrides the catalog hint).
 *
 * Returns null when no operator qualifies; the caller MUST hard-fail the
 * request rather than route direct (un-relayed) — that would defeat the
 * privacy guarantee. Mirror of proto/go/selection/select.go::SelectRelay
 * (which returns ErrNoRelay where this returns null).
 */
export function selectRelay(ops: Operator[], target: Operator, seed: number): Operator | null {
    const pool = eligibleRelays(ops, target)
    if (pool.length === 0) return null
    return pool[seed % pool.length] ?? null
}

/**
 * eligibleRelays returns the relay candidates for `target` that `selectRelay`
 * would index into — the same diversity/version/reachable filtering and
 * (id, node_id) ordering, but WITHOUT the final `seed % len` pick. It is a pure
 * extraction of selectRelay's pool step (selectRelay is now
 * `eligibleRelays(...)[seed % len]`), so its output is unchanged and the golden
 * vectors stay green.
 *
 * It exists for a caller that wants to rank the eligible pool by a signal the
 * shared policy deliberately omits — client-observed network latency. Latency is
 * stateful/per-process and vantage-specific, so it isn't a pure function of the
 * static inputs the golden vectors pin; it can't live in this shared policy at
 * all, and instead is measured by each caller from its own position (the client
 * app and the proxy are both single-payer processes reaching the mesh) and
 * applied as an app-side refinement over this pool. Such a caller takes this pool
 * and does its own pick (e.g. latency-weighted rotation) rather than duplicating
 * the diversity rules and risking drift from the /16 + owner-key guards. The pool
 * is already in preferred-tier order: when any relay is `reachable` only
 * reachables are returned, else the full eligible set (the cold-start fallback),
 * matching selectRelay exactly.
 */
export function eligibleRelays(ops: Operator[], target: Operator): Operator[] {
    const eligible = ops.filter(
        (op) =>
            op.id !== target.id &&
            op.owner_addr !== target.owner_addr &&
            protoVersionCompatible(op.proto_version) &&
            diverseSubnet(op.base_url, target.base_url),
    )
    const reachable = eligible.filter((op) => op.reachable)
    const pool = reachable.length > 0 ? reachable : eligible
    pool.sort((a, b) => (a.id !== b.id ? a.id - b.id : a.node_id - b.node_id))
    return pool
}

/**
 * diverseSubnet reports whether two base URLs are in different /16 networks.
 * Best-effort, defense-in-depth against co-locating relay and target in one
 * *public* hosting subnet. Conservative about excluding relays:
 *   - DNS-name hosts (the common NFD case) are unverifiable → treated as diverse.
 *   - Non-public addresses (loopback / private / link-local) are treated as
 *     diverse too — sharing a /16 is the norm among them in local/test
 *     deployments, so applying the rule would exclude every relay on a localnet.
 *   - Only two *public* IPv4 hosts sharing the first two octets are excluded.
 * Mirror of proto/go/selection/select.go::diverseSubnet.
 */
function diverseSubnet(a: string, b: string): boolean {
    const ipA = hostIPv4(a)
    const ipB = hostIPv4(b)
    if (ipA === null || ipB === null) return true
    if (!isPublicIPv4(ipA) || !isPublicIPv4(ipB)) return true
    return !(ipA[0] === ipB[0] && ipA[1] === ipB[1])
}

/**
 * isPublicIPv4 reports whether the octets are a globally-routable IPv4 address
 * — not loopback (127/8), private (10/8, 172.16/12, 192.168/16), link-local
 * (169.254/16), unspecified (0.0.0.0), or multicast (224/4). Mirrors the exact
 * set of net.IP.Is* checks the Go isPublicIPv4 uses.
 */
function isPublicIPv4(o: [number, number, number, number]): boolean {
    if (o[0] === 127) return false // loopback
    if (o[0] === 10) return false // private 10/8
    if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return false // private 172.16/12
    if (o[0] === 192 && o[1] === 168) return false // private 192.168/16
    if (o[0] === 169 && o[1] === 254) return false // link-local 169.254/16
    if (o[0] === 0 && o[1] === 0 && o[2] === 0 && o[3] === 0) return false // unspecified
    if (o[0] >= 224 && o[0] <= 239) return false // multicast 224/4
    return true
}

/** hostIPv4 returns baseURL's host as a 4-octet tuple, or null when it's not a literal IPv4. */
function hostIPv4(baseURL: string): [number, number, number, number] | null {
    let host: string
    try {
        host = new URL(baseURL).hostname
    } catch {
        return null
    }
    const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host)
    if (!m) return null
    const octets = [Number(m[1]), Number(m[2]), Number(m[3]), Number(m[4])]
    if (octets.some((o) => o > 255)) return null
    return octets as [number, number, number, number]
}
