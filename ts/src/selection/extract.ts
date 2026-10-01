/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Body-parsing helpers for affinity-key derivation and tool-aware routing.
// Mirror of proto/go/selection/extract.go. Living in proto guarantees the
// proxy and the client/ chat app derive the same affinity keys and tool sets
// from a request body — otherwise the two "user" endpoints would route
// continuations differently. All are advisory: a parse failure returns the
// empty value, never throws.

import { type Operator, type OperatorRef, parseOperatorRef } from './operator.js'
import { orderHardExcludes, passesRefFilters } from './select.js'

function parse(body: string): unknown {
    try {
        return JSON.parse(body)
    } catch {
        return undefined
    }
}

/** Pulls the top-level "model" string from a request body. */
export function extractModel(body: string): string {
    const o = parse(body) as { model?: unknown } | undefined
    return typeof o?.model === 'string' ? o.model : ''
}

/** Returns every built-in `zs_*` tool type named in the request body's tools[], in order. */
export function extractRequestedBuiltinTools(body: string): string[] {
    const o = parse(body) as { tools?: Array<{ type?: unknown }> } | undefined
    if (!Array.isArray(o?.tools)) return []
    const out: string[] = []
    for (const t of o.tools) {
        const type = t?.type
        if (typeof type === 'string' && type.startsWith('zs_')) out.push(type)
    }
    return out
}

/**
 * Per-request image-tool budgets a client declares on a /v1/responses body to
 * opt the hayai image tools in:
 *
 *     "tool_budgets": {
 *       "zs_image_generation": { "max_n": 4 },
 *       "zs_image_edit":       { "max_n": 2 }
 *     }
 *
 * max_n is the maximum number of images that tool may produce over the whole
 * request. Omitted ⇒ 0 ⇒ the tool is unusable for the request even if the
 * operator advertises a factor and the model decides to call it — the
 * proxy/client sizes the reserve from these counts and the node enforces them
 * in the tool loop.
 */
export interface ImageToolBudgets {
    generationMaxN: number
    editMaxN: number
}

/**
 * Reads the tool_budgets object from a request body. Advisory: a missing or
 * malformed object yields the zero value (both budgets 0). Keyed by tool type
 * so it stays aligned with the zs_image_generation / zs_image_edit tool
 * names on the wire. Mirror of proto/go/selection/extract.go::ParseToolBudgets.
 */
export function parseToolBudgets(body: string): ImageToolBudgets {
    const o = parse(body) as { tool_budgets?: Record<string, { max_n?: unknown }> } | undefined
    const tb = o?.tool_budgets
    const maxN = (key: string): number => {
        const v = tb?.[key]?.max_n
        // Match Go's uint64 max_n: a non-integer or negative value fails the
        // Go unmarshal (→ 0), and a fractional budget would be rejected by the
        // node's uint64 image_tool_budget on the reserve request anyway.
        return typeof v === 'number' && Number.isInteger(v) && v > 0 ? v : 0
    }
    return {
        generationMaxN: maxN('zs_image_generation'),
        editMaxN: maxN('zs_image_edit'),
    }
}

/** Scans a chat-completions request body for role:tool messages' tool_call_id values, in order. */
export function extractInputToolCallIDs(body: string): string[] {
    const o = parse(body) as { messages?: Array<{ role?: unknown; tool_call_id?: unknown }> } | undefined
    if (!Array.isArray(o?.messages)) return []
    const out: string[] = []
    for (const m of o.messages) {
        if (m?.role === 'tool' && typeof m.tool_call_id === 'string' && m.tool_call_id !== '') {
            out.push(m.tool_call_id)
        }
    }
    return out
}

/** Scans a chat-completions response body for tool_calls[].id across every choice. */
export function extractResponseToolCallIDs(body: string): string[] {
    const o = parse(body) as
        | { choices?: Array<{ message?: { tool_calls?: Array<{ id?: unknown }> } }> }
        | undefined
    if (!Array.isArray(o?.choices)) return []
    const out: string[] = []
    for (const ch of o.choices) {
        const calls = ch?.message?.tool_calls
        if (!Array.isArray(calls)) continue
        for (const tc of calls) {
            if (typeof tc?.id === 'string' && tc.id !== '') out.push(tc.id)
        }
    }
    return out
}

/** Pulls "previous_response_id" from a /v1/responses request body. */
export function extractPreviousResponseID(body: string): string {
    const o = parse(body) as { previous_response_id?: unknown } | undefined
    return typeof o?.previous_response_id === 'string' ? o.previous_response_id : ''
}

/**
 * Pulls top-level "id" from a /v1/responses non-streaming response body.
 * Guards against a non-Response object carrying an "id" via the object
 * discriminator.
 */
export function extractResponseID(body: string): string {
    const o = parse(body) as { id?: unknown; object?: unknown } | undefined
    if (o === undefined) return ''
    if (typeof o.object === 'string' && o.object !== '' && o.object !== 'response') return ''
    return typeof o.id === 'string' ? o.id : ''
}

// Sort values for RoutingPreferences.sort — the caller's base-ordering choice.
// "price" is the policy default; "throughput"/"latency" are honored by each
// caller's app-side post-pass (runtime metrics the shared policy omits). Mirror
// of the go Sort* constants.
export const SORT_PRICE = 'price' as const
export const SORT_THROUGHPUT = 'throughput' as const
export const SORT_LATENCY = 'latency' as const

// Relay values for RoutingPreferences.relay — the per-request transport-privacy
// override. "auto" defers to the process config; "off" sends direct (no relay);
// "required" forces a relay (hard-fail if none eligible). Consumed app-side.
// Mirror of the go Relay* constants.
export const RELAY_AUTO = 'auto' as const
export const RELAY_OFF = 'off' as const
export const RELAY_REQUIRED = 'required' as const

/**
 * The caller's OpenRouter-style provider-selection inputs, parsed from a request
 * body's `provider` object. Living in proto guarantees the proxy and client/
 * app derive identical preferences. order/only/ignore/allow_fallbacks/
 * max_*_usd_per_1m/require_tools map onto selection.Constraints; sort and relay
 * are app-side signals the shared policy leaves to each process. Mirror of
 * proto/go/selection/extract.go::RoutingPreferences.
 */
export interface RoutingPreferences {
    order: OperatorRef[]
    only: OperatorRef[]
    ignore: OperatorRef[]
    // default true; false only when the caller explicitly sent allow_fallbacks:false.
    allow_fallbacks: boolean
    // price ceilings from max_price.{input,output}; 0 ⇒ no ceiling on that axis.
    max_input_usd_per_1m: number
    max_output_usd_per_1m: number
    require_tools: boolean
    // "" | SORT_* (app-side ordering).
    sort: string
    // "" | RELAY_* (app-side privacy override).
    relay: string
}

/**
 * Parses the `provider` object from a request body into RoutingPreferences.
 * Advisory: a missing/malformed `provider` yields the defaults (notably
 * allow_fallbacks=true, so an absent object never silently pins). Malformed refs
 * are skipped, an unrecognized sort/relay normalizes to "", and a non-positive
 * ceiling means "no ceiling". The caller must strip `provider` from the body
 * before sealing it to the node — it is a proxy/client-only routing hint. Mirror
 * of proto/go/selection/extract.go::ExtractRoutingPreferences.
 */
export function extractRoutingPreferences(body: string): RoutingPreferences {
    const prefs: RoutingPreferences = {
        order: [],
        only: [],
        ignore: [],
        allow_fallbacks: true,
        max_input_usd_per_1m: 0,
        max_output_usd_per_1m: 0,
        require_tools: false,
        sort: '',
        relay: '',
    }
    const o = parse(body) as { provider?: unknown } | undefined
    const p = o?.provider
    if (p === undefined || p === null || typeof p !== 'object') return prefs
    const prov = p as {
        order?: unknown
        only?: unknown
        ignore?: unknown
        allow_fallbacks?: unknown
        max_price?: { input?: unknown; output?: unknown }
        require_tools?: unknown
        sort?: unknown
        relay?: unknown
    }
    prefs.order = parseOperatorRefs(prov.order)
    prefs.only = parseOperatorRefs(prov.only)
    prefs.ignore = parseOperatorRefs(prov.ignore)
    if (typeof prov.allow_fallbacks === 'boolean') prefs.allow_fallbacks = prov.allow_fallbacks
    if (prov.max_price && typeof prov.max_price === 'object') {
        const inN = prov.max_price.input
        const outN = prov.max_price.output
        if (typeof inN === 'number' && inN > 0) prefs.max_input_usd_per_1m = inN
        if (typeof outN === 'number' && outN > 0) prefs.max_output_usd_per_1m = outN
    }
    if (prov.require_tools === true) prefs.require_tools = true
    prefs.sort = normalizeSort(prov.sort)
    prefs.relay = normalizeRelay(prov.relay)
    return prefs
}

/** Parses a list of ref strings, skipping malformed entries. Non-array ⇒ []. */
function parseOperatorRefs(input: unknown): OperatorRef[] {
    if (!Array.isArray(input)) return []
    const out: OperatorRef[] = []
    for (const s of input) {
        if (typeof s !== 'string') continue
        const ref = parseOperatorRef(s)
        if (ref !== null) out.push(ref)
    }
    return out
}

function normalizeSort(s: unknown): string {
    if (typeof s !== 'string') return ''
    switch (s.trim().toLowerCase()) {
        case SORT_PRICE:
            return SORT_PRICE
        case SORT_THROUGHPUT:
            return SORT_THROUGHPUT
        case SORT_LATENCY:
            return SORT_LATENCY
        default:
            return ''
    }
}

function normalizeRelay(s: unknown): string {
    if (typeof s !== 'string') return ''
    switch (s.trim().toLowerCase()) {
        case RELAY_AUTO:
            return RELAY_AUTO
        case RELAY_OFF:
            return RELAY_OFF
        case RELAY_REQUIRED:
            return RELAY_REQUIRED
        default:
            return ''
    }
}

/**
 * Reports whether a single, already-chosen operator — e.g. a Responses-API
 * previous_response_id continuation target resolved OUTSIDE selectTargets —
 * survives the caller's HARD routing constraints: the only allowlist, the
 * ignore denylist, and a no-fallback order pin. Mirrors exactly the constraints
 * that would hard-exclude an operator from selectTargets' output, and ignores
 * the soft (fallbacks-allowed) order, price, tools, and sizing (a continuation
 * pin overrides those — the session lives in that operator's account). Use it to
 * detect a caller-pin vs continuation conflict before bypassing selectTargets.
 * Mirror of proto/go/selection/extract.go::RoutingPreferences.AllowsOperator.
 */
export function routingPreferencesAllowOperator(prefs: RoutingPreferences, op: Operator): boolean {
    // Exactly the hard exclusions selectTargets binds the affinity-preferred
    // continuation target by (passesRefFilters + orderHardExcludes), so the
    // response-id and tool-call continuation paths agree on what a caller pin
    // excludes. A no-fallback order is a hard pin; an only/ignore exclusion always
    // blocks; a fallbacks-allowed order is soft and never blocks.
    return (
        passesRefFilters(op, prefs.only, prefs.ignore) &&
        !orderHardExcludes(op, prefs.order, prefs.allow_fallbacks)
    )
}

/**
 * Pulls response.id from a decrypted SSE data payload when the frame type is
 * "response.created" or "response.completed". Empty otherwise.
 */
export function extractResponseIDFromFrame(frameData: string): string {
    const o = parse(frameData) as { type?: unknown; response?: { id?: unknown } } | undefined
    if (o?.type === 'response.created' || o?.type === 'response.completed') {
        return typeof o.response?.id === 'string' ? o.response.id : ''
    }
    return ''
}
