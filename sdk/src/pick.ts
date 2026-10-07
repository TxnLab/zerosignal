/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Candidate selection for one request, mirroring proto/go/zs dispatch.go's
// pickCandidates and the helpers around it. The eligibility, sizing and
// preference policy is the shared selectTargets; what stays here is the
// runtime state around it: the continuation pins, the node exclusions, the
// post-pass ordering and the relay pool.

import {
    type Constraints,
    type ImageToolBudgets,
    MIN_SIGNER_SPENDABLE_MICROALGOS,
    type Operator as SelectionOperator,
    type RoutingPreferences,
    type SizingMiss,
    extractInputToolCallIDs,
    extractPreviousResponseID,
    extractRequestedBuiltinTools,
    routingPreferencesAllowOperator,
    selectTargets,
    signerUnderfunded,
} from '@txnlab/zs-proto/selection'
import { contradictsWeightsConsensus, weightsConsensus } from '@txnlab/zs-proto/steering'
import { protoVersionCompatible } from '@txnlab/zs-proto/wire'

import type { AffinityStore } from './affinity.js'
import { goDecodeUTF8, goQuote, wellFormed } from './gotext.js'
import { binaryOf } from './multipart.js'
import { type Operator, isTeeAttested, refOf, selectionOf } from './operator.js'
import type { RegistryProvider } from './parts.js'
import type { LogAttrs, Logger } from './ports.js'
import type { TargetBackoffStore } from './routing/backoff.js'
import { type RankDetail, type ResponsivenessMode, catalogConfidence } from './routing/banding.js'
import type { NodeExclusionStore } from './routing/exclusion.js'
import type { RelayLatencyStore } from './routing/latency.js'
import { type CandidateOrderInput, orderCandidatesDetailed } from './routing/order.js'
import { type RelayHop, randomRelaySeed, selectRelayHopWeighted } from './routing/relay.js'
import type { RelayReputationStore } from './routing/reputation.js'
import { capacityOf, effectiveMaxOutput, fits, maxDeclaredOutput, type SizingRequest } from './sizing.js'
import type { AffinityPolicy, Endpoint, NodeRef } from './types.js'
import { nodeRefString } from './types.js'

/** What candidate selection reads off the Client. */
export interface PickDeps {
    registry: RegistryProvider
    toolAffinity: AffinityStore
    responseAffinity: AffinityStore
    affinityPolicy: AffinityPolicy
    allowStaging: boolean
    relayLatency?: RelayLatencyStore | undefined
    targetBackoff?: TargetBackoffStore | undefined
    nodeExclusions?: NodeExclusionStore | undefined
    relayReputation?: RelayReputationStore | undefined
    logger: Logger
    /** The (model, node) pairs already warned about, for the process. */
    weightsWarned: Set<string>
}

/** One request as selection sees it. */
export interface PickRequest {
    endpoint: Endpoint
    model: string
    body: string | Uint8Array
    sizing: SizingRequest
    requireTee: boolean
    toolBudgets: ImageToolBudgets
    prefs: RoutingPreferences
}

/**
 * PickResult is the ordered candidates, or why there are none. Each flag maps
 * to its own refusal in dispatch, so a caller can tell "nobody serves this
 * model" from "only staging nodes serve it" from a pin that cannot be kept.
 */
export interface PickResult {
    operators: Operator[]
    registryCount: number
    affinityBlocked: boolean
    affinityBlockReason: string
    sizingMisses: SizingMiss[]
    teeBlocked: boolean
    stagingBlocked: boolean
    signerUnderfundedBlocked: boolean
    /** Replaces the model-wide message when a pin, not the pool, is underfunded. */
    signerUnderfundedReason: string
    versionBlocked: boolean
    imageEndpointUnsupported: boolean
    providerPinBlocked: boolean
    pinConflict: boolean
    pinConflictReason: string
    priceBlocked: boolean
    toolUnsupported: boolean
}

function emptyResult(registryCount: number): PickResult {
    return {
        operators: [],
        registryCount,
        affinityBlocked: false,
        affinityBlockReason: '',
        sizingMisses: [],
        teeBlocked: false,
        stagingBlocked: false,
        signerUnderfundedBlocked: false,
        signerUnderfundedReason: '',
        versionBlocked: false,
        imageEndpointUnsupported: false,
        providerPinBlocked: false,
        pinConflict: false,
        pinConflictReason: '',
        priceBlocked: false,
        toolUnsupported: false,
    }
}

// The body as Go's selection extractors read it: invalid UTF-8 byte by byte,
// a lone surrogate as U+FFFD.
export function bodyText(body: string | Uint8Array): string {
    return typeof body === 'string' ? wellFormed(body) : goDecodeUTF8(body)
}

// Go's %q of an id or model that came from the request body.
export const quoted = (s: string): string => goQuote(binaryOf(new TextEncoder().encode(s)))

const minSignerAlgo = MIN_SIGNER_SPENDABLE_MICROALGOS / 1_000_000

function excluded(deps: PickDeps, op: Operator): boolean {
    return deps.nodeExclusions?.nodeExcluded(refOf(op)) ?? false
}

// A registry that rejects a resolve has no such node, as Go reads any Resolve
// error; both are logged, as Go logs its not-found error.
async function resolveNode(
    deps: PickDeps,
    ref: NodeRef,
    missMsg: string,
    attrs: LogAttrs,
    signal?: AbortSignal,
): Promise<Operator | undefined> {
    let op: Operator | undefined
    let err: unknown = 'not found'
    try {
        op = await deps.registry.resolve(ref, signal)
    } catch (e) {
        err = e
    }
    if (op === undefined) deps.logger.debug(missMsg, { ...attrs, operator_id: ref.op, node_id: ref.node, err: String(err) })
    return op
}

/**
 * resolveResponseIdPin resolves a previous_response_id to the exact node that
 * issued it, or says why it cannot be continued there. The session lives in
 * that node's upstream account, so a sibling node of the same operator would
 * 404 it just as another operator would.
 */
export async function resolveResponseIdPin(
    deps: PickDeps,
    previousResponseId: string,
    model: string,
    sizing: SizingRequest,
    signal?: AbortSignal,
): Promise<{ op: Operator } | { reason: string }> {
    const id = quoted(previousResponseId)
    const ref = deps.responseAffinity.lookup(previousResponseId)
    if (ref === undefined) {
        return {
            reason:
                `previous_response_id ${id} not found in routing cache; ` +
                'the conversation may have expired or been served by a different ' +
                'proxy replica — retry without previous_response_id',
        }
    }
    // An excluded node is barred as a target for the process, a continuation
    // included: the exclusion fires in the settle of a turn whose response id
    // is already recorded.
    if (deps.nodeExclusions?.nodeExcluded(ref)) {
        return {
            reason:
                `previous_response_id ${id} is pinned to operator ${ref.op} node ${ref.node}, which this payer excluded ` +
                'for handing it a fraudulent settle group; start a new conversation',
        }
    }
    const op = await resolveNode(
        deps,
        ref,
        'response_id pin: node not in registry',
        { previous_response_id: previousResponseId },
        signal,
    )
    if (op === undefined) {
        return {
            reason:
                `previous_response_id ${id} is pinned to operator ${ref.op} node ${ref.node} which is no longer registered; ` +
                'retry without previous_response_id',
        }
    }
    if (!op.models.includes(model)) {
        return { reason: `previous_response_id ${id} is pinned to operator ${ref.op} which no longer serves model ${quoted(model)}` }
    }
    if (!fits(op, sizing)) {
        // The max_output this operator was fit-checked against, not the flat display ceiling.
        return {
            reason:
                `previous_response_id ${id} is pinned to operator ${ref.op} which cannot fit input_tokens=${sizing.inputTokens} max_output_tokens=${effectiveMaxOutput(op, sizing)}; ` +
                'reduce prompt size or start a new conversation',
        }
    }
    return { op }
}

/**
 * routableIgnoringSize reports whether op could serve the request if token
 * counts were no object: the hard exclusions selection applies regardless of
 * size. Hard exclusions only, and only ones selection applies unconditionally:
 * keeping an operator selection later drops can only raise poolMaxOutput's
 * ceiling, which clamps less, while dropping one that selection would keep
 * clamps a caller below what that operator was ready to serve.
 */
export function routableIgnoringSize(deps: PickDeps, op: Operator, requireTee: boolean, prefs: RoutingPreferences): boolean {
    if (excluded(deps, op)) return false
    if (op.staging && !deps.allowStaging) return false
    if (!protoVersionCompatible(op.protoVersion)) return false
    if (requireTee && !isTeeAttested(op)) return false
    const sel = selectionOf(op)
    if (signerUnderfunded(sel)) return false
    return routingPreferencesAllowOperator(prefs, sel)
}

/**
 * poolMaxOutput is the largest max_output declared for model across the
 * operators this request could be routed to, or 0 when they declare none
 * worth clamping to. Filtering to the routable set matters because one
 * undeclared operator switches the clamp off for everyone: a staging node, a
 * banned node or one the caller's preferences exclude must not. A registry
 * failure is 0; pickCandidates reports it.
 */
export async function poolMaxOutput(
    deps: PickDeps,
    model: string,
    requireTee: boolean,
    prefs: RoutingPreferences,
    signal?: AbortSignal,
): Promise<number> {
    let registry: Operator[]
    try {
        registry = await deps.registry.operators(model, signal)
    } catch {
        return 0
    }
    return maxDeclaredOutput(
        registry.filter((op) => routableIgnoringSize(deps, op, requireTee, prefs)),
        model,
    )
}

/**
 * pickCandidates returns the operators to try for a request, in order, or the
 * reason there are none. A previous_response_id pins the request to the node
 * holding the session whatever the affinity policy, and blocks rather than
 * falls through when that node cannot take it. Otherwise the shared
 * selectTargets applies eligibility, sizing and the caller's preferences, with
 * the tool-affinity node as its preferred one, and the result is ordered by
 * responsiveness, weights consensus and backoff. A registry failure rejects.
 */
export async function pickCandidates(deps: PickDeps, req: PickRequest, signal?: AbortSignal): Promise<PickResult> {
    const { endpoint, model, sizing, requireTee, toolBudgets, prefs } = req
    // A node proven to have handed a fraudulent settle group is dropped
    // before counting, so the empty-candidate diagnostics reflect it.
    const registry = (await deps.registry.operators(model, signal)).filter((op) => !excluded(deps, op))
    const res = emptyResult(registry.length)
    const text = bodyText(req.body)

    if (endpoint === '/v1/responses') {
        const rid = extractPreviousResponseID(text)
        if (rid !== '') {
            const pin = await resolveResponseIdPin(deps, rid, model, sizing, signal)
            if ('reason' in pin) {
                res.affinityBlocked = true
                res.affinityBlockReason = pin.reason
                return res
            }
            const op = pin.op
            // Each conflict overrides the pin rather than route the session
            // somewhere it must not go: a wire generation this build can't
            // seal for, a non-attested node for a TEE request, or a node the
            // caller's own preferences exclude.
            if (!protoVersionCompatible(op.protoVersion)) {
                res.versionBlocked = true
                return res
            }
            if (requireTee && !isTeeAttested(op)) {
                res.teeBlocked = true
                return res
            }
            const sel = selectionOf(op)
            if (!routingPreferencesAllowOperator(prefs, sel)) {
                res.pinConflict = true
                res.pinConflictReason =
                    `previous_response_id ${quoted(rid)} is pinned to operator ${op.id} node ${op.nodeId}, which your provider ` +
                    'preferences (only/ignore/order) exclude; the continuation can only be served by ' +
                    'that operator — remove the conflicting preference or start a new conversation'
                return res
            }
            // After the conflicts, so a permanent contradiction is reported
            // ahead of this transient one.
            if (signerUnderfunded(sel)) {
                res.signerUnderfundedBlocked = true
                res.signerUnderfundedReason =
                    `previous_response_id ${quoted(rid)} is pinned to operator ${op.id} node ${op.nodeId}, whose signing account has less than ${minSignerAlgo} ALGO ` +
                    'spendable to pay network fees; retry once the operator tops up, or start a new conversation'
                return res
            }
            res.operators = [op]
            return res
        }
    }

    // The first tool-call id with a live pin decides; a pin whose node is gone
    // or excluded is no preference at all. selectTargets would put an excluded
    // node back past the filter above, and this pin is a cache location, not a
    // session, so even strict falls through to normal selection.
    let preferredOp: Operator | undefined
    if (deps.affinityPolicy !== 'none') {
        for (const id of extractInputToolCallIDs(text)) {
            const ref = deps.toolAffinity.lookup(id)
            if (ref === undefined) continue
            if (deps.nodeExclusions?.nodeExcluded(ref)) {
                deps.logger.debug('affinity-preferred node is excluded', { operator_id: ref.op, node_id: ref.node })
            } else {
                preferredOp = await resolveNode(deps, ref, 'affinity-preferred node not in registry', {}, signal)
            }
            break
        }
    }

    const c: Constraints = {
        model,
        input_tokens: sizing.inputTokens,
        input_tokens_v2: sizing.inputTokensV2,
        max_output_tokens: sizing.maxOutputTokens,
        max_output_unspecified: sizing.deriveMaxOutput,
        max_output_ceiling: sizing.maxOutputCeiling,
        endpoint,
        require_tee: requireTee,
        allow_staging: deps.allowStaging,
        requested_tools: extractRequestedBuiltinTools(text),
        image_tool_gen_budget: toolBudgets.generationMaxN,
        image_tool_edit_budget: toolBudgets.editMaxN,
        affinity_policy: deps.affinityPolicy,
        only: prefs.only,
        ignore: prefs.ignore,
        order: prefs.order,
        allow_fallbacks: prefs.allow_fallbacks,
        max_input_usd_per_1m: prefs.max_input_usd_per_1m,
        max_output_usd_per_1m: prefs.max_output_usd_per_1m,
        require_tools: prefs.require_tools,
    }
    const tr = selectTargets(registry.map(selectionOf), c, preferredOp ? selectionOf(preferredOp) : null)

    const d = tr.diagnostics
    res.versionBlocked = d.version_blocked
    res.teeBlocked = d.tee_blocked
    res.stagingBlocked = d.staging_blocked
    res.signerUnderfundedBlocked = d.signer_underfunded_blocked
    if (
        res.signerUnderfundedBlocked &&
        preferredOp !== undefined &&
        signerUnderfunded(selectionOf(preferredOp)) &&
        deps.affinityPolicy === 'strict'
    ) {
        res.signerUnderfundedReason =
            `this tool-call continuation is pinned (strict affinity) to operator ${preferredOp.id} node ${preferredOp.nodeId}, whose signing account ` +
            `has less than ${minSignerAlgo} ALGO spendable to pay network fees; retry later, or set the affinity policy to prefer so another node can continue it`
    }
    res.imageEndpointUnsupported = d.image_endpoint_unsupported
    res.affinityBlocked = d.affinity_blocked
    res.providerPinBlocked = d.provider_pin_blocked
    res.priceBlocked = d.price_blocked
    res.toolUnsupported = d.tool_unsupported
    res.sizingMisses = [...(d.sizing_misses ?? [])]

    if (tr.operators.length > 0) {
        // By (operator, node): the registry holds one entry per node, and the
        // preferred node may be missing from the model-filtered list.
        const byNode = new Map<string, Operator>()
        for (const op of registry) byNode.set(nodeRefString(refOf(op)), op)
        if (preferredOp) byNode.set(nodeRefString(refOf(preferredOp)), preferredOp)
        const ops = tr.operators.map((so) => byNode.get(nodeRefString({ op: so.id, node: so.node_id }))!)
        res.operators = orderOperators(deps, ops, preferredOp, prefs.sort as ResponsivenessMode, registry, model)
    }
    return res
}

/**
 * orderOperators runs Go's orderCandidates post-passes on a price-ordered
 * list: responsiveness bands with pin first, then contradicted weights to the
 * tail (voted over evidence, the whole registry, with no pin exempt), then
 * backed-off nodes to the tail, the pin exempt as the node holding the tool
 * loop's KV cache.
 */
export function orderOperators(
    deps: PickDeps,
    ops: readonly Operator[],
    pin: Operator | undefined,
    mode: ResponsivenessMode,
    evidence: readonly Operator[],
    model: string,
): Operator[] {
    const pinKey = pin ? nodeRefString(refOf(pin)) : undefined
    const digest = (op: Operator) => capacityOf(op, model)?.weightsDigest ?? ''
    const consensus = weightsConsensus(evidence.map((op) => ({ owner: op.ownerAddr, digest: digest(op) })))
    const inputs = new Map<Operator, CandidateOrderInput>()
    for (const op of ops) {
        const ref = refOf(op)
        const pinned = pinKey !== undefined && nodeRefString(ref) === pinKey
        inputs.set(op, {
            rtt: deps.relayLatency?.targetLatency(ref),
            ttftEwmaMs: op.metrics.latencyEwmaMs,
            tokensPerSecEwma: op.metrics.tokensPerSecEwma,
            catalog: Object.values(op.modelCapacities).map((mc) => mc.outputModalities),
            pinned,
            contradicted: contradictsWeightsConsensus(digest(op), consensus),
            backedOff: deps.targetBackoff?.targetBackedOff(ref) ?? false,
            backoffPinned: pinned,
        })
    }
    const inputOf = (op: Operator) => inputs.get(op)!
    const { list: ordered, details } = orderCandidatesDetailed(ops, inputOf, mode)
    warnWeightsContradiction(deps, model, ops.filter((op) => inputOf(op).contradicted).map(refOf))
    logRanking(deps, model, mode, ordered, ops, details, inputOf)
    return ordered
}

/**
 * warnWeightsContradiction warns once per (model, node) for the process: the
 * demerit is recomputed on every pick, and an operator serving a requant
 * contradicts identically each time, so an undeduped line would repeat until
 * nobody read it.
 */
function warnWeightsContradiction(deps: PickDeps, model: string, refs: readonly NodeRef[]): void {
    for (const ref of refs) {
        const key = `${model}\x00${ref.op}\x00${ref.node}`
        if (deps.weightsWarned.has(key)) continue
        deps.weightsWarned.add(key)
        deps.logger.warn('weights digest contradicts peer consensus, deprioritizing operator', {
            model,
            operator_id: ref.op,
            node_id: ref.node,
        })
    }
}

// The final order and the banding inputs behind it, so "why that operator?"
// can be answered after the fact: the price sort, the confidence discount and
// the demotions are otherwise silent. A candidate placed differently from its
// band was moved by a demotion. Rates, latencies and ids only.
function logRanking(
    deps: PickDeps,
    model: string,
    mode: ResponsivenessMode,
    ordered: readonly Operator[],
    ops: readonly Operator[],
    details: RankDetail[] | null,
    inputOf: (op: Operator) => CandidateOrderInput,
): void {
    if (ordered.length === 0) return
    const byOp = new Map<Operator, RankDetail>()
    for (const d of details ?? []) byOp.set(ops[d.index]!, d)
    deps.logger.debug('target ranking', {
        model,
        sort: mode || 'balanced',
        banded: details !== null,
        candidates: ordered.map((op, rank) => {
            const mc = capacityOf(op, model)
            const line: Record<string, unknown> = {
                rank,
                operator_id: op.id,
                node_id: op.nodeId,
                input_usd_per_1m: mc?.inputUsdPer1m ?? 0,
                output_usd_per_1m: mc?.outputUsdPer1m ?? 0,
            }
            const d = byOp.get(op)
            if (d) {
                Object.assign(line, {
                    catalog_models: Object.keys(op.modelCapacities).length,
                    metrics_confidence: catalogConfidence(inputOf(op).catalog),
                    rtt: { raw: d.rtt.value, confidence: d.rtt.confidence, effective: d.rttEff },
                    ttft: { raw: d.ttft.value, confidence: d.ttft.confidence, effective: d.ttftEff },
                    decode: { raw: d.decode.value, confidence: d.decode.confidence, effective: d.decodeEff },
                    score_ms: d.score,
                    band: d.band,
                    signal: d.signal,
                    pinned: d.pinned,
                })
            }
            return line
        }),
    })
}

/**
 * relayPool projects every known node onto the relay candidates: a proven-
 * fraudulent node is dropped, and a relay on a failure streak is marked
 * unreachable, which moves it to the fallback tier rather than out. Built
 * once per sweep, so a relay that crosses the threshold mid-sweep keeps its
 * tier until the next one.
 */
export async function relayPool(deps: PickDeps, signal?: AbortSignal): Promise<SelectionOperator[]> {
    // Go's AllOperators cannot fail: a registry that can't list is an empty
    // pool, which leaves no relay rather than failing some other way.
    let all: Operator[]
    try {
        all = await deps.registry.allOperators(signal)
    } catch (err) {
        deps.logger.debug('relay pool: registry list failed', { err: String(err) })
        return []
    }
    const out: SelectionOperator[] = []
    for (const op of all) {
        if (excluded(deps, op)) continue
        const sel = selectionOf(op)
        if (deps.relayReputation?.relayDownranked(refOf(op))) sel.reachable = false
        out.push(sel)
    }
    return out
}

/**
 * relayHopForPool picks a relay hop for target from a pool relayPool built,
 * weighted toward relays fast for this target. Called only with privacy on:
 * null is Go's ErrNoRelay, and the caller must fail rather than go direct.
 */
export function relayHopForPool(deps: PickDeps, pool: SelectionOperator[], target: Operator): RelayHop | null {
    const targetRef = refOf(target)
    const latencyOf = (relay: NodeRef) => deps.relayLatency?.relayLatencyForTarget(relay, targetRef)
    return selectRelayHopWeighted(pool, selectionOf(target), randomRelaySeed(), latencyOf)
}
