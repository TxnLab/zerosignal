/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The reserve phase of one turn, mirroring proto/go/zs dispatch.go's dispatch:
// shape the body, size it, pick candidates, then walk them until one signs a
// ticket the payer accepts, which goes to the sealed run. Everything after the
// ticket (escrow, sealing, the response) is runSealed's.

import {
    clampMaxOutput,
    defaultStoreFalse,
    dropEmptyTools,
    dropPromptCacheKey,
    dropRoutingPreferences,
} from '@txnlab/zs-proto/inject'
import {
    type Operator as SelectionOperator,
    MIN_SIGNER_SPENDABLE_MICROALGOS,
    RELAY_OFF,
    extractModel,
    extractRoutingPreferences,
    parseToolBudgets,
} from '@txnlab/zs-proto/selection'
import type { ReserveRequest } from '@txnlab/zs-proto/ticket'
import { BOUND_VERSION_2, inputTokenBoundVersion } from '@txnlab/zs-proto/tokenize'
import { SWEEPS, sweepDelayMs, wait } from '@txnlab/zs-proto/transient'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'

import { admitEstimate } from './admit.js'
import { newError } from './codes.js'
import { DuplicateTicketError, type Remedies, type SpendGuard } from './config.js'
import { ZsError, findError } from './errors.js'
import { type Estimate, type EstimatePolicy, MaxOutputRequiredError, estimate } from './estimate.js'
import { type ReserveSizeRejection, noFitMessage, reserveSizeFailureMessage } from './nofit.js'
import { type Operator, refOf, servesImageEdit, servesImageGen } from './operator.js'
import {
    BUSY_RETRIES,
    BUSY_RETRY_BUDGET_MS,
    TRANSIENT_RETRY_AFTER_HINT_MS,
    busyRetryWait,
    resolveUsePrivacy,
} from './pacing.js'
import type { ReserveClient, Reserved, WalletOpener } from './parts.js'
import {
    type PickDeps,
    type PickResult,
    bodyText,
    pickCandidates,
    poolMaxOutput,
    quoted,
    relayHopForPool,
    relayPool,
} from './pick.js'
import type { Clock, LogAttrs } from './ports.js'
import { parseImageEditMultipart, parseImageRequestN, streamableRequest } from './request-parse.js'
import { operatorPricingOf, verifyReservePrice } from './reserve-price.js'
import { reserveWithTransientRetry } from './reserve-retry.js'
import type { BusyError, PayerRefusalError, SizeError } from './reserve.js'
import { type RelayHop, relayRef, targetRef } from './routing/relay.js'
import { type ResweepReason, classifyReserveFailure, nextResweep, reserveRouteFor } from './routing/verdict.js'
import { type SizingRequest, capacityOf, effectiveMaxOutput, reserveInputCount } from './sizing.js'
import { sleep as sleepFor } from './sleep.js'
import type { Emitter, Turn } from './turn.js'
import { type Endpoint, type NodeRef, type Privacy, nodeRefString } from './types.js'

/**
 * The most images one request may budget per image tool. It bounds the
 * caller's max_n before it sizes the reserve: the node takes the counts as
 * given, and an unbounded one would let a caller size an absurd escrow. Go's
 * maxImageToolBudgetPerRequest.
 */
export const MAX_IMAGE_TOOL_BUDGET_PER_REQUEST = 64

/** What the sealed run needs from the reserve phase: a signed ticket the payer accepted, and how to reach its node. */
export interface SealedRun {
    endpoint: Endpoint
    model: string
    /** The body as shaped for the node: what the envelope seals and the admission tag commits to. */
    body: string | Uint8Array
    /** The node that signed, as the reserve last saw it: a re-probe may have refreshed it. */
    op: Operator
    reserved: Reserved
    stream: boolean
    /** The relay the reserve rode, which the inference forward must ride too. */
    hop: RelayHop | null
}

/**
 * RunSealed opens escrow on the ticket and runs the turn to its end through
 * em. The spend guard already holds the ticket's ceiling; the sealed run
 * releases it when the open fails.
 */
export type RunSealed = (em: Emitter, run: SealedRun, signal?: AbortSignal) => Promise<void>

/** Everything dispatch reads off the Client. */
export interface DispatchDeps {
    pick: PickDeps
    reserveClient: ReserveClient
    wallet: Pick<WalletOpener, 'payerAddr'>
    estimatePolicy: EstimatePolicy
    privacy: Privacy
    allowPrivacyOverride: boolean
    requireTeeModels: readonly string[]
    spendGuard?: SpendGuard | undefined
    remedies: Remedies
    /** The whole request's transient-retry budget, in milliseconds. */
    retryBudget: number
    sweepDelay?: ((sweep: number) => number) | undefined
    /** The cached protocol fee rate, never waiting: Go's feeRateNow. */
    feeRate(): number | null
    runSealed: RunSealed
    clock: Clock
    /** Waits ms, resolving false when signal aborts first. */
    sleep?: (ms: number, signal: AbortSignal | undefined) => Promise<boolean>
}

const opAttrs = (op: Operator): LogAttrs => ({ operator_id: op.id, node_id: op.nodeId })

// The relay a request rode, flat beside the target's ids; nothing for a direct route.
const relayAttrs = (hop: RelayHop | null): LogAttrs =>
    hop === null ? {} : { relay_operator_id: hop.relayId, relay_node_id: hop.relayNodeId }

const relayOf = (hop: RelayHop | null): NodeRef | null => (hop === null ? null : relayRef(hop))

const errText = (err: unknown): string => (err instanceof Error ? err.message : String(err))

// The inject mutators keep the body's type, through overloads a union can't pick.
type Mutator = { (b: string): string; (b: Uint8Array): Uint8Array }
const shape = (body: string | Uint8Array, f: Mutator): string | Uint8Array =>
    typeof body === 'string' ? f(body) : f(body)

// Go's zero Duration is no hint, so a 0 stays off the error.
const retryAfterOf = (ms: number): { retryAfter?: number } => (ms > 0 ? { retryAfter: ms } : {})

function routeCandidates(model: string, ops: readonly Operator[]) {
    return { type: 'route.candidates' as const, model, candidates: ops.map(refOf) }
}

/**
 * dispatch runs a turn's reserve phase, ending it through em: in em.fail, or
 * in runSealed once a node signs a ticket the payer accepts. If every
 * candidate is at capacity the turn fails unpaid with operators_busy and the
 * nodes' Retry-After.
 */
export async function dispatch(deps: DispatchDeps, em: Emitter, t: Turn, signal?: AbortSignal): Promise<void> {
    const log = deps.pick.logger
    const clock = deps.clock
    const sleep = deps.sleep ?? sleepFor
    const { endpoint } = t
    let body = t.body
    const isImage = endpoint === '/v1/images/generations'
    const isImageEdit = endpoint === '/v1/images/edits'

    // The caller's routing preferences, read before the body is shaped: the
    // `provider` object guides selection but never reaches the node. An image
    // edit is multipart, so it reads as the defaults.
    const routingPrefs = extractRoutingPreferences(bodyText(body))

    // Shaped before sealing, so the envelope and admission tag commit to what
    // the node forwards. Each leaves a body it can't parse as it was.
    if (!isImageEdit) {
        // `provider` is a payer-only hint a strict upstream would reject.
        body = shape(body, dropRoutingPreferences)
        // The caller's own store wins; an omitted one defaults to false.
        body = shape(body, defaultStoreFalse)
        // OpenAI tolerates an empty tools array; strict upstreams don't.
        body = shape(body, dropEmptyTools)
        // A session-stable cache key would join one payer's turns exactly.
        body = shape(body, dropPromptCacheKey)
    }

    let model: string
    let imageN = 0
    let imageSize = ''
    let imageQuality = ''
    let imageEditStream = false
    if (isImageEdit) {
        try {
            const r = parseImageEditMultipart(t.contentType, body)
            model = r.model
            imageN = r.n
            imageSize = r.size
            imageQuality = r.quality
            imageEditStream = r.stream
        } catch (err) {
            em.fail(newError('bad_image_edit_request', errText(err)))
            return
        }
    } else {
        model = extractModel(bodyText(body))
        if (model === '') {
            em.fail(newError('missing_model', 'request body has no model field'))
            return
        }
        if (isImage) {
            try {
                const r = parseImageRequestN(body)
                imageN = r.n
                imageSize = r.size
                imageQuality = r.quality
            } catch (err) {
                em.fail(newError('bad_image_request', errText(err)))
                return
            }
        }
    }

    // So a bounded refresh probes this model's servers first. Advisory.
    deps.pick.registry.recordModelDemand(model)

    const wantsStream = isImageEdit ? imageEditStream : streamableRequest(body)
    // Resolved ahead of the estimate: the max_output clamp reads the
    // ceilings of only the operators this request could reach.
    const requireTee = t.requireTee || deps.requireTeeModels.includes(model)

    let est: Estimate = { inputTokens: 0, maxOutputTokens: 0, deriveMaxOutput: false, maxOutputCeiling: 0 }
    if (!isImage && !isImageEdit) {
        // Lower an over-large max_output to what the pool can serve, before
        // the estimate reads it. It is an upper bound, not a demand: a caller
        // asking for more than any operator caps at is served by the most
        // generous one and escrows less, where left alone it would route
        // nowhere and read as a context-length miss.
        const ceiling = await poolMaxOutput(deps.pick, model, requireTee, routingPrefs, signal)
        const clamped = typeof body === 'string' ? clampMaxOutput(body, ceiling) : clampMaxOutput(body, ceiling)
        if (clamped.requested > 0n) {
            body = clamped.body
            // Otherwise a reply that stops at the lowered budget looks like
            // the model choosing to stop.
            em.clamped(ceiling)
            // Debug: a tool that hardcodes an over-large ceiling sends one on
            // every request.
            log.debug('lowered caller max_output_tokens to the pool ceiling', {
                model,
                requested: Number(clamped.requested),
                clamped_to: ceiling,
            })
        }
        try {
            est = estimate(model, body, deps.estimatePolicy)
        } catch (err) {
            if (err instanceof MaxOutputRequiredError) {
                em.fail(
                    newError(
                        'max_output_required',
                        'request omits max_tokens/max_completion_tokens/max_output_tokens and no default is configured for this model',
                    ),
                )
            } else {
                log.warn('tokenize failed', { endpoint, model, err: errText(err) })
                em.fail(newError('tokenize', 'input tokenization failed'))
            }
            return
        }
    }

    // Parsed and clamped once, then read by pickCandidates and the reserve.
    const toolBudgets = { generationMaxN: 0, editMaxN: 0 }
    if (!isImage && !isImageEdit) {
        const tb = parseToolBudgets(bodyText(body))
        toolBudgets.generationMaxN = Math.min(tb.generationMaxN, MAX_IMAGE_TOOL_BUDGET_PER_REQUEST)
        toolBudgets.editMaxN = Math.min(tb.editMaxN, MAX_IMAGE_TOOL_BUDGET_PER_REQUEST)
    }

    const sizing: SizingRequest = {
        model,
        inputTokens: est.inputTokens,
        maxOutputTokens: est.maxOutputTokens,
        // The same body under bound v2, so the filter charges a 9.2 operator
        // what the reserve will.
        inputTokensV2: inputTokenBoundVersion(body, BOUND_VERSION_2),
        deriveMaxOutput: est.deriveMaxOutput,
        maxOutputCeiling: est.maxOutputCeiling,
    }
    // The body's provider.relay outranks the caller's Request.relay. Turning
    // the relay off is honored only where the config allows overrides.
    const relayPref = routingPrefs.relay || t.relay
    const usePrivacy = resolveUsePrivacy(deps.privacy !== 'direct', deps.allowPrivacyOverride, relayPref)
    if (relayPref === RELAY_OFF && !deps.allowPrivacyOverride) {
        log.debug('ignoring relay=off override; allow_privacy_override is disabled', { endpoint })
    }

    const pickReq = { endpoint, model, body, sizing, requireTee, toolBudgets, prefs: routingPrefs }
    let pick: PickResult
    try {
        pick = await pickCandidates(deps.pick, pickReq, signal)
    } catch (err) {
        log.error('operator selection failed', { endpoint, model, err: errText(err) })
        em.fail(newError('registry', 'operator selection failed'))
        return
    }
    if (pick.operators.length === 0) {
        em.fail(emptyPickError(endpoint, model, sizing, pick))
        return
    }
    let candidates = pick.operators
    em.note(routeCandidates(model, candidates))

    // Before any reserve, so a request over the cap costs no node a
    // reservation. Image routes are priced per image and skip it.
    if (deps.spendGuard && !isImage && !isImageEdit) {
        const admit = admitEstimate(candidates, model, body, sizing, deps.feeRate())
        if (admit !== null) {
            try {
                deps.spendGuard.admit(admit)
            } catch (err) {
                log.warn('spend cap reached before reserve; refusing request', {
                    endpoint,
                    estimate_microusdc: admit,
                    err: errText(err),
                })
                em.fail(
                    newError(
                        'spend_cap_exceeded',
                        `spend cap reached (${errText(err)}): the cheapest available operator would escrow more than the limit allows. No reservation was made. To fix it, ${deps.remedies.raiseSpendCap}.`,
                    ),
                )
                return
            }
        }
    }

    // Sticky across sweeps. anyBusy is any 429, with or without a
    // Retry-After; busyHint is only the largest hint, so 0 doesn't mean
    // nobody was busy.
    let busyHint = 0
    let anyBusy = false
    // Nodes can refuse on limits their advertisement didn't expose; if every
    // candidate refuses for size, the caller gets that, not operators_busy.
    const reserveSizeRejections: ReserveSizeRejection[] = []
    // Privacy on and no eligible relay for a candidate: skipped, never sent direct.
    let relayUnavailable = false
    // A budgeted image tool the candidate's capacity doesn't price.
    let toolFactorMissing = false
    // No valid, unexpired ephemeral to seal to; there is no durable-key fallback.
    let ephemeralMissing = false
    // A signed ticket whose price failed the payer's verification.
    let priceRejected = false
    // The spend guard refused a candidate's signed ceiling; a later, cheaper one may fit.
    let capRefused = false
    // Built once: the pool is target-independent.
    let relaySel: SelectionOperator[] = []
    if (usePrivacy) relaySel = await relayPool(deps.pick, signal)
    // Gave up while every candidate failed through infrastructure rather than refusing.
    let transientExhausted = false
    // Any considered refusal that left no other record. The terminal
    // operators_unreachable asserts none refused, so this must veto it.
    let anyRefusal = false
    // The longest Retry-After a transient failure hinted: a gateway saying
    // when it is back outranks the fixed schedule.
    let transientHint = 0
    // Shared by the per-candidate rotation and the sweeps.
    const retryDeadline = clock() + deps.retryBudget
    // Much smaller: waiting out a fleet restart is worth a minute, a queue slot seconds.
    const busyDeadline = clock() + BUSY_RETRY_BUDGET_MS
    let busyRetriesLeft = BUSY_RETRIES
    // Why the previous pass asked for another, which picks this pass's wait.
    let resweep: ResweepReason = 'none'

    // Re-walks the whole list when every candidate failed transiently (a
    // fleet restart) or was at capacity. A considered refusal ends it: an
    // answer, not weather.
    for (let sweep = 0; sweep < SWEEPS; sweep++) {
        if (sweep > 0) {
            const w =
                resweep === 'busy'
                    ? busyRetryWait(sweep, busyHint, busyDeadline - clock(), deps.sweepDelay)
                    : wait(deps.sweepDelay ? deps.sweepDelay(sweep) : sweepDelayMs(sweep), transientHint, retryDeadline - clock())
            if (!w.ok || !(await sleep(w.delayMs, signal))) break
            // A node that finished restarting is eligible again. An error just
            // ends the sweeps with what is already known.
            let repick: PickResult
            try {
                repick = await pickCandidates(deps.pick, pickReq, signal)
            } catch {
                break
            }
            if (repick.operators.length === 0) break
            candidates = repick.operators
            em.note(routeCandidates(model, candidates))
            // So a relay this request just proved dead isn't drawn again at full weight.
            if (usePrivacy) relaySel = await relayPool(deps.pick, signal)
            if (resweep === 'busy') {
                log.info('every operator was at capacity; re-sweeping after the hinted wait', {
                    endpoint,
                    model,
                    sweep: sweep + 1,
                    candidates: candidates.length,
                    waited: w.delayMs,
                })
            } else {
                log.info('every operator failed transiently; re-sweeping the candidate list', {
                    endpoint,
                    model,
                    sweep: sweep + 1,
                    candidates: candidates.length,
                })
            }
        }
        // sweepRefused: some candidate gave a considered refusal, busy included.
        // sweepHardRefusal: refused for a reason waiting can't fix.
        let sweepTransient = false
        let sweepRefused = false
        let sweepBusy = false
        let sweepHardRefusal = false
        // No skip checks the affinity policy: under strict, pickCandidates has
        // already cut a pinned turn down to its one operator.
        for (const candidate of candidates) {
            if (signal?.aborted) break
            let op = candidate
            let hop: RelayHop | null = null
            if (usePrivacy) {
                hop = relayHopForPool(deps.pick, relaySel, op)
                if (hop === null) {
                    relayUnavailable = true
                    log.info('privacy mode: no eligible relay; skipping operator', { ...opAttrs(op), endpoint })
                    continue
                }
            }
            // The flat estimate, or the derivation from this operator's
            // capacity: the value the filter admitted it on.
            const requestFor = (o: Operator): ReserveCallRequest => {
                const maxOut = effectiveMaxOutput(o, sizing)
                const input = reserveInputCount(o, model, body, maxOut)
                const r: ReserveCallRequest = {
                    model,
                    input_count: input.count,
                    max_output_count: maxOut,
                    stream: wantsStream,
                }
                const payer = deps.wallet.payerAddr()
                if (payer !== '') r.payer_addr = payer
                // Names the bound that sized input_count, so the node
                // re-measures the same way. A pre-9.2 target is sent v1,
                // which it reads as its default.
                r.input_bound_version = input.boundVersion
                return r
            }
            let reserveReq = requestFor(op)
            if (isImage || isImageEdit) {
                // The node sizes a dedicated image route from these parameters
                // and its per-image rate, not from tokens.
                const mc = capacityOf(op, model)
                const serves = mc !== undefined && (isImage ? servesImageGen(mc) : servesImageEdit(mc))
                if (!serves) {
                    // Debug: an edit-only (or generation-only) model is legitimate.
                    log.debug(
                        isImage
                            ? 'operator does not serve image generation at reserve time; skipping'
                            : 'operator does not serve image edits at reserve time; skipping',
                        { ...opAttrs(op), ...relayAttrs(hop), model },
                    )
                    continue
                }
                reserveReq = imageRequest(reserveReq, imageN, imageSize, imageQuality, isImageEdit)
            }
            if (!isImage && !isImageEdit && (toolBudgets.generationMaxN > 0 || toolBudgets.editMaxN > 0)) {
                // The per-tool cap lives on the chat model's tool rates. A
                // candidate that publishes none can't size the budget: skipped,
                // remembered, and a 400 unsupported_tool if nothing else answered.
                const mc = capacityOf(op, model)
                if (toolBudgets.generationMaxN > 0 && (mc?.imageToolRateMicroUsdc ?? 0) === 0) {
                    toolFactorMissing = true
                    log.debug('operator missing image-tool pricing for chat-model image tool; skipping', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        model,
                    })
                    continue
                }
                if (toolBudgets.editMaxN > 0 && (mc?.imageEditToolRateMicroUsdc ?? 0) === 0) {
                    toolFactorMissing = true
                    log.debug('operator missing image-edit-tool pricing for chat-model image tool; skipping', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        model,
                    })
                    continue
                }
                reserveReq = withToolBudgets(reserveReq, toolBudgets.generationMaxN, toolBudgets.editMaxN)
            }
            // A re-probe can refresh op, and the bound version and max_output
            // are per-operator, so the retry re-sizes against the refreshed
            // one. The image routes carry no token sizing to redo. The price
            // check below reads the request as first built, as Go's does.
            const firstOp = op
            const firstReq = reserveReq
            const attemptRequest = (o: Operator): ReserveCallRequest => {
                if (o === firstOp || isImage || isImageEdit) return firstReq
                const r = requestFor(o)
                return toolBudgets.generationMaxN > 0 || toolBudgets.editMaxN > 0
                    ? withToolBudgets(r, toolBudgets.generationMaxN, toolBudgets.editMaxN)
                    : r
            }
            em.note({ type: 'relay.hop', relay: relayOf(hop), target: refOf(op), reason: 'chosen' })
            const attempt = await reserveWithTransientRetry<Operator, Reserved>({
                target: op,
                ref: refOf,
                hop,
                usePrivacy,
                deadlineMs: retryDeadline,
                attempt: (o, h) => deps.reserveClient.reserve(o, attemptRequest(o), h, signal),
                nextHop: (o, excluded) =>
                    relayHopForPool(
                        deps.pick,
                        relaySel.filter((s) => !excluded.has(nodeRefString({ op: s.id, node: s.node_id }))),
                        o,
                    ),
                reprobeEphemeral: (o) => deps.pick.registry.reprobeEphemeral(o, signal),
                recordRelayFailure: (h) => deps.pick.relayReputation?.recordRelayOutcome(relayRef(h), false),
                note: (ev) => em.note(ev),
                ...(signal ? { signal } : {}),
                clock,
                sleep,
            })
            op = attempt.target
            hop = attempt.hop
            const rt = attempt.result
            if (rt !== undefined) {
                // This node served us: it returns to the preferred tier now
                // rather than serving out a backoff it just disproved.
                deps.pick.targetBackoff?.recordTargetOutcome(refOf(op), true)
                // The succeeding attempt's round trip alone: a clean network
                // RTT for the path it rode.
                const latency = deps.pick.relayLatency
                if (latency) {
                    if (hop !== null) latency.recordRelayedRtt(relayRef(hop), targetRef(hop), attempt.elapsedMs)
                    else latency.recordDirectRtt(refOf(op), attempt.elapsedMs)
                }
                // Refuse a mis-priced ticket before escrowing against it.
                // Another operator may be honest, so it is skipped like a
                // size rejection. Fails open with no reference.
                const v = await verifyReservePrice({
                    ticket: rt.ticket,
                    pricing: operatorPricingOf(op, model),
                    feeBps: async () => deps.feeRate(),
                    reserveInputCount: firstReq.input_count,
                    imageToolBudget: firstReq.image_tool_budget ?? 0,
                    imageEditToolBudget: firstReq.image_edit_tool_budget ?? 0,
                })
                if (v !== null) {
                    priceRejected = true
                    log.warn('reserve refused: ticket price failed verification; trying next operator', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        check: v.check,
                        field: v.field,
                        allowed: v.want,
                        signed: v.got,
                    })
                    continue
                }
                logReserve(log, op, hop, rt)
                // Bounds the aggregate drain before money moves. The next
                // candidate may be cheaper, and this ticket just expires unopened.
                if (deps.spendGuard) {
                    try {
                        deps.spendGuard.reserve(rt.ticket.ticket_id, rt.ticket.max_price)
                    } catch (err) {
                        // The operator reused a ticket id it already handed
                        // out, which no local config can fix: not a cap breach.
                        if (findError(err, DuplicateTicketError) !== undefined) {
                            log.warn('operator reused a ticket id; refusing request', {
                                endpoint,
                                ...opAttrs(op),
                                ...relayAttrs(hop),
                                ticket_id: rt.ticket.ticket_id,
                                err: errText(err),
                            })
                            em.fail(
                                newError(
                                    'operator_ticket_reuse',
                                    'the operator issued a ticket id that is already in flight for this payer; no payment was made',
                                ),
                            )
                            return
                        }
                        capRefused = true
                        sweepRefused = true
                        sweepHardRefusal = true
                        log.info("spend cap: this operator's ticket is over the limit; trying next operator", {
                            endpoint,
                            ...opAttrs(op),
                            ...relayAttrs(hop),
                            max_price_microusdc: rt.ticket.max_price,
                            err: errText(err),
                        })
                        continue
                    }
                }
                await deps.runSealed(em, { endpoint, model, body, op, reserved: rt, stream: wantsStream, hop }, signal)
                return
            }

            const err = attempt.err
            const f = classifyReserveFailure(err, reserveRouteFor(err, hop, signal), usePrivacy)
            if (f.strike) deps.pick.targetBackoff?.recordTargetOutcome(refOf(op), false)
            sweepRefused ||= f.refused
            sweepHardRefusal ||= f.hardRefused
            sweepBusy ||= f.busyResweepable
            sweepTransient ||= f.transient
            anyBusy ||= f.busy
            ephemeralMissing ||= f.ephemeralMissing
            switch (f.outcome) {
                case 'busy': {
                    if (f.hintMs > busyHint) busyHint = f.hintMs
                    const be = err as BusyError
                    log.info('operator busy; trying next', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        endpoint,
                        code: be.code,
                        resweepable: f.busyResweepable,
                        retry_after: be.retryAfterMs,
                    })
                    break
                }
                case 'size': {
                    // Info: the request's shape, not the operator's fault.
                    const se = err as SizeError
                    reserveSizeRejections.push({ operatorId: op.id, code: se.code, message: se.nodeMessage })
                    log.info('operator refused for sizing; trying next', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        endpoint,
                        code: se.code,
                    })
                    break
                }
                case 'payer_refusal': {
                    // Every node would refuse this payer alike, and iterating
                    // would misreport it as congestion. The node's own code
                    // and message name the limit and when it resets.
                    const pr = err as PayerRefusalError
                    log.info('payer-scoped refusal; not trying other operators', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        endpoint,
                        code: pr.code,
                    })
                    // The kind is set here, not looked up, so a refusal code
                    // without an errorKinds entry still reads as funds.
                    em.fail(
                        new ZsError({ kind: 'funds', code: pr.code, message: pr.nodeMessage, ...retryAfterOf(pr.retryAfterMs) }),
                    )
                    return
                }
                case 'no_ephemeral':
                    // Debug: a rotation gap trips this routinely. No key bytes logged.
                    log.debug('operator has no valid ephemeral recipient; skipping', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        endpoint,
                    })
                    break
                case 'transient':
                    // The rotation is spent, but this is still weather.
                    if (f.hintMs > transientHint) transientHint = f.hintMs
                    log.warn('operator unreachable through infrastructure; trying next operator', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        endpoint,
                        attribution: f.attribution,
                        err: errText(err),
                    })
                    break
                default:
                    log.warn('reserve failed; trying next operator', {
                        ...opAttrs(op),
                        ...relayAttrs(hop),
                        endpoint,
                        err: errText(err),
                    })
            }
        }

        // Sticky, so a refusal in a later sweep outranks an earlier sweep of
        // pure weather at the terminal ladder.
        if (sweepRefused) anyRefusal = true
        resweep = nextResweep({
            transient: sweepTransient,
            refused: sweepRefused,
            busy: sweepBusy,
            hardRefused: sweepHardRefusal,
            sizeRejected: reserveSizeRejections.length > 0,
            anyBusy,
            relayUnavailable,
            toolFactorMissing,
            ephemeralMissing,
            priceRejected,
            busyBudgetLeft: busyRetriesLeft > 0 && clock() < busyDeadline,
        })
        // Busy doesn't set transientExhausted: the pool is reachable and full,
        // so the terminal error stays operators_busy.
        if (resweep === 'weather') transientExhausted = true
        else if (resweep === 'busy') busyRetriesLeft--
        if (resweep === 'none') break
    }

    // The caller left mid-sweep, and the answers so far are half of one.
    if (signal?.aborted) {
        em.fail(newError('canceled', 'the request ended before any operator was paid', { cause: signal.reason }))
        return
    }
    // A size refusal at reserve or by the filter is the actionable answer:
    // no amount of waiting fits this request to these operators.
    if (reserveSizeRejections.length > 0 || pick.sizingMisses.length > 0) {
        em.fail(
            newError(
                'context_length_exceeded',
                reserveSizeFailureMessage(model, sizing, reserveSizeRejections, pick.sizingMisses),
            ),
        )
        return
    }
    // No candidate could price a budgeted image tool. A busy, relay-gapped or
    // capped candidate passed that gate, so it proves the tool serviceable,
    // and its retryable outcome wins.
    if (toolFactorMissing && !anyBusy && !relayUnavailable && !capRefused) {
        em.fail(
            newError(
                'unsupported_tool',
                `no operator serves a built-in image tool for model ${model} — the model does not advertise an image-tool factor`,
            ),
        )
        return
    }
    // A privacy-fleet gap, told apart from capacity. Never routed direct.
    if (relayUnavailable) {
        em.fail(
            newError(
                'no_relay_available',
                'transport-privacy mode is enabled but no eligible relay operator is available for the selected target(s)',
            ),
        )
        return
    }
    // A busy candidate may fit once a slot frees; without one, waiting lowers no ceiling.
    if (capRefused && !anyBusy) {
        em.fail(
            newError(
                'spend_cap_exceeded',
                `spend cap reached: this request would exceed the configured USDC limit — to fix it, ${deps.remedies.raiseSpendCap}.`,
            ),
        )
        return
    }
    // A forward-secrecy posture gap, told apart from capacity.
    if (ephemeralMissing && !anyBusy && !relayUnavailable) {
        em.fail(
            newError(
                'no_ephemeral_capacity',
                'no operator with a valid forward-secrecy ephemeral recipient can serve this request',
            ),
        )
        return
    }
    // Operator misbehaviour that a retry won't fix.
    if (priceRejected && !anyBusy && !relayUnavailable) {
        em.fail(
            newError(
                'ticket_price_rejected',
                'every eligible operator returned a ticket whose price failed verification (mis-priced or internally inconsistent)',
            ),
        )
        return
    }
    // The fleet-restart signature: unreachable, not full, and nobody refused.
    // operators_busy here would invite a retry storm at the wrong moment.
    if (transientExhausted && !anyRefusal && !anyBusy && !relayUnavailable) {
        em.fail(
            newError(
                'operators_unreachable',
                `every operator serving ${model} is currently unreachable through its gateway, and none refused the request; this usually clears within a minute — retry after the hint`,
                { retryAfter: TRANSIENT_RETRY_AFTER_HINT_MS },
            ),
        )
        return
    }
    em.fail(newError('operators_busy', 'all eligible operators are at capacity; retry after the hint', retryAfterOf(busyHint)))
}

/** ReserveCallRequest is what dispatch hands the ReserveClient. */
type ReserveCallRequest = Omit<ReserveRequest, 'proxy_recipient' | 'payer_sig' | 'payer_issued_at'>

// A dedicated image reserve: token sizing off, the image parameters on. Zero
// fields stay off, as Go's omitempty. The bound version stays, as in Go.
function imageRequest(r: ReserveCallRequest, n: number, size: string, quality: string, edit: boolean): ReserveCallRequest {
    const out: ReserveCallRequest = { ...r, input_count: 0, max_output_count: 0 }
    if (n !== 0) out.image_n = n
    if (size !== '') out.image_size = size
    if (quality !== '') out.image_quality = quality
    if (edit) out.image_edit = true
    return out
}

function withToolBudgets(r: ReserveCallRequest, gen: number, edit: number): ReserveCallRequest {
    const out: ReserveCallRequest = { ...r }
    if (gen !== 0) out.image_tool_budget = gen
    if (edit !== 0) out.image_edit_tool_budget = edit
    return out
}

function logReserve(log: PickDeps['logger'], op: Operator, hop: RelayHop | null, rt: Reserved): void {
    const t = rt.ticket
    const attrs: LogAttrs = {
        ...opAttrs(op),
        ...relayAttrs(hop),
        ticket_id: t.ticket_id,
        model: t.model,
        input_tokens: t.input_count,
        max_output_tokens: t.max_output_count,
        input_rate_microusdc_per_1m: t.input_rate,
        output_rate_microusdc_per_1m: t.output_rate,
        cache_read_rate_microusdc_per_1m: t.cache_read_rate,
        max_price_microusdc: t.max_price,
        stream: t.stream,
        expires_at: new Date(t.expires_at * 1000).toISOString(),
        // microUSDC, so independent of the ALGO/USD oracle.
        max_price_usd: `$${(t.max_price / 1_000_000).toFixed(6)}`,
    }
    if (rt.algoUsdPrice > 0) attrs.algo_usd = rt.algoUsdPrice
    log.debug('reserve response', attrs)
}

// The refusal for a request no candidate survived selection for, most
// specific cause first.
function emptyPickError(endpoint: Endpoint, model: string, sizing: SizingRequest, pick: PickResult): ZsError {
    const q = quoted(model)
    if (pick.versionBlocked) {
        // Upgrade required: retrying against the same fleet keeps failing.
        return newError(
            'no_compatible_operator',
            `no operator advertises a compatible wire protocol version (${PROTO_VERSION})`,
        )
    }
    if (pick.teeBlocked) {
        return newError('no_tee_capacity', 'no operator with current TEE attestation can serve this request')
    }
    if (pick.stagingBlocked) {
        return newError(
            'no_production_operator',
            `the model ${q} is only served by staging nodes; allow routing to staging nodes to reach them`,
        )
    }
    if (pick.signerUnderfundedBlocked) {
        // Clears when an operator tops up; there is no knob the payer can turn.
        const msg =
            pick.signerUnderfundedReason ||
            `every node serving the model ${q} has less than ${Math.floor(MIN_SIGNER_SPENDABLE_MICROALGOS / 1_000_000)} ALGO spendable in its signing account to pay network fees; retry later or pick another model`
        return newError('no_funded_operator', msg)
    }
    if (pick.registryCount === 0) {
        // The most common miss, and the model id is safe to name.
        return newError('no_operator', `no operator is currently advertising the model ${q}`)
    }
    if (pick.imageEndpointUnsupported) {
        const which = endpoint === '/v1/images/generations' ? 'image generation' : 'image edits'
        return newError('no_operator', `no operator advertises ${model} for ${which}`)
    }
    if (pick.affinityBlocked) {
        // Relocating a pinned conversation silently would corrupt its state,
        // so the real reason, not a pool-wide context miss.
        const msg =
            pick.affinityBlockReason ||
            `strict affinity target cannot serve ${model} with input_tokens=${sizing.inputTokens} max_output_tokens=${sizing.maxOutputTokens}; reduce prompt size or switch affinity_policy to "prefer"`
        return newError('context_length_exceeded', msg)
    }
    if (pick.pinConflict) return newError('pin_conflicts_with_continuation', pick.pinConflictReason)
    if (pick.providerPinBlocked) {
        return newError(
            'no_pinned_operator',
            `no operator matching your provider preferences is currently available to serve ${model}; adjust provider.only / provider.order or remove the pin`,
        )
    }
    if (pick.priceBlocked) {
        return newError(
            'price_ceiling_exceeded',
            `no operator serves ${model} within your provider.max_price ceiling; raise or remove the ceiling`,
        )
    }
    if (pick.toolUnsupported) {
        return newError(
            'no_tool_capacity',
            `no operator advertises every requested built-in tool for ${model} (provider.require_tools is set)`,
        )
    }
    // Operators serve the model but none fits the request: the prompt, not availability.
    return newError('context_length_exceeded', noFitMessage(model, sizing, pick.sizingMisses))
}
