/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The discovery probe: GET /v1/zs/details, directly or through a relay hop,
// and the relay rotation around it. Mirrors proto/go/zs's DetailsClient
// (details.go) and probeDetailsWithRetry (fetcher.go); SPEC § 3c is the
// response, § 3f and § 10 the attribution.
//
// Differences from Go, all because this side parses in TypeScript: the body
// is read by zs-proto's parseOperatorDetails, which drops a malformed field
// where Go's decoder rejects the whole body, so DetailsBodyError is only a body
// that won't read or isn't a JSON object. And the caller's abort is rethrown as
// is rather than folded into a hop error, since a TypeScript caller tells an
// abort apart by its own signal.

import { type OperatorDetails, parseOperatorDetails } from '@txnlab/zs-proto/inject'
import { RelayErrorCode, isHopErrorCode } from '@txnlab/zs-proto/relay'
import { isRelayFrontDoorStatus } from '@txnlab/zs-proto/transient'
import { RELAY_HOP_HEADER, setsRelayHopHeader } from '@txnlab/zs-proto/wire'

import { defaults } from './config.js'
import { readLimited } from './http.js'
import type { Clock, Fetch, Logger } from './ports.js'
import { discardLogger } from './ports.js'
import type { RelayHealthStore } from './routing/health.js'
import type { RelayLatencyStore } from './routing/latency.js'
import { type RelayHop, applyRelay, relayRef, targetRef } from './routing/relay.js'
import type { RelayReputationStore } from './routing/reputation.js'
import { type NodeRef, nodeRefString } from './types.js'

export const DETAILS_PATH = '/v1/zs/details'

/** DEFAULT_DETAILS_TIMEOUT_MS is Go's DefaultDetailsFetchTimeout. */
export const DEFAULT_DETAILS_TIMEOUT_MS = defaults.discovery.detailsTimeout

/**
 * MAX_DISCOVERY_RELAY_ATTEMPTS bounds the relays one probe tries, as Go's
 * maxDiscoveryRelayAttempts: a fleet-wide relay outage must not turn one probe
 * into a timeout per relay.
 */
export const MAX_DISCOVERY_RELAY_ATTEMPTS = 3

// A relay's error body is a short OpenAI-shaped object; Go reads this much of it.
const MAX_RELAY_ERROR_BYTES = 8 << 10

/**
 * One relay a probe gave up on, and why: no response from it (unreachable), a
 * relay error or front-door status (hop), the probe's own deadline (timeout),
 * or its claim that the target was down (upstream-unreachable).
 */
export interface RelayAttempt {
    relay: NodeRef
    relayUrl: string
    reason: 'unreachable' | 'hop' | 'timeout' | 'upstream-unreachable'
}

/**
 * RelayHopError is a relayed probe that failed at the relay, never reaching the
 * target: the relay couldn't be reached, answered with a relay_* hop code, or
 * (a relay that marks its hops) its front door answered a transient status
 * without the hop marker. The target's status is unknown.
 */
export class RelayHopError extends Error {
    override readonly name = 'RelayHopError'
    readonly relay: NodeRef
    readonly relayUrl: string
    /** No response arrived at all, so the relay's endpoint is down from here. */
    readonly transport: boolean
    /**
     * The probe's own deadline ended it. That says nothing about either hop
     * (SPEC § 10): a relay is silent while it waits on a slow target.
     */
    readonly timedOut: boolean
    /** Set on the error a probe gives up with: every relay it tried. */
    attempts?: readonly RelayAttempt[]

    constructor(
        hop: RelayHop,
        message: string,
        opts: { transport?: boolean; timedOut?: boolean; cause?: unknown } = {},
    ) {
        super(`relay hop (operator ${hop.relayId}, node ${hop.relayNodeId}, ${hop.baseUrl}): ${message}`, {
            cause: opts.cause,
        })
        this.relay = relayRef(hop)
        this.relayUrl = hop.baseUrl
        this.transport = opts.transport ?? false
        this.timedOut = opts.timedOut ?? false
    }
}

/**
 * RelayUpstreamUnreachableError is a relay's claim (relay_upstream_unreachable)
 * that it reached out and the target was down. The relay works, but one
 * relay's view proves little, so a probe rotates past it; given up on, it is
 * the target's failure.
 */
export class RelayUpstreamUnreachableError extends Error {
    override readonly name = 'RelayUpstreamUnreachableError'
    readonly relay: NodeRef
    readonly relayUrl: string
    readonly status: number
    /** Set on the error a probe gives up with: every relay it tried. */
    attempts?: readonly RelayAttempt[]

    constructor(hop: RelayHop, status: number) {
        super(
            `relay (operator ${hop.relayId}, node ${hop.relayNodeId}, ${hop.baseUrl}) could not reach the target: ${status} ${RelayErrorCode.UpstreamUnreachable}`,
        )
        this.relay = relayRef(hop)
        this.relayUrl = hop.baseUrl
        this.status = status
    }
}

/** DetailsHTTPError is the target's own error status, directly or forwarded by a relay. */
export class DetailsHTTPError extends Error {
    override readonly name = 'DetailsHTTPError'
    readonly status: number

    constructor(status: number) {
        super(`details endpoint returned ${status}`)
        this.status = status
    }
}

/** DetailsBodyError is a 2xx whose body won't read or isn't a JSON object. The target answered. */
export class DetailsBodyError extends Error {
    override readonly name = 'DetailsBodyError'
}

/** DetailsTransportError is a direct probe that got no response from the target. */
export class DetailsTransportError extends Error {
    override readonly name = 'DetailsTransportError'
    /** The probe's own deadline ended it. */
    readonly timedOut: boolean

    constructor(timedOut: boolean, cause: unknown) {
        super(`details request: ${cause instanceof Error ? cause.message : String(cause)}`, { cause })
        this.timedOut = timedOut
    }
}

/**
 * detailsQuery is the ?model=&expand= suffix of a per-model deep probe (SPEC §
 * 3c), or '' for the lean probe.
 */
export function detailsQuery(model?: string, expand: readonly string[] = []): string {
    if (!model && expand.length === 0) return ''
    const q = new URLSearchParams()
    if (model) q.set('model', model)
    if (expand.length > 0) q.set('expand', expand.join(','))
    return `?${q.toString()}`
}

export interface DetailsCall {
    /** The target node's root. */
    baseUrl: string
    /** The relay to probe through; null or absent probes directly. */
    hop?: RelayHop | null
    /** Scopes the probe to one model (SPEC § 3c deep details). */
    model?: string
    /** Field groups to expand on a deep probe (coordinates, digest). */
    expand?: readonly string[]
    fetch: Fetch
    /** Bounds the probe; DEFAULT_DETAILS_TIMEOUT_MS when absent. */
    timeoutMs?: number
    signal?: AbortSignal
}

/**
 * fetchDetails probes one node's details, directly or through call.hop, and
 * returns the parsed advertisement. A failure throws one of RelayHopError,
 * RelayUpstreamUnreachableError, DetailsHTTPError, DetailsBodyError or
 * DetailsTransportError, or the caller's abort reason when call.signal fired.
 */
export async function fetchDetails(call: DetailsCall): Promise<OperatorDetails> {
    const base = call.baseUrl.replace(/\/+$/, '')
    if (base === '') throw new Error('empty operator base_url')
    const hop = call.hop ?? null
    const innerPath = DETAILS_PATH + detailsQuery(call.model, call.expand)
    const req = applyRelay(hop, base + innerPath, 'GET', { Accept: 'application/json' }, innerPath)
    const timeout = AbortSignal.timeout(call.timeoutMs ?? DEFAULT_DETAILS_TIMEOUT_MS)
    const signal = call.signal ? AbortSignal.any([call.signal, timeout]) : timeout

    let resp: Response
    try {
        resp = await call.fetch(req.url, {
            method: req.method,
            headers: req.headers,
            signal,
            // The advertisement carries the node's rotating ephemeral seal key;
            // an HTTP cache serving a frozen copy would keep a rotated key from
            // ever landing.
            cache: 'no-store',
        })
    } catch (err) {
        if (call.signal?.aborted) throw call.signal.reason
        if (hop !== null) {
            throw new RelayHopError(hop, `details request: ${message(err)}`, {
                transport: !timeout.aborted,
                timedOut: timeout.aborted,
                cause: err,
            })
        }
        throw new DetailsTransportError(timeout.aborted, err)
    }

    if (resp.status >= 400) {
        if (hop !== null) {
            let raw: Uint8Array
            try {
                raw = await readLimited(resp, MAX_RELAY_ERROR_BYTES)
            } catch (err) {
                if (call.signal?.aborted) throw call.signal.reason
                // Ended mid-body: a relay code and the target's own error are
                // indistinguishable, so blame neither.
                if (timeout.aborted) {
                    throw new RelayHopError(hop, `read relay error body for ${resp.status}: ${message(err)}`, {
                        timedOut: true,
                        cause: err,
                    })
                }
                raw = new Uint8Array()
            }
            const code = relayErrorCode(raw)
            if (isHopErrorCode(code)) {
                throw new RelayHopError(hop, `relay returned ${resp.status} (code ${code})`)
            }
            if (code === RelayErrorCode.UpstreamUnreachable) {
                throw new RelayUpstreamUnreachableError(hop, resp.status)
            }
            // The relay's own front door: a front-door status, unmarked, from a
            // relay that marks every response its handler produces. Status
            // first, ahead of any code a front door writes itself, as Go's
            // details.go: this only picks rotate over blame-the-target, and
            // never flips retryability as NarrowRelayed would.
            if (
                isRelayFrontDoorStatus(resp.status) &&
                setsRelayHopHeader(hop.relayProtoVersion) &&
                // Empty counts as unmarked, as in Go and reserve.ts.
                !resp.headers.get(RELAY_HOP_HEADER)
            ) {
                throw new RelayHopError(
                    hop,
                    `relay front door returned ${resp.status} with no protocol code and no ${RELAY_HOP_HEADER}`,
                )
            }
        } else {
            await resp.body?.cancel().catch(() => {})
        }
        throw new DetailsHTTPError(resp.status)
    }

    let raw: Uint8Array
    try {
        raw = await readLimited(resp)
    } catch (err) {
        if (call.signal?.aborted) throw call.signal.reason
        // A deadline mid-body is a slow read, not a body the target got wrong.
        if (timeout.aborted) {
            if (hop !== null) {
                throw new RelayHopError(hop, `read details body: ${message(err)}`, { timedOut: true, cause: err })
            }
            throw new DetailsTransportError(true, err)
        }
        throw new DetailsBodyError(`read details body: ${message(err)}`, { cause: err })
    }
    let body: unknown
    try {
        body = JSON.parse(new TextDecoder().decode(raw))
    } catch (err) {
        throw new DetailsBodyError(`decode details: ${message(err)}`, { cause: err })
    }
    const details = parseOperatorDetails(body)
    if (details === null) throw new DetailsBodyError('decode details: not a JSON object')
    return details
}

/** The routing stores a probe reports to. A Client passes its own. */
export interface DetailsProbeStores {
    health: Pick<RelayHealthStore, 'markRelayUnreachable' | 'markRelayReachable' | 'recordRelayTransportFailure'>
    reputation: Pick<RelayReputationStore, 'recordRelayOutcome' | 'recordRelayUpstreamUnreachable'>
    latency: Pick<RelayLatencyStore, 'recordRelayedRtt' | 'recordDirectRtt'>
}

export interface DetailsProbe {
    baseUrl: string
    /** The node probed, which a relay hop must name. */
    target: NodeRef
    /** The first relay, or null to probe directly. */
    hop: RelayHop | null
    /**
     * nextHop picks another relay for target, avoiding the excluded relays
     * (nodeRefString keys); null when none is left. Without it a failed relay
     * ends the probe.
     */
    nextHop?: (excluded: ReadonlySet<string>) => RelayHop | null
    stores: DetailsProbeStores
    fetch: Fetch
    timeoutMs?: number
    signal?: AbortSignal
    /** Times the round trip for the latency store. Date.now when absent. */
    clock?: Clock
    /** MAX_DISCOVERY_RELAY_ATTEMPTS when absent. */
    maxRelayAttempts?: number
    logger?: Logger
}

export interface DetailsProbeResult {
    details: OperatorDetails
    /** The relay that carried the probe, or null for a direct one. */
    hop: RelayHop | null
}

/**
 * probeDetails probes the target's details. Directly it is one fetchDetails.
 * Through relays it rotates past a relay that failed the hop, and past one that
 * said the target was down (relay_upstream_unreachable: the mesh can be
 * partitioned, so one relay's view proves little), recording each relay's
 * outcome in the stores.
 *
 * It throws what fetchDetails throws. Given up on, it throws a
 * RelayUpstreamUnreachableError when any relay that worked said the target was
 * down (the target's failure), and otherwise the last RelayHopError (the
 * target's status is unknown), either carrying every relay tried in attempts.
 */
export async function probeDetails(p: DetailsProbe): Promise<DetailsProbeResult> {
    const clock = p.clock ?? Date.now
    const log = p.logger ?? discardLogger
    const call: DetailsCall = {
        baseUrl: p.baseUrl,
        fetch: p.fetch,
        ...(p.timeoutMs !== undefined ? { timeoutMs: p.timeoutMs } : {}),
        ...(p.signal !== undefined ? { signal: p.signal } : {}),
    }

    if (p.hop === null) {
        const start = clock()
        const details = await fetchDetails({ ...call, hop: null })
        p.stores.latency.recordDirectRtt(p.target, clock() - start)
        return { details, hop: null }
    }

    const max = Math.max(1, Math.floor(p.maxRelayAttempts ?? MAX_DISCOVERY_RELAY_ATTEMPTS) || 1)
    const excluded = new Set<string>()
    const attempts: RelayAttempt[] = []
    let lastHopErr: RelayHopError | undefined
    let upstreamErr: RelayUpstreamUnreachableError | undefined
    const claimers: RelayHop[] = []
    // Scores the relays that said the target was down, using what this probe
    // saw where it can. Scoring each claim as it came, against the previous
    // view of the target, would strike every honest relay the probe rotates
    // through when a target that was up has just gone down.
    const settleClaims = (reached: boolean): void => {
        for (const c of claimers) {
            if (reached) {
                // Another relay reached the target: the claim was wrong.
                p.stores.reputation.recordRelayOutcome(relayRef(c), false)
            } else if (claimers.length > 1) {
                // Working relays agree the target is down.
                p.stores.reputation.recordRelayOutcome(relayRef(c), true)
            } else {
                // One uncorroborated claim: judge it by our last view.
                p.stores.reputation.recordRelayUpstreamUnreachable(relayRef(c), targetRef(c))
            }
        }
    }
    const giveUp = (): never => {
        settleClaims(false)
        const err = upstreamErr ?? lastHopErr!
        err.attempts = attempts
        throw err
    }

    let hop: RelayHop | null = p.hop
    for (let attempt = 0; attempt < max && hop !== null; attempt++) {
        if (hop.targetId !== p.target.op || hop.targetNodeId !== p.target.node) {
            throw new Error(
                `relay hop names node (${hop.targetId}, ${hop.targetNodeId}), not the probed (${p.target.op}, ${p.target.node})`,
            )
        }
        const relay = relayRef(hop)
        const start = clock()
        try {
            const details = await fetchDetails({ ...call, hop })
            relayForwarded(p.stores, hop, clock() - start)
            settleClaims(true)
            return { details, hop }
        } catch (err) {
            if (err instanceof RelayHopError) {
                if (err.transport) {
                    p.stores.health.recordRelayTransportFailure(relay)
                } else if (!err.timedOut) {
                    p.stores.health.markRelayUnreachable(relay)
                    p.stores.reputation.recordRelayOutcome(relay, false)
                }
                const reason = err.transport ? 'unreachable' : err.timedOut ? 'timeout' : 'hop'
                attempts.push({ relay, relayUrl: hop.baseUrl, reason })
                lastHopErr = err
            } else if (err instanceof RelayUpstreamUnreachableError) {
                // A claim about the target, scored when the probe resolves. Not
                // a health mark: the relay answered us fine.
                claimers.push(hop)
                attempts.push({ relay, relayUrl: hop.baseUrl, reason: 'upstream-unreachable' })
                upstreamErr = err
            } else if (err instanceof DetailsHTTPError || err instanceof DetailsBodyError) {
                // The target answered through this relay. A 2xx credits the
                // relay, whatever the body.
                if (err instanceof DetailsBodyError) relayForwarded(p.stores, hop, clock() - start)
                settleClaims(true)
                throw err
            } else {
                // The caller's abort: nothing more was learned.
                settleClaims(false)
                throw err
            }
        }
        excluded.add(nodeRefString(relay))
        if (attempt + 1 >= max) break
        hop = p.nextHop?.(excluded) ?? null
        if (hop !== null) {
            log.debug('relay failed the details probe; retrying through a different relay', {
                operator_id: p.target.op,
                node_id: p.target.node,
                failed_relay_operator_id: relay.op,
                failed_relay_node_id: relay.node,
                relay_operator_id: hop.relayId,
                relay_node_id: hop.relayNodeId,
            })
        }
    }
    return giveUp()
}

function relayForwarded(stores: DetailsProbeStores, hop: RelayHop, rttMs: number): void {
    const relay = relayRef(hop)
    stores.health.markRelayReachable(relay)
    stores.reputation.recordRelayOutcome(relay, true)
    stores.latency.recordRelayedRtt(relay, targetRef(hop), rttMs)
}

// relayErrorCode reads the OpenAI-shaped error.code off a relay's error body,
// or '' when the body isn't that shape: a relay forwards the target's own error
// verbatim, and those never carry a relay_ code.
function relayErrorCode(raw: Uint8Array): string {
    try {
        const parsed: unknown = JSON.parse(new TextDecoder().decode(raw))
        const code = (parsed as { error?: { code?: unknown } } | null)?.error?.code
        return typeof code === 'string' ? code : ''
    } catch {
        return ''
    }
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
