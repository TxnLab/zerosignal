/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Single-hop relay routing (SPEC §3f), mirroring proto/go/zs/relayrouter.go.
// Eligibility comes from the shared selection policy; this layer adds the
// latency-weighted pick within the eligible pool and the request rewrite onto
// the relay's /v1/zs/relay route. The relay never decrypts: the body stays
// sealed to the target.

import { buildRequest } from '@txnlab/zs-proto/relay'
import { type Operator as SelectionOperator, eligibleRelays } from '@txnlab/zs-proto/selection'
import {
    RELAY_METHOD_HEADER,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
} from '@txnlab/zs-proto/wire'

import { type NodeRef, nodeRefString } from '../types.js'

/**
 * RelayHop is one chosen relay indirection, mirroring Go's RelayHop. The relay
 * is a single node, so a failed hop is recorded against (relayId, relayNodeId)
 * and never against the relay operator's other nodes.
 */
export interface RelayHop {
    /** The relay node's root, where the relay route lives. */
    baseUrl: string
    targetId: number
    /** Sent in X-Zs-Relay-Target-Node so the relay forwards to the node the payer reserved against. */
    targetNodeId: number
    relayId: number
    relayNodeId: number
    /**
     * The proto_version this relay advertised at discovery, so a
     * response-attribution site can apply the relay-hop-header rule without a
     * catalog lookup. Never a bootstrap-seeded value: that would credit an
     * unprobed peer with a header nobody established it can set.
     */
    relayProtoVersion: string
}

export function relayRef(h: RelayHop): NodeRef {
    return { op: h.relayId, node: h.relayNodeId }
}

export function targetRef(h: RelayHop): NodeRef {
    return { op: h.targetId, node: h.targetNodeId }
}

/**
 * The additive bias in the inverse-latency weight 1 / (latency + bias). It
 * keeps a near-zero latency from taking a runaway weight and damps the
 * preference between relays that are already fast: 5ms against 10ms is 55
 * against 60, a few percent, not 2x.
 */
export const LATENCY_WEIGHT_BIAS_MS = 50

/**
 * The share of selection mass spread evenly over every eligible relay
 * regardless of latency. It caps one relay's per-request share at about
 * (1 − FLOOR) + FLOOR/n and floors every relay at FLOOR/n, which is what keeps
 * §3f's anti-profiling diffusion meaningful under a large latency gap: without
 * it a 100x-faster relay takes ~98% of a target's traffic.
 *
 * The cap is also the most one relay can capture by gaming its measured RTT,
 * so it doubles as the adversarial capture bound. To hold any relay to at most
 * a share C of a target's requests (C ≥ 1/n):
 *
 *     FLOOR ≈ (1 − C) · n/(n−1), clamped to ≤ 1
 *
 *     ceiling C │ n=4   n=10  n=100
 *        25%    │ 1.00  0.83  0.76
 *        50%    │ 0.67  0.56  0.51
 *        75%    │ 0.33  0.28  0.25
 *
 * 0.15 is latency-first (ceiling ≈ 85–93%). The ceiling is a worst case, only
 * approached when one relay is far faster than all the others; and a tight
 * ceiling at large n forces FLOOR ≈ 1 − C, which largely cancels the latency
 * bias. Mirrors Go's latencyFloorFraction.
 */
export const LATENCY_FLOOR_FRACTION = 0.15

function median(xs: number[]): number {
    const s = [...xs].sort((a, b) => a - b)
    const mid = Math.floor(s.length / 2)
    return s.length % 2 === 1 ? s[mid]! : (s[mid - 1]! + s[mid]!) / 2
}

/**
 * A relay's latency in ms, or undefined when it has no fresh sample.
 */
export type LatencyOf = (relay: NodeRef) => number | undefined

// A relay with no sample gets the median of the known weights, so a cold relay
// keeps being explored rather than buried or blindly favored. With nothing
// known at all the pick is exactly pool[seed % len], the unweighted rotation.
function weightedPick(pool: SelectionOperator[], rawSeed: number, latencyOf: LatencyOf): SelectionOperator {
    // As a uint32 on both paths: a negative or fractional seed would otherwise
    // index past the pool on the cold path.
    const seed = rawSeed >>> 0
    const lats = pool.map((op) => latencyOf({ op: op.id, node: op.node_id }))
    const known = lats.filter((x): x is number => x !== undefined)
    if (known.length === 0) return pool[seed % pool.length]!

    const toWeight = (ms: number): number => 1 / (ms + LATENCY_WEIGHT_BIAS_MS)
    const exploreWeight = median(known.map(toWeight))
    const raw = lats.map((ms) => (ms === undefined ? exploreWeight : toWeight(ms)))
    const rawTotal = raw.reduce((a, b) => a + b, 0)
    // w' = (1-FLOOR)·w + FLOOR·(rawTotal/n) keeps the total, so the draw is
    // unchanged while every share is floored and capped.
    const uniform = rawTotal / pool.length
    const weights = raw.map((w) => (1 - LATENCY_FLOOR_FRACTION) * w + LATENCY_FLOOR_FRACTION * uniform)
    const total = weights.reduce((a, b) => a + b, 0)

    // uint32 seed → [0,1): the same seed always lands the same pick.
    const r = (seed / 0x1_0000_0000) * total
    let acc = 0
    for (let i = 0; i < pool.length; i++) {
        acc += weights[i]!
        if (r < acc) return pool[i]!
    }
    return pool[pool.length - 1]!
}

/**
 * selectRelayHopWeighted picks the relay hop for a request whose target is
 * already chosen: eligibility from the shared eligibleRelays policy, then a
 * latency-weighted seeded draw within it.
 *
 * allSel must be the full known operator set, not a reachability-filtered
 * subset, so eligibleRelays' cold-start fallback can still pick before any
 * probe lands. excluded drops relay nodes by nodeRefString before selection.
 *
 * Returns null, Go's ErrNoRelay, when nothing qualifies. A caller must then
 * fail the request: routing direct silently drops the privacy guarantee.
 */
export function selectRelayHopWeighted(
    allSel: SelectionOperator[],
    target: SelectionOperator,
    seed: number,
    latencyOf: LatencyOf,
    excluded?: ReadonlySet<string>,
): RelayHop | null {
    const filtered =
        excluded && excluded.size > 0
            ? allSel.filter((o) => !excluded.has(nodeRefString({ op: o.id, node: o.node_id })))
            : allSel
    const pool = eligibleRelays(filtered, target)
    if (pool.length === 0) return null
    const relay = weightedPick(pool, seed, latencyOf)
    return {
        baseUrl: relay.base_url,
        targetId: target.id,
        targetNodeId: target.node_id,
        relayId: relay.id,
        relayNodeId: relay.node_id,
        relayProtoVersion: relay.proto_version,
    }
}

/**
 * randomRelaySeed is a fresh per-request seed. A fresh seed each request is the
 * rotation itself: it keeps any one relay from accumulating a session-long
 * payer→target profile (SPEC §3f). Go draws a uint64; the two need not agree.
 */
export function randomRelaySeed(): number {
    return crypto.getRandomValues(new Uint32Array(1))[0]!
}

const RELAY_HEADER_NAMES = new Set(
    [RELAY_TARGET_HEADER, RELAY_TARGET_NODE_HEADER, RELAY_PATH_HEADER, RELAY_METHOD_HEADER].map((h) =>
        h.toLowerCase(),
    ),
)

/** The fetch parameters a relayed or direct request is issued with. */
export interface RelayApplication {
    url: string
    method: string
    headers: Record<string, string>
}

/**
 * applyRelay rewrites a direct request into a relayed one, mirroring Go's
 * ApplyRelay. A null hop returns the request unchanged. Otherwise the URL moves
 * to the relay route, the method becomes POST (the route's only method), and
 * the relay headers carry the target, inner path and inner method; the sealed
 * body passes through untouched.
 *
 * innerPathOverride is the inner path with its query. Without it the path is
 * innerUrl's pathname and the query is dropped, which is right for the
 * path-only inference, reserve and details routes; the per-model deep details
 * probe (SPEC §3c) passes it to keep its ?model=&expand= scoping across the
 * hop.
 */
export function applyRelay(
    hop: RelayHop | null,
    innerUrl: string,
    innerMethod: string,
    headers: Record<string, string> = {},
    innerPathOverride?: string,
): RelayApplication {
    if (hop === null) {
        return { url: innerUrl, method: innerMethod, headers: { ...headers } }
    }
    const innerPath = innerPathOverride ?? new URL(innerUrl).pathname
    const rr = buildRequest(hop.baseUrl, hop.targetId, hop.targetNodeId, innerPath, innerMethod)
    // The relay headers always win, as Go's Header.Set: a caller's value under
    // any spelling of their names is dropped, or fetch would send both joined
    // and the hop could forward to a node, path or method the payer never
    // reserved against.
    const own = Object.fromEntries(
        Object.entries(headers).filter(([name]) => !RELAY_HEADER_NAMES.has(name.toLowerCase())),
    )
    return {
        url: rr.url,
        method: 'POST',
        headers: {
            ...own,
            [RELAY_TARGET_HEADER]: rr.target,
            [RELAY_TARGET_NODE_HEADER]: rr.targetNode,
            [RELAY_PATH_HEADER]: rr.path,
            [RELAY_METHOD_HEADER]: rr.method,
        },
    }
}
