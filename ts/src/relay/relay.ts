/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Transport-binding helpers for single-hop operator-as-relay routing. Mirror
// of proto/go/relay/relay.go — keep in lockstep. Pure: builds the relay
// indirection metadata a user endpoint attaches to an outbound request, and
// defines the closed allow-list of inner paths a relaying node will forward.
// The relay never decrypts; the request stays sealed to the target's age key.

import { RELAY_PATH } from '../wire/constants.js'

/**
 * Request is the relay indirection for one inner request: the URL to send to
 * (the relay's RELAY_PATH endpoint) plus the values for the three relay
 * headers (RELAY_TARGET_HEADER / RELAY_PATH_HEADER / RELAY_METHOD_HEADER).
 */
export interface Request {
    url: string
    target: string
    targetNode: string
    path: string
    method: string
}

/**
 * buildRequest constructs the relay indirection for an inner request bound for
 * the (targetOperatorID, targetNodeID) destination node. relayBaseURL is the
 * chosen relay node's root; innerPath and innerMethod identify the inner
 * request the relay reconstructs against the target. Body and content-type are
 * unchanged from the direct case.
 */
export function buildRequest(
    relayBaseURL: string,
    targetOperatorID: number,
    targetNodeID: number,
    innerPath: string,
    innerMethod: string,
): Request {
    return {
        url: relayBaseURL.replace(/\/+$/, '') + RELAY_PATH,
        target: String(targetOperatorID),
        targetNode: String(targetNodeID),
        path: innerPath,
        method: innerMethod,
    }
}

// Closed set of fixed inner paths a relay will forward. RELAY_PATH itself is
// deliberately absent — relaying is single-hop (no relay-to-relay chaining).
const EXACT_ALLOWED_INNER_PATHS = new Set<string>([
    '/v1/chat/completions',
    '/v1/responses',
    '/v1/images/generations',
    '/v1/images/edits',
    '/v1/models',
    '/v1/zs/reserve',
    '/v1/zs/details',
    '/v1/zs/attestation',
])

const MODELS_PREFIX = '/v1/models/'

/**
 * isAllowedInnerPath reports whether p is a path a relay may forward — the
 * SSRF boundary. Anything outside the allow-list (or any traversal attempt) is
 * rejected, so a relay reaches only the well-known hayai endpoints on a known
 * operator, never an arbitrary host.
 */
export function isAllowedInnerPath(p: string): boolean {
    // The relay forwards any query string to the target verbatim (appended to
    // the fixed on-chain baseURL), so the query can change neither the host nor
    // the route. The allow-list (the SSRF boundary) therefore gates the PATH
    // only: split off the query before matching. The per-model deep details
    // probe rides /v1/zs/details?model=…&expand=… (SPEC §3c). Mirrors Go's
    // IsAllowedInnerPath.
    const q = p.indexOf('?')
    const path = q >= 0 ? p.slice(0, q) : p
    // Defense-in-depth on the path portion: a traversal in a query value is not
    // a route traversal, so it must not false-reject an otherwise-allowed path.
    if (path.includes('..') || !path.startsWith('/v1/')) return false
    if (EXACT_ALLOWED_INNER_PATHS.has(path)) return true
    if (path.startsWith(MODELS_PREFIX)) {
        const id = path.slice(MODELS_PREFIX.length)
        return id !== '' && !id.includes('/')
    }
    return false
}

/**
 * Relay error codes — the values a relaying node puts in the OpenAI-shaped
 * error body's "code" field on the RELAY_PATH route. They identify failures at
 * the relay (the outer hop) as opposed to the target operator, so a user
 * endpoint routing a request through a relay can attribute a failure correctly:
 * a relay-hop failure must NOT be mistaken for the target being down.
 *
 * UpstreamUnreachable is the deliberate exception: the relay emits it precisely
 * when it reached out but the *target* was down, so it is a target-side signal,
 * not a relay-side one — see isHopErrorCode. Mirror of proto/go/relay/relay.go.
 */
export const RelayErrorCode = {
    BadTarget: 'relay_bad_target', // 400: malformed/missing X-Zs-Relay-Target
    BadPath: 'relay_bad_path', // 400: inner path not relay-forwardable
    BadMethod: 'relay_bad_method', // 400: inner method not GET/POST
    Busy: 'relay_busy', // 503: relay at its concurrent-circuit cap
    UnknownTarget: 'relay_unknown_target', // 404: target id not a known on-chain operator
    BuildRequest: 'relay_build_request', // 502: relay could not construct the inner request
    UpstreamUnreachable: 'relay_upstream_unreachable', // 502: relay reached out but the target was down
} as const

// Codes that mean the relay itself (the outer hop) failed — every RelayErrorCode
// except UpstreamUnreachable, which is a target-side signal.
const HOP_ERROR_CODES = new Set<string>([
    RelayErrorCode.BadTarget,
    RelayErrorCode.BadPath,
    RelayErrorCode.BadMethod,
    RelayErrorCode.Busy,
    RelayErrorCode.UnknownTarget,
    RelayErrorCode.BuildRequest,
])

/**
 * isHopErrorCode reports whether code names a relay-generated error that means
 * the relay itself (the outer hop) failed — as opposed to the target. Returns
 * false for UpstreamUnreachable (relay reached, target down → a target-side
 * signal) and for every non-relay code: a relay forwards the target's own error
 * responses verbatim, and those never carry a relay_ code, so an unrecognized
 * code is treated as a target-side failure. Mirror of relay.IsHopErrorCode.
 */
export function isHopErrorCode(code: string): boolean {
    return HOP_ERROR_CODES.has(code)
}
