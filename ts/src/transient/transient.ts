/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Classification of a failed request as a retryable infrastructure fault or a
// terminal application-level one, plus the retry schedule both callers pace
// themselves by. Mirror of proto/go/transient/transient.go — keep in lockstep;
// drift fails proto/testdata/transient_vectors.json on both sides.
//
// Why this exists: no zs component ever emits 504. A relaying node answers a
// failed forward with 502 relay_upstream_unreachable (every RelayErrorCode is
// 400/404/502/503) and otherwise copies the target's status verbatim. So a
// 502/503/504 carrying no recognized error code came from something OUTSIDE the
// protocol — an operator's CDN, ingress, or load balancer — and is exactly the
// class that resolves on its own within seconds, most visibly while a fleet
// rolls through a node update. Without this, such a response is
// indistinguishable from a deliberate refusal and surfaces to the user as
// terminal.
//
// Two entry points, both pure. classify is the per-response verdict over
// (status, code). narrowRelayed then refines an unattributed verdict using
// route evidence the response body cannot carry — whether a relay was in the
// path, whether it stamped RELAY_HOP_HEADER, and whether it is new enough that
// a missing marker means anything. Callers on a relayed path should run both;
// the split keeps classify's two-argument vector contract intact while still
// putting the narrowing rules under the same cross-language vectors, so the Go
// and TS ports cannot drift on either half.

import { RelayErrorCode, isHopErrorCode } from '../relay/relay.js'

/**
 * Which hop a retryable failure should be charged to. It drives the caller's
 * reputation bookkeeping, and getting it wrong is worse than recording nothing:
 * crediting a relay for its own broken front door keeps it in rotation, and
 * charging a target for its relay's front door benches a healthy node.
 */
export const Attribution = {
    /** Accompanies a non-retryable verdict. */
    None: '',
    /**
     * The relay itself failed and the target provably never saw the request.
     * This is the only attribution safe to retry AFTER payment has committed:
     * the ticket cannot have been consumed, so re-sending the byte-identical
     * sealed envelope through a different relay can't collide with an inference
     * already running.
     */
    Relay: 'relay',
    /**
     * The target is implicated — it answered with a transient fault of its own,
     * or a relay claimed it was unreachable. Callers with a per-target backoff
     * record it here.
     */
    Target: 'target',
    /**
     * Unattributable infrastructure: a status with no recognized error code,
     * i.e. a CDN / ingress / LB error page rather than anything the protocol
     * generated. Which hop's front door produced it is unknowable FROM THE
     * RESPONSE BODY ALONE, so callers MUST NOT record a bare Unknown against
     * either party — neither credit nor penalty.
     *
     * It is not always the last word: a caller holding route evidence the body
     * doesn't carry should run the verdict through narrowRelayed first, which
     * resolves the common relayed cases (no response at all, or a
     * present/absent RELAY_HOP_HEADER from a relay new enough to set one). A
     * verdict still Unknown after that narrowing is the genuinely undecidable
     * residue — let a rotation prove where the fault lies.
     */
    Unknown: 'unknown',
} as const

export type AttributionValue = (typeof Attribution)[keyof typeof Attribution]

/** The classification of one failed response. */
export interface Verdict {
    /**
     * Whether re-issuing the request could plausibly succeed without the caller
     * changing anything about it.
     */
    retryable: boolean
    /** The hop to charge; `Attribution.None` when not retryable. */
    attribution: AttributionValue
}

/**
 * The status callers pass for a failure that never produced an HTTP response at
 * all (fetch threw, connection reset, TLS failure). Distinguishing it from a
 * real status matters because the hop that failed is often known from context
 * even though the response isn't: in relayed mode the caller connected to the
 * relay, not the target, so a transport error is unambiguously a relay-hop fault
 * and the caller may narrow `Unknown` to `Relay` itself.
 */
export const TRANSPORT_FAILURE_STATUS = 0

// HTTP statuses that, absent a recognized protocol error code, mean
// "infrastructure between us and the node is unhappy right now" rather than
// "your request was rejected".
//
// The 52x block is Cloudflare's origin-fault vocabulary (521 origin down, 522
// connect timeout, 523 origin unreachable, 524 origin timeout) — precisely what
// a node behind Cloudflare emits while it restarts. Ordinary reverse proxies
// stick to 502/503/504.
const RETRYABLE_STATUSES = new Set<number>([
    TRANSPORT_FAILURE_STATUS,
    408, // Request Timeout
    425, // Too Early
    429, // Too Many Requests
    500, // Internal Server Error
    502, // Bad Gateway
    503, // Service Unavailable
    504, // Gateway Timeout
    520, // Cloudflare: unknown origin error
    521, // Cloudflare: origin down
    522, // Cloudflare: origin connect timeout
    523, // Cloudflare: origin unreachable
    524, // Cloudflare: origin response timeout
    525, // Cloudflare: origin TLS handshake failed
    526, // Cloudflare: invalid origin certificate
    527, // Cloudflare: Railgun error
])

/**
 * Decide whether a failed request is worth retrying, and to whom the failure
 * belongs. `code` is the OpenAI-shaped `error.code` already extracted from the
 * response body (empty/null when the body carried none — an HTML error page, an
 * empty body, or a parse failure); taking it pre-extracted keeps this module
 * free of `Response` handling so both language ports stay trivially identical.
 *
 * The rules, in order:
 *
 * 1. A relay-generated hop code is a relay fault; the target never saw it.
 * 2. `relay_upstream_unreachable` is the relay's claim about the TARGET, so it
 *    attributes to the target — callers keep whatever differential treatment
 *    they already apply to that claim (it is a claim, not an observation).
 * 3. Any OTHER non-empty code means the zs stack itself answered and its own
 *    per-code semantics own the outcome. Not classified as infrastructure —
 *    e.g. `context_length_exceeded` is terminal, `provider_unavailable` already
 *    fails over. Returning "not retryable" here does NOT stop those flows; it
 *    only keeps this module from second-guessing them.
 * 4. A transient-shaped status with NO code is infrastructure, unattributable.
 * 5. Everything else is terminal.
 */
export function classify(status: number, code: string | null | undefined): Verdict {
    const c = code ?? ''
    if (isHopErrorCode(c)) {
        return { retryable: true, attribution: Attribution.Relay }
    }
    if (c === RelayErrorCode.UpstreamUnreachable) {
        return { retryable: true, attribution: Attribution.Target }
    }
    if (c !== '') {
        return { retryable: false, attribution: Attribution.None }
    }
    if (RETRYABLE_STATUSES.has(status)) {
        return { retryable: true, attribution: Attribution.Unknown }
    }
    return { retryable: false, attribution: Attribution.None }
}

/**
 * What a caller knows about the hop a failed response came back through,
 * beyond the (status, code) pair classify already saw. Every field is a fact
 * the CALLER holds — which route it chose, what the response headers carried,
 * what the relay advertised at discovery — not a value classify could have
 * read off the body. Keeping them separate is what lets classify stay a pure
 * two-argument function over the response, with a stable vector contract.
 */
export interface RelayEvidence {
    /**
     * The request rode a relay hop (transport-privacy mode). False for a
     * direct send, where the caller's own direct-mode rules already own an
     * unattributed failure.
     */
    relayed: boolean
    /**
     * The response carried RELAY_HOP_HEADER — the relay's own handler ran and
     * produced or forwarded this response.
     */
    hopMarker: boolean
    /**
     * The relay advertises a proto_version at or above
     * RELAY_HOP_HEADER_MIN_VERSION, so a MISSING hopMarker is evidence rather
     * than an artifact of its age. Get this from setsRelayHopHeader over the
     * version the relay advertised at discovery — never a bootstrap-seeded one
     * (see bootstrapProtoVersion).
     */
    relayMarksHops: boolean
    /**
     * The failure was the CALLER's own doing — its AbortSignal fired, or its
     * own client-side deadline expired — rather than anything the far end did.
     *
     * This exists because a caller-side abort produces the same
     * TRANSPORT_FAILURE_STATUS as a dial failure to a dead relay, and rule 3
     * would charge the relay for a socket the caller tore down. A user hitting stop,
     * or a reserve exceeding the caller's own timeout while the RELAY was
     * legitimately waiting on a slow target, must not cost the relay a strike.
     * Only the caller can see this, which is why it lives here rather than in
     * classify — and why it is decided in this pure, vectored layer rather than
     * duplicated at each recording site, where Go and TS would drift.
     */
    callerAborted: boolean
}

/**
 * The statuses that, arriving from a marking relay WITHOUT its hop marker,
 * prove the relay's own front door answered us and its handler never ran. This
 * is the set rule 4 charges on sight.
 *
 * Spelled out member by member rather than derived as "RETRYABLE_STATUSES minus
 * the timeouts". The derived form was one subtraction away from being wrong in
 * a way nobody would notice: every future addition to the retryable set would
 * silently join the charge set, and the two subtracted sets already disagreed
 * with the prose in SPEC § 10, which enumerated a narrower list than the code
 * actually charged. An explicit list is the only form where the docs and the
 * behavior can be diffed.
 *
 * Each member means "the request never reached the zs handler". 429 is
 * deliberately included even though "come back later" is a capacity signal
 * rather than a fault: the alternative is worse, because on the discovery path
 * a relay's throttle answering 429 would otherwise fall through as a TARGET-side
 * failure and bench a node the probe never even reached. The self-reinforcing
 * risk is bounded — the downrank is soft, needs 3 consecutive strikes, and any
 * successful forward resets it.
 *
 * EXCLUDED, and why — the retryable statuses that mean "took too long" rather
 * than "could not connect": 408, 504 and 524 (Cloudflare origin response
 * timeout, TCP up but no reply). A relay is byte-transparent and writes NOTHING
 * until the target's headers arrive — it cannot flush its marker early without
 * committing to a status it does not yet know. So for the whole forward window
 * it looks idle to its own gateway, and a gateway giving up in that window
 * emits one of these unmarked, indistinguishable between "relay wedged" and
 * "relay waiting on a slow target". Charging would bench whoever fronts the
 * slowest targets, so rule 4 abstains and the rotation differential decides.
 * Note 522 IS charged — it is a CONNECT timeout, so TCP never established.
 *
 * TRANSPORT_FAILURE_STATUS is absent on purpose too: rule 3 owns it, and needs
 * no version gate because there is no marker to be missing.
 */
const RELAY_FRONT_DOOR_STATUSES: ReadonlySet<number> = new Set([
    425, // Too Early — TLS early-data replay refused at the edge
    429, // Too Many Requests — the edge throttled us; the handler never ran
    500, // the relay's own stack failed ahead of the handler
    502, // Bad Gateway — front door could not reach its origin
    503, // Service Unavailable — no healthy origin (a live relay says relay_busy)
    520, // Cloudflare: origin returned something CF could not parse
    521, // Cloudflare: origin down
    522, // Cloudflare: origin CONNECT timeout — TCP never established
    523, // Cloudflare: origin unreachable
    525, // Cloudflare: origin TLS handshake failed
    526, // Cloudflare: invalid origin certificate
    527, // Cloudflare: Railgun error
])

/**
 * Reports whether `status`, arriving unmarked from a relay that advertises
 * RELAY_HOP_HEADER_MIN_VERSION or newer, proves the relay's own front door
 * answered rather than its handler.
 *
 * Exported for the one caller that must reason about the STATUS while
 * deliberately ignoring the body: the discovery probe, which uses
 * marker-absence from a marking relay as proof the handler never ran — evidence
 * that outranks whatever JSON its front door happened to emit (an Envoy
 * upstream_connect_error, or a per-IP throttle answering a coded 429 ahead of
 * the handler). That path only picks an error TYPE (rotate vs. blame the
 * target), so acting on the stronger signal is safe there; narrowRelayed cannot
 * do the same, because reinterpreting a coded response would mean flipping
 * `retryable`.
 *
 * Both ports must agree member-for-member, so this is golden-vectored
 * (front_door_cases in proto/testdata/transient_vectors.json) rather than left
 * to two hand-maintained lists — the discovery probes are the one place Go and
 * TS consume it directly, and they already drifted once.
 */
export function isRelayFrontDoorStatus(status: number): boolean {
    return RELAY_FRONT_DOOR_STATUSES.has(status)
}

/**
 * Refines an Unknown verdict using evidence classify cannot see. classify
 * answers "what does this response say"; this answers "and what does the route
 * it came back through tell me". Any verdict that is already attributed — or
 * any non-relayed request — passes through untouched, so this is safe to apply
 * unconditionally at a response seam.
 *
 * The rules, in order:
 *
 * 1. Not Unknown, or not relayed -> unchanged. A coded response already names
 *    its hop, and a direct send has no relay to reason about.
 * 2. callerAborted -> unchanged. Our own cancel/deadline says nothing about
 *    either hop, and rule 3 would otherwise charge a relay for a socket we tore
 *    down ourselves.
 * 3. TRANSPORT_FAILURE_STATUS while relayed -> Relay. No response arrived at
 *    all and the socket the caller opened was the RELAY's, so nothing about
 *    which hop failed to answer is ambiguous — once rule 2 has excluded the
 *    caller's own doing. No version gate: there is no marker to be missing.
 *    The one rule that works against an entirely un-upgraded fleet.
 * 4. No marker but relayMarksHops, and the status is front-door shaped
 *    (RELAY_FRONT_DOOR_STATUSES — "could not connect", NOT the 408/504/524
 *    timeouts) -> Relay. A relay at or above RELAY_HOP_HEADER_MIN_VERSION that
 *    had run its handler would have marked the response; it didn't, and the
 *    status says its front door answered us. So the request died at that door.
 *
 *    Ordered BEFORE rule 5, so when both could apply the relay is charged
 *    rather than the target. Note what it does NOT do: it never reinterprets a
 *    response that carried a protocol error code, because rule 1 already
 *    returned. Reclassifying a coded response here would mean flipping
 *    `retryable`, and this function must only ever answer WHO, never WHETHER.
 * 5. hopMarker set -> Target. The relay ran its handler and copied a code-less
 *    transient status back, which is the same shape of claim as
 *    relay_upstream_unreachable: "I forwarded, and this is what I got".
 *    Callers already treat that claim DIFFERENTIALLY rather than at face value,
 *    and routing this case to the same attribution puts it in the same
 *    already-threat-modeled path. It grants a dishonest relay nothing new: one
 *    that wants a healthy target benched can emit relay_upstream_unreachable
 *    today and reach Target directly.
 * 6. Everything else -> unchanged (Unknown). Two shapes land here and both are
 *    genuinely undecidable from one response: a pre-floor relay (owes no
 *    header), and a gateway TIMEOUT from any relay (it may simply have been
 *    waiting on a slow target — see RELAY_FRONT_DOOR_STATUSES' exclusion note).
 *    The rotation differential resolves both.
 */
export function narrowRelayed(v: Verdict, status: number, e: RelayEvidence): Verdict {
    if (v.attribution !== Attribution.Unknown || !e.relayed || e.callerAborted) return v
    if (status === TRANSPORT_FAILURE_STATUS) {
        return { retryable: v.retryable, attribution: Attribution.Relay }
    }
    if (e.relayMarksHops && !e.hopMarker && RELAY_FRONT_DOOR_STATUSES.has(status)) {
        return { retryable: v.retryable, attribution: Attribution.Relay }
    }
    if (e.hopMarker) {
        return { retryable: v.retryable, attribution: Attribution.Target }
    }
    return v
}

// Retry schedule. The shape is two nested loops: a few fast attempts against one
// candidate (rotating the relay hop each time, which is what actually clears a
// bad front door), then — only if EVERY candidate failed transiently — slower
// whole-list sweeps. A single flaky relay costs a couple of seconds; a
// fleet-wide restart gets ridden out for a minute rather than surfaced.
//
// Both ports read these so a request behaves the same whether it went through
// zs-proxy or the browser app.

/**
 * Tries against one candidate, including the first. Each retry rotates to a
 * different relay when one is available.
 */
export const INNER_ATTEMPTS = 3

/**
 * Passes over the whole candidate list, including the first. Sweeps beyond the
 * first only happen when no candidate committed payment and every failure was
 * retryable.
 */
export const SWEEPS = 4

/**
 * Total wall-clock ceiling across all attempts and sweeps. A ceiling, not a
 * target — a request that exhausts the candidate list terminally returns
 * immediately.
 */
export const OVERALL_DEADLINE_MS = 60_000

// Waits BEFORE attempt/sweep i, so index 0 is always zero (the first try is
// immediate). Frozen because an exported array is otherwise mutable by any
// importer.
const INNER_DELAYS_MS: readonly number[] = Object.freeze([0, 500, 1500])
const SWEEP_DELAYS_MS: readonly number[] = Object.freeze([0, 4000, 12000, 30000])

function lookup(table: readonly number[], i: number): number {
    if (i <= 0) return table[0]!
    if (i >= table.length) return table[table.length - 1]!
    return table[i]!
}

/**
 * The wait before the zero-based attempt against a single candidate.
 * Out-of-range indices clamp to the last delay, so raising INNER_ATTEMPTS
 * without extending the table degrades to a constant wait rather than
 * returning undefined.
 */
export function innerDelayMs(attempt: number): number {
    return lookup(INNER_DELAYS_MS, attempt)
}

/**
 * The wait before the zero-based sweep over the candidate list. Sweep 0 is the
 * initial pass and always returns 0.
 */
export function sweepDelayMs(sweep: number): number {
    return lookup(SWEEP_DELAYS_MS, sweep)
}

/** The resolved wait, and whether there is budget to make the attempt at all. */
export interface WaitDecision {
    delayMs: number
    ok: boolean
}

/**
 * Resolve how long to wait before the next attempt.
 *
 * `scheduledMs` is the table value from {@link innerDelayMs} / {@link sweepDelayMs}.
 * `retryAfterMs` is a server-supplied Retry-After (0 when absent) and WINS when
 * longer — a node or gateway telling us when it will be ready is better
 * information than a fixed table. `remainingMs` is what's left of
 * {@link OVERALL_DEADLINE_MS}.
 *
 * `ok` is false when the resolved wait would consume the remaining budget, which
 * the caller treats as "stop retrying and surface the failure" — waiting right
 * up to the deadline only delays the error without improving the odds.
 */
export function wait(scheduledMs: number, retryAfterMs: number, remainingMs: number): WaitDecision {
    if (remainingMs <= 0) return { delayMs: 0, ok: false }
    const d = Math.max(scheduledMs, retryAfterMs)
    if (d >= remainingMs) return { delayMs: 0, ok: false }
    return { delayMs: d, ok: true }
}
