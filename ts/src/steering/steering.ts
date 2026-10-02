/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The pure arithmetic behind a payer's app-side routing signals: relay
// reputation decay, target backoff, and the weights-digest consensus. Mirrors
// proto/go/steering, where the reasons are written up, and is pinned by
// testdata/steering_vectors.json. Times are millisecond epochs and durations
// are milliseconds.
//
// The stores these feed stay with each payer; this fixes only that the same
// state yields the same verdict in Go and TS.

/** Standing evidence on the forward-failure or stale-ephemeral streak that demotes a relay. */
export const RELAY_DOWNRANK_THRESHOLD = 3
/** How long one unit of evidence on those two streaks takes to age out. */
export const RELAY_REPUTATION_COOLDOWN_MS = 10 * 60_000
/** Higher than RELAY_DOWNRANK_THRESHOLD: a timeout is weaker evidence than a proven fault. */
export const RELAY_TIMEOUT_DOWNRANK_THRESHOLD = 5
/** Longer than RELAY_REPUTATION_COOLDOWN_MS: the timeout streak has no probe feeder. */
export const RELAY_TIMEOUT_COOLDOWN_MS = 60 * 60_000

/** The first window a failing target is demoted for. */
export const TARGET_BACKOFF_BASE_MS = 30_000
/** The longest window, and the grace period after one before the record is forgotten. */
export const TARGET_BACKOFF_CAP_MS = 5 * 60_000

/** Distinct owners that must advertise one digest before it is a model's reference. */
export const WEIGHTS_CONSENSUS_MIN_OWNERS = 2

/**
 * Whether status is a gateway "took too long" answer (408, 504, 524) rather
 * than a "could not connect" one: exactly the statuses narrowRelayed leaves
 * unattributed, and disjoint from isRelayFrontDoorStatus.
 */
export function isForwardTimeoutStatus(status: number): boolean {
    return status === 408 || status === 504 || status === 524
}

/** One relay's standing count on one streak, and the time it is aged from. */
export interface Evidence {
    count: number
    at: number
}

/**
 * Ages e by one unit per whole cooldown elapsed since `at`, or undefined when
 * no evidence survives. `at` advances by the windows consumed, not to now, so
 * a second call at the same instant changes nothing; a backwards clock
 * consumes nothing, and neither does a cooldown that isn't positive.
 */
export function decay(e: Evidence | undefined, now: number, cooldownMs: number): Evidence | undefined {
    if (e === undefined || e.count <= 0) return undefined
    if (!(cooldownMs > 0)) return e
    // trunc, as Go's Duration division: floor would make a backwards clock -1
    // steps, and a guard that ever let that through would grow the evidence.
    const steps = Math.trunc((now - e.at) / cooldownMs)
    if (steps <= 0) return e
    const count = e.count - steps
    return count > 0 ? { count, at: e.at + steps * cooldownMs } : undefined
}

/**
 * Whether a relay's standing evidence demotes it: the forward-failure or
 * stale-ephemeral streak at RELAY_DOWNRANK_THRESHOLD, or the timeout streak at
 * RELAY_TIMEOUT_DOWNRANK_THRESHOLD. Pass each count after aging it with its own
 * cooldown; a payer with no stale-ephemeral signal passes 0.
 */
export function relayDownranked(failures: number, stale: number, timeouts: number): boolean {
    return (
        failures >= RELAY_DOWNRANK_THRESHOLD ||
        stale >= RELAY_DOWNRANK_THRESHOLD ||
        timeouts >= RELAY_TIMEOUT_DOWNRANK_THRESHOLD
    )
}

/** Ages e and then adds one unit of evidence, dated now. */
export function bump(e: Evidence | undefined, now: number, cooldownMs: number): Evidence {
    return { count: (decay(e, now, cooldownMs)?.count ?? 0) + 1, at: now }
}

/** One target node's failure record. `failures` survives a lapsed window, so a renewed failure escalates. */
export interface Backoff {
    failures: number
    /** The last failure. */
    at: number
    /** The end of the current window. */
    until: number
}

/** min(TARGET_BACKOFF_BASE_MS · 2^(n-1), TARGET_BACKOFF_CAP_MS), or 0 for n < 1. */
export function backoffWindowMs(failures: number): number {
    if (failures < 1) return 0
    return Math.min(TARGET_BACKOFF_BASE_MS * 2 ** Math.min(failures - 1, 32), TARGET_BACKOFF_CAP_MS)
}

/** Adds a failure at now and re-arms the window. A success clears the record outright. */
export function recordFailure(b: Backoff | undefined, now: number): Backoff {
    const failures = (b?.failures ?? 0) + 1
    return { failures, at: now, until: now + backoffWindowMs(failures) }
}

/**
 * How long b keeps its target demoted at now, and whether the record is stale
 * enough to forget (its window lapsed at least TARGET_BACKOFF_CAP_MS ago).
 *
 * floorMs raises the window to at least floorMs past the last failure: 0 for
 * dispatch, a probe's refetch cooldown for discovery.
 *
 * A wall clock that steps backwards holds the demotion until it catches up with
 * `until`, as it pauses decay. Bounding that needs a re-anchored record written
 * back, which is the store's job.
 */
export function backoffRemaining(
    b: Backoff | undefined,
    now: number,
    floorMs = 0,
): { remainingMs: number; forget: boolean } {
    if (b === undefined || b.failures < 1) return { remainingMs: 0, forget: true }
    const until = Math.max(b.until, b.at + floorMs)
    if (now < until) return { remainingMs: until - now, forget: false }
    return { remainingMs: 0, forget: now - until >= TARGET_BACKOFF_CAP_MS }
}

/** One operator's advertised weights digest for a model, with the owner that makes its vote distinct. */
export interface DigestClaim {
    owner?: string
    digest?: string
}

// Only ASCII folds. Unicode lowercasing differs between JS and Go (JS writes a
// final Σ as ς), so a crafted node-authored digest could otherwise split the
// two sides' verdicts.
const asciiLower = (s: string): string => s.replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32))

/**
 * The ASCII-lowercased digest the most distinct owners advertise, or undefined
 * when none holds a decisive plurality: fewer than WEIGHTS_CONSENSUS_MIN_OWNERS
 * owners behind the leader, or a tie for the lead. A claim with no owner is not
 * counted. Pass every operator advertising the model, not just this request's
 * candidates.
 */
export function weightsConsensus(claims: Iterable<DigestClaim>): string | undefined {
    const owners = new Map<string, Set<string>>()
    for (const c of claims) {
        const d = c.digest === undefined ? undefined : asciiLower(c.digest)
        if (!c.owner || !d) continue
        const set = owners.get(d)
        if (set) set.add(c.owner)
        else owners.set(d, new Set([c.owner]))
    }
    let lead: string | undefined
    let leadN = 0
    let runnerUpN = 0
    for (const [d, set] of owners) {
        if (set.size > leadN) {
            runnerUpN = leadN
            lead = d
            leadN = set.size
        } else if (set.size > runnerUpN) {
            runnerUpN = set.size
        }
    }
    return leadN < WEIGHTS_CONSENSUS_MIN_OWNERS || leadN === runnerUpN ? undefined : lead
}

/** Whether digest disagrees with an established consensus. Advertising none never does. */
export function contradictsWeightsConsensus(digest: string | undefined, consensus: string | undefined): boolean {
    const d = digest === undefined ? undefined : asciiLower(digest)
    return !!consensus && !!d && d !== consensus
}
