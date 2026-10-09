/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What one candidate's failed reserve means for a dispatch loop, apart from its
// side effects (logging, the backoff store, the terminal-error accumulators),
// and whether a finished sweep earns another. Mirrors classifyReserveFailure
// and nextResweep in proto/go/zs/candidate_verdict.go, pinned by
// testdata/dispatch_verdict_vectors.json.

import { type AttributionValue, Attribution, type Verdict, classify, narrowRelayed } from '@txnlab/zs-proto/transient'
import { setsRelayHopHeader } from '@txnlab/zs-proto/wire'

import {
    BusyError,
    NoEphemeralError,
    PayerRefusalError,
    ReserveHTTPError,
    SizeError,
} from '../reserve.js'
import type { RelayHop } from './relay.js'

/** Which branch of the dispatch loop a failed reserve takes. */
export type ReserveOutcome = 'busy' | 'size' | 'payer_refusal' | 'no_ephemeral' | 'transient' | 'refused'

/** One candidate's failed reserve, decided. */
export interface ReserveFailure {
    outcome: ReserveOutcome
    /**
     * End the whole dispatch: every remaining candidate would refuse the
     * identical request identically (a payer-scoped refusal).
     */
    stop: boolean
    /**
     * Record a failure against the target's dispatch backoff. Only a transient
     * failure this node is answerable for does; see shouldRecordTargetFailure.
     */
    strike: boolean
    /**
     * A considered refusal: an answer, not weather, so it ends the weather
     * re-sweep and is sticky evidence for the terminal error.
     */
    refused: boolean
    /** Refused for a reason waiting can't fix, which also vetoes a busy re-sweep. */
    hardRefused: boolean
    /** A 429. */
    busy: boolean
    /** A 429 whose code says re-asking can help. */
    busyResweepable: boolean
    /** Infrastructure weather that keeps the outer sweep eligible. */
    transient: boolean
    sizeRejected: boolean
    ephemeralMissing: boolean
    /**
     * The wait the failure asks for: a busy node's Retry-After capped at
     * MAX_NODE_RETRY_HINT_MS, a transient failure's raw, a payer refusal's reset.
     */
    hintMs: number
    /** The transient verdict's attribution, for logs; '' otherwise. */
    attribution: AttributionValue
}

/** The route evidence a reserve failure's body can't carry. */
export interface ReserveRoute {
    /** The reserve rode a relay hop. */
    relayed: boolean
    /** That relay's generation sets the hop marker, so a missing marker means something. */
    relayMarksHops: boolean
    /** Our own cancellation or deadline ended it. */
    callerAborted: boolean
}

/**
 * The most a node's Retry-After may make a dispatch wait. A longer hint is a
 * node misbehaving or a reset the payer shouldn't sit through; Go's
 * maxNodeRetryHint.
 */
export const MAX_NODE_RETRY_HINT_MS = 5 * 60_000

/** A node's Retry-After as a dispatch honors it, capped at MAX_NODE_RETRY_HINT_MS. */
export function nodeRetryHintMs(ms: number): number {
    return Math.min(ms, MAX_NODE_RETRY_HINT_MS)
}

/**
 * Reads the route evidence for err off the hop it rode, or null for a direct
 * reserve. signal is the dispatch's own: an abort there blames nobody, whatever
 * the far end answered.
 */
export function reserveRouteFor(err: unknown, hop: RelayHop | null, signal?: AbortSignal): ReserveRoute {
    if (hop === null) return { relayed: false, relayMarksHops: false, callerAborted: false }
    return {
        relayed: true,
        relayMarksHops: setsRelayHopHeader(hop.relayProtoVersion),
        callerAborted: err instanceof ReserveHTTPError && (signal?.aborted === true || err.aborted),
    }
}

/** The shared transient verdict over a reserve failure, narrowed with the route evidence. */
export function narrowReserveVerdict(err: ReserveHTTPError, route: ReserveRoute): Verdict {
    const v = classify(err.status, err.code)
    if (!route.relayed) return v
    return narrowRelayed(v, err.status, {
        relayed: true,
        hopMarker: err.relayHopMarked,
        relayMarksHops: route.relayMarksHops,
        callerAborted: route.callerAborted,
    })
}

/**
 * Whether a transient verdict strikes the target's dispatch backoff: always
 * when the target is implicated, and for an unattributable failure only on a
 * direct reserve, where there is no other hop to blame. Through a relay an
 * unattributable failure waits for a rotation to show where the fault lies.
 */
export function shouldRecordTargetFailure(v: Verdict, usePrivacy: boolean): boolean {
    if (v.attribution === Attribution.Target) return true
    if (v.attribution === Attribution.Unknown) return !usePrivacy
    return false
}

const noFailure: Omit<ReserveFailure, 'outcome'> = {
    stop: false,
    strike: false,
    refused: false,
    hardRefused: false,
    busy: false,
    busyResweepable: false,
    transient: false,
    sizeRejected: false,
    ephemeralMissing: false,
    hintMs: 0,
    attribution: Attribution.None,
}

/**
 * Decides one candidate's failed reserve, testing in this order:
 *
 *  - busy (429): a considered refusal, resweepable only when its code says so;
 *    never strikes, because a saturated node is healthy.
 *  - size: other operators may have larger limits, so the loop keeps going.
 *  - payer refusal: the chain said no about this PAYER, so stop.
 *  - no ephemeral: this node can't be sealed to right now; skip it.
 *  - a transient ReserveHTTPError: weather, which strikes only when the target
 *    is answerable for it.
 *  - anything else, including a bad_reserve_envelope the self-heal couldn't
 *    fix: a hard refusal by this operator, with no strike.
 */
export function classifyReserveFailure(err: unknown, route: ReserveRoute, usePrivacy: boolean): ReserveFailure {
    if (err instanceof BusyError) {
        return {
            ...noFailure,
            outcome: 'busy',
            refused: true,
            busy: true,
            busyResweepable: err.retryable,
            hintMs: nodeRetryHintMs(err.retryAfterMs),
        }
    }
    if (err instanceof SizeError) return { ...noFailure, outcome: 'size', sizeRejected: true }
    if (err instanceof PayerRefusalError) {
        return { ...noFailure, outcome: 'payer_refusal', stop: true, hintMs: err.retryAfterMs }
    }
    if (err instanceof NoEphemeralError) return { ...noFailure, outcome: 'no_ephemeral', ephemeralMissing: true }
    if (err instanceof ReserveHTTPError) {
        const v = narrowReserveVerdict(err, route)
        if (v.retryable) {
            return {
                ...noFailure,
                outcome: 'transient',
                transient: true,
                strike: shouldRecordTargetFailure(v, usePrivacy),
                hintMs: err.retryAfterMs,
                attribution: v.attribution,
            }
        }
    }
    return { ...noFailure, outcome: 'refused', refused: true, hardRefused: true }
}

/** What one pass over the candidates produced, for deciding whether to make another. */
export interface SweepOutcome {
    /** This sweep had a transient failure. */
    transient: boolean
    /** This sweep had a considered refusal. */
    refused: boolean
    /** This sweep had a 429 whose code is resweepable; anyBusy is any 429 at all. */
    busy: boolean
    /** This sweep had a refusal waiting can't fix. */
    hardRefused: boolean
    // Sticky across the whole request.
    sizeRejected: boolean
    anyBusy: boolean
    relayUnavailable: boolean
    toolFactorMissing: boolean
    ephemeralMissing: boolean
    priceRejected: boolean
    /** Busy re-sweeps remain and their deadline hasn't passed. */
    busyBudgetLeft: boolean
}

/** Why another sweep runs, if one does. */
export type ResweepReason = 'none' | 'weather' | 'busy'

/**
 * Decides whether to walk the candidates again, and why. Two independent
 * reasons, each with its own disqualifiers:
 *
 *  - weather: every candidate failed transiently and nothing refused. Blocked
 *    by any considered refusal or sticky accumulator, since each is a property
 *    of the request or the fleet that waiting doesn't change.
 *  - busy: a candidate was at capacity with a resweepable code, and none
 *    refused for a reason waiting can't fix. Deliberately narrower: only what
 *    outranks busy in the terminal ladder (a hard refusal, a size rejection, a
 *    relay gap) may veto it, since the ladder already treats a missing tool
 *    factor, ephemeral or price as subordinate to busy.
 */
export function nextResweep(o: SweepOutcome): ResweepReason {
    const weatherBlocked =
        o.hardRefused ||
        o.sizeRejected ||
        o.anyBusy ||
        o.relayUnavailable ||
        o.toolFactorMissing ||
        o.ephemeralMissing ||
        o.priceRejected
    const busyBlocked = o.hardRefused || o.sizeRejected || o.relayUnavailable
    if (o.transient && !o.refused && !weatherBlocked) return 'weather'
    if (o.busy && !busyBlocked && o.busyBudgetLeft) return 'busy'
    return 'none'
}
