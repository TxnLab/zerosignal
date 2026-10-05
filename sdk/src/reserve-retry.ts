/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Transient-failure retry for the reserve leg: one candidate, asked again
// through a different relay each time, until the attempt budget or the
// deadline runs out. Mirrors reserveWithTransientRetry in
// proto/go/zs/transient_retry.go, whose header carries the reasoning.
//
// Relay reputation on this leg: no credit, ever, but a proven fault is
// recorded. The reserve rides the same hop as the paid forward, which is the
// authoritative signal and the only one that credits (see relayHopAction). A
// fault is proven when the narrowed verdict names the relay, or by the rotation
// differential: a relay that failed with a verdict still unattributed is at
// fault once a later rotation reaches the same target through another relay.

import { Attribution, type AttributionValue, INNER_ATTEMPTS, innerDelayMs, wait } from '@txnlab/zs-proto/transient'

import type { Event, ReserveRetrying } from './events.js'
import { BadReserveEnvelopeError, NoEphemeralError, ReserveHTTPError } from './reserve.js'
import { type RelayHop, relayRef } from './routing/relay.js'
import { narrowReserveVerdict, reserveRouteFor } from './routing/verdict.js'
import { type NodeRef, nodeRefString } from './types.js'

/** What reserveWithTransientRetry needs from its caller. T is the candidate. */
export interface TransientReserveCall<T, R> {
    /** The candidate. A stale-ephemeral re-probe may replace it. */
    target: T
    /** Its NodeRef, for events. */
    ref(target: T): NodeRef
    /** The relay the first attempt rides; null for a direct reserve. */
    hop: RelayHop | null
    /** Whether the request is relayed. A rotation happens only then. */
    usePrivacy: boolean
    /** When the whole request's transient retrying must stop, in clock milliseconds. */
    deadlineMs: number
    /**
     * One reserve against target through hop. The caller builds the request
     * per call, so a re-probed target is re-sized here: Go's resize hook.
     */
    attempt(target: T, hop: RelayHop | null): Promise<R>
    /**
     * The relay to rotate to, excluding the relay nodes in excluded (by
     * nodeRefString), or null when none is left. Never a direct route: that
     * would drop the privacy the request asked for.
     */
    nextHop(target: T, excluded: ReadonlySet<string>): RelayHop | null
    /**
     * Re-probes target's ephemeral live after a stale one, returning the
     * refreshed candidate or null when there is none. Runs at most once.
     */
    reprobeEphemeral?(target: T): Promise<T | null>
    /** Records a proven relay fault against the reputation store. */
    recordRelayFailure(hop: RelayHop): void
    note?(event: Event): void
    signal?: AbortSignal
    clock?: () => number
    /**
     * Waits ms before a retry, resolving false when the caller is gone first.
     * Defaults to a timer bound to signal.
     */
    sleep?(ms: number, signal: AbortSignal | undefined): Promise<boolean>
}

/**
 * The final attempt of one candidate's reserve leg. target and hop produced
 * it, and the caller must carry both forward: sealing the paid forward to a
 * pre-rotation hop would send it through a relay just abandoned. result is set
 * on success, err otherwise; elapsedMs is the final round trip's.
 */
export interface TransientReserveAttempt<T, R> {
    result?: R
    err?: unknown
    target: T
    hop: RelayHop | null
    elapsedMs: number
}

function relayOf(hop: RelayHop | null): NodeRef | null {
    return hop === null ? null : relayRef(hop)
}

// Resolves after ms, or false at once when signal aborts first. A non-positive
// ms still checks the signal, so a caller gone during a zero wait is noticed
// before another round trip. Go's sleepCtx.
function sleep(ms: number, signal: AbortSignal | undefined): Promise<boolean> {
    if (signal?.aborted) return Promise.resolve(false)
    if (ms <= 0) return Promise.resolve(true)
    return new Promise((resolve) => {
        const onAbort = () => {
            clearTimeout(timer)
            resolve(false)
        }
        const timer = setTimeout(() => {
            signal?.removeEventListener('abort', onAbort)
            resolve(true)
        }, ms)
        signal?.addEventListener('abort', onAbort, { once: true })
    })
}

/**
 * reserveWithTransientRetry reserves against call.target, retrying an
 * infrastructure failure (a retryable ReserveHTTPError) through a different
 * relay each time, up to INNER_ATTEMPTS, while the deadline allows. It absorbs
 * the stale-ephemeral self-heal, once per candidate. Any other failure, or the
 * budget running out, returns the last attempt with its error, so the caller's
 * per-error handling (classifyReserveFailure) still sees the real cause.
 */
export async function reserveWithTransientRetry<T, R>(
    call: TransientReserveCall<T, R>,
): Promise<TransientReserveAttempt<T, R>> {
    const clock = call.clock ?? Date.now
    const note = call.note ?? (() => {})
    let { target, hop } = call
    // Relays already tried, so a rotation genuinely changes the path.
    const excluded = new Set<string>()
    let retryAfterMs = 0
    let reprobed = false
    let last: TransientReserveAttempt<T, R> = { target, hop, elapsedMs: 0 }
    // Relays that failed with a verdict still unattributed, held until a later
    // rotation settles them or every attempt fails and they are dropped.
    const unattributed: RelayHop[] = []
    let failed: unknown
    let failedAttribution: AttributionValue = Attribution.None

    for (let attempt = 0; attempt < INNER_ATTEMPTS; attempt++) {
        if (attempt > 0) {
            const w = wait(innerDelayMs(attempt), retryAfterMs, call.deadlineMs - clock())
            if (!w.ok) break
            // Picked before the wait, so a retry with no relay left to take it
            // is never announced. Without a relay the retry is a straight
            // re-attempt, still worth it as a restarting node's gateway recovers.
            let next = hop
            if (call.usePrivacy && hop !== null) {
                excluded.add(nodeRefString(relayRef(hop)))
                next = call.nextHop(target, excluded)
                if (next === null) break
            }
            note(retrying(call.ref(target), failed, failedAttribution, w.delayMs, attempt + 1))
            if (next !== hop) {
                note({ type: 'relay.hop', relay: relayOf(next), target: call.ref(target), reason: 'rotated' })
            }
            if (!(await (call.sleep ?? sleep)(w.delayMs, call.signal))) break
            hop = next
        }

        const run = async (): Promise<{ ok: true; result: R } | { ok: false; err: unknown }> => {
            note({ type: 'reserve.started', target: call.ref(target), relay: relayOf(hop), attempt: attempt + 1 })
            try {
                return { ok: true, result: await call.attempt(target, hop) }
            } catch (err) {
                return { ok: false, err }
            }
        }
        let start = clock()
        let got = await run()
        if (
            !got.ok &&
            !reprobed &&
            (got.err instanceof NoEphemeralError || got.err instanceof BadReserveEnvelopeError)
        ) {
            reprobed = true
            const refreshed = call.reprobeEphemeral ? await call.reprobeEphemeral(target) : null
            if (refreshed !== null) {
                target = refreshed
                start = clock()
                got = await run()
            }
        }

        last = { target, hop, elapsedMs: clock() - start }
        if (got.ok) {
            last.result = got.result
            // Same target, another relay, success: the target was up, so the
            // most recent held relay's failure was its own. One strike only:
            // a target that 5xxs then recovers inside the inner delay looks
            // the same, and one flap must not burn a healthy relay's budget.
            // The succeeding relay is not credited; the paid forward does that.
            const bad = unattributed.at(-1)
            if (bad !== undefined) call.recordRelayFailure(bad)
            return last
        }
        const err = got.err
        last.err = err

        if (!(err instanceof ReserveHTTPError)) return last
        const v = narrowReserveVerdict(err, reserveRouteFor(err, hop, call.signal))
        if (!v.retryable) return last
        retryAfterMs = err.retryAfterMs
        failed = err
        failedAttribution = v.attribution
        if (call.usePrivacy && hop !== null) {
            if (v.attribution === Attribution.Relay) call.recordRelayFailure(hop)
            else if (v.attribution === Attribution.Unknown) unattributed.push(hop)
        }
    }
    return last
}

function retrying(
    target: NodeRef,
    err: unknown,
    attribution: AttributionValue,
    waitMs: number,
    attempt: number,
): ReserveRetrying {
    const http = err instanceof ReserveHTTPError
    return {
        type: 'reserve.retrying',
        target,
        status: http ? err.status : 0,
        code: http ? err.code : '',
        attribution,
        wait: waitMs,
        attempt,
    }
}
