/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Per-relay forward reliability, mirroring proto/go/zs/relay_reputation.go.
// This tracks whether forwards THROUGH a node succeed, which is distinct from
// the node's own probe health: a non-compliant fork can answer its own details
// probe, staying a valid target, while dropping every forward. Its failure
// streak climbs and relay selection demotes it.
//
// The demotion is soft: a downranked relay drops to selectRelay's fallback
// tier and is never excluded, so the cold-start fallback still holds. A
// downranked relay is not picked while a healthy pool exists, so it never
// earns the success that would clear it; evidence therefore also ages, one
// unit per cooldown (decay, not reset).
//
// There are three streaks, each with its own rules: proven forward failures,
// stale ephemeral advertisements served through the relay, and gateway
// timeouts the shared verdict refuses to attribute. Each is kept apart so that
// credits earned on one can't erase evidence on another.

import {
    type Evidence,
    RELAY_REPUTATION_COOLDOWN_MS,
    RELAY_TIMEOUT_COOLDOWN_MS,
    bump,
    decay,
    relayDownranked,
} from '@txnlab/zs-proto/steering'

import type { Clock } from '../ports.js'
import { type NodeRef, nodeRefString } from '../types.js'

export interface RelayReputationOptions {
    clock: Clock
    /**
     * Whether the target node's own discovery probe found it reachable this
     * cycle, possibly through another relay. An unprobed node is false.
     */
    targetReachable: (target: NodeRef) => boolean
}

/** A relay's standing evidence on each streak. */
export interface RelayStanding {
    failures: number
    stale: number
    timeouts: number
}

export class RelayReputationStore {
    readonly #clock: Clock
    readonly #targetReachable: (target: NodeRef) => boolean
    // Keyed by relay node: one operator's nodes accrue independent streaks.
    // Sparse: an entry exists only while evidence survives.
    readonly #failures = new Map<string, Evidence>()
    // Separate from #failures: a stale block still forwarded fine, and the
    // discovery probe credits #failures in the same cycle, which would reset
    // the staleness signal before it crossed the threshold.
    readonly #stale = new Map<string, Evidence>()
    // Separate for a sharper form of the same reason. The fault it catches is
    // a front door that kills only byte-silent forwards. A buffered relayed
    // request is silent until its target's headers arrive, while streamed
    // forwards stay alive on the node's keepalive and reserves finish in
    // milliseconds; so the relay timing out every buffered forward is credited
    // on #failures many times a minute. For the same reason a success never
    // clears it.
    readonly #timeouts = new Map<string, Evidence>()

    constructor(opts: RelayReputationOptions) {
        this.#clock = opts.clock
        this.#targetReachable = opts.targetReachable
    }

    /**
     * recordRelayOutcome notes whether a forward through the relay succeeded.
     * A success clears the failure streak, returning the relay to the preferred
     * tier at once; a failure ages the standing evidence and adds one.
     */
    recordRelayOutcome(relay: NodeRef, ok: boolean): void {
        const key = nodeRefString(relay)
        if (ok) {
            this.#failures.delete(key)
            return
        }
        this.#failures.set(key, bump(this.#failures.get(key), this.#clock(), RELAY_REPUTATION_COOLDOWN_MS))
    }

    /**
     * recordRelayUpstreamUnreachable records a relay's claim (a
     * relay_upstream_unreachable response) that target was down. That code is
     * the one relay error attributed to the target, so a fork could otherwise
     * black-hole every forward behind it and never accrue a streak. The claim
     * is resolved differentially: about a target we saw reachable this cycle
     * it is contradicted and counts against the relay; otherwise it credits
     * the relay, so an honest forwarder isn't punished for a dead target.
     */
    recordRelayUpstreamUnreachable(relay: NodeRef, target: NodeRef): void {
        this.recordRelayOutcome(relay, !this.#targetReachable(target))
    }

    /**
     * recordRelayForwardedTargetFault records a code-less transient status from
     * a relay that provably ran its handler (it stamped the relay-hop header),
     * so the status is nominally the target's. Like
     * recordRelayUpstreamUnreachable, but penalty-only: when the target was
     * seen reachable it counts against the relay, and otherwise nothing is
     * recorded. The relay asserted nothing beyond "my handler ran", so crediting
     * it would let ordinary target restarts keep a half-broken relay under the
     * threshold indefinitely.
     */
    recordRelayForwardedTargetFault(relay: NodeRef, target: NodeRef): void {
        if (!this.#targetReachable(target)) return
        this.recordRelayOutcome(relay, false)
    }

    /**
     * recordRelayStaleEphemeral notes that the relay served a valid but stale
     * ephemeral advertisement for some target: an older key block than the
     * target should have.
     */
    recordRelayStaleEphemeral(relay: NodeRef): void {
        const key = nodeRefString(relay)
        this.#stale.set(key, bump(this.#stale.get(key), this.#clock(), RELAY_REPUTATION_COOLDOWN_MS))
    }

    /** recordRelayFreshEphemeral clears the staleness streak; the failure streak is untouched. */
    recordRelayFreshEphemeral(relay: NodeRef): void {
        this.#stale.delete(nodeRefString(relay))
    }

    /**
     * recordRelayForwardTimeout records a forward through the relay that died
     * with a gateway timeout the shared verdict left unattributed.
     *
     * Penalty-only, like recordRelayForwardedTargetFault: a timeout asserts
     * nothing, so there is no claim it can have been right about. A details
     * probe is a tiny GET that succeeds against a target whose generation is
     * slow, which makes the corroboration weaker than for a hop error; hence
     * the separate streak, the higher threshold and the slower decay.
     */
    recordRelayForwardTimeout(relay: NodeRef, target: NodeRef): void {
        if (!this.#targetReachable(target)) return
        const key = nodeRefString(relay)
        this.#timeouts.set(key, bump(this.#timeouts.get(key), this.#clock(), RELAY_TIMEOUT_COOLDOWN_MS))
    }

    /**
     * relayDownranked reports whether the relay's standing evidence on any
     * streak demotes it in relay selection.
     *
     * Despite the name this mutates: it is where evidence ages, since a
     * downranked relay is not selected and a call is the only occasion to
     * notice time has passed. Callers may treat it as a query.
     */
    relayDownranked(relay: NodeRef): boolean {
        const key = nodeRefString(relay)
        const now = this.#clock()
        // All read unconditionally: each read ages its own map, and a
        // short-circuit would leave a streak undecayed while another stays
        // over threshold.
        const failures = pruneAndRead(this.#failures, key, now, RELAY_REPUTATION_COOLDOWN_MS)
        const stale = pruneAndRead(this.#stale, key, now, RELAY_REPUTATION_COOLDOWN_MS)
        const timeouts = pruneAndRead(this.#timeouts, key, now, RELAY_TIMEOUT_COOLDOWN_MS)
        return relayDownranked(failures, stale, timeouts)
    }

    /**
     * standing returns the relay's raw counts without aging them. A threshold
     * check can't show that one response charged the relay: on the inference
     * leg the reserve's success just cleared the failure streak, so a proven
     * fault there never passes 1.
     */
    standing(relay: NodeRef): RelayStanding {
        const key = nodeRefString(relay)
        return {
            failures: this.#failures.get(key)?.count ?? 0,
            stale: this.#stale.get(key)?.count ?? 0,
            timeouts: this.#timeouts.get(key)?.count ?? 0,
        }
    }

    clear(): void {
        this.#failures.clear()
        this.#stale.clear()
        this.#timeouts.clear()
    }
}

// pruneAndRead writes back the aged entry, or deletes one that fully decayed,
// and returns the surviving count. decay advances `at` by the windows consumed,
// so reading twice at one instant does not compound.
//
// An entry dated after now means the wall clock stepped back. Decay can't run
// backwards, so it would pause until the clock caught up; Go's monotonic clock
// never sees the step. Re-dating the entry to now bounds the pause to the
// fraction of a window already elapsed.
function pruneAndRead(m: Map<string, Evidence>, key: string, now: number, cooldownMs: number): number {
    const e = m.get(key)
    if (e === undefined) return 0
    if (now < e.at) {
        m.set(key, { count: e.count, at: now })
        return e.count
    }
    const aged = decay(e, now, cooldownMs)
    if (aged === undefined) {
        m.delete(key)
        return 0
    }
    if (aged !== e) m.set(key, aged)
    return aged.count
}
