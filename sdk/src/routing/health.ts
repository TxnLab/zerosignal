/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Short-lived memory of relays whose first-hop contact just failed: the
// transient half of relay steering. The cross-request half, a failure streak
// that softly demotes a persistently bad relay, is RelayReputationStore. Go
// splits the same way, between its per-cycle exclusions and lastReachable and
// its relay reputation.
//
// The exclusion steers; it never gates. It must not cut availability below
// what the pool can serve, so marks age out after their TTL, a relay that
// proves reachable is cleared at once, and the caller retries without the
// exclusions rather than fail when they would strand a request.

import type { Clock } from '../ports.js'
import { type NodeRef, nodeRefString } from '../types.js'
import { boundedMapSet } from './bounded-map.js'
import type { RelayReputationStore } from './reputation.js'

/**
 * How long a transient hop failure excludes a relay: about one discovery probe
 * cycle, after which a fresh details probe has had a chance to settle the
 * relay's reachability independently.
 */
export const RELAY_UNREACHABLE_TTL_MS = 30_000

/**
 * How long a relay the payer could not connect to at all is excluded. A
 * transport failure to the relay's own endpoint (offline, DNS, TLS, a blocked
 * port, CORS) is a far stronger, device-level signal than a relay that
 * answered but could not forward, so it is parked for minutes rather than
 * retried every probe cycle.
 */
export const RELAY_ENDPOINT_DOWN_TTL_MS = 3 * 60_000

// Evicting a verdict only returns that relay to "unknown", so this bound is a
// memory guardrail a normal fleet never reaches.
const REACH_VERDICT_MAX = 2048

export interface RelayHealthOptions {
    clock: Clock
    /** Charged with the failure streak when a relay can't be reached at all. */
    reputation: Pick<RelayReputationStore, 'recordRelayOutcome'>
}

export class RelayHealthStore {
    readonly #clock: Clock
    readonly #reputation: Pick<RelayReputationStore, 'recordRelayOutcome'>
    // Per-entry ttl lets an endpoint-down park and a transient hop failure
    // share one store.
    readonly #failedAt = new Map<string, { at: number; ttl: number }>()
    // The payer's own sticky verdict on reaching a node AS A RELAY: true after
    // a forward through it succeeded, false after a connection to it failed
    // outright, absent with no direct evidence.
    //
    // This is deliberately distinct from the catalog's reachability, which is
    // TARGET reachability: some relay reached the node through the mesh. In a
    // browser that does not imply the payer can reach the node directly (a
    // localhost or firewalled node, a CORS block), and the reverse holds too.
    // A server reaches every node directly, so for zs-proxy the two coincide.
    // The verdict overrides the catalog hint in selectRelay's preference, so a
    // relay seen failing is demoted on the first failure rather than after the
    // three-strike downrank, and it stays demoted across exclusion TTLs until
    // the next direct contact.
    readonly #reachVerdict = new Map<string, boolean>()

    constructor(opts: RelayHealthOptions) {
        this.#clock = opts.clock
        this.#reputation = opts.reputation
    }

    /**
     * markRelayUnreachable excludes a relay for ttlMs after a transient hop
     * failure: it answered but could not serve this forward. The endpoint is
     * reachable, so the sticky verdict is untouched.
     */
    markRelayUnreachable(relay: NodeRef, ttlMs: number = RELAY_UNREACHABLE_TTL_MS): void {
        this.#park(nodeRefString(relay), ttlMs)
    }

    /**
     * markRelayEndpointDead records that the payer could not connect to the
     * relay at all: the long park, and the sticky false verdict that keeps a
     * never-reachable node from being picked once any working relay is known.
     */
    markRelayEndpointDead(relay: NodeRef): void {
        const key = nodeRefString(relay)
        this.#park(key, RELAY_ENDPOINT_DOWN_TTL_MS)
        boundedMapSet(this.#reachVerdict, key, false, REACH_VERDICT_MAX)
    }

    /**
     * recordRelayTransportFailure records all a relay transport failure proves:
     * the endpoint-dead park and verdict, and a failure on the reputation
     * streak. They are one observation about the relay alone; written out by
     * hand at each site, the reserve rotation once recorded only the streak
     * after its budget ran out and lost the verdict for the attempt that
     * proved it.
     */
    recordRelayTransportFailure(relay: NodeRef): void {
        this.markRelayEndpointDead(relay)
        this.#reputation.recordRelayOutcome(relay, false)
    }

    /** markRelayReachable clears a relay's exclusion and sets the true verdict after a forward through it succeeded. */
    markRelayReachable(relay: NodeRef): void {
        const key = nodeRefString(relay)
        this.#failedAt.delete(key)
        boundedMapSet(this.#reachVerdict, key, true, REACH_VERDICT_MAX)
    }

    /** relayReachVerdict is the sticky direct-contact verdict, or undefined to fall back to the catalog. */
    relayReachVerdict(relay: NodeRef): boolean | undefined {
        return this.#reachVerdict.get(nodeRefString(relay))
    }

    /**
     * relayExclusions returns the nodeRefString of every relay inside its
     * exclusion window, pruning the lapsed ones.
     */
    relayExclusions(now: number = this.#clock()): Set<string> {
        const out = new Set<string>()
        for (const [key, mark] of this.#failedAt) {
            if (now < mark.at) {
                // The wall clock stepped back: re-date the mark so it lasts at
                // most its ttl from here, not ttl plus the step.
                this.#failedAt.set(key, { at: now, ttl: mark.ttl })
                out.add(key)
            } else if (now - mark.at < mark.ttl) {
                out.add(key)
            } else {
                this.#failedAt.delete(key)
            }
        }
        return out
    }

    clear(): void {
        this.#failedAt.clear()
        this.#reachVerdict.clear()
    }

    // #park excludes key for ttlMs from now, keeping any longer park already
    // standing: a transient hop failure through a relay that was parked as
    // endpoint-dead (reached by the stranding fallback) must not cut its
    // minutes-long park to 30 seconds.
    #park(key: string, ttlMs: number): void {
        const now = this.#clock()
        const prior = this.#failedAt.get(key)
        const left = prior === undefined ? 0 : Math.min(prior.at + prior.ttl - now, prior.ttl)
        this.#failedAt.set(key, { at: now, ttl: Math.max(ttlMs, left) })
    }
}
