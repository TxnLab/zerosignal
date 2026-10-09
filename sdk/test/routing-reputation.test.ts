/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import {
    RELAY_DOWNRANK_THRESHOLD as THRESHOLD,
    RELAY_REPUTATION_COOLDOWN_MS as COOLDOWN,
    RELAY_TIMEOUT_COOLDOWN_MS as TIMEOUT_COOLDOWN,
    RELAY_TIMEOUT_DOWNRANK_THRESHOLD as TIMEOUT_THRESHOLD,
} from '@txnlab/zs-proto/steering'

import { RelayReputationStore } from '../src/routing/index.js'
import { type NodeRef, nodeRefString } from '../src/index.js'

const relay: NodeRef = { op: 2, node: 0 }
const target: NodeRef = { op: 7, node: 0 }

function harness(start = 0) {
    let now = start
    const up = new Set<string>()
    const store = new RelayReputationStore({
        clock: () => now,
        targetReachable: (t) => up.has(nodeRefString(t)),
    })
    return {
        store,
        at: (t: number) => (now = t),
        up: (...ts: NodeRef[]) => ts.forEach((t) => up.add(nodeRefString(t))),
        fail: (n: number, r: NodeRef = relay) => {
            for (let i = 0; i < n; i++) store.recordRelayOutcome(r, false)
        },
    }
}

// The values are pinned against Go by the steering vectors; the relation is
// not. The timeout streak's evidence is weaker (a higher threshold) and rarer,
// with no probe feeder (a longer cooldown); equalizing either on both sides at
// once would pass the vectors.
it('the timeout streak costs more strikes and decays slower than the failure streak', () => {
    expect(TIMEOUT_THRESHOLD).toBeGreaterThan(THRESHOLD)
    expect(TIMEOUT_COOLDOWN).toBeGreaterThan(COOLDOWN)
})

describe('RelayReputationStore', () => {
    it('downranks only at the threshold of consecutive failures', () => {
        const h = harness()
        for (let i = 1; i < THRESHOLD; i++) {
            h.fail(1)
            expect(h.store.relayDownranked(relay)).toBe(false)
        }
        h.fail(1)
        expect(h.store.relayDownranked(relay)).toBe(true)
    })

    it('a success clears the streak to zero', () => {
        const h = harness()
        h.fail(THRESHOLD)
        h.store.recordRelayOutcome(relay, true)
        expect(h.store.relayDownranked(relay)).toBe(false)
        h.fail(THRESHOLD - 1)
        expect(h.store.relayDownranked(relay)).toBe(false)
    })

    it('keys by node: a dead node neither downranks nor is cleared by its sibling', () => {
        const h = harness()
        const dead = { op: 3, node: 4 }
        const sibling = { op: 3, node: 2 }
        h.fail(THRESHOLD, dead)
        expect(h.store.relayDownranked(dead)).toBe(true)
        expect(h.store.relayDownranked(sibling)).toBe(false)
        h.store.recordRelayOutcome(sibling, true)
        expect(h.store.relayDownranked(dead)).toBe(true)
    })

    // A downranked relay is not selected while a healthy pool exists, so it
    // never earns the success that clears it; without aging, a demotion would
    // be permanent.
    describe('evidence decay', () => {
        it('ages one unit per cooldown, so a repeat offender re-crosses on its next failure', () => {
            const h = harness()
            h.fail(THRESHOLD)
            h.at(COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(false)
            h.fail(1)
            expect(h.store.relayDownranked(relay)).toBe(true)
        })

        it('lets a recovered relay walk back to zero', () => {
            const h = harness()
            h.fail(THRESHOLD)
            h.at(THRESHOLD * COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(false)
            expect(h.store.standing(relay).failures).toBe(0)
            h.fail(THRESHOLD - 1)
            expect(h.store.relayDownranked(relay)).toBe(false)
        })

        // Aging from now instead of from the windows consumed would stretch
        // the decay under traffic, since every request reads. Only a
        // fractional offset tells the two apart.
        it('carries the residual fraction across a read', () => {
            const h = harness()
            h.fail(THRESHOLD)
            h.at(1.5 * COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(false)
            h.at(2 * COOLDOWN)
            h.fail(1)
            expect(h.store.standing(relay).failures).toBe(THRESHOLD - 1)
        })

        it('dates a fresh failure at the observation, not the boundary it aged to', () => {
            const h = harness()
            h.fail(THRESHOLD)
            h.at(1.5 * COOLDOWN)
            h.fail(1)
            h.at(2.4 * COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(true)
        })

        it('a failure after full decay starts a fresh streak', () => {
            const h = harness()
            h.fail(THRESHOLD)
            h.at(THRESHOLD * COOLDOWN)
            h.fail(1)
            expect(h.store.standing(relay).failures).toBe(1)
        })

        // Browser clocks step back (NTP, resume, a user's edit). A negative
        // step count would grow the evidence.
        it('a backwards clock neither ages nor grows the evidence', () => {
            const h = harness()
            h.fail(THRESHOLD - 1)
            h.at(-5 * COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(false)
            expect(h.store.standing(relay).failures).toBe(THRESHOLD - 1)
        })

        // Go's monotonic clock never sees the step, so decay must resume from
        // the new now rather than wait for the clock to catch up.
        it('after a backwards step, decay resumes one cooldown from the step', () => {
            const h = harness(10 * COOLDOWN)
            h.fail(THRESHOLD)
            h.at(0)
            expect(h.store.relayDownranked(relay)).toBe(true)
            h.at(COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(false)
            expect(h.store.standing(relay).failures).toBe(THRESHOLD - 1)
        })
    })

    describe('relay_upstream_unreachable', () => {
        it('charges the relay when the target was seen reachable', () => {
            const h = harness()
            h.up(target)
            for (let i = 0; i < THRESHOLD; i++) h.store.recordRelayUpstreamUnreachable(relay, target)
            expect(h.store.relayDownranked(relay)).toBe(true)
        })

        it('credits the relay when the target was not, clearing its streak', () => {
            const h = harness()
            h.fail(THRESHOLD - 1)
            h.store.recordRelayUpstreamUnreachable(relay, target)
            expect(h.store.standing(relay).failures).toBe(0)
        })

        it('asks about the target node, not its operator sibling', () => {
            const h = harness()
            h.up({ op: 7, node: 1 })
            for (let i = 0; i < THRESHOLD; i++) h.store.recordRelayUpstreamUnreachable(relay, { op: 7, node: 2 })
            expect(h.store.relayDownranked(relay)).toBe(false)
            for (let i = 0; i < THRESHOLD; i++) h.store.recordRelayUpstreamUnreachable(relay, { op: 7, node: 1 })
            expect(h.store.relayDownranked(relay)).toBe(true)
        })
    })

    describe('forwarded target faults', () => {
        it('charge the relay when the target was seen reachable', () => {
            const h = harness()
            h.up(target)
            for (let i = 0; i < THRESHOLD; i++) h.store.recordRelayForwardedTargetFault(relay, target)
            expect(h.store.relayDownranked(relay)).toBe(true)
        })

        // Unlike relay_upstream_unreachable: the relay claimed nothing, so a
        // dead target must not wipe its streak.
        it('record nothing, not even a credit, otherwise', () => {
            const h = harness()
            h.fail(THRESHOLD - 1)
            h.store.recordRelayForwardedTargetFault(relay, target)
            expect(h.store.standing(relay).failures).toBe(THRESHOLD - 1)
        })
    })

    describe('stale ephemerals', () => {
        it('downrank at the threshold on their own streak', () => {
            const h = harness()
            for (let i = 1; i < THRESHOLD; i++) {
                h.store.recordRelayStaleEphemeral(relay)
                expect(h.store.relayDownranked(relay)).toBe(false)
            }
            h.store.recordRelayStaleEphemeral(relay)
            expect(h.store.relayDownranked(relay)).toBe(true)
            expect(h.store.standing(relay)).toEqual({ failures: 0, stale: THRESHOLD, timeouts: 0 })
        })

        // A stale block still forwards, and discovery credits that forward
        // in the same cycle.
        it('survive successful forwards, and a fresh block clears only them', () => {
            const h = harness()
            h.fail(1)
            for (let i = 0; i < THRESHOLD; i++) {
                h.store.recordRelayStaleEphemeral(relay)
                h.store.recordRelayOutcome(relay, true)
            }
            expect(h.store.relayDownranked(relay)).toBe(true)
            h.fail(1)
            h.up(target)
            h.store.recordRelayForwardTimeout(relay, target)
            h.store.recordRelayFreshEphemeral(relay)
            expect(h.store.standing(relay)).toEqual({ failures: 1, stale: 0, timeouts: 1 })
        })

        // At record time as well as at read, and on the short clock as in Go.
        it('age on the reputation cooldown when a new one is recorded', () => {
            const h = harness()
            h.store.recordRelayStaleEphemeral(relay)
            h.store.recordRelayStaleEphemeral(relay)
            h.at(COOLDOWN + 1)
            h.store.recordRelayStaleEphemeral(relay)
            expect(h.store.standing(relay).stale).toBe(THRESHOLD - 1)
            expect(h.store.relayDownranked(relay)).toBe(false)
        })

        it('age on the reputation cooldown', () => {
            const h = harness()
            for (let i = 0; i < THRESHOLD; i++) h.store.recordRelayStaleEphemeral(relay)
            h.at(COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(false)
            expect(h.store.standing(relay).stale).toBe(THRESHOLD - 1)
        })
    })

    describe('forward timeouts', () => {
        it('downrank only at their own higher threshold', () => {
            const h = harness()
            h.up(target)
            for (let i = 1; i < TIMEOUT_THRESHOLD; i++) {
                h.store.recordRelayForwardTimeout(relay, target)
                expect(h.store.relayDownranked(relay)).toBe(false)
            }
            h.store.recordRelayForwardTimeout(relay, target)
            expect(h.store.relayDownranked(relay)).toBe(true)
            expect(h.store.standing(relay)).toEqual({ failures: 0, stale: 0, timeouts: TIMEOUT_THRESHOLD })
        })

        // The relay asserted nothing, so there is nothing to credit.
        it('record nothing, not even a credit, when the target was not seen reachable', () => {
            const h = harness()
            h.fail(THRESHOLD)
            h.store.recordRelayForwardTimeout(relay, target)
            expect(h.store.standing(relay)).toEqual({ failures: THRESHOLD, stale: 0, timeouts: 0 })
        })

        // A relay behind a front door that kills silent forwards still carries
        // every streamed forward and reserve, and is credited for them.
        it('survive successful forwards', () => {
            const h = harness()
            h.up(target)
            for (let i = 0; i < TIMEOUT_THRESHOLD; i++) {
                h.store.recordRelayForwardTimeout(relay, target)
                h.store.recordRelayOutcome(relay, true)
            }
            expect(h.store.relayDownranked(relay)).toBe(true)
        })

        // At record time too, not just at read: aged on the short clock, one
        // timeout every 10 minutes would sit at 4 forever.
        it('age on their own clock when a new timeout is recorded', () => {
            const h = harness()
            h.up(target)
            for (let i = 0; i < TIMEOUT_THRESHOLD - 1; i++) h.store.recordRelayForwardTimeout(relay, target)
            h.at(COOLDOWN)
            h.store.recordRelayForwardTimeout(relay, target)
            expect(h.store.standing(relay).timeouts).toBe(TIMEOUT_THRESHOLD)
            expect(h.store.relayDownranked(relay)).toBe(true)
        })

        it('age on their own, longer clock, from the windows consumed', () => {
            const start = 1_700_000_000_000
            const h = harness(start)
            h.up(target)
            for (let i = 0; i < TIMEOUT_THRESHOLD; i++) h.store.recordRelayForwardTimeout(relay, target)
            h.at(start + COOLDOWN * 1.5)
            expect(h.store.relayDownranked(relay)).toBe(true)
            h.at(start + TIMEOUT_COOLDOWN * 1.5)
            expect(h.store.relayDownranked(relay)).toBe(false)
            h.at(start + TIMEOUT_COOLDOWN * 2)
            expect(h.store.relayDownranked(relay)).toBe(false)
            expect(h.store.standing(relay).timeouts).toBe(TIMEOUT_THRESHOLD - 2)
        })

        // Both streaks age on every read: a short-circuit would freeze the
        // timeout streak while the failure streak stays over the line.
        it('age even while the failure streak is over threshold', () => {
            const h = harness()
            h.up(target)
            h.store.recordRelayForwardTimeout(relay, target)
            h.at(TIMEOUT_COOLDOWN - 1)
            h.fail(THRESHOLD)
            h.at(TIMEOUT_COOLDOWN)
            expect(h.store.relayDownranked(relay)).toBe(true)
            expect(h.store.standing(relay).timeouts).toBe(0)
        })
    })

    it('clear forgets every streak', () => {
        const h = harness()
        h.up(target)
        h.fail(THRESHOLD)
        h.store.recordRelayStaleEphemeral(relay)
        h.store.recordRelayForwardTimeout(relay, target)
        h.store.clear()
        expect(h.store.standing(relay)).toEqual({ failures: 0, stale: 0, timeouts: 0 })
    })
})
