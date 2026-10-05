/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// reserveWithTransientRetry, checked against testdata/reserve_retry_vectors.json,
// which Go's retryReserve generates. Each scenario injects the same fakes on
// both sides: a clock a wait advances, a rotation that takes the first relay
// in the pool not yet excluded, and a script of reserve outcomes.

import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'

import type { Event } from '../src/events.js'
import {
    BadReserveEnvelopeError,
    NoEphemeralError,
    ReserveHTTPError,
    reserveWithTransientRetry,
} from '../src/index.js'
import { type RelayHop, relayRef } from '../src/routing/index.js'
import { nodeRefString } from '../src/types.js'

interface Outcome {
    kind: string
    status?: number
    code?: string
    marked?: boolean
    aborted?: boolean
    retry_after_ms?: number
}

interface Scenario {
    name: string
    use_privacy: boolean
    relays: VectorRelay[] | null
    budget_ms: number
    attempt_ms: number
    script: Outcome[]
    reprobe: boolean
    abort_sleep: boolean
    want: {
        calls: { relay: string | null; reprobed: boolean }[]
        relay_failures: string[]
        events: Record<string, unknown>[]
        result: string
        final_hop: string | null
        final_reprobed: boolean
        elapsed_ms: number
    }
}

interface VectorRelay {
    id: number
    node: number
    proto_version: string
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/reserve_retry_vectors.json', import.meta.url), 'utf8'),
) as { scenarios: Scenario[] }

function errorOf(o: Outcome): Error | null {
    switch (o.kind) {
        case 'ok':
            return null
        case 'http':
            return new ReserveHTTPError({
                status: o.status ?? 0,
                code: o.code ?? '',
                relayHopMarked: o.marked ?? false,
                retryAfterMs: o.retry_after_ms ?? 0,
                aborted: o.aborted ?? false,
            })
        case 'bad_reserve_envelope':
            return new BadReserveEnvelopeError()
        case 'no_ephemeral':
            return new NoEphemeralError()
        default:
            return new Error('other')
    }
}

function describeResult(err: unknown): string {
    if (err === undefined) return 'ok'
    if (err instanceof BadReserveEnvelopeError) return 'bad_reserve_envelope'
    if (err instanceof NoEphemeralError) return 'no_ephemeral'
    if (err instanceof ReserveHTTPError) return err.code ? `http ${err.status} ${err.code}` : `http ${err.status}`
    return 'other'
}

// Go's omitempty: a nil, zero or empty field is left out.
function compact(e: Record<string, unknown>): Record<string, unknown> {
    return Object.fromEntries(Object.entries(e).filter(([, v]) => v !== null && v !== 0 && v !== ''))
}

const nameOf = (r: { op: number | bigint; node: number | bigint } | null): string | null =>
    r === null ? null : `${r.op}/${r.node}`
const hopName = (h: RelayHop | null): string | null => (h === null ? null : nameOf(relayRef(h)))

function eventOf(e: Event): Record<string, unknown> {
    switch (e.type) {
        case 'reserve.started':
            return compact({ type: e.type, relay: nameOf(e.relay), attempt: e.attempt })
        case 'reserve.retrying':
            return compact({
                type: e.type,
                attempt: e.attempt,
                status: e.status,
                code: e.code,
                attribution: e.attribution,
                wait_ms: e.wait,
            })
        case 'relay.hop':
            return compact({ type: e.type, relay: nameOf(e.relay), reason: e.reason })
        default:
            throw new Error(`unexpected event ${e.type}`)
    }
}

interface Candidate {
    reprobed: boolean
}

async function run(sc: Scenario): Promise<Scenario['want']> {
    const pool = sc.relays ?? []
    const hopFor = (r: VectorRelay): RelayHop => ({
        baseUrl: `https://relay${r.id}-${r.node}.example`,
        targetId: 1,
        targetNodeId: 1,
        relayId: r.id,
        relayNodeId: r.node,
        relayProtoVersion: r.proto_version,
    })
    let now = 1_700_000_000_000
    let calls = 0
    const got: Scenario['want'] = {
        calls: [],
        relay_failures: [],
        events: [],
        result: '',
        final_hop: null,
        final_reprobed: false,
        elapsed_ms: 0,
    }
    const attempt = await reserveWithTransientRetry<Candidate, string>({
        target: { reprobed: false },
        ref: () => ({ op: 1, node: 1 }),
        hop: sc.use_privacy && pool.length > 0 ? hopFor(pool[0]!) : null,
        usePrivacy: sc.use_privacy,
        deadlineMs: now + sc.budget_ms,
        async attempt(target, hop) {
            got.calls.push({ relay: hopName(hop), reprobed: target.reprobed })
            const o = sc.script[Math.min(calls, sc.script.length - 1)]!
            calls++
            now += sc.attempt_ms
            const err = errorOf(o)
            if (err) throw err
            return 'ticket'
        },
        nextHop(_target, excluded) {
            for (const r of pool) {
                const h = hopFor(r)
                if (!excluded.has(nodeRefString(relayRef(h)))) return h
            }
            return null
        },
        reprobeEphemeral: async () => (sc.reprobe ? { reprobed: true } : null),
        recordRelayFailure: (hop) => got.relay_failures.push(hopName(hop)!),
        note: (e) => got.events.push(eventOf(e)),
        clock: () => now,
        sleep: async (ms) => {
            if (sc.abort_sleep) return false
            now += ms
            return true
        },
    })
    got.result = attempt.err === undefined && attempt.result === undefined ? 'no ticket' : describeResult(attempt.err)
    got.final_hop = hopName(attempt.hop)
    got.final_reprobed = attempt.target.reprobed
    got.elapsed_ms = attempt.elapsedMs
    return got
}

describe('reserveWithTransientRetry', () => {
    it('has vectors', () => {
        expect(vectors.scenarios.length).toBeGreaterThan(0)
    })

    it.each(vectors.scenarios.map((sc) => [sc.name, sc] as const))('%s', async (_, sc) => {
        expect(await run(sc)).toEqual(sc.want)
    })

    // The default sleep and the caller's signal, which the vectors replace
    // with fakes: Go pins its twins (sleepCtx, the ctx in callerAborted) in
    // its own tests.
    describe('with the caller signal', () => {
        const relay = (id: number): RelayHop => ({
            baseUrl: `https://relay${id}.example`,
            targetId: 1,
            targetNodeId: 1,
            relayId: id,
            relayNodeId: 1,
            relayProtoVersion: '9.1',
        })

        function call(signal: AbortSignal, outcomes: (Error | null)[]) {
            const failures: number[] = []
            const calls: number[] = []
            const run = reserveWithTransientRetry<null, string>({
                target: null,
                ref: () => ({ op: 1, node: 1 }),
                hop: relay(2),
                usePrivacy: true,
                deadlineMs: Date.now() + 60_000,
                async attempt(_t, hop) {
                    calls.push(hop!.relayId)
                    const err = outcomes[Math.min(calls.length - 1, outcomes.length - 1)]
                    if (err) throw err
                    return 'ticket'
                },
                nextHop: (_t, excluded) => (excluded.has(nodeRefString(relayRef(relay(3)))) ? null : relay(3)),
                recordRelayFailure: (hop) => failures.push(hop.relayId),
                signal,
            })
            return { run, failures, calls }
        }

        it('waits out the schedule, then rotates', async () => {
            vi.useFakeTimers()
            try {
                const c = call(new AbortController().signal, [new ReserveHTTPError({ status: 0 }), null])
                await vi.advanceTimersByTimeAsync(500)
                const got = await c.run
                expect(got.result).toBe('ticket')
                expect(c.calls).toEqual([2, 3])
                // A transport failure through a relay is the relay's.
                expect(c.failures).toEqual([2])
            } finally {
                vi.useRealTimers()
            }
        })

        it('reads a transport failure after our own abort as nobody\'s, and stops at the wait', async () => {
            const abort = new AbortController()
            abort.abort()
            const c = call(abort.signal, [new ReserveHTTPError({ status: 0 }), null])
            const got = await c.run
            expect(got.err).toBeInstanceOf(ReserveHTTPError)
            expect(c.calls).toEqual([2])
            expect(c.failures).toEqual([])
        })
    })
})
