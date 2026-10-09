/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// classifyReserveFailure and nextResweep, checked against
// testdata/dispatch_verdict_vectors.json, which Go's twins generate. Each case
// describes its error as data; errorOf builds the real SDK error from it, as
// Go's verdictErr builds its own, so the vectors run the real classifier.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { BadReserveEnvelopeError, BusyError, NoEphemeralError, PayerRefusalError, ReserveHTTPError, SizeError } from '../src/reserve.js'
import {
    MAX_NODE_RETRY_HINT_MS,
    type ReserveRoute,
    type SweepOutcome,
    classifyReserveFailure,
    nextResweep,
    reserveRouteFor,
} from '../src/routing/index.js'
import type { RelayHop } from '../src/routing/relay.js'

interface VectorError {
    kind: string
    status?: number
    code?: string
    retry_after_ms?: number
    relay_hop_marked?: boolean
}

interface FailureCase {
    name: string
    error: VectorError
    route: { relayed: boolean; relay_marks_hops: boolean; caller_aborted: boolean }
    use_privacy: boolean
    want: {
        outcome: string
        stop: boolean
        strike: boolean
        refused: boolean
        hard_refused: boolean
        busy: boolean
        busy_resweepable: boolean
        transient: boolean
        size_rejected: boolean
        ephemeral_missing: boolean
        hint_ms: number
        attribution: string
    }
}

interface ResweepCase {
    name: string
    input: Record<string, boolean>
    want: string
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/dispatch_verdict_vectors.json', import.meta.url), 'utf8'),
) as { failures: FailureCase[]; resweeps: ResweepCase[] }

function errorOf(e: VectorError): unknown {
    const retryAfterMs = e.retry_after_ms ?? 0
    const code = e.code ?? ''
    switch (e.kind) {
        case 'busy':
            return new BusyError(code, retryAfterMs)
        case 'size':
            return new SizeError(code, 'too big')
        case 'payer_refusal':
            return new PayerRefusalError(code, 'spent', retryAfterMs)
        case 'no_ephemeral':
            return new NoEphemeralError()
        case 'bad_reserve_envelope':
            return new BadReserveEnvelopeError()
        case 'http': {
            const status = e.status ?? 0
            return new ReserveHTTPError(
                { status, code, retryAfterMs, relayHopMarked: e.relay_hop_marked ?? false },
                status === 0 ? new Error('connection refused') : undefined,
            )
        }
        case 'other':
            return new Error('something else')
        default:
            throw new Error(`unknown error kind ${e.kind}`)
    }
}

describe('classifyReserveFailure vectors', () => {
    it('covers every outcome', () => {
        const outcomes = new Set(vectors.failures.map((c) => c.want.outcome))
        expect([...outcomes].sort()).toEqual(['busy', 'no_ephemeral', 'payer_refusal', 'refused', 'size', 'transient'])
    })

    for (const c of vectors.failures) {
        it(c.name, () => {
            const route: ReserveRoute = {
                relayed: c.route.relayed,
                relayMarksHops: c.route.relay_marks_hops,
                callerAborted: c.route.caller_aborted,
            }
            const f = classifyReserveFailure(errorOf(c.error), route, c.use_privacy)
            expect({
                outcome: f.outcome,
                stop: f.stop,
                strike: f.strike,
                refused: f.refused,
                hard_refused: f.hardRefused,
                busy: f.busy,
                busy_resweepable: f.busyResweepable,
                transient: f.transient,
                size_rejected: f.sizeRejected,
                ephemeral_missing: f.ephemeralMissing,
                hint_ms: f.hintMs,
                attribution: f.attribution,
            }).toEqual(c.want)
        })
    }
})

describe('nextResweep vectors', () => {
    const fields: (keyof SweepOutcome)[] = [
        'transient',
        'refused',
        'busy',
        'hardRefused',
        'sizeRejected',
        'anyBusy',
        'relayUnavailable',
        'toolFactorMissing',
        'ephemeralMissing',
        'priceRejected',
        'busyBudgetLeft',
    ]
    const snake = (k: string) => k.replace(/[A-Z]/g, (m) => `_${m.toLowerCase()}`)

    it('covers every reason', () => {
        expect([...new Set(vectors.resweeps.map((c) => c.want))].sort()).toEqual(['busy', 'none', 'weather'])
    })

    it('names every SweepOutcome field and nothing else', () => {
        for (const c of vectors.resweeps) expect(Object.keys(c.input).sort()).toEqual(fields.map(snake).sort())
    })

    for (const c of vectors.resweeps) {
        it(c.name, () => {
            const o = Object.fromEntries(fields.map((k) => [k, c.input[snake(k)]])) as unknown as SweepOutcome
            expect(nextResweep(o)).toBe(c.want)
        })
    }
})

describe('reserveRouteFor', () => {
    const hop = (relayProtoVersion: string) => ({ relayProtoVersion }) as RelayHop
    const transport = (aborted: boolean) => new ReserveHTTPError({ status: 0, aborted }, new Error('reset'))

    it('reports a direct reserve as unrelayed, whatever the error', () => {
        expect(reserveRouteFor(transport(true), null)).toEqual({ relayed: false, relayMarksHops: false, callerAborted: false })
    })

    it('reads the hop marker from the relay advertised version', () => {
        expect(reserveRouteFor(transport(false), hop('9.1')).relayMarksHops).toBe(true)
        expect(reserveRouteFor(transport(false), hop('9.0')).relayMarksHops).toBe(false)
    })

    it('counts our own timeout as the caller aborting', () => {
        expect(reserveRouteFor(transport(true), hop('9.1')).callerAborted).toBe(true)
        expect(reserveRouteFor(transport(false), hop('9.1')).callerAborted).toBe(false)
    })

    it('counts a fired dispatch signal as the caller aborting, even on a status', () => {
        const ac = new AbortController()
        ac.abort()
        const re = new ReserveHTTPError({ status: 502 })
        expect(reserveRouteFor(re, hop('9.1'), ac.signal).callerAborted).toBe(true)
        expect(reserveRouteFor(re, hop('9.1')).callerAborted).toBe(false)
    })

    it('never marks an error other than a ReserveHTTPError aborted', () => {
        const ac = new AbortController()
        ac.abort()
        expect(reserveRouteFor(new BusyError('no_capacity', 0), hop('9.1'), ac.signal).callerAborted).toBe(false)
    })
})

describe('MAX_NODE_RETRY_HINT_MS', () => {
    it('is five minutes, as Go caps it', () => {
        expect(MAX_NODE_RETRY_HINT_MS).toBe(300_000)
    })
})
