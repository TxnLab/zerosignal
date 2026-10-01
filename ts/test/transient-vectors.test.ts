/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity for transient-failure classification and the retry
// schedule, against proto/testdata/transient_vectors.json (produced by
// `cd proto/go && go test ./transient -run TestTransientVectors -update`).
//
// The schedule is asserted alongside the classifier because the numbers are the
// user-visible half: a fleet-wide node restart is ridden out for the same minute
// whether the caller is zs-proxy or this browser app, or it isn't.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
    INNER_ATTEMPTS,
    OVERALL_DEADLINE_MS,
    SWEEPS,
    classify,
    innerDelayMs,
    isRelayFrontDoorStatus,
    narrowRelayed,
    sweepDelayMs,
    wait,
} from '../src/transient/index.js'
import { protoVersionCompatible, setsRelayHopHeader } from '../src/wire/version.js'

interface ClassifyCase {
    name: string
    status: number
    code: string
    expected: { retryable: boolean; attribution: string }
}

interface NarrowCase {
    name: string
    status: number
    code: string
    evidence: {
        relayed: boolean
        hop_marker: boolean
        relay_marks_hops: boolean
        caller_aborted: boolean
    }
    expected: { retryable: boolean; attribution: string }
}

// The minor-gated version helpers RelayEvidence.relayMarksHops is derived from.
// Vectored because leaving them unvectored is exactly what let the two ports
// drift: Go's strconv.Atoi accepted a leading "+" the TS regex rejected, and
// JS's parseInt silently overflowed a 20-digit segment to a float where Atoi
// returned ErrRange — the JS direction failing OPEN.
interface VersionCase {
    name: string
    version: string
    compatible: boolean
    at_least_hop_marker: boolean
}

// Membership of the front-door status set. narrowRelayed's rule 4 exercises it
// indirectly, but both DISCOVERY probes call the predicate directly and
// status-first (deliberately ignoring the body), so agreeing member-for-member
// is its own cross-language contract — and the one the two probes drifted on.
interface FrontDoorCase {
    name: string
    status: number
    front_door: boolean
}

interface WaitCase {
    name: string
    scheduled_ms: number
    retry_after_ms: number
    remaining_ms: number
    expected_ms: number
    expected_ok: boolean
}

interface TransientVectorsFile {
    version: number
    comment: string
    schedule: {
        inner_attempts: number
        sweeps: number
        overall_deadline_ms: number
        inner_delays_ms: number[]
        sweep_delays_ms: number[]
    }
    classify_cases: ClassifyCase[]
    narrow_cases: NarrowCase[]
    version_cases: VersionCase[]
    front_door_cases: FrontDoorCase[]
    wait_cases: WaitCase[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'transient_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as TransientVectorsFile

describe('cross-impl transient vectors (proto/testdata/transient_vectors.json)', () => {
    it('vectors file is current schema', () => {
        expect(vectors.version).toBe(2)
        expect(vectors.classify_cases.length).toBeGreaterThan(0)
        expect(vectors.narrow_cases.length).toBeGreaterThan(0)
        expect(vectors.version_cases.length).toBeGreaterThan(0)
        expect(vectors.front_door_cases.length).toBeGreaterThan(0)
        expect(vectors.wait_cases.length).toBeGreaterThan(0)
    })

    it('retry schedule matches the Go table', () => {
        expect(INNER_ATTEMPTS).toBe(vectors.schedule.inner_attempts)
        expect(SWEEPS).toBe(vectors.schedule.sweeps)
        expect(OVERALL_DEADLINE_MS).toBe(vectors.schedule.overall_deadline_ms)
        expect(vectors.schedule.inner_delays_ms.map((_, i) => innerDelayMs(i))).toEqual(
            vectors.schedule.inner_delays_ms,
        )
        expect(vectors.schedule.sweep_delays_ms.map((_, i) => sweepDelayMs(i))).toEqual(
            vectors.schedule.sweep_delays_ms,
        )
    })

    for (const tc of vectors.classify_cases) {
        it(`classify: ${tc.name}`, () => {
            expect(classify(tc.status, tc.code)).toEqual(tc.expected)
        })
    }

    for (const nc of vectors.narrow_cases) {
        it(`narrowRelayed: ${nc.name}`, () => {
            const got = narrowRelayed(classify(nc.status, nc.code), nc.status, {
                relayed: nc.evidence.relayed,
                hopMarker: nc.evidence.hop_marker,
                relayMarksHops: nc.evidence.relay_marks_hops,
                callerAborted: nc.evidence.caller_aborted,
            })
            expect(got).toEqual(nc.expected)
        })
    }

    for (const vc of vectors.version_cases) {
        it(`version: ${vc.name}`, () => {
            expect(protoVersionCompatible(vc.version)).toBe(vc.compatible)
            expect(setsRelayHopHeader(vc.version)).toBe(vc.at_least_hop_marker)
        })
    }

    for (const fc of vectors.front_door_cases) {
        it(`isRelayFrontDoorStatus: ${fc.name}`, () => {
            expect(isRelayFrontDoorStatus(fc.status)).toBe(fc.front_door)
        })
    }

    for (const wc of vectors.wait_cases) {
        it(`wait: ${wc.name}`, () => {
            const got = wait(wc.scheduled_ms, wc.retry_after_ms, wc.remaining_ms)
            expect(got.ok).toBe(wc.expected_ok)
            expect(got.delayMs).toBe(wc.expected_ms)
        })
    }
})

describe('transient classifier: TS-side edges the vectors do not encode', () => {
    // The proxy passes "" for a body with no code; the client's
    // readRelayErrorCode returns null for a non-JSON body (an HTML 502 from an
    // intermediary). Both must classify identically or the two sides diverge on
    // exactly the case this package exists for.
    it('treats null and undefined code the same as empty', () => {
        const empty = classify(504, '')
        expect(classify(504, null)).toEqual(empty)
        expect(classify(504, undefined)).toEqual(empty)
    })

    // The Go side asserts the delay-table clamp (transient_test.go
    // TestDelayTablesClamp); the vectors only exercise in-range indices, so
    // without this the TS clamp is unenforced and could silently regress to
    // returning undefined for an out-of-range index. Mirrors the Go contract.
    it('clamps out-of-range delay indices instead of returning undefined', () => {
        expect(innerDelayMs(0)).toBe(0) // first attempt is immediate
        expect(sweepDelayMs(0)).toBe(0) // first sweep is immediate
        const lastInner = innerDelayMs(INNER_ATTEMPTS - 1)
        expect(innerDelayMs(INNER_ATTEMPTS + 50)).toBe(lastInner)
        expect(innerDelayMs(-3)).toBe(0)
        const lastSweep = sweepDelayMs(SWEEPS - 1)
        expect(sweepDelayMs(SWEEPS + 50)).toBe(lastSweep)
        // A finite number, never undefined/NaN — a NaN delay would make wait()
        // sleep NaN ms.
        expect(Number.isFinite(innerDelayMs(999))).toBe(true)
        expect(Number.isFinite(sweepDelayMs(999))).toBe(true)
    })
})
