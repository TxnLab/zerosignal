/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A catalog row's reachability. answeredWithin is the half of the registry's
// advertisable gate that registry_cycle_vectors.json pins, so the row verdict
// is checked against those cases too: a picker that shows a node as ok when
// the registry would not route to it, or the reverse, is the drift this
// module exists to prevent.

import { readFileSync } from 'node:fs'
import { signerSpendableBelowFloor } from '@txnlab/zs-proto/selection'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { carryLapsesAt, reachabilityOf } from '../src/catalog/reachability.js'
import { defaults } from '../src/config.js'
import type { Operator } from '../src/operator.js'
import { advertisable } from '../src/registry/registry.js'
import { testOperator } from './fixtures.js'

const NOW = 1_800_000_000_000
const MAX = defaults.discovery.maxCarryAge
const OTHER_MAJOR = `${Number(PROTO_VERSION.split('.')[0]) + 1}.0`

/** A node this cycle reached, up. */
const up = (over: Partial<Operator> = {}) =>
    testOperator({ reachable: true, probed: true, reachableAsOf: NOW, lastRefreshAt: NOW, protoVersion: PROTO_VERSION, ...over })

/** A node this cycle skipped, its last answer agoMs before now. */
const carried = (agoMs: number, over: Partial<Operator> = {}) =>
    testOperator({ reachable: false, reachableAsOf: NOW - agoMs, protoVersion: PROTO_VERSION, ...over })

describe('reachabilityOf', () => {
    it('is ok when this cycle reached the node', () => {
        expect(reachabilityOf(up(), NOW, MAX)).toBe('ok')
    })

    it('is failing when this cycle reached it down, whatever it answered before', () => {
        expect(reachabilityOf(up({ reachable: false, reachableAsOf: NOW - 1000 }), NOW, MAX)).toBe('failing')
    })

    it('is incompatible for a node that answered on another wire major, reached or carried', () => {
        expect(reachabilityOf(up({ protoVersion: OTHER_MAJOR }), NOW, MAX)).toBe('incompatible')
        expect(reachabilityOf(carried(1000, { protoVersion: OTHER_MAJOR }), NOW, MAX)).toBe('incompatible')
    })

    it("is incompatible for an answer that carried no version ('')", () => {
        expect(reachabilityOf(up({ protoVersion: '' }), NOW, MAX)).toBe('incompatible')
    })

    it.each(['', OTHER_MAJOR])("is never incompatible for a node that never answered (protoVersion '%s')", (protoVersion) => {
        expect(reachabilityOf(testOperator({ reachable: false, protoVersion }), NOW, MAX)).toBe('probing')
        expect(reachabilityOf(testOperator({ reachable: false, protoVersion, lastRefreshAt: NOW }), NOW, MAX)).toBe('failing')
    })

    it('carries an untried node’s answer for the window, and fails it at the edge', () => {
        expect(reachabilityOf(carried(MAX - 1), NOW, MAX)).toBe('ok')
        expect(reachabilityOf(carried(MAX, { lastRefreshAt: NOW - MAX }), NOW, MAX)).toBe('failing')
    })

    it('is probing for an aged-out answer no refresh has tried yet, as on a restored catalog', () => {
        expect(reachabilityOf(carried(MAX), NOW, MAX)).toBe('probing')
    })

    it('reads the window it is given', () => {
        expect(reachabilityOf(carried(10_000, { lastRefreshAt: NOW }), NOW, 5_000)).toBe('failing')
    })

    // As the registry reads its discovery.maxCarryAge, so passing that setting
    // through gives the window the registry applies.
    it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])('reads a window of %s as the default', (window) => {
        expect(reachabilityOf(carried(MAX - 1), NOW, window)).toBe('ok')
        expect(reachabilityOf(carried(MAX, { lastRefreshAt: NOW }), NOW, window)).toBe('failing')
        expect(carryLapsesAt([carried(10)], NOW, window)).toBe(NOW - 10 + MAX)
    })
})

describe('carryLapsesAt', () => {
    it('is when the next carried answer leaves the window', () => {
        expect(carryLapsesAt([carried(10), carried(20)], NOW, MAX)).toBe(NOW - 20 + MAX)
    })

    it('skips an answer already out of the window, and one exactly at its edge', () => {
        expect(carryLapsesAt([carried(MAX + 5), carried(MAX), carried(10)], NOW, MAX)).toBe(NOW - 10 + MAX)
    })

    it('is Infinity with nothing carried: a probed node, or one never answered', () => {
        expect(carryLapsesAt([up(), testOperator({ reachable: false })], NOW, MAX)).toBe(Infinity)
    })
})

interface CycleOp {
    id: number
    node_id: number
    reachable: boolean
    probed: boolean
    reachable_as_of_ms: number
    last_refresh_at_ms: number
    staging: boolean
    signer_spendable_microalgos: number | null
    proto_version: string
}

const cycleVectors = JSON.parse(readFileSync(new URL('../../testdata/registry_cycle_vectors.json', import.meta.url), 'utf8')) as {
    advertisable: { name: string; now_ms: number; max_carry_age_ms: number; allow_staging: boolean; op: CycleOp; want: boolean }[]
}

describe('reachabilityOf against the registry_cycle advertisable vectors', () => {
    // The row verdict leaves out staging and the signer floor, so only the
    // cases neither term decides compare.
    const cases = cycleVectors.advertisable.filter(
        (c) => !(c.op.staging && !c.allow_staging) && !signerSpendableBelowFloor(c.op.signer_spendable_microalgos ?? undefined),
    )

    it.each(cases.map((c) => [c.name, c] as const))('%s', (_, c) => {
        const op = testOperator({ id: c.op.id, nodeId: c.op.node_id, reachable: c.op.reachable, staging: c.op.staging, protoVersion: c.op.proto_version })
        if (c.op.signer_spendable_microalgos !== null) op.signerSpendableMicroAlgos = c.op.signer_spendable_microalgos
        if (c.op.probed) op.probed = true
        if (c.op.reachable_as_of_ms !== 0) op.reachableAsOf = c.op.reachable_as_of_ms
        if (c.op.last_refresh_at_ms !== 0) op.lastRefreshAt = c.op.last_refresh_at_ms
        expect(advertisable(op, c.now_ms, c.allow_staging, c.max_carry_age_ms)).toBe(c.want)
        expect(reachabilityOf(op, c.now_ms, c.max_carry_age_ms) === 'ok').toBe(c.want)
    })
})
