/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The operator descriptor, checked against testdata/operator_vectors.json,
// which Go's applyDetailsFields and Operator.Selection generate.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { type OperatorDetailsModel, parseOperatorDetails } from '@txnlab/zs-proto/inject'

import {
    NoEphemeralError,
    type Operator,
    detailsFieldsOf,
    isTeeAttested,
    modelCapacityOf,
    refOf,
    sealRecipientOf,
    selectionOf,
} from '../src/index.js'
import { testOperator } from './fixtures.js'

interface Scenario {
    name: string
    node: {
        id: number
        node_id: number
        owner_addr: string
        base_url: string
        reachable: boolean
        staging: boolean
        signer_spendable_microalgos: number | null
        tee_verified: boolean | null
    }
    details: unknown
    fields: unknown
    selection: unknown
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/operator_vectors.json', import.meta.url), 'utf8')) as {
    scenarios: Scenario[]
}

// JSON with every object's keys sorted, so two values compare as Go
// serializes them: a key left out differs from one present as false, and a
// model id like "constructor" is plain data. toStrictEqual reads that last one
// as the object's constructor.
function canonical(v: unknown): string {
    return JSON.stringify(v, (_k, x: unknown) =>
        x !== null && typeof x === 'object' && !Array.isArray(x)
            ? Object.fromEntries(Object.entries(x).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
            : x,
    )
}

function operatorOf(sc: Scenario): Operator {
    const details = parseOperatorDetails(sc.details)
    if (details === null) throw new Error(`${sc.name}: details do not parse`)
    const n = sc.node
    return testOperator({
        id: n.id,
        nodeId: n.node_id,
        ownerAddr: n.owner_addr,
        baseUrl: n.base_url,
        reachable: n.reachable,
        staging: n.staging,
        signerSpendableMicroAlgos: n.signer_spendable_microalgos ?? undefined,
        tee:
            n.tee_verified === null
                ? undefined
                : { mode: 'dstack-tdx', attestedAt: 0, verifierId: 'builtin', verified: n.tee_verified, failureTag: '' },
        ...detailsFieldsOf(details),
    })
}

describe('operator vectors', () => {
    it('covers every scenario', () => expect(vectors.scenarios.length).toBeGreaterThan(0))
    it.each(vectors.scenarios.map((s) => [s.name, s] as const))('%s', (_name, sc) => {
        const details = parseOperatorDetails(sc.details)!
        expect(canonical(detailsFieldsOf(details))).toBe(canonical(sc.fields))
        expect(canonical(selectionOf(operatorOf(sc)))).toBe(canonical(sc.selection))
    })
})

describe('modelCapacityOf', () => {
    const model: OperatorDetailsModel = { id: 'm', input_rate_usd_per_1m: 1, output_rate_usd_per_1m: 2 }

    // parseOperatorDetails drops an unknown tier first, so the vectors cannot
    // reach this guard on their own.
    it('drops a retention tier this build does not know', () => {
        expect(modelCapacityOf({ ...model, retention: 'trust_me' }).retention).toBe('')
        expect(modelCapacityOf({ ...model, retention: 'no_upstream' }).retention).toBe('no_upstream')
    })
})

describe('sealRecipientOf', () => {
    const op = testOperator({ ephemeralRecipient: 'age1abc', ephemeralExpiry: 1_000 })

    it('returns the recipient until it expires', () => {
        expect(sealRecipientOf(op, 999_999)).toBe('age1abc')
        expect(() => sealRecipientOf(op, 1_000_000)).toThrow(NoEphemeralError)
    })

    it('has nothing to seal to without a verified recipient', () => {
        expect(() => sealRecipientOf({ ...op, ephemeralRecipient: undefined }, 0)).toThrow(NoEphemeralError)
        expect(() => sealRecipientOf({ ...op, ephemeralRecipient: '' }, 0)).toThrow(NoEphemeralError)
    })
})

describe('operator helpers', () => {
    it('refOf keys by operator and node', () => {
        expect(refOf(testOperator())).toEqual({ op: 7, node: 2 })
    })

    it('counts only a passing verdict as attested', () => {
        const tee = { mode: 'dstack-tdx', attestedAt: 0, verifierId: 'builtin', failureTag: '' }
        expect(isTeeAttested(testOperator())).toBe(false)
        expect(isTeeAttested(testOperator({ tee: { ...tee, verified: false } }))).toBe(false)
        expect(isTeeAttested(testOperator({ tee: { ...tee, verified: true } }))).toBe(true)
    })
})
