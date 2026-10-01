/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Cross-impl parity test for the selection policy. Loads
// proto/testdata/selection_vectors.json (produced by
// proto/go/selection/vectors_test.go) and asserts the TypeScript port of
// selectTargets / selectRelay produces identical ordered targets, relay picks,
// and diagnostics. If this fails, the TS selection logic has drifted from the
// Go reference; sync both sides before regenerating.

import { describe, it, expect } from 'vitest'
import * as fs from 'node:fs'
import * as path from 'node:path'
import { fileURLToPath } from 'node:url'

import {
    selectTargets,
    selectRelay,
    deriveMaxOutput,
    type Operator,
    type Constraints,
    type Diagnostics,
} from '../src/selection/index.js'

interface TargetCase {
    name: string
    operators: Operator[]
    constraints: Constraints
    preferred?: Operator
    expected: { operator_ids: number[]; node_ids: number[]; diagnostics: Diagnostics }
}

interface RelayCase {
    name: string
    operators: Operator[]
    target_id: number
    seed: number
    expected: { relay_id?: number; no_relay: boolean }
}

interface DeriveCase {
    name: string
    context_window: number
    declared_max: number
    base_ceiling: number
    expected: number
}

interface SelectionVectorsFile {
    version: number
    comment: string
    target_cases: TargetCase[]
    relay_cases: RelayCase[]
    derive_cases: DeriveCase[]
}

const here = path.dirname(fileURLToPath(import.meta.url))
const vectorsPath = path.resolve(here, '..', '..', 'testdata', 'selection_vectors.json')
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8')) as SelectionVectorsFile

describe('cross-impl selection vectors (proto/testdata/selection_vectors.json)', () => {
    it('vectors file is current schema', () => {
        expect(vectors.version).toBe(4)
        expect(vectors.target_cases.length).toBeGreaterThan(0)
        expect(vectors.relay_cases.length).toBeGreaterThan(0)
        expect(vectors.derive_cases.length).toBeGreaterThan(0)
    })

    for (const tc of vectors.target_cases) {
        it(`selectTargets: ${tc.name}`, () => {
            const got = selectTargets(tc.operators, tc.constraints, tc.preferred ?? null)
            expect(got.operators.map((o) => o.id)).toEqual(tc.expected.operator_ids)
            expect(got.operators.map((o) => o.node_id)).toEqual(tc.expected.node_ids)
            // Normalize: Go omits sizing_misses when empty; TS leaves it undefined too.
            expect(got.diagnostics).toEqual(tc.expected.diagnostics)
        })
    }

    for (const rc of vectors.relay_cases) {
        it(`selectRelay: ${rc.name}`, () => {
            const target = rc.operators.find((o) => o.id === rc.target_id)
            expect(target).toBeDefined()
            const got = selectRelay(rc.operators, target!, rc.seed)
            if (rc.expected.no_relay) {
                expect(got).toBeNull()
            } else {
                expect(got).not.toBeNull()
                expect(got!.id).toBe(rc.expected.relay_id)
            }
        })
    }

    for (const dc of vectors.derive_cases) {
        it(`deriveMaxOutput: ${dc.name}`, () => {
            expect(deriveMaxOutput(dc.context_window, dc.declared_max, dc.base_ceiling)).toBe(dc.expected)
        })
    }
})
