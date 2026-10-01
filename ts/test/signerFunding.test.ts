/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'

import {
    MIN_SIGNER_SPENDABLE_MICROALGOS,
    signerSpendableBelowFloor,
    signerUnderfunded,
    type Operator,
} from '../src/selection/index.js'

// Mirrors proto/go/selection TestSignerUnderfunded_Boundary. The vectors cover
// an absent balance, 0 and the floor through selectTargets; this pins the
// predicate on `null`, which Go's omitempty never emits but a TS caller
// building an Operator from its own nullable column can.
function op(spendable: number | null | undefined): Operator {
    return {
        id: 1,
        node_id: 0,
        owner_addr: 'A',
        base_url: 'http://a',
        proto_version: '',
        reachable: true,
        tee_attested: false,
        signer_spendable_microalgos: spendable as number | undefined,
        models: ['m1'],
        model_capacities: {},
        builtin_tools: [],
    }
}

describe('signer funding floor (mirror of selection.SignerUnderfunded)', () => {
    it('is 5 ALGO', () => {
        expect(MIN_SIGNER_SPENDABLE_MICROALGOS).toBe(5_000_000)
    })

    it.each([
        ['never read (undefined)', undefined, false],
        ['never read (null)', null, false],
        ['zero is a real reading', 0, true],
        ['one short', MIN_SIGNER_SPENDABLE_MICROALGOS - 1, true],
        ['at floor', MIN_SIGNER_SPENDABLE_MICROALGOS, false],
        ['max safe', Number.MAX_SAFE_INTEGER, false],
    ] as const)('%s', (_name, spendable, want) => {
        expect(signerSpendableBelowFloor(spendable)).toBe(want)
        expect(signerUnderfunded(op(spendable))).toBe(want)
    })
})
