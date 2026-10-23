/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import { signerFloorText } from '../src/rail.js'

describe('signerFloorText', () => {
    // A Client always passes its resolved rail, never undefined, so Algorand's
    // spelling is pinned for 'algorand' as well as for an absent rail. Go's
    // TestNoFundedOperator_NamesTheRailsFloor.
    it.each([
        [undefined, '5 ALGO'],
        ['algorand', '5 ALGO'],
        ['solana', '10120 lamports'],
    ] as const)('names the floor on %s as %s', (rail, want) => {
        expect(signerFloorText(rail)).toBe(want)
    })
})
