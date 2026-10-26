/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it } from 'vitest'

import { opensOnChain, signerFloorText } from '../src/rail.js'

describe('opensOnChain', () => {
    // Only a free Solana turn opens nothing; an Algorand free ticket opens at
    // zero under the contract's quota. Go's TestOpensOnChain.
    it.each([
        [undefined, 0, true],
        ['algorand', 0, true],
        ['algorand', 5, true],
        ['solana', 1, true],
        ['solana', 0, false],
    ] as const)('on %s at max_price %d is %s', (rail, maxPrice, want) => {
        expect(opensOnChain(rail, maxPrice)).toBe(want)
    })
})

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
