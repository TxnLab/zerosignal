/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import { isPrivateAddress } from '../src/index.js'

const vectors = JSON.parse(readFileSync(new URL('../../testdata/private_target_vectors.json', import.meta.url), 'utf8')) as {
    cases: { address: string; refused: boolean }[]
}

describe('isPrivateAddress', () => {
    it('has vectors', () => expect(vectors.cases.length).toBeGreaterThan(100))

    it.each(vectors.cases.map((c) => [c.address, c.refused] as const))('%j: refused %s, as Go dials it', (address, refused) => {
        expect(isPrivateAddress(address)).toBe(refused)
    })
})
