/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// src/attest/trust-lists.ts is generated from the Go lists: Go fails when the
// committed file is stale (TestTrustListTwinVectors) and checks each list's
// shapes (TestReleaseLists_EntryShapes). These checks repeat that on the values
// a TypeScript payer actually imports, because a wrong value refuses every node
// on that release with nothing logged.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, expect, it } from 'vitest'

import {
    trustedComposeSkeletons,
    trustedDstackOSImages,
    trustedNodeImages,
} from '../src/attest/index.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const composeVectorsPath = path.resolve(here, '../../testdata/compose_vectors.json')

const HEX64 = /^[0-9a-f]{64}$/
const NODE_IMAGE = /^ghcr\.io\/txnlab\/zs-node@sha256:[0-9a-f]{64}$/

describe('trust lists', () => {
    const lists = {
        trustedComposeSkeletons: { values: trustedComposeSkeletons(), shape: HEX64 },
        trustedNodeImages: { values: trustedNodeImages(), shape: NODE_IMAGE },
        trustedDstackOSImages: { values: trustedDstackOSImages(), shape: HEX64 },
    }

    for (const [name, { values, shape }] of Object.entries(lists)) {
        it(`${name} is non-empty, well-formed and free of duplicates`, () => {
            expect(values.length).toBeGreaterThan(0)
            for (const v of values) expect(v).toMatch(shape)
            expect(new Set(values).size).toBe(values.length)
        })
    }

    it('returns a fresh array per call', () => {
        const first = trustedNodeImages()
        first.push('mutated')
        expect(trustedNodeImages()).not.toContain('mutated')
    })

    // compose_vectors.json carries the OS images as part of the shared compose
    // policy, which Go generates from the same function. Both reading the same
    // list is what keeps the browser's shared policy and its trust list in step.
    it('the OS images equal the compose vectors shared policy', () => {
        const V = JSON.parse(fs.readFileSync(composeVectorsPath, 'utf8')) as {
            shared_policy: { trusted_os_images: string[] }
        }
        expect(trustedDstackOSImages()).toEqual(V.shared_policy.trusted_os_images)
    })
})
