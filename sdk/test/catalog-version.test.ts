/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { describe, expect, it } from 'vitest'

import { restoredProtoVersion } from '../src/catalog/index.js'

describe('restoredProtoVersion', () => {
    const vectors = JSON.parse(readFileSync(new URL('../../testdata/persisted_proto_version_vectors.json', import.meta.url), 'utf8')) as {
        cases: Array<{ persisted: string; want: string }>
    }

    it('has vectors', () => expect(vectors.cases.length).toBeGreaterThan(5))
    for (const c of vectors.cases) {
        it(`floors ${JSON.stringify(c.persisted)} as Go does`, () => expect(restoredProtoVersion(c.persisted)).toBe(c.want))
    }
})
