/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { decodeDeploymentId } from '@txnlab/zs-proto/ticket'
import { describe, expect, it } from 'vitest'

import { checkDetailsDeployment } from '../src/catalog/index.js'

interface VectorCase {
    name: string
    /** The payer's own deployment id, base64; absent when it doesn't know it. */
    deployment?: string
    advertised?: string
    proto_version?: string
    admitted: boolean
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/details_deployment_vectors.json', import.meta.url), 'utf8'),
) as { cases: VectorCase[] }

describe('checkDetailsDeployment vectors', () => {
    it('covers both verdicts', () => {
        expect(new Set(vectors.cases.map((c) => c.admitted))).toEqual(new Set([true, false]))
    })

    it('matches Go for every case', () => {
        for (const c of vectors.cases) {
            const want = c.deployment ? decodeDeploymentId(c.deployment) : undefined
            const refusal = checkDetailsDeployment({ deployment: c.advertised, proto_version: c.proto_version }, want)
            expect(refusal === undefined, c.name).toBe(c.admitted)
        }
    })
})
