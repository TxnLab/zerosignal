/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// How resolveConfig builds the default TEE verifier. Its own file because it
// mocks defaultVerifier for the whole module.

import { describe, expect, it, vi } from 'vitest'

import { type Signer, consoleLogger, resolveConfig, testnet } from '../src/index.js'

const built = vi.hoisted(() => ({ opts: [] as unknown[] }))
vi.mock('../src/tee/defaults.js', async (importOriginal) => {
    const real = await importOriginal<typeof import('../src/tee/defaults.js')>()
    return {
        ...real,
        defaultVerifier: (opts: Parameters<typeof real.defaultVerifier>[0]) => {
            built.opts.push(opts)
            return real.defaultVerifier(opts)
        },
    }
})

const signer: Signer = { address: 'PAYER', signBytes: async () => new Uint8Array(), signTransactions: async () => [] }

describe('the default TEE verifier', () => {
    // Its warnings (an unreachable Intel PCS, a refused node) are the host's
    // only view of why a node counts as unattested.
    it("logs to the Client's logger, on the wall clock as Go's does", () => {
        const logger = consoleLogger()
        resolveConfig({ signer, network: testnet(), logger, clock: () => 1 })
        expect(built.opts).toEqual([{ log: logger }])
    })
})
