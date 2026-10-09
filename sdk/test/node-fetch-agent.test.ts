/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// What nodeFetch builds its pools with. The guarded pool can't be reached
// from a test, since it refuses every loopback origin, so its options are
// read where it is built.

import { describe, expect, it, vi } from 'vitest'

const built = vi.hoisted(() => [] as unknown[])

vi.mock('undici', async (importOriginal) => {
    const m = await importOriginal<typeof import('undici')>()
    const Agent = function (opts?: ConstructorParameters<typeof m.Agent>[0]) {
        built.push(opts)
        return new m.Agent(opts)
    }
    return { ...m, Agent }
})

const { nodeFetch } = await import('../src/node/index.js')

describe('nodeFetch’s pool', () => {
    // A streamed answer's silences are Config.streamIdle's to bound, and the
    // wait for headers is bounded per request: Go's backstop on inference,
    // their own deadlines on the reserve and the probes.
    it('sets no timeout of its own, guarded or not', () => {
        for (const allowPrivateHosts of [false, true]) {
            built.length = 0
            nodeFetch({ allowPrivateHosts })
            expect(built).toHaveLength(1)
            expect(built[0]).toMatchObject({ bodyTimeout: 0, headersTimeout: 0 })
        }
    })
})
