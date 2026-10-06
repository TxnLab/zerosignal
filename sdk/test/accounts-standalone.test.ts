/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Imports the subpath and nothing else of the SDK: the package root wires
// @noble/ed25519's SHA-512 hook as a side effect, and a test sharing a module
// graph with it would pass with the subpath's own wiring gone. Vitest runs
// each file in its own graph.

import { generateAccount } from 'algosdk'
import { expect, it } from 'vitest'

import { algosdkSigner } from '../src/accounts/algosdk.js'

it('signs bytes when its subpath is the only one imported', async () => {
    const s = algosdkSigner(generateAccount())
    expect(await s.signBytes(s.address, new Uint8Array(32))).toHaveLength(64)
})
