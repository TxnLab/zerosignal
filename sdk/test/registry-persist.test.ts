/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { describe, expect, it } from 'vitest'

import type { ModelCapacity, Operator } from '../src/operator.js'
import { memoryStorage } from '../src/ports.js'
import {
    CATALOG_FORMAT_VERSION,
    CATALOG_STORAGE_KEY,
    decodeCatalog,
    loadCatalog,
    marshalCatalog,
    saveCatalog,
} from '../src/registry/persist.js'

// The fixture names every field in snake_case, independent of the Go field
// names the catalog itself uses; these turn them into the SDK's camelCase by
// rule, so a field persist.ts maps by hand to the wrong name cannot pass.
type Vec = Record<string, unknown>

interface VecOp extends Vec {
    ticket_signing_key: string
    reachable_as_of_ms: number
    builtin_tools: string[]
    node_version: string
    model_capacities: Record<string, Vec>
    metrics: Vec
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/persisted_catalog_vectors.json', import.meta.url), 'utf8')) as {
    format_version: number
    catalogs: { name: string; operators: VecOp[]; bytes: string; loaded: VecOp[] }[]
    loads: { name: string; bytes: string; loaded: VecOp[] }[]
    rejects: { name: string; bytes: string }[]
}

const camel = (k: string) => k.replace(/_([a-z0-9])/g, (_, c: string) => c.toUpperCase())

// Go's null pointer or slice is the SDK's absent field.
function camelObject(v: Vec): Record<string, unknown> {
    const out: Record<string, unknown> = {}
    for (const [k, x] of Object.entries(v)) if (x !== null) out[camel(k)] = x
    return out
}

function operatorOf(v: VecOp): Operator {
    const { ticket_signing_key, reachable_as_of_ms, builtin_tools, node_version, model_capacities, metrics, ...rest } = v
    // The SDK keeps no node version; persist.ts says so.
    void node_version
    const caps = Object.create(null) as Record<string, ModelCapacity>
    for (const [m, c] of Object.entries(model_capacities)) caps[m] = camelObject(c) as unknown as ModelCapacity
    const op = {
        ...camelObject(rest),
        ticketSigningKey: hexToBytes(ticket_signing_key),
        builtinTools: builtin_tools.map((type) => ({ type })),
        modelCapacities: caps,
        metrics: camelObject(metrics),
        reachable: false,
        ephemeralExpiry: 0,
        ephemeralIssuedAt: 0,
    } as unknown as Operator
    if (reachable_as_of_ms !== 0) op.reachableAsOf = reachable_as_of_ms
    return op
}

// Undefined members compare equal to absent ones under toEqual, so an
// optional field left undefined reads like Go's nil.
function comparable(op: Operator): unknown {
    return { ...op, ticketSigningKey: bytesToHex(op.ticketSigningKey), modelCapacities: { ...op.modelCapacities } }
}

describe('persisted_catalog vectors', () => {
    it('reads the format version Go writes', () => {
        expect(vectors.format_version).toBe(CATALOG_FORMAT_VERSION)
    })

    describe.each(vectors.catalogs.map((c) => [c.name, c] as const))('%s', (_, c) => {
        it('writes the bytes Go writes', () => {
            expect(marshalCatalog(c.operators.map(operatorOf))).toBe(c.bytes)
        })
        it('reads them back to what Go reads', () => {
            expect(decodeCatalog(c.bytes).map(comparable)).toEqual(c.loaded.map(operatorOf).map(comparable))
        })
        it('writes what it read as Go rewrites it', () => {
            expect(marshalCatalog(decodeCatalog(c.bytes))).toBe(marshalCatalog(c.loaded.map(operatorOf)))
        })
    })

    it.each(vectors.loads.map((c) => [c.name, c] as const))('reads %s', (_, c) => {
        expect(decodeCatalog(c.bytes).map(comparable)).toEqual(c.loaded.map(operatorOf).map(comparable))
    })

    it.each(vectors.rejects.map((c) => [c.name, c] as const))('refuses %s', (_, c) => {
        expect(() => decodeCatalog(c.bytes)).toThrow()
    })

    it('restores no node as probed, reachable or able to seal', () => {
        const [op] = decodeCatalog(vectors.catalogs[0]!.bytes)
        expect(op).toMatchObject({ reachable: false, ephemeralExpiry: 0, ephemeralIssuedAt: 0 })
        expect(op!.probed).toBeUndefined()
        expect(op!.ephemeralRecipient).toBeUndefined()
        expect(op!.tee).toBeUndefined()
        expect(op!.signerSpendableMicroAlgos).toBeUndefined()
        expect(op!.protoVersion).toBe('9.0')
    })
})

describe('catalog storage', () => {
    it('reads nothing from an empty storage, and back what it saved', async () => {
        const storage = memoryStorage()
        expect(await loadCatalog(storage)).toBeUndefined()
        const ops = decodeCatalog(vectors.catalogs[0]!.bytes)
        await saveCatalog(storage, ops)
        expect(await storage.get(CATALOG_STORAGE_KEY)).toBe(marshalCatalog(ops))
        expect((await loadCatalog(storage))!.map(comparable)).toEqual(ops.map(comparable))
    })

    it('keeps each key to itself', async () => {
        const storage = memoryStorage()
        await saveCatalog(storage, [], 'testnet')
        expect(await loadCatalog(storage)).toBeUndefined()
        expect(await loadCatalog(storage, 'testnet')).toEqual([])
    })

    it('throws on a rate JSON cannot hold, as json.Marshal fails on one', () => {
        const [op] = decodeCatalog(vectors.catalogs[0]!.bytes)
        op!.modelCapacities['qwen3-32b']!.inputUsdPer1m = Number.NaN
        expect(() => marshalCatalog([op!])).toThrow(/unsupported value/)
    })

    it('writes a host-built operator that leaves optional fields out', () => {
        const [op] = decodeCatalog(vectors.catalogs[1]!.bytes)
        const bare = { ...op!, metrics: { latencyEwmaMs: 0, tokensPerSecEwma: 0 } }
        delete bare.nfdAppId
        expect(marshalCatalog([bare])).toBe(vectors.catalogs[1]!.bytes)
    })
})
