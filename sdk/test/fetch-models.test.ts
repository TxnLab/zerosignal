/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// zs.fetch's catalog routes: the entry builder replays
// testdata/openai_model_vectors.json from proto/go/zs/handler
// TestOpenAIModelVectors, and the routes port handleListModels and
// handleGetModel from Go's handlers_test.go.

import { readFileSync } from 'node:fs'
import { type OperatorDetailsModel, huggingFaceRepo, usdPerToken } from '@txnlab/zs-proto/inject'
import { describe, expect, it } from 'vitest'

import { MODELS_OWNED_BY, grossRate, modelEntryFor } from '../src/fetch/models.js'
import { type FetchTarget, openAIFetch } from '../src/fetch/serve.js'
import type { RegistryProvider } from '../src/parts.js'
import type { Stream } from '../src/turn.js'

const vectors = JSON.parse(readFileSync(new URL('../../testdata/openai_model_vectors.json', import.meta.url), 'utf8')) as {
    owned_by: string
    cases: { name: string; details: OperatorDetailsModel; fee_bps: number | null; want: unknown }[]
}

describe('openai_model vectors', () => {
    it('own every entry as the SDK does', () => {
        expect(vectors.owned_by).toBe(MODELS_OWNED_BY)
    })

    it.each(vectors.cases.map((c) => [c.name, c] as const))('%s', (_, c) => {
        const fee = c.fee_bps
        const entry = modelEntryFor(structuredClone(c.details), fee === null ? 1 : 1 + fee / 10000, fee !== null)
        expect(entry).toEqual(c.want)
    })

    it('leave the details they are given as they were', () => {
        const d: OperatorDetailsModel = { id: 'm', input_rate_usd_per_1m: 1, output_rate_usd_per_1m: 2, cache_read_rate_usd_per_1m: 0.5 }
        modelEntryFor(d, 1.025, true)
        expect(d).toEqual({ id: 'm', input_rate_usd_per_1m: 1, output_rate_usd_per_1m: 2, cache_read_rate_usd_per_1m: 0.5 })
    })
})

// What Go's types rule out and a JS number allows.
describe('per-language edges', () => {
    it.each([Number.NaN, Number.POSITIVE_INFINITY, -1, 0])('prices %s per token as 0', (v) => {
        expect(usdPerToken(v)).toBe('0')
    })

    it('grosses an overflowing rate to 0, which publishes no price', () => {
        expect(grossRate(Number.MAX_VALUE, 2)).toBe(0)
        expect(modelEntryFor({ id: 'm', input_rate_usd_per_1m: Number.MAX_VALUE, output_rate_usd_per_1m: 1 }, 2, true).pricing).toBeUndefined()
    })

    it('rounds a negative half away from zero, as math.Round does', () => {
        expect(grossRate(-0.0000025, 1.0)).toBe(-0.000003)
        expect(grossRate(0.0000025, 1.0)).toBe(0.000003)
    })

    it('trims what Go’s TrimSpace trims, and refuses a segment it would not', () => {
        expect(huggingFaceRepo('\u0085hf:org/model@main\u0085')).toBe('org/model')
        expect(huggingFaceRepo('hf:org/mo\ndel')).toBe('')
    })
})

const BASE = 'https://zerosignal.invalid'

function target(registry: Partial<RegistryProvider> | undefined, fee: number | null = 0): FetchTarget {
    const t: FetchTarget = {
        stream(): Stream {
            throw new Error('a catalog route must not start a turn')
        },
        feeRate: () => fee,
    }
    if (registry !== undefined) Object.assign(t, { registry })
    return t
}

const fleet = (): Partial<RegistryProvider> => ({
    allModels: async () => ['b', 'org/a', 'bare'],
    allModelDetails: async () => [
        { id: 'org/a', input_rate_usd_per_1m: 1, output_rate_usd_per_1m: 2, context_window: 8192 },
        { id: 'b', input_rate_usd_per_1m: 3, output_rate_usd_per_1m: 4 },
    ],
})

async function errorCode(res: Response): Promise<string> {
    return ((await res.json()) as { error: { code: string } }).error.code
}

describe('catalog routes', () => {
    it('lists every model in the registry’s order, joined to its details, a model without any listed bare', async () => {
        const res = await openAIFetch(target(fleet()))(`${BASE}/v1/models`)
        expect(res.status).toBe(200)
        expect(res.headers.get('Content-Type')).toBe('application/json')
        const body = (await res.json()) as { object: string; data: { id: string; context_length?: number; pricing?: unknown }[] }
        expect(body.object).toBe('list')
        expect(body.data.map((m) => m.id)).toEqual(['b', 'org/a', 'bare'])
        expect(body.data[1]!.context_length).toBe(8192)
        expect(body.data[2]).toEqual({ id: 'bare', object: 'model', created: 0, owned_by: MODELS_OWNED_BY })
    })

    it('answers /models as an alias, and an id with a slash in it', async () => {
        const f = openAIFetch(target(fleet()))
        expect(((await (await f(`${BASE}/models`)).json()) as { data: unknown[] }).data).toHaveLength(3)
        const res = await f(`${BASE}/models/org/a`)
        expect(res.status).toBe(200)
        expect(((await res.json()) as { id: string }).id).toBe('org/a')
        expect(((await (await f(`${BASE}/v1/models/b`)).json()) as { id: string }).id).toBe('b')
    })

    it('answers an unknown model 404 and an empty id 400', async () => {
        const f = openAIFetch(target(fleet()))
        const missing = await f(`${BASE}/v1/models/nope`)
        expect(missing.status).toBe(404)
        expect(await errorCode(missing)).toBe('model_not_found')
        const empty = await f(`${BASE}/v1/models/`)
        expect(empty.status).toBe(400)
        expect(await errorCode(empty)).toBe('missing_model_id')
    })

    it('answers HEAD with the headers alone, and any other method 405', async () => {
        const f = openAIFetch(target(fleet()))
        const head = await f(`${BASE}/v1/models`, { method: 'HEAD' })
        expect(head.status).toBe(200)
        expect(head.body).toBeNull()
        const post = await f(`${BASE}/v1/models`, { method: 'POST', body: '{}' })
        expect(post.status).toBe(405)
        expect(post.headers.get('Allow')).toBe('GET, HEAD')
    })

    it('publishes no price while the fee is unread, and the grossed price once it is', async () => {
        const cold = await (await openAIFetch(target(fleet(), null))(`${BASE}/v1/models/b`)).json()
        expect(cold).not.toHaveProperty('pricing')
        const warm = (await (await openAIFetch(target(fleet(), 250))(`${BASE}/v1/models/b`)).json()) as { pricing: unknown }
        expect(warm.pricing).toEqual({ prompt: '0.000003075', completion: '0.0000041' })
    })

    it('lists each model by id alone when the registry has no details', async () => {
        const res = await openAIFetch(target({ allModels: async () => ['m'] }))(`${BASE}/v1/models`)
        expect(await res.json()).toEqual({ object: 'list', data: [{ id: 'm', object: 'model', created: 0, owned_by: MODELS_OWNED_BY }] })
    })

    it('answers 501 when the registry has no catalog', async () => {
        for (const reg of [undefined, {}]) {
            const res = await openAIFetch(target(reg))(`${BASE}/v1/models`)
            expect(res.status).toBe(501)
            expect(await errorCode(res)).toBe('catalog_unavailable')
        }
    })

    it('answers 503 when the registry cannot read, and rethrows the caller’s abort', async () => {
        const failing = target({ allModels: () => Promise.reject(new Error('no fleet')) })
        const res = await openAIFetch(failing)(`${BASE}/v1/models`)
        expect(res.status).toBe(503)
        expect(await errorCode(res)).toBe('catalog_unavailable')

        const ac = new AbortController()
        const aborting = target({
            allModels: () => {
                ac.abort(new Error('caller left'))
                return Promise.reject(new Error('aborted read'))
            },
        })
        await expect(openAIFetch(aborting)(`${BASE}/v1/models`, { signal: ac.signal })).rejects.toThrow('caller left')
    })
})
