/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The catalog GET routes of zs.fetch, mirroring proto/go/zs handler's
// handleListModels, handleGetModel and modelEntryFor: GET /v1/models and
// /v1/models/{id}, with /models and /models/{id} as aliases, answered from
// the registry. testdata/openai_model_vectors.json pins the entry builder;
// the routes are tested per language.
//
// Differences from Go:
//   - A registry without allModels has no catalog to list, so the routes
//     answer 501. Go's RegistryProvider always has one.
//   - A registry read that fails answers 503. Go's aggregates cannot fail;
//     the TS registry's reads reject on a boot that never produced a fleet.

import { type OpenAIModel, type OpenAIModelList, type OperatorDetailsModel, openAIModelFromDetails } from '@txnlab/zs-proto/inject'
import { BPS_DENOMINATOR } from '@txnlab/zs-proto/pricing'

import { goJSON } from '../gojson.js'
import type { RegistryProvider } from '../parts.js'
import { openAIErrorResponse } from './errors.js'

/** MODELS_OWNED_BY is every catalog entry's owned_by: the registry speaks for no one operator. */
export const MODELS_OWNED_BY = 'zerosignal'

/** What the catalog routes read off the Client. */
export interface CatalogSource {
    readonly registry?: RegistryProvider
    /** The payer's protocol fee in basis points; null until it has been read. */
    feeRate?(): number | null
}

/** A catalog route a path names, or undefined for none. id is the decoded rest of the path, possibly empty. */
export function catalogRoute(path: string): { id: string | undefined } | undefined {
    if (path === '/v1/models' || path === '/models') return { id: undefined }
    for (const prefix of ['/v1/models/', '/models/']) if (path.startsWith(prefix)) return { id: path.slice(prefix.length) }
    return undefined
}

/**
 * serveCatalog answers a catalog route: the list, or the entry for id. Both
 * read the same aggregate through the same builder, so a client learns the
 * same about a model from either. A model in the list with no capability
 * entry is listed by id alone.
 */
export async function serveCatalog(source: CatalogSource, id: string | undefined, head: boolean, signal: AbortSignal): Promise<Response> {
    const registry = source.registry
    if (registry?.allModels === undefined) {
        return openAIErrorResponse(new Headers(), 501, 'invalid_request_error', 'catalog_unavailable', 'this endpoint has no operator catalog to list')
    }
    if (id === '') return openAIErrorResponse(new Headers(), 400, 'invalid_request_error', 'missing_model_id', 'model id is required')
    let models: string[]
    let byId: Map<string, OperatorDetailsModel>
    try {
        models = await registry.allModels(signal)
        byId = new Map((await (registry.allModelDetails?.(signal) ?? Promise.resolve([]))).map((d) => [d.id, d]))
    } catch (err) {
        signal.throwIfAborted()
        return openAIErrorResponse(
            new Headers(),
            503,
            'service_unavailable',
            'catalog_unavailable',
            `operator catalog unavailable: ${err instanceof Error ? err.message : String(err)}`,
        )
    }
    const fee = source.feeRate?.() ?? null
    const grossFactor = fee === null ? 1 : 1 + fee / BPS_DENOMINATOR
    const entry = (m: string) => modelEntryFor(byId.get(m) ?? { id: m, input_rate_usd_per_1m: 0, output_rate_usd_per_1m: 0 }, grossFactor, fee !== null)
    let body: OpenAIModel | OpenAIModelList
    if (id === undefined) {
        body = { object: 'list', data: models.map(entry) }
    } else {
        if (!models.includes(id)) {
            return openAIErrorResponse(
                new Headers(),
                404,
                'invalid_request_error',
                'model_not_found',
                `The model '${id}' does not exist or you do not have access to it.`,
            )
        }
        body = entry(id)
    }
    return new Response(head ? null : `${goJSON(body)}\n`, { status: 200, headers: { 'Content-Type': 'application/json' } })
}

/**
 * modelEntryFor is one aggregated model's /v1/models entry, priced at what
 * the payer pays: rates grossed up by the protocol fee, since OpenRouter's
 * pricing object has no fee field. It publishes no price at all while the
 * fee is unread, or when either rate is 0, which in the aggregate means no
 * operator declared one: a number on this surface is a claim, an absent
 * object is not.
 */
export function modelEntryFor(d: OperatorDetailsModel, grossFactor: number, feeKnown: boolean): OpenAIModel {
    if (grossFactor !== 1) {
        d = {
            ...d,
            input_rate_usd_per_1m: grossRate(d.input_rate_usd_per_1m, grossFactor),
            output_rate_usd_per_1m: grossRate(d.output_rate_usd_per_1m, grossFactor),
        }
        if (d.cache_read_rate_usd_per_1m !== undefined) d.cache_read_rate_usd_per_1m = grossRate(d.cache_read_rate_usd_per_1m, grossFactor)
    }
    const m = openAIModelFromDetails(d, MODELS_OWNED_BY, 0)
    if (!feeKnown || d.input_rate_usd_per_1m === 0 || d.output_rate_usd_per_1m === 0) delete m.pricing
    return m
}

/**
 * grossRate is a rate times the fee factor, rounded to the microdollar as
 * Go's math.Round rounds, half away from zero. A non-finite result is 0,
 * which publishes no price: an absurd advertised rate would otherwise
 * overflow to Infinity and render as free.
 */
export function grossRate(usdPer1M: number, grossFactor: number): number {
    const scaled = usdPer1M * grossFactor * 1e6
    const out = (Math.sign(scaled) * Math.round(Math.abs(scaled))) / 1e6
    return Number.isFinite(out) ? out : 0
}
