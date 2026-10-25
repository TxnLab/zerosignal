/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The discovery aggregates, mirroring proto/go/zs/registry.go
// (aggregateModels, aggregateBuiltinTools, aggregateModelDetails and their
// fold helpers) and pinned by testdata/catalog_aggregate_vectors.json. Each
// folds the catalogs of the nodes keep admits; the registry passes its
// advertisable gate, so the catalog lists only what dispatch can route to.
//
// Differences from Go:
//   - aggregateModelDetails returns its models in the order first seen, where
//     Go's come in map order. An empty fleet is [] where Go returns nil.

import type { ModelCoordinates, ModelReasoning, OperatorDetailsModel } from '@txnlab/zs-proto/inject'

import { type BuiltinToolDef, type ModelCapacity, type Operator, servesImageEdit, servesImageGen } from '../operator.js'
import { capacityOf } from '../sizing.js'

/** The models of every node keep admits, first seen first. */
export function aggregateModels(ops: readonly Operator[], keep: (op: Operator) => boolean): string[] {
    const seen = new Set<string>()
    for (const op of ops) {
        if (!keep(op)) continue
        for (const m of op.models) seen.add(m)
    }
    return [...seen]
}

/**
 * The built-in tools of every node keep admits, the first definition of each
 * type kept: a client needs only the type, and the node that serves a request
 * uses its own definition.
 */
export function aggregateBuiltinTools(ops: readonly Operator[], keep: (op: Operator) => boolean): BuiltinToolDef[] {
    const seen = new Map<string, BuiltinToolDef>()
    for (const op of ops) {
        if (!keep(op)) continue
        for (const t of op.builtinTools) if (!seen.has(t.type)) seen.set(t.type, { ...t })
    }
    return [...seen.values()]
}

// One model's union while the nodes are folded; written out by detailsOf.
interface Fold {
    id: string
    contextWindow: number
    maxOutputTokens: number
    inputModalities: string[]
    outputModalities: string[]
    inputRate: number
    outputRate: number
    cacheRead: number | undefined
    longContextThreshold: number
    longContextInput: number | undefined
    longContextOutput: number | undefined
    longContextCacheRead: number | undefined
    reasoning: ModelReasoning | undefined
    toolUse: boolean | undefined
    tags: string[]
    imageToolRate: number
    imageEditToolRate: number
    imageToolBase: number
    imageEditToolBase: number
    imageRate: number
    imageEditRate: number
    imageDefault: number
    imageEditDefault: number
    imageCap: number
    imageEditCap: number
    servesImageGen: boolean
    servesImageEdit: boolean
    coordinates: ModelCoordinates[]
    digests: string[]
    sources: string[]
    canonicals: string[]
}

// A model a node lists with no capability entry reads as Go's zero value.
const NO_CAPACITY: ModelCapacity = {
    contextWindow: 0,
    maxOutputTokens: 0,
    inputUsdPer1m: 0,
    outputUsdPer1m: 0,
    longContextThresholdTokens: 0,
    weightsDigest: '',
    weightsUnverifiable: false,
    source: '',
    canonicalId: '',
    retention: '',
    imageToolRateMicroUsdc: 0,
    imageEditToolRateMicroUsdc: 0,
    imageToolBaseMicroUsdc: 0,
    imageEditToolBaseMicroUsdc: 0,
    imageRateMicroUsdc: 0,
    imageEditRateMicroUsdc: 0,
    imageDefaultMicroUsdc: 0,
    imageEditDefaultMicroUsdc: 0,
    imageCapMicroUsdc: 0,
    imageEditCapMicroUsdc: 0,
    advertisesImageGen: false,
    advertisesImageEdit: false,
    vendorToolCatchAllMicroUsdc: 0,
    vendorToolCallCap: 0,
    vendorToolTokensPerCall: 0,
}

/**
 * The capability union of every model the nodes keep admits serve, the
 * figures behind /v1/models. Modalities are unioned, tags unioned then folded
 * into a sorted set (foldTags), sizing takes
 * the lowest declared (non-zero) value and each rate the lowest declared one
 * ("from $X"); the rate a request pays is the one its node signs into the
 * ticket. Coordinates take each field's majority, and the weights digest,
 * source and canonical id their consensus.
 */
export function aggregateModelDetails(ops: readonly Operator[], keep: (op: Operator) => boolean): OperatorDetailsModel[] {
    const folds = new Map<string, Fold>()
    for (const op of ops) {
        if (!keep(op)) continue
        for (const m of op.models) {
            const c = capacityOf(op, m) ?? NO_CAPACITY
            const f = folds.get(m)
            if (f === undefined) {
                folds.set(m, firstFold(m, c))
                continue
            }
            if (c.coordinates !== undefined) f.coordinates.push(c.coordinates)
            if (c.weightsDigest !== '') f.digests.push(c.weightsDigest)
            if (c.source !== '') f.sources.push(c.source)
            if (c.canonicalId !== '') f.canonicals.push(c.canonicalId)
            f.inputModalities = unionStrings(f.inputModalities, c.inputModalities)
            f.outputModalities = unionStrings(f.outputModalities, c.outputModalities)
            f.tags = unionStrings(f.tags, c.tags)
            f.toolUse = aggregateBool(f.toolUse, c.toolUse)
            f.reasoning = aggregateReasoning(f.reasoning, c.reasoning)
            f.contextWindow = minNonZero(f.contextWindow, c.contextWindow)
            f.maxOutputTokens = minNonZero(f.maxOutputTokens, c.maxOutputTokens)
            f.inputRate = minNonZero(f.inputRate, c.inputUsdPer1m)
            f.outputRate = minNonZero(f.outputRate, c.outputUsdPer1m)
            f.cacheRead = minRate(f.cacheRead, c.cacheReadUsdPer1m)
            f.longContextThreshold = minNonZero(f.longContextThreshold, c.longContextThresholdTokens)
            f.longContextInput = minRate(f.longContextInput, c.longContextInputUsdPer1m)
            f.longContextOutput = minRate(f.longContextOutput, c.longContextOutputUsdPer1m)
            f.longContextCacheRead = minRate(f.longContextCacheRead, c.longContextCacheReadUsdPer1m)
            f.imageToolRate = minNonZero(f.imageToolRate, c.imageToolRateMicroUsdc)
            f.imageEditToolRate = minNonZero(f.imageEditToolRate, c.imageEditToolRateMicroUsdc)
            f.imageRate = minNonZero(f.imageRate, c.imageRateMicroUsdc)
            f.imageEditRate = minNonZero(f.imageEditRate, c.imageEditRateMicroUsdc)
            f.imageToolBase = minNonZero(f.imageToolBase, c.imageToolBaseMicroUsdc)
            f.imageEditToolBase = minNonZero(f.imageEditToolBase, c.imageEditToolBaseMicroUsdc)
            f.imageDefault = minNonZero(f.imageDefault, c.imageDefaultMicroUsdc)
            f.imageEditDefault = minNonZero(f.imageEditDefault, c.imageEditDefaultMicroUsdc)
            f.imageCap = minNonZero(f.imageCap, c.imageCapMicroUsdc)
            f.imageEditCap = minNonZero(f.imageEditCap, c.imageEditCapMicroUsdc)
            // Price-independent: a free route advertises a 0 rate.
            if (servesImageGen(c)) f.servesImageGen = true
            if (servesImageEdit(c)) f.servesImageEdit = true
        }
    }
    return [...folds.values()].map(detailsOf)
}

function firstFold(id: string, c: ModelCapacity): Fold {
    return {
        id,
        contextWindow: c.contextWindow,
        maxOutputTokens: c.maxOutputTokens,
        inputModalities: [...(c.inputModalities ?? [])],
        outputModalities: [...(c.outputModalities ?? [])],
        inputRate: c.inputUsdPer1m,
        outputRate: c.outputUsdPer1m,
        cacheRead: c.cacheReadUsdPer1m,
        longContextThreshold: c.longContextThresholdTokens,
        longContextInput: c.longContextInputUsdPer1m,
        longContextOutput: c.longContextOutputUsdPer1m,
        longContextCacheRead: c.longContextCacheReadUsdPer1m,
        reasoning: aggregateReasoning(undefined, c.reasoning),
        toolUse: c.toolUse,
        tags: [...(c.tags ?? [])],
        imageToolRate: c.imageToolRateMicroUsdc,
        imageEditToolRate: c.imageEditToolRateMicroUsdc,
        imageToolBase: c.imageToolBaseMicroUsdc,
        imageEditToolBase: c.imageEditToolBaseMicroUsdc,
        imageRate: c.imageRateMicroUsdc,
        imageEditRate: c.imageEditRateMicroUsdc,
        imageDefault: c.imageDefaultMicroUsdc,
        imageEditDefault: c.imageEditDefaultMicroUsdc,
        imageCap: c.imageCapMicroUsdc,
        imageEditCap: c.imageEditCapMicroUsdc,
        servesImageGen: servesImageGen(c),
        servesImageEdit: servesImageEdit(c),
        coordinates: c.coordinates === undefined ? [] : [c.coordinates],
        digests: c.weightsDigest === '' ? [] : [c.weightsDigest],
        sources: c.source === '' ? [] : [c.source],
        canonicals: c.canonicalId === '' ? [] : [c.canonicalId],
    }
}

// detailsOf writes a fold out as /v1/zs/details carries a model, leaving out
// each field Go's encoding omits when empty.
function detailsOf(f: Fold): OperatorDetailsModel {
    const d: OperatorDetailsModel = { id: f.id, input_rate_usd_per_1m: f.inputRate, output_rate_usd_per_1m: f.outputRate }
    if (f.cacheRead !== undefined) d.cache_read_rate_usd_per_1m = f.cacheRead
    if (f.longContextThreshold > 0) d.long_context_threshold_tokens = f.longContextThreshold
    if (f.longContextInput !== undefined) d.long_context_input_rate_usd_per_1m = f.longContextInput
    if (f.longContextOutput !== undefined) d.long_context_output_rate_usd_per_1m = f.longContextOutput
    if (f.longContextCacheRead !== undefined) d.long_context_cache_read_rate_usd_per_1m = f.longContextCacheRead
    if (f.contextWindow > 0) d.context_window = f.contextWindow
    if (f.maxOutputTokens > 0) d.max_output_tokens = f.maxOutputTokens
    if (f.inputModalities.length > 0) d.input_modalities = f.inputModalities
    if (f.outputModalities.length > 0) d.output_modalities = f.outputModalities
    if (f.reasoning !== undefined) d.reasoning = f.reasoning
    if (f.toolUse !== undefined) d.tool_use = f.toolUse
    const tags = foldTags(f.tags)
    if (tags.length > 0) d.tags = tags
    const coordinates = aggregateCoordinates(f.coordinates)
    if (coordinates !== undefined) d.coordinates = coordinates
    const source = aggregateSource(f.sources)
    if (source !== '') d.source = source
    // canonical_id only rides without a source, the node's own per-model rule.
    else {
        const canonical = aggregateIdentity(f.canonicals)
        if (canonical !== '') d.canonical_id = canonical
    }
    const { consensus, mismatch } = aggregateDigest(f.digests)
    if (consensus !== '') d.weights_digest = consensus
    if (mismatch) d.weights_mismatch = true
    if (f.imageToolRate > 0) d.image_tool_rate_micro_usdc = f.imageToolRate
    if (f.imageEditToolRate > 0) d.image_edit_tool_rate_micro_usdc = f.imageEditToolRate
    if (f.imageToolBase > 0) d.image_tool_base_micro_usdc = f.imageToolBase
    if (f.imageEditToolBase > 0) d.image_edit_tool_base_micro_usdc = f.imageEditToolBase
    if (f.imageRate > 0) d.image_rate_micro_usdc = f.imageRate
    if (f.imageEditRate > 0) d.image_edit_rate_micro_usdc = f.imageEditRate
    if (f.imageDefault > 0) d.image_default_micro_usdc = f.imageDefault
    if (f.imageEditDefault > 0) d.image_edit_default_micro_usdc = f.imageEditDefault
    if (f.imageCap > 0) d.image_cap_micro_usdc = f.imageCap
    if (f.imageEditCap > 0) d.image_edit_cap_micro_usdc = f.imageEditCap
    if (f.servesImageGen) d.serves_image_gen = true
    if (f.servesImageEdit) d.serves_image_edit = true
    return d
}

// The lowest declared value, where 0 is undeclared: v replaces cur only when
// positive and lower, or when cur is undeclared. Go's merge for the sizing,
// the token rates and the image fields, which minNonZero matches on Go's
// unsigned ones.
function minNonZero(cur: number, v: number): number {
    return v > 0 && (cur === 0 || v < cur) ? v : cur
}

// The lowest declared optional rate, where absent is no value and 0 is free.
function minRate(a: number | undefined, b: number | undefined): number | undefined {
    if (a === undefined) return b
    if (b === undefined) return a
    return b < a ? b : a
}

// Any known true is true, a known false beats unknown.
function aggregateBool(a: boolean | undefined, b: boolean | undefined): boolean | undefined {
    if (a === undefined && b === undefined) return undefined
    return a === true || b === true
}

// Supported is ORed and the efforts unioned. A default effort has no
// cross-operator meaning, so it is dropped.
function aggregateReasoning(a: ModelReasoning | undefined, b: ModelReasoning | undefined): ModelReasoning | undefined {
    if (a === undefined && b === undefined) return undefined
    let supported = false
    let efforts: string[] = []
    if (a !== undefined) {
        supported = a.supported
        efforts = [...(a.allowed_efforts ?? [])]
    }
    if (b !== undefined) {
        supported = supported || b.supported
        efforts = unionStrings(efforts, b.allowed_efforts)
    }
    const out: ModelReasoning = { supported }
    if (efforts.length > 0) out.allowed_efforts = efforts
    return out
}

// Go's foldTags: one entry per tag however it was cased or padded, lowercased,
// in Go's byte order (code point order, which UTF-16 `<` is not). Go's foldTags
// says where toLowerCase and trim differ from its ToLower and TrimSpace.
function foldTags(tags: readonly string[]): string[] {
    const out = new Set<string>()
    for (const t of tags) {
        const k = t.trim().toLowerCase()
        if (k !== '') out.add(k)
    }
    return [...out].sort(compareCodePoints)
}

function compareCodePoints(a: string, b: string): number {
    const x = Array.from(a, (c) => c.codePointAt(0) ?? 0)
    const y = Array.from(b, (c) => c.codePointAt(0) ?? 0)
    for (let i = 0; i < x.length && i < y.length; i++) if (x[i] !== y[i]) return x[i]! - y[i]!
    return x.length - y.length
}

// a, then each of b not in a. A value b repeats is appended each time, as
// Go's unionStrings appends it: neither side dedupes what a node advertised.
function unionStrings(a: string[], b: readonly string[] | undefined): string[] {
    if (b === undefined || b.length === 0) return a
    const out = [...a]
    const seen = new Set(a)
    for (const s of b) if (!seen.has(s)) out.push(s)
    return out
}

// Each field's unique most-common declared value; a tie or nothing declared
// leaves it out, and undefined when every field is out.
function aggregateCoordinates(cs: readonly ModelCoordinates[]): ModelCoordinates | undefined {
    const out: ModelCoordinates = {}
    const family = uniqueMode(cs.map((c) => c.family ?? ''), '')
    const quantization = uniqueMode(cs.map((c) => c.quantization ?? ''), '')
    const variant = uniqueMode(cs.map((c) => c.variant ?? ''), '')
    const parameters = uniqueMode(cs.map((c) => c.parameters ?? 0), 0)
    const active = uniqueMode(cs.map((c) => c.active_parameters ?? 0), 0)
    if (family !== '') out.family = family
    if (parameters !== 0) out.parameters = parameters
    if (active !== 0) out.active_parameters = active
    if (quantization !== '') out.quantization = quantization
    if (variant !== '') out.variant = variant
    return Object.keys(out).length === 0 ? undefined : out
}

function uniqueMode<T>(vals: readonly T[], unset: T): T {
    const counts = new Map<T, number>()
    for (const v of vals) if (v !== unset) counts.set(v, (counts.get(v) ?? 0) + 1)
    let best = unset
    let max = 0
    let winners = 0
    for (const [v, n] of counts) {
        if (n > max) {
            best = v
            max = n
            winners = 1
        } else if (n === max) {
            winners++
        }
    }
    return winners === 1 ? best : unset
}

// The one digest every operator that published one agrees on, and whether
// two distinct digests appeared. An operator with none neither makes nor
// breaks a consensus.
function aggregateDigest(digests: readonly string[]): { consensus: string; mismatch: boolean } {
    const seen = new Set(digests.filter((d) => d !== ''))
    if (seen.size === 0) return { consensus: '', mismatch: false }
    if (seen.size === 1) return { consensus: [...seen][0]!, mismatch: false }
    return { consensus: '', mismatch: true }
}

// The first declared source when every source names the same repo, revision
// and case aside; else "".
function aggregateSource(vals: readonly string[]): string {
    let consensus = ''
    let key = ''
    for (const v of vals) {
        if (v === '') continue
        if (consensus === '') {
            consensus = v
            key = sourceIdentityKey(v)
        } else if (sourceIdentityKey(v) !== key) {
            return ''
        }
    }
    return consensus
}

function sourceIdentityKey(source: string): string {
    let repo = source.startsWith('hf:') ? source.slice(3) : source
    const at = repo.indexOf('@')
    if (at >= 0) repo = repo.slice(0, at)
    return goToLower(repo)
}

// Go's strings.ToLower, which maps each rune on its own by unicode.ToLower.
// Lowered alone, a code point maps as Go's does except U+0130, which
// toLowerCase expands to "i" plus a combining dot.
function goToLower(s: string): string {
    let out = ''
    for (const ch of s) out += ch === 'İ' ? 'i' : ch.toLowerCase()
    return out
}

// The one exact canonical id every declaring operator agrees on; else "".
function aggregateIdentity(vals: readonly string[]): string {
    let consensus = ''
    for (const v of vals) {
        if (v === '') continue
        if (consensus === '') consensus = v
        else if (consensus !== v) return ''
    }
    return consensus
}
