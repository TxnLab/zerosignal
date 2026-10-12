/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The saved operator catalog: what a restart warm-starts discovery from, so a
// large fleet routes at once instead of filling in over bounded-probing sweeps.
// Mirrors go/zs persist.go (marshalCatalog, decodeCatalog, LoadCatalog,
// SaveCatalog) in Go's format version 1, so either SDK reads a catalog the
// other wrote. Go's minorFloor is restoredProtoVersion in catalog/engine.ts,
// pinned by testdata/persisted_proto_version_vectors.json. testdata/persisted_catalog_vectors.json pins it:
// what marshalCatalog writes is byte for byte what Go writes for the same
// operators, and what decodeCatalog reads is what Go reads. MergeCatalog is
// mergeCatalog in registry.ts, beside the carry it shares.
//
// As in Go, the file keeps identity, the capabilities that are slow to
// rediscover and the reachableAsOf carry clock, and leaves out what a probe
// re-establishes or what moves on every settle: the ephemeral seal key, the
// TEE verdict, the signer's balance, the this-cycle reachable and probed, and
// lastRefreshAt, which the registry carries between cycles but which says
// what this process tried, not what the node serves.
//
// Differences from Go:
//   - The catalog is a string in a StorageAdapter under a key, not a file
//     written to a temp path and renamed; whether a write is atomic is the
//     adapter's business. A torn write still reads as a malformed catalog and
//     starts cold.
//   - Times are written in UTC to the millisecond. Go writes its local zone to
//     the nanosecond. Both forms read, sub-millisecond digits truncated.
//   - The node's build id (node_version) is never written and is ignored on
//     read: the SDK's Operator does not carry one.
//   - The catalog is read with JSON.parse, so keys match exactly where Go also
//     matches them case-insensitively, and an integer written as 1.0, 1e2 or
//     -0, or past 2^53, is accepted (and rounded) where Go refuses it or keeps
//     it exact. Some forms Go reads are refused here, costing a cold start: a
//     time with a comma before its fraction or more than nine fraction digits,
//     and base64 with non-zero trailing bits or embedded line breaks. Neither
//     SDK writes any of these.

import { base64 } from '@scure/base'
import { type ModelCoordinates, type ModelReasoning, isKnownRetention } from '@txnlab/zs-proto/inject'

import { restoredProtoVersion } from '../catalog/engine.js'
import { compareCodePoints, goJSON } from '../gojson.js'
import { wellFormed } from '../gotext.js'
import type { BuiltinToolDef, ModelCapacity, Operator, OperatorMetrics } from '../operator.js'
import type { StorageAdapter } from '../ports.js'

/** CATALOG_FORMAT_VERSION is Go's catalogFormatVersion; a catalog of any other version starts cold. */
export const CATALOG_FORMAT_VERSION = 1

/**
 * CATALOG_STORAGE_KEY is where a registry keeps its catalog by default.
 * Operator and node ids repeat across networks, so a host that runs more than
 * one network on one storage gives each registry its own key.
 */
export const CATALOG_STORAGE_KEY = 'zs.catalog'

// ---- writing ----

/**
 * marshalCatalog encodes ops as Go's marshalCatalog does, byte for byte. It
 * throws on a rate that is not a finite number, as json.Marshal fails on one.
 */
export function marshalCatalog(ops: readonly Operator[]): string {
    return `{"version":${CATALOG_FORMAT_VERSION},"operators":[${ops.map(encodeOperator).join(',')}]}`
}

// Field order and omitempty are persistedOperator's.
function encodeOperator(op: Operator): string {
    const f: string[] = [member('id', num(op.id)), member('node_id', num(op.nodeId))]
    if (op.nfdAppId) f.push(member('nfd_app_id', num(op.nfdAppId)))
    f.push(member('owner_addr', str(op.ownerAddr)), member('signing_addr', str(op.signingAddr)))
    if (op.ticketSigningKey.length > 0) f.push(member('ticket_signing_key', str(base64.encode(op.ticketSigningKey))))
    f.push(member('base_url', str(op.baseUrl)))
    if (op.staging) f.push(member('staging', 'true'))
    if (op.models.length > 0) f.push(member('models', strList(op.models)))
    const caps = Object.keys(op.modelCapacities)
    if (caps.length > 0) {
        const entries = caps.sort(compareCodePoints).map((m) => member(m, encodeCapacity(op.modelCapacities[m]!)))
        f.push(member('model_capacities', `{${entries.join(',')}}`))
    }
    if (op.builtinTools.length > 0) f.push(member('builtin_tools', `[${op.builtinTools.map(encodeTool).join(',')}]`))
    if (op.maxToolIters) f.push(member('max_tool_iters', num(op.maxToolIters)))
    if (op.toolHeadroomPerIteration) f.push(member('tool_headroom_per_iteration', num(op.toolHeadroomPerIteration)))
    if (op.protoVersion !== '') f.push(member('proto_version', str(op.protoVersion)))
    // A struct is never empty to omitempty, so the zero time is written out.
    f.push(member('reachable_as_of', str(formatTime(op.reachableAsOf))), member('metrics', encodeMetrics(op.metrics)))
    if (op.minChargeOutputTokens) f.push(member('min_charge_output_tokens', num(op.minChargeOutputTokens)))
    if (op.minChargeAlgoTxns) f.push(member('min_charge_algo_txns', num(op.minChargeAlgoTxns)))
    if (op.minChargeMicroUsdc) f.push(member('min_charge_microusdc', num(op.minChargeMicroUsdc)))
    return `{${f.join(',')}}`
}

// Go's ModelCapacity has no json tags, so its members are its field names, in
// declaration order, with nothing omitted.
function encodeCapacity(c: ModelCapacity): string {
    return `{${[
        member('ContextWindow', num(c.contextWindow)),
        member('MaxOutputTokens', num(c.maxOutputTokens)),
        member('InputModalities', strList(c.inputModalities)),
        member('OutputModalities', strList(c.outputModalities)),
        member('InputUSDPer1M', num(c.inputUsdPer1m)),
        member('OutputUSDPer1M', num(c.outputUsdPer1m)),
        member('CacheReadUSDPer1M', optNum(c.cacheReadUsdPer1m)),
        member('LongContextThresholdTokens', num(c.longContextThresholdTokens)),
        member('LongContextInputUSDPer1M', optNum(c.longContextInputUsdPer1m)),
        member('LongContextOutputUSDPer1M', optNum(c.longContextOutputUsdPer1m)),
        member('LongContextCacheReadUSDPer1M', optNum(c.longContextCacheReadUsdPer1m)),
        member('Reasoning', c.reasoning === undefined ? 'null' : encodeReasoning(c.reasoning)),
        member('ToolUse', c.toolUse === undefined ? 'null' : flag(c.toolUse)),
        member('Tags', strList(c.tags)),
        member('Coordinates', c.coordinates === undefined ? 'null' : encodeCoordinates(c.coordinates)),
        member('WeightsDigest', str(c.weightsDigest)),
        member('WeightsUnverifiable', flag(c.weightsUnverifiable)),
        member('Source', str(c.source)),
        member('CanonicalID', str(c.canonicalId)),
        member('Retention', str(c.retention)),
        member('ImageToolRateMicroUSDC', num(c.imageToolRateMicroUsdc)),
        member('ImageEditToolRateMicroUSDC', num(c.imageEditToolRateMicroUsdc)),
        member('ImageToolBaseMicroUSDC', num(c.imageToolBaseMicroUsdc)),
        member('ImageEditToolBaseMicroUSDC', num(c.imageEditToolBaseMicroUsdc)),
        member('ImageRateMicroUSDC', num(c.imageRateMicroUsdc)),
        member('ImageEditRateMicroUSDC', num(c.imageEditRateMicroUsdc)),
        member('ImageDefaultMicroUSDC', num(c.imageDefaultMicroUsdc)),
        member('ImageEditDefaultMicroUSDC', num(c.imageEditDefaultMicroUsdc)),
        member('ImageCapMicroUSDC', num(c.imageCapMicroUsdc)),
        member('ImageEditCapMicroUSDC', num(c.imageEditCapMicroUsdc)),
        member('AdvertisesImageGen', flag(c.advertisesImageGen)),
        member('AdvertisesImageEdit', flag(c.advertisesImageEdit)),
        member('ToolCallRatesMicroUSDC', c.toolCallRatesMicroUsdc === undefined ? 'null' : numMap(c.toolCallRatesMicroUsdc)),
        member('VendorToolCatchAllMicroUSDC', num(c.vendorToolCatchAllMicroUsdc)),
        member('VendorToolCallCap', num(c.vendorToolCallCap)),
        member('VendorToolTokensPerCall', num(c.vendorToolTokensPerCall)),
    ].join(',')}}`
}

// inject.ModelReasoning and inject.ModelCoordinates are tagged, so these follow
// their tags and omitempty.
function encodeReasoning(r: ModelReasoning): string {
    const f = [member('supported', flag(r.supported))]
    if (r.allowed_efforts !== undefined && r.allowed_efforts.length > 0) f.push(member('allowed_efforts', strList(r.allowed_efforts)))
    if (r.default_effort) f.push(member('default_effort', str(r.default_effort)))
    return `{${f.join(',')}}`
}

function encodeCoordinates(c: ModelCoordinates): string {
    const f: string[] = []
    if (c.family) f.push(member('family', str(c.family)))
    if (c.parameters) f.push(member('parameters', num(c.parameters)))
    if (c.active_parameters) f.push(member('active_parameters', num(c.active_parameters)))
    if (c.quantization) f.push(member('quantization', str(c.quantization)))
    if (c.variant) f.push(member('variant', str(c.variant)))
    return `{${f.join(',')}}`
}

function encodeTool(t: BuiltinToolDef): string {
    return `{${member('Type', str(t.type))}}`
}

const METRIC_FIELDS = [
    ['LastActivityAt', 'lastActivityAt'],
    ['TicketsOpened', 'ticketsOpened'],
    ['TicketsSettled', 'ticketsSettled'],
    ['TicketsLapsedSettled', 'ticketsLapsedSettled'],
    ['TicketsRefundedInactive', 'ticketsRefundedInactive'],
    ['TicketsProtested', 'ticketsProtested'],
    ['TicketsFrozenDispute', 'ticketsFrozenDispute'],
    ['TotalRefundedInactiveUsdc', 'totalRefundedInactiveUsdc'],
    ['TotalProtestedUsdc', 'totalProtestedUsdc'],
    ['TotalFrozenDisputeUsdc', 'totalFrozenDisputeUsdc'],
    ['LatencyTotalMs', 'latencyTotalMs'],
    ['LatencyEwmaMs', 'latencyEwmaMs'],
    ['LatencySamples', 'latencySamples'],
    ['TokensPerSecEwma', 'tokensPerSecEwma'],
    ['TotalRevenueGross', 'totalRevenueGross'],
    ['Revenue24hUsdc', 'revenue24hUsdc'],
    ['Revenue7dUsdc', 'revenue7dUsdc'],
    ['Revenue30dUsdc', 'revenue30dUsdc'],
] as const satisfies readonly (readonly [string, keyof OperatorMetrics])[]

function encodeMetrics(m: OperatorMetrics): string {
    return `{${METRIC_FIELDS.map(([goName, key]) => member(goName, num(m[key]))).join(',')}}`
}

function member(key: string, value: string): string {
    return `${str(key)}:${value}`
}

// The encoders take a field a host left out as Go's zero value, so a
// hand-built operator cannot make the catalog unreadable.

// A lone surrogate reaches Go as U+FFFD, which Go writes as the character.
function str(s: string | undefined): string {
    return goJSON(wellFormed(s ?? ''))
}

function strList(l: readonly string[] | undefined): string {
    return l === undefined ? 'null' : `[${l.map(str).join(',')}]`
}

function flag(b: boolean | undefined): string {
    return b === true ? 'true' : 'false'
}

// JSON.stringify writes a finite number as Go does: the shortest round-trip
// digits, in exponent form below 1e-6 and from 1e21 up.
function num(n: number | undefined): string {
    const v = n ?? 0
    if (!Number.isFinite(v)) throw new Error(`json: unsupported value: ${v}`)
    return Object.is(v, -0) ? '-0' : JSON.stringify(v)
}

function optNum(n: number | undefined): string {
    return n === undefined ? 'null' : num(n)
}

function numMap(m: Record<string, number>): string {
    return `{${Object.keys(m)
        .sort(compareCodePoints)
        .map((k) => member(k, num(m[k]!)))
        .join(',')}}`
}

// Go's zero time, which a node never confirmed live carries.
const ZERO_TIME = '0001-01-01T00:00:00Z'
const ZERO_TIME_MS = Date.parse(ZERO_TIME)

// Go's RFC 3339 with nanoseconds: the fraction's trailing zeros, and an empty
// fraction, are dropped.
function formatTime(ms: number | undefined): string {
    if (ms === undefined || ms === 0) return ZERO_TIME
    return new Date(ms).toISOString().replace(/\.?0+Z$/, 'Z')
}

// ---- reading ----

/**
 * decodeCatalog reads a catalog as Go's LoadCatalog does once it has the
 * bytes: every node unprobed, its proto_version floored to minor 0 (see
 * restoredProtoVersion). It throws on text that is not a catalog of this
 * format version, which a caller logs and then starts cold.
 */
export function decodeCatalog(text: string): Operator[] {
    let doc: unknown
    try {
        doc = JSON.parse(text)
    } catch (err) {
        throw new Error(`unmarshal catalog: ${message(err)}`, { cause: err })
    }
    // Go decodes a top-level null into the zero struct, version 0.
    const pc = doc === null ? {} : object(doc, 'catalog')
    const version = doc === null ? 0 : int(pc.version, 'version')
    if (version !== CATALOG_FORMAT_VERSION) {
        throw new Error(`catalog format version ${version} != supported ${CATALOG_FORMAT_VERSION}`)
    }
    const ops = pc.operators
    if (ops === null || ops === undefined) return []
    if (!Array.isArray(ops)) throw typeError('operators', ops)
    return ops.map((po, i) => decodeOperator(po === null ? {} : object(po, `operators[${i}]`), `operators[${i}]`))
}

function decodeOperator(p: Record<string, unknown>, at: string): Operator {
    const field = (k: string) => `${at}.${k}`
    const caps = Object.create(null) as Record<string, ModelCapacity>
    const capsIn = optObject(p.model_capacities, field('model_capacities'))
    if (capsIn !== undefined) {
        for (const [m, c] of Object.entries(capsIn)) {
            caps[wellFormed(m)] = decodeCapacity(c === null ? {} : object(c, `${field('model_capacities')}.${m}`), `${field('model_capacities')}.${m}`)
        }
    }
    const tools = optStrings(p.builtin_tools, field('builtin_tools'), (t, path) => {
        const o = t === null ? {} : object(t, path)
        return { type: string(o.Type, `${path}.Type`) }
    })
    const metricsIn = optObject(p.metrics, field('metrics')) ?? {}
    const metrics = {} as Record<keyof OperatorMetrics, number>
    for (const [goName, key] of METRIC_FIELDS) metrics[key] = uint(metricsIn[goName], `${field('metrics')}.${goName}`)
    const reachableAsOf = parseTime(p.reachable_as_of, field('reachable_as_of'))
    const op: Operator = {
        id: uint(p.id, field('id')),
        nodeId: uint(p.node_id, field('node_id')),
        nfdAppId: uint(p.nfd_app_id, field('nfd_app_id')),
        ownerAddr: string(p.owner_addr, field('owner_addr')),
        signingAddr: string(p.signing_addr, field('signing_addr')),
        ticketSigningKey: bytes(p.ticket_signing_key, field('ticket_signing_key')),
        baseUrl: string(p.base_url, field('base_url')),
        models: optStrings(p.models, field('models'), stringAt) ?? [],
        staging: bool(p.staging, field('staging')),
        // Nothing a probe sets is restored: the node reads as not probed this
        // cycle, so the carry window governs it, and the next probe or
        // reprobeEphemeral re-establishes its seal key.
        ephemeralExpiry: 0,
        ephemeralIssuedAt: 0,
        modelCapacities: caps,
        builtinTools: tools ?? [],
        maxToolIters: int(p.max_tool_iters, field('max_tool_iters')),
        toolHeadroomPerIteration: uint(p.tool_headroom_per_iteration, field('tool_headroom_per_iteration')),
        protoVersion: restoredProtoVersion(string(p.proto_version, field('proto_version'))),
        reachable: false,
        metrics,
        minChargeOutputTokens: uint(p.min_charge_output_tokens, field('min_charge_output_tokens')),
        minChargeAlgoTxns: uint(p.min_charge_algo_txns, field('min_charge_algo_txns')),
        minChargeMicroUsdc: uint(p.min_charge_microusdc, field('min_charge_microusdc')),
    }
    // Read only so a file Go refuses is refused here too.
    string(p.node_version, field('node_version'))
    if (reachableAsOf !== undefined) op.reachableAsOf = reachableAsOf
    return op
}

function decodeCapacity(c: Record<string, unknown>, at: string): ModelCapacity {
    const field = (k: string) => `${at}.${k}`
    const out: ModelCapacity = {
        contextWindow: uint(c.ContextWindow, field('ContextWindow')),
        maxOutputTokens: uint(c.MaxOutputTokens, field('MaxOutputTokens')),
        inputModalities: optStrings(c.InputModalities, field('InputModalities'), stringAt),
        outputModalities: optStrings(c.OutputModalities, field('OutputModalities'), stringAt),
        inputUsdPer1m: float(c.InputUSDPer1M, field('InputUSDPer1M')),
        outputUsdPer1m: float(c.OutputUSDPer1M, field('OutputUSDPer1M')),
        cacheReadUsdPer1m: optFloat(c.CacheReadUSDPer1M, field('CacheReadUSDPer1M')),
        longContextThresholdTokens: uint(c.LongContextThresholdTokens, field('LongContextThresholdTokens')),
        longContextInputUsdPer1m: optFloat(c.LongContextInputUSDPer1M, field('LongContextInputUSDPer1M')),
        longContextOutputUsdPer1m: optFloat(c.LongContextOutputUSDPer1M, field('LongContextOutputUSDPer1M')),
        longContextCacheReadUsdPer1m: optFloat(c.LongContextCacheReadUSDPer1M, field('LongContextCacheReadUSDPer1M')),
        reasoning: decodeReasoning(c.Reasoning, field('Reasoning')),
        toolUse: c.ToolUse === null || c.ToolUse === undefined ? undefined : bool(c.ToolUse, field('ToolUse')),
        tags: optStrings(c.Tags, field('Tags'), stringAt),
        coordinates: decodeCoordinates(c.Coordinates, field('Coordinates')),
        weightsDigest: string(c.WeightsDigest, field('WeightsDigest')),
        weightsUnverifiable: bool(c.WeightsUnverifiable, field('WeightsUnverifiable')),
        source: string(c.Source, field('Source')),
        canonicalId: string(c.CanonicalID, field('CanonicalID')),
        // As the probe filters it: a newer build's file, or a hand edit,
        // would otherwise label the node with a tier this build cannot vouch for.
        retention: knownRetention(string(c.Retention, field('Retention'))),
        imageToolRateMicroUsdc: uint(c.ImageToolRateMicroUSDC, field('ImageToolRateMicroUSDC')),
        imageEditToolRateMicroUsdc: uint(c.ImageEditToolRateMicroUSDC, field('ImageEditToolRateMicroUSDC')),
        imageToolBaseMicroUsdc: uint(c.ImageToolBaseMicroUSDC, field('ImageToolBaseMicroUSDC')),
        imageEditToolBaseMicroUsdc: uint(c.ImageEditToolBaseMicroUSDC, field('ImageEditToolBaseMicroUSDC')),
        imageRateMicroUsdc: uint(c.ImageRateMicroUSDC, field('ImageRateMicroUSDC')),
        imageEditRateMicroUsdc: uint(c.ImageEditRateMicroUSDC, field('ImageEditRateMicroUSDC')),
        imageDefaultMicroUsdc: uint(c.ImageDefaultMicroUSDC, field('ImageDefaultMicroUSDC')),
        imageEditDefaultMicroUsdc: uint(c.ImageEditDefaultMicroUSDC, field('ImageEditDefaultMicroUSDC')),
        imageCapMicroUsdc: uint(c.ImageCapMicroUSDC, field('ImageCapMicroUSDC')),
        imageEditCapMicroUsdc: uint(c.ImageEditCapMicroUSDC, field('ImageEditCapMicroUSDC')),
        advertisesImageGen: bool(c.AdvertisesImageGen, field('AdvertisesImageGen')),
        advertisesImageEdit: bool(c.AdvertisesImageEdit, field('AdvertisesImageEdit')),
        toolCallRatesMicroUsdc: undefined,
        vendorToolCatchAllMicroUsdc: uint(c.VendorToolCatchAllMicroUSDC, field('VendorToolCatchAllMicroUSDC')),
        vendorToolCallCap: uint(c.VendorToolCallCap, field('VendorToolCallCap')),
        vendorToolTokensPerCall: uint(c.VendorToolTokensPerCall, field('VendorToolTokensPerCall')),
    }
    const rates = optObject(c.ToolCallRatesMicroUSDC, field('ToolCallRatesMicroUSDC'))
    if (rates !== undefined) {
        const r = Object.create(null) as Record<string, number>
        for (const [k, v] of Object.entries(rates)) r[wellFormed(k)] = uint(v, `${field('ToolCallRatesMicroUSDC')}.${k}`)
        out.toolCallRatesMicroUsdc = r
    }
    return out
}

// Go's knownRetention: a tier this build does not recognise reads as unknown.
function knownRetention(v: string): string {
    return isKnownRetention(v) ? v : ''
}

function decodeReasoning(v: unknown, at: string): ModelReasoning | undefined {
    if (v === null || v === undefined) return undefined
    const o = object(v, at)
    const out: ModelReasoning = { supported: bool(o.supported, `${at}.supported`) }
    const efforts = optStrings(o.allowed_efforts, `${at}.allowed_efforts`, stringAt)
    if (efforts !== undefined && efforts.length > 0) out.allowed_efforts = efforts
    const effort = string(o.default_effort, `${at}.default_effort`)
    if (effort !== '') out.default_effort = effort
    return out
}

function decodeCoordinates(v: unknown, at: string): ModelCoordinates | undefined {
    if (v === null || v === undefined) return undefined
    const o = object(v, at)
    const out: ModelCoordinates = {}
    const family = string(o.family, `${at}.family`)
    const parameters = uint(o.parameters, `${at}.parameters`)
    const active = uint(o.active_parameters, `${at}.active_parameters`)
    const quantization = string(o.quantization, `${at}.quantization`)
    const variant = string(o.variant, `${at}.variant`)
    if (family !== '') out.family = family
    if (parameters !== 0) out.parameters = parameters
    if (active !== 0) out.active_parameters = active
    if (quantization !== '') out.quantization = quantization
    if (variant !== '') out.variant = variant
    return out
}

// Each reader takes a JSON value and a path for the error. Go leaves a field
// the file sets to null at its zero value, as it does a field the file lacks.

function object(v: unknown, at: string): Record<string, unknown> {
    if (typeof v !== 'object' || v === null || Array.isArray(v)) throw typeError(at, v)
    return v as Record<string, unknown>
}

function optObject(v: unknown, at: string): Record<string, unknown> | undefined {
    return v === null || v === undefined ? undefined : object(v, at)
}

function optStrings<T>(v: unknown, at: string, each: (e: unknown, path: string) => T): T[] | undefined {
    if (v === null || v === undefined) return undefined
    if (!Array.isArray(v)) throw typeError(at, v)
    return v.map((e, i) => each(e, `${at}[${i}]`))
}

function stringAt(v: unknown, at: string): string {
    return string(v, at)
}

function string(v: unknown, at: string): string {
    if (v === null || v === undefined) return ''
    if (typeof v !== 'string') throw typeError(at, v)
    return wellFormed(v)
}

function bool(v: unknown, at: string): boolean {
    if (v === null || v === undefined) return false
    if (typeof v !== 'boolean') throw typeError(at, v)
    return v
}

function float(v: unknown, at: string): number {
    if (v === null || v === undefined) return 0
    // A literal past float64's range parses to Infinity here; Go refuses it,
    // and a rate of Infinity carried forward would fail every later save.
    if (typeof v !== 'number' || !Number.isFinite(v)) throw typeError(at, v)
    return v
}

function optFloat(v: unknown, at: string): number | undefined {
    return v === null || v === undefined ? undefined : float(v, at)
}

function int(v: unknown, at: string): number {
    if (v === null || v === undefined) return 0
    if (typeof v !== 'number' || !Number.isInteger(v)) throw typeError(at, v)
    return v
}

function uint(v: unknown, at: string): number {
    const n = int(v, at)
    if (n < 0) throw typeError(at, v)
    return n
}

// Go decodes a []byte from standard, padded base64.
function bytes(v: unknown, at: string): Uint8Array {
    const s = string(v, at)
    if (s === '') return new Uint8Array(0)
    try {
        return base64.decode(s)
    } catch (err) {
        throw new Error(`json: ${at}: ${message(err)}`, { cause: err })
    }
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(?:Z|([+-])(\d{2}):(\d{2}))$/

// Unix ms, or undefined for Go's zero time. Go refuses a date that does not
// exist, so the fields are range-checked rather than left to Date to roll over.
function parseTime(v: unknown, at: string): number | undefined {
    const s = string(v, at)
    if (s === '') {
        if (v === null || v === undefined) return undefined
        throw new Error(`json: ${at}: parsing time "" as RFC 3339`)
    }
    const m = RFC3339.exec(s)
    if (m === null) throw new Error(`json: ${at}: parsing time ${JSON.stringify(s)} as RFC 3339`)
    const [y, mo, d, h, mi, sec] = m.slice(1, 7).map(Number) as [number, number, number, number, number, number]
    const day = new Date(0)
    day.setUTCFullYear(y, mo - 1, d)
    const valid =
        mo >= 1 && mo <= 12 && day.getUTCMonth() === mo - 1 && day.getUTCDate() === d && h < 24 && mi < 60 && sec < 60
    const offH = m[9] === undefined ? 0 : Number(m[9])
    const offM = m[10] === undefined ? 0 : Number(m[10])
    // Go's own offset bounds, which admit +24:00 and +00:60.
    if (!valid || offH > 24 || offM > 60) throw new Error(`json: ${at}: time ${JSON.stringify(s)} out of range`)
    day.setUTCHours(h, mi, sec, 0)
    const fraction = m[7] === undefined ? 0 : Math.floor(Number(m[7].padEnd(9, '0')) / 1e6)
    const offset = (m[8] === '-' ? -1 : 1) * (offH * 60 + offM) * 60_000
    const ms = day.getTime() + fraction - offset
    return ms === ZERO_TIME_MS ? undefined : ms
}

function typeError(at: string, v: unknown): TypeError {
    const kind = v === null ? 'null' : Array.isArray(v) ? 'array' : typeof v
    return new TypeError(`json: cannot unmarshal ${kind} into ${at}`)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}

// ---- storage ----

/**
 * loadCatalog reads the catalog saved under key: undefined when there is none,
 * so a fresh install starts cold, and a throw when what is there is not a
 * catalog this build reads, which the caller logs before starting cold. The
 * next save overwrites it either way.
 */
export async function loadCatalog(storage: StorageAdapter, key: string = CATALOG_STORAGE_KEY): Promise<Operator[] | undefined> {
    const text = await storage.get(key)
    return text === undefined ? undefined : decodeCatalog(text)
}

/**
 * saveCatalog writes ops under key. Best effort for a registry, which logs a
 * failure and carries on: it only costs a colder next start.
 */
export async function saveCatalog(storage: StorageAdapter, ops: readonly Operator[], key: string = CATALOG_STORAGE_KEY): Promise<void> {
    await storage.set(key, marshalCatalog(ops))
}
