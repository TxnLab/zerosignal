/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'
import { hexToBytes } from '@noble/hashes/utils.js'
import { RelayErrorCode } from '@txnlab/zs-proto/relay'
import {
    PROTO_VERSION,
    RELAY_PATH,
    RELAY_PATH_HEADER,
    RELAY_TARGET_HEADER,
    RELAY_TARGET_NODE_HEADER,
    bootstrapProtoVersion,
} from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import type { Operator, TEEStatus } from '../src/operator.js'
import type { LogAttrs, Logger } from '../src/ports.js'
import { ChainOperatorSource } from '../src/registry/chain.js'
import { RelayHopError, RelayUpstreamUnreachableError } from '../src/details.js'
import { NodeProber, type ProbeOptions, type ProbeOutcome, applyProbeOutcome, classifyProbeFailure } from '../src/registry/probe.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import type { Verdict, Verifier } from '../src/tee/types.js'
import { type NodeRef, nodeRefString } from '../src/types.js'
import { testOperator } from './fixtures.js'

// ---- the outcome vectors ----

interface VectorState {
    reachable: boolean
    probed: boolean
    last_refresh_at_ms: number
    reachable_as_of_ms: number
    models: string[]
    ephemeral: boolean
    tee: boolean
}

const outcomeVectors = JSON.parse(
    readFileSync(new URL('../../testdata/registry_probe_vectors.json', import.meta.url), 'utf8'),
) as {
    now_ms: number
    cases: { name: string; outcome: ProbeOutcome; prior: VectorState; want: VectorState & { record_reachable: boolean | null } }[]
}

const TEE: TEEStatus = {
    mode: 'dstack',
    attestedAt: 0,
    verifierId: 'dstack-tdx',
    verified: true,
    failureTag: '',
    osImageChecked: true,
    composeReleaseChecked: true,
}

// Go's zero values arrive as unset fields, as a fresh chain row has them.
function operatorOf(s: VectorState, nowMs: number): Operator {
    const op = testOperator({ reachable: s.reachable, models: [...s.models] })
    if (s.probed) op.probed = true
    if (s.last_refresh_at_ms !== 0) op.lastRefreshAt = s.last_refresh_at_ms
    if (s.reachable_as_of_ms !== 0) op.reachableAsOf = s.reachable_as_of_ms
    if (s.ephemeral) {
        op.ephemeralRecipient = 'age1rc8wp62cfvmldwhm49mdp5lg3gu6qkrs2whhactp0w9nqjk6wp7sl74d8s'
        op.ephemeralExpiry = Math.floor(nowMs / 1000) + 600
        op.ephemeralIssuedAt = Math.floor(nowMs / 1000) - 600
    }
    if (s.tee) op.tee = { ...TEE }
    return op
}

function stateOf(op: Operator): VectorState {
    return {
        reachable: op.reachable,
        probed: op.probed === true,
        last_refresh_at_ms: op.lastRefreshAt ?? 0,
        reachable_as_of_ms: op.reachableAsOf ?? 0,
        models: op.models,
        ephemeral: op.ephemeralRecipient !== undefined || op.ephemeralExpiry !== 0 || op.ephemeralIssuedAt !== 0,
        tee: op.tee !== undefined,
    }
}

describe('registry_probe vectors', () => {
    it('covers every outcome', () => {
        expect(new Set(outcomeVectors.cases.map((c) => c.outcome))).toEqual(
            new Set(['no_relay', 'cancelled', 'hop_failed', 'target_failed', 'succeeded']),
        )
    })
    it.each(outcomeVectors.cases.map((c) => [c.name, c] as const))('%s', (_, c) => {
        const op = operatorOf(c.prior, outcomeVectors.now_ms)
        const recorded = applyProbeOutcome(op, c.outcome, outcomeVectors.now_ms)
        const { record_reachable, ...want } = c.want
        expect(stateOf(op)).toEqual(want)
        expect(recorded ?? null).toBe(record_reachable)
    })
})

describe('classifyProbeFailure', () => {
    const hop = { baseUrl: 'https://r.example', targetId: 42, targetNodeId: 7, relayId: 2, relayNodeId: 1, relayProtoVersion: '9.11' }
    const aborted = AbortSignal.abort(new Error('refresh deadline'))

    // A hop error that lands as the signal fires learned nothing about the
    // hop: read as hop_failed it would stamp the node as attempted.
    it('reads an abort ahead of a hop error', () => {
        expect(classifyProbeFailure(new RelayHopError(hop, 'relay returned 503'), aborted)).toBe('cancelled')
        expect(classifyProbeFailure(new Error('details endpoint returned 500'), aborted)).toBe('cancelled')
    })
    it('reads a hop error as the hop, and anything else as the target', () => {
        expect(classifyProbeFailure(new RelayHopError(hop, 'relay returned 503'), undefined)).toBe('hop_failed')
        expect(classifyProbeFailure(new RelayUpstreamUnreachableError(hop, 502), new AbortController().signal)).toBe('target_failed')
        expect(classifyProbeFailure(new Error('details endpoint returned 500'), undefined)).toBe('target_failed')
    })
})

// ---- the probe pass, against a fake network ----

const NOW_MS = 1_800_000_000_000

interface EphemeralCase {
    name: string
    signing_key: string
    advertisement: Record<string, unknown>
}

const ephemeralCases = (
    JSON.parse(readFileSync(new URL('../../testdata/ephemeral_verdict_vectors.json', import.meta.url), 'utf8')) as {
        cases: EphemeralCase[]
    }
).cases
const ephemeral = (name: string): EphemeralCase => ephemeralCases.find((c) => c.name === name)!
const FRESH = ephemeral('a fresh, genuine block')
const STALE = ephemeral('past the freshness target is stale but usable')
const FORGED = ephemeral('a flipped signature byte')

// The target is the node the ephemeral vectors are signed for.
const T: NodeRef = { op: 42, node: 7 }
const R2: NodeRef = { op: 2, node: 1 }
const R3: NodeRef = { op: 3, node: 1 }
const host = (r: NodeRef) => `https://n${r.op}-${r.node}.example`

function node(r: NodeRef, over: Partial<Operator> = {}): Operator {
    return testOperator({
        id: r.op,
        nodeId: r.node,
        ownerAddr: `OWNER${r.op}`,
        baseUrl: host(r),
        reachable: false,
        ticketSigningKey: hexToBytes(FRESH.signing_key),
        ...over,
    })
}

interface Call {
    /** The node the request reached: the relay when relayed. */
    to: string
    /** The node it is about, and the path there. */
    target: string
    path: string
    relayed: boolean
}

type Answer = (c: Call, signal: AbortSignal | null | undefined) => Response | Promise<Response>

function network(answer: Answer) {
    const calls: Call[] = []
    const fetch = (async (url: string, init: RequestInit) => {
        const u = new URL(url)
        const h = (init.headers ?? {}) as Record<string, string>
        const relayed = u.pathname === RELAY_PATH
        const call: Call = relayed
            ? {
                  to: u.origin,
                  target: host({ op: Number(h[RELAY_TARGET_HEADER]), node: Number(h[RELAY_TARGET_NODE_HEADER]) }),
                  path: h[RELAY_PATH_HEADER]!,
                  relayed,
              }
            : { to: u.origin, target: u.origin, path: u.pathname, relayed }
        calls.push(call)
        if (init.signal?.aborted) throw init.signal.reason
        return answer(call, init.signal)
    }) as typeof globalThis.fetch
    return { fetch, calls }
}

function json(status: number, body: unknown): Response {
    return new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
}

function details(over: Record<string, unknown> = {}): Response {
    return json(200, { models: [{ id: 'fresh-model' }], oracle_healthy: true, proto_version: PROTO_VERSION, ...over })
}

const relayError = (status: number, code: string) => json(status, { error: { code, message: 'm' } })

// Never answers; rejects when its signal fires, as fetch does.
function hang(signal: AbortSignal | null | undefined): Promise<Response> {
    return new Promise((_, reject) => signal?.addEventListener('abort', () => reject(signal.reason), { once: true }))
}

function recordingLogger() {
    const lines: { level: string; msg: string; attrs: LogAttrs | undefined }[] = []
    const at =
        (level: string) =>
        (msg: string, attrs?: LogAttrs): void => {
            lines.push({ level, msg, attrs })
        }
    const logger: Logger = { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') }
    return { logger, lines }
}

function prober(o: ProbeOptions) {
    return new NodeProber({ clock: () => NOW_MS, ...o })
}

describe('NodeProber direct', () => {
    it('applies a success: details fields, liveness stamps, reachability and the round trip', async () => {
        const { fetch } = network(() => details({ max_tool_iterations: 4 }))
        const p = prober({ fetch, privacy: 'direct' })
        const op = node(T, { models: ['old'] })
        await p.enrichSubset([op], null)
        expect(op).toMatchObject({
            reachable: true,
            probed: true,
            lastRefreshAt: NOW_MS,
            reachableAsOf: NOW_MS,
            models: ['fresh-model'],
            maxToolIters: 4,
            protoVersion: PROTO_VERSION,
        })
        expect(p.recallReachable(T)).toBe(true)
        expect(p.relayLatency.targetLatency(T)).toBeDefined()
    })

    it.each([
        ['an error status', () => json(500, {})],
        ['an unreadable body', () => new Response('not json', { status: 200 })],
        [
            'no response',
            () => {
                throw new TypeError('connection refused')
            },
        ],
    ])('marks the target down on %s and keeps what it carried', async (_, answer) => {
        const { fetch } = network(answer)
        const p = prober({ fetch, privacy: 'direct' })
        const op = node(T, { reachable: true, models: ['carried'], reachableAsOf: NOW_MS - 60_000, ephemeralRecipient: 'age1x', ephemeralExpiry: 1 })
        await p.enrichSubset([op], null)
        expect(op).toMatchObject({
            reachable: false,
            probed: true,
            lastRefreshAt: NOW_MS,
            reachableAsOf: NOW_MS - 60_000,
            models: ['carried'],
            ephemeralRecipient: 'age1x',
        })
        expect(p.recallReachable(T)).toBe(false)
        expect(p.relayLatency.targetLatency(T)).toBeUndefined()
    })

    it('probes only the probe set and leaves the rest as seeded', async () => {
        const { fetch, calls } = network(() => details())
        const p = prober({ fetch, privacy: 'direct' })
        const ops = [node(T), node(R2, { models: ['seeded'] }), node(R3)]
        await p.enrichSubset(ops, new Set([nodeRefString(T), nodeRefString(R3)]))
        expect(calls.map((c) => c.target).sort()).toEqual([host(R3), host(T)])
        expect(ops[1]).toMatchObject({ models: ['seeded'], reachable: false })
        expect(ops[1]!.lastRefreshAt).toBeUndefined()
    })

    it('caps the probes in flight', async () => {
        let inFlight = 0
        let peak = 0
        const { fetch } = network(async () => {
            peak = Math.max(peak, ++inFlight)
            await new Promise((r) => setTimeout(r, 5))
            inFlight--
            return details()
        })
        const p = prober({ fetch, privacy: 'direct', detailsConcurrency: 2 })
        const ops = Array.from({ length: 7 }, (_, i) => node({ op: 100 + i, node: 1 }))
        await p.enrichSubset(ops, null)
        expect(peak).toBe(2)
        expect(ops.every((o) => o.reachable)).toBe(true)
    })

    it('reads a fractional concurrency under one as the default, not as no probes', async () => {
        const { fetch, calls } = network(() => details())
        await prober({ fetch, privacy: 'direct', detailsConcurrency: 0.5 }).enrichSubset([node(T)], null)
        expect(calls).toHaveLength(1)
    })

    it('leaves every node as it was when the caller aborted first', async () => {
        const { fetch } = network(() => details())
        const p = prober({ fetch, privacy: 'direct' })
        const ac = new AbortController()
        ac.abort(new Error('refresh deadline'))
        const ops = [node(T, { reachable: true, models: ['carried'] }), node(R2)]
        await p.enrichSubset(ops, null, ac.signal)
        expect(ops[0]).toMatchObject({ reachable: true, models: ['carried'] })
        expect(ops[0]!.lastRefreshAt).toBeUndefined()
        expect(ops[0]!.probed).toBeUndefined()
        expect(p.recallReachable(T)).toBe(false)
    })

    it('leaves a node as it was when the caller aborts mid-probe', async () => {
        const ac = new AbortController()
        const { fetch } = network(() => {
            const pending = hang(ac.signal)
            ac.abort(new Error('refresh deadline'))
            return pending
        })
        const p = prober({ fetch, privacy: 'direct' })
        const op = node(T, { reachable: true })
        await p.enrichSubset([op], null, ac.signal)
        expect(op.reachable).toBe(true)
        expect(op.lastRefreshAt).toBeUndefined()
    })

    it('reprobes a copy, leaving the snapshot row alone', async () => {
        const { fetch } = network(() => details({ ...FRESH.advertisement }))
        const p = prober({ fetch, privacy: 'direct' })
        const row = node(T)
        const got = await p.reprobeEphemeral([row], row)
        expect(got).not.toBe(row)
        expect(got.ephemeralRecipient).toBe(FRESH.advertisement.ephemeral_age_pubkey)
        expect(got.reachable).toBe(true)
        expect(row.ephemeralRecipient).toBeUndefined()
        expect(row.reachable).toBe(false)
    })
})

describe('NodeProber relayed', () => {
    const fleet = () => [node(T), node(R2), node(R3)]

    it('seeds an unprobed relay with the bootstrap version, and tiers by reachability and reputation', async () => {
        const { fetch } = network(() => details())
        const p = prober({ fetch })
        const cold = p.buildSelAll(fleet())
        expect(cold.map((s) => [s.proto_version, s.reachable])).toEqual([
            [bootstrapProtoVersion(), false],
            [bootstrapProtoVersion(), false],
            [bootstrapProtoVersion(), false],
        ])
        // A cold fleet still probes: the seed keeps every peer relay-eligible.
        const ops = fleet()
        await p.enrichSubset(ops, null)
        expect(ops.every((o) => o.reachable)).toBe(true)
        // An advertised version is kept, and a relay on a failure streak drops
        // to the fallback tier although its own probe answered.
        for (let i = 0; i < 3; i++) p.relayReputation.recordRelayOutcome(R2, false)
        const warm = p.buildSelAll(ops)
        expect(warm.map((s) => [s.proto_version, s.reachable])).toEqual([
            [PROTO_VERSION, true],
            [PROTO_VERSION, false],
            [PROTO_VERSION, true],
        ])
    })

    it('skips a node with no eligible relay, stamping the attempt only', async () => {
        const { fetch, calls } = network(() => details())
        const p = prober({ fetch })
        // The only peer shares the target's owner, so it cannot relay for it.
        const op = node(T, { reachable: true })
        await p.enrichSubset([op, node(R2, { ownerAddr: op.ownerAddr })], new Set([nodeRefString(T)]))
        expect(calls).toHaveLength(0)
        expect(op).toMatchObject({ reachable: true, lastRefreshAt: NOW_MS })
        expect(op.probed).toBeUndefined()
    })

    it('credits a relay that forwarded, and records no reachability for it', async () => {
        const { fetch, calls } = network(() => details())
        const p = prober({ fetch })
        const ops = [node(T), node(R2)]
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(calls).toEqual([{ to: host(R2), target: host(T), path: '/v1/zs/details', relayed: true }])
        expect(ops[0]!.reachable).toBe(true)
        expect(p.recallReachable(T)).toBe(true)
        expect(p.recallReachable(R2)).toBe(false)
        expect(p.relayLatency.relayLatencyForTarget(R2, T)).toBeDefined()
    })

    it.each([
        [
            'no response',
            () => {
                throw new TypeError('connection refused')
            },
        ],
        ['a relay hop code', () => relayError(503, RelayErrorCode.Busy)],
    ])('on %s from every relay, charges each one and leaves the target unknown', async (_, answer) => {
        let failing = false
        const { fetch, calls } = network((c) => (failing && c.target === host(T) ? answer() : details()))
        const p = prober({ fetch })
        // A first cycle sees every node up.
        const warm = fleet()
        await p.enrichSubset(warm, null)
        expect([T, R2, R3].map((r) => p.recallReachable(r))).toEqual([true, true, true])
        calls.length = 0
        failing = true

        const ops = fleet().map((o, i) => ({ ...o, models: warm[i]!.models, protoVersion: PROTO_VERSION }))
        ops[0]!.reachable = true
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(calls.map((c) => c.to).sort()).toEqual([host(R2), host(R3)])
        expect(ops[0]).toMatchObject({ reachable: true, lastRefreshAt: NOW_MS, models: ['fresh-model'] })
        expect(ops[0]!.probed).toBeUndefined()
        expect([T, R2, R3].map((r) => p.recallReachable(r))).toEqual([true, false, false])
        expect(p.relayReputation.standing(R2).failures).toBe(1)
        expect(p.relayReputation.standing(R3).failures).toBe(1)
    })

    it("charges no relay for the probe's own deadline", async () => {
        const { fetch } = network((_c, signal) => hang(signal))
        const p = prober({ fetch, detailsTimeoutMs: 20 })
        const ops = fleet()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(ops[0]!.lastRefreshAt).toBe(NOW_MS)
        expect(ops[0]!.probed).toBeUndefined()
        expect(p.relayReputation.standing(R2).failures).toBe(0)
        expect(p.relayReputation.standing(R3).failures).toBe(0)
    })

    it("judges one relay's claim the target is down by the target's last probe", async () => {
        let claim = false
        const { fetch } = network((c) =>
            claim && c.target === host(T) ? relayError(502, RelayErrorCode.UpstreamUnreachable) : details(),
        )
        const p = prober({ fetch })
        const pair = () => [node(T), node(R2)]
        await p.enrichSubset(pair(), new Set([nodeRefString(T)]))
        expect(p.recallReachable(T)).toBe(true)

        claim = true
        const ops = pair()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        // Seen up a cycle ago, so the lone claim is contradicted and counts
        // against the relay; the target is still the one marked down.
        expect(p.relayReputation.standing(R2).failures).toBe(1)
        expect(ops[0]).toMatchObject({ reachable: false, probed: true })
        expect(p.recallReachable(T)).toBe(false)
    })

    it('marks the target down when every relay that worked says so, and credits them', async () => {
        const { fetch } = network((c) => (c.target === host(T) ? relayError(502, RelayErrorCode.UpstreamUnreachable) : details()))
        const p = prober({ fetch })
        for (const r of [R2, R3]) p.relayReputation.recordRelayOutcome(r, false)
        const ops = fleet()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(ops[0]).toMatchObject({ reachable: false, probed: true, lastRefreshAt: NOW_MS })
        expect(p.relayReputation.standing(R2).failures).toBe(0)
        expect(p.relayReputation.standing(R3).failures).toBe(0)
    })

    it('charges no relay and leaves every reachability alone when the caller aborts mid-hop', async () => {
        let aborting = false
        const ac = new AbortController()
        const { fetch } = network((c, signal) => {
            if (!aborting || c.target !== host(T)) return details()
            const pending = hang(signal)
            ac.abort(new Error('refresh deadline'))
            return pending
        })
        const p = prober({ fetch })
        await p.enrichSubset(fleet(), null)
        aborting = true
        const ops = fleet()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]), ac.signal)
        expect(ops[0]!.lastRefreshAt).toBeUndefined()
        expect([T, R2, R3].map((r) => p.recallReachable(r))).toEqual([true, true, true])
        expect([R2, R3].map((r) => p.relayReputation.standing(r).failures)).toEqual([0, 0])
    })

    it("settles a claim the target is down as unheard when the caller aborts before another relay answers", async () => {
        const ac = new AbortController()
        const claimers: string[] = []
        const { fetch } = network((c, signal) => {
            if (claimers.length === 0) {
                claimers.push(c.to)
                return relayError(502, RelayErrorCode.UpstreamUnreachable)
            }
            const pending = hang(signal)
            ac.abort(new Error('refresh deadline'))
            return pending
        })
        const p = prober({ fetch })
        for (const r of [R2, R3]) p.relayReputation.recordRelayOutcome(r, false)
        const ops = fleet()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]), ac.signal)
        // Judged against our view of a target never seen up, the lone claim
        // credits its relay. Read as refuted by a relay that got through, it
        // would have been a strike.
        const claimer = claimers[0] === host(R2) ? R2 : R3
        const other = claimer === R2 ? R3 : R2
        expect(p.relayReputation.standing(claimer).failures).toBe(0)
        expect(p.relayReputation.standing(other).failures).toBe(1)
        expect(ops[0]!.lastRefreshAt).toBeUndefined()
        expect(ops[0]!.probed).toBeUndefined()
    })

    it("names the relay a target's own failure came through", async () => {
        const { fetch } = network(() => json(500, {}))
        const { logger, lines } = recordingLogger()
        const p = prober({ fetch, logger })
        await p.enrichSubset([node(T), node(R2)], new Set([nodeRefString(T)]))
        expect(lines.find((l) => l.msg === 'operator details probe failed')?.attrs).toMatchObject({
            operator_id: T.op,
            relay_operator_id: R2.op,
            relay_node_id: R2.node,
        })
    })

    it('stamps a node with no eligible relay even when the caller has already aborted', async () => {
        const { fetch, calls } = network(() => details())
        const p = prober({ fetch })
        const op = node(T, { reachable: true })
        await p.enrichSubset([op], null, AbortSignal.abort(new Error('refresh deadline')))
        expect(calls).toHaveLength(0)
        expect(op).toMatchObject({ reachable: true, lastRefreshAt: NOW_MS })
    })

    it('names the relay that claimed the target down when it gives up', async () => {
        const { fetch, calls } = network(() => relayError(502, RelayErrorCode.UpstreamUnreachable))
        const { logger, lines } = recordingLogger()
        const p = prober({ fetch, logger })
        await p.enrichSubset(fleet(), new Set([nodeRefString(T)]))
        const last = calls.at(-1)!.to === host(R2) ? R2 : R3
        expect(calls).toHaveLength(2)
        expect(lines.find((l) => l.msg === 'operator details probe failed')?.attrs).toMatchObject({
            relay_operator_id: last.op,
            relay_node_id: last.node,
        })
    })

    it('reprobes through a relay drawn from the pool it is handed', async () => {
        const { fetch, calls } = network(() => details({ ...FRESH.advertisement }))
        const p = prober({ fetch })
        const target = node(T)
        const got = await p.reprobeEphemeral([target, node(R2)], target)
        expect(calls).toEqual([{ to: host(R2), target: host(T), path: '/v1/zs/details', relayed: true }])
        expect(got.ephemeralRecipient).toBe(FRESH.advertisement.ephemeral_age_pubkey)
        // A pool with no other node leaves nothing to relay through.
        calls.length = 0
        const alone = await p.reprobeEphemeral([target], target)
        expect(calls).toHaveLength(0)
        expect(alone.lastRefreshAt).toBe(NOW_MS)
        expect(alone.ephemeralRecipient).toBeUndefined()
        expect(target.lastRefreshAt).toBeUndefined()
    })

    it('records to a reputation store the host supplies', async () => {
        const { fetch } = network(() => {
            throw new TypeError('connection refused')
        })
        let src: ChainOperatorSource | undefined
        const shared = new RelayReputationStore({ clock: () => NOW_MS, targetReachable: (t) => src!.recallReachable(t) })
        src = new ChainOperatorSource({ algod: {} as never, escrowAppId: 1n, fetch, clock: () => NOW_MS, relayReputation: shared })
        expect(src.relayReputation).toBe(shared)
        await src.enrichSubset([node(T), node(R2)], new Set([nodeRefString(T)]))
        expect(shared.standing(R2).failures).toBe(1)
    })
})

describe('NodeProber ephemeral', () => {
    const pair = () => [node(T), node(R2)]

    it('sets a verified recipient and clears a relay staleness streak', async () => {
        const { fetch } = network(() => details({ ...FRESH.advertisement }))
        const p = prober({ fetch })
        p.relayReputation.recordRelayStaleEphemeral(R2)
        const ops = pair()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(ops[0]).toMatchObject({
            ephemeralRecipient: FRESH.advertisement.ephemeral_age_pubkey,
            ephemeralExpiry: FRESH.advertisement.ephemeral_expiry,
            ephemeralIssuedAt: FRESH.advertisement.ephemeral_issued_at,
        })
        expect(p.relayReputation.standing(R2).stale).toBe(0)
    })

    it('charges the relay that carried a stale block, which still seals', async () => {
        const { fetch } = network(() => details({ ...STALE.advertisement }))
        const p = prober({ fetch })
        const ops = pair()
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(ops[0]!.ephemeralRecipient).toBe(STALE.advertisement.ephemeral_age_pubkey)
        expect(p.relayReputation.standing(R2).stale).toBe(1)
    })

    it('charges nobody for a stale block fetched directly', async () => {
        const { fetch } = network(() => details({ ...STALE.advertisement }))
        const p = prober({ fetch, privacy: 'direct' })
        const op = node(T)
        await p.enrichSubset([op], null)
        expect(op.ephemeralRecipient).toBe(STALE.advertisement.ephemeral_age_pubkey)
    })

    it('leaves no seal target, and warns, on a block that fails verification', async () => {
        const { fetch } = network(() => details({ ...FORGED.advertisement }))
        const { logger, lines } = recordingLogger()
        const p = prober({ fetch, privacy: 'direct', logger })
        const op = node(T, { ephemeralRecipient: 'age1old', ephemeralExpiry: 2_000_000_000, ephemeralIssuedAt: 1 })
        await p.enrichSubset([op], null)
        expect(op).toMatchObject({ ephemeralRecipient: undefined, ephemeralExpiry: 0, ephemeralIssuedAt: 0, reachable: true })
        expect(lines.find((l) => l.level === 'warn')?.msg).toMatch(/failed verification/)
    })

    it('drops a carried recipient when the node advertises none', async () => {
        const { fetch } = network(() => details())
        const p = prober({ fetch, privacy: 'direct' })
        const op = node(T, { ephemeralRecipient: 'age1old', ephemeralExpiry: 2_000_000_000 })
        await p.enrichSubset([op], null)
        expect(op.ephemeralRecipient).toBeUndefined()
        expect(op.ephemeralExpiry).toBe(0)
    })
})

describe('NodeProber attestation', () => {
    const BUNDLE = '{"mode":"dstack-tdx","generated_at":"2026-10-01T00:00:00Z"}'
    const PASS: Verdict = {
        pass: true,
        failureTag: '',
        verifierId: 'dstack-tdx',
        attestedAt: 5,
        detail: { measurementChecks: { osImage: true, composeRelease: true, composeHash: false } },
    }
    const verifier = (verdict: Verdict = PASS): Verifier & { nodes: unknown[] } => {
        const nodes: unknown[] = []
        return {
            nodes,
            verify: async (_a, _b, n) => {
                nodes.push(n)
                return verdict
            },
        }
    }
    const answer = (c: Call): Response => (c.path === '/v1/zs/attestation' ? new Response(BUNDLE) : details({ tee: { mode: 'dstack-tdx' }, ...FRESH.advertisement }))

    it('verifies through the hop the details probe succeeded through, against the verified recipient', async () => {
        const { fetch, calls } = network(answer)
        const v = verifier()
        const p = prober({ fetch, teeVerifier: v })
        const ops = [node(T), node(R2)]
        await p.enrichSubset(ops, new Set([nodeRefString(T)]))
        expect(calls).toEqual([
            { to: host(R2), target: host(T), path: '/v1/zs/details', relayed: true },
            { to: host(R2), target: host(T), path: '/v1/zs/attestation', relayed: true },
        ])
        expect(v.nodes).toEqual([{ operatorId: 42n, nodeId: 7n, ephemeralRecipientPubkey: FRESH.advertisement.ephemeral_age_pubkey }])
        expect(ops[0]!.tee).toMatchObject({
            mode: 'dstack-tdx',
            verified: true,
            attestedAt: 5,
            osImageChecked: true,
            composeReleaseChecked: true,
            detail: PASS.detail,
        })
    })

    it('fetches no evidence without a verifier, and clears a carried verdict', async () => {
        const { fetch, calls } = network(answer)
        const p = prober({ fetch, privacy: 'direct' })
        const op = node(T, { tee: { ...TEE } })
        await p.enrichSubset([op], null)
        expect(calls.map((c) => c.path)).toEqual(['/v1/zs/details'])
        expect(op.tee).toBeUndefined()
    })

    it('fetches no evidence from a node advertising no TEE', async () => {
        const { fetch, calls } = network(() => details())
        const p = prober({ fetch, privacy: 'direct', teeVerifier: verifier() })
        const op = node(T, { tee: { ...TEE } })
        await p.enrichSubset([op], null)
        expect(calls.map((c) => c.path)).toEqual(['/v1/zs/details'])
        expect(op.tee).toBeUndefined()
    })

    it('keeps a node whose evidence failed routable, with the failure recorded', async () => {
        const { fetch } = network((c) => (c.path === '/v1/zs/attestation' ? json(500, {}) : answer(c)))
        const p = prober({ fetch, privacy: 'direct', teeVerifier: verifier() })
        const op = node(T)
        await p.enrichSubset([op], null)
        expect(op.reachable).toBe(true)
        expect(op.tee).toMatchObject({ verified: false, failureTag: 'fetch_failed' })
    })

    it('records fetch_failed when the caller aborts the attestation probe, as the registry keeps the cycle', async () => {
        const ac = new AbortController()
        const { fetch } = network((c) => {
            if (c.path !== '/v1/zs/attestation') return answer(c)
            const pending = hang(ac.signal)
            ac.abort(new Error('refresh deadline'))
            return pending
        })
        const { logger, lines } = recordingLogger()
        const p = prober({ fetch, privacy: 'direct', teeVerifier: verifier(), logger })
        const op = node(T, { tee: { ...TEE } })
        await p.enrichSubset([op], null, ac.signal)
        expect(op.reachable).toBe(true)
        expect(op.tee).toEqual({
            mode: 'dstack-tdx',
            attestedAt: 0,
            verifierId: 'builtin',
            verified: false,
            failureTag: 'fetch_failed',
            osImageChecked: false,
            composeReleaseChecked: false,
        })
        expect(lines.some((l) => l.msg === 'operator attestation probe failed')).toBe(true)
    })

    it('records fetch_failed when the caller aborts mid-verification', async () => {
        const ac = new AbortController()
        const { fetch } = network(answer)
        const aborting: Verifier = {
            verify: async () => {
                ac.abort(new Error('refresh deadline'))
                return PASS
            },
        }
        const p = prober({ fetch, privacy: 'direct', teeVerifier: aborting })
        const op = node(T)
        await p.enrichSubset([op], null, ac.signal)
        expect(op.tee).toMatchObject({ verified: false, failureTag: 'fetch_failed' })
    })

    it('leaves no verdict, with a warning, when a verifier throws', async () => {
        const { fetch } = network(answer)
        const { logger, lines } = recordingLogger()
        const broken: Verifier = {
            verify: async () => {
                throw new Error('verifier bug')
            },
        }
        const p = prober({ fetch, privacy: 'direct', teeVerifier: broken, logger })
        const op = node(T, { tee: { ...TEE } })
        await p.enrichSubset([op], null)
        expect(op.reachable).toBe(true)
        expect(op.tee).toBeUndefined()
        expect(lines.some((l) => l.msg === 'operator attestation probe threw')).toBe(true)
    })
})

describe('NodeProber host ports', () => {
    it("drops a logger's throw, so the node is still applied in full", async () => {
        const { fetch } = network(() => details({ ...FORGED.advertisement }))
        const throwing: Logger = {
            debug: () => {},
            info: () => {},
            warn: () => {
                throw new Error('logger down')
            },
            error: () => {},
        }
        const p = prober({ fetch, privacy: 'direct', logger: throwing })
        const op = node(T)
        await p.enrichSubset([op], null)
        expect(op).toMatchObject({ reachable: true, models: ['fresh-model'], ephemeralRecipient: undefined })
        expect(p.recallReachable(T)).toBe(true)
    })

    it("keeps one node's throwing store from rejecting the cycle or stopping the others", async () => {
        const { fetch } = network(() => details({ ...FRESH.advertisement }))
        const { logger, lines } = recordingLogger()
        let src: NodeProber | undefined
        class ThrowingReputation extends RelayReputationStore {
            override recordRelayFreshEphemeral(): void {
                throw new Error('store down')
            }
        }
        const rep = new ThrowingReputation({ clock: () => NOW_MS, targetReachable: (t) => src!.recallReachable(t) })
        src = prober({ fetch, relayReputation: rep, logger })
        // T's block verifies, so its relay's staleness is recorded and throws;
        // R2's does not, signed as it is for T.
        const ops = [node(T), node(R2)]
        await src.enrichSubset(ops, null)
        expect(ops[1]!.reachable).toBe(true)
        expect(lines.find((l) => l.msg === 'operator details probe threw')?.attrs).toMatchObject({ operator_id: T.op })
    })
})
