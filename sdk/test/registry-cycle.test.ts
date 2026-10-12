/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { getEventListeners } from 'node:events'
import { readFileSync } from 'node:fs'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { defaults } from '../src/config.js'
import { type Operator, modelCapacityOf } from '../src/operator.js'
import { type LogAttrs, type Logger, type StorageAdapter, memoryStorage } from '../src/ports.js'
import { CATALOG_STORAGE_KEY, decodeCatalog, marshalCatalog } from '../src/registry/persist.js'
import {
    DiscoveryRegistry,
    type DiscoveryRegistryOptions,
    type OperatorSource,
    type RegistrySnapshot,
    STORAGE_TIMEOUT_MS,
    advertisable,
    carryForwardLastGood,
    mergeCatalog,
    seedFromCatalog,
} from '../src/registry/registry.js'
import { nodeRefString } from '../src/types.js'
import { testOperator } from './fixtures.js'

// ---- the cycle vectors ----

interface CycleOp {
    id: number
    node_id: number
    reachable: boolean
    probed: boolean
    reachable_as_of_ms: number
    last_refresh_at_ms: number
    staging: boolean
    signer_spendable_microalgos: number | null
    models: string[]
    context_windows: Record<string, number>
    builtin_tools: string[]
    max_tool_iters: number
    tool_headroom_per_iteration: number
    proto_version: string
}

const cycleVectors = JSON.parse(readFileSync(new URL('../../testdata/registry_cycle_vectors.json', import.meta.url), 'utf8')) as {
    carry: { name: string; now_ms: number; max_carry_age_ms: number; prev: CycleOp[] | null; ops: CycleOp[]; want: CycleOp[] }[]
    advertisable: { name: string; now_ms: number; max_carry_age_ms: number; allow_staging: boolean; op: CycleOp; want: boolean }[]
    merge: { name: string; now_ms: number; max_carry_age_ms: number; saved_catalog: string; fresh: CycleOp[]; want: CycleOp[] }[]
    seed: { name: string; now_ms: number; max_carry_age_ms: number; saved_catalog: string; want: CycleOp[] }[]
}

// Go's zero values arrive as unset fields, as a fresh chain row has them.
function operatorOf(c: CycleOp): Operator {
    const caps: Operator['modelCapacities'] = {}
    for (const [m, w] of Object.entries(c.context_windows)) {
        caps[m] = modelCapacityOf({ id: m, input_rate_usd_per_1m: 0, output_rate_usd_per_1m: 0, context_window: w })
    }
    const op = testOperator({
        id: c.id,
        nodeId: c.node_id,
        reachable: c.reachable,
        staging: c.staging,
        models: [...c.models],
        modelCapacities: caps,
        builtinTools: c.builtin_tools.map((type) => ({ type })),
        maxToolIters: c.max_tool_iters,
        toolHeadroomPerIteration: c.tool_headroom_per_iteration,
        protoVersion: c.proto_version,
    })
    if (c.probed) op.probed = true
    if (c.reachable_as_of_ms !== 0) op.reachableAsOf = c.reachable_as_of_ms
    if (c.last_refresh_at_ms !== 0) op.lastRefreshAt = c.last_refresh_at_ms
    if (c.signer_spendable_microalgos !== null) op.signerSpendableMicroAlgos = c.signer_spendable_microalgos
    return op
}

function cycleOpOf(op: Operator): CycleOp {
    return {
        id: op.id,
        node_id: op.nodeId,
        reachable: op.reachable,
        probed: op.probed === true,
        reachable_as_of_ms: op.reachableAsOf ?? 0,
        last_refresh_at_ms: op.lastRefreshAt ?? 0,
        staging: op.staging,
        signer_spendable_microalgos: op.signerSpendableMicroAlgos ?? null,
        models: [...op.models],
        context_windows: Object.fromEntries(Object.entries(op.modelCapacities).map(([m, c]) => [m, c.contextWindow])),
        builtin_tools: op.builtinTools.map((t) => t.type),
        max_tool_iters: op.maxToolIters,
        tool_headroom_per_iteration: op.toolHeadroomPerIteration,
        proto_version: op.protoVersion,
    }
}

describe('registry_cycle vectors', () => {
    it('agree with the SDK on the defaults they assume', () => {
        expect(cycleVectors.carry[0]!.max_carry_age_ms).toBe(defaults.discovery.maxCarryAge)
    })

    it.each(cycleVectors.carry.map((c) => [c.name, c] as const))('carry: %s', (_, c) => {
        const prev = c.prev === null ? undefined : new Map(c.prev.map((p) => [nodeRefString({ op: p.id, node: p.node_id }), operatorOf(p)]))
        const ops = c.ops.map(operatorOf)
        carryForwardLastGood(prev, ops, c.now_ms, c.max_carry_age_ms)
        expect(ops.map(cycleOpOf)).toEqual(c.want)
    })

    it.each(cycleVectors.advertisable.map((c) => [c.name, c] as const))('advertisable: %s', (_, c) => {
        expect(advertisable(operatorOf(c.op), c.now_ms, c.allow_staging, c.max_carry_age_ms)).toBe(c.want)
    })

    it.each(cycleVectors.merge.map((c) => [c.name, c] as const))('merge: %s', (_, c) => {
        const fresh = c.fresh.map(operatorOf)
        const merged = mergeCatalog(decodeCatalog(c.saved_catalog), fresh, c.max_carry_age_ms, c.now_ms)
        expect(merged.map(cycleOpOf)).toEqual(c.want)
        // The fresh rows are copied, as Go's append copies the values.
        expect(fresh.map(cycleOpOf)).toEqual(c.fresh)
    })

    it.each(cycleVectors.seed.map((c) => [c.name, c] as const))('seed: %s', (_, c) => {
        const saved = decodeCatalog(c.saved_catalog)
        const before = saved.map(cycleOpOf)
        expect(seedFromCatalog(saved, c.max_carry_age_ms, c.now_ms).map(cycleOpOf)).toEqual(c.want)
        expect(saved.map(cycleOpOf)).toEqual(before)
    })
})

// ---- the registry, against a fake source ----

const T0 = 1_800_000_000_000
const MIN = 60_000

interface Advert {
    models: string[]
    tools?: string[]
    protoVersion?: string
}

/**
 * A fleet on chain and what each node answers its probe with: an advert, or
 * 'down' for a target-side failure. A node with no answer is not reached.
 */
class FakeSource implements OperatorSource {
    chain: Operator[] | Error = []
    /** Read before chain, one per call. */
    next: (Operator[] | Error)[] = []
    answers = new Map<string, Advert | 'down'>()
    fetchCalls = 0
    probeSets: (string[] | null)[] = []
    /** Holds fetchChain, then enrichSubset, until released. */
    holdFetch: Promise<void> | undefined
    holdProbe: Promise<void> | undefined
    fetchSignals: AbortSignal[] = []

    constructor(private readonly clock: () => number) {}

    async fetchChain(signal?: AbortSignal): Promise<Operator[]> {
        this.fetchCalls++
        if (signal) this.fetchSignals.push(signal)
        if (this.holdFetch) {
            await Promise.race([this.holdFetch, aborted(signal)])
        }
        signal?.throwIfAborted()
        const chain = this.next.shift() ?? this.chain
        if (chain instanceof Error) throw chain
        return chain.map((op) => ({ ...op, metrics: { ...op.metrics } }))
    }

    async enrichSubset(ops: Operator[], probeSet: ReadonlySet<string> | null, signal?: AbortSignal): Promise<void> {
        this.probeSets.push(probeSet === null ? null : [...probeSet].sort())
        if (this.holdProbe) await Promise.race([this.holdProbe, aborted(signal)])
        for (const op of ops) {
            const key = nodeRefString({ op: op.id, node: op.nodeId })
            if (probeSet !== null && !probeSet.has(key)) continue
            // A probe the deadline cut short learned nothing.
            if (signal?.aborted) continue
            const a = this.answers.get(key)
            if (a === undefined) continue
            op.probed = true
            op.lastRefreshAt = this.clock()
            if (a === 'down') {
                op.reachable = false
                continue
            }
            op.reachable = true
            op.reachableAsOf = this.clock()
            op.models = [...a.models]
            op.modelCapacities = Object.fromEntries(
                a.models.map((m) => [m, modelCapacityOf({ id: m, input_rate_usd_per_1m: 0, output_rate_usd_per_1m: 0, context_window: 8192 })]),
            )
            op.builtinTools = (a.tools ?? []).map((type) => ({ type }))
            op.protoVersion = a.protoVersion ?? PROTO_VERSION
        }
    }
}

function aborted(signal: AbortSignal | undefined): Promise<void> {
    return new Promise((resolve) => {
        if (signal?.aborted) resolve()
        signal?.addEventListener('abort', () => resolve(), { once: true })
    })
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
    let resolve!: () => void
    const promise = new Promise<void>((r) => (resolve = r))
    return { promise, resolve }
}

function row(id: number, nodeId = 1, over: Partial<Operator> = {}): Operator {
    return testOperator({ id, nodeId, reachable: false, ownerAddr: `OWNER${id}`, signingAddr: `SIGNER${id}`, ...over })
}

function recordingLogger() {
    const lines: { level: string; msg: string; attrs: LogAttrs | undefined }[] = []
    const at =
        (level: string) =>
        (msg: string, attrs?: LogAttrs): void => {
            lines.push({ level, msg, attrs })
        }
    const logger: Logger = { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') }
    return { logger, lines, msgs: () => lines.map((l) => l.msg) }
}

function countingStorage(inner: StorageAdapter = memoryStorage()) {
    const writes: string[] = []
    const storage: StorageAdapter = {
        get: (k) => inner.get(k),
        set: (k, v) => {
            writes.push(v)
            return inner.set(k, v)
        },
        delete: (k) => inner.delete(k),
    }
    return { storage, writes, inner }
}

// Lets every queued promise callback run.
async function settle(): Promise<void> {
    for (let i = 0; i < 20; i++) await Promise.resolve()
    await new Promise((r) => setImmediate(r))
}

describe('DiscoveryRegistry', () => {
    let now: number
    let source: FakeSource
    const clock = () => now
    const registries: DiscoveryRegistry[] = []

    beforeEach(() => {
        now = T0
        source = new FakeSource(clock)
    })
    afterEach(async () => {
        await Promise.all(registries.splice(0).map((r) => r.stop()))
        vi.useRealTimers()
    })

    function registry(over: Partial<DiscoveryRegistryOptions> = {}): DiscoveryRegistry {
        const r = new DiscoveryRegistry({ source, clock, ...over })
        registries.push(r)
        return r
    }

    describe('boot', () => {
        it('seeds from the saved catalog and one chain read, then probes every node in the background', async () => {
            const saved = row(1, 1, {
                models: ['m'],
                modelCapacities: { m: modelCapacityOf({ id: 'm', input_rate_usd_per_1m: 0, output_rate_usd_per_1m: 0, context_window: 4096 }) },
                protoVersion: '9.11',
                reachableAsOf: T0 - 10 * MIN,
            })
            const storage = memoryStorage()
            await storage.set(CATALOG_STORAGE_KEY, marshalCatalog([saved]))
            source.chain = [row(1), row(2)]
            source.answers.set('1/1', { models: ['m', 'fresh'] })
            source.answers.set('2/1', { models: ['n'] })
            const probe = deferred()
            source.holdProbe = probe.promise
            const reg = registry({ storage })

            await reg.ready
            const seed = reg.snapshot()!
            expect(seed.operators.map((op) => [op.id, op.models, op.protoVersion, op.reachable])).toEqual([
                [1, ['m'], '9.0', false],
                [2, [], '', false],
            ])
            expect(source.fetchCalls).toBe(1)

            let served: Operator[] | undefined
            const read = reg.operators('fresh').then((ops) => (served = ops))
            await settle()
            expect(served).toBeUndefined()
            probe.resolve()
            await read
            expect(served!.map((op) => op.id)).toEqual([1])
            // The first cycle probes the whole fleet, on boot's chain read.
            expect(source.probeSets).toEqual([null])
            expect(source.fetchCalls).toBe(1)
        })

        it('starts without a saved catalog it cannot read, and overwrites it', async () => {
            const { storage, writes, inner } = countingStorage()
            await inner.set(CATALOG_STORAGE_KEY, '{"version":1,"operators":[{"id":1')
            source.chain = [row(1)]
            const log = recordingLogger()
            const reg = registry({ storage, logger: log.logger })
            await reg.ready
            expect(log.msgs()).toContain('failed to load persisted operator catalog; starting without it')
            expect(writes.length).toBeGreaterThan(0)
            expect(decodeCatalog((await inner.get(CATALOG_STORAGE_KEY))!).map((op) => op.id)).toEqual([1])
        })

        it('serves the saved catalog alone when the chain read fails, and retries on a stale read', async () => {
            const storage = memoryStorage()
            const aged = row(2, 1, { models: ['old'], reachableAsOf: T0 - 2 * defaults.discovery.maxCarryAge })
            await storage.set(CATALOG_STORAGE_KEY, marshalCatalog([row(1, 1, { models: ['m'], reachableAsOf: T0 - MIN }), aged]))
            source.next = [new Error('algod down')]
            source.chain = [row(1), row(3)]
            source.answers.set('3/1', { models: ['x'] })
            const log = recordingLogger()
            const reg = registry({ storage, logger: log.logger })
            await reg.ready
            expect(log.lines.find((l) => l.msg.startsWith('initial operator fetch failed'))?.attrs).toEqual({
                err: 'algod down',
                persisted: 2,
            })
            // No first cycle to wait for: the seed is served as Go serves it,
            // each node's models only within the carry window.
            expect((await reg.operators('m')).map((op) => [op.id, op.models])).toEqual([[1, ['m']]])
            expect(await reg.operators('old')).toEqual([])
            const seeded = reg.snapshot()!.operators.find((op) => op.id === 2)!
            expect([seeded.baseUrl, seeded.models, seeded.reachableAsOf]).toEqual([aged.baseUrl, [], undefined])
            expect(await reg.operators('x')).toEqual([])
            expect(source.fetchCalls).toBe(1)
            expect(source.probeSets).toEqual([])

            now += defaults.discovery.maxCacheAge
            expect((await reg.operators('x')).map((op) => op.id)).toEqual([3])
            // Node 1 went unanswered and keeps its saved models.
            expect((await reg.operators('m')).map((op) => op.id)).toEqual([1])
            expect(source.fetchCalls).toBe(2)
        })

        it('refreshes on the next read when stop cut the first cycle short', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const probe = deferred()
            source.holdProbe = probe.promise
            const reg = registry()
            await reg.ready
            await settle()
            await reg.stop()
            // Published, as a cycle cut short is, with nothing probed.
            expect(reg.snapshot()!.operators.map((op) => [op.id, op.models])).toEqual([[1, []]])
            expect(reg.snapshot()!.fetchedAt).toBe(now)

            source.holdProbe = undefined
            expect((await reg.operators('m')).map((op) => op.id)).toEqual([1])
            expect(source.fetchCalls).toBe(2)
            // That read's cycle ran to its end, so the next one is free.
            await reg.operators('m')
            expect(source.fetchCalls).toBe(2)
        })

        it('has nothing to serve until a chain read succeeds', async () => {
            source.chain = new Error('algod down')
            const reg = registry()
            await reg.ready
            expect(reg.snapshot()).toBeUndefined()
            await expect(reg.operators('m')).rejects.toThrow('operator registry uninitialised')
            expect(await reg.resolve({ op: 1, node: 1 })).toBeUndefined()
            expect(await reg.allOperators()).toEqual([])
        })

        it('fails, as Go fails New, when the only fleet it has is invalid', async () => {
            const storage = memoryStorage()
            await storage.set(CATALOG_STORAGE_KEY, marshalCatalog([row(1), row(1)]))
            source.chain = new Error('algod down')
            const reg = registry({ storage })
            await expect(reg.ready).rejects.toThrow('duplicate node 1/1')
            await expect(reg.operators('m')).rejects.toThrow('duplicate node 1/1')
        })
    })

    describe('ensureFresh', () => {
        it('shares one refresh among concurrent stale reads', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry({ discovery: { maxCacheAge: 5 * MIN } })
            await reg.operators('m')
            expect(source.fetchCalls).toBe(1)

            now += 4 * MIN
            await Promise.all([reg.operators('m'), reg.allOperators()])
            expect(source.fetchCalls).toBe(1)

            now += 2 * MIN
            const reads = await Promise.all([
                reg.operators('m'),
                reg.operators('m'),
                reg.resolve({ op: 1, node: 1 }),
                reg.allOperators(),
                reg.allModels(),
            ])
            expect(source.fetchCalls).toBe(2)
            expect(reads[0].map((op) => op.id)).toEqual([1])
            expect(reg.snapshot()!.fetchedAt).toBe(now)
        })

        it('keeps the previous snapshot when the chain read fails', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const reg = registry({ logger: log.logger })
            await reg.operators('m')
            const before = reg.snapshot()

            source.chain = new Error('algod down')
            now += defaults.discovery.maxCacheAge
            expect((await reg.operators('m')).map((op) => op.id)).toEqual([1])
            expect(reg.snapshot()).toBe(before)
            const warn = log.lines.find((l) => l.msg === 'operator refresh failed; keeping previous snapshot')
            expect(warn?.attrs).toEqual({ err: 'algod down', have_snapshot: true })
        })

        it('keeps the previous snapshot when the reader aborts the chain read', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry()
            await reg.operators('m')
            const before = reg.snapshot()

            now += defaults.discovery.maxCacheAge
            const hold = deferred()
            source.holdFetch = hold.promise
            const ac = new AbortController()
            const read = reg.operators('m', ac.signal)
            await settle()
            ac.abort(new Error('caller gave up'))
            await expect(read).rejects.toThrow('caller gave up')
            expect(reg.snapshot()).toBe(before)
            source.holdFetch = undefined
            expect((await reg.operators('m')).map((op) => op.id)).toEqual([1])
            expect(reg.snapshot()!.fetchedAt).toBe(now)
        })

        it('rejects an aborted read on a cold start, and the first cycle runs on for the others', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const probe = deferred()
            source.holdProbe = probe.promise
            const reg = registry()
            const other = reg.operators('m')

            const ac = new AbortController()
            const read = reg.operators('m', ac.signal)
            await settle()
            ac.abort(new Error('caller gave up'))
            await expect(read).rejects.toThrow('caller gave up')
            await expect(reg.allOperators(AbortSignal.abort(new Error('already gone')))).rejects.toThrow('already gone')

            probe.resolve()
            expect((await other).map((op) => op.id)).toEqual([1])
            expect(source.probeSets).toEqual([null])
            expect(source.fetchCalls).toBe(1)
        })

        it('lets a reader waiting on another reader\'s refresh give up, and keeps the queue in order', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry()
            await reg.operators('m')

            now += defaults.discovery.maxCacheAge
            const hold = deferred()
            source.holdFetch = hold.promise
            // Settled between them, so each is queued behind the one before.
            const first = reg.operators('m')
            await settle()
            const ac = new AbortController()
            const quitter = reg.operators('m', ac.signal)
            await settle()
            const third = reg.operators('m')
            await settle()
            expect(source.fetchCalls).toBe(2)
            ac.abort(new Error('caller gave up'))
            await expect(quitter).rejects.toThrow('caller gave up')

            let thirdDone = false
            void third.then(() => (thirdDone = true))
            await settle()
            expect(thirdDone).toBe(false)
            expect(source.fetchCalls).toBe(2)
            hold.resolve()
            expect((await first).map((op) => op.id)).toEqual([1])
            expect((await third).map((op) => op.id)).toEqual([1])
            // The third found the first one's refresh fresh behind the lock.
            expect(source.fetchCalls).toBe(2)
        })

        it('publishes a cycle cut short during the probes, the nodes it missed carried', async () => {
            source.chain = [row(1), row(2)]
            source.answers.set('1/1', { models: ['m'] })
            source.answers.set('2/1', { models: ['n'] })
            const reg = registry()
            await reg.operators('m')
            const asOf = reg.snapshot()!.operators.map((op) => op.reachableAsOf)

            now += defaults.discovery.maxCacheAge
            const hold = deferred()
            source.holdProbe = hold.promise
            const ac = new AbortController()
            const read = reg.allOperators(ac.signal)
            await settle()
            ac.abort(new Error('caller gave up'))
            await expect(read).rejects.toThrow('caller gave up')
            const ops = reg.snapshot()!.operators
            expect(reg.snapshot()!.fetchedAt).toBe(now)
            expect(ops.map((op) => [op.id, op.reachable, op.probed, op.models, op.reachableAsOf])).toEqual([
                [1, false, undefined, ['m'], asOf[0]],
                [2, false, undefined, ['n'], asOf[1]],
            ])
        })
    })

    describe('abort signals', () => {
        it('hands the chain read an aborted signal when stop came first', async () => {
            source.chain = [row(1)]
            // A load to wait on, so the chain read starts after stop.
            const reg = registry({ storage: memoryStorage() })
            void reg.stop()
            await reg.ready
            expect(source.fetchSignals).toHaveLength(1)
            expect(source.fetchSignals[0]!.aborted).toBe(true)
        })

        it('leaves no listener on a reader\'s signal, whether its waits resolve or reject', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry()
            const ac = new AbortController()
            for (let i = 0; i < 3; i++) {
                await reg.operators('m', ac.signal)
                now += defaults.discovery.maxCacheAge
            }
            expect(source.fetchCalls).toBe(3)
            expect(getEventListeners(ac.signal, 'abort')).toHaveLength(0)

            const storage = memoryStorage()
            await storage.set(CATALOG_STORAGE_KEY, marshalCatalog([row(1), row(1)]))
            source.chain = new Error('algod down')
            const broken = registry({ storage })
            for (let i = 0; i < 3; i++) await expect(broken.operators('m', ac.signal)).rejects.toThrow('duplicate node 1/1')
            expect(getEventListeners(ac.signal, 'abort')).toHaveLength(0)
        })

        it('unlinks from the signal start was given on stop', async () => {
            source.chain = [row(1)]
            const reg = registry()
            await reg.ready
            const ac = new AbortController()
            reg.start(ac.signal)
            expect(getEventListeners(ac.signal, 'abort')).toHaveLength(1)
            await reg.stop()
            expect(getEventListeners(ac.signal, 'abort')).toHaveLength(0)
        })
    })

    describe('the timer', () => {
        beforeEach(() => {
            vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'setTimeout', 'clearTimeout'] })
        })

        it('refreshes every refreshInterval after start, and never after stop', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry({ discovery: { refreshInterval: MIN } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(5 * MIN)
            expect(source.fetchCalls).toBe(1)

            reg.start()
            reg.start()
            await vi.advanceTimersByTimeAsync(MIN)
            expect(source.fetchCalls).toBe(2)
            await vi.advanceTimersByTimeAsync(2 * MIN)
            expect(source.fetchCalls).toBe(4)

            await reg.stop()
            await vi.advanceTimersByTimeAsync(10 * MIN)
            expect(source.fetchCalls).toBe(4)
            reg.start()
            await vi.advanceTimersByTimeAsync(10 * MIN)
            expect(source.fetchCalls).toBe(4)
        })

        it('aborts the refresh in flight on stop and waits for it', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry({ discovery: { refreshInterval: MIN } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            reg.start()
            source.holdFetch = new Promise(() => {})
            await vi.advanceTimersByTimeAsync(MIN)
            expect(source.fetchCalls).toBe(2)
            const signal = source.fetchSignals.at(-1)!
            expect(signal.aborted).toBe(false)
            await reg.stop()
            expect(signal.aborted).toBe(true)
        })

        it('stops when the signal start was given aborts', async () => {
            source.chain = [row(1)]
            const reg = registry({ discovery: { refreshInterval: MIN } })
            await reg.ready
            const ac = new AbortController()
            reg.start(ac.signal)
            await vi.advanceTimersByTimeAsync(MIN)
            const calls = source.fetchCalls
            ac.abort()
            await vi.advanceTimersByTimeAsync(5 * MIN)
            expect(source.fetchCalls).toBe(calls)
        })

        it('never starts on a signal that has already aborted', async () => {
            source.chain = [row(1)]
            const reg = registry({ discovery: { refreshInterval: MIN } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            reg.start(AbortSignal.abort())
            await vi.advanceTimersByTimeAsync(5 * MIN)
            expect(source.fetchCalls).toBe(1)
        })

        it('skips a tick while the previous tick is still refreshing', async () => {
            source.chain = [row(1)]
            const reg = registry({ discovery: { refreshInterval: MIN, refreshTimeout: 10 * MIN } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            reg.start()
            const hold = deferred()
            source.holdFetch = hold.promise
            await vi.advanceTimersByTimeAsync(3 * MIN)
            expect(source.fetchCalls).toBe(2)
            hold.resolve()
            source.holdFetch = undefined
            await vi.advanceTimersByTimeAsync(MIN)
            expect(source.fetchCalls).toBe(3)
        })

        it('bounds a cycle by refreshTimeout', async () => {
            source.chain = [row(1)]
            const log = recordingLogger()
            const reg = registry({ logger: log.logger, discovery: { refreshTimeout: 1_000 } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            source.holdFetch = new Promise(() => {})
            now += defaults.discovery.maxCacheAge
            const read = reg.allOperators()
            await vi.advanceTimersByTimeAsync(1_000)
            expect((await read).map((op) => op.id)).toEqual([1])
            expect(log.lines.find((l) => l.msg === 'operator refresh failed; keeping previous snapshot')?.attrs?.err).toBe(
                'deadline of 1000 ms exceeded',
            )
        })

        it('caps an interval or timeout past setTimeout\'s limit rather than firing it at once', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const reg = registry({ logger: log.logger, discovery: { refreshInterval: 2 ** 31, refreshTimeout: 2 ** 31 } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            reg.start()
            // Short, since an uncapped interval would fire every millisecond.
            await vi.advanceTimersByTimeAsync(100)
            expect(source.fetchCalls).toBe(1)

            const hold = deferred()
            source.holdFetch = hold.promise
            now += defaults.discovery.maxCacheAge
            const read = reg.allOperators()
            await vi.advanceTimersByTimeAsync(10 * MIN)
            hold.resolve()
            await read
            expect(log.msgs()).not.toContain('operator refresh failed; keeping previous snapshot')
            expect(reg.snapshot()!.fetchedAt).toBe(now)
        })

        it('logs why stop cut a cycle short', async () => {
            source.chain = [row(1)]
            const log = recordingLogger()
            const reg = registry({ logger: log.logger, discovery: { refreshInterval: MIN } })
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            reg.start()
            source.holdFetch = new Promise(() => {})
            await vi.advanceTimersByTimeAsync(MIN)
            await reg.stop()
            expect(log.lines.find((l) => l.msg === 'operator refresh failed; keeping previous snapshot')?.attrs).toEqual({
                err: 'discovery registry stopped',
                have_snapshot: true,
            })
        })

        it('leaves no deadline timer behind a finished cycle', async () => {
            source.chain = [row(1)]
            const reg = registry()
            await reg.ready
            await vi.advanceTimersByTimeAsync(0)
            expect(vi.getTimerCount()).toBe(0)
            reg.start()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            // Only the refresh interval.
            expect(vi.getTimerCount()).toBe(1)
        })

        it('stops at once during a saved-catalog load that never answers', async () => {
            const storage: StorageAdapter = { ...memoryStorage(), get: () => new Promise(() => {}) }
            const reg = registry({ storage })
            let stopped = false
            void reg.stop().then(() => (stopped = true))
            await vi.advanceTimersByTimeAsync(STORAGE_TIMEOUT_MS - 1)
            const early = stopped
            // Past the load's own deadline, so a stop that waited for it still
            // finishes before afterEach stops the registry again.
            await vi.advanceTimersByTimeAsync(1)
            expect(early).toBe(true)
        })

        it('boots without a saved catalog whose load never answers', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const storage: StorageAdapter = { ...memoryStorage(), get: () => new Promise(() => {}) }
            const reg = registry({ storage, logger: log.logger })
            let booted = false
            void reg.ready.then(() => (booted = true))
            await vi.advanceTimersByTimeAsync(STORAGE_TIMEOUT_MS - 1)
            expect(booted).toBe(false)
            await vi.advanceTimersByTimeAsync(1)
            expect(booted).toBe(true)
            expect(log.lines.find((l) => l.msg === 'failed to load persisted operator catalog; starting without it')?.attrs).toEqual({
                err: `deadline of ${STORAGE_TIMEOUT_MS} ms exceeded`,
                key: CATALOG_STORAGE_KEY,
            })
            expect((await reg.operators('m')).map((op) => op.id)).toEqual([1])
        })

        it('neither ready nor stop waits past the deadline on a save that never answers', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const sets: string[] = []
            const storage: StorageAdapter = {
                ...memoryStorage(),
                set: (_k, v) => {
                    sets.push(v)
                    return new Promise(() => {})
                },
            }
            const reg = registry({ storage, logger: log.logger })
            await vi.advanceTimersByTimeAsync(STORAGE_TIMEOUT_MS)
            await reg.ready
            let stopped = false
            void reg.stop().then(() => (stopped = true))
            await vi.advanceTimersByTimeAsync(STORAGE_TIMEOUT_MS)
            expect(stopped).toBe(true)
            const fails = log.lines.filter((l) => l.msg === 'failed to persist operator catalog')
            expect(fails.map((l) => l.attrs)).toEqual([
                { err: `deadline of ${STORAGE_TIMEOUT_MS} ms exceeded`, key: CATALOG_STORAGE_KEY },
                { err: `deadline of ${STORAGE_TIMEOUT_MS} ms exceeded`, key: CATALOG_STORAGE_KEY },
            ])
            // Boot's save and the first cycle's: an abandoned save is tried again.
            expect(sets).toHaveLength(2)
        })
    })

    describe('bounded probing', () => {
        it('probes the demanded model’s fastest servers first, then sweeps', async () => {
            // Nodes 7, 8 and 9 serve hot; 9 is the fastest of them, then 8.
            const latency: Record<number, number> = { 7: 900, 8: 300, 9: 100 }
            source.chain = Array.from({ length: 10 }, (_, i) =>
                row(i + 1, 1, { metrics: { latencyEwmaMs: latency[i + 1] ?? 0, tokensPerSecEwma: 0 } }),
            )
            for (let i = 1; i <= 10; i++) source.answers.set(`${i}/1`, { models: i >= 7 ? ['hot'] : ['cold'] })
            const reg = registry({ discovery: { probeBudget: 4, targetTopK: 2 } })
            await reg.allOperators()
            expect(source.probeSets).toEqual([null])

            reg.recordModelDemand('hot')
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(source.probeSets.slice(1)).toEqual([
                ['1/1', '2/1', '8/1', '9/1'],
                ['3/1', '4/1', '8/1', '9/1'],
            ])
            // A node outside the probe set keeps what it last advertised.
            expect((await reg.operators('cold')).map((op) => op.id)).toEqual([1, 2, 3, 4, 5, 6])
        })

        // Fails if the registry stops handing selectProbeSet each row's last
        // attempt and answer, or picks the set before the carry: every row
        // would then look unknown, and the set would be the plain sweep's.
        it('probes a node new on chain ahead of the sweep, but not one tried and down', async () => {
            source.chain = Array.from({ length: 20 }, (_, i) => row(i + 1))
            for (let i = 1; i <= 20; i++) source.answers.set(`${i}/1`, i === 15 ? 'down' : { models: ['m'] })
            const reg = registry({ discovery: { probeBudget: 4 } })
            await reg.allOperators()
            expect(source.probeSets).toEqual([null])

            source.chain = [...source.chain, row(21)]
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(source.probeSets[1]).toEqual(['1/1', '2/1', '21/1', '3/1'])
        })

        it('probes every node of a fleet within the budget', async () => {
            source.chain = [row(2), row(1)]
            const reg = registry({ discovery: { probeBudget: 4 } })
            await reg.allOperators()
            now += defaults.discovery.maxCacheAge
            reg.recordModelDemand('m')
            await reg.allOperators()
            expect(source.probeSets).toEqual([null, null])
            // Sorted by (operator, node), whatever order the chain read returned.
            expect(reg.snapshot()!.operators.map((op) => op.id)).toEqual([1, 2])
        })

        it('reads a fractional budget under one as the default, not as no bound', async () => {
            const budget = defaults.discovery.probeBudget
            source.chain = Array.from({ length: budget + 1 }, (_, i) => row(i + 1))
            const reg = registry({ discovery: { probeBudget: 0.5, targetTopK: 0.5 } })
            await reg.allOperators()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(source.probeSets[1]).toHaveLength(budget)
        })
    })

    describe('transition logs', () => {
        it('names a tool swapped for another, the count unchanged', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'], tools: ['a'] })
            const log = recordingLogger()
            const reg = registry({ logger: log.logger })
            await reg.allOperators()
            source.answers.set('1/1', { models: ['m'], tools: ['b'] })
            now += defaults.discovery.maxCacheAge
            log.lines.length = 0
            await reg.allOperators()
            expect(log.lines.map((l) => [l.msg, l.attrs])).toEqual([
                ['node builtin tools changed', { operator_id: 1, node_id: 1, from_count: 1, to_count: 1 }],
            ])
        })

        it('names each node added, removed, changed or newly underfunded', async () => {
            const floor = 5_000_000
            source.chain = [row(1), row(2), row(3), row(4, 1, { signerSpendableMicroAlgos: floor })]
            source.answers.set('1/1', { models: ['m'] })
            source.answers.set('2/1', { models: ['m'] })
            source.answers.set('3/1', { models: ['m'], tools: ['zs_web_search'] })
            source.answers.set('4/1', { models: ['m'] })
            const log = recordingLogger()
            const reg = registry({ logger: log.logger })
            await reg.allOperators()
            expect(log.lines.filter((l) => l.msg.startsWith('node '))).toEqual([])
            expect(log.lines.find((l) => l.msg === 'operator registry refreshed')?.attrs).toEqual({ count: 4, reachable: 4 })

            source.chain = [row(1), row(3), row(4, 1, { signerSpendableMicroAlgos: floor - 1 }), row(5)]
            source.answers.set('1/1', 'down')
            source.answers.set('3/1', { models: ['m', 'n'], tools: [] })
            source.answers.set('5/1', { models: ['m'] })
            now += defaults.discovery.maxCacheAge
            log.lines.length = 0
            await reg.allOperators()
            expect(log.lines.map((l) => [l.level, l.msg, l.attrs])).toEqual([
                ['info', 'node reachability changed', { operator_id: 1, node_id: 1, from: true, to: false }],
                ['info', 'node model list changed', { operator_id: 3, node_id: 1, from_count: 1, to_count: 2 }],
                ['info', 'node builtin tools changed', { operator_id: 3, node_id: 1, from_count: 1, to_count: 0 }],
                [
                    'warn',
                    'node signing account is below the routing floor; not routing to it until topped up',
                    { operator_id: 4, node_id: 1, signing_addr: 'SIGNER4', signer_spendable_microalgos: floor - 1, floor_microalgos: floor },
                ],
                ['info', 'node added', { operator_id: 5, node_id: 1, base_url: 'https://node.example.com', reachable: true }],
                ['info', 'node removed', { operator_id: 2, node_id: 1, base_url: 'https://node.example.com' }],
            ])

            source.chain = [row(1), row(3), row(4, 1, { signerSpendableMicroAlgos: floor }), row(5)]
            now += defaults.discovery.maxCacheAge
            log.lines.length = 0
            await reg.allOperators()
            expect(log.lines.filter((l) => l.msg.includes('signing account'))).toEqual([
                {
                    level: 'info',
                    msg: 'node signing account topped up; routing to it again',
                    attrs: { operator_id: 4, node_id: 1, signing_addr: 'SIGNER4', signer_spendable_microalgos: floor },
                },
            ])

            source.chain = [row(1), row(3), row(4, 1, { signerSpendableMicroAlgos: 0 }), row(5)]
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            source.chain = [row(1), row(3), row(4), row(5)]
            now += defaults.discovery.maxCacheAge
            log.lines.length = 0
            await reg.allOperators()
            expect(log.lines.filter((l) => l.msg.includes('signing account')).map((l) => l.msg)).toEqual([
                'node signing account balance is unknown (signer changed); routing to it again',
            ])
        })

        it('summarises the first cycle rather than diff it against the seed, and names a node broke from the start once', async () => {
            source.chain = [row(1), row(2, 1, { signerSpendableMicroAlgos: 0 })]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const reg = registry({ logger: log.logger })
            await reg.allOperators()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(log.lines.map((l) => [l.msg, l.attrs])).toEqual([
                ['operators loaded', { count: 2 }],
                ['operator registry refreshed', { count: 2, reachable: 1 }],
                [
                    'node signing account is below the routing floor; not routing to it until topped up',
                    { operator_id: 2, node_id: 1, signing_addr: 'SIGNER2', signer_spendable_microalgos: 0, floor_microalgos: 5_000_000 },
                ],
            ])
        })
    })

    describe('persistence', () => {
        it('saves each cycle that changed the catalog, and only those', async () => {
            const { storage, writes, inner } = countingStorage()
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry({ storage })
            await reg.allOperators()
            // The seed, then the first probe.
            expect(writes).toHaveLength(2)

            // Nothing reached: every node carried as it was.
            source.answers.clear()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(writes).toHaveLength(2)

            source.answers.set('1/1', { models: ['m', 'n'] })
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(writes).toHaveLength(3)
            expect(decodeCatalog((await inner.get(CATALOG_STORAGE_KEY))!)[0]!.models).toEqual(['m', 'n'])
        })

        it('retries a failed save on the next cycle', async () => {
            const inner = memoryStorage()
            let fail = true
            const storage: StorageAdapter = {
                ...inner,
                set: (k, v) => (fail ? Promise.reject(new Error('quota exceeded')) : inner.set(k, v)),
            }
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const reg = registry({ storage, storageKey: 'zs.catalog.testnet', logger: log.logger })
            await reg.allOperators()
            expect(log.lines.find((l) => l.msg === 'failed to persist operator catalog')?.attrs).toEqual({
                err: 'quota exceeded',
                key: 'zs.catalog.testnet',
            })

            fail = false
            source.answers.clear()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(decodeCatalog((await inner.get('zs.catalog.testnet'))!)[0]!.models).toEqual(['m'])
        })
    })

    describe('subscribe', () => {
        it('hands each published cycle to every subscriber, past one that throws', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const log = recordingLogger()
            const reg = registry({ logger: log.logger })
            const seen: RegistrySnapshot[] = []
            reg.subscribe(() => {
                throw new Error('subscriber bug')
            })
            const off = reg.subscribe((s) => seen.push(s))
            await reg.allOperators()
            expect(seen).toHaveLength(2)
            expect(seen[0]!.operators[0]!.reachable).toBe(false)
            expect(seen[1]).toBe(reg.snapshot())
            expect(seen[1]!.operators[0]!.reachable).toBe(true)
            expect(log.msgs().filter((m) => m === 'discovery registry subscriber threw')).toHaveLength(2)

            off()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(seen).toHaveLength(2)
        })

        it('publishes nothing for a failed cycle', async () => {
            source.chain = [row(1)]
            const reg = registry()
            await reg.allOperators()
            const seen: RegistrySnapshot[] = []
            reg.subscribe((s) => seen.push(s))
            source.chain = new Error('algod down')
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(seen).toEqual([])
        })

        it('keeps each registration of the same function to itself', async () => {
            source.chain = [row(1)]
            const reg = registry()
            await reg.allOperators()
            let calls = 0
            const fn = () => void calls++
            const off = reg.subscribe(fn)
            reg.subscribe(fn)
            off()
            now += defaults.discovery.maxCacheAge
            await reg.allOperators()
            expect(calls).toBe(1)
        })
    })

    describe('reads', () => {
        it('hands out copies, and a frozen snapshot', async () => {
            source.chain = [row(1)]
            source.answers.set('1/1', { models: ['m'] })
            const reg = registry()
            const [op] = await reg.operators('m')
            op!.reachable = false
            expect((await reg.resolve({ op: 1, node: 1 }))!.reachable).toBe(true)
            const snap = reg.snapshot()!
            expect(Object.isFrozen(snap.operators)).toBe(true)
            expect(Object.isFrozen(snap.operators[0])).toBe(true)
        })

        it('lists only what it can route to on the aggregates, and every node to the relay pool', async () => {
            source.chain = [row(1), row(2, 1, { staging: true }), row(3)]
            source.answers.set('1/1', { models: ['m'], tools: ['zs_web_search'] })
            source.answers.set('2/1', { models: ['staged'], tools: ['zs_web_read'] })
            source.answers.set('3/1', { models: ['old'], protoVersion: '1.0' })
            const reg = registry()
            expect(await reg.allModels()).toEqual(['m'])
            expect(await reg.allBuiltinTools()).toEqual([{ type: 'zs_web_search' }])
            expect((await reg.allModelDetails()).map((d) => d.id)).toEqual(['m'])
            expect((await reg.allOperators()).map((op) => op.id)).toEqual([1, 2, 3])
            expect((await reg.operators('staged')).map((op) => op.id)).toEqual([2])

            const staging = registry({ allowStaging: true })
            expect(await staging.allModels()).toEqual(['m', 'staged'])
            expect((await staging.allModelDetails()).map((d) => d.id)).toEqual(['m', 'staged'])
        })

        it('reprobes through the source when it can, and re-checks the node as it is when not', async () => {
            const expiry = Math.floor(T0 / 1000) + 600
            const sealable = row(1, 1, { ephemeralRecipient: 'age1x', ephemeralExpiry: expiry })
            const noSource: OperatorSource = { fetchChain: async () => [row(1)], enrichSubset: async () => {} }
            const plain = registry({ source: noSource })
            expect(await plain.reprobeEphemeral(sealable)).toBe(sealable)
            expect(await plain.reprobeEphemeral(row(1))).toBeNull()

            const seen: { all: readonly Operator[]; target: Operator }[] = []
            const reprobing: OperatorSource = {
                ...noSource,
                reprobeEphemeral: async (all, target) => {
                    seen.push({ all, target })
                    return { ...target, ephemeralRecipient: 'age1y', ephemeralExpiry: expiry }
                },
            }
            const live = registry({ source: reprobing })
            await live.ready
            const got = await live.reprobeEphemeral(row(1))
            expect(got?.ephemeralRecipient).toBe('age1y')
            expect(seen[0]!.all.map((op) => op.id)).toEqual([1])
            now = expiry * 1000
            expect(await live.reprobeEphemeral(row(1))).toBeNull()
        })
    })
})
