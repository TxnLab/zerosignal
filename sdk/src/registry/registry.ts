/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The discovery registry: a snapshot of the fleet that a timer and stale reads
// refresh, each cycle reading the chain, carrying last-known capabilities onto
// the nodes it does not reach, and probing a bounded set. Mirrors go/zs
// registry_dynamic.go (DynamicRegistryProvider), the boot in assemble.go
// (bootRegistry) and MergeCatalog in persist.go. carryWithin, advertisable and
// a saved catalog merged at boot are pinned by
// testdata/registry_cycle_vectors.json, the probe set by probe_set_vectors.json;
// the timer, the coalescing and the logging are tested per language.
//
// Differences from Go:
//   - Boot. Go's blocks on the chain read and a probe of every node, both
//     under one 60 s bound. Here `ready` settles once the saved catalog and the
//     chain read have, and the first cycle, a probe of every node under a
//     fresh 60 s bound, runs in the background on boot's chain rows; every
//     read waits for it, since a read before it would find no node it can
//     seal to. So a read can wait for the chain read and the probe one after
//     the other, up to twice Go's bound. When boot's chain read fails there
//     is no first cycle: as in Go, the saved catalog (or nothing) is served
//     and the timer or a stale read retries. The first cycle logs as Go's
//     first snapshot does, a summary and each broke signer, not a line per
//     node against boot's unprobed seed; boot's own summary has no reachable
//     count, since nothing is probed yet.
//   - No unbounded fallback. Go falls back to its source's Fetch when the
//     source cannot split the chain read from the probes; an OperatorSource
//     here always can.
//   - maxCacheAge 0 is unset, as for every Discovery setting, where Go reads
//     it as "every read is stale". The injected clock is what a test uses
//     instead. refreshInterval and refreshTimeout are capped at MAX_TIMER_MS,
//     and probeBudget and targetTopK are floored before a value under one
//     falls back to its default.
//   - A read whose signal aborts rejects with its reason, also while it waits
//     for boot, the first cycle or another reader's refresh; what it waited
//     on runs on for the others. Go's read waits out the refresh mutex
//     whatever its context, and returns the snapshot a cancelled refresh left.
//   - Each StorageAdapter call is bounded by STORAGE_TIMEOUT_MS, so a stalled
//     adapter holds neither ready nor stop: a load that has not answered is
//     logged and boot starts without a saved catalog, and a save that has not
//     is logged and tried again on the next cycle. Go's file I/O is unbounded.
//   - The carry window, the cache age and the seal check run on the injected
//     clock, not the wall clock.
//   - A timer tick that finds the previous tick's refresh still waiting or
//     running is skipped. Go's ticker keeps one tick queued behind it.
//   - stop() also aborts boot's chain read and the first cycle, which Go's
//     boot has finished before Stop exists. A first cycle cut short that way
//     is published, as any cycle cut short is, but until a cycle runs to its
//     end or its deadline neither it nor boot's seed counts as fresh, so the
//     next read refreshes rather than serve an unprobed fleet for maxCacheAge.
//     start takes an AbortSignal for Go's context.
//   - Snapshot operators are frozen; reads hand out shallow copies, as Go
//     hands out values. resolve answers undefined where Go returns
//     ErrOperatorUnknown, and reprobeEphemeral null where Go returns false.
//   - A list, map or tool list carryCaps finds empty counts as unset: TS has
//     no nil. The rows carried onto are fresh chain rows, whose lists Go also
//     leaves nil.
//   - The node's build id is neither carried nor persisted, since Operator has
//     none, so there is no allNodeVersions.
//   - persist compares the catalog text with the last one written rather than
//     a sha256 of it, and writes to a StorageAdapter key, not a file.
//   - A logger or subscriber that throws is caught.

import type { OperatorDetailsModel } from '@txnlab/zs-proto/inject'
import { MIN_SIGNER_SPENDABLE_LAMPORTS, MIN_SIGNER_SPENDABLE_MICROALGOS, signerReadingsUnderfunded } from '@txnlab/zs-proto/selection'
import { protoVersionCompatible } from '@txnlab/zs-proto/wire'

import { DEFAULT_DEMAND_MAX, ModelDemand, selectProbeSet } from '../catalog/probe.js'
import { answeredWithin } from '../catalog/reachability.js'
import { type Discovery, defaults } from '../config.js'
import { quietLogger } from '../log.js'
import { type BuiltinToolDef, type Operator, refOf, sealRecipientOf } from '../operator.js'
import type { RegistryProvider } from '../parts.js'
import { type Clock, type LogAttrs, type Logger, type StorageAdapter, discardLogger } from '../ports.js'
import { MAX_TIMER_MS, untilAborted } from '../sleep.js'
import { type NodeRef, nodeRefString } from '../types.js'
import { aggregateBuiltinTools, aggregateModelDetails, aggregateModels } from './aggregate.js'
import { CATALOG_STORAGE_KEY, loadCatalog, marshalCatalog } from './persist.js'

/**
 * BOOT_FETCH_TIMEOUT_MS bounds boot's chain read, and then the first cycle's
 * probe of every node, as Go's bootFetchTimeout bounds both together.
 */
export const BOOT_FETCH_TIMEOUT_MS = 60_000

/** STORAGE_TIMEOUT_MS bounds each load and save of the catalog. */
export const STORAGE_TIMEOUT_MS = 5_000

/**
 * OperatorSource is what a registry refreshes from. ChainOperatorSource is
 * one. reprobeEphemeral is optional, as Go's ephemeralReprober is: without it
 * reprobeEphemeral re-checks the operator as it is.
 */
export interface OperatorSource {
    /** One Operator per live node, unprobed; throws when the chain read fails. */
    fetchChain(signal?: AbortSignal): Promise<Operator[]>
    /** Probes the nodes of ops whose nodeRefString is in probeSet (all when null) in place, never throwing. */
    enrichSubset(ops: Operator[], probeSet: ReadonlySet<string> | null, signal?: AbortSignal): Promise<void>
    reprobeEphemeral?(all: readonly Operator[], target: Operator, signal?: AbortSignal): Promise<Operator>
}

/** RegistrySnapshot is one published cycle. Neither the list nor its operators may be changed. */
export interface RegistrySnapshot {
    readonly operators: readonly Operator[]
    /** Unix ms when the cycle finished. */
    readonly fetchedAt: number
}

export interface DiscoveryRegistryOptions {
    source: OperatorSource
    /** Where the catalog is saved for a warm restart; absent saves nothing. */
    storage?: StorageAdapter | undefined
    /** CATALOG_STORAGE_KEY when absent. */
    storageKey?: string | undefined
    /**
     * The key the catalog was saved under before: read when storageKey holds
     * nothing, and deleted after the first save under storageKey.
     */
    legacyStorageKey?: string | undefined
    /** Config.discovery; each absent, zero or negative setting takes its default. */
    discovery?: Partial<Discovery> | undefined
    /** Config.allowStaging: lists staging nodes on the discovery aggregates. */
    allowStaging?: boolean | undefined
    logger?: Logger | undefined
    /** Unix ms. */
    clock?: Clock | undefined
}

interface Snapshot {
    view: RegistrySnapshot
    byNode: ReadonlyMap<string, Operator>
}

interface CycleOptions {
    /** Probe every node under BOOT_FETCH_TIMEOUT_MS, as Go's boot does. */
    full?: boolean
    /** Boot's chain rows, so the first cycle need not read the chain again. */
    chainOps?: Operator[] | undefined
}

/**
 * DiscoveryRegistry is Go's DynamicRegistryProvider: a RegistryProvider whose
 * snapshot a timer refreshes every refreshInterval, and any read older than
 * maxCacheAge refreshes first, concurrent reads sharing one refresh. A failed
 * refresh is logged and the previous snapshot kept, so a chain or node outage
 * never reads as an empty fleet. It needs no Client or signer.
 */
export class DiscoveryRegistry implements RegistryProvider {
    /**
     * Settles once boot has loaded the saved catalog and read the chain, and
     * rejects when the fleet boot seeds from (the chain read merged with the
     * saved catalog, or the saved catalog alone when the read failed) holds a
     * duplicate or zero id, as Go's New fails. Reads wait for it.
     */
    readonly ready: Promise<void>

    readonly #source: OperatorSource
    readonly #storage: StorageAdapter | undefined
    readonly #storageKey: string
    // Cleared once a save under #storageKey lands and the legacy entry goes.
    #legacyStorageKey: string | undefined
    readonly #log: Logger
    readonly #clock: Clock
    readonly #refreshInterval: number
    readonly #refreshTimeout: number
    readonly #maxCacheAge: number
    readonly #maxCarryAge: number
    readonly #probeBudget: number
    readonly #targetTopK: number
    readonly #allowStaging: boolean
    readonly #demand = new ModelDemand(DEFAULT_DEMAND_MAX)

    // Touched only by boot, before any cycle, and by a cycle, and cycles are
    // serialized by #lock.
    #sweepCursor = 0
    #catalogText: string | undefined
    // Set while the snapshot is boot's seed or a first cycle that stop cut
    // short: neither has probed the fleet, so neither is fresh.
    #unprobed = false

    #snap: Snapshot | undefined
    #lock: Promise<void> = Promise.resolve()
    #firstCycle: Promise<void> = Promise.resolve()
    readonly #subscribers = new Set<(snap: RegistrySnapshot) => void>()

    #started = false
    #stopped = false
    #stopping: Promise<void> | undefined
    #timer: ReturnType<typeof setInterval> | undefined
    #tickBusy = false
    #unlinkStart: () => void = () => {}
    readonly #lifetime = new AbortController()
    readonly #background = new Set<Promise<void>>()

    constructor(o: DiscoveryRegistryOptions) {
        const d = o.discovery ?? {}
        const dd = defaults.discovery
        this.#source = o.source
        this.#storage = o.storage
        this.#storageKey = o.storageKey || CATALOG_STORAGE_KEY
        this.#legacyStorageKey = o.legacyStorageKey && o.legacyStorageKey !== this.#storageKey ? o.legacyStorageKey : undefined
        this.#log = quietLogger(o.logger ?? discardLogger)
        this.#clock = o.clock ?? Date.now
        this.#refreshInterval = timerMs(d.refreshInterval, dd.refreshInterval)
        this.#refreshTimeout = timerMs(d.refreshTimeout, dd.refreshTimeout)
        this.#maxCacheAge = positiveOr(d.maxCacheAge, dd.maxCacheAge)
        this.#maxCarryAge = positiveOr(d.maxCarryAge, dd.maxCarryAge)
        this.#probeBudget = wholeOr(d.probeBudget, dd.probeBudget)
        this.#targetTopK = wholeOr(d.targetTopK, dd.targetTopK)
        this.#allowStaging = o.allowStaging ?? false
        this.ready = this.#boot()
        // A host that never awaits ready still sees the failure on every read.
        this.ready.catch(() => {})
    }

    // ---- lifecycle ----

    /**
     * start runs a refresh every refreshInterval until stop, or until signal
     * aborts. A second call, or one after stop, does nothing.
     */
    start(signal?: AbortSignal): void {
        if (this.#started || this.#stopped) return
        this.#started = true
        this.#timer = setInterval(() => this.#tick(), this.#refreshInterval)
        // A registry left running must not keep a Node process alive.
        ;(this.#timer as { unref?: () => void }).unref?.()
        if (signal === undefined) return
        if (signal.aborted) {
            void this.stop()
            return
        }
        const onAbort = () => void this.stop()
        signal.addEventListener('abort', onAbort, { once: true })
        this.#unlinkStart = () => signal.removeEventListener('abort', onAbort)
    }

    /**
     * stop ends the timer, aborts the refresh it or boot started, and resolves
     * once they have finished. Reads still refresh a stale snapshot on their
     * own, as in Go. Repeat calls share the first one's wait.
     */
    stop(): Promise<void> {
        if (this.#stopping !== undefined) return this.#stopping
        this.#stopped = true
        this.#unlinkStart()
        if (this.#timer !== undefined) clearInterval(this.#timer)
        this.#lifetime.abort(new Error('discovery registry stopped'))
        this.#stopping = (async () => {
            await this.ready.catch(() => {})
            await Promise.all([...this.#background])
        })()
        return this.#stopping
    }

    #tick(): void {
        if (this.#tickBusy || this.#stopped) return
        this.#tickBusy = true
        this.#track(
            (async () => {
                try {
                    await this.ready
                } catch {
                    return
                }
                await this.#refresh(this.#lifetime.signal, {})
            })().finally(() => {
                this.#tickBusy = false
            }),
        )
    }

    #track(p: Promise<void>): Promise<void> {
        this.#background.add(p)
        void p.finally(() => this.#background.delete(p))
        return p
    }

    async #boot(): Promise<void> {
        let saved: Operator[] | undefined
        const storage = this.#storage
        if (storage !== undefined) {
            try {
                const ops = await withDeadline(STORAGE_TIMEOUT_MS, this.#lifetime.signal, (s) =>
                    untilAborted(
                        (async () => {
                            const cur = await loadCatalog(storage, this.#storageKey)
                            const legacy = this.#legacyStorageKey
                            return cur !== undefined || legacy === undefined ? cur : loadCatalog(storage, legacy)
                        })(),
                        s,
                    ),
                )
                if (ops !== undefined && ops.length > 0) {
                    saved = ops
                    this.#log.info('loaded persisted operator catalog', { count: saved.length })
                }
            } catch (err) {
                this.#log.warn('failed to load persisted operator catalog; starting without it', {
                    err: message(err),
                    key: this.#storageKey,
                })
            }
        }

        let ops: Operator[] | undefined
        let chainOps: Operator[] | undefined
        try {
            chainOps = await withDeadline(BOOT_FETCH_TIMEOUT_MS, this.#lifetime.signal, (s) => this.#source.fetchChain(s))
            // Nodes the first probe does not reach keep their saved
            // capabilities, and a subscriber can render the fleet before it.
            ops = saved === undefined ? chainOps : mergeCatalog(saved, chainOps, this.#maxCarryAge, this.#clock())
        } catch (err) {
            this.#log.warn('initial operator fetch failed — seeding from persisted catalog (empty if none); background refresh will retry', {
                err: message(err),
                persisted: saved?.length ?? 0,
            })
            ops = saved === undefined ? undefined : seedFromCatalog(saved, this.#maxCarryAge, this.#clock())
        }
        this.#log.info('operators loaded', { count: ops?.length ?? 0 })

        if (ops !== undefined) {
            const snap = buildSnapshot(ops, this.#clock())
            this.#snap = snap
            this.#publish(snap)
            // Saved now, not a cycle from now, so a fast restart is covered.
            // Without a chain read the seed is the catalog just loaded, less
            // what has aged out: nothing new to save, and a stop or a caller's
            // abort is not held up by the write. Go saves it, dropping the
            // aged-out nodes' capabilities from the file; keeping them here
            // only helps a later boot with a longer window.
            if (chainOps !== undefined) await this.#persist(snap.view.operators)
        }
        // Go's boot probe. Without a chain read there is nothing to probe, and
        // Go serves what boot seeded rather than retry inside the same wait.
        if (chainOps !== undefined) {
            this.#unprobed = true
            if (!this.#stopped) {
                this.#firstCycle = this.#track(this.#refresh(this.#lifetime.signal, { full: true, chainOps }))
            }
        }
    }

    // ---- refresh ----

    // Serializes cycles: a caller waits for the one ahead of it, then runs fn.
    // A caller whose signal aborts while it waits leaves the queue, and the
    // one behind it still waits for the one ahead.
    async #withLock(fn: () => Promise<void>, signal?: AbortSignal): Promise<void> {
        const ahead = this.#lock
        let release!: () => void
        this.#lock = new Promise((r) => (release = r))
        try {
            await untilAborted(ahead, signal)
        } catch (err) {
            void ahead.then(release)
            throw err
        }
        try {
            await fn()
        } finally {
            release()
        }
    }

    #refresh(signal: AbortSignal | undefined, opts: CycleOptions): Promise<void> {
        return this.#withLock(() => this.#refreshLocked(signal, opts))
    }

    #fresh(): boolean {
        return !this.#unprobed && this.#snap !== undefined && this.#clock() - this.#snap.view.fetchedAt < this.#maxCacheAge
    }

    // Every read path's lazy refresh: free while the snapshot is younger than
    // maxCacheAge, else one cycle, which concurrent callers share by waiting
    // on the lock and finding the snapshot fresh behind it. A reader that
    // gives up stops waiting; boot and the first cycle run on for the rest.
    async #ensureFresh(signal?: AbortSignal): Promise<void> {
        await untilAborted(this.ready, signal)
        await untilAborted(this.#firstCycle, signal)
        if (this.#fresh()) return
        await this.#withLock(async () => {
            if (this.#fresh()) return
            await this.#refreshLocked(signal, {})
        }, signal)
        // Its own refresh, cut short by the abort, was still published.
        signal?.throwIfAborted()
    }

    // One cycle under the lock: fetch and probe, then swap the snapshot. A
    // failure keeps the previous one. Never throws.
    async #refreshLocked(signal: AbortSignal | undefined, opts: CycleOptions): Promise<void> {
        const prev = this.#snap
        let next: Snapshot
        try {
            const ops = await withDeadline(opts.full ? BOOT_FETCH_TIMEOUT_MS : this.#refreshTimeout, signal, (s) =>
                this.#fetchAndProbe(s, prev, opts),
            )
            try {
                next = buildSnapshot(ops, this.#clock())
            } catch (err) {
                this.#log.warn('operator refresh produced invalid snapshot; keeping previous', { err: message(err) })
                return
            }
        } catch (err) {
            this.#log.warn('operator refresh failed; keeping previous snapshot', { err: message(err), have_snapshot: prev !== undefined })
            return
        }
        // The first cycle is Go's boot probe, which nothing came before: diffed
        // against boot's unprobed seed it would log every node as changed.
        // Logged as a first snapshot, it names each broke signer once, and the
        // cycles after it diff against it, so a node broke at boot that stays
        // broke never transitions and is named now or never.
        this.#logTransitions(opts.full ? undefined : prev, next)
        this.#snap = next
        // A deadline is the cycle's own end; a stop or a reader's abort is not.
        if (!signal?.aborted) this.#unprobed = false
        this.#publish(next)
        await this.#persist(next.view.operators)
    }

    // The split cycle: read the chain, sort it so the sweep cursor advances
    // over a stable order, carry last-known capabilities onto every row before
    // probing (all are unreachable yet, so all are candidates), then probe the
    // chosen subset. A probe the deadline cuts short leaves its node as
    // carried, and the cycle is still published, as in Go.
    async #fetchAndProbe(signal: AbortSignal, prev: Snapshot | undefined, opts: CycleOptions): Promise<Operator[]> {
        const ops = opts.chainOps?.map((op) => ({ ...op })) ?? (await this.#source.fetchChain(signal))
        ops.sort((a, b) => a.id - b.id || a.nodeId - b.nodeId)
        carryForwardLastGood(prev?.byNode, ops, this.#clock(), this.#maxCarryAge)
        const probeSet = opts.full ? null : this.#selectProbeSet(ops)
        await this.#source.enrichSubset(ops, probeSet, signal)
        if (probeSet !== null) {
            this.#log.debug('bounded operator probe', { fleet: ops.length, probed: probeSet.size, budget: this.#probeBudget })
        }
        return ops
    }

    // Go's selectProbeSet: the bounded probe set, advancing the sweep cursor.
    #selectProbeSet(ops: readonly Operator[]): Set<string> | null {
        const nodes = ops.map((op) => ({
            op: op.id,
            node: op.nodeId,
            ttftEwmaMs: op.metrics.latencyEwmaMs,
            tokensPerSecEwma: op.metrics.tokensPerSecEwma,
            models: op.models,
            lastRefreshAt: op.lastRefreshAt,
            reachableAsOf: op.reachableAsOf,
        }))
        const { probe, cursor } = selectProbeSet(nodes, this.#demand.snapshot(), this.#probeBudget, this.#targetTopK, this.#sweepCursor)
        this.#sweepCursor = cursor
        return probe === null ? null : new Set(probe.map((n) => nodeRefString({ op: n.op, node: n.node })))
    }

    // Best effort: a failed save is logged and only costs a colder next start.
    async #persist(ops: readonly Operator[]): Promise<void> {
        if (this.#storage === undefined) return
        let text: string
        try {
            text = marshalCatalog(ops)
        } catch (err) {
            this.#log.warn('failed to marshal operator catalog', { err: message(err) })
            return
        }
        // Every successful probe moves reachableAsOf, so in practice this
        // skips only a cycle that reached no node.
        if (text === this.#catalogText) return
        const storage = this.#storage
        try {
            // Not bound to stop: the write is already issued, and stop waits
            // at most the deadline for it.
            await withDeadline(STORAGE_TIMEOUT_MS, undefined, (s) => untilAborted(storage.set(this.#storageKey, text), s))
        } catch (err) {
            this.#log.warn('failed to persist operator catalog', { err: message(err), key: this.#storageKey })
            return
        }
        this.#catalogText = text
        const legacy = this.#legacyStorageKey
        if (legacy !== undefined) {
            // Only after the save: until then the legacy entry is the only
            // catalog there is.
            try {
                await withDeadline(STORAGE_TIMEOUT_MS, undefined, (s) => untilAborted(storage.delete(legacy), s))
                this.#legacyStorageKey = undefined
            } catch (err) {
                this.#log.warn('failed to delete the operator catalog saved under its earlier key', { err: message(err), key: legacy })
            }
        }
    }

    #publish(snap: Snapshot): void {
        for (const fn of [...this.#subscribers]) {
            try {
                fn(snap.view)
            } catch (err) {
                this.#log.warn('discovery registry subscriber threw', { err: message(err) })
            }
        }
    }

    // ---- transitions ----

    // One line per change between prev and next: nodes added and removed,
    // reachability, signer funding, and model and tool lists. Quiet when
    // nothing changed, the common case.
    #logTransitions(prev: Snapshot | undefined, next: Snapshot): void {
        const ops = next.view.operators
        if (prev === undefined) {
            this.#log.info('operator registry refreshed', { count: ops.length, reachable: countReachable(ops) })
            this.#logUnderfundedIn(ops)
            return
        }
        for (const op of ops) {
            const old = prev.byNode.get(nodeKey(op))
            if (old === undefined) {
                this.#log.info('node added', { ...nodeAttrs(op), base_url: op.baseUrl, reachable: op.reachable })
                if (signerUnderfunded(op)) this.#logSignerUnderfunded(op)
                continue
            }
            const was = signerUnderfunded(old)
            const is = signerUnderfunded(op)
            if (!was && is) {
                this.#logSignerUnderfunded(op)
            } else if (was && !is && op.signerSpendableMicroAlgos === undefined && op.signerSpendableLamports === undefined) {
                // A rotated signer whose first read failed: nothing says it was
                // funded, only that it is no longer known to be broke.
                this.#log.info('node signing account balance is unknown (signer changed); routing to it again', {
                    ...nodeAttrs(op),
                    signing_addr: op.signingAddr,
                })
            } else if (was && !is) {
                const { spendable } = signerReadingAttrs(op)
                this.#log.info('node signing account topped up; routing to it again', {
                    ...nodeAttrs(op),
                    signing_addr: op.signingAddr,
                    ...spendable,
                })
            }
            if (old.reachable !== op.reachable) {
                this.#log.info('node reachability changed', { ...nodeAttrs(op), from: old.reachable, to: op.reachable })
            }
            if (!sameSet(old.models, op.models)) {
                this.#log.info('node model list changed', { ...nodeAttrs(op), from_count: old.models.length, to_count: op.models.length })
            }
            if (!sameSet(old.builtinTools.map(toolType), op.builtinTools.map(toolType))) {
                this.#log.info('node builtin tools changed', {
                    ...nodeAttrs(op),
                    from_count: old.builtinTools.length,
                    to_count: op.builtinTools.length,
                })
            }
        }
        for (const old of prev.view.operators) {
            if (!next.byNode.has(nodeKey(old))) {
                this.#log.info('node removed', { ...nodeAttrs(old), base_url: old.baseUrl })
            }
        }
    }

    // WARN, not info: it silently takes models out of this payer's catalog, and
    // without it "why did my model vanish" has no answer in the log.
    #logSignerUnderfunded(op: Operator): void {
        const { spendable, floor } = signerReadingAttrs(op)
        this.#log.warn('node signing account is below the routing floor; not routing to it until topped up', {
            ...nodeAttrs(op),
            signing_addr: op.signingAddr,
            ...spendable,
            ...floor,
        })
    }

    #logUnderfundedIn(ops: readonly Operator[]): void {
        for (const op of ops) if (signerUnderfunded(op)) this.#logSignerUnderfunded(op)
    }

    // ---- reads ----

    /** snapshot is the current published cycle, or undefined before boot seeds one. Never refreshes. */
    snapshot(): RegistrySnapshot | undefined {
        return this.#snap?.view
    }

    /**
     * subscribe calls fn with each snapshot published from now on, boot's seed
     * included, and returns the unsubscribe. A throw from fn is logged.
     */
    subscribe(fn: (snap: RegistrySnapshot) => void): () => void {
        const own = (s: RegistrySnapshot) => fn(s)
        this.#subscribers.add(own)
        return () => {
            this.#subscribers.delete(own)
        }
    }

    /**
     * operators lists every node whose catalog serves model, carried
     * capabilities included, for dispatch to choose among. It rejects when
     * there is no snapshot at all, and with signal's reason when it aborts,
     * as every read does.
     */
    async operators(model: string, signal?: AbortSignal): Promise<Operator[]> {
        await this.#ensureFresh(signal)
        const snap = this.#snap
        if (snap === undefined) throw new Error('operator registry uninitialised')
        return snap.view.operators.filter((op) => op.models.includes(model)).map(copy)
    }

    async resolve(ref: NodeRef, signal?: AbortSignal): Promise<Operator | undefined> {
        await this.#ensureFresh(signal)
        const op = this.#snap?.byNode.get(nodeRefString(ref))
        return op === undefined ? undefined : copy(op)
    }

    /**
     * allOperators is every node, staging ones included: a relay forwards
     * bytes and runs no inference, so a staging node is a good hop, and
     * leaving it out would shrink the pool relay diffusion depends on.
     */
    async allOperators(signal?: AbortSignal): Promise<Operator[]> {
        await this.#ensureFresh(signal)
        return this.#snap?.view.operators.map(copy) ?? []
    }

    /** allModels is the models of every advertisable node, first seen first. */
    async allModels(signal?: AbortSignal): Promise<string[]> {
        await this.#ensureFresh(signal)
        return aggregateModels(this.#snap?.view.operators ?? [], this.#advertisableNow())
    }

    /** allBuiltinTools is the built-in tools of every advertisable node, the first definition of each type kept. */
    async allBuiltinTools(signal?: AbortSignal): Promise<BuiltinToolDef[]> {
        await this.#ensureFresh(signal)
        return aggregateBuiltinTools(this.#snap?.view.operators ?? [], this.#advertisableNow())
    }

    /**
     * allModelDetails is the capability union across every advertisable node
     * of each model they serve: the figures /v1/models lists. Rates are the
     * lowest any of them declared; see aggregateModelDetails.
     */
    async allModelDetails(signal?: AbortSignal): Promise<OperatorDetailsModel[]> {
        await this.#ensureFresh(signal)
        return aggregateModelDetails(this.#snap?.view.operators ?? [], this.#advertisableNow())
    }

    // One instant for every node an aggregate judges.
    #advertisableNow(): (op: Operator) => boolean {
        const now = this.#clock()
        return (op) => this.advertisable(op, now)
    }

    /** advertisable is the one gate every discovery aggregate shares; see the exported advertisable. */
    advertisable(op: Operator, nowMs: number): boolean {
        return advertisable(op, nowMs, this.#allowStaging, this.#maxCarryAge)
    }

    /**
     * reprobeEphemeral probes op live, outside the cycle, for a node that just
     * minted a new ephemeral recipient, and returns the refreshed copy if it
     * can now seal. The snapshot is left to the next cycle, so this never
     * races it.
     */
    async reprobeEphemeral(op: Operator, signal?: AbortSignal): Promise<Operator | null> {
        const reprobe = this.#source.reprobeEphemeral
        let refreshed = op
        if (reprobe !== undefined) {
            // Go's reprober answers false on any failure; a source is free to
            // reject, and the caller reads null as "can't seal to it".
            try {
                refreshed = await reprobe.call(this.#source, this.#snap?.view.operators ?? [], op, signal)
            } catch (err) {
                this.#log.debug('ephemeral re-probe failed', { ...nodeAttrs(op), err: err instanceof Error ? err.message : String(err) })
                return null
            }
        }
        try {
            sealRecipientOf(refreshed, this.#clock())
            return refreshed
        } catch {
            return null
        }
    }

    recordModelDemand(model: string): void {
        this.#demand.record(model)
    }
}

// ---- the cycle rules, pinned by registry_cycle_vectors.json ----

/**
 * carryForwardLastGood is Go's carryWithin: each row of ops not confirmed live
 * this cycle takes the capabilities its node had in lastGood (keyed by
 * nodeRefString), when that node's last successful probe is within
 * maxCarryAge of nowMs. That keeps a node routable and advertised across the
 * cycles bounded probing skips it, and lets a node that is really gone age
 * out. Its last probe attempt is carried whatever the window. No lastGood
 * carries nothing.
 */
export function carryForwardLastGood(
    lastGood: ReadonlyMap<string, Operator> | undefined,
    ops: Operator[],
    nowMs: number,
    maxCarryAge: number,
): void {
    if (lastGood === undefined) return
    for (const op of ops) {
        if (op.reachable) continue
        const old = lastGood.get(nodeKey(op))
        if (old === undefined) continue
        // Not a capability, so the window does not gate it: a node tried and
        // never answered, or aged out, was still tried, which is what tells
        // "failing" from "not probed yet" on a cycle that skips the node.
        if (op.lastRefreshAt === undefined) op.lastRefreshAt = old.lastRefreshAt
        // Never confirmed live is nothing worth carrying.
        if (!old.reachableAsOf || nowMs - old.reachableAsOf >= maxCarryAge) continue
        carryCaps(op, old)
    }
}

/** carryCaps fills each of dst's capabilities that is unset from src, and its carry clock. */
export function carryCaps(dst: Operator, src: Operator): void {
    if (!dst.reachableAsOf) dst.reachableAsOf = src.reachableAsOf
    if (dst.models.length === 0) dst.models = src.models
    if (Object.keys(dst.modelCapacities).length === 0) dst.modelCapacities = src.modelCapacities
    if (dst.builtinTools.length === 0) dst.builtinTools = src.builtinTools
    if (dst.maxToolIters === 0) dst.maxToolIters = src.maxToolIters
    if (dst.toolHeadroomPerIteration === 0) dst.toolHeadroomPerIteration = src.toolHeadroomPerIteration
    if (dst.protoVersion === '') dst.protoVersion = src.protoVersion
}

/**
 * mergeCatalog is Go's MergeCatalog: copies of fresh, each one not confirmed
 * live taking its saved capabilities from base within maxCarryAge (zero or
 * negative is the default), so a restart routes to a node before the first
 * probe reaches it. A fresh probe result always wins; a saved node gone from
 * fresh is dropped. base is meant to be a loaded catalog: like the carry, the
 * merge also takes base's lastRefreshAt outside the window, which a saved
 * catalog never holds.
 */
export function mergeCatalog(base: readonly Operator[], fresh: readonly Operator[], maxCarryAge: number, nowMs: number): Operator[] {
    const window = maxCarryAge > 0 ? maxCarryAge : defaults.discovery.maxCarryAge
    const byNode = new Map<string, Operator>()
    for (const op of base) byNode.set(nodeKey(op), op)
    const out = fresh.map((op) => ({ ...op }))
    carryForwardLastGood(byNode, out, nowMs, window)
    return out
}

/**
 * seedFromCatalog is Go's seedFromCatalog: what a boot whose chain read
 * failed seeds the registry with, the saved operators as if a chain read had
 * returned them and no probe had reached any. Each keeps its capabilities
 * only within maxCarryAge, since dispatch reads operators(), which applies no
 * carry window, and would otherwise route to an aged-out node until a chain
 * read succeeds. Past the window a node keeps its identity, and stays in the
 * relay pool at the bootstrap version, as an unprobed chain row does.
 */
export function seedFromCatalog(saved: readonly Operator[], maxCarryAge: number, nowMs: number): Operator[] {
    return mergeCatalog(saved, saved.map(withoutCarriedCaps), maxCarryAge, nowMs)
}

/** op with every capability carryCaps fills left unset. */
function withoutCarriedCaps(op: Operator): Operator {
    const out: Operator = {
        ...op,
        models: [],
        // Null-prototype, as a chain row's is, so a model id never reads an
        // inherited key.
        modelCapacities: Object.create(null) as Operator['modelCapacities'],
        builtinTools: [],
        maxToolIters: 0,
        toolHeadroomPerIteration: 0,
        protoVersion: '',
    }
    delete out.reachableAsOf
    return out
}

/**
 * advertisable reports whether op surfaces on the discovery aggregates. One
 * gate for all of them, holding out what dispatch would refuse: a staging
 * node the payer has not opted in to, a node on another wire major (or none
 * said), and a signer known to be below the routing floor. A node probed this
 * cycle is advertised on that probe's answer; one not probed, while its last
 * success is within maxCarryAge, so bounded probing does not drop a fine node
 * between its probes.
 */
export function advertisable(op: Operator, nowMs: number, allowStaging: boolean, maxCarryAge: number): boolean {
    if ((op.staging && !allowStaging) || !protoVersionCompatible(op.protoVersion) || signerUnderfunded(op)) return false
    return answeredWithin(op, nowMs, maxCarryAge)
}

// ---- helpers ----

function signerUnderfunded(op: Operator): boolean {
    return signerReadingsUnderfunded(op.signerSpendableMicroAlgos, op.signerSpendableLamports)
}

// Names op's signer reading and its floor in its rail's unit, as Go's
// signerReadingAttrs: lamports when op has a lamports reading, else
// microAlgos, 0 when unread.
function signerReadingAttrs(op: Operator): { spendable: LogAttrs; floor: LogAttrs } {
    if (op.signerSpendableLamports !== undefined) {
        return {
            spendable: { signer_spendable_lamports: op.signerSpendableLamports },
            floor: { floor_lamports: MIN_SIGNER_SPENDABLE_LAMPORTS },
        }
    }
    return {
        spendable: { signer_spendable_microalgos: op.signerSpendableMicroAlgos ?? 0 },
        floor: { floor_microalgos: MIN_SIGNER_SPENDABLE_MICROALGOS },
    }
}

function buildSnapshot(ops: readonly Operator[], nowMs: number): Snapshot {
    const byNode = new Map<string, Operator>()
    const frozen: Operator[] = []
    for (const op of ops) {
        if (op.id === 0) throw new Error('operator missing id (0 is reserved)')
        const key = nodeKey(op)
        if (byNode.has(key)) throw new Error(`duplicate node ${key}`)
        const f = Object.freeze({ ...op })
        byNode.set(key, f)
        frozen.push(f)
    }
    return { view: Object.freeze({ operators: Object.freeze(frozen), fetchedAt: nowMs }), byNode }
}

// Runs fn under a signal that aborts at ms or when parent does. A timer of
// our own rather than AbortSignal.timeout, so it is cleared with the call.
async function withDeadline<T>(ms: number, parent: AbortSignal | undefined, fn: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(new DOMException(`deadline of ${ms} ms exceeded`, 'TimeoutError')), ms)
    const onAbort = () => ac.abort(parent?.reason)
    if (parent?.aborted) onAbort()
    else parent?.addEventListener('abort', onAbort, { once: true })
    try {
        return await fn(ac.signal)
    } finally {
        clearTimeout(timer)
        parent?.removeEventListener('abort', onAbort)
    }
}

function nodeKey(op: Operator): string {
    return nodeRefString(refOf(op))
}

function copy(op: Operator): Operator {
    return { ...op }
}

function countReachable(ops: readonly Operator[]): number {
    return ops.filter((op) => op.reachable).length
}

function toolType(t: BuiltinToolDef): string {
    return t.type
}

// Go's stringSlicesEqual: the same elements, order aside.
function sameSet(a: readonly string[], b: readonly string[]): boolean {
    if (a.length !== b.length) return false
    const x = [...a].sort()
    const y = [...b].sort()
    return x.every((v, i) => v === y[i])
}

function nodeAttrs(op: Operator): Record<string, number> {
    return { operator_id: op.id, node_id: op.nodeId }
}

function positiveOr(v: number | undefined, fallback: number): number {
    return v !== undefined && Number.isFinite(v) && v > 0 ? v : fallback
}

// Floored first, as probe.ts floors its concurrency, so a fraction under one
// is the default rather than a budget of 0, which would probe every node.
function wholeOr(v: number | undefined, fallback: number): number {
    return positiveOr(v === undefined ? undefined : Math.floor(v), fallback)
}

// setTimeout fires at once past its limit, which would turn a long interval
// into a busy loop.
function timerMs(v: number | undefined, fallback: number): number {
    return Math.min(positiveOr(v, fallback), MAX_TIMER_MS)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
