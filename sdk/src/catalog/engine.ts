/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The catalog's per-node state: each node's details probes folded into what a
// picker and dispatch may use. The app runs the probes on its own scheduler and
// hands each result over as it lands; the engine keeps the last answer and
// decides, from the latest result and the carry window, what the node reads as.
//
// The rules are the Go SDK registry's (registry_dynamic.go carryForwardLastGood
// and advertisable, fetcher.go probeOne): a node keeps its last-probed
// capabilities for maxCarryAge after its last successful probe, whatever
// happened since, so one bad relay or one failed probe never empties the
// catalog; a probe that reached the node and failed marks it down without
// dropping what it serves; and a probe that learned nothing changes nothing.
//
// Two places read a node more cautiously than Go, which starts every cycle with
// each node unprobed: a node's own failure keeps it 'failing' until it is next
// probed (Go advertises it again from the carry window on a cycle that skips
// it), and no-relay reads as its own state (Go leaves the node as it was). The
// models are carried the same in both; only the reading differs.

import { protoVersionCompatible } from '@txnlab/zs-proto/wire'

import { defaults } from '../config.js'
import type { Clock } from '../ports.js'
import type { Reachability } from './rows.js'

/**
 * One finished details probe.
 * - answered: the node returned a details body.
 * - target-failed: the probe reached the node, or tried it directly, and it
 *   failed: down, an error status, an unreadable body, or every relay that
 *   worked said it was unreachable. Go's probeOne default branch.
 * - unknown: nothing was learned about the node, because every relay hop failed
 *   before reaching it or the probe was cancelled. Go leaves such a node as it
 *   was.
 * - no-relay: privacy mode found no relay to probe through, so it didn't.
 */
export type ProbeObservation<D> =
    | { kind: 'answered'; details: D }
    | { kind: 'target-failed' }
    | { kind: 'unknown' }
    | { kind: 'no-relay' }

/** A node's routing identity: on-chain operator id and node id. */
export interface CatalogNodeRef {
    op: number
    node: number
}

/** What a node reads as now. */
export interface CatalogNodeView<D> {
    reachability: Reachability
    /**
     * The last answer, while its carry window is open: absent before any
     * answer and once maxCarryAge has passed since the last one.
     */
    capabilities: D | undefined
    /** When the last answer arrived, in Unix ms; 0 when none has. */
    reachableAsOf: number
}

export interface CatalogEngineOptions {
    /** How long a node keeps its last answer, in ms. Go's DefaultMaxCarryAge when absent. */
    maxCarryAge?: number | undefined
    clock?: Clock | undefined
}

interface NodeState<D> {
    latest: ProbeObservation<D>['kind']
    /** Time of the latest observation applied, so a repeat is a no-op. */
    at: number
    lastAnswer: D | undefined
    reachableAsOf: number
}

const nodeKey = (ref: CatalogNodeRef) => `${ref.op}:${ref.node}`

/**
 * CatalogEngine folds each node's probe results. applyProbe is idempotent per
 * observation time, so an app may hand it the same result from every place it
 * reads one.
 */
export class CatalogEngine<D extends { protoVersion?: string | undefined }> {
    readonly maxCarryAge: number
    private readonly clock: Clock
    private readonly nodes = new Map<string, NodeState<D>>()

    constructor(opts: CatalogEngineOptions = {}) {
        this.maxCarryAge =
            opts.maxCarryAge !== undefined && opts.maxCarryAge > 0 ? opts.maxCarryAge : defaults.discovery.maxCarryAge
        // Looked up per call, so a host that swaps Date.now (a test clock) is seen.
        this.clock = opts.clock ?? (() => Date.now())
    }

    /**
     * applyProbe records an observation made at `at` (Unix ms). One no newer
     * than the last applied for the node doesn't change how the node reads, so
     * a stale or repeated result can't overwrite a fresher one; an answer newer
     * than the last answer still refreshes what the node is carried as.
     * Returns whether anything changed.
     */
    applyProbe(ref: CatalogNodeRef, obs: ProbeObservation<D>, at: number): boolean {
        const k = nodeKey(ref)
        const prev = this.nodes.get(k)
        if (prev && at <= prev.at) {
            // A late answer from another reader, older than a later failure but
            // newer than the answer carried: what it served is the freshest known.
            if (obs.kind !== 'answered' || at <= prev.reachableAsOf) return false
            this.nodes.set(k, { ...prev, lastAnswer: obs.details, reachableAsOf: at })
            return true
        }
        const next: NodeState<D> = {
            latest: obs.kind,
            at,
            lastAnswer: prev?.lastAnswer,
            reachableAsOf: prev?.reachableAsOf ?? 0,
        }
        if (obs.kind === 'answered') {
            next.lastAnswer = obs.details
            next.reachableAsOf = at
        }
        this.nodes.set(k, next)
        return true
    }

    /** view reads the node as of now. */
    view(ref: CatalogNodeRef): CatalogNodeView<D> {
        const s = this.nodes.get(nodeKey(ref))
        if (!s) return { reachability: 'probing', capabilities: undefined, reachableAsOf: 0 }
        const capabilities = this.carried(s) ? s.lastAnswer : undefined
        return { reachability: this.reachability(s, capabilities), capabilities, reachableAsOf: s.reachableAsOf }
    }

    /** clear forgets every node. */
    clear(): void {
        this.nodes.clear()
    }

    // Go's carry window: open while the last answer is younger than maxCarryAge,
    // and never for a node that has not answered.
    private carried(s: NodeState<D>): boolean {
        return s.lastAnswer !== undefined && s.reachableAsOf > 0 && this.clock() - s.reachableAsOf < this.maxCarryAge
    }

    private reachability(s: NodeState<D>, capabilities: D | undefined): Reachability {
        const judged = (d: D) => (protoVersionCompatible(d.protoVersion) ? 'ok' : 'incompatible')
        switch (s.latest) {
            // An answer and a probe that learned nothing read alike: by the
            // carried answer while the window is open, and as failing once it
            // closes, when Go stops advertising the node.
            case 'answered':
            case 'unknown':
                return capabilities ? judged(capabilities) : 'failing'
            case 'target-failed':
                return 'failing'
            case 'no-relay':
                return 'no-relay'
        }
    }
}

/**
 * restoredProtoVersion floors a protocol version read back from storage to
 * "<major>.0". What a node advertised last session says nothing about what it
 * runs now, and assuming too high a minor fails hard (a reserve sized for a
 * capability the node rolled back is refused after escrow opens), while too
 * low only forgoes the capability until the next probe. The major is kept, so
 * compatibility is unaffected. Go's minorFloor in persist.go, pinned by
 * testdata/persisted_proto_version_vectors.json.
 */
export function restoredProtoVersion(version: string): string {
    if (version === '') return ''
    const dot = version.indexOf('.')
    if (dot < 0 || dot === 0) return version
    return `${version.slice(0, dot)}.0`
}
