/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A node's reachability as a catalog row shows it, by the rule the registry
// advertises on: answeredWithin is the liveness half of the registry's
// advertisable gate (Go's advertisableAt), pinned there by
// registry_cycle_vectors.json. reachabilityOf and carryLapsesAt have no Go
// twin, since Go's proxy has no picker.

import { protoVersionCompatible } from '@txnlab/zs-proto/wire'

import { defaults } from '../config.js'
import type { Operator } from '../operator.js'
import type { Reachability } from './rows.js'

// The window a registry built with maxCarryAge applies: it reads 0 or less,
// or a non-finite number, as the default, so a caller passing the same
// setting gets the same window rather than none.
function carryWindow(maxCarryAge: number): number {
    return Number.isFinite(maxCarryAge) && maxCarryAge > 0 ? maxCarryAge : defaults.discovery.maxCarryAge
}

/** The fields the reachability rules read. */
export type ReachabilityFields = Pick<Operator, 'reachable' | 'probed' | 'reachableAsOf' | 'lastRefreshAt' | 'protoVersion'>

/**
 * answeredWithin reports whether op's last answer still stands at nowMs: this
 * cycle's result when a probe reached it, else whether its last success is
 * inside maxCarryAge. A node that never answered has nothing to stand on.
 */
export function answeredWithin(op: ReachabilityFields, nowMs: number, maxCarryAge: number): boolean {
    if (op.probed === true) return op.reachable
    return !!op.reachableAsOf && nowMs - op.reachableAsOf < maxCarryAge
}

/**
 * reachabilityOf is op's row verdict at nowMs, for a registry with
 * maxCarryAge (0 or less is the default, as the registry reads it): the
 * registry's advertisable gate less its staging and signer-funding terms,
 * which a picker applies as filters of its own. Whether a node has been tried
 * is the registry's own record, so a registry built anew reads every node it
 * has not tried as probing.
 *
 * A node that has answered speaks our wire major or is `incompatible`, an
 * answer with no version included, as the registry refuses one. Otherwise it
 * is `ok` while its answer stands (answeredWithin), `probing` until a refresh
 * first tries it, and `failing` after. A cycle with no relay to probe through
 * is not told apart from a down node: neither is evidence the node is up.
 */
export function reachabilityOf(op: ReachabilityFields, nowMs: number, maxCarryAge: number): Reachability {
    if (op.reachableAsOf && !protoVersionCompatible(op.protoVersion)) return 'incompatible'
    if (answeredWithin(op, nowMs, carryWindow(maxCarryAge))) return 'ok'
    return op.lastRefreshAt === undefined ? 'probing' : 'failing'
}

/**
 * carryLapsesAt is when, after nowMs, the next carried answer among ops
 * leaves the carry window, so verdicts reached at nowMs stop being current;
 * Infinity when none will. A registry publishes nothing while its chain read
 * fails, so rows built from one snapshot must age on their own.
 */
export function carryLapsesAt(ops: readonly ReachabilityFields[], nowMs: number, maxCarryAge: number): number {
    const window = carryWindow(maxCarryAge)
    let at = Infinity
    for (const op of ops) {
        if (op.probed === true || !op.reachableAsOf) continue
        const lapse = op.reachableAsOf + window
        if (lapse > nowMs) at = Math.min(at, lapse)
    }
    return at
}
