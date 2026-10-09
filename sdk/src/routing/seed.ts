/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Candidate selection for a payer who picked an OPERATOR in a model picker
// rather than an exact node, plus the guard that keeps that pick from being
// lost. Client-side only: Go's proxy has no picker, and its affinity pin is a
// cached node, so neither has a Go twin.

import {
    AFFINITY_NONE,
    AFFINITY_PREFER,
    type Constraints,
    type Operator,
    type TargetResult,
    selectTargets,
} from '@txnlab/zs-proto/selection'

export interface SelectedOperatorResult {
    /** selectTargets under AFFINITY_PREFER, seeded with `preferred`. */
    result: TargetResult
    /** The exact node the selection was seeded with, or null when the operator has none to offer. */
    preferred: Operator | null
}

/**
 * Runs selectTargets with the payer's selected operator preferred.
 *
 * The pick is operator-level, but an operator's nodes can differ in capability,
 * so it can't seed AFFINITY_PREFER with an arbitrary node of that operator:
 * AFFINITY_PREFER pins the EXACT node given, which would override the
 * image-tool partition and route to a toolless sibling. So this ranks once
 * with no affinity, then seeds with that operator's TOP-ranked node for this
 * request.
 *
 * When the first pass filtered the operator out entirely, it is still seeded
 * with its first node in `ops` so it is tried first (never regress below the
 * single attempt the payer asked for), but not past staging or require_tee:
 * selectTargets filters the candidate LIST, never the caller-supplied
 * preferred node, so such a seed would resurrect a node the payer's own
 * settings hold out. Signer funding needs no clause here, because the shared
 * affinity step re-checks it on the preferred node itself, and under
 * AFFINITY_PREFER a broke one yields rather than floats.
 *
 * The pin is recomputed from the operator id on every call, so a conversation
 * may land on different nodes of one operator across turns. That is safe only
 * for a stateless caller that re-sends full history each turn (no
 * previous_response_id / store: true). A caller with server-side session
 * continuation has to pin the exact node instead.
 */
export function selectTargetsForOperator(
    ops: Operator[],
    constraints: Omit<Constraints, 'affinity_policy'>,
    operatorId: number,
): SelectedOperatorResult {
    const ranked = selectTargets(ops, { ...constraints, affinity_policy: AFFINITY_NONE }, null)
    const preferred =
        ranked.operators.find((o) => o.id === operatorId) ??
        ops.find(
            (o) =>
                o.id === operatorId &&
                (constraints.allow_staging === true || !o.staging) &&
                (!constraints.require_tee || o.tee_attested),
        ) ??
        null
    const result = selectTargets(ops, { ...constraints, affinity_policy: AFFINITY_PREFER }, preferred)
    return { result, preferred }
}

/**
 * Never regress below a single attempt: when `ordered` lacks the payer's own
 * pick (selectTargets can filter it out, e.g. an incompatible version committed
 * before churn), put it first. A pick that is present but demoted stays where
 * it is, so a known-down selection is never re-promoted ahead of reachable
 * peers.
 *
 * `isSelected` must match the pick exactly, operator AND model, never operator
 * alone: a cross-spelling candidate can carry the same operator under a
 * different model id, and letting it satisfy the guard would skip the literal
 * pick.
 *
 * `heldOut` is true when one of the payer's own restrictions excludes the pick
 * (only-favorites, staging off, attested-only, a node proven fraudulent, or a
 * signer known to be underfunded). Re-adding it would route around that
 * restriction, so the list is returned as is, possibly empty.
 */
export function withSelectedCandidate<T>(
    ordered: T[],
    selected: T,
    isSelected: (candidate: T) => boolean,
    heldOut: boolean,
): T[] {
    if (heldOut || ordered.some(isSelected)) return ordered
    return [selected, ...ordered]
}
