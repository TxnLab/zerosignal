/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Pooling operators that serve the SAME model under a DIFFERENT wire id into
// one dispatch candidate list, merged by price. Client-side only: Go's
// pickCandidates dispatches one model id and has no twin. Its display-side
// relative is registry.go's aggregate (aggregateDigest, aggregateSource,
// aggregateIdentity), which folds the same three identity fields per id but
// never pools across ids.
//
// Identity is layered — published weights digest, else declared HuggingFace
// source, else the node's curated frontier canonical — and never a name-parser
// guess: two ids sharing a family is taxonomy, not interchangeability.

import {
    AFFINITY_NONE,
    type Constraints,
    type Operator,
    selectTargets,
} from '@txnlab/zs-proto/selection'

/** The identity fields one operator advertises for one model id. */
export interface ModelIdentity {
    weightsDigest?: string | undefined
    source?: string | undefined
    canonicalId?: string | undefined
}

/** One node as the identity votes read it. */
export interface IdentityRow {
    /** The node's live probe verdict; only 'ok' counts as reachable. */
    reachability: string
    modelInfos: ReadonlyMap<string, ModelIdentity>
}

/**
 * The model-identity key of a declared source: the `hf:` scheme and any
 * `@revision` stripped, lowercased. Revisions don't change which model it is,
 * and HuggingFace repo names compare case-insensitively. Same rule as Go's
 * registry.go sourceIdentityKey.
 */
export function sourceIdentityKey(source: string): string {
    const noScheme = source.startsWith('hf:') ? source.slice(3) : source
    const at = noScheme.indexOf('@')
    return (at >= 0 ? noScheme.slice(0, at) : noScheme).toLowerCase()
}

// The distinct values `pick` yields for modelId across rows. `pick` returns
// undefined for a field the operator left out or empty; anything else counts,
// including an empty identity key, so a declared-but-degenerate source such as
// "hf:" still dissents rather than abstaining.
function distinct(
    rows: readonly IdentityRow[],
    modelId: string,
    pick: (info: ModelIdentity) => string | undefined,
): Set<string> {
    const out = new Set<string>()
    for (const row of rows) {
        const info = row.modelInfos.get(modelId)
        const v = info && pick(info)
        if (v !== undefined) out.add(v)
    }
    return out
}

// The single value reachable rows agree on, else (when no reachable row has an
// opinion) the single value across all rows, else undefined. A disagreement
// among the reachable ones aborts rather than widening.
//
// The all-rows fallback is the headline case: a model's only server just went
// down, which is exactly when cross-spelling failover is needed, and its last
// successful details are still cached. Identity is a static property of the
// served weights, not a freshness-sensitive signal like reachability, so a
// stale-but-cached value is the right trade-off here. A display-only vote
// should not do this: there an unreachable peer's stale digest would raise a
// false "weights differ" badge.
function reachableFirstConsensus(
    rows: readonly IdentityRow[],
    modelId: string,
    pick: (info: ModelIdentity) => string | undefined,
): string | undefined {
    const reachable = distinct(
        rows.filter((r) => r.reachability === 'ok'),
        modelId,
        pick,
    )
    if (reachable.size > 0) return reachable.size === 1 ? [...reachable][0] : undefined
    const all = distinct(rows, modelId, pick)
    return all.size === 1 ? [...all][0] : undefined
}

const digestOf = (i: ModelIdentity): string | undefined => i.weightsDigest || undefined
const sourceOf = (i: ModelIdentity): string | undefined =>
    i.source ? sourceIdentityKey(i.source) : undefined
const canonicalOf = (i: ModelIdentity): string | undefined =>
    i.canonicalId ? i.canonicalId.toLowerCase() : undefined

/**
 * The single digest operators serving modelId agree on, or undefined when they
 * disagree (a real cross-operator weights mismatch) or none publishes one. A
 * mismatch always aborts: it means we don't know which weights the payer is
 * running, so no cross-spelling gate is possible.
 */
export function consensusDigestForModel(rows: readonly IdentityRow[], modelId: string): string | undefined {
    return reachableFirstConsensus(rows, modelId, digestOf)
}

/**
 * The single source identity key operators serving modelId agree on: the
 * fallback when NOBODY publishes a digest for it, the norm for hosted-API and
 * passthrough upstreams. Undefined when they disagree, none declares one, or
 * any operator publishes a digest for this id: a digest is proof and owns
 * identity, so an id that has one never widens through the weaker tier.
 */
export function consensusSourceForModel(rows: readonly IdentityRow[], modelId: string): string | undefined {
    if (distinct(rows, modelId, digestOf).size > 0) return undefined
    return reachableFirstConsensus(rows, modelId, sourceOf)
}

/**
 * The single lowercased frontier canonical operators serving modelId agree on:
 * the fallback for a CLOSED-weights model with no HuggingFace repo. It fires
 * only when no digest and no source exist anywhere for the id, since any
 * source means the model is sourced and belongs to the stronger tier.
 */
export function consensusCanonicalForModel(rows: readonly IdentityRow[], modelId: string): string | undefined {
    if (distinct(rows, modelId, digestOf).size > 0) return undefined
    if (distinct(rows, modelId, sourceOf).size > 0) return undefined
    return reachableFirstConsensus(rows, modelId, canonicalOf)
}

/**
 * The identity modelId has across rows, as a per-operator predicate: whether
 * one operator's advertisement of some id names the same model. Undefined when
 * no tier yields an identity.
 *
 * Each tier admits only advertisements that are ALSO silent at every stronger
 * tier, so a claim never stands in for proof, and it is checked PER OPERATOR:
 * an id can qualify because one operator matched, and a peer serving the same
 * id under a stale digest or a different source must not ride along on it.
 */
export function modelIdentityMatcher(
    rows: readonly IdentityRow[],
    modelId: string,
): ((info: ModelIdentity | undefined) => boolean) | undefined {
    const digest = consensusDigestForModel(rows, modelId)
    const source = digest ? undefined : consensusSourceForModel(rows, modelId)
    const canonical = digest || source ? undefined : consensusCanonicalForModel(rows, modelId)
    if (!digest && !source && !canonical) return undefined
    return (info) => {
        if (!info) return false
        if (digest) return info.weightsDigest === digest
        if (info.weightsDigest) return false
        if (source) return !!info.source && sourceIdentityKey(info.source) === source
        return !info.source && !!info.canonicalId && info.canonicalId.toLowerCase() === canonical
    }
}

/** A node and the wire id it serves the pooled model under. */
export interface SpellingCandidate<R> {
    row: R
    modelId: string
}

/**
 * Operators serving the same model as `modelId` under a DIFFERENT wire id, one
 * price-ordered list per such id (sorted by id), so the caller can k-way merge
 * them with its exact-id list.
 *
 * Eligibility for each qualifying id is re-derived by re-running selectTargets
 * with that model, so a peer is held to exactly the bar it would face had the
 * payer picked it directly, and each candidate carries ITS OWN wire id, the id
 * that operator is reserved under.
 *
 * `alreadyTried` excludes nodes by (id, node_id), and only nodes actually in it:
 * if the selected operator stopped serving `modelId`, that same physical node
 * may be the best candidate under the id it still serves. A node appears at
 * most once across all lists.
 */
export function equivalentSpellingLists<R extends IdentityRow>(
    modelId: string,
    rows: readonly R[],
    rowOf: (op: Operator) => R | undefined,
    ops: Operator[],
    alreadyTried: readonly { id: number; node_id: number }[],
    constraints: Omit<Constraints, 'model' | 'affinity_policy'>,
): SpellingCandidate<R>[][] {
    const qualifies = modelIdentityMatcher(rows, modelId)
    if (!qualifies) return []

    const keyOf = (o: { id: number; node_id: number }): string => `${o.id}:${o.node_id}`
    const seen = new Set(alreadyTried.map(keyOf))

    const otherIds = new Set<string>()
    for (const row of rows) {
        for (const [id, info] of row.modelInfos) {
            if (id !== modelId && qualifies(info)) otherIds.add(id)
        }
    }

    const lists: SpellingCandidate<R>[][] = []
    for (const id of [...otherIds].sort()) {
        const ranked = selectTargets(ops, { ...constraints, model: id, affinity_policy: AFFINITY_NONE }, null)
        const list: SpellingCandidate<R>[] = []
        for (const op of ranked.operators) {
            const key = keyOf(op)
            if (seen.has(key)) continue
            const row = rowOf(op)
            if (!row || !qualifies(row.modelInfos.get(id))) continue
            seen.add(key)
            list.push({ row, modelId: id })
        }
        if (list.length > 0) lists.push(list)
    }
    return lists
}

/**
 * Stable k-way merge of already cost-ordered lists into one cost-ordered pool.
 * Ties keep the earlier list's element, so an exact-id list passed first wins
 * over an equally priced other-spelling peer; there is no id tiebreak, since
 * each list already arrives in its own order and ordering across lists on id
 * would only override that preference with an arbitrary one.
 *
 * Merging rather than concatenating is what lets a sort preference apply across
 * providers: a concatenated pool would rank every exact-id candidate above a
 * cheaper or faster peer that merely spells the model differently. It also
 * keeps each list's internal order, so selectTargets' partitions survive.
 *
 * Comparing only list heads is a correct merge ONLY while every list is ordered
 * by the same comparator, so `costOf` must be the cost the lists were ranked by
 * (selectTargets ranks by `requestCost`), never a second opinion about price.
 * An unpriceable candidate should cost +Infinity, which sorts it last; two such
 * are a tie.
 */
export function mergeOrderedByCost<T>(lists: readonly (readonly T[])[], costOf: (item: T) => number): T[] {
    const cursors = lists.map(() => 0)
    const total = lists.reduce((n, l) => n + l.length, 0)
    const out: T[] = []
    while (out.length < total) {
        let best = -1
        for (let i = 0; i < lists.length; i++) {
            if (cursors[i]! >= lists[i]!.length) continue
            // Explicit comparison, not subtraction: Infinity - Infinity is NaN,
            // which reads as "not less than" and would order an unpriceable pool
            // by whichever list was scanned first instead of the tie rule.
            if (best === -1 || costOf(lists[i]![cursors[i]!]!) < costOf(lists[best]![cursors[best]!]!)) best = i
        }
        out.push(lists[best]![cursors[best]!]!)
        cursors[best]!++
    }
    return out
}
