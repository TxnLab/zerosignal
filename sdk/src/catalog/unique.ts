/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// A model picker's rows: the catalog's per-node rows deduplicated into one row
// per model, each with a default node chosen exactly as dispatch would rank it,
// and (optionally) the spellings of one model merged into one row. Client-side
// only: Go's proxy has no picker. Its display-side relative is registry.go's
// per-model aggregate, which folds nodes per id but never picks a default.
//
// What the app knows and this module can't is passed in: its selection
// projection of a node, its attestation predicate, and any per-node fields it
// carries on each serving entry.

import {
    AFFINITY_NONE,
    type Constraints,
    ENDPOINT_RESPONSES,
    type Operator as SelectionOperator,
    selectTargets,
} from '@txnlab/zs-proto/selection'
import { contradictsWeightsConsensus, type DigestClaim, weightsConsensus } from '@txnlab/zs-proto/steering'

import { type ModelIdentity, sourceIdentityKey } from '../routing/equivalent.js'
import {
    REACHABILITY_RANK,
    type RankedModelInfo,
    type Reachability,
    compareUniqueModelRows,
    deriveWeightsConsensus,
} from './rows.js'

/** The node identity the derivation reads; the app's operator record passes as is. */
export interface CatalogNodeIdentity {
    id: bigint
    nodeId: bigint
    /** The node's on-chain owner; a node without one casts no weights vote. */
    ownerAddr?: string | undefined
}

/** The model fields the derivation reads, in the app's parsed (camelCase) shape. */
export interface UniqueModelInfo extends RankedModelInfo, ModelIdentity {}

/** One node's probed catalog row, as the derivation reads it. */
export interface CatalogNodeRow<Op extends CatalogNodeIdentity, Info extends UniqueModelInfo, Tool> {
    operator: Op
    models: readonly string[]
    modelInfos: ReadonlyMap<string, Info>
    reachability: Reachability
    protoVersion?: string | undefined
    builtinTools: readonly Tool[]
    ephemeralRecipient?: string | undefined
    ephemeralExpiry?: number | undefined
}

/** One operator serving a unique-model row, with the app's per-node extras. */
export type ServingNode<Op, Info, Tool, X> = {
    operator: Op
    /**
     * THIS operator's own wire id for the model, its reserve id. Equal to the
     * row's modelId on an unmerged row; on a merged row it is that provider's
     * spelling. Every commit, dispatch and reserve path must use this.
     */
    modelId: string
    /**
     * EVERY spelling this operator serves for the row's identity. An operator
     * advertising the model under several ids collapses to one entry, and a
     * persisted selection may name any of them.
     */
    modelIds: string[]
    modelInfo: Info | null
    reachability: Reachability
    protoVersion?: string | undefined
    /** THIS node's tools; the row-level list belongs to the default operator. */
    builtinTools: readonly Tool[]
} & X

/** A single deduplicated model row in a picker. */
export interface UniqueModelRow<Op, Info, Tool, X = object> {
    /**
     * The DEFAULT OPERATOR'S OWN wire id: what a click commits and what that
     * operator is reserved under. On a merged row, every other operator carries
     * its own spelling in servingOperators[].modelId and must be reserved under
     * it. Never render this as the label (that is displayModelId).
     */
    modelId: string
    /**
     * The row's label. A merged row shows the shared identity (a spelling the
     * fleet publishes unqualified, else the declared repo); an unmerged row its
     * wire id, shortened by the label pass when the bare name is unambiguous.
     * Display only.
     */
    displayModelId: string
    /**
     * Which identity tier bucketed the row: 'digest' (proven identical
     * weights), 'source' (a declared HuggingFace repo, no digest), 'canonical'
     * (a closed-weights frontier model merged on the node's curated canonical)
     * or 'id' (the bare wire id, no merge).
     */
    identityBasis: 'digest' | 'source' | 'canonical' | 'id'
    defaultOperator: Op
    /** Null while the default operator's probe hasn't resolved. */
    defaultModelInfo: Info | null
    defaultBuiltinTools: readonly Tool[]
    /** Never 'incompatible': the selection primitive drops those. */
    defaultReachability: Reachability
    defaultEphemeralRecipient?: string | undefined
    defaultEphemeralExpiry?: number | undefined
    /**
     * Every OPERATOR serving the model, id-ascending, one entry per operator
     * (the best-reachability node, ties to the lowest node id), not per node.
     * Incompatible operators stay listed so a UI can say why a peer is
     * unavailable, though they cannot be the default.
     */
    servingOperators: Array<ServingNode<Op, Info, Tool, X>>
    /** Advisory weights summary over the reachable serving operators. */
    weightsMismatch: boolean
    weightsConsensus?: string | undefined
    /**
     * Every candidate NODE behind the row passed the app's display attestation
     * predicate: a fact about the nodes, not about which pass built the row, so
     * an all-attested model reads true in both passes of uniqueModelRowVariants
     * and a picker can drop the redundant twin. Computed per node, before the
     * operator collapse, since an operator with one attested and one unattested
     * node looks identical in both passes once collapsed.
     */
    teeAttestedOnly: boolean
}

/** What the app supplies that the derivation can't know. */
export interface UniqueModelDeps<R, X> {
    /** The selection primitive's projection of one node, the same one dispatch ranks. */
    toSelectionOperator(row: R): SelectionOperator
    /** The app's DISPLAY attestation predicate for one node. */
    displayAttested(row: R): boolean
    /** Per-node fields to carry on the node's serving entry. */
    servingExtras(row: R): X
}

export interface UniqueModelOptions {
    /** Prefer an image-tool-capable default over a cheaper toolless one. */
    preferImageTools?: boolean | undefined
    /** Caller constraints the default pick honours, e.g. favourites as only/order. */
    constraints?: Partial<Pick<Constraints, 'only' | 'order' | 'allow_fallbacks'>> | undefined
    /**
     * Threaded into the default pick so the selection gate keeps staging nodes
     * the caller's own filter let through. It does not filter by itself.
     */
    allowStaging?: boolean | undefined
    /** Merge the rows whose operators agree on one identity (see rowIdentityKey). */
    unifyEquivalent?: boolean | undefined
}

/** Any node row the derivation accepts. */
export type AnyCatalogNodeRow = CatalogNodeRow<CatalogNodeIdentity, UniqueModelInfo, unknown>

/** The unique-model row derived from the app's node row type R, with its per-node extras X. */
export type UniqueModelRowOf<R extends AnyCatalogNodeRow, X = object> = UniqueModelRow<
    R['operator'],
    R['modelInfos'] extends ReadonlyMap<string, infer I> ? I : never,
    R['builtinTools'] extends ReadonlyArray<infer T> ? T : never,
    X
>

// The bodies work on this erased shape; the exported functions return the
// app's own row type, which differs only in the element types it carries.
type AnyRow = UniqueModelRow<CatalogNodeIdentity, UniqueModelInfo, unknown, object>
type AnyServing = AnyRow['servingOperators'][number]

/**
 * buildUniqueModelRows derives the picker rows for one already-filtered slice
 * of the catalog, sorted case-insensitively by label, then by wire id.
 *
 * allRows is the WHOLE catalog and stays separate from candidateRows: the
 * weights vote runs over every node, as dispatch's does, since a node held out
 * as a target (staging, unattested, an unfunded signer) still says something
 * true about which bytes the model is.
 *
 * A node whose probe hasn't resolved contributes no models, so a model appears
 * once some node serving it has answered.
 */
export function buildUniqueModelRows<R extends AnyCatalogNodeRow, X extends object = object>(
    allRows: readonly R[],
    candidateRows: readonly R[],
    opts: UniqueModelOptions,
    deps: UniqueModelDeps<R, X>,
): Array<UniqueModelRowOf<R, X>> {
    return buildRows(allRows, candidateRows, opts, deps) as unknown as Array<UniqueModelRowOf<R, X>>
}

function buildRows<R extends AnyCatalogNodeRow, X extends object>(
    allRows: readonly R[],
    candidateRows: readonly R[],
    opts: UniqueModelOptions,
    deps: UniqueModelDeps<R, X>,
): AnyRow[] {
    const preferImageTools = opts.preferImageTools ?? false

    const byModelId = new Map<string, Array<{ serving: AnyServing; row: R }>>()
    for (const row of candidateRows) {
        const extras = deps.servingExtras(row)
        for (const modelId of row.models) {
            const list = byModelId.get(modelId) ?? []
            list.push({
                row,
                serving: {
                    ...extras,
                    operator: row.operator,
                    modelId,
                    // One spelling per node here; mergeEquivalentRows unions them
                    // when an operator turns out to serve several.
                    modelIds: [modelId],
                    modelInfo: row.modelInfos.get(modelId) ?? null,
                    reachability: row.reachability,
                    protoVersion: row.protoVersion,
                    builtinTools: row.builtinTools,
                },
            })
            byModelId.set(modelId, list)
        }
    }

    // The default pick runs through the shared selection primitive so a picker
    // and dispatch order operators identically: serves-model and wire-version
    // eligibility, the price sort, the in-loop image-tool partition. Both image
    // budgets at 1 make step 7b's `capable` gen>0 || edit>0, i.e.
    // modelInfoOffersImageTools; only >0 matters.
    const selOps = candidateRows.map((r) => deps.toSelectionOperator(r))
    const byNode = new Map<string, R>()
    selOps.forEach((op, i) => byNode.set(`${op.id}:${op.node_id}`, candidateRows[i]!))
    const imgBudget = preferImageTools ? 1 : 0

    const out: AnyRow[] = []
    for (const [modelId, candidates] of byModelId) {
        const tr = selectTargets(
            selOps,
            {
                model: modelId,
                // Relaxed sizing: a picker doesn't know the request size, and the
                // per-attempt context gate at dispatch is authoritative.
                input_tokens: 0,
                max_output_tokens: 0,
                endpoint: ENDPOINT_RESPONSES,
                // False on purpose: the caller's candidate filter already decided
                // attestation, laxer than dispatch's strict per-binding gate
                // (rendering a row sends no prompt). Handing it back here would
                // drop the default for a node mid-rotation and blink the row out.
                require_tee: false,
                allow_staging: opts.allowStaging ?? false,
                requested_tools: null,
                image_tool_gen_budget: imgBudget,
                image_tool_edit_budget: imgBudget,
                affinity_policy: AFFINITY_NONE,
                ...opts.constraints,
            },
            null,
        )
        // The first ranked node that DECLARES the model, skipping one whose
        // weights digest contradicts the peer consensus unless every one does
        // (demote, never drop). An automatic pick represents each fallback model
        // by this one node, so a contradicted default would hide its agreeing
        // peers from it.
        const consensus = peerWeightsConsensus(allRows, modelId)
        let defRow: R | undefined
        let contradictedDefRow: R | undefined
        for (const sel of tr.operators) {
            const row = byNode.get(`${sel.id}:${sel.node_id}`)
            if (!row?.modelInfos.has(modelId)) continue
            if (contradictsWeightsConsensus(row.modelInfos.get(modelId)?.weightsDigest, consensus)) {
                contradictedDefRow ??= row
                continue
            }
            defRow = row
            break
        }
        defRow ??= contradictedDefRow
        if (!defRow) continue

        const teeAttestedOnly = candidates.every((c) => deps.displayAttested(c.row))
        const servingOperators = collapseByOperator(candidates.map((c) => c.serving))
        const { weightsMismatch, weightsConsensus } = deriveWeightsConsensus(servingOperators)
        out.push({
            modelId,
            displayModelId: modelId,
            identityBasis: 'id',
            defaultOperator: defRow.operator,
            defaultModelInfo: defRow.modelInfos.get(modelId) ?? null,
            defaultBuiltinTools: defRow.builtinTools,
            defaultReachability: defRow.reachability,
            defaultEphemeralRecipient: defRow.ephemeralRecipient,
            defaultEphemeralExpiry: defRow.ephemeralExpiry,
            servingOperators,
            weightsMismatch,
            weightsConsensus,
            teeAttestedOnly,
        })
    }
    const merged = opts.unifyEquivalent ? mergeEquivalentRows(out, preferImageTools) : out
    applyDisplayLabels(merged)
    // Case-insensitive so a canonical-cased repo name ("GLM-5.2") lands with its
    // lowercase siblings; the wire id keeps the order total.
    merged.sort(
        (a, b) =>
            a.displayModelId.toLowerCase().localeCompare(b.displayModelId.toLowerCase()) ||
            (a.modelId < b.modelId ? -1 : a.modelId > b.modelId ? 1 : 0),
    )
    return merged
}

/**
 * uniqueModelRowVariants derives both views a picker needs: every model, and
 * the same models restricted to nodes the app has attested. They are two
 * lists, not one: consumers that find by model id or rank with
 * compareUniqueModelRows would turn order-dependent if a twin were appended,
 * and an automatic pick could hand a user an attestation pin they never asked
 * for. A picker interleaves the twins for display only.
 *
 * candidatesFor(requireTee) is the app's eligible slice of allRows. With
 * requireTee set, the plain view is already the attested one and both lists
 * are the same array.
 */
export function uniqueModelRowVariants<R extends AnyCatalogNodeRow, X extends object = object>(
    allRows: readonly R[],
    candidatesFor: (requireTee: boolean) => readonly R[],
    requireTee: boolean,
    opts: UniqueModelOptions,
    deps: UniqueModelDeps<R, X>,
): { rows: Array<UniqueModelRowOf<R, X>>; attestedRows: Array<UniqueModelRowOf<R, X>> } {
    const plain = buildUniqueModelRows(allRows, candidatesFor(requireTee), opts, deps)
    if (requireTee) return { rows: plain, attestedRows: plain }

    const attested = buildUniqueModelRows(allRows, candidatesFor(true), opts, deps)
    // The label pass runs per list and shortens a name only when it doesn't
    // collide, so the two lists can label one model differently, which reads
    // as two models rather than one on two kinds of hardware. Safe to mutate:
    // nothing has seen `attested` yet.
    const plainByWireId = rowsByWireId(plain)
    for (const row of attested) {
        const twin = plainByWireId.get(row.modelId)
        if (twin) row.displayModelId = twin.displayModelId
    }
    return { rows: plain, attestedRows: attested }
}

/**
 * rowsByWireId indexes rows by every wire id they serve: the default's own and
 * each serving operator's spellings. The first row to claim an id keeps it.
 */
export function rowsByWireId<R extends { modelId: string; servingOperators: ReadonlyArray<{ modelIds: readonly string[] }> }>(
    rows: readonly R[],
): Map<string, R> {
    const out = new Map<string, R>()
    for (const row of rows) {
        if (!out.has(row.modelId)) out.set(row.modelId, row)
        for (const so of row.servingOperators) {
            for (const id of so.modelIds) if (!out.has(id)) out.set(id, row)
        }
    }
    return out
}

/**
 * rowIdentityKey is the row's cross-operator identity, voted by the operators
 * that serve it: digest, then declared HuggingFace source, then the node's
 * curated frontier canonical, then the bare wire id.
 *
 * Voted by every serving operator rather than read off the default, which is
 * merely the cheapest: otherwise a price change could redefine what the model
 * is. Silence abstains, it doesn't dissent, so a not-yet-upgraded node can't
 * veto a merge its peers agree on; only two distinct values at a tier withdraw
 * the claim. A declared source whose identity key is empty ("hf:") counts as a
 * value, as dispatch's vote counts it, so it dissents beside another source and
 * names no identity on its own.
 *
 * Dispatch (modelIdentityMatcher in routing/equivalent.ts) uses the same
 * precedence but rechecks every cross-spelling operator individually; keep the
 * tier order aligned with it.
 */
export function rowIdentityKey(row: {
    modelId: string
    servingOperators: ReadonlyArray<{ modelInfo: ModelIdentity | null }>
}): string {
    const values = (pick: (info: ModelIdentity) => string | undefined): Set<string> => {
        const out = new Set<string>()
        for (const s of row.servingOperators) {
            const v = s.modelInfo ? pick(s.modelInfo) : undefined
            if (v !== undefined) out.add(v)
        }
        return out
    }
    const bare = `id:${row.modelId}`
    // Two distinct digests are a real weights mismatch no declared source may
    // paper over.
    const digests = values((i) => i.weightsDigest || undefined)
    if (digests.size > 1) return bare
    if (digests.size === 1) return `digest:${[...digests][0]!}`
    const sources = values((i) => (i.source ? sourceIdentityKey(i.source) : undefined))
    if (sources.size > 1) return bare
    if (sources.size === 1) {
        const source = [...sources][0]!
        return source ? `src:${source}` : bare
    }
    const canonicals = values((i) => (i.canonicalId ? i.canonicalId.toLowerCase() : undefined))
    return canonicals.size === 1 ? `canonical:${[...canonicals][0]!}` : bare
}

/**
 * Collapse rows that are the SAME model under different wire ids into one row.
 * Rows bucket by rowIdentityKey, so only proven or declared-equivalent models
 * merge. A group of one is returned untouched, label included. A merged row's
 * default is the compareUniqueModelRows winner across its members, and its
 * modelId stays that operator's own wire id.
 */
function mergeEquivalentRows(rows: AnyRow[], preferImageTools: boolean): AnyRow[] {
    const order: string[] = []
    const groups = new Map<string, AnyRow[]>()
    for (const row of rows) {
        const key = rowIdentityKey(row)
        const group = groups.get(key)
        if (group) group.push(row)
        else {
            groups.set(key, [row])
            order.push(key)
        }
    }

    const out: AnyRow[] = []
    for (const key of order) {
        const group = groups.get(key)!
        if (group.length === 1) {
            out.push(group[0]!)
            continue
        }
        const members = [...group].sort((a, b) => compareUniqueModelRows(a, b, preferImageTools))
        const primary = members[0]!

        // One entry per OPERATOR across every spelling, by the same rule as the
        // per-spelling collapse; each keeps its own wire id, and modelIds
        // gathers every spelling the operator serves, so a selection committed
        // against a losing spelling still reads as this row.
        const spellings = new Map<bigint, Set<string>>()
        for (const member of members) {
            for (const so of member.servingOperators) {
                const seen = spellings.get(so.operator.id) ?? new Set<string>()
                for (const id of so.modelIds) seen.add(id)
                spellings.set(so.operator.id, seen)
            }
        }
        const servingOperators = collapseByOperator(members.flatMap((m) => m.servingOperators)).map(
            (so) => ({ ...so, modelIds: [...(spellings.get(so.operator.id) ?? [so.modelId])].sort() }),
        )

        // A multi-member group is never id-keyed: an id key is one row's own
        // wire id, unique per row. The 'id' arm keeps the expression total.
        const identityBasis: AnyRow['identityBasis'] = key.startsWith('digest:')
            ? 'digest'
            : key.startsWith('src:')
              ? 'source'
              : key.startsWith('canonical:')
                ? 'canonical'
                : 'id'
        // A spelling the fleet already publishes unqualified, so the row reads
        // like its siblings; else the declared repo; else the first spelling.
        // Taken from the merged set, never the primary, which is only the
        // cheapest member and would move the label when prices move.
        const declaredSource = servingOperators.map((s) => s.modelInfo?.source).find((s): s is string => !!s)
        const memberSpellings = [...new Set(members.map((m) => m.modelId))].sort()
        const displayModelId =
            memberSpellings.find((s) => !s.includes('/')) ??
            (identityBasis === 'source' && declaredSource ? stripSourceScheme(declaredSource) : memberSpellings[0]!)

        const { weightsMismatch, weightsConsensus } = deriveWeightsConsensus(servingOperators)
        out.push({
            ...primary,
            displayModelId,
            identityBasis,
            servingOperators,
            weightsMismatch,
            weightsConsensus,
            // AND, not the primary's: a merge unions the members' node sets, so
            // the cheapest spelling's attested fleet mustn't vouch for a peer's.
            teeAttestedOnly: members.every((m) => m.teeAttestedOnly),
        })
    }
    return out
}

/**
 * Shorten every label to the bare model name, dropping the publisher org, so a
 * list sorts by model rather than by publisher. Bare names that collide across
 * publishers (a finetune and its base) keep their qualified labels, and only
 * those do. Identity is untouched. Mutates rows not yet observed.
 */
function applyDisplayLabels(rows: Array<{ displayModelId: string }>): void {
    const bare = (label: string): string => {
        const slash = label.lastIndexOf('/')
        return slash >= 0 ? label.slice(slash + 1) : label
    }
    const counts = new Map<string, number>()
    for (const row of rows) {
        const key = bare(row.displayModelId).toLowerCase()
        counts.set(key, (counts.get(key) ?? 0) + 1)
    }
    for (const row of rows) {
        const short = bare(row.displayModelId)
        if ((counts.get(short.toLowerCase()) ?? 0) === 1) row.displayModelId = short
    }
}

// One entry per operator id, keeping the best-reachability node (ties to the
// lowest node id) so the representative is the usable one and the choice is
// stable; id-ascending.
function collapseByOperator<S extends { operator: CatalogNodeIdentity; reachability: Reachability }>(
    entries: readonly S[],
): S[] {
    const byOperator = new Map<bigint, S>()
    for (const e of entries) {
        const prev = byOperator.get(e.operator.id)
        if (
            prev === undefined ||
            REACHABILITY_RANK[e.reachability] < REACHABILITY_RANK[prev.reachability] ||
            (REACHABILITY_RANK[e.reachability] === REACHABILITY_RANK[prev.reachability] &&
                e.operator.nodeId < prev.operator.nodeId)
        ) {
            byOperator.set(e.operator.id, e)
        }
    }
    return [...byOperator.values()].sort((a, b) =>
        a.operator.id < b.operator.id ? -1 : a.operator.id > b.operator.id ? 1 : 0,
    )
}

// The digest the most distinct owners advertise for modelId, across every node.
// Owners, not nodes: one owner's five nodes are one opinion.
function peerWeightsConsensus(
    rows: readonly CatalogNodeRow<CatalogNodeIdentity, UniqueModelInfo, unknown>[],
    modelId: string,
): string | undefined {
    return weightsConsensus(
        rows.map((row): DigestClaim => {
            const claim: DigestClaim = {}
            if (row.operator.ownerAddr !== undefined) claim.owner = row.operator.ownerAddr
            const digest = row.modelInfos.get(modelId)?.weightsDigest
            if (digest !== undefined) claim.digest = digest
            return claim
        }),
    )
}

// The declared repo as written, minus the hf: scheme and any @revision: a label,
// so case is kept (sourceIdentityKey lowercases for comparison).
function stripSourceScheme(source: string): string {
    const noScheme = source.startsWith('hf:') ? source.slice(3) : source
    const at = noScheme.indexOf('@')
    return at >= 0 ? noScheme.slice(0, at) : noScheme
}
