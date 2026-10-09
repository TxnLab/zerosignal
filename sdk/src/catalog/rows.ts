/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The rules a payer's model picker ranks its unique-model rows by: which row an
// automatic pick lands on, which spellings a row covers, and the advisory
// weights summary across its serving nodes. Client-side only: the proxy has no
// picker, so none of this has a Go twin and no golden vector pins it.
//
// The types here are the fields these rules read, so an app's own row type
// passes as long as it carries them.

/**
 * A node's live probe verdict as the catalog reads it: still probing, usable,
 * on an incompatible protocol version, failing its probe, or unreachable
 * because no relay would carry the probe.
 */
export type Reachability = 'probing' | 'ok' | 'incompatible' | 'failing' | 'no-relay'

/**
 * Which node best represents its operator among siblings; lower is better.
 * 'incompatible' is last on purpose, so an operator whose every node is
 * incompatible still surfaces with a reason rather than being shadowed by a
 * transient 'failing' sibling.
 */
export const REACHABILITY_RANK: Readonly<Record<Reachability, number>> = Object.freeze({
    ok: 0,
    probing: 1,
    'no-relay': 2,
    failing: 3,
    incompatible: 4,
})

/** The model fields the ranking rules read, in the app's parsed (camelCase) shape. */
export interface RankedModelInfo {
    inputUsdPer1m?: number | undefined
    outputUsdPer1m?: number | undefined
    imageToolRateMicroUsdc?: number | undefined
    imageEditToolRateMicroUsdc?: number | undefined
    tags?: readonly string[] | undefined
    weightsDigest?: string | undefined
}

/** A unique-model row as the ranking rules read it. */
export interface RankedRow {
    /** The default operator's own wire id for the model. */
    modelId: string
    /** The operator id: on-chain uint64, a bigint in an app that keeps it exact. */
    defaultOperator: { id: bigint | number }
    defaultModelInfo: RankedModelInfo | null
}

/** A row as `rowServesWireId` reads it: every serving operator's spellings. */
export interface SpelledRow {
    modelId: string
    servingOperators: ReadonlyArray<{ modelIds: readonly string[] }>
}

/**
 * The domain-specialist tags. A model carrying one is tuned to one domain and
 * is a poor general-purpose default, so an automatic pick ranks it last. The
 * maturity tags (`nsfw`, `uncensored`) describe content, not a domain, and are
 * deliberately not here.
 */
export const SPECIALIST_TAGS: ReadonlySet<string> = new Set(['medical', 'x-ray', 'code'])

/** Whether the model advertises a domain-specialist tag, matched case-insensitively. */
export function modelInfoIsSpecialist(info: Pick<RankedModelInfo, 'tags'> | null | undefined): boolean {
    return (info?.tags ?? []).some((t) => SPECIALIST_TAGS.has(t.toLowerCase()))
}

/**
 * Whether the model offers an in-loop image tool (`zs_image_generation` or
 * `zs_image_edit`), read off a positive per-image tool rate. The dedicated
 * image routes' rate is a different field and says nothing about the tools.
 */
export function modelInfoOffersImageTools(
    info: Pick<RankedModelInfo, 'imageToolRateMicroUsdc' | 'imageEditToolRateMicroUsdc'> | null | undefined,
): boolean {
    if (!info) return false
    const pos = (v: unknown): boolean => typeof v === 'number' && Number.isFinite(v) && v > 0
    return pos(info.imageToolRateMicroUsdc) || pos(info.imageEditToolRateMicroUsdc)
}

/**
 * Orders rows for an automatic pick: image-tool capability (only when
 * `preferImageTools`), then general before specialist, then input price, then
 * output price, then operator id, then model id. An unpriced row sorts after
 * every priced one on each price axis.
 *
 * Image tools rank above price so that, with the setting on, a pick can't
 * silently land on a toolless operator. The specialist rule is a preference,
 * not a filter: a catalog of only specialists still resolves, but a free
 * specialist can't win every general pick and pull all general traffic onto
 * one operator. It ranks below image tools because that setting is the user's
 * and this is a default.
 */
export function compareUniqueModelRows(a: RankedRow, b: RankedRow, preferImageTools = false): number {
    if (preferImageTools) {
        const aTools = modelInfoOffersImageTools(a.defaultModelInfo)
        const bTools = modelInfoOffersImageTools(b.defaultModelInfo)
        if (aTools !== bTools) return aTools ? -1 : 1
    }
    const aSpec = modelInfoIsSpecialist(a.defaultModelInfo)
    const bSpec = modelInfoIsSpecialist(b.defaultModelInfo)
    if (aSpec !== bSpec) return aSpec ? 1 : -1
    const byIn = comparePrice(a.defaultModelInfo?.inputUsdPer1m, b.defaultModelInfo?.inputUsdPer1m)
    if (byIn !== 0) return byIn
    const byOut = comparePrice(a.defaultModelInfo?.outputUsdPer1m, b.defaultModelInfo?.outputUsdPer1m)
    if (byOut !== 0) return byOut
    if (a.defaultOperator.id < b.defaultOperator.id) return -1
    if (a.defaultOperator.id > b.defaultOperator.id) return 1
    if (a.modelId < b.modelId) return -1
    if (a.modelId > b.modelId) return 1
    return 0
}

function comparePrice(a: number | undefined, b: number | undefined): number {
    const aHas = typeof a === 'number'
    const bHas = typeof b === 'number'
    if (aHas && bHas) return a === b ? 0 : a - b
    if (aHas !== bHas) return aHas ? -1 : 1
    return 0
}

/** The row `compareUniqueModelRows` ranks first, or null for none. */
export function pickColdStartDefault<R extends RankedRow>(rows: readonly R[], preferImageTools = false): R | null {
    if (rows.length === 0) return null
    let best = rows[0]!
    for (let i = 1; i < rows.length; i++) {
        if (compareUniqueModelRows(rows[i]!, best, preferImageTools) < 0) best = rows[i]!
    }
    return best
}

/**
 * Whether `wireId` is the row's own id or the spelling one of its serving
 * operators uses. A row merging several spellings of one model can be named
 * by any of them, so a lookup by committed id must go through this.
 */
export function rowServesWireId(row: SpelledRow, wireId: string): boolean {
    return row.modelId === wireId || row.servingOperators.some((s) => s.modelIds.includes(wireId))
}

/**
 * The advisory weights summary a picker shows for a row, voted by its serving
 * operators (one representative node each): only reachable ('ok') operators'
 * non-empty digests vote, so an unusable peer's stale digest can't raise a
 * caution among the operators the user can pick. Two or more distinct digests
 * are a mismatch; exactly one is the consensus. Display only: the routing vote
 * that demotes a default operator is zs-proto's steering weightsConsensus,
 * which counts owners and never reads this.
 */
export function deriveWeightsConsensus(
    servingOperators: ReadonlyArray<{
        modelInfo: Pick<RankedModelInfo, 'weightsDigest'> | null
        reachability: Reachability
    }>,
): { weightsMismatch: boolean; weightsConsensus?: string } {
    const digests = new Set<string>()
    for (const op of servingOperators) {
        if (op.reachability !== 'ok') continue
        const d = op.modelInfo?.weightsDigest
        if (d) digests.add(d)
    }
    if (digests.size >= 2) return { weightsMismatch: true }
    if (digests.size === 1) return { weightsMismatch: false, weightsConsensus: [...digests][0]! }
    return { weightsMismatch: false }
}
