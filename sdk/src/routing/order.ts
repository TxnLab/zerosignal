/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The post-passes a price-ordered candidate list goes through before dispatch,
// mirroring orderCandidates in proto/go/zs/dispatch.go and pinned by the
// post_pass cases in testdata/banding_vectors.json. The order is the policy:
// responsiveness banding first, then the weights demotion, then the backoff
// demotion, so a node that keeps failing goes behind one whose weights are
// contradicted, and both still count toward the banding median.

import { type BandingInput, type RankDetail, type ResponsivenessMode, rankByResponsiveness } from './banding.js'

export interface CandidateOrderInput extends BandingInput {
    /**
     * The candidate advertises a weights digest that contradicts the peer
     * consensus for its model (`contradictsWeightsConsensus` in
     * `@txnlab/zs-proto/steering`). The caller votes over every operator it
     * knows, not just the candidates. No pin is exempt.
     */
    contradicted: boolean
    /** The candidate is in a dispatch-failure backoff window, or otherwise known down. */
    backedOff: boolean
    /**
     * Exempt from the backoff demotion. Go's proxy sets it on its tool-affinity
     * pin, the node holding the tool loop's KV cache. A pin that only expresses
     * a preference should leave it unset, so a node that just failed yields to
     * its peers.
     */
    backoffPinned?: boolean | undefined
}

/**
 * Stable partition: the items `demote` rejects keep their order ahead of the
 * ones it accepts, which keep theirs.
 */
function demoteWhere<T>(list: readonly T[], demote: (item: T) => boolean): T[] {
    const ok: T[] = []
    const demoted: T[] = []
    for (const item of list) (demote(item) ? demoted : ok).push(item)
    return [...ok, ...demoted]
}

/**
 * Orders a price-ordered candidate list for dispatch: responsiveness bands
 * (price within band, the banding pin first), then contradicted weights to the
 * tail, then backed-off nodes to the tail. Demote, never drop: a model only one
 * node serves must stay reachable as a last resort.
 */
export function orderCandidates<T>(
    list: readonly T[],
    inputOf: (item: T) => CandidateOrderInput,
    mode: ResponsivenessMode,
): T[] {
    return orderCandidatesDetailed(list, inputOf, mode).list
}

/**
 * orderCandidatesDetailed is orderCandidates with the banding behind it:
 * details is null when no banding ran, and its index is into list.
 */
export function orderCandidatesDetailed<T>(
    list: readonly T[],
    inputOf: (item: T) => CandidateOrderInput,
    mode: ResponsivenessMode,
): { list: T[]; details: RankDetail[] | null } {
    const inputs = list.map(inputOf)
    const { order, details } = rankByResponsiveness(inputs, mode)
    const weighed = demoteWhere(order, (i) => inputs[i]!.contradicted)
    const final = demoteWhere(weighed, (i) => inputs[i]!.backedOff && inputs[i]!.backoffPinned !== true)
    return { list: final.map((i) => list[i]!), details }
}
