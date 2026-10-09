/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Which nodes a bounded discovery cycle probes, and the recently requested
// models that steer the choice. Mirrors proto/go/zs's probeSelection and
// RecordModelDemand (registry_dynamic.go), pinned by
// testdata/probe_set_vectors.json. Go keeps the cursor and the demand list on
// its registry provider; here the caller holds both, since an app decides when
// a cycle starts.

/** The fields probe selection reads off a node. */
export interface ProbeNode {
    op: bigint | number
    node: bigint | number
    /** On-chain time-to-first-token EWMA in ms; 0 or absent is no signal. */
    ttftEwmaMs?: bigint | number | undefined
    /** On-chain decode throughput EWMA in tokens/s; 0 or absent adds nothing. */
    tokensPerSecEwma?: bigint | number | undefined
    /** The model ids this node was last seen serving. */
    models: readonly string[]
}

/** The probe set for one cycle and the sweep cursor the next cycle starts from. */
export interface ProbeSelection<N> {
    /** The nodes to probe, or null to probe every node. */
    probe: N[] | null
    cursor: number
}

const U64_MAX = (1n << 64n) - 1n
// Decode tokens the throughput term prices, independent of routing's banding
// constant: choosing which nodes to re-probe is not choosing where to route.
const PROBE_DECODE_NORM_TOKENS = 128n

/**
 * The probe-priority key, lower first: on-chain TTFT plus the time to decode
 * 128 tokens, in uint64 integer arithmetic as Go computes it. A node with no
 * TTFT signal sorts last.
 */
export function probeResponsivenessScore(n: Pick<ProbeNode, 'ttftEwmaMs' | 'tokensPerSecEwma'>): bigint {
    const ttft = BigInt(n.ttftEwmaMs ?? 0)
    if (ttft === 0n) return U64_MAX
    const tps = BigInt(n.tokensPerSecEwma ?? 0)
    const score = tps > 0n ? ttft + (PROBE_DECODE_NORM_TOKENS * 1000n) / tps : ttft
    return BigInt.asUintN(64, score)
}

/**
 * The nodes to probe this cycle, bounded by `budget`: each recently demanded
 * model's fastest servers (at most `targetTopK` each, up to three quarters of
 * the budget), then a round-robin sweep from `cursor` that fills the rest, so
 * every node is eventually re-probed and new models found. A fleet within the
 * budget, or no budget, probes every node and leaves the cursor alone.
 *
 * `nodes` must be in (op, node) order and `demand` most recent first. The
 * cursor advances by the nodes the sweep scanned, including ones demand had
 * already chosen.
 */
export function selectProbeSet<N extends ProbeNode>(
    nodes: readonly N[],
    demand: readonly string[],
    budget: number,
    targetTopK: number,
    cursor: number,
): ProbeSelection<N> {
    if (budget <= 0 || nodes.length <= budget) return { probe: null, cursor }
    // At least 1 for any budget past the early return above.
    const demandCap = budget - Math.floor(budget / 4)
    const chosen = new Map<string, N>()
    const add = (n: N) => {
        const key = `${n.op}/${n.node}`
        if (!chosen.has(key)) chosen.set(key, n)
    }
    for (const model of demand) {
        if (chosen.size >= demandCap) break
        const servers = nodes
            .filter((n) => n.models.includes(model))
            .map((n) => ({ n, score: probeResponsivenessScore(n) }))
            .sort((a, b) => (a.score < b.score ? -1 : a.score > b.score ? 1 : 0))
        for (let i = 0; i < servers.length && i < targetTopK && chosen.size < demandCap; i++) add(servers[i]!.n)
    }
    const total = nodes.length
    let scanned = 0
    for (; scanned < total && chosen.size < budget; scanned++) add(nodes[(cursor + scanned) % total]!)
    return { probe: [...chosen.values()], cursor: (cursor + scanned) % total }
}

/** How many recently requested models steer probing, as Go's defaultDemandMax. */
export const DEFAULT_DEMAND_MAX = 32

/**
 * The recently requested models, most recent first, bounded to `max` (0 is
 * unbounded). Record each request's model so the next cycle keeps its fastest
 * servers fresh.
 */
export class ModelDemand {
    // Insertion order is recency: a repeat is deleted and re-added at the end.
    private readonly models = new Map<string, true>()

    constructor(private readonly max = DEFAULT_DEMAND_MAX) {}

    record(model: string): void {
        if (model === '') return
        this.models.delete(model)
        this.models.set(model, true)
        if (this.max > 0 && this.models.size > this.max) {
            const oldest = this.models.keys().next().value
            if (oldest !== undefined) this.models.delete(oldest)
        }
    }

    /** The recorded models, most recent first. */
    snapshot(): string[] {
        return [...this.models.keys()].reverse()
    }

    /** Forgets every recorded model. */
    clear(): void {
        this.models.clear()
    }
}
