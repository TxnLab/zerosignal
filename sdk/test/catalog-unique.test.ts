/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, expect, it, vi } from 'vitest'

import type { Operator as SelectionOperator } from '@txnlab/zs-proto/selection'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'

import {
    type CatalogNodeIdentity,
    type CatalogNodeRow,
    type Reachability,
    type UniqueModelDeps,
    type UniqueModelInfo,
    buildUniqueModelRows,
    rowIdentityKey,
    rowsByWireId,
    uniqueModelRowVariants,
} from '../src/catalog/index.js'

type Row = CatalogNodeRow<CatalogNodeIdentity, UniqueModelInfo, string> & { attested?: boolean; staging?: boolean }

function node(
    op: number,
    nodeId: number,
    models: Record<string, UniqueModelInfo>,
    extra: { owner?: string; reachability?: Reachability; attested?: boolean; recipient?: string; staging?: boolean } = {},
): Row {
    return {
        operator: { id: BigInt(op), nodeId: BigInt(nodeId), ownerAddr: extra.owner ?? `OWNER${op}` },
        models: Object.keys(models),
        modelInfos: new Map(Object.entries(models)),
        reachability: extra.reachability ?? 'ok',
        protoVersion: PROTO_VERSION,
        builtinTools: [`tool-${op}-${nodeId}`],
        ephemeralRecipient: extra.recipient,
        attested: extra.attested ?? false,
        staging: extra.staging ?? false,
    }
}

const price = (input: number, extra: Partial<UniqueModelInfo> = {}): UniqueModelInfo => ({
    inputUsdPer1m: input,
    outputUsdPer1m: input,
    ...extra,
})

function toSelectionOperator(row: Row): SelectionOperator {
    return {
        id: Number(row.operator.id),
        node_id: Number(row.operator.nodeId),
        owner_addr: row.operator.ownerAddr ?? '',
        base_url: `https://n${row.operator.id}-${row.operator.nodeId}.example`,
        proto_version: row.protoVersion ?? '',
        reachable: row.reachability === 'ok',
        tee_attested: false,
        staging: row.staging === true,
        models: [...row.models],
        model_capacities: Object.fromEntries(
            [...row.modelInfos].map(([id, info]) => [
                id,
                {
                    context_window: 128_000,
                    max_output_tokens: 4096,
                    serves_image_gen: false,
                    serves_image_edit: false,
                    offers_image_gen_tool: (info.imageToolRateMicroUsdc ?? 0) > 0,
                    offers_image_edit_tool: false,
                    input_usd_per_1m: info.inputUsdPer1m ?? 0,
                    output_usd_per_1m: info.outputUsdPer1m ?? 0,
                    image_rate_micro_usdc: 0,
                    image_edit_rate_micro_usdc: 0,
                },
            ]),
        ),
        builtin_tools: [],
    }
}

const deps: UniqueModelDeps<Row, { nodeTag: string }> = {
    toSelectionOperator,
    displayAttested: (row) => row.attested === true,
    servingExtras: (row) => ({ nodeTag: `${row.operator.id}:${row.operator.nodeId}` }),
}

const build = (rows: Row[], opts = {}, candidates = rows) => buildUniqueModelRows(rows, candidates, opts, deps)

describe('buildUniqueModelRows', () => {
    it('picks the cheapest node as the default and lists one entry per operator, id-ascending', () => {
        const rows = [
            node(3, 0, { m: price(5) }),
            node(1, 0, { m: price(4) }, { reachability: 'failing' }),
            node(1, 1, { m: price(9) }),
            node(2, 0, { m: price(2) }, { recipient: 'age1x' }),
        ]
        const [row] = build(rows)
        expect(row!.defaultOperator.id).toBe(2n)
        expect(row!.defaultEphemeralRecipient).toBe('age1x')
        expect(row!.defaultBuiltinTools).toEqual(['tool-2-0'])
        expect(row!.servingOperators.map((s) => s.nodeTag)).toEqual(['1:1', '2:0', '3:0'])
        expect(row!.servingOperators[0]!.builtinTools).toEqual(['tool-1-1'])
        expect(row!.identityBasis).toBe('id')
    })

    it('breaks a reachability tie on the lowest node id', () => {
        const [row] = build([node(1, 4, { m: price(1) }), node(1, 2, { m: price(1) })])
        expect(row!.servingOperators.map((s) => s.nodeTag)).toEqual(['1:2'])
    })

    it('demotes a default whose digest contradicts the peer consensus, voting over the whole catalog', () => {
        const rows = [
            node(1, 0, { m: price(1, { weightsDigest: 'bad' }) }),
            node(2, 0, { m: price(2, { weightsDigest: 'good' }) }),
            // Held out of the candidates, still a vote.
            node(3, 0, { m: price(3, { weightsDigest: 'good' }) }),
        ]
        const [row] = build(rows, {}, rows.slice(0, 2))
        expect(row!.defaultOperator.id).toBe(2n)
    })

    it('falls back to a contradicted default when every candidate contradicts', () => {
        const rows = [
            node(1, 0, { m: price(1, { weightsDigest: 'bad' }) }),
            node(2, 0, { m: price(2, { weightsDigest: 'good' }) }),
            node(3, 0, { m: price(3, { weightsDigest: 'good' }) }),
        ]
        const [row] = build(rows, {}, rows.slice(0, 1))
        expect(row!.defaultOperator.id).toBe(1n)
    })

    it('falls back to the FIRST-ranked contradicted candidate, not the last', () => {
        const rows = [
            node(1, 0, { m: price(1, { weightsDigest: 'bad' }) }),
            node(2, 0, { m: price(2, { weightsDigest: 'worse' }) }),
            node(3, 0, { m: price(3, { weightsDigest: 'good' }) }),
            node(4, 0, { m: price(4, { weightsDigest: 'good' }) }),
        ]
        const [row] = build(rows, {}, rows.slice(0, 2))
        expect(row!.defaultOperator.id).toBe(1n)
    })

    it('counts one owner running several nodes as one vote', () => {
        // Owner A's three nodes advertise X; owners B and C advertise Y. Counted
        // by node, X would win and demote B, the cheapest.
        const rows = [
            node(2, 0, { m: price(1, { weightsDigest: 'Y' }) }, { owner: 'B' }),
            node(1, 0, { m: price(2, { weightsDigest: 'X' }) }, { owner: 'A' }),
            node(1, 1, { m: price(2, { weightsDigest: 'X' }) }, { owner: 'A' }),
            node(1, 2, { m: price(2, { weightsDigest: 'X' }) }, { owner: 'A' }),
            node(3, 0, { m: price(3, { weightsDigest: 'Y' }) }, { owner: 'C' }),
        ]
        expect(build(rows)[0]!.defaultOperator.id).toBe(2n)
    })

    it('skips a ranked node that lists the model without declaring it', () => {
        // Reachable through the SDK API, where models and modelInfos are
        // independent: node 1 ranks first but carries no ModelInfo for m.
        const rows = [{ ...node(1, 0, { m: price(1) }), modelInfos: new Map() }, node(2, 0, { m: price(5) })]
        const projectWithPrice: typeof deps = {
            ...deps,
            toSelectionOperator: (r) => (r === rows[0] ? toSelectionOperator(node(1, 0, { m: price(1) })) : toSelectionOperator(r)),
        }
        const out = buildUniqueModelRows(rows, rows, {}, projectWithPrice)
        expect(out[0]!.defaultOperator.id).toBe(2n)
    })

    it('breaks a case-insensitive label tie on the wire id', () => {
        const out = build([node(1, 0, { 'org/m': price(1), 'Org/M': price(1) })])
        expect(out.map((r) => r.modelId)).toEqual(['Org/M', 'org/m'])
    })

    it('reads teeAttestedOnly per node, before the operator collapse', () => {
        const mixed = build([node(1, 0, { m: price(1) }, { attested: true }), node(1, 1, { m: price(1) })])
        expect(mixed[0]!.teeAttestedOnly).toBe(false)
        const all = build([node(1, 0, { m: price(1) }, { attested: true }), node(1, 1, { m: price(1) }, { attested: true })])
        expect(all[0]!.teeAttestedOnly).toBe(true)
    })

    it('drops a model no allowed operator serves', () => {
        const rows = [node(1, 0, { a: price(1) }), node(2, 0, { b: price(1) })]
        const out = build(rows, {
            constraints: { only: [{ operator_id: 2, node_id: 0, match_all_nodes: true }], allow_fallbacks: true },
        })
        expect(out.map((r) => r.modelId)).toEqual(['b'])
    })

    it('prefers an image-tool node as the default only when asked', () => {
        const rows = [node(1, 0, { m: price(1) }), node(2, 0, { m: price(5, { imageToolRateMicroUsdc: 80_000 }) })]
        expect(build(rows)[0]!.defaultOperator.id).toBe(1n)
        expect(build(rows, { preferImageTools: true })[0]!.defaultOperator.id).toBe(2n)
    })

    it('keeps a staging node as a default only when staging is allowed', () => {
        const rows = [node(1, 0, { m: price(1), solo: price(1) }, { staging: true }), node(2, 0, { m: price(5) })]
        const off = build(rows)
        expect(off.map((r) => [r.modelId, r.defaultOperator.id])).toEqual([['m', 2n]])
        const on = build(rows, { allowStaging: true })
        expect(on.map((r) => [r.modelId, r.defaultOperator.id])).toEqual([
            ['m', 1n],
            ['solo', 1n],
        ])
    })

    it('strips the publisher org only where the bare name is unambiguous, and sorts by label', () => {
        const out = build([
            node(1, 0, { 'zai-org/GLM-5.2': price(1), 'unsloth/llama-8b': price(1), 'meta/llama-8b': price(1), 'glm-5': price(1) }),
        ])
        expect(out.map((r) => r.displayModelId)).toEqual(['glm-5', 'GLM-5.2', 'meta/llama-8b', 'unsloth/llama-8b'])
        expect(out.map((r) => r.modelId)).toContain('zai-org/GLM-5.2')
    })
})

describe('buildUniqueModelRows with unifyEquivalent', () => {
    const glm = (op: number, id: string, input: number, extra: Partial<UniqueModelInfo> = {}, opts = {}) =>
        node(op, 0, { [id]: price(input, { source: 'hf:zai-org/GLM-5.2', ...extra }) }, opts)

    it('merges spellings that declare one source, keeping each operator its own wire id', () => {
        const out = build(
            [glm(1, 'zai-org/GLM-5.2', 3), glm(2, 'glm-5.2', 1), node(1, 1, { 'glm-5.2': price(9, { source: 'hf:zai-org/GLM-5.2' }) })],
            { unifyEquivalent: true },
        )
        expect(out).toHaveLength(1)
        const row = out[0]!
        expect(row.identityBasis).toBe('source')
        expect(row.modelId).toBe('glm-5.2')
        expect(row.defaultOperator.id).toBe(2n)
        expect(row.displayModelId).toBe('glm-5.2')
        expect(row.servingOperators.map((s) => [s.operator.id, s.modelId, s.modelIds])).toEqual([
            [1n, 'zai-org/GLM-5.2', ['glm-5.2', 'zai-org/GLM-5.2']],
            [2n, 'glm-5.2', ['glm-5.2']],
        ])
    })

    it('labels a merge of qualified spellings with the declared repo', () => {
        const out = build([glm(1, 'zai-org/GLM-5.2', 1), glm(2, 'zai/glm-5.2', 2)], { unifyEquivalent: true })
        // One row, so the label pass shortens the repo to its bare name.
        expect(out.map((r) => r.displayModelId)).toEqual(['GLM-5.2'])
    })

    it('leads a merge with the image-tool spelling only when asked', () => {
        const rows = [glm(1, 'glm-5.2', 1), glm(2, 'zai-org/GLM-5.2', 5, { imageToolRateMicroUsdc: 80_000 })]
        expect(build(rows, { unifyEquivalent: true })[0]!.modelId).toBe('glm-5.2')
        expect(build(rows, { unifyEquivalent: true, preferImageTools: true })[0]!.modelId).toBe('zai-org/GLM-5.2')
    })

    it('merges on a shared digest and labels it with a spelling, never the declared repo', () => {
        const out = build(
            [
                node(1, 0, { 'b-org/m': price(1, { weightsDigest: 'dd', source: 'hf:real/Repo' }) }),
                node(2, 0, { 'a-org/m': price(2, { weightsDigest: 'dd' }) }),
            ],
            { unifyEquivalent: true },
        )
        expect(out).toHaveLength(1)
        expect(out[0]!.identityBasis).toBe('digest')
        // Every spelling is qualified, so the first one names the row, shortened.
        expect(out[0]!.displayModelId).toBe('m')
        expect(out[0]!.modelId).toBe('b-org/m')
    })

    it('takes the label from the first spelling alphabetically, not the cheapest', () => {
        const out = build(
            [
                node(1, 0, { 'z-org/m': price(1, { weightsDigest: 'dd' }) }),
                node(2, 0, { 'a-org/m': price(2, { weightsDigest: 'dd' }) }),
                // Shares the bare name, so the merged label stays qualified.
                node(3, 0, { 'other/m': price(1) }),
            ],
            { unifyEquivalent: true },
        )
        expect(out.map((r) => [r.modelId, r.displayModelId])).toEqual([
            ['z-org/m', 'a-org/m'],
            ['other/m', 'other/m'],
        ])
    })

    it("keeps the primary's spelling for a node that serves two", () => {
        const out = build(
            [
                node(1, 0, {
                    'glm-5.2': price(1, { source: 'hf:zai-org/GLM-5.2' }),
                    'zai-org/GLM-5.2': price(3, { source: 'hf:zai-org/GLM-5.2' }),
                }),
            ],
            { unifyEquivalent: true },
        )
        const row = out[0]!
        expect(row.modelId).toBe('glm-5.2')
        expect(row.servingOperators.map((s) => [s.modelId, s.modelInfo?.inputUsdPer1m, s.modelIds])).toEqual([
            ['glm-5.2', 1, ['glm-5.2', 'zai-org/GLM-5.2']],
        ])
    })

    it('drops the revision from a declared-repo label', () => {
        const out = build(
            [
                node(1, 0, { 'zai-org/GLM-5.2': price(1, { source: 'hf:zai-org/GLM-5.2@main' }) }),
                node(2, 0, { 'zai/glm-5.2': price(2, { source: 'hf:zai-org/GLM-5.2@main' }) }),
                // Keeps the merged label qualified, so the strip is the label's own.
                node(3, 0, { 'x/GLM-5.2': price(1) }),
            ],
            { unifyEquivalent: true },
        )
        expect(out.map((r) => r.displayModelId)).toContain('zai-org/GLM-5.2')
    })

    it('merges a closed-weights model on its curated canonical', () => {
        const out = build(
            [node(1, 0, { 'x-ai/grok-4': price(1, { canonicalId: 'Grok-4' }) }), node(2, 0, { 'grok-4-latest': price(2, { canonicalId: 'grok-4' }) })],
            { unifyEquivalent: true },
        )
        expect(out.map((r) => [r.identityBasis, r.displayModelId, r.modelId])).toEqual([['canonical', 'grok-4-latest', 'x-ai/grok-4']])
    })

    it('marks a merged row attested only when every member is', () => {
        const out = build([glm(1, 'zai-org/GLM-5.2', 1, {}, { attested: true }), glm(2, 'glm-5.2', 2)], { unifyEquivalent: true })
        expect(out[0]!.teeAttestedOnly).toBe(false)
    })

    it('never merges across two digests, even with one declared source', () => {
        const out = build([glm(1, 'zai-org/GLM-5.2', 1, { weightsDigest: 'aa' }), glm(2, 'glm-5.2', 2, { weightsDigest: 'bb' })], {
            unifyEquivalent: true,
        })
        expect(out).toHaveLength(2)
    })

    it('leaves rows unmerged when not asked', () => {
        expect(build([glm(1, 'zai-org/GLM-5.2', 1), glm(2, 'glm-5.2', 2)])).toHaveLength(2)
    })

    it('does not merge two rows whose only declared source is an empty repo', () => {
        const out = build([node(1, 0, { a: price(1, { source: 'hf:' }) }), node(2, 0, { b: price(1, { source: 'hf:' }) })], {
            unifyEquivalent: true,
        })
        expect(out.map((r) => r.modelId)).toEqual(['a', 'b'])
    })
})

describe('rowIdentityKey', () => {
    const row = (modelId: string, ...infos: Array<Partial<UniqueModelInfo> | null>) => ({
        modelId,
        servingOperators: infos.map((modelInfo) => ({ modelInfo })),
    })

    it('layers digest, source, canonical, then the wire id', () => {
        expect(rowIdentityKey(row('m', { weightsDigest: 'd', source: 'hf:a/b' }))).toBe('digest:d')
        expect(rowIdentityKey(row('m', { source: 'hf:A/B@rev' }, null))).toBe('src:a/b')
        expect(rowIdentityKey(row('m', { canonicalId: 'Grok-4' }))).toBe('canonical:grok-4')
        expect(rowIdentityKey(row('m', {}))).toBe('id:m')
    })

    it('lets silence abstain and a conflict withdraw the claim', () => {
        expect(rowIdentityKey(row('m', { source: 'hf:a/b' }, {}))).toBe('src:a/b')
        expect(rowIdentityKey(row('m', { source: 'hf:a/b' }, { source: 'hf:a/c' }))).toBe('id:m')
        expect(rowIdentityKey(row('m', { weightsDigest: 'x' }, { weightsDigest: 'y' }, { source: 'hf:a/b' }))).toBe('id:m')
        expect(rowIdentityKey(row('m', { source: 'hf:a/b', canonicalId: 'p' }, { source: 'hf:a/c' }))).toBe('id:m')
    })

    it('withdraws on two canonicals, and lets an empty digest abstain', () => {
        expect(rowIdentityKey(row('m', { canonicalId: 'a' }, { canonicalId: 'b' }))).toBe('id:m')
        expect(rowIdentityKey(row('m', { weightsDigest: '' }, { weightsDigest: 'd1' }))).toBe('digest:d1')
    })

    it('reads an empty declared source as no identity, and as a dissent beside a real one', () => {
        expect(rowIdentityKey(row('m', { source: 'hf:' }))).toBe('id:m')
        expect(rowIdentityKey(row('m', { source: 'hf:' }, { source: 'hf:a/b' }))).toBe('id:m')
        // Nor does it fall through to the canonical tier, which dispatch would refuse.
        expect(rowIdentityKey(row('m', { source: 'hf:', canonicalId: 'grok-4' }))).toBe('id:m')
    })
})

describe('uniqueModelRowVariants', () => {
    const rows = [
        node(1, 0, { 'x/grok': price(1) }, { attested: true }),
        node(2, 0, { 'x/grok': price(1), 'y/grok': price(1) }),
    ]

    it('returns one array for both views when attestation is already required', () => {
        const candidatesFor = vi.fn((tee: boolean) => (tee ? rows.filter((r) => r.attested) : rows))
        const out = uniqueModelRowVariants(rows, candidatesFor, true, {}, deps)
        expect(out.attestedRows).toBe(out.rows)
        expect(candidatesFor.mock.calls).toEqual([[true]])
    })

    it('labels each attested twin as its plain partner', () => {
        const out = uniqueModelRowVariants(rows, (tee) => (tee ? rows.filter((r) => r.attested) : rows), false, {}, deps)
        // Alone in the attested view, x/grok would shorten to "grok"; the plain
        // view keeps it qualified beside y/grok, and the twin follows.
        expect(out.rows.map((r) => r.displayModelId)).toEqual(['x/grok', 'y/grok'])
        expect(out.attestedRows.map((r) => r.displayModelId)).toEqual(['x/grok'])
        expect(out.attestedRows[0]!.teeAttestedOnly).toBe(true)
        expect(out.rows[0]!.teeAttestedOnly).toBe(false)
    })
})

describe('rowsByWireId', () => {
    it('indexes every spelling and keeps the first row to claim one', () => {
        const a = { modelId: 'a', servingOperators: [{ modelIds: ['a', 'shared'] }] }
        const b = { modelId: 'b', servingOperators: [{ modelIds: ['b', 'shared'] }] }
        const idx = rowsByWireId([a, b])
        expect(idx.get('shared')).toBe(a)
        expect(idx.get('b')).toBe(b)
    })

    it("keeps an earlier row's spelling against a later row's own wire id", () => {
        const a = { modelId: 'a', servingOperators: [{ modelIds: ['a', 'x'] }] }
        const x = { modelId: 'x', servingOperators: [] }
        expect(rowsByWireId([a, x]).get('x')).toBe(a)
    })
})
