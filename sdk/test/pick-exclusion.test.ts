/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// An excluded node stays off both continuation pins, porting go/zs
// malicious_nodes_dispatch_test.go's TestPickCandidates_ExcludedNodeOffContinuationPins.
// The exclusion fires in the settle of a turn whose response id and tool-call
// ids are already recorded, so the next continuation is exactly the request
// that would otherwise reach the node.

import { describe, expect, it } from 'vitest'

import { extractRoutingPreferences } from '@txnlab/zs-proto/selection'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'

import { IDAffinity } from '../src/affinity.js'
import type { Operator } from '../src/operator.js'
import { type PickDeps, pickCandidates } from '../src/pick.js'
import type { LogAttrs } from '../src/ports.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import { testOperator } from './fixtures.js'

const MODEL = 'm'

function op(id: number): Operator {
    return testOperator({ id, nodeId: 0, ownerAddr: `OWNER${id}`, models: [MODEL], protoVersion: PROTO_VERSION })
}

function setup(policy: PickDeps['affinityPolicy'], ops = [op(1), op(7)]) {
    const nodeExclusions = new NodeExclusionStore()
    nodeExclusions.excludeNode({ op: 7, node: 0 })
    const debug: [string, LogAttrs | undefined][] = []
    const deps: PickDeps = {
        registry: {
            operators: async () => ops,
            resolve: async (r) => ops.find((o) => o.id === r.op && o.nodeId === r.node),
            allOperators: async () => ops,
            reprobeEphemeral: async () => null,
            recordModelDemand: () => {},
        },
        toolAffinity: new IDAffinity(16, 60_000),
        responseAffinity: new IDAffinity(16, 60_000),
        affinityPolicy: policy,
        allowStaging: false,
        nodeExclusions,
        logger: { debug: (m, a) => debug.push([m, a]), info() {}, warn() {}, error() {} },
        weightsWarned: new Set(),
    }
    deps.responseAffinity.record({ op: 7, node: 0 }, ['rid'])
    deps.toolAffinity.record({ op: 7, node: 0 }, ['call_1'])
    return { deps, debug }
}

const request = (endpoint: '/v1/responses' | '/v1/chat/completions', body: string) => ({
    endpoint,
    model: MODEL,
    body,
    sizing: { model: MODEL, inputTokens: 100, maxOutputTokens: 100, inputTokensV2: 0, deriveMaxOutput: false, maxOutputCeiling: 0 },
    requireTee: false,
    toolBudgets: { generationMaxN: 0, editMaxN: 0 },
    prefs: extractRoutingPreferences('{}'),
})

describe('an excluded node and the continuation pins', () => {
    it('blocks a previous_response_id pinned to it, whatever the policy', async () => {
        for (const policy of ['none', 'prefer', 'strict'] as const) {
            const { deps } = setup(policy)
            const res = await pickCandidates(
                deps,
                request('/v1/responses', `{"model":"${MODEL}","previous_response_id":"rid","input":[]}`),
            )
            expect(res.affinityBlocked).toBe(true)
            expect(res.operators).toEqual([])
            expect(res.affinityBlockReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 node 0, which this payer excluded for handing it a fraudulent settle group; start a new conversation',
            )
        }
    })

    // An excluded node behind the newest pin ends the walk; the older pin behind
    // it, to a live node, is not consulted.
    it('stops at an excluded newest pin rather than taking an older one', async () => {
        const { deps } = setup('prefer', [op(1), op(2), op(7)])
        deps.toolAffinity.record({ op: 2, node: 0 }, ['call_old'])
        const res = await pickCandidates(
            deps,
            request(
                '/v1/chat/completions',
                `{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"call_old"},{"role":"tool","tool_call_id":"call_1"}]}`,
            ),
        )
        expect(res.operators.map((o) => o.id)).toEqual([1, 2])
    })

    it('reads a tool-call pin to it as no preference, under strict too', async () => {
        for (const policy of ['prefer', 'strict'] as const) {
            const { deps, debug } = setup(policy)
            const res = await pickCandidates(
                deps,
                request('/v1/chat/completions', `{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"call_1"}]}`),
            )
            expect(res.affinityBlocked).toBe(false)
            expect(res.operators.map((o) => o.id)).toEqual([1])
            expect(debug).toContainEqual(['affinity-preferred node is excluded', { operator_id: 7, node_id: 0 }])
        }
    })
})
