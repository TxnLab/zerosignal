/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Candidate selection, porting go/zs routable_test.go, relay_pool_test.go,
// weights_trust_test.go's demotion and the pickCandidates cases of
// dispatch_routing_test.go, dispatch_tee_test.go, dispatch_version_test.go,
// dispatch_signer_test.go and dispatch_staging_test.go. The policy itself is
// the shared selectTargets, pinned by the selection vectors; these pin the
// runtime state around it.

import { describe, expect, it, vi } from 'vitest'

import {
    MIN_SIGNER_SPENDABLE_MICROALGOS,
    type OperatorRef,
    type RoutingPreferences,
    extractRoutingPreferences,
} from '@txnlab/zs-proto/selection'
import { PROTO_VERSION } from '@txnlab/zs-proto/wire'

import { IDAffinity } from '../src/affinity.js'
import type { ModelCapacity, Operator } from '../src/operator.js'
import type { RegistryProvider } from '../src/parts.js'
import {
    type PickDeps,
    type PickRequest,
    pickCandidates,
    poolMaxOutput,
    relayHopForPool,
    relayPool,
    routableIgnoringSize,
} from '../src/pick.js'
import type { LogAttrs, Logger } from '../src/ports.js'
import { TargetBackoffStore } from '../src/routing/backoff.js'
import { NodeExclusionStore } from '../src/routing/exclusion.js'
import { RelayLatencyStore } from '../src/routing/latency.js'
import { RelayReputationStore } from '../src/routing/reputation.js'
import type { SizingRequest } from '../src/sizing.js'
import type { NodeRef } from '../src/types.js'
import { testOperator } from './fixtures.js'

// A node that judges fit itself rather than deferring to its upstream (pre-9.11):
// the cases that need a size refusal use it, since a current node is offered a
// bound up to 3x its input ceiling.
const JUDGES_FIT = '9.10'

const MODEL = 'm'

function cap(over: Partial<ModelCapacity> = {}): ModelCapacity {
    return {
        contextWindow: 0,
        maxOutputTokens: 0,
        inputUsdPer1m: 0,
        outputUsdPer1m: 0,
        longContextThresholdTokens: 0,
        weightsDigest: '',
        weightsUnverifiable: false,
        source: '',
        canonicalId: '',
        retention: '',
        imageToolRateMicroUsdc: 0,
        imageEditToolRateMicroUsdc: 0,
        imageToolBaseMicroUsdc: 0,
        imageEditToolBaseMicroUsdc: 0,
        imageRateMicroUsdc: 0,
        imageEditRateMicroUsdc: 0,
        imageDefaultMicroUsdc: 0,
        imageEditDefaultMicroUsdc: 0,
        imageCapMicroUsdc: 0,
        imageEditCapMicroUsdc: 0,
        advertisesImageGen: false,
        advertisesImageEdit: false,
        vendorToolCatchAllMicroUsdc: 0,
        vendorToolCallCap: 0,
        vendorToolTokensPerCall: 0,
        ...over,
    }
}

/** A serving node: current wire version, priced, funded. */
function op(id: number, over: Partial<Operator> = {}, capOver: Partial<ModelCapacity> = {}, node = 1): Operator {
    return testOperator({
        id,
        nodeId: node,
        ownerAddr: `OWNER${id}`,
        baseUrl: `https://n${id}-${node}.example.com`,
        models: [MODEL],
        protoVersion: PROTO_VERSION,
        modelCapacities: { [MODEL]: cap({ inputUsdPer1m: 1, outputUsdPer1m: 1, ...capOver }) },
        ...over,
    })
}

const ref = (id: number): OperatorRef => ({ operator_id: id, node_id: 0, match_all_nodes: true })
const prefs = (over: Partial<RoutingPreferences> = {}): RoutingPreferences => ({ ...extractRoutingPreferences('{}'), ...over })
const sizing = (over: Partial<SizingRequest> = {}): SizingRequest => ({
    model: MODEL,
    inputTokens: 100,
    maxOutputTokens: 100,
    inputTokensV2: 0,
    deriveMaxOutput: false,
    maxOutputCeiling: 0,
    ...over,
})

function registryOf(ops: Operator[], over: Partial<RegistryProvider> = {}): RegistryProvider {
    return {
        operators: async (model) => ops.filter((o) => o.models.includes(model)),
        resolve: async (r) => ops.find((o) => o.id === r.op && o.nodeId === r.node),
        allOperators: async () => ops,
        reprobeEphemeral: async () => null,
        recordModelDemand: () => {},
        ...over,
    }
}

interface Logged {
    level: string
    msg: string
    attrs: LogAttrs | undefined
}

function deps(ops: Operator[], over: Partial<PickDeps> = {}): PickDeps & { logged: Logged[] } {
    const logged: Logged[] = []
    const at =
        (level: string) =>
        (msg: string, attrs?: LogAttrs): void => {
            logged.push({ level, msg, attrs })
        }
    const logger: Logger = { debug: at('debug'), info: at('info'), warn: at('warn'), error: at('error') }
    return {
        registry: registryOf(ops),
        toolAffinity: new IDAffinity(16, 60_000),
        responseAffinity: new IDAffinity(16, 60_000),
        affinityPolicy: 'prefer',
        allowStaging: false,
        logger,
        weightsWarned: new Set(),
        ...over,
        logged,
    }
}

function request(over: Partial<PickRequest> = {}): PickRequest {
    return {
        endpoint: '/v1/chat/completions',
        model: MODEL,
        body: `{"model":"${MODEL}"}`,
        sizing: sizing(),
        requireTee: false,
        toolBudgets: { generationMaxN: 0, editMaxN: 0 },
        prefs: prefs(),
        ...over,
    }
}

const ids = (ops: readonly Operator[]) => ops.map((o) => `${o.id}/${o.nodeId}`)
const attested = {
    mode: 'dstack-tdx',
    attestedAt: 0,
    verifierId: 'dstack-tdx',
    verified: true,
    failureTag: '',
    osImageChecked: true,
    composeReleaseChecked: true,
}

describe('routableIgnoringSize', () => {
    const cases: [string, Partial<Operator>, { allowStaging?: boolean; excluded?: boolean; requireTee?: boolean; prefs?: Partial<RoutingPreferences> }, boolean][] = [
        ['plain serving operator is routable', {}, {}, true],
        ['staging node is held out by default', { staging: true }, {}, false],
        ['staging node counts once the payer opts in', { staging: true }, { allowStaging: true }, true],
        ['node proven to have handed a fraudulent settle group', {}, { excluded: true }, false],
        ['operator speaking a different wire generation', { protoVersion: '1.0' }, {}, false],
        ['TEE required and the operator is not attested', {}, { requireTee: true }, false],
        ['TEE required and the operator is attested', { tee: attested }, { requireTee: true }, true],
        ['TEE required and the pass matched no published release', { tee: { ...attested, composeReleaseChecked: false } }, { requireTee: true }, false],
        ['signing account one microAlgo below the routing floor', { signerSpendableMicroAlgos: MIN_SIGNER_SPENDABLE_MICROALGOS - 1 }, {}, false],
        ['signing account exactly at the routing floor', { signerSpendableMicroAlgos: MIN_SIGNER_SPENDABLE_MICROALGOS }, {}, true],
        ["caller's provider.ignore excludes it", {}, { prefs: { ignore: [ref(7)] } }, false],
        ["caller's provider.only names someone else", {}, { prefs: { only: [ref(9)] } }, false],
    ]
    it.each(cases)('%s', (_, mutate, o, want) => {
        const target = op(7, mutate)
        const nodeExclusions = new NodeExclusionStore()
        if (o.excluded) nodeExclusions.excludeNode({ op: 7, node: 1 })
        const d = deps([target], { allowStaging: o.allowStaging ?? false, nodeExclusions })
        expect(routableIgnoringSize(d, target, o.requireTee ?? false, prefs(o.prefs))).toBe(want)
    })
})

describe('poolMaxOutput', () => {
    it('reads the ceiling over the routable operators only', async () => {
        // A staging node with no ceiling would switch the clamp off for everyone.
        const ops = [op(1, {}, { maxOutputTokens: 4000 }), op(2, {}, { maxOutputTokens: 8000 }), op(3, { staging: true })]
        expect(await poolMaxOutput(deps(ops), MODEL, false, prefs())).toBe(8000)
        expect(await poolMaxOutput(deps(ops, { allowStaging: true }), MODEL, false, prefs())).toBe(0)
        expect(await poolMaxOutput(deps(ops), MODEL, false, prefs({ ignore: [ref(2)] }))).toBe(4000)
    })

    it('is 0 when the registry fails', async () => {
        const d = deps([], { registry: registryOf([], { operators: () => Promise.reject(new Error('down')) }) })
        expect(await poolMaxOutput(d, MODEL, false, prefs())).toBe(0)
    })
})

describe('pickCandidates', () => {
    it('rejects with the registry', async () => {
        const d = deps([], { registry: registryOf([], { operators: () => Promise.reject(new Error('down')) }) })
        await expect(pickCandidates(d, request())).rejects.toThrow('down')
    })

    it('drops excluded nodes before counting the registry', async () => {
        const nodeExclusions = new NodeExclusionStore()
        nodeExclusions.excludeNode({ op: 2, node: 1 })
        const res = await pickCandidates(deps([op(1), op(2)], { nodeExclusions }), request())
        expect(res.registryCount).toBe(1)
        expect(ids(res.operators)).toEqual(['1/1'])
    })

    it('keeps an operator’s nodes apart', async () => {
        const res = await pickCandidates(deps([op(1, {}, {}, 1), op(1, {}, {}, 2)]), request())
        expect(ids(res.operators).sort()).toEqual(['1/1', '1/2'])
    })

    describe("the caller's provider preferences", () => {
        const three = () => [op(1), op(2), op(3)]

        it('ignore drops the named operator', async () => {
            const res = await pickCandidates(deps(three()), request({ prefs: prefs({ ignore: [ref(2)] }) }))
            expect(ids(res.operators)).toEqual(['1/1', '3/1'])
        })

        it('an only that matches nobody blocks, counting the model-serving pool', async () => {
            const res = await pickCandidates(deps(three()), request({ prefs: prefs({ only: [ref(9)] }) }))
            expect(res.providerPinBlocked).toBe(true)
            expect(res.operators).toEqual([])
            expect(res.registryCount).toBe(3)
        })

        it('a no-fallback order pins, and blocks when it matches nobody', async () => {
            let res = await pickCandidates(deps(three()), request({ prefs: prefs({ allow_fallbacks: false, order: [ref(3)] }) }))
            expect(ids(res.operators)).toEqual(['3/1'])
            res = await pickCandidates(deps(three()), request({ prefs: prefs({ allow_fallbacks: false, order: [ref(99)] }) }))
            expect(res.providerPinBlocked).toBe(true)
            expect(res.operators).toEqual([])
        })

        it('max_price filters, and blocks below everyone', async () => {
            const ops = [op(1, {}, { inputUsdPer1m: 9 }), op(2, {}, { inputUsdPer1m: 5, outputUsdPer1m: 10 }), op(3, {}, { inputUsdPer1m: 0, outputUsdPer1m: 0 })]
            let res = await pickCandidates(deps(ops), request({ prefs: prefs({ max_input_usd_per_1m: 6 }) }))
            expect(ids(res.operators)).toEqual(['2/1'])
            res = await pickCandidates(deps(ops), request({ prefs: prefs({ max_input_usd_per_1m: 1 }) }))
            expect(res.priceBlocked).toBe(true)
            expect(res.operators).toEqual([])
        })

        it('max_output_usd_per_1m caps the output rate on its own', async () => {
            const ops = [op(1, {}, { outputUsdPer1m: 10 }), op(2, {}, { inputUsdPer1m: 5, outputUsdPer1m: 4 })]
            let res = await pickCandidates(deps(ops), request({ prefs: prefs({ max_output_usd_per_1m: 5 }) }))
            expect(ids(res.operators)).toEqual(['2/1'])
            res = await pickCandidates(deps(ops), request({ prefs: prefs({ max_output_usd_per_1m: 1 }) }))
            expect(res.priceBlocked).toBe(true)
            expect(res.operators).toEqual([])
        })

        it('require_tools reads the requested tools from the body, as bytes too', async () => {
            const tool = { type: 'zs_web_search', name: 'zs_web_search' } as Operator['builtinTools'][number]
            const ops = [op(1), op(2, { builtinTools: [tool] }), op(3)]
            const body = `{"model":"${MODEL}","tools":[{"type":"zs_web_search"}]}`
            for (const b of [body, new TextEncoder().encode(body)]) {
                const res = await pickCandidates(deps(ops), request({ body: b, prefs: prefs({ require_tools: true }) }))
                expect(ids(res.operators)).toEqual(['2/1'])
            }
            const res = await pickCandidates(deps([op(1), op(3)]), request({ body, prefs: prefs({ require_tools: true }) }))
            expect(res.toolUnsupported).toBe(true)
            expect(res.operators).toEqual([])
        })
    })

    it('maps the policy diagnostics', async () => {
        let res = await pickCandidates(deps([op(1, { staging: true })]), request())
        expect(res.stagingBlocked).toBe(true)
        res = await pickCandidates(deps([op(1, { protoVersion: '1.0' })]), request())
        expect(res.versionBlocked).toBe(true)
        res = await pickCandidates(deps([op(1)]), request({ requireTee: true }))
        expect(res.teeBlocked).toBe(true)
        res = await pickCandidates(deps([op(1, { signerSpendableMicroAlgos: 0 })]), request())
        expect(res.signerUnderfundedBlocked).toBe(true)
        expect(res.signerUnderfundedReason).toBe('')
        res = await pickCandidates(deps([op(1)]), request({ endpoint: '/v1/images/generations' }))
        expect(res.imageEndpointUnsupported).toBe(true)
        res = await pickCandidates(deps([op(1, { protoVersion: JUDGES_FIT }, { contextWindow: 150 })]), request())
        expect(res.sizingMisses).toEqual([{ operator_id: 1, context_window: 150, max_output_tokens: 0, effective_max_output: 100 }])
        expect(res.operators).toEqual([])
    })

    it('derives max_output per operator when the caller omitted it, under the caller’s ceiling', async () => {
        // A flat 200k would miss both; derived, the 100k window fits, and the
        // 4k one misses at a quarter of its window clamped to the ceiling.
        const ops = [op(1, {}, { contextWindow: 100_000 }), op(2, { protoVersion: JUDGES_FIT }, { contextWindow: 4000 })]
        const s = sizing({ inputTokens: 4000, maxOutputTokens: 200_000, deriveMaxOutput: true, maxOutputCeiling: 500 })
        const res = await pickCandidates(deps(ops), request({ sizing: s }))
        expect(ids(res.operators)).toEqual(['1/1'])
        expect(res.sizingMisses).toEqual([{ operator_id: 2, context_window: 4000, max_output_tokens: 0, effective_max_output: 500 }])
    })

    it('sizes a current-wire operator by the v2 input count', async () => {
        const res = await pickCandidates(
            deps([op(1, {}, { contextWindow: 1000 })]),
            request({ sizing: sizing({ inputTokens: 950, inputTokensV2: 500 }) }),
        )
        expect(ids(res.operators)).toEqual(['1/1'])
    })

    it('ranks image-tool operators for the budget asked for', async () => {
        const gen = op(1, {}, { imageToolRateMicroUsdc: 1, inputUsdPer1m: 9, outputUsdPer1m: 9 })
        const edit = op(2, {}, { imageEditToolRateMicroUsdc: 1, inputUsdPer1m: 9, outputUsdPer1m: 9 })
        const plain = op(3)
        // Price alone would lead with the plain operator.
        let res = await pickCandidates(deps([gen, edit, plain]), request({ toolBudgets: { generationMaxN: 1, editMaxN: 0 } }))
        expect(ids(res.operators)).toEqual(['1/1', '3/1', '2/1'])
        res = await pickCandidates(deps([gen, edit, plain]), request({ toolBudgets: { generationMaxN: 0, editMaxN: 1 } }))
        expect(ids(res.operators)).toEqual(['2/1', '3/1', '1/1'])
    })

    it('routes an opted-in payer to a staging node', async () => {
        const res = await pickCandidates(deps([op(1, { staging: true })], { allowStaging: true }), request())
        expect(ids(res.operators)).toEqual(['1/1'])
        expect(res.stagingBlocked).toBe(false)
    })

    describe('a previous_response_id', () => {
        const body = `{"model":"${MODEL}","previous_response_id":"rid","input":[]}`
        const pinned = (target: Operator, others: Operator[] = [], over: Partial<PickDeps> = {}) => {
            const d = deps([target, ...others], over)
            d.responseAffinity.record({ op: target.id, node: target.nodeId }, ['rid'])
            return d
        }
        const pick = (d: PickDeps, over: Partial<PickRequest> = {}) =>
            pickCandidates(d, request({ endpoint: '/v1/responses', body, ...over }))

        it('routes to the exact node that issued it, whatever the policy', async () => {
            for (const affinityPolicy of ['prefer', 'strict', 'none'] as const) {
                const res = await pick(pinned(op(7, {}, {}, 2), [op(1), op(7, {}, {}, 1)], { affinityPolicy }))
                expect(ids(res.operators)).toEqual(['7/2'])
            }
        })

        it('is read only on /v1/responses', async () => {
            const d = pinned(op(7), [op(1)])
            const res = await pickCandidates(d, request({ body }))
            expect(ids(res.operators).sort()).toEqual(['1/1', '7/1'])
        })

        it('blocks on a miss, with the reason', async () => {
            const d = deps([op(7)])
            const res = await pick(d)
            expect(res.affinityBlocked).toBe(true)
            expect(res.operators).toEqual([])
            expect(res.affinityBlockReason).toBe(
                'previous_response_id "rid" not found in routing cache; the conversation may have expired or been served by a different proxy replica — retry without previous_response_id',
            )
        })

        it("quotes the id as Go's %q", async () => {
            for (const [rid, want] of [
                ['a\x01b', '"a\\x01b"'],
                ['a​b', '"a\\u200bb"'],
                ['a b', '"a\\u00a0b"'],
                ['é', '"é"'],
            ]) {
                const res = await pick(deps([op(7)]), { body: JSON.stringify({ model: MODEL, previous_response_id: rid }) })
                expect(res.affinityBlockReason).toBe(
                    `previous_response_id ${want} not found in routing cache; the conversation may have expired or been served by a different proxy replica — retry without previous_response_id`,
                )
            }
        })

        it('logs a pinned node the registry no longer has', async () => {
            const d = pinned(op(7), [], { registry: registryOf([]) })
            await pick(d)
            expect(d.logged).toContainEqual({
                level: 'debug',
                msg: 'response_id pin: node not in registry',
                attrs: { previous_response_id: 'rid', operator_id: 7, node_id: 1, err: 'not found' },
            })
        })

        it('blocks when its node is gone, no longer serves the model, or cannot fit', async () => {
            const gone = pinned(op(7), [], { registry: registryOf([op(7)], { resolve: () => Promise.reject(new Error('gone')) }) })
            expect((await pick(gone)).affinityBlockReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 node 1 which is no longer registered; retry without previous_response_id',
            )
            const absent = pinned(op(7), [], { registry: registryOf([]) })
            expect((await pick(absent)).affinityBlockReason).toContain('no longer registered')

            const other = pinned(op(7, { models: ['other'] }), [op(1)])
            expect((await pick(other)).affinityBlockReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 which no longer serves model "m"',
            )

            const small = pinned(op(7, { protoVersion: JUDGES_FIT }, { contextWindow: 1000 }))
            const res = await pick(small, { sizing: sizing({ inputTokens: 990, maxOutputTokens: 100 }) })
            expect(res.affinityBlocked).toBe(true)
            expect(res.affinityBlockReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 which cannot fit input_tokens=990 max_output_tokens=100; reduce prompt size or start a new conversation',
            )
        })

        it('keeps a pin to a node that defers fit to its upstream, up to 3x its input ceiling', async () => {
            const deferring = (inputTokens: number) =>
                pick(pinned(op(7, {}, { contextWindow: 1000 })), { sizing: sizing({ inputTokens, maxOutputTokens: 100 }) })
            const within = await deferring(2700)
            expect(within.affinityBlocked).toBe(false)
            expect(ids(within.operators)).toEqual(['7/1'])
            expect((await deferring(2701)).affinityBlocked).toBe(true)
        })

        it('reports the max_output the pin was fit-checked against, derived when the caller omitted it', async () => {
            const res = await pick(pinned(op(7, { protoVersion: JUDGES_FIT }, { contextWindow: 1000 })), {
                sizing: sizing({ inputTokens: 990, maxOutputTokens: 32768, deriveMaxOutput: true, maxOutputCeiling: 32768 }),
            })
            expect(res.affinityBlockReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 which cannot fit input_tokens=990 max_output_tokens=256; reduce prompt size or start a new conversation',
            )
        })

        it('yields to a wire-version, TEE or preference conflict, in that order', async () => {
            let res = await pick(pinned(op(7, { protoVersion: '1.0' })), { requireTee: true, prefs: prefs({ only: [ref(9)] }) })
            expect([res.versionBlocked, res.teeBlocked, res.pinConflict]).toEqual([true, false, false])

            res = await pick(pinned(op(7)), { requireTee: true, prefs: prefs({ only: [ref(9)] }) })
            expect([res.versionBlocked, res.teeBlocked, res.pinConflict]).toEqual([false, true, false])
            expect(res.operators).toEqual([])

            res = await pick(pinned(op(7, { tee: attested })), { requireTee: true })
            expect(ids(res.operators)).toEqual(['7/1'])

            // A pass on no published release is not attested, so it still overrides the pin.
            res = await pick(pinned(op(7, { tee: { ...attested, composeReleaseChecked: false } })), { requireTee: true })
            expect(res.teeBlocked).toBe(true)

            res = await pick(pinned(op(7, { signerSpendableMicroAlgos: 0 })), { prefs: prefs({ only: [ref(9)] }) })
            expect(res.pinConflict).toBe(true)
            expect(res.providerPinBlocked).toBe(false)
            expect(res.signerUnderfundedBlocked).toBe(false)
            expect(res.operators).toEqual([])
            expect(res.pinConflictReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 node 1, which your provider preferences (only/ignore/order) exclude; the continuation can only be served by that operator — remove the conflicting preference or start a new conversation',
            )
            res = await pick(pinned(op(7)), { prefs: prefs({ only: [ref(7)] }) })
            expect(ids(res.operators)).toEqual(['7/1'])
        })

        it('reports its own node underfunded, not the pool', async () => {
            const res = await pick(pinned(op(7, { signerSpendableMicroAlgos: MIN_SIGNER_SPENDABLE_MICROALGOS - 1 }), [op(1)]))
            expect(res.signerUnderfundedBlocked).toBe(true)
            expect(res.operators).toEqual([])
            expect(res.signerUnderfundedReason).toBe(
                'previous_response_id "rid" is pinned to operator 7 node 1, whose signing account has less than 5 ALGO spendable to pay network fees; retry once the operator tops up, or start a new conversation',
            )
        })

        it('skips an excluded node, which the registry count then omits', async () => {
            const nodeExclusions = new NodeExclusionStore()
            nodeExclusions.excludeNode({ op: 1, node: 1 })
            const res = await pick(pinned(op(7), [op(1)], { nodeExclusions }))
            expect(res.registryCount).toBe(1)
        })
    })

    describe('tool-call affinity', () => {
        const body = `{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"miss"},{"role":"tool","tool_call_id":"call_1"}]}`
        // The pin is the most expensive, so only affinity can put it first.
        const ops = () => [op(1), op(2), op(7, {}, { inputUsdPer1m: 50, outputUsdPer1m: 50 })]
        const withPin = (over: Partial<PickDeps> = {}, list = ops()) => {
            const d = deps(list, over)
            d.toolAffinity.record({ op: 7, node: 1 }, ['call_1'])
            return d
        }

        it('prefers the node that issued the call, and strict pins it', async () => {
            let res = await pickCandidates(withPin(), request({ body }))
            expect(ids(res.operators)).toEqual(['7/1', '1/1', '2/1'])
            res = await pickCandidates(withPin({ affinityPolicy: 'strict' }), request({ body }))
            expect(ids(res.operators)).toEqual(['7/1'])
        })

        // A stateless Responses tool turn answers its call by call_id in input[],
        // and only the issuing node's upstream reads the replayed reasoning.
        it('pins a Responses tool turn by the call_id it answers', async () => {
            const responses = `{"model":"${MODEL}","store":false,"input":[{"type":"reasoning","id":"rs_1","encrypted_content":"e"},{"type":"function_call","call_id":"call_1","name":"f","arguments":"{}"},{"type":"function_call_output","call_id":"call_1","output":"x"}]}`
            const res = await pickCandidates(withPin({ affinityPolicy: 'strict' }), request({ body: responses }))
            expect(ids(res.operators)).toEqual(['7/1'])
        })

        // A resent history carries every earlier call id; a conversation that
        // moved off its first node follows the node that served the latest turn.
        it('lets the newest live call id decide', async () => {
            const d = withPin()
            d.toolAffinity.record({ op: 2, node: 1 }, ['call_2'])
            const history = `{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"call_1"},{"role":"tool","tool_call_id":"call_2"},{"role":"tool","tool_call_id":"miss"}]}`
            const res = await pickCandidates(d, request({ body: history }))
            expect(ids(res.operators)[0]).toBe('2/1')
        })

        it('is off under policy none', async () => {
            const res = await pickCandidates(withPin({ affinityPolicy: 'none' }), request({ body }))
            expect(ids(res.operators)).toEqual(['1/1', '2/1', '7/1'])
        })

        it('under policy none, leaves a pin to the backoff demotion like any node', async () => {
            const targetBackoff = new TargetBackoffStore(Date.now)
            for (let i = 0; i < 5; i++) targetBackoff.recordTargetOutcome({ op: 1, node: 1 }, false)
            const d = deps(ops(), { affinityPolicy: 'none', targetBackoff })
            d.toolAffinity.record({ op: 1, node: 1 }, ['call_1'])
            const res = await pickCandidates(d, request({ body }))
            expect(ids(res.operators)).toEqual(['2/1', '7/1', '1/1'])
        })

        it('blocks a strict pin that cannot fit, as an affinity refusal', async () => {
            const list = [op(1), op(7, { protoVersion: JUDGES_FIT }, { contextWindow: 150 })]
            const res = await pickCandidates(withPin({ affinityPolicy: 'strict' }, list), request({ body }))
            expect(res.affinityBlocked).toBe(true)
            expect(res.operators).toEqual([])
        })

        it('keeps the pin first though a sibling answers faster', async () => {
            const relayLatency = new RelayLatencyStore({ clock: Date.now })
            for (let i = 0; i < 3; i++) {
                relayLatency.recordDirectRtt({ op: 7, node: 1 }, 3000)
                relayLatency.recordDirectRtt({ op: 1, node: 1 }, 50)
                relayLatency.recordDirectRtt({ op: 2, node: 1 }, 50)
            }
            const res = await pickCandidates(withPin({ relayLatency }), request({ body }))
            expect(ids(res.operators)).toEqual(['7/1', '1/1', '2/1'])
        })

        it('takes the newest live pin, and a pin whose node is gone is no preference', async () => {
            const d = withPin()
            d.toolAffinity.record({ op: 2, node: 1 }, ['call_1'])
            d.toolAffinity.record({ op: 99, node: 1 }, ['miss'])
            // The gone node's id is the newest, so it decides; the older call_1
            // pin to op 2 must not be reached past it.
            const newestGone = `{"model":"${MODEL}","messages":[{"role":"tool","tool_call_id":"call_1"},{"role":"tool","tool_call_id":"miss"}]}`
            const res = await pickCandidates(d, request({ body: newestGone }))
            expect(ids(res.operators)).toEqual(['1/1', '2/1', '7/1'])
            expect(d.logged).toContainEqual({
                level: 'debug',
                msg: 'affinity-preferred node not in registry',
                attrs: { operator_id: 99, node_id: 1, err: 'not found' },
            })
        })

        it('leads with the pinned node though the model list missed it', async () => {
            const pinnedNode = op(7, {}, { inputUsdPer1m: 50, outputUsdPer1m: 50 })
            const list = [op(1), op(2)]
            const d = deps(list, { registry: registryOf(list, { resolve: async () => pinnedNode }) })
            d.toolAffinity.record({ op: 7, node: 1 }, ['call_1'])
            const res = await pickCandidates(d, request({ body }))
            expect(res.operators[0]).toBe(pinnedNode)
        })

        it('says when a strict pin is underfunded', async () => {
            const list = [op(1), op(7, { signerSpendableMicroAlgos: 0 })]
            let res = await pickCandidates(withPin({ affinityPolicy: 'strict' }, list), request({ body }))
            expect(res.signerUnderfundedBlocked).toBe(true)
            expect(res.signerUnderfundedReason).toBe(
                'this tool-call continuation is pinned (strict affinity) to operator 7 node 1, whose signing account has less than 5 ALGO spendable to pay network fees; retry later, or set the affinity policy to prefer so another node can continue it',
            )
            res = await pickCandidates(withPin({ affinityPolicy: 'prefer' }, list), request({ body }))
            expect(res.signerUnderfundedReason).toBe('')
            expect(ids(res.operators)).toEqual(['1/1'])
        })

        it('says when a strict pin lost its attestation, though the pool has an attested node', async () => {
            const list = [op(1, { tee: attested }), op(7)]
            let res = await pickCandidates(withPin({ affinityPolicy: 'strict' }, list), request({ body, requireTee: true }))
            expect(res.teeBlocked).toBe(true)
            expect(res.teeBlockedReason).toBe(
                'this tool-call continuation is pinned (strict affinity) to operator 7 node 1, which no longer has current TEE attestation; retry once it refreshes its evidence, or set the affinity policy to prefer so an attested node can continue it',
            )
            res = await pickCandidates(withPin({ affinityPolicy: 'prefer' }, list), request({ body, requireTee: true }))
            expect(res.teeBlockedReason).toBe('')
            expect(ids(res.operators)).toEqual(['1/1'])
        })

        // The pool's message stands when the pool has no attested node: under
        // prefer, and under strict when the pin is attested but dropped earlier.
        it('leaves a pin out of a pool-wide TEE block', async () => {
            let res = await pickCandidates(withPin({ affinityPolicy: 'prefer' }, [op(1), op(7)]), request({ body, requireTee: true }))
            expect(res.teeBlocked).toBe(true)
            expect(res.teeBlockedReason).toBe('')
            const oldWire = [op(1), op(7, { tee: attested, protoVersion: '1.0' })]
            res = await pickCandidates(withPin({ affinityPolicy: 'strict' }, oldWire), request({ body, requireTee: true }))
            expect(res.teeBlocked).toBe(true)
            expect(res.teeBlockedReason).toBe('')
        })

        it('leaves a funded strict pin out of an underfunded pool’s reason', async () => {
            const pinnedNode = op(7)
            const list = [op(1, { signerSpendableMicroAlgos: 0 })]
            const d = deps(list, { affinityPolicy: 'strict', registry: registryOf(list, { resolve: async () => pinnedNode }) })
            d.toolAffinity.record({ op: 7, node: 1 }, ['call_1'])
            const res = await pickCandidates(d, request({ body }))
            expect(res.signerUnderfundedBlocked).toBe(true)
            expect(res.signerUnderfundedReason).toBe('')
        })

        it('keeps the pin first though it is backed off', async () => {
            const targetBackoff = new TargetBackoffStore(Date.now)
            for (let i = 0; i < 5; i++) targetBackoff.recordTargetOutcome({ op: 7, node: 1 }, false)
            for (let i = 0; i < 5; i++) targetBackoff.recordTargetOutcome({ op: 1, node: 1 }, false)
            const res = await pickCandidates(withPin({ targetBackoff }), request({ body }))
            expect(ids(res.operators)).toEqual(['7/1', '2/1', '1/1'])
        })
    })

    describe('ordering', () => {
        it('demotes a backed-off node to the tail', async () => {
            const targetBackoff = new TargetBackoffStore(Date.now)
            for (let i = 0; i < 5; i++) targetBackoff.recordTargetOutcome({ op: 1, node: 1 }, false)
            expect(targetBackoff.targetBackedOff({ op: 1, node: 1 })).toBe(true)
            const res = await pickCandidates(deps([op(1), op(2), op(3)], { targetBackoff }), request())
            expect(ids(res.operators)).toEqual(['2/1', '3/1', '1/1'])
        })

        it('bands by the payer’s own RTT unless the caller sorts by price', async () => {
            const relayLatency = new RelayLatencyStore({ clock: Date.now })
            for (let i = 0; i < 3; i++) {
                relayLatency.recordDirectRtt({ op: 1, node: 1 }, 3000)
                relayLatency.recordDirectRtt({ op: 2, node: 1 }, 50)
            }
            const ops = [op(1), op(2, {}, { inputUsdPer1m: 2, outputUsdPer1m: 2 })]
            let res = await pickCandidates(deps(ops, { relayLatency }), request())
            expect(ids(res.operators)).toEqual(['2/1', '1/1'])
            res = await pickCandidates(deps(ops, { relayLatency }), request({ prefs: prefs({ sort: 'price' }) }))
            expect(ids(res.operators)).toEqual(['1/1', '2/1'])
        })

        it('demotes a node whose weights contradict two other owners, voting over the whole registry, and warns once', async () => {
            const ops = [
                op(1, {}, { weightsDigest: 'BAD' }),
                op(2, {}, { weightsDigest: 'good', inputUsdPer1m: 2, outputUsdPer1m: 2 }),
                // Out of the candidates by price, still a vote.
                op(3, {}, { weightsDigest: 'GOOD', inputUsdPer1m: 99 }),
            ]
            const d = deps(ops)
            const r = request({ prefs: prefs({ max_input_usd_per_1m: 10 }) })
            let res = await pickCandidates(d, r)
            expect(ids(res.operators)).toEqual(['2/1', '1/1'])
            res = await pickCandidates(d, r)
            const warned = d.logged.filter((l) => l.level === 'warn')
            expect(warned).toEqual([
                {
                    level: 'warn',
                    msg: 'weights digest contradicts peer consensus, deprioritizing operator',
                    attrs: { model: MODEL, operator_id: 1, node_id: 1 },
                },
            ])
        })

        it('logs the final order with the banding behind it', async () => {
            const relayLatency = new RelayLatencyStore({ clock: Date.now })
            for (let i = 0; i < 3; i++) relayLatency.recordDirectRtt({ op: 2, node: 1 }, 50)
            const d = deps([op(1), op(2)], { relayLatency })
            await pickCandidates(d, request())
            const line = d.logged.find((l) => l.msg === 'target ranking')!
            expect(line.attrs).toMatchObject({ model: MODEL, sort: 'balanced', banded: true })
            const cands = line.attrs!.candidates as Record<string, unknown>[]
            expect(cands.map((c) => [c.rank, c.operator_id, c.node_id])).toEqual([
                [0, 1, 1],
                [1, 2, 1],
            ])
            expect(cands[1]).toMatchObject({ rtt: { raw: 50, confidence: 1 }, signal: true, pinned: false })
        })

        it('logs each candidate with its own banding when the banding reorders', async () => {
            const relayLatency = new RelayLatencyStore({ clock: Date.now })
            for (let i = 0; i < 3; i++) {
                relayLatency.recordDirectRtt({ op: 1, node: 1 }, 3000)
                relayLatency.recordDirectRtt({ op: 2, node: 1 }, 50)
            }
            const d = deps([op(1), op(2, {}, { inputUsdPer1m: 2, outputUsdPer1m: 2 })], { relayLatency })
            await pickCandidates(d, request())
            const cands = d.logged.find((l) => l.msg === 'target ranking')!.attrs!.candidates as Record<string, unknown>[]
            expect(cands.map((c) => [c.operator_id, (c.rtt as { raw: number }).raw])).toEqual([
                [2, 50],
                [1, 3000],
            ])
        })

        it('bands on the on-chain TTFT and throughput, discounted by catalog breadth', async () => {
            const metrics = (latencyEwmaMs: number, tokensPerSecEwma: number) => ({ metrics: { latencyEwmaMs, tokensPerSecEwma } })
            const pricier = { inputUsdPer1m: 2, outputUsdPer1m: 2 }
            // Only the speed figures can put the pricier node first.
            let res = await pickCandidates(deps([op(1, metrics(3000, 0)), op(2, metrics(100, 0), pricier)]), request())
            expect(ids(res.operators)).toEqual(['2/1', '1/1'])
            res = await pickCandidates(deps([op(1, metrics(0, 5)), op(2, metrics(0, 100), pricier)]), request())
            expect(ids(res.operators)).toEqual(['2/1', '1/1'])

            // A 300ms TTFT edge is a band ahead from a one-model node; across
            // four token models it counts half, inside the slow node's band,
            // so price decides.
            res = await pickCandidates(deps([op(1, metrics(3000, 0)), op(2, metrics(2700, 0), pricier)]), request())
            expect(ids(res.operators)).toEqual(['2/1', '1/1'])
            const broad = { t1: cap(), t2: cap(), t3: cap(), [MODEL]: cap(pricier) }
            res = await pickCandidates(deps([op(1, metrics(3000, 0)), op(2, { ...metrics(2700, 0), modelCapacities: broad })]), request())
            expect(ids(res.operators)).toEqual(['1/1', '2/1'])
        })

        it('warns once per model, not once per node', async () => {
            const two = (id: number, digest: string) =>
                op(id, { models: [MODEL, 'm2'], modelCapacities: { [MODEL]: cap({ weightsDigest: digest }), m2: cap({ weightsDigest: digest }) } })
            const d = deps([two(1, 'BAD'), two(2, 'good'), two(3, 'good')])
            await pickCandidates(d, request())
            await pickCandidates(d, request({ model: 'm2', sizing: sizing({ model: 'm2' }), body: '{"model":"m2"}' }))
            expect(d.logged.filter((l) => l.level === 'warn').map((l) => l.attrs)).toEqual([
                { model: MODEL, operator_id: 1, node_id: 1 },
                { model: 'm2', operator_id: 1, node_id: 1 },
            ])
        })
    })
})

describe('relayPool', () => {
    it('keeps staging and underfunded nodes, which relay without serving', async () => {
        const pool = await relayPool(deps([op(1, { staging: true }), op(2, { signerSpendableMicroAlgos: 0 })]))
        expect(pool.map((s) => s.id)).toEqual([1, 2])
    })

    it('is empty when the registry cannot list, as Go, whose list cannot fail', async () => {
        const d = deps([], { registry: registryOf([], { allOperators: () => Promise.reject(new Error('down')) }) })
        expect(await relayPool(d)).toEqual([])
    })

    it('drops an excluded node and marks a downranked relay unreachable', async () => {
        const nodeExclusions = new NodeExclusionStore()
        nodeExclusions.excludeNode({ op: 1, node: 1 })
        const relayReputation = new RelayReputationStore({ clock: Date.now, targetReachable: () => true })
        for (let i = 0; i < 10; i++) relayReputation.recordRelayOutcome({ op: 2, node: 1 }, false)
        expect(relayReputation.relayDownranked({ op: 2, node: 1 })).toBe(true)
        const pool = await relayPool(deps([op(1), op(2), op(3)], { nodeExclusions, relayReputation }))
        expect(pool.map((s) => [s.id, s.reachable])).toEqual([
            [2, false],
            [3, true],
        ])
    })
})

describe('relayHopForPool', () => {
    it('picks a relay other than the target, weighted by latency to it', async () => {
        const target = op(1)
        const ops = [target, op(2), op(3)]
        const relayLatency = new RelayLatencyStore({ clock: Date.now })
        const spy = vi.spyOn(relayLatency, 'relayLatencyForTarget')
        const d = deps(ops, { relayLatency })
        const hop = relayHopForPool(d, await relayPool(d), target)!
        expect([2, 3]).toContain(hop.relayId)
        expect([hop.targetId, hop.targetNodeId]).toEqual([1, 1])
        expect(spy.mock.calls.every(([, t]) => (t as NodeRef).op === 1 && (t as NodeRef).node === 1)).toBe(true)
        expect(spy).toHaveBeenCalled()
    })

    it('is null when nothing can relay', async () => {
        const target = op(1)
        const d = deps([target])
        expect(relayHopForPool(d, await relayPool(d), target)).toBeNull()
    })
})
