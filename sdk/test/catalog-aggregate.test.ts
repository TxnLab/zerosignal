/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The discovery aggregates, replaying testdata/catalog_aggregate_vectors.json
// from proto/go/zs TestCatalogAggregateVectors: what allModels,
// allBuiltinTools and allModelDetails list for a fleet, through the same
// advertisable gate the registry applies.

import { readFileSync } from 'node:fs'
import type { OperatorDetailsModel } from '@txnlab/zs-proto/inject'
import { describe, expect, it } from 'vitest'

import { type Operator, modelCapacityOf } from '../src/operator.js'
import { aggregateBuiltinTools, aggregateModelDetails, aggregateModels } from '../src/registry/aggregate.js'
import { advertisable } from '../src/registry/registry.js'
import { testOperator } from './fixtures.js'

interface AggregateNode {
    id: number
    node_id: number
    reachable: boolean
    probed: boolean
    reachable_as_of_ms: number
    staging: boolean
    signer_spendable_microalgos: number | null
    proto_version: string
    builtin_tools: string[]
    models: OperatorDetailsModel[]
    bare_models: string[]
}

interface AggregateCase {
    name: string
    now_ms: number
    max_carry_age_ms: number
    allow_staging: boolean
    nodes: AggregateNode[]
    models: string[]
    builtin_tools: string[]
    model_details: OperatorDetailsModel[]
}

const vectors = JSON.parse(readFileSync(new URL('../../testdata/catalog_aggregate_vectors.json', import.meta.url), 'utf8')) as {
    cases: AggregateCase[]
}

// The node as the probe pass leaves it: each advertised model through
// modelCapacityOf, a bare model with no capacity entry at all.
function operatorOf(n: AggregateNode): Operator {
    const op = testOperator({
        id: n.id,
        nodeId: n.node_id,
        reachable: n.reachable,
        staging: n.staging,
        protoVersion: n.proto_version,
        models: [...n.models.map((m) => m.id), ...n.bare_models],
        modelCapacities: Object.fromEntries(n.models.map((m) => [m.id, modelCapacityOf(m)])),
        builtinTools: n.builtin_tools.map((type) => ({ type })),
    })
    if (n.probed) op.probed = true
    if (n.reachable_as_of_ms !== 0) op.reachableAsOf = n.reachable_as_of_ms
    if (n.signer_spendable_microalgos !== null) op.signerSpendableMicroAlgos = n.signer_spendable_microalgos
    return op
}

describe('catalog_aggregate vectors', () => {
    it.each(vectors.cases.map((c) => [c.name, c] as const))('%s', (_, c) => {
        const ops = c.nodes.map(operatorOf)
        const keep = (op: Operator) => advertisable(op, c.now_ms, c.allow_staging, c.max_carry_age_ms)
        expect(aggregateModels(ops, keep)).toEqual(c.models)
        expect(aggregateBuiltinTools(ops, keep).map((t) => t.type)).toEqual(c.builtin_tools)
        const details = aggregateModelDetails(ops, keep).sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
        expect(details).toEqual(c.model_details)
    })
})
