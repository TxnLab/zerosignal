/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'

import { servesModel, type Operator } from '../src/selection/index.js'

// Mirrors proto/go/selection TestServesModel_EmptyServesNothing and
// proxy/internal/hayai TestRegistry_EmptyModelsServesNothing: an empty models
// list serves NOTHING regardless of reachable (no wildcard); a non-empty list
// serves only its members.
function op(models: string[], reachable: boolean): Operator {
    return {
        id: 1,
        node_id: 0,
        owner_addr: 'A',
        base_url: 'http://a',
        proto_version: '',
        reachable,
        tee_attested: false,
        models,
        model_capacities: {},
        builtin_tools: [],
    }
}

describe('servesModel (mirror of proto/go/selection.Operator.ServesModel)', () => {
    it.each([
        ['empty + reachable serves nothing', [], true, 'm1', false],
        ['empty + unreachable serves nothing', [], false, 'm1', false],
        ['member matches', ['m1', 'm2'], true, 'm2', true],
        ['non-member misses', ['m1', 'm2'], true, 'm3', false],
        ['member matches even if unreachable', ['m1'], false, 'm1', true],
    ] as const)('%s', (_name, models, reachable, query, want) => {
        expect(servesModel(op([...models], reachable), query)).toBe(want)
    })
})
