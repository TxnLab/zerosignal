/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Parity guard for extractRequestedBuiltinTools. The Go mirror
// (proto/go/selection/extract_test.go) asserts the same cases; both must agree
// so the proxy and the client/ app derive identical tool sets — in particular
// a bare "zs_" type is INCLUDED (matches `startsWith('zs_')`).

import { describe, it, expect } from 'vitest'
import {
    extractRequestedBuiltinTools,
    extractRoutingPreferences,
    type Operator,
    type OperatorRef,
    parseOperatorRef,
    parseToolBudgets,
    RELAY_OFF,
    type RoutingPreferences,
    routingPreferencesAllowOperator,
    SORT_THROUGHPUT,
} from '../src/selection/index.js'

describe('extractRequestedBuiltinTools', () => {
    const cases: Array<{ name: string; body: string; want: string[] }> = [
        { name: 'none', body: '{"model":"m1"}', want: [] },
        { name: 'empty tools', body: '{"tools":[]}', want: [] },
        {
            name: 'hayai and non-hayai, order preserved',
            body: '{"tools":[{"type":"function"},{"type":"zs_web_search"},{"type":"zs_image_search"}]}',
            want: ['zs_web_search', 'zs_image_search'],
        },
        { name: 'bare zs_ prefix is included', body: '{"tools":[{"type":"zs_"}]}', want: ['zs_'] },
        { name: 'malformed body', body: '{not json', want: [] },
        { name: 'tool without type', body: '{"tools":[{"foo":"bar"},{"type":"zs_x"}]}', want: ['zs_x'] },
    ]
    for (const tc of cases) {
        it(tc.name, () => {
            expect(extractRequestedBuiltinTools(tc.body)).toEqual(tc.want)
        })
    }
})

// Parity guard for parseToolBudgets. Mirrors proto/go/selection/tool_budgets_test.go
// (TestParseToolBudgets) so the proxy and the client/ app size image-tool
// reserves identically. The fractional / negative cases are TS-specific: they
// pin the Number.isInteger guard that keeps a JS number from emitting a budget
// the node's uint64 image_tool_budget would reject.
describe('parseToolBudgets', () => {
    const cases: Array<{ name: string; body: string; gen: number; edit: number }> = [
        {
            name: 'both tools',
            body: '{"model":"gpt-4o","tool_budgets":{"zs_image_generation":{"max_n":4},"zs_image_edit":{"max_n":2}}}',
            gen: 4,
            edit: 2,
        },
        { name: 'generation only', body: '{"tool_budgets":{"zs_image_generation":{"max_n":3}}}', gen: 3, edit: 0 },
        { name: 'absent', body: '{"model":"gpt-4o"}', gen: 0, edit: 0 },
        { name: 'malformed yields zero', body: '{"tool_budgets":"nonsense"}', gen: 0, edit: 0 },
        { name: 'unrelated tool ignored', body: '{"tool_budgets":{"zs_web_search":{"max_n":9}}}', gen: 0, edit: 0 },
        { name: 'not json', body: 'not json', gen: 0, edit: 0 },
        { name: 'explicit zero is unusable', body: '{"tool_budgets":{"zs_image_generation":{"max_n":0}}}', gen: 0, edit: 0 },
        { name: 'fractional rejected', body: '{"tool_budgets":{"zs_image_generation":{"max_n":2.5}}}', gen: 0, edit: 0 },
        { name: 'negative rejected', body: '{"tool_budgets":{"zs_image_generation":{"max_n":-1}}}', gen: 0, edit: 0 },
    ]
    for (const tc of cases) {
        it(tc.name, () => {
            const b = parseToolBudgets(tc.body)
            expect(b.generationMaxN).toBe(tc.gen)
            expect(b.editMaxN).toBe(tc.edit)
        })
    }
})

// Parity guard for parseOperatorRef. Mirrors proto/go/selection/extract_test.go
// (TestParseOperatorRef) so the proxy and the client/ app resolve a caller ref
// string identically — both ref forms and every malformed shape must agree
// (Go splits on the FIRST ':' too, so "1:2:3" fails on the node part).
describe('parseOperatorRef', () => {
    const cases: Array<{ name: string; in: string; want: OperatorRef | null }> = [
        { name: 'operator only', in: '1234', want: { operator_id: 1234, node_id: 0, match_all_nodes: true } },
        { name: 'operator and node', in: '1234:2', want: { operator_id: 1234, node_id: 2, match_all_nodes: false } },
        { name: 'node zero is explicit', in: '5:0', want: { operator_id: 5, node_id: 0, match_all_nodes: false } },
        { name: 'whitespace trimmed', in: '  7 : 3 ', want: { operator_id: 7, node_id: 3, match_all_nodes: false } },
        { name: 'empty', in: '', want: null },
        { name: 'non-numeric operator', in: 'abc', want: null },
        { name: 'non-numeric node', in: '1:x', want: null },
        { name: 'extra colon', in: '1:2:3', want: null },
        { name: 'negative', in: '-1', want: null },
        { name: 'trailing colon', in: '1:', want: null },
        { name: 'leading colon', in: ':2', want: null },
    ]
    for (const tc of cases) {
        it(tc.name, () => {
            expect(parseOperatorRef(tc.in)).toEqual(tc.want)
        })
    }
})

// Parity guard for extractRoutingPreferences. Mirrors
// proto/go/selection/extract_test.go (TestExtractRoutingPreferences): an
// absent/garbage provider defaults allow_fallbacks=true; malformed refs are
// skipped; unknown sort/relay and non-positive ceilings normalize away.
describe('extractRoutingPreferences', () => {
    it('no provider defaults', () => {
        const got = extractRoutingPreferences('{"model":"m1"}')
        expect(got.allow_fallbacks).toBe(true)
        expect(got.order).toEqual([])
        expect(got.only).toEqual([])
        expect(got.ignore).toEqual([])
        expect(got.sort).toBe('')
        expect(got.relay).toBe('')
    })

    it('full provider object', () => {
        const body = JSON.stringify({
            model: 'm1',
            provider: {
                order: ['3:1', 'x', '2'],
                only: ['1', '9:9'],
                ignore: ['7'],
                allow_fallbacks: false,
                max_price: { input: 2.5, output: 6 },
                require_tools: true,
                sort: 'THROUGHPUT',
                relay: ' off ',
            },
        })
        const got = extractRoutingPreferences(body)
        expect(got.order).toEqual([
            { operator_id: 3, node_id: 1, match_all_nodes: false },
            { operator_id: 2, node_id: 0, match_all_nodes: true },
        ])
        expect(got.only).toEqual([
            { operator_id: 1, node_id: 0, match_all_nodes: true },
            { operator_id: 9, node_id: 9, match_all_nodes: false },
        ])
        expect(got.allow_fallbacks).toBe(false)
        expect(got.max_input_usd_per_1m).toBe(2.5)
        expect(got.max_output_usd_per_1m).toBe(6)
        expect(got.require_tools).toBe(true)
        expect(got.sort).toBe(SORT_THROUGHPUT)
        expect(got.relay).toBe(RELAY_OFF)
    })

    it('unknown sort/relay and negative ceiling normalize away', () => {
        const got = extractRoutingPreferences('{"provider":{"sort":"fastest","relay":"maybe","max_price":{"input":-1}}}')
        expect(got.sort).toBe('')
        expect(got.relay).toBe('')
        expect(got.max_input_usd_per_1m).toBe(0)
    })

    // Parity guard: a mistyped field (or array element) must discard only
    // itself, never the rest of the object — Go parses the same body field- and
    // element-by-element so the two stay in lockstep on a malformed `provider`.
    // Mirrors "malformed fields are isolated" in extract_test.go.
    it('malformed fields are isolated, not all-or-nothing', () => {
        const got = extractRoutingPreferences(
            '{"provider":{"order":[3,"5"],"only":["7"],"max_price":{"input":"x","output":4},"allow_fallbacks":"nope"}}',
        )
        expect(got.order).toEqual([{ operator_id: 5, node_id: 0, match_all_nodes: true }])
        expect(got.only).toEqual([{ operator_id: 7, node_id: 0, match_all_nodes: true }])
        expect(got.max_input_usd_per_1m).toBe(0)
        expect(got.max_output_usd_per_1m).toBe(4)
        expect(got.allow_fallbacks).toBe(true)
    })
})

// Parity guard for routingPreferencesAllowOperator. Mirrors
// proto/go/selection/extract_test.go (TestRoutingPreferencesAllowsOperator):
// only/ignore and a no-fallback order are hard; a fallbacks-allowed order never
// blocks the continuation target.
describe('routingPreferencesAllowOperator', () => {
    const op: Operator = {
        id: 3,
        node_id: 1,
        owner_addr: '',
        base_url: '',
        proto_version: '',
        reachable: true,
        tee_attested: false,
        models: [],
        model_capacities: {},
        builtin_tools: [],
    }
    const base: RoutingPreferences = {
        order: [],
        only: [],
        ignore: [],
        allow_fallbacks: true,
        max_input_usd_per_1m: 0,
        max_output_usd_per_1m: 0,
        require_tools: false,
        sort: '',
        relay: '',
    }
    const allRef = (id: number): OperatorRef => ({ operator_id: id, node_id: 0, match_all_nodes: true })
    const cases: Array<{ name: string; prefs: RoutingPreferences; want: boolean }> = [
        { name: 'no constraints', prefs: base, want: true },
        { name: 'ignore matches → blocked', prefs: { ...base, ignore: [allRef(3)] }, want: false },
        { name: 'only names op → allowed', prefs: { ...base, only: [{ operator_id: 3, node_id: 1, match_all_nodes: false }] }, want: true },
        { name: 'only excludes op → blocked', prefs: { ...base, only: [allRef(9)] }, want: false },
        { name: 'no-fallback order names op → allowed', prefs: { ...base, allow_fallbacks: false, order: [allRef(3)] }, want: true },
        { name: 'no-fallback order excludes op → blocked', prefs: { ...base, allow_fallbacks: false, order: [allRef(9)] }, want: false },
        { name: 'fallbacks-allowed order never blocks', prefs: { ...base, order: [allRef(9)] }, want: true },
        { name: 'node-specific only excludes sibling node', prefs: { ...base, only: [{ operator_id: 3, node_id: 2, match_all_nodes: false }] }, want: false },
    ]
    for (const tc of cases) {
        it(tc.name, () => {
            expect(routingPreferencesAllowOperator(tc.prefs, op)).toBe(tc.want)
        })
    }
})
