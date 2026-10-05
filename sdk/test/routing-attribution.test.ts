/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// relayHopAction, checked against testdata/relay_attribution_vectors.json,
// which Go's relayHopAction generates, and recordRelayHopAction's mapping of
// each action onto the reputation store.

import { readFileSync } from 'node:fs'
import { describe, expect, it, vi } from 'vitest'

import type { RelayEvidence } from '@txnlab/zs-proto/transient'

import {
    type RelayAction,
    type RelayHop,
    type RelayReputationStore,
    recordRelayHopAction,
    relayHopAction,
} from '../src/routing/index.js'

interface AttributionCase {
    status: number
    code: string
    evidence: { relayed: boolean; hop_marker: boolean; relay_marks_hops: boolean; caller_aborted: boolean }
    want: RelayAction
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/relay_attribution_vectors.json', import.meta.url), 'utf8'),
) as { cases: AttributionCase[] }

function evidenceOf(c: AttributionCase): RelayEvidence {
    return {
        relayed: c.evidence.relayed,
        hopMarker: c.evidence.hop_marker,
        relayMarksHops: c.evidence.relay_marks_hops,
        callerAborted: c.evidence.caller_aborted,
    }
}

describe('relayHopAction', () => {
    it('has vectors', () => {
        expect(vectors.cases.length).toBeGreaterThan(0)
    })

    it.each(vectors.cases.map((c) => [`${c.status} ${JSON.stringify(c.code)} ${JSON.stringify(c.evidence)}`, c] as const))(
        '%s',
        (_, c) => {
            expect(relayHopAction(c.status, c.code, evidenceOf(c))).toBe(c.want)
        },
    )
})

describe('recordRelayHopAction', () => {
    const hop: RelayHop = {
        baseUrl: 'https://relay.example',
        relayId: 1,
        relayNodeId: 2,
        targetId: 3,
        targetNodeId: 4,
        relayProtoVersion: '9.1',
    }
    const relay = { op: 1, node: 2 }
    const target = { op: 3, node: 4 }

    function spyStore() {
        return {
            recordRelayOutcome: vi.fn(),
            recordRelayUpstreamUnreachable: vi.fn(),
            recordRelayForwardedTargetFault: vi.fn(),
            recordRelayForwardTimeout: vi.fn(),
        }
    }

    it.each<[RelayAction, string, unknown[]]>([
        ['strike', 'recordRelayOutcome', [relay, false]],
        ['credit', 'recordRelayOutcome', [relay, true]],
        ['upstream_unreachable', 'recordRelayUpstreamUnreachable', [relay, target]],
        ['forwarded_target_fault', 'recordRelayForwardedTargetFault', [relay, target]],
        ['forward_timeout', 'recordRelayForwardTimeout', [relay, target]],
    ])('records %s with %s, and nothing else', (action, method, args) => {
        const store = spyStore()
        recordRelayHopAction(store as unknown as RelayReputationStore, hop, action)
        for (const [name, fn] of Object.entries(store)) {
            if (name === method) expect(fn).toHaveBeenCalledExactlyOnceWith(...args)
            else expect(fn).not.toHaveBeenCalled()
        }
    })

    it('records nothing for none', () => {
        const store = spyStore()
        recordRelayHopAction(store as unknown as RelayReputationStore, hop, 'none')
        for (const fn of Object.values(store)) expect(fn).not.toHaveBeenCalled()
    })
})
