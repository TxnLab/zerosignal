/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect } from 'vitest'

import { buildRequest, isAllowedInnerPath, isHopErrorCode, RelayErrorCode } from '../src/relay/index.js'
import { RELAY_PATH } from '../src/wire/constants.js'

describe('relay transport binding (mirror of proto/go/relay)', () => {
    it('buildRequest composes the relay URL and metadata', () => {
        const r = buildRequest('https://relay.example/', 42, 7, '/v1/chat/completions', 'POST')
        expect(r.url).toBe('https://relay.example' + RELAY_PATH)
        expect(r.target).toBe('42')
        expect(r.targetNode).toBe('7')
        expect(r.path).toBe('/v1/chat/completions')
        expect(r.method).toBe('POST')
    })

    it('isAllowedInnerPath accepts the well-known endpoints', () => {
        for (const p of [
            '/v1/chat/completions',
            '/v1/responses',
            '/v1/images/generations',
            '/v1/images/edits',
            '/v1/models',
            '/v1/models/gpt-4.1-mini',
            '/v1/zs/reserve',
            '/v1/zs/details',
            '/v1/zs/attestation',
            // Per-model deep details probe (SPEC §3c): a query scopes the
            // request; the allow-list gates the path, the relay forwards the query.
            '/v1/zs/details?model=alpha&expand=coordinates',
            '/v1/zs/details?expand=coordinates%2Cdigest&model=Qwen%2FQwen2.5-7B',
            '/v1/models/gpt-4.1-mini?x=y',
        ]) {
            expect(isAllowedInnerPath(p)).toBe(true)
        }
    })

    it('isAllowedInnerPath rejects chaining, traversal, and unknown paths', () => {
        for (const p of [
            RELAY_PATH,
            '/v1/zs/relay?x=y', // ...even with a query
            '/v1/models/',
            '/v1/models/a/b',
            '/v1/models/../hayai/reserve',
            '/v1/chat/completions/../admin',
            '/v1/chat/completions/../admin?q=1', // traversal survives a query suffix
            '/admin',
            '/admin?x=y', // a query can't launder a disallowed path
            '/healthz',
            '/metrics',
            '',
            'http://evil.example/',
        ]) {
            expect(isAllowedInnerPath(p)).toBe(false)
        }
    })

    it('isHopErrorCode flags relay-side codes, not target-side ones', () => {
        for (const c of [
            RelayErrorCode.BadTarget,
            RelayErrorCode.BadPath,
            RelayErrorCode.BadMethod,
            RelayErrorCode.Busy,
            RelayErrorCode.UnknownTarget,
            RelayErrorCode.BuildRequest,
        ]) {
            expect(isHopErrorCode(c)).toBe(true)
        }
        for (const c of [
            RelayErrorCode.UpstreamUnreachable, // relay reached, target down
            'ticket_required',
            'rate_limited',
            '',
            'relay_unknown_future_code',
        ]) {
            expect(isHopErrorCode(c)).toBe(false)
        }
    })
})
