/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { readFileSync } from 'node:fs'

import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { CatalogEngine, restoredProtoVersion } from '../src/catalog/index.js'
import { defaults } from '../src/config.js'

const major = Number(PROTO_VERSION.split('.')[0])
const ref = { op: 7, node: 2 }

type D = { protoVersion?: string | undefined; models: string[] }
const answer = (models: string[], protoVersion: string | undefined = PROTO_VERSION): D => ({ protoVersion, models })

function engine(maxCarryAge?: number) {
    let now = 1_000_000
    const e = new CatalogEngine<D>({ maxCarryAge, clock: () => now })
    return {
        e,
        at: () => now,
        advance: (ms: number) => {
            now += ms
            return now
        },
    }
}

describe('CatalogEngine', () => {
    it('reads probing before any result', () => {
        expect(engine().e.view(ref)).toEqual({ reachability: 'probing', capabilities: undefined, reachableAsOf: 0 })
    })

    it('judges an answer on its protocol version', () => {
        const { e, at, advance } = engine()
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, at())
        expect(e.view(ref)).toEqual({ reachability: 'ok', capabilities: answer(['m']), reachableAsOf: at() })
        e.applyProbe(ref, { kind: 'answered', details: answer(['m'], `${major}.999`) }, advance(1))
        expect(e.view(ref).reachability).toBe('ok')
        e.applyProbe(ref, { kind: 'answered', details: answer(['m'], `${major + 1}.0`) }, advance(1))
        expect(e.view(ref).reachability).toBe('incompatible')
        e.applyProbe(ref, { kind: 'answered', details: { models: ['m'] } }, advance(1))
        expect(e.view(ref).reachability).toBe('incompatible')
    })

    it('keeps the last answer through a failure that reached the node, and reads it failing', () => {
        const { e, at, advance } = engine()
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, at())
        const asOf = at()
        e.applyProbe(ref, { kind: 'target-failed' }, advance(1000))
        expect(e.view(ref)).toEqual({ reachability: 'failing', capabilities: answer(['m']), reachableAsOf: asOf })
    })

    it('reads an unknown result as the carried answer, and as failing with none', () => {
        const { e, at, advance } = engine()
        e.applyProbe(ref, { kind: 'unknown' }, at())
        expect(e.view(ref).reachability).toBe('failing')
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, advance(1))
        e.applyProbe(ref, { kind: 'target-failed' }, advance(1))
        e.applyProbe(ref, { kind: 'unknown' }, advance(1))
        expect(e.view(ref)).toMatchObject({ reachability: 'ok', capabilities: answer(['m']) })
        e.applyProbe(ref, { kind: 'answered', details: answer(['m'], `${major + 1}.0`) }, advance(1))
        e.applyProbe(ref, { kind: 'unknown' }, advance(1))
        expect(e.view(ref).reachability).toBe('incompatible')
    })

    it('reads no-relay as such, carrying the answer', () => {
        const { e, at, advance } = engine()
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, at())
        e.applyProbe(ref, { kind: 'no-relay' }, advance(1))
        expect(e.view(ref)).toMatchObject({ reachability: 'no-relay', capabilities: answer(['m']) })
    })

    it('drops the answer once maxCarryAge has passed since it, whatever followed', () => {
        const { e, at, advance } = engine(10_000)
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, at())
        e.applyProbe(ref, { kind: 'unknown' }, advance(5_000))
        advance(4_999)
        expect(e.view(ref)).toMatchObject({ reachability: 'ok', capabilities: answer(['m']) })
        advance(1)
        expect(e.view(ref)).toMatchObject({ reachability: 'failing', capabilities: undefined })
        // A fresh answer reopens the window.
        e.applyProbe(ref, { kind: 'answered', details: answer(['n']) }, advance(1))
        expect(e.view(ref).capabilities).toEqual(answer(['n']))
    })

    it('ages out an answer that nothing has followed exactly as one a probe that learned nothing followed', () => {
        const { e, at, advance } = engine(10_000)
        const other = { op: 8, node: 0 }
        const t0 = at()
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, t0)
        e.applyProbe(other, { kind: 'answered', details: answer(['m']) }, t0)
        e.applyProbe(other, { kind: 'unknown' }, advance(1))
        advance(10_000)
        expect(e.view(ref)).toEqual({ reachability: 'failing', capabilities: undefined, reachableAsOf: t0 })
        expect(e.view(other)).toEqual(e.view(ref))
    })

    it('never carries an answer dated 0', () => {
        const { e } = engine()
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, 0)
        expect(e.view(ref)).toMatchObject({ reachability: 'failing', capabilities: undefined })
    })

    it('reads a failure on a node that never answered without inventing models', () => {
        const { e, at } = engine()
        e.applyProbe(ref, { kind: 'target-failed' }, at())
        expect(e.view(ref)).toEqual({ reachability: 'failing', capabilities: undefined, reachableAsOf: 0 })
        const other = { op: 8, node: 0 }
        e.applyProbe(other, { kind: 'no-relay' }, at())
        expect(e.view(other)).toEqual({ reachability: 'no-relay', capabilities: undefined, reachableAsOf: 0 })
    })

    it('reads no-relay as such after the window closes, without the models', () => {
        const { e, at, advance } = engine(10_000)
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, at())
        e.applyProbe(ref, { kind: 'no-relay' }, advance(1))
        advance(10_000)
        expect(e.view(ref)).toMatchObject({ reachability: 'no-relay', capabilities: undefined })
    })

    it('takes a late answer newer than the carried one without moving the latest reading', () => {
        const { e, at, advance } = engine(10_000)
        const t0 = at()
        e.applyProbe(ref, { kind: 'answered', details: answer(['old']) }, t0)
        const t5 = advance(5_000)
        e.applyProbe(ref, { kind: 'target-failed' }, advance(1_000))
        // Another reader surfaces the answer from t5 only now.
        expect(e.applyProbe(ref, { kind: 'answered', details: answer(['new']) }, t5)).toBe(true)
        expect(e.view(ref)).toEqual({ reachability: 'failing', capabilities: answer(['new']), reachableAsOf: t5 })
        // Its window runs from t5, not from the older answer.
        advance(5_000)
        expect(e.view(ref).capabilities).toEqual(answer(['new']))
        // An answer no newer than the carried one changes nothing.
        expect(e.applyProbe(ref, { kind: 'answered', details: answer(['older']) }, t5 - 1)).toBe(false)
        expect(e.applyProbe(ref, { kind: 'answered', details: answer(['same']) }, t5)).toBe(false)
        expect(e.view(ref).capabilities).toEqual(answer(['new']))
    })

    it('ignores a late result that is not an answer, however it falls between the answer and the latest', () => {
        const { e, at, advance } = engine()
        const t0 = at()
        e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, t0)
        e.applyProbe(ref, { kind: 'target-failed' }, advance(2_000))
        for (const kind of ['unknown', 'target-failed', 'no-relay'] as const) {
            expect(e.applyProbe(ref, { kind }, t0 + 1_000)).toBe(false)
        }
        expect(e.view(ref)).toEqual({ reachability: 'failing', capabilities: answer(['m']), reachableAsOf: t0 })
    })

    it('ignores an observation no newer than the last, so a repeat or a stale one is a no-op', () => {
        const { e, at, advance } = engine()
        expect(e.applyProbe(ref, { kind: 'answered', details: answer(['m']) }, at())).toBe(true)
        expect(e.applyProbe(ref, { kind: 'target-failed' }, at())).toBe(false)
        expect(e.applyProbe(ref, { kind: 'target-failed' }, at() - 1)).toBe(false)
        expect(e.view(ref).reachability).toBe('ok')
        expect(e.applyProbe(ref, { kind: 'target-failed' }, advance(1))).toBe(true)
        expect(e.view(ref).reachability).toBe('failing')
    })

    it('keys nodes by operator and node id', () => {
        const { e, at } = engine()
        e.applyProbe({ op: 7, node: 2 }, { kind: 'answered', details: answer(['m']) }, at())
        expect(e.view({ op: 7, node: 3 }).reachability).toBe('probing')
        expect(e.view({ op: 2, node: 7 }).reachability).toBe('probing')
        e.clear()
        expect(e.view({ op: 7, node: 2 }).reachability).toBe('probing')
    })

    it("defaults maxCarryAge to Go's", () => {
        expect(new CatalogEngine().maxCarryAge).toBe(defaults.discovery.maxCarryAge)
        expect(new CatalogEngine({ maxCarryAge: 0 }).maxCarryAge).toBe(defaults.discovery.maxCarryAge)
        expect(new CatalogEngine({ maxCarryAge: -1 }).maxCarryAge).toBe(defaults.discovery.maxCarryAge)
        expect(new CatalogEngine({ maxCarryAge: 5 }).maxCarryAge).toBe(5)
    })
})

describe('restoredProtoVersion', () => {
    const vectors = JSON.parse(readFileSync(new URL('../../testdata/persisted_proto_version_vectors.json', import.meta.url), 'utf8')) as {
        cases: Array<{ persisted: string; want: string }>
    }

    it('has vectors', () => expect(vectors.cases.length).toBeGreaterThan(5))
    for (const c of vectors.cases) {
        it(`floors ${JSON.stringify(c.persisted)} as Go does`, () => expect(restoredProtoVersion(c.persisted)).toBe(c.want))
    }
})
