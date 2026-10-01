/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { describe, it, expect } from 'vitest'

import {
    APP_COMPOSE_MIN_VERSION,
    LEGACY_PROTO_VERSION,
    PROTO_VERSION,
    RELAY_HOP_HEADER_MIN_VERSION,
    bootstrapProtoVersion,
    protoVersionAtLeast,
    protoVersionCompatible,
    publishesAppCompose,
    setsRelayHopHeader,
} from '../src/wire/version.js'

describe('protoVersionCompatible', () => {
    const cases: Array<[string, string | undefined | null, boolean]> = [
        // Written against the constant, so the "same version" case cannot
        // quietly become a lower-minor case at the next bump — which is what
        // the hardcoded "current 9.1" here had already become by 9.6.
        ['same exact (whatever this build advertises)', PROTO_VERSION, true],
        ['same major, lower minor (9.0 stays relay-eligible)', '9.0', true],
        // A minor no build has reached, so this stays a HIGHER minor however
        // far the constant moves inside major 9.
        ['same major, higher minor', '9.999', true],
        ['same major, no minor', '9', true],
        ['same major with patch', '9.0.7', true],
        ['empty string treated as legacy 1.0 — incompatible with 9.x', '', false],
        ['undefined treated as legacy 1.0 — incompatible', undefined, false],
        ['null treated as legacy 1.0 — incompatible', null, false],
        ['explicit legacy 1.0', '1.0', false],
        ['prior major (2.0)', '2.0', false],
        ['prior major (3.0) — dropped at the 4.0 operator/node-split cutover', '3.0', false],
        ['prior major (4.0) — dropped at the 5.0 usage-type / v2-tag cutover', '4.0', false],
        ['prior major (5.0) — dropped at the 6.0 ephemeral node_id / v3-tag cutover', '5.0', false],
        ['prior major (6.0) — dropped at the 7.0 hayai→zs transport-label rename', '6.0', false],
        ['prior major (7.0) — dropped at the 8.0 relay-metadata-minimization cutover', '7.0', false],
        ['prior major (8.1) — dropped at the 9.0 cached-token / v2-tag cutover', '8.1', false],
        ['different major higher', '10.0', false],
        ['non-numeric major', 'vNext', false],
        ['negative major', '-1.0', false],
        ['garbage', 'not-a-version', false],
        ['dot only', '.0', false],
    ]
    for (const [name, input, want] of cases) {
        it(name, () => {
            expect(protoVersionCompatible(input)).toBe(want)
        })
    }
})

describe('constants', () => {
    it('PROTO_VERSION is parseable', () => {
        expect(PROTO_VERSION).toMatch(/^\d+\.\d+$/)
    })
    it('LEGACY_PROTO_VERSION is parseable', () => {
        expect(LEGACY_PROTO_VERSION).toMatch(/^\d+(\.\d+)?$/)
    })
})

describe('protoVersionAtLeast', () => {
    const cases: Array<[string, string | undefined | null, string, boolean]> = [
        ['equal', '9.1', '9.1', true],
        ['same major, higher minor', '9.2', '9.1', true],
        ['same major, lower minor', '9.0', '9.1', false],
        ['bare major reads as minor zero', '9', '9.1', false],
        ['bare major meets a bare-major floor', '9', '9.0', true],
        ['patch suffix ignored, minor still counts', '9.1.3', '9.1', true],
        ['patch suffix on a lower minor still fails', '9.0.9', '9.1', false],
        ['higher major wins regardless of minor', '10.0', '9.1', true],
        ['lower major loses regardless of minor', '8.9', '9.1', false],
        ['empty reads as legacy 1.0', '', '9.1', false],
        ['undefined reads as legacy 1.0', undefined, '9.1', false],
        ['null reads as legacy 1.0', null, '9.1', false],
        // Fails closed on both sides — an unparseable peer must never be
        // treated as capable, or garbage advertisements get charged for a
        // header they were never asked to set.
        ['unparseable peer fails closed', 'vNext', '9.1', false],
        ['negative peer fails closed', '-1.0', '9.1', false],
        ['non-numeric minor fails closed', '9.x', '9.1', false],
        ['unparseable floor fails closed', '9.1', 'nope', false],
    ]
    for (const [name, other, floor, want] of cases) {
        it(name, () => {
            expect(protoVersionAtLeast(other, floor)).toBe(want)
        })
    }
})

describe('setsRelayHopHeader', () => {
    const capable = [RELAY_HOP_HEADER_MIN_VERSION, '9.1', '9.2', '10.0', '9.1.4']
    // The whole un-upgraded fleet. A missing marker from any of these proves
    // nothing, and treating it as evidence would charge every relay alive
    // today for a header that did not exist when it shipped.
    const notCapable = ['9.0', '9', '8.1', '1.0', '', undefined, null, 'garbage']
    for (const v of capable) {
        it(`${v} marks hops`, () => expect(setsRelayHopHeader(v)).toBe(true))
    }
    for (const v of notCapable) {
        it(`${String(v)} does not mark hops`, () => expect(setsRelayHopHeader(v)).toBe(false))
    }
})

describe('publishesAppCompose', () => {
    const capable = [APP_COMPOSE_MIN_VERSION, '9.6', '9.7', '10.0', '9.6.1']
    // The pre-9.6 dstack fleet. These nodes CANNOT publish the preimage, so an
    // absent app_compose says nothing about them — and they still pass
    // major-equality, so they are routable peers a verifier meets in practice.
    const notCapable = ['9.5', '9.0', '9', '8.1', '1.0', '', undefined, null, 'garbage']
    for (const v of capable) {
        it(`${v} publishes the preimage`, () => expect(publishesAppCompose(v)).toBe(true))
    }
    for (const v of notCapable) {
        it(`${String(v)} predates the preimage`, () =>
            expect(publishesAppCompose(v)).toBe(false))
    }

    // Pinned to the constant, not a literal. A hand-typed min-version that
    // drifted BELOW PROTO_VERSION would be inert and one ABOVE it would make
    // this build's own nodes read as withholding — neither shows up above.
    it('covers this build', () => expect(publishesAppCompose(PROTO_VERSION)).toBe(true))
})

// Regression pin for the seeding trap. Callers seed an UNPROBED peer's
// proto_version so cold-start relay selection can bootstrap (privacy mode needs
// a relay to run the probe that learns the version). That seed must stay
// relay-ELIGIBLE while never implying a minor-gated CAPABILITY: seeding the
// full PROTO_VERSION would make every never-probed relay read as marker-capable
// and eat a strike on its first code-less 5xx. On the client this matters more
// than on the proxy — the seeded pool feeds dispatch, not just discovery.
describe('bootstrapProtoVersion', () => {
    it('stays relay-eligible', () => {
        expect(protoVersionCompatible(bootstrapProtoVersion())).toBe(true)
    })
    it('never implies hop-marker support', () => {
        expect(setsRelayHopHeader(bootstrapProtoVersion())).toBe(false)
    })
    it('is this build major with minor zero', () => {
        expect(bootstrapProtoVersion()).toBe(`${PROTO_VERSION.split('.')[0]}.0`)
    })
})

// A bump on one side only makes the two implementations advertise different
// versions, and nothing else compares them. Read from the Go source because
// the constant has no golden vector.
describe('PROTO_VERSION', () => {
    it('matches Go wire.ProtoVersion', () => {
        const here = path.dirname(fileURLToPath(import.meta.url))
        const goSrc = fs.readFileSync(path.resolve(here, '../../go/wire/version.go'), 'utf8')
        const m = /^const ProtoVersion = "([^"]+)"$/m.exec(goSrc)
        expect(m, 'ProtoVersion not found in go/wire/version.go').not.toBeNull()
        expect(PROTO_VERSION).toBe(m![1])
    })
})
