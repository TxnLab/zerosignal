/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import { PROTO_VERSION } from '@txnlab/zs-proto/wire'
import { describe, expect, it } from 'vitest'

import { type ProbeOutcome, type Reachability, probeReachability } from '../src/catalog/index.js'

const major = Number(PROTO_VERSION.split('.')[0])

describe('probeReachability', () => {
    const table: Array<[string, ProbeOutcome, Reachability]> = [
        ['no probe finished', { status: 'pending' }, 'probing'],
        ['the probe threw', { status: 'failed', noRelay: false }, 'failing'],
        ['no relay would carry it', { status: 'failed', noRelay: true }, 'no-relay'],
        ['an answer on this major', { status: 'answered', unreachable: false, protoVersion: PROTO_VERSION }, 'ok'],
        ['a newer minor', { status: 'answered', unreachable: false, protoVersion: `${major}.999` }, 'ok'],
        ['another major', { status: 'answered', unreachable: false, protoVersion: `${major + 1}.0` }, 'incompatible'],
        ['no version advertised', { status: 'answered', unreachable: false, protoVersion: undefined }, 'incompatible'],
        ['no hop reached it', { status: 'answered', unreachable: true, protoVersion: undefined }, 'failing'],
        ['unreachable outranks a good version', { status: 'answered', unreachable: true, protoVersion: PROTO_VERSION }, 'failing'],
    ]
    for (const [name, outcome, want] of table) {
        it(name, () => expect(probeReachability(outcome)).toBe(want))
    }
})
