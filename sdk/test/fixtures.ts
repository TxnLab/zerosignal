/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

import type { Operator } from '../src/index.js'

/** An operator with every field zero but its identity, overridden by over. */
export function testOperator(over: Partial<Operator> = {}): Operator {
    return {
        id: 7,
        nodeId: 2,
        ownerAddr: 'OWNER',
        signingAddr: 'SIGNER',
        ticketSigningKey: new Uint8Array(32),
        baseUrl: 'https://node.example.com',
        models: [],
        staging: false,
        ephemeralExpiry: 0,
        ephemeralIssuedAt: 0,
        modelCapacities: {},
        builtinTools: [],
        maxToolIters: 0,
        toolHeadroomPerIteration: 0,
        protoVersion: '',
        reachable: true,
        metrics: { latencyEwmaMs: 0, tokensPerSecEwma: 0 },
        minChargeOutputTokens: 0,
        minChargeAlgoTxns: 0,
        minChargeMicroUsdc: 0,
        ...over,
    }
}
