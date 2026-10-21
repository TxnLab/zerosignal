/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// verifyReceipt, checked against testdata/receipt_check_vectors.json, which
// Go's VerifyReceipt generates from the same receipts and tickets.

import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import type { Ticket } from '@txnlab/zs-proto/ticket'

import { ReceiptError, parseReceiptJSON, verifyReceipt } from '../src/index.js'

interface Scenario {
    name: string
    ticket: Ticket
    receipt: unknown
    signing_key: string
    computed_hash: string
    violation: string
}

const vectors = JSON.parse(
    readFileSync(new URL('../../testdata/receipt_check_vectors.json', import.meta.url), 'utf8'),
) as { scenarios: Scenario[] }

describe('verifyReceipt vectors', () => {
    it('covers every scenario', () => expect(vectors.scenarios.length).toBeGreaterThan(0))
    it.each(vectors.scenarios.map((s) => [s.name, s] as const))('%s', (_name, sc) => {
        const receipt = parseReceiptJSON(new TextEncoder().encode(JSON.stringify(sc.receipt)))
        const key = new Uint8Array(Buffer.from(sc.signing_key, 'base64'))
        const computed = new Uint8Array(Buffer.from(sc.computed_hash, 'hex'))
        let got = ''
        try {
            verifyReceipt(receipt, sc.ticket, key, computed)
        } catch (err) {
            if (!(err instanceof ReceiptError)) throw err
            got = err.violation
        }
        expect(got).toBe(sc.violation)
    })
})
