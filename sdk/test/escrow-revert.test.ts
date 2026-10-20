/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Revert naming, porting go/escrow errors_test.go. Tests drive off the assert
// strings and look their pcs up in the ARC-56, since pcs shift on every
// contract rebuild.

import { execFileSync } from 'node:child_process'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { describe, expect, it } from 'vitest'

import { APPROVAL_ERROR_PCS } from '../src/escrow/generated/abi.js'
import {
    APPROVAL_ASSERT,
    ApprovalError,
    approvalErrorMessage,
    approvalErrorMessages,
    enrichSubmitError,
    extractPC,
} from '../src/index.js'

const pcsOf = (assert: string): readonly number[] => {
    const pcs = APPROVAL_ERROR_PCS.find(([m]) => m === assert)?.[1]
    if (!pcs?.length) throw new Error(`no source-info entry for ${JSON.stringify(assert)} in the ARC-56`)
    return pcs
}
const algodErr = (pc: number) =>
    new Error(`HTTP 400: TransactionPool.Remember: logic eval error: assert failed pc=${pc}. Details: pc=${pc}, opcodes=...`)

describe('extractPC', () => {
    it('takes the first pc from algod, and none from a failure that has none', () => {
        expect(extractPC('TransactionPool.Remember: logic eval error: assert failed pc=1988. Details: pc=1988, opcodes=...')).toBe(1988)
        expect(extractPC('logic eval error pc=42')).toBe(42)
        expect(extractPC('read tcp 1.2.3.4:80: connection reset by peer')).toBeUndefined()
        expect(extractPC('')).toBeUndefined()
    })
})

describe('the ARC-56 assert table', () => {
    // A reword in the contract fails here, not as a classifier that never matches.
    it('carries every assert a caller acts on, each pc mapping back to it', () => {
        for (const assert of Object.values(APPROVAL_ASSERT)) {
            for (const pc of pcsOf(assert)) expect(approvalErrorMessage(pc), `pc=${pc}`).toBe(assert)
        }
        expect(approvalErrorMessages()).toEqual(expect.arrayContaining(Object.values(APPROVAL_ASSERT)))
    })

    it('holds the strings Go names', () => {
        expect(APPROVAL_ASSERT).toEqual({
            ticketNotFound: 'ticket not found',
            settleAfterRefundDeadline: 'settle after refund deadline',
            ticketNotSettleable: 'ticket not settleable',
            ticketNotPendingSettle: 'ticket not pending settle',
            tooEarlyToLapseSettle: 'too early to lapse settle',
            onlyOperatorClaimsCanLapse: 'only operator claims can lapse into settle',
            insufficientMbrDeposit: 'insufficient MBR deposit',
            insufficientMbrDepositFreeQuota: 'insufficient MBR deposit for free-quota box',
            payerHasNoMbrDeposit: 'payer has no MBR deposit',
            protestAfterDeadline: 'protest after deadline',
            receiptDigestMismatch: 'receiptDigest must match the pending claim',
        })
    })

    // The committed module is what the generator writes from the in-repo ARC-56.
    it('is current with the ARC-56', () => {
        const out = join(mkdtempSync(join(tmpdir(), 'zs-abi-')), 'abi.ts')
        execFileSync('node', [new URL('../scripts/gen-escrow-abi.mjs', import.meta.url).pathname, out])
        const committed = new URL('../src/escrow/generated/abi.ts', import.meta.url)
        expect(readFileSync(out, 'utf8')).toBe(readFileSync(committed, 'utf8'))
    })
})

describe('enrichSubmitError', () => {
    // Go's sentinel rendering: the sentinel's text stands in for algod's.
    it('names a sentinel assert by itself', () => {
        for (const assert of [
            APPROVAL_ASSERT.ticketNotFound,
            APPROVAL_ASSERT.settleAfterRefundDeadline,
            APPROVAL_ASSERT.ticketNotSettleable,
            APPROVAL_ASSERT.ticketNotPendingSettle,
            APPROVAL_ASSERT.tooEarlyToLapseSettle,
            APPROVAL_ASSERT.onlyOperatorClaimsCanLapse,
            APPROVAL_ASSERT.protestAfterDeadline,
            APPROVAL_ASSERT.receiptDigestMismatch,
        ]) {
            const pc = pcsOf(assert)[0]!
            const cause = algodErr(pc)
            const err = enrichSubmitError('settleLapsed', cause)
            expect(err).toBeInstanceOf(ApprovalError)
            expect(err).toMatchObject({ method: 'settleLapsed', pc, assert, cause })
            expect(err.message).toBe(`escrow: submit settleLapsed pc=${pc}: escrow: ${assert}`)
        }
    })

    // A resolved assert with no sentinel keeps algod's text after it.
    it('carries both the assert and algod for any other resolved assert', () => {
        const assert = APPROVAL_ASSERT.insufficientMbrDeposit
        const pc = pcsOf(assert)[0]!
        const err = enrichSubmitError('open', algodErr(pc))
        expect(err).toMatchObject({ method: 'open', pc, assert })
        expect(err.message).toBe(`escrow: submit open pc=${pc}: ${assert}: ${algodErr(pc).message}`)
    })

    // A deployed app older than the compiled-in spec: a revert, but unnamed.
    it("types a revert at a pc the ARC-56 doesn't know, with no assert", () => {
        let pc = 1
        while (approvalErrorMessage(pc) !== undefined) pc++
        const err = enrichSubmitError('settle', algodErr(pc))
        expect(err).toBeInstanceOf(ApprovalError)
        expect(err).toMatchObject({ pc, assert: '' })
        expect(err.message).toBe(`escrow: submit settle pc=${pc}: ${algodErr(pc).message}`)
    })

    it('leaves a failure without a pc a plain error', () => {
        const cause = new Error('connection reset by peer')
        const err = enrichSubmitError('settle', cause)
        expect(err).not.toBeInstanceOf(ApprovalError)
        expect(err.message).toBe('escrow: submit settle: connection reset by peer')
        expect(err.cause).toBe(cause)
    })
})
