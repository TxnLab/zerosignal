/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Escrow reverts by name: algod reports only "assert failed pc=NNN", and the
// ARC-56 maps that program counter back to the assert the contract was compiled
// from. Mirrors go/escrow/errors.go.

import { APPROVAL_ERROR_PCS } from './generated/abi.js'

/**
 * The assert strings the approval program raises that an off-chain caller acts
 * on (Go's Assert* constants). Each is pinned to the ARC-56 by a test, so a
 * contract reword fails there rather than leaving a classifier that never matches.
 */
export const APPROVAL_ASSERT = {
    ticketNotFound: 'ticket not found',
    settleAfterRefundDeadline: 'settle after refund deadline',
    ticketNotSettleable: 'ticket not settleable',
    // settleLapsed's three guards, each a different fact about a lapsed ticket.
    ticketNotPendingSettle: 'ticket not pending settle',
    tooEarlyToLapseSettle: 'too early to lapse settle',
    onlyOperatorClaimsCanLapse: 'only operator claims can lapse into settle',
    // open()'s three prepaid-pool guards: one fact (the pool can't back
    // another ticket box), three terms of the shortfall.
    insufficientMbrDeposit: 'insufficient MBR deposit',
    insufficientMbrDepositFreeQuota: 'insufficient MBR deposit for free-quota box',
    payerHasNoMbrDeposit: 'payer has no MBR deposit',
} as const

// The asserts Go promotes to sentinels. Their rendering drops algod's raw
// text, as Go's does, since the sentinel's own text says the same thing.
const SENTINEL_ASSERTS: ReadonlySet<string> = new Set([
    APPROVAL_ASSERT.ticketNotFound,
    APPROVAL_ASSERT.settleAfterRefundDeadline,
    APPROVAL_ASSERT.ticketNotSettleable,
    APPROVAL_ASSERT.ticketNotPendingSettle,
    APPROVAL_ASSERT.tooEarlyToLapseSettle,
    APPROVAL_ASSERT.onlyOperatorClaimsCanLapse,
])

let byPc: Map<number, string> | undefined

/** approvalErrorMessage is the assert raised at pc, or undefined when the ARC-56 names none. */
export function approvalErrorMessage(pc: number): string | undefined {
    if (byPc === undefined) {
        byPc = new Map()
        for (const [msg, pcs] of APPROVAL_ERROR_PCS) for (const p of pcs) byPc.set(p, msg)
    }
    return byPc.get(pc)
}

/** approvalErrorMessages is every assert message the approval program can raise. */
export function approvalErrorMessages(): string[] {
    return APPROVAL_ERROR_PCS.map(([msg]) => msg)
}

/**
 * ApprovalError is a contract revert at a known program counter (Go's
 * *escrow.ApprovalError). assert is the assert it resolved to, or '' when the
 * ARC-56 has no entry for the pc: the compiled-in spec is always the newest
 * contract while the deployed app may be older, which is exactly when pcs
 * shift, so '' is "a revert we could not name", not "one we don't handle".
 * cause is algod's error.
 */
export class ApprovalError extends Error {
    override readonly name = 'ApprovalError'

    constructor(
        readonly method: string,
        readonly pc: number,
        readonly assert: string,
        cause: unknown,
    ) {
        super(renderApprovalError(method, pc, assert, cause), { cause })
    }
}

// Go's ApprovalError.Error, byte for byte: a sentinel stands in for algod's
// text, an unresolved pc carries algod's text alone, and any other assert
// carries both.
function renderApprovalError(method: string, pc: number, assert: string, cause: unknown): string {
    if (SENTINEL_ASSERTS.has(assert)) return `escrow: submit ${method} pc=${pc}: escrow: ${assert}`
    if (assert === '') return `escrow: submit ${method} pc=${pc}: ${message(cause)}`
    return `escrow: submit ${method} pc=${pc}: ${assert}: ${message(cause)}`
}

const PC_PATTERN = /pc=(\d+)/

/** extractPC is the first pc=NNN in an algod error's text, or undefined when it carries none. */
export function extractPC(text: string): number | undefined {
    const m = PC_PATTERN.exec(text)
    if (!m) return undefined
    const pc = Number(m[1])
    return Number.isSafeInteger(pc) ? pc : undefined
}

/**
 * enrichSubmitError types a failed submit of method (Go's enrichSubmitError).
 * A failure without a pc wasn't a TEAL eval failure (network, signing, a
 * balance check) and comes back as a plain wrapped Error, never an
 * ApprovalError.
 */
export function enrichSubmitError(method: string, err: unknown): Error {
    const text = message(err)
    const pc = extractPC(text)
    if (pc === undefined) return new Error(`escrow: submit ${method}: ${text}`, { cause: err })
    return new ApprovalError(method, pc, approvalErrorMessage(pc) ?? '', err)
}

function message(err: unknown): string {
    return err instanceof Error ? err.message : String(err)
}
