/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The checks every transaction a payer co-signs for someone else must pass,
// shared by the open offer and the relayed ack. Mirrors
// proto/go/solana/zsescrow/signed.go. The payer's signature covers the whole
// message, and the program accepts it as the ack of any settle_cooperative of
// the payer's tickets in the same transaction, so each verifier rebuilds every
// instruction from the payer's own values rather than judge only the one it
// expects.

import { base64 } from '@scure/base'

import { type UsageReceipt, receiptSigDigest } from '../../ticket/receipt.js'
import { equalBytes } from '../../util/bytes.js'
import { COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT, COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE } from '../computebudget.js'
import { COMPUTE_BUDGET_PROGRAM_ID, SYSTEM_PROGRAM_ID, type PublicKey } from '../key.js'
import { type AccountMeta, type Instruction, isWritable, parseMessage } from '../message.js'
import { type ClaimFields, type Ending, type RefundFallback } from './instructions.js'

/** Throws the verifier's own error for a failed check: field is the slug shared with the Go twin. */
export type Fail = (field: string, detail: string) => never

// SetComputeUnitLimit and SetComputeUnitPrice, by tag, with their data
// length. The fee payer pays for both; the others size heap and loaded data,
// which neither transaction needs.
const SIGNED_COMPUTE_BUDGET = new Map([
    [COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT, 5],
    [COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE, 9],
])

/**
 * Parses a message the payer is asked to sign as its second signer, with
 * Go's payerMessage checks in its order: no lookup table, exactly two
 * signers (a fee payer feePayer accepts, then the payer, read-only), compute
 * budget leading with at most one of each allowed kind and no accounts, and
 * kind naming every other instruction or failing it. Returns every
 * instruction, with account keys but no privileges, and the kinds of those
 * after the compute budget.
 */
export function payerMessage(
    message: Uint8Array,
    payer: PublicKey,
    fail: Fail,
    feePayer: (k: PublicKey) => void,
    kind: (i: number, ix: Instruction) => string,
): { ixs: Instruction[]; rest: string[] } {
    let m
    try {
        m = parseMessage(message)
    } catch (err) {
        return fail('message.parse', err instanceof Error ? err.message : String(err))
    }
    if (m.addressTableLookups.length !== 0) fail('message.lookups', `${m.addressTableLookups.length} address lookup tables, want none`)
    if (m.header.numRequiredSignatures !== 2) fail('header.signers', `${m.header.numRequiredSignatures} signers, want a fee payer and the payer`)
    feePayer(m.accountKeys[0]!)
    if (m.accountKeys[1] !== payer) fail('header.payer', `second signer ${m.accountKeys[1]}, want the payer ${payer}`)
    if (isWritable(m, 1)) fail('header.payerWritable', "the payer's key is writable")

    const keys = m.accountKeys
    const ixs: Instruction[] = []
    const rest: string[] = []
    const budget = new Set<number>()
    m.instructions.forEach((ci, i) => {
        const ix: Instruction = {
            programId: keys[ci.programIdIndex]!,
            accounts: ci.accounts.map((a) => ({ publicKey: keys[a]!, isSigner: false, isWritable: false })),
            data: ci.data,
        }
        ixs.push(ix)
        if (ix.programId !== COMPUTE_BUDGET_PROGRAM_ID) {
            rest.push(kind(i, ix))
            return
        }
        if (rest.length !== 0) fail('computeBudget.order', `instruction ${i}: compute budget after another program's instruction`)
        const tag = ix.data[0]
        if (tag === undefined || ix.accounts.length !== 0 || SIGNED_COMPUTE_BUDGET.get(tag) !== ix.data.length) {
            fail('computeBudget.instruction', `instruction ${i}: compute-budget data with ${ix.accounts.length} accounts`)
        }
        if (budget.has(tag)) fail('computeBudget.duplicate', `instruction ${i}: a second compute-budget instruction of tag ${tag}`)
        budget.add(tag)
    })
    return { ixs, rest }
}

/**
 * The claim the payer acks for its ticket ticketId: the receipt's, once the
 * receipt names that ticket. Compared as the string the node signed, so no
 * base64 decoder's leniency can make two spellings of one id agree.
 */
export function receiptClaim(field: string, ticketId: Uint8Array, r: UsageReceipt | undefined, fail: Fail): ClaimFields {
    if (!r) return fail(field, 'no receipt for the ticket')
    const want = base64.encode(ticketId)
    if (r.ticket_id !== want) fail(field, `the receipt names ticket ${JSON.stringify(r.ticket_id)}, not the payer's ${JSON.stringify(want)}`)
    return claimFromReceipt(r)
}

/**
 * The claim a payer acks for a receipt: the values the node signed, and the
 * digest of the receipt's canonical bytes.
 */
export function claimFromReceipt(r: UsageReceipt): ClaimFields {
    return {
        amount: BigInt(r.amount_charged),
        receiptDigest: receiptSigDigest(r),
        ttftMs: BigInt(r.ttft_ms),
        decodeMs: BigInt(r.decode_ms),
        inputUnits: BigInt(r.actual_input_count),
        outputUnits: BigInt(r.actual_output_count),
        outputUsageType: r.output_usage_type,
        auxUsageType: r.aux_output_usage_type,
        auxCount: BigInt(r.aux_output_count),
    }
}

/**
 * Checks that ix is build's ending of e's ticket at claim. The rent payer is
 * whoever funded the ticket, which the program checks against the ticket
 * itself, so ix's own is taken. Each fallback shape is one the program may be
 * handed for the same settle; an absent treasury, or the default key, accepts
 * only the one that passes none. The treasury's USDC account passes writable
 * as well as read-only, because sameInstruction compares keys and not
 * privileges, and that must stay so: the program forfeits a refund the
 * payer's account can't take on every ending, so refusing the transaction
 * would change only which ending does it.
 */
export function matchEnding(field: string, ix: Instruction, build: (e: Ending, f: ClaimFields) => Instruction, e: Omit<Ending, 'rentPayer'>, claim: ClaimFields, fail: Fail): void {
    const rentPayer = ix.accounts[5]
    if (!rentPayer) fail(`${field}.accounts`, `${field} names ${ix.accounts.length} accounts`)
    const treasury = e.treasury === SYSTEM_PROGRAM_ID ? undefined : e.treasury
    const fallbacks: RefundFallback[] = treasury ? ['none', 'readonly'] : ['none']
    for (const fallback of fallbacks) {
        const want = build({ ...e, rentPayer: rentPayer.publicKey, treasury, fallback }, claim)
        if (sameKeys(ix.accounts, want.accounts)) return sameInstruction(ix, want, field, fail)
    }
    fail(`${field}.accounts`, `${field}'s accounts are not the payer's ticket at node ${e.operatorId}/${e.nodeId}`)
}

export function hasPrefix(data: Uint8Array, prefix: Uint8Array): boolean {
    return data.length >= prefix.length && equalBytes(data.subarray(0, prefix.length), prefix)
}

// Compares the program, the account keys in order and the data. Privileges
// are the message's, checked once in the header.
export function sameInstruction(got: Instruction, want: Instruction, field: string, fail: Fail): void {
    if (got.programId !== want.programId || !sameKeys(got.accounts, want.accounts)) fail(`${field}.accounts`, `${field}'s accounts are not the payer's`)
    if (!equalBytes(got.data, want.data)) fail(`${field}.data`, `${field}'s data differs from the payer's`)
}

function sameKeys(a: AccountMeta[], b: AccountMeta[]): boolean {
    return a.length === b.length && a.every((m, i) => m.publicKey === b[i]!.publicKey)
}
