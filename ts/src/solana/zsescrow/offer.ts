/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's check of a node's open offer. Mirrors
// proto/go/solana/zsescrow/offer.go, pinned by solana_open_offer_vectors.json,
// which carries the refusing check's field slug for every case.
//
// The open offer is a transaction the node composes, signs as fee payer and
// hands the payer to co-sign: compute budget, the payer's TransferChecked into
// the node's vault, and open, with the payer's previous ticket's
// settle_cooperative optionally folded in ahead of the transfer. The payer's
// signature covers the whole message, so verifyOpenOffer checks the whole
// message: every instruction must be one the payer's own values rebuild. The
// program checks much of the same, but only for the instructions it is
// handed; an instruction beside them (an Approve of the payer's token account,
// a second transfer) runs under the payer's signature unchecked.

import { base64 } from '@scure/base'

import { type UsageReceipt, receiptSigDigest } from '../../ticket/receipt.js'
import { equalBytes } from '../../util/bytes.js'
import { COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT, COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE } from '../computebudget.js'
import { COMPUTE_BUDGET_PROGRAM_ID, TOKEN_PROGRAM_ID, type PublicKey } from '../key.js'
import { type AccountMeta, type Instruction, isWritable, parseMessage } from '../message.js'
import { TOKEN_TRANSFER_CHECKED, transferChecked } from '../token.js'
import { type ClaimFields, type Deployment, type Ending, type RefundFallback } from './instructions.js'
import { discriminator } from './program.js'

/** The error verifyOpenOffer throws. field is a stable slug naming the check that refused, shared with the Go twin. */
export class OfferRejectedError extends Error {
    constructor(
        readonly field: string,
        detail: string,
    ) {
        super(`zsescrow: open offer: ${detail}`)
        this.name = 'OfferRejectedError'
    }
}

/** What the payer knows before it signs a node's open offer, all from its own state, never from the offer. */
export interface OpenOfferSpec {
    /** The node's signing key, read from its Node account: the offer's fee payer, and open's signer. */
    nodeSigning: PublicKey
    operatorId: bigint
    nodeId: bigint
    payer: PublicKey
    /** The payer's token account the transfer draws from. */
    payerUsdc: PublicKey
    /** The mint's, Config.usdc_decimals. */
    decimals: number
    ticketId: Uint8Array
    maxPrice: bigint
    expiresAt: bigint
    /** The payer's previous ticket, whose cooperative settle the node may fold into the offer. Absent refuses an offer that carries one. */
    fold?: FoldSpec
}

/** A ticket the payer holds a verified receipt for: a settle_cooperative signed by the payer's own transaction signature is its ack. */
export interface FoldSpec {
    operatorId: bigint
    nodeId: bigint
    /**
     * The payer's own record of the ticket, 16 bytes, never the receipt's: the
     * node writes the receipt's ticket id, and the program accepts the payer's
     * signature as the ack of any of its tickets the settle names.
     */
    ticketId: Uint8Array
    receipt: UsageReceipt
}

const U32_MAX = 0xffffffff

/**
 * The claim a payer acks for a receipt: the values the node signed, and the
 * digest of the receipt's canonical bytes. A receipt whose timings or aux
 * count overflow the claim's u32 fields has no claim the program can carry.
 */
export function claimFromReceipt(r: UsageReceipt): ClaimFields {
    if (r.ttft_ms > U32_MAX || r.decode_ms > U32_MAX || r.aux_output_count > U32_MAX) {
        throw new RangeError("zsescrow: receipt timings or aux count exceed a claim's u32 fields")
    }
    return {
        amount: BigInt(r.amount_charged),
        receiptDigest: receiptSigDigest(r),
        ttftMs: r.ttft_ms,
        decodeMs: r.decode_ms,
        inputUnits: BigInt(r.actual_input_count),
        outputUnits: BigInt(r.actual_output_count),
        outputUsageType: r.output_usage_type,
        auxUsageType: r.aux_output_usage_type,
        auxCount: r.aux_output_count,
    }
}

// SetComputeUnitLimit and SetComputeUnitPrice, by tag, with their data
// length. The fee payer pays for both; the others size heap and loaded data,
// which an offer never needs.
const OFFER_COMPUTE_BUDGET = new Map([
    [COMPUTE_BUDGET_SET_COMPUTE_UNIT_LIMIT, 5],
    [COMPUTE_BUDGET_SET_COMPUTE_UNIT_PRICE, 9],
])

const OPEN = discriminator('global', 'open')
const SETTLE_COOPERATIVE = discriminator('global', 'settle_cooperative')

/**
 * Checks the message of a node's open offer against spec before the payer
 * signs it, throwing OfferRejectedError. The checks and their order are Go's
 * VerifyOpenOffer's. A spec outside its fields' types (a ticket id not 16
 * bytes, a price not a u64) is the caller's error, a RangeError, as Go's
 * types rule it out.
 */
export function verifyOpenOffer(d: Deployment, message: Uint8Array, spec: OpenOfferSpec): void {
    if (spec.ticketId.length !== 16 || (spec.fold && spec.fold.ticketId.length !== 16)) throw new RangeError('zsescrow: an open offer spec ticket id is not 16 bytes')
    let m
    try {
        m = parseMessage(message)
    } catch (err) {
        throw new OfferRejectedError('message.parse', err instanceof Error ? err.message : String(err))
    }
    if (m.addressTableLookups.length !== 0) throw new OfferRejectedError('message.lookups', `${m.addressTableLookups.length} address lookup tables, want none`)
    if (m.header.numRequiredSignatures !== 2) throw new OfferRejectedError('header.signers', `${m.header.numRequiredSignatures} signers, want the node and the payer`)
    if (m.accountKeys[0] !== spec.nodeSigning) throw new OfferRejectedError('header.feePayer', `fee payer ${m.accountKeys[0]}, want the node's signing key ${spec.nodeSigning}`)
    if (m.accountKeys[1] !== spec.payer) throw new OfferRejectedError('header.payer', `second signer ${m.accountKeys[1]}, want the payer ${spec.payer}`)
    if (isWritable(m, 1)) throw new OfferRejectedError('header.payerWritable', "the payer's key is writable")

    const keys = m.accountKeys
    const ixs: Instruction[] = []
    const kinds: string[] = []
    const budget = new Set<number>()
    m.instructions.forEach((ci, i) => {
        const ix: Instruction = {
            programId: keys[ci.programIdIndex]!,
            accounts: ci.accounts.map((a) => ({ publicKey: keys[a]!, isSigner: false, isWritable: false })),
            data: ci.data,
        }
        ixs.push(ix)
        if (ix.programId === COMPUTE_BUDGET_PROGRAM_ID) {
            if (i > 0 && kinds[i - 1] !== 'computeBudget') throw new OfferRejectedError('computeBudget.order', `instruction ${i}: compute budget after another program's instruction`)
            const tag = ix.data[0]
            if (tag === undefined || ix.accounts.length !== 0 || OFFER_COMPUTE_BUDGET.get(tag) !== ix.data.length) {
                throw new OfferRejectedError('computeBudget.instruction', `instruction ${i}: compute-budget data with ${ix.accounts.length} accounts`)
            }
            if (budget.has(tag)) throw new OfferRejectedError('computeBudget.duplicate', `instruction ${i}: a second compute-budget instruction of tag ${tag}`)
            budget.add(tag)
            kinds.push('computeBudget')
        } else if (ix.programId === TOKEN_PROGRAM_ID) {
            if (ix.data[0] !== TOKEN_TRANSFER_CHECKED) throw new OfferRejectedError('token.instruction', `instruction ${i}: a token instruction other than TransferChecked`)
            kinds.push('transfer')
        } else if (ix.programId === d.program) {
            if (hasPrefix(ix.data, OPEN)) kinds.push('open')
            else if (hasPrefix(ix.data, SETTLE_COOPERATIVE)) kinds.push('settle')
            else throw new OfferRejectedError('escrow.instruction', `instruction ${i}: an escrow instruction other than open or settle_cooperative`)
        } else {
            throw new OfferRejectedError('instruction.program', `instruction ${i}: program ${ix.programId}, outside compute budget, SPL Token and the escrow`)
        }
    })
    const rest = kinds.slice(budget.size).join(',')
    let fold: Instruction | undefined
    if (rest === 'settle,transfer,open') fold = ixs[budget.size]
    else if (rest !== 'transfer,open') throw new OfferRejectedError('instructions.shape', `instructions [${rest}] after compute budget, want [settle,]transfer,open`)
    const transfer = ixs[ixs.length - 2]!
    const open = ixs[ixs.length - 1]!

    const node = d.node(spec.operatorId, spec.nodeId)
    sameInstruction(transfer, transferChecked(spec.payerUsdc, d.mint, d.vault(node), spec.payer, spec.maxPrice, spec.decimals), 'transfer')
    const want = d.open(spec.nodeSigning, spec.operatorId, spec.nodeId, { ticketId: spec.ticketId, payer: spec.payer, maxPrice: spec.maxPrice, expiresAt: spec.expiresAt, grace: 0 })
    sameInstruction(open, want, 'open')
    if (fold) verifyFold(d, fold, spec)
}

function verifyFold(d: Deployment, ix: Instruction, spec: OpenOfferSpec): void {
    const f = spec.fold
    if (!f) throw new OfferRejectedError('fold.unexpected', 'a folded settle_cooperative, and no ticket to fold')
    if (!f.receipt) throw new OfferRejectedError('fold.receipt', 'no receipt for the ticket to fold')
    // Compared as the string the node signed, so no base64 decoder's leniency
    // can make two spellings of one id agree.
    const want = base64.encode(f.ticketId)
    if (f.receipt.ticket_id !== want) throw new OfferRejectedError('fold.receipt', `the receipt names ticket ${JSON.stringify(f.receipt.ticket_id)}, not the payer's ${JSON.stringify(want)}`)
    let claim: ClaimFields
    try {
        claim = claimFromReceipt(f.receipt)
    } catch (err) {
        throw new OfferRejectedError('fold.receipt', err instanceof Error ? err.message : String(err))
    }
    // The rent payer is whoever funded the ticket, which the program checks
    // against the ticket itself, so the offer's own is taken. Each fallback
    // shape is one the program may be handed for the same settle.
    const rentPayer = ix.accounts[5]
    if (!rentPayer) throw new OfferRejectedError('fold.accounts', `settle_cooperative names ${ix.accounts.length} accounts`)
    const e: Ending = { submitter: spec.nodeSigning, operatorId: f.operatorId, nodeId: f.nodeId, ticketId: f.ticketId, rentPayer: rentPayer.publicKey, payer: spec.payer }
    for (const fallback of ['none', 'readonly'] as RefundFallback[]) {
        const want = d.settleCooperative({ ...e, fallback }, claim)
        if (sameKeys(ix.accounts, want.accounts)) return sameInstruction(ix, want, 'fold')
    }
    throw new OfferRejectedError('fold.accounts', `settle_cooperative's accounts are not the payer's ticket at node ${f.operatorId}/${f.nodeId}`)
}

function hasPrefix(data: Uint8Array, prefix: Uint8Array): boolean {
    return data.length >= prefix.length && equalBytes(data.subarray(0, prefix.length), prefix)
}

// Compares the program, the account keys in order and the data. Privileges
// are the message's, checked once in the header.
function sameInstruction(got: Instruction, want: Instruction, field: string): void {
    if (got.programId !== want.programId || !sameKeys(got.accounts, want.accounts)) throw new OfferRejectedError(`${field}.accounts`, `${field}'s accounts are not the payer's`)
    if (!equalBytes(got.data, want.data)) throw new OfferRejectedError(`${field}.data`, `${field}'s data differs from the payer's`)
}

function sameKeys(a: AccountMeta[], b: AccountMeta[]): boolean {
    return a.length === b.length && a.every((m, i) => m.publicKey === b[i]!.publicKey)
}
