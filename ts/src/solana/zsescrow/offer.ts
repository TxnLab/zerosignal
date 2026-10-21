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

import type { UsageReceipt } from '../../ticket/receipt.js'
import { TOKEN_PROGRAM_ID, type PublicKey } from '../key.js'
import type { Instruction } from '../message.js'
import { TOKEN_TRANSFER_CHECKED, transferChecked } from '../token.js'
import type { Deployment } from './instructions.js'
import { discriminator } from './program.js'
import { type Fail, hasPrefix, matchEnding, payerMessage, receiptClaim, sameInstruction } from './signed.js'

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
    /**
     * The Config's treasury, whose USDC account the folded settle may pass for
     * a refund the payer's account can't take. Absent, or the default key,
     * accepts only a fold that passes none. Its account is accepted writable
     * too, so the payer's signature can ack a settle that forfeits the refund:
     * the program forfeits a refund the payer's account can't take on every
     * ending, so refusing the fold changes only which settle does it.
     */
    treasury?: PublicKey
}

export { claimFromReceipt } from './signed.js'

const OPEN = discriminator('global', 'open')
const SETTLE_COOPERATIVE = discriminator('global', 'settle_cooperative')

const offerFail: Fail = (field, detail) => {
    throw new OfferRejectedError(field, detail)
}

/**
 * Checks the message of a node's open offer against spec before the payer
 * signs it, throwing OfferRejectedError. The checks and their order are Go's
 * VerifyOpenOffer's. A spec outside its fields' types (a ticket id not 16
 * bytes, a price not a u64) is the caller's error, a RangeError, as Go's
 * types rule it out.
 */
export function verifyOpenOffer(d: Deployment, message: Uint8Array, spec: OpenOfferSpec): void {
    if (spec.ticketId.length !== 16 || (spec.fold && spec.fold.ticketId.length !== 16)) throw new RangeError('zsescrow: an open offer spec ticket id is not 16 bytes')
    const fail = offerFail
    const feePayer = (k: PublicKey): void => {
        if (k !== spec.nodeSigning) fail('header.feePayer', `fee payer ${k}, want the node's signing key ${spec.nodeSigning}`)
    }
    const kind = (i: number, ix: Instruction): string => {
        if (ix.programId === TOKEN_PROGRAM_ID) {
            if (ix.data[0] !== TOKEN_TRANSFER_CHECKED) fail('token.instruction', `instruction ${i}: a token instruction other than TransferChecked`)
            return 'transfer'
        }
        if (ix.programId === d.program) {
            if (hasPrefix(ix.data, OPEN)) return 'open'
            if (hasPrefix(ix.data, SETTLE_COOPERATIVE)) return 'settle'
            return fail('escrow.instruction', `instruction ${i}: an escrow instruction other than open or settle_cooperative`)
        }
        return fail('instruction.program', `instruction ${i}: program ${ix.programId}, outside compute budget, SPL Token and the escrow`)
    }
    const { ixs, rest } = payerMessage(message, spec.payer, fail, feePayer, kind)
    const shape = rest.join(',')
    let fold: Instruction | undefined
    if (shape === 'settle,transfer,open') fold = ixs[ixs.length - 3]
    else if (shape !== 'transfer,open') fail('instructions.shape', `instructions [${shape}] after compute budget, want [settle,]transfer,open`)
    const transfer = ixs[ixs.length - 2]!
    const open = ixs[ixs.length - 1]!

    const node = d.node(spec.operatorId, spec.nodeId)
    sameInstruction(transfer, transferChecked(spec.payerUsdc, d.mint, d.vault(node), spec.payer, spec.maxPrice, spec.decimals), 'transfer', fail)
    const want = d.open(spec.nodeSigning, spec.operatorId, spec.nodeId, { ticketId: spec.ticketId, payer: spec.payer, maxPrice: spec.maxPrice, expiresAt: spec.expiresAt, grace: 0 })
    sameInstruction(open, want, 'open', fail)
    if (fold) verifyFold(d, fold, spec)
}

function verifyFold(d: Deployment, ix: Instruction, spec: OpenOfferSpec): void {
    const f = spec.fold
    if (!f) return offerFail('fold.unexpected', 'a folded settle_cooperative, and no ticket to fold')
    const claim = receiptClaim('fold.receipt', f.ticketId, f.receipt, offerFail)
    const e = { submitter: spec.nodeSigning, operatorId: f.operatorId, nodeId: f.nodeId, ticketId: f.ticketId, payer: spec.payer, treasury: f.treasury }
    matchEnding('fold', ix, (e, c) => d.settleCooperative(e, c), e, claim, offerFail)
}
