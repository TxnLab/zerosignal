/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's check of a relayed ack, and the ack digest it signs for a
// receipt. Mirrors proto/go/solana/zsescrow/ack.go, pinned by
// solana_ack_vectors.json.
//
// A payer acks a ticket's claim in one of two ways. Off chain, it signs the
// ack digest, which the node puts in an Ed25519 precompile instruction before
// its settle_cooperative. On chain, it signs an ack instruction as its
// submitter; a payer holds no SOL, so a relayer (the node, say) builds that
// transaction and pays for it. The program counts the payer's signature on the
// transaction as its ack of every settle_cooperative of the payer's tickets in
// it, so a relayer that put one beside the ack would settle a ticket of its
// choosing at a claim of its choosing.

import type { UsageReceipt } from '../../ticket/receipt.js'
import type { Hash, PublicKey } from '../key.js'
import type { Instruction } from '../message.js'
import { type Deployment, claimHash } from './instructions.js'
import { discriminator } from './program.js'
import { type Fail, hasPrefix, matchEnding, payerMessage, receiptClaim } from './signed.js'

/**
 * The error verifyRelayedAck and receiptAckDigest throw. field is a stable
 * slug naming the check that refused, shared with the Go twin and with
 * OfferRejectedError's slugs where the check is the same.
 */
export class AckRejectedError extends Error {
    constructor(
        readonly field: string,
        detail: string,
    ) {
        super(`zsescrow: ${detail}`)
        this.name = 'AckRejectedError'
    }
}

/** What the payer knows before it signs a relayed ack, all from its own state: the ticket it opened, and the receipt it verified for it. */
export interface AckSpec {
    payer: PublicKey
    operatorId: bigint
    nodeId: bigint
    /** The payer's own record of the ticket, 16 bytes, never the receipt's, which the node writes. */
    ticketId: Uint8Array
    receipt?: UsageReceipt
    /**
     * The Config's treasury, whose USDC account the ack may pass for a refund
     * the payer's account can't take. Absent, or the default key, accepts only
     * an ack that passes none.
     */
    treasury?: PublicKey
}

const ACK = discriminator('global', 'ack')

const failAs =
    (what: string): Fail =>
    (field, detail) => {
        throw new AckRejectedError(field, `${what}: ${detail}`)
    }
const relayedFail = failAs('relayed ack')
const digestFail = failAs('ack digest')

/**
 * Checks the message of an ack transaction someone else built before the
 * payer signs it, throwing AckRejectedError. The checks and their order are
 * Go's VerifyRelayedAck's: any fee payer, then the payer read-only; compute
 * budget leading; then one ack and nothing else, a settle_cooperative or a
 * second ack above all; the receipt naming the payer's ticket; and the ack
 * posting the payer's half of that ticket at exactly the receipt's claim. A
 * ticket id not 16 bytes is the caller's error, a RangeError, as Go's types
 * rule it out.
 */
export function verifyRelayedAck(d: Deployment, message: Uint8Array, spec: AckSpec): void {
    if (spec.ticketId.length !== 16) throw new RangeError('zsescrow: an ack spec ticket id is not 16 bytes')
    const fail = relayedFail
    const kind = (i: number, ix: Instruction): string => {
        if (ix.programId !== d.program) return fail('instruction.program', `instruction ${i}: program ${ix.programId}, outside compute budget and the escrow`)
        if (!hasPrefix(ix.data, ACK)) return fail('escrow.instruction', `instruction ${i}: an escrow instruction other than ack`)
        return 'ack'
    }
    const { ixs, rest } = payerMessage(message, spec.payer, fail, () => {}, kind)
    if (rest.length !== 1) fail('instructions.shape', `${rest.length} acks after compute budget, want one`)
    const claim = receiptClaim('ack.receipt', spec.ticketId, spec.receipt, fail)
    const e = { submitter: spec.payer, operatorId: spec.operatorId, nodeId: spec.nodeId, ticketId: spec.ticketId, payer: spec.payer, treasury: spec.treasury }
    matchEnding('ack', ixs[ixs.length - 1]!, (e, c) => d.ack(e, c), e, claim, fail)
}

/**
 * The ack digest the payer signs off chain for its ticket: the receipt's
 * claim, once the receipt names the ticket, never a claim the node proposes.
 * openSeq is the ticket account's, which tells a reopened ticket id apart.
 * genesis is the cluster's, the Config's genesis_hash.
 */
export function receiptAckDigest(d: Deployment, genesis: Hash, operatorId: bigint, nodeId: bigint, ticketId: Uint8Array, openSeq: bigint, receipt: UsageReceipt | undefined): Uint8Array {
    if (ticketId.length !== 16) throw new RangeError('zsescrow: an ack ticket id is not 16 bytes')
    const claim = receiptClaim('ack.receipt', ticketId, receipt, digestFail)
    return d.ackDigest(genesis, d.ticket(d.node(operatorId, nodeId), ticketId), openSeq, claimHash(claim))
}
