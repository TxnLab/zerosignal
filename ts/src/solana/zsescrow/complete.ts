/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's signature on a transaction someone else built, behind that
// transaction's verifier, where the SDK's completeOpenGroup and
// completeSettleGroup put Algorand's: the signer port signs blindly, so these
// are the only places a counterparty's message reaches it. Mirrors
// proto/go/solana/zsescrow/complete.go, pinned by solana_sign_vectors.json.
// A decode or signer failure is rethrown with the original as its cause. A transaction the
// payer builds itself has nothing foreign to check and is signed with
// signTransactionWith directly.
//
// Each signs the message it verified: both come from one parse of the
// transaction, and the result is that message with the payer's signature in
// its slot, the other slots as given. Nothing is submitted.

import type { PublicKey } from '../key.js'
import { encodeMessage, encodeTransaction, parseTransaction } from '../message.js'
import { type TransactionSigner, signTransactionWith } from '../sign.js'
import type { AckSpec } from './ack.js'
import { verifyRelayedAck } from './ack.js'
import type { Deployment } from './instructions.js'
import type { OpenOfferSpec } from './offer.js'
import { verifyOpenOffer } from './offer.js'

/**
 * completeOpenOffer checks a node's open offer, a wire transaction, against
 * spec, and has signer sign it as spec.payer. A refusal is the verifier's
 * OfferRejectedError, thrown before the signer is called; an offer that does
 * not decode, or a signer that fails, is another error and no evidence
 * against the node.
 */
export function completeOpenOffer(d: Deployment, offer: Uint8Array, spec: OpenOfferSpec, signer: TransactionSigner): Promise<Uint8Array> {
    return cosign('open offer', offer, spec.payer, signer, (message) => verifyOpenOffer(d, message, spec))
}

/**
 * completeRelayedAck checks an ack transaction a relayer built against spec,
 * and has signer sign it as spec.payer. A refusal is the verifier's
 * AckRejectedError, thrown before the signer is called; an ack that does not
 * decode, or a signer that fails, is another error.
 */
export function completeRelayedAck(d: Deployment, ack: Uint8Array, spec: AckSpec, signer: TransactionSigner): Promise<Uint8Array> {
    return cosign('relayed ack', ack, spec.payer, signer, (message) => verifyRelayedAck(d, message, spec))
}

async function cosign(what: string, wire: Uint8Array, payer: PublicKey, signer: TransactionSigner, verify: (message: Uint8Array) => void): Promise<Uint8Array> {
    let tx
    let message
    try {
        tx = parseTransaction(wire)
        message = encodeMessage(tx.message)
    } catch (err) {
        throw new Error(`zsescrow: decode ${what}: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    verify(message)
    try {
        await signTransactionWith(tx, payer, signer)
    } catch (err) {
        throw new Error(`zsescrow: ${what}: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    return encodeTransaction(tx)
}
