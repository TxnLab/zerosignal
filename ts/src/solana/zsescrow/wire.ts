/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Solana values of the rail-neutral wire fields (SPEC.md § 3a, § 4), as
// the payer writes them and the node reads them. Mirrors
// proto/go/solana/zsescrow/wire.go, pinned by solana_wire_vectors.json.
//
//   - presigned_open_txn: the node's open offer, a wire transaction with the
//     node's signature and the payer's slot empty, in base64.
//   - payment_open: the offer with the payer's signature in its slot, in
//     base64; payment_ref: its first signature, the node's, in base58, which
//     is the transaction's id.
//   - the settle-group slot (X-Zs-Settle-Group, zs-settle-group): the open's
//     open_seq in decimal, which the payer's ack digest binds.
//   - payment_settle: the payer's Ed25519 signature over receiptAckDigest, in
//     base64.
//
// Every reader takes one spelling of each value, the one its writer produces,
// so two parties can never read one value two ways.

import { base64 } from '@scure/base'

import type { UsageReceipt } from '../../ticket/receipt.js'
import type { BytesSigner } from '../../ticket/signing.js'
import { type Hash, type PublicKey, encodeBase58 } from '../key.js'
import { type Transaction, parseTransaction, verifySignatures } from '../message.js'
import { verifyStrict } from '../verify.js'
import { receiptAckDigest } from './ack.js'
import type { Deployment } from './instructions.js'

const MAX_U64 = (1n << 64n) - 1n

/** decodeOpenOffer reads presigned_open_txn. The transaction is not parsed: completeOpenOffer parses and verifies it. */
export function decodeOpenOffer(presigned: string): Uint8Array {
    return decodeCanonicalBase64('presigned_open_txn', presigned)
}

/**
 * encodeOpenPayment writes payment_open and payment_ref for a completed open,
 * completeOpenOffer's result. It refuses one whose signatures don't all
 * verify, as the node's reading would: completeOpenOffer checks the message,
 * not the node's signature on it.
 */
export function encodeOpenPayment(completed: Uint8Array): { paymentOpen: string; paymentRef: string } {
    const tx = parse('payment_open', completed)
    verify(tx)
    return { paymentOpen: base64.encode(completed), paymentRef: encodeBase58(tx.signatures[0]!) }
}

/**
 * decodeOpenPayment reads payment_open and payment_ref: a transaction whose
 * every signature verifies, and whose first is payment_ref. It checks nothing
 * else; what the transaction does is the node's check.
 */
export function decodeOpenPayment(paymentOpen: string, paymentRef: string): Transaction {
    const tx = parse('payment_open', decodeCanonicalBase64('payment_open', paymentOpen))
    const got = encodeBase58(tx.signatures[0]!)
    if (got !== paymentRef) throw new Error(`zsescrow: payment_ref ${JSON.stringify(paymentRef)} is not payment_open's first signature ${got}`)
    verify(tx)
    return tx
}

function verify(tx: Transaction): void {
    try {
        verifySignatures(tx)
    } catch (err) {
        throw new Error(`zsescrow: payment_open: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
}

/** formatOpenSeq writes an open_seq for the settle-group slot. */
export function formatOpenSeq(openSeq: bigint): string {
    if (openSeq < 0n || openSeq > MAX_U64) throw new RangeError(`zsescrow: open_seq ${openSeq} is not a u64`)
    return openSeq.toString()
}

/** parseOpenSeq reads the settle-group slot: an unsigned decimal with no leading zero, at most 2^64−1. */
export function parseOpenSeq(s: string): bigint {
    if (!/^(0|[1-9][0-9]*)$/.test(s) || BigInt(s) > MAX_U64) throw new Error(`zsescrow: open_seq ${JSON.stringify(s)} is not a decimal u64`)
    return BigInt(s)
}

/**
 * signReceiptAck writes the payer's payment_settle for a receipt: signer's
 * signature, as payer, over receiptAckDigest. A signature that does not
 * verify under payer is refused here rather than handed to the node, whose
 * settle would fail on chain at its own expense.
 */
export async function signReceiptAck(
    signer: BytesSigner,
    payer: PublicKey,
    d: Deployment,
    genesis: Hash,
    operatorId: bigint,
    nodeId: bigint,
    ticketId: Uint8Array,
    openSeq: bigint,
    receipt: UsageReceipt | undefined,
): Promise<string> {
    const digest = receiptAckDigest(d, genesis, operatorId, nodeId, ticketId, openSeq, receipt)
    let sig
    try {
        sig = await signer.signBytes(payer, digest)
    } catch (err) {
        throw new Error(`zsescrow: sign ack: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    if (sig.length !== 64 || !verifyStrict(payer, digest, sig)) throw new Error(`zsescrow: sign ack: the signer's signature does not verify as ${payer}`)
    return base64.encode(sig)
}

/** decodeAckSignature reads payment_settle: 64 bytes. Whether it verifies is the node's check, against the digest of the claim it settles. */
export function decodeAckSignature(paymentSettle: string): Uint8Array {
    const b = decodeCanonicalBase64('payment_settle', paymentSettle)
    if (b.length !== 64) throw new Error(`zsescrow: payment_settle: ${b.length} bytes, want 64`)
    return b
}

function parse(what: string, b: Uint8Array): Transaction {
    let tx
    try {
        tx = parseTransaction(b)
    } catch (err) {
        throw new Error(`zsescrow: ${what}: ${err instanceof Error ? err.message : String(err)}`, { cause: err })
    }
    if (tx.signatures.length === 0) throw new Error(`zsescrow: ${what}: a transaction with no signer`)
    return tx
}

// Standard padded base64 in the one spelling base64.encode writes, which is
// also the one Go's EncodeToString writes, the only one either reader takes.
function decodeCanonicalBase64(what: string, s: string): Uint8Array {
    let b
    try {
        b = base64.decode(s)
    } catch {
        b = undefined
    }
    if (b === undefined || base64.encode(b) !== s) throw new Error(`zsescrow: ${what}: not canonical standard base64`)
    if (b.length === 0) throw new Error(`zsescrow: ${what}: empty`)
    return b
}
