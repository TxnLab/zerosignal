/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's side of the atomic settle: at the end of a turn the node builds
// a two-txn group, signs its own settle() call, and leaves the payer's ack
// unsigned. The payer checks both halves against the receipt it verified,
// then signs only the ack. Mirrors proto/go/escrow (DecodeSettleGroup,
// VerifySettleGroup, CompletePresignedSettleGroup, EncodeSettleGroup); the
// checks run in Go's order and refuse with Go's field names, and the completed
// group encodes to Go's bytes, both pinned by testdata/escrow_group_vectors.json.

import algosdk, { ABIMethod, Address, OnApplicationComplete } from 'algosdk'

import { type Signer, SignerAddressError } from '../ports.js'
import {
    type GroupMember,
    base32NoPad,
    bytesEqual,
    canonicalTxid,
    decodeSignedGroup,
    encodeSignedPair,
    groupCommitsToMembers,
    hex,
    isZero,
} from './group.js'

/** The settle() signature in the deployed ARC-56; the vectors pin its selector. */
export const SETTLE_METHOD_SIGNATURE = 'settle(byte[],uint64,byte[],uint64,uint64,uint64,uint64,uint64,uint64,uint64,bool)void'

const settleSelector = ABIMethod.fromSignature(SETTLE_METHOD_SIGNATURE).getSelector()

/**
 * SettleGroupSpec is what both halves must say. Every value comes from the
 * signature-verified receipt and the caller's own chain config, never from
 * the group: the contract co-signs the nine billing values across the two
 * halves, and a mismatch on the second freezes the ticket.
 */
export interface SettleGroupSpec {
    appId: bigint
    /** The 16-byte ticket id, not its base64. */
    ticketIdRaw: Uint8Array
    amountCharged: bigint
    /** The receipt's signature digest, 32 bytes. */
    receiptDigest: Uint8Array
    ttftMs: bigint
    decodeMs: bigint
    inputCount: bigint
    outputCount: bigint
    outputUsageType: bigint
    auxOutputUsageType: bigint
    auxOutputCount: bigint
    payerAddr: string
    /** The serving node's signing address, sender of the operator half. */
    operatorSigningAddr: string
}

/**
 * SettleGroupRejectedError names the check that refused the group. The node
 * built both halves and signed the receipt they must match, so any rejection
 * is the node contradicting itself: refuse the group, fall back to the
 * standalone ack, and treat the node as misbehaving. field is a stable slug
 * shared with Go's SettleGroupRejectedError ("payer.rekeyTo", …).
 */
export class SettleGroupRejectedError extends Error {
    constructor(
        readonly field: string,
        readonly detail: string,
    ) {
        super(`escrow: settle group rejected [${field}]: ${detail}`)
        this.name = 'SettleGroupRejectedError'
    }
}

function reject(field: string, detail: string): never {
    throw new SettleGroupRejectedError(field, detail)
}

/** decodeSettleGroup is decodeSignedGroup for the two-member settle group. */
export function decodeSettleGroup(b64: string): GroupMember[] {
    if (!b64) throw new Error('escrow: settle-group payload is empty')
    const g = decodeSignedGroup(b64)
    if (g.length !== 2) throw new Error(`escrow: decoded ${g.length} txns, want 2`)
    return g
}

// The keys an app call may carry: the header and the app-call fields.
const APPL_KEYS = new Set([
    'type', 'snd', 'fee', 'fv', 'lv', 'note', 'gen', 'gh', 'grp', 'lx', 'rekey',
    'apid', 'apan', 'apaa', 'apat', 'apas', 'apfa', 'al', 'apbx', 'apls', 'apgs', 'apap', 'apsu', 'apep', 'aprv',
])

const ABI_TRUE = 0x80
const ABI_FALSE = 0x00

/**
 * verifySettleGroup checks a node-built settle group against spec and throws
 * SettleGroupRejectedError on the first check that fails, in Go's order. The
 * operator half's fee is not checked: the operator pools the whole group's
 * fee there and sizes it to the inner txns its settle fires, so a wrong one
 * costs only the operator.
 */
export function verifySettleGroup(group: GroupMember[], spec: SettleGroupSpec): void {
    if (group.length !== 2) reject('group.size', `settle group size = ${group.length}, want 2`)
    const gid = group[0]!.stxn.txn.group
    if (!gid || isZero(gid)) reject('group.id', 'settle group missing group id')
    const gid1 = group[1]!.stxn.txn.group
    if (!gid1 || !bytesEqual(gid1, gid)) reject('group.id', 'settle group: group id mismatch across members')
    if (!groupCommitsToMembers(gid, group)) reject('group.id', 'settle group id does not commit to its members')
    verifyMember(group[0]!, spec, 'operator', spec.operatorSigningAddr, ABI_TRUE, false)
    verifyMember(group[1]!, spec, 'payer', spec.payerAddr, ABI_FALSE, true)
}

function verifyMember(m: GroupMember, spec: SettleGroupSpec, role: string, sender: string, asOperator: number, payerHalf: boolean): void {
    const tag = `settle[${role}]`
    const no = (field: string, msg: string): never => reject(`${role}.${field}`, `${tag} ${msg}`)
    const txn = m.stxn.txn
    if (txn.type !== algosdk.TransactionType.appl) no('type', `type = "${txn.type}", want "appl"`)
    const call = txn.applicationCall!
    if (call.appIndex !== spec.appId) no('appId', `app_id = ${call.appIndex}, want ${spec.appId}`)
    // A rekey hands the signer's account to whoever the node names; anything
    // but NoOp skips settle() (ClearState runs no approval code at all).
    if (txn.rekeyTo && !txn.rekeyTo.equals(Address.zeroAddress())) {
        no('rekeyTo', `rekeyTo = ${txn.rekeyTo.toString()}, want none (account-takeover attempt)`)
    }
    if (call.onComplete !== OnApplicationComplete.NoOpOC) {
        no('onComplete', `onComplete = ${call.onComplete}, want NoOp (${OnApplicationComplete.NoOpOC})`)
    }
    if (txn.sender.toString() !== sender) no('sender', `sender = ${txn.sender.toString()}, want ${sender}`)
    if (payerHalf) {
        if (txn.fee !== 0n) no('fee', `fee = ${txn.fee}, want 0`)
        if (txn.note.length !== 0) no('note', `note = ${txn.note.length} bytes, want none`)
        if (txn.lease && !isZero(txn.lease)) no('lease', `lease = ${hex(txn.lease)}, want none`)
        for (const k of m.txn.keys()) {
            if (!APPL_KEYS.has(k)) no('foreignFields', 'carries fields outside an app call')
        }
    }
    const args = call.appArgs
    if (args.length < 12) no('args', `has ${args.length} args, want >= 12`)
    // settle() never reads past its last arg, so an extra one on the ack is
    // node-chosen bytes published under the payer's signature, like a note.
    if (payerHalf && args.length !== 12) no('args', `has ${args.length} args, want 12`)
    // Each read follows the length check that covers it.
    const arg = (i: number) => args[i]!
    if (!bytesEqual(arg(0), settleSelector)) no('selector', `selector = ${hex(arg(0))}, want ${hex(settleSelector)}`)
    // After the selector: ticketId, amountCharged, receiptDigest, ttftMs,
    // decodeMs, inputCount, outputCount, outputUsageType, auxOutputUsageType,
    // auxOutputCount, asOperator.
    const slice = (i: number, want: Uint8Array, field: string) => {
        const raw = arg(i)
        if (raw.length < 2) no(field, `${field} = ${raw.length}-byte arg, want length-prefixed`)
        const n = (raw[0]! << 8) | raw[1]!
        if (n !== raw.length - 2) no(field, `${field} length prefix ${n}, payload ${raw.length - 2}`)
        if (n !== want.length || !bytesEqual(raw.subarray(2), want)) {
            no(field, `${field} value mismatch (got ${hex(raw.subarray(2))} want ${hex(want)})`)
        }
    }
    const u64 = (i: number, want: bigint, field: string) => {
        const raw = arg(i)
        if (raw.length !== 8) no(field, `${field} = ${raw.length}-byte uint64, want 8`)
        const got = new DataView(raw.buffer, raw.byteOffset, 8).getBigUint64(0)
        if (got !== want) no(field, `${field} = ${got}, want ${want}`)
    }
    slice(1, spec.ticketIdRaw, 'ticketId')
    u64(2, spec.amountCharged, 'amountCharged')
    slice(3, spec.receiptDigest, 'receiptDigest')
    u64(4, spec.ttftMs, 'ttftMs')
    u64(5, spec.decodeMs, 'decodeMs')
    u64(6, spec.inputCount, 'inputCount')
    u64(7, spec.outputCount, 'outputCount')
    u64(8, spec.outputUsageType, 'outputUsageType')
    u64(9, spec.auxOutputUsageType, 'auxOutputUsageType')
    u64(10, spec.auxOutputCount, 'auxOutputCount')
    const asOp = arg(11)
    if (asOp.length !== 1 || asOp[0] !== asOperator) {
        no('asOperator', `asOperator = ${hex(asOp)}, want 0x${asOperator.toString(16).padStart(2, '0')}`)
    }
}

/** CompletedSettleGroup is the payer-signed settle group, ready for algod or for the node. */
export interface CompletedSettleGroup {
    /** The two signed txns concatenated in group order, for sendRawTransaction. */
    signedGroup: Uint8Array
    /**
     * The same group as Go's EncodeSettleGroup writes it, base64(msgpack of the
     * two signed txns): the settle ack's settle_group for a node that submits
     * it (takesSettleAck).
     */
    encoded: string
    /** The payer ack's txid (gtxn[1]), as Go's CallResult.TxID reports it. */
    txid: string
    /** The group id in base32, as Go logs it. */
    groupId: string
    /** The whole group's fee in microalgos, nearly all on the operator half. */
    feeMicroalgos: bigint
    /** The payer ack's own fee: 0 for any group that passed the checks. */
    payerFeeMicroalgos: bigint
}

/**
 * completeSettleGroup decodes the node's pre-signed settle group, checks it
 * against spec, and has the payer sign the ack. Nothing is signed unless the
 * whole group passes. A SettleGroupRejectedError means the node contradicted
 * its own receipt; any other error (decode, signer) is not evidence of that.
 * It submits nothing; the caller sends signedGroup or hands encoded to the node.
 */
export async function completeSettleGroup(settleGroupB64: string, spec: SettleGroupSpec, signer: Signer): Promise<CompletedSettleGroup> {
    if (signer.address !== spec.payerAddr) throw new SignerAddressError(signer.address, spec.payerAddr)
    const group = decodeSettleGroup(settleGroupB64)
    verifySettleGroup(group, spec)
    const txns = group.map((m) => m.stxn.txn)
    // The wallet signs algosdk's model of the ack; it must be the member just
    // checked, or the signature covers a txn nobody verified.
    if (!bytesEqual(txns[1]!.rawTxID(), canonicalTxid(group[1]!))) {
        throw new Error('escrow: settle ack does not survive algosdk decoding unchanged')
    }
    const signed = await signer.signTransactions(txns, [1])
    const payerSigned = signed[0]
    if (signed.length !== 1 || !payerSigned) throw new Error(`escrow: payer signer returned ${signed.length} txns, want 1`)
    const nodeSigned = group[0]!.bytes
    const out = new Uint8Array(nodeSigned.length + payerSigned.length)
    out.set(nodeSigned)
    out.set(payerSigned, nodeSigned.length)
    return {
        signedGroup: out,
        encoded: encodeSignedPair(out),
        txid: txns[1]!.txID(),
        groupId: base32NoPad(txns[0]!.group!),
        feeMicroalgos: txns[0]!.fee + txns[1]!.fee,
        payerFeeMicroalgos: txns[1]!.fee,
    }
}
