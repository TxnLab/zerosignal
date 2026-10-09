/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The payer's side of an escrow open: the node builds the whole two-txn group
// at reserve, signing the open() app call and leaving the payer's USDC
// transfer unsigned. The payer checks every field of that group against the
// ticket it verified before signing anything, then signs only the transfer.
// Mirrors proto/go/escrow (DecodeOpenGroup, VerifyOpenGroup,
// SubmitPresignedOpenGroup); the checks run in Go's order and refuse with Go's
// field names, pinned by testdata/escrow_group_vectors.json.

import algosdk, { ABIMethod, Address, OnApplicationComplete } from 'algosdk'

import { type Signer, SignerAddressError } from '../ports.js'
import { type GroupMember, base32NoPad, bytesEqual, canonicalTxid, decodeSignedGroup, groupCommitsToMembers, hex, isZero } from './group.js'

/** The open() signature in the deployed ARC-56; the vectors pin its selector. */
export const OPEN_METHOD_SIGNATURE = 'open(axfer,byte[],uint64,uint64,address,uint64,uint64,uint64)void'

const openSelector = ABIMethod.fromSignature(OPEN_METHOD_SIGNATURE).getSelector()

/**
 * OpenGroupSpec is what the open group must say. Every value comes from the
 * signature-verified ticket and the caller's own chain config, never from the
 * group.
 */
export interface OpenGroupSpec {
    appId: bigint
    /** The application account, receiver of the USDC transfer. */
    appAddress: string
    /** The 16-byte ticket id, not its base64. */
    ticketIdRaw: Uint8Array
    operatorId: bigint
    nodeId: bigint
    maxPrice: bigint
    usdcAssetId: bigint
    /** The serving node's signing address, read from its node box. */
    nodeSigningAddr: string
    payerAddr: string
    /** The ticket's expires_at. */
    expiresAt: bigint
    /**
     * Reference callers pin 0: a node-chosen grace would push the refund
     * deadline past the one the payer computes.
     */
    settlementGraceSeconds: bigint
}

/**
 * OpenGroupRejectedError names the check that refused the group. field is a
 * stable slug shared with Go's OpenGroupRejectedError ("payer.rekeyTo",
 * "open.maxPrice", …).
 */
export class OpenGroupRejectedError extends Error {
    constructor(
        readonly field: string,
        detail: string,
    ) {
        super(detail)
        this.name = 'OpenGroupRejectedError'
    }
}

function reject(field: string, detail: string): never {
    throw new OpenGroupRejectedError(field, `escrow: ${detail}`)
}

/** decodeOpenGroup is decodeSignedGroup for the two-member open group. */
export function decodeOpenGroup(b64: string): GroupMember[] {
    if (!b64) throw new Error('escrow: presigned open group is empty')
    const g = decodeSignedGroup(b64)
    if (g.length !== 2) throw new Error(`escrow: decoded ${g.length} txns, want 2`)
    return g
}

// The keys an asset transfer may carry: the header and the transfer. close is
// a payment field with its own check ahead of this one.
const AXFER_KEYS = new Set(['type', 'snd', 'fee', 'fv', 'lv', 'note', 'gen', 'gh', 'grp', 'lx', 'rekey', 'xaid', 'aamt', 'asnd', 'arcv', 'aclose', 'close'])

function checkByteSlice(raw: Uint8Array, want: Uint8Array, field: string): void {
    const f = `open.${field}`
    if (raw.length < 2) reject(f, `open[1] ${field}: ${raw.length}-byte arg, want length-prefixed`)
    const n = (raw[0]! << 8) | raw[1]!
    if (n !== raw.length - 2) reject(f, `open[1] ${field}: length prefix ${n}, payload ${raw.length - 2}`)
    if (n !== want.length) reject(f, `open[1] ${field}: len prefix ${n}, want ${want.length}`)
    if (!bytesEqual(raw.subarray(2), want)) {
        reject(f, `open[1] ${field}: value mismatch (got ${hex(raw.subarray(2))} want ${hex(want)})`)
    }
}

function checkUint64(raw: Uint8Array, want: bigint, field: string): void {
    const f = `open.${field}`
    if (raw.length !== 8) reject(f, `open[1] ${field}: ${raw.length}-byte uint64, want 8`)
    const got = new DataView(raw.buffer, raw.byteOffset, 8).getBigUint64(0)
    if (got !== want) reject(f, `open[1] ${field}: ${got}, want ${want}`)
}

function checkAddress(raw: Uint8Array, want: string, field: string): void {
    const f = `open.${field}`
    if (raw.length !== 32) reject(f, `open[1] ${field}: ${raw.length}-byte address, want 32`)
    const got = algosdk.encodeAddress(raw)
    if (got !== want) reject(f, `open[1] ${field}: ${got}, want ${want}`)
}

/**
 * verifyOpenGroup checks a node-built open group against spec and throws
 * OpenGroupRejectedError on the first check that fails, in Go's order. The
 * node's own signature is not checked: consensus checks it at admission.
 */
export function verifyOpenGroup(group: GroupMember[], spec: OpenGroupSpec): void {
    if (group.length !== 2) reject('group.size', `open group size = ${group.length}, want 2`)
    const axfer = group[0]!.stxn.txn
    const app = group[1]!.stxn.txn
    const gid = axfer.group
    if (!gid || isZero(gid)) reject('group.id', 'open group missing group id')
    if (!app.group || !bytesEqual(app.group, gid)) reject('group.id', 'open group: group id mismatch across members')
    if (!groupCommitsToMembers(gid, group)) reject('group.id', 'open group id does not commit to its members')

    // The one txn the payer signs. Each guard stops the signature meaning more
    // than "move max_price USDC into escrow": a rekey hands the account over, an
    // asset close-to sweeps the whole USDC holding, an asset sender makes it a
    // clawback, a fee spends ALGO the node was to pool, and a note or lease
    // publishes node-chosen bytes under the payer's name. open()'s TEAL rejects
    // some of these too, but only if gtxn[1] really is open().
    if (axfer.type !== algosdk.TransactionType.axfer) reject('payer.type', `open[0] type = "${axfer.type}", want "axfer"`)
    const zero = Address.zeroAddress()
    const xfer = axfer.assetTransfer!
    if (axfer.rekeyTo && !axfer.rekeyTo.equals(zero)) {
        reject('payer.rekeyTo', `open[0] rekey_to = ${axfer.rekeyTo.toString()}, want none (account-takeover attempt)`)
    }
    if (xfer.closeRemainderTo && !xfer.closeRemainderTo.equals(zero)) {
        reject('payer.assetCloseTo', `open[0] asset_close_to = ${xfer.closeRemainderTo.toString()}, want none (balance-sweep attempt)`)
    }
    if (xfer.assetSender && !xfer.assetSender.equals(zero)) {
        reject('payer.assetSender', `open[0] asset_sender = ${xfer.assetSender.toString()}, want none (clawback form)`)
    }
    // algosdk's model has no payment close-to on an asset transfer, so read it
    // off the raw map.
    const close = group[0]!.txn.get('close')
    if (close instanceof Uint8Array && !isZero(close)) {
        reject('payer.closeRemainderTo', `open[0] close_remainder_to = ${algosdk.encodeAddress(close)}, want none`)
    }
    // Anything else outside an asset transfer is refused by algod today; pinning
    // it keeps the signature off whatever a later protocol might make of one.
    // It also keeps the model the payer signs equal to the member checked here.
    for (const k of group[0]!.txn.keys()) {
        if (!AXFER_KEYS.has(k)) reject('payer.foreignFields', 'open[0] carries fields outside an asset transfer')
    }
    if (axfer.fee !== 0n) reject('payer.fee', `open[0] fee = ${axfer.fee}, want 0`)
    if (axfer.note.length !== 0) reject('payer.note', `open[0] note = ${axfer.note.length} bytes, want none`)
    if (axfer.lease && !isZero(axfer.lease)) reject('payer.lease', `open[0] lease = ${hex(axfer.lease)}, want none`)
    if (axfer.sender.toString() !== spec.payerAddr) {
        reject('payer.sender', `open[0] sender = ${axfer.sender.toString()}, want payer ${spec.payerAddr}`)
    }
    if (xfer.receiver.toString() !== spec.appAddress) {
        reject('payer.receiver', `open[0] asset_receiver = ${xfer.receiver.toString()}, want app ${spec.appAddress}`)
    }
    if (xfer.assetIndex !== spec.usdcAssetId) {
        reject('payer.asset', `open[0] xfer_asset = ${xfer.assetIndex}, want usdc = ${spec.usdcAssetId}`)
    }
    if (xfer.amount !== spec.maxPrice) {
        reject('payer.amount', `open[0] asset_amount = ${xfer.amount}, want max_price = ${spec.maxPrice}`)
    }

    // The node's app call. Its fee is the node's own, so it is not checked.
    if (app.type !== algosdk.TransactionType.appl) reject('open.type', `open app call type = "${app.type}", want "appl"`)
    const call = app.applicationCall!
    if (call.appIndex !== spec.appId) reject('open.appId', `open app call app_id = ${call.appIndex}, want ${spec.appId}`)
    if (app.sender.toString() !== spec.nodeSigningAddr) {
        reject('open.sender', `open app call sender = ${app.sender.toString()}, want node_signing ${spec.nodeSigningAddr}`)
    }
    const args = call.appArgs
    // Each read follows the length check that covers it.
    const arg = (i: number) => args[i]!
    if (args.length < 1) reject('open.args', 'open app call missing application args')
    if (!bytesEqual(arg(0), openSelector)) {
        reject('open.selector', `open app call selector = ${hex(arg(0))}, want ${hex(openSelector)}`)
    }
    // After the selector: ticketId, operatorId, nodeId, payerAddr, maxPrice,
    // expiresAt, settlementGraceSeconds.
    if (args.length <= 5) reject('open.args', `open app call has ${args.length} args, want ≥ 6`)
    checkByteSlice(arg(1), spec.ticketIdRaw, 'ticketId')
    checkUint64(arg(2), spec.operatorId, 'operatorId')
    checkUint64(arg(3), spec.nodeId, 'nodeId')
    checkAddress(arg(4), spec.payerAddr, 'payerAddr')
    checkUint64(arg(5), spec.maxPrice, 'maxPrice')
    // ClearState runs the clear program, so open() never executes: the group
    // commits and the USDC lands in the app with no ticket to refund it from.
    if (call.onComplete !== OnApplicationComplete.NoOpOC) {
        reject('open.onComplete', `open[1] on_complete = ${call.onComplete}, want NoOp (${OnApplicationComplete.NoOpOC})`)
    }
    // The node authored the window args and the contract stores them as given,
    // so only this check holds them to the ticket.
    if (args.length <= 7) reject('open.args', `open app call has ${args.length} args, want ≥ 8`)
    checkUint64(arg(6), spec.expiresAt, 'expiresAt')
    checkUint64(arg(7), spec.settlementGraceSeconds, 'settlementGraceSeconds')
}

/** CompletedOpenGroup is the payer-signed group, ready for algod. */
export interface CompletedOpenGroup {
    /** The two signed txns concatenated in group order, for sendRawTransaction. */
    signedGroup: Uint8Array
    /** Per-member txids; txids[1], the app call, is the envelope's algorand_tx_id. */
    txids: string[]
    /** The group id in base32, as Go logs it. */
    groupId: string
    /** The payer transfer's own fee: 0 when the operator's app call pools the group's. */
    payerFeeMicroalgos: bigint
}

/**
 * completeOpenGroup decodes the node's pre-signed open group, checks it
 * against spec, and has the payer sign its transfer. Nothing is signed unless
 * the whole group passes: the node composed the transfer the payer signs.
 */
export async function completeOpenGroup(presignedOpenTxn: string, spec: OpenGroupSpec, signer: Signer): Promise<CompletedOpenGroup> {
    if (signer.address !== spec.payerAddr) throw new SignerAddressError(signer.address, spec.payerAddr)
    const group = decodeOpenGroup(presignedOpenTxn)
    verifyOpenGroup(group, spec)
    const txns = group.map((m) => m.stxn.txn)
    // The wallet signs algosdk's model of the transfer; it must be the member
    // just checked, or the signature covers a txn nobody verified.
    if (!bytesEqual(txns[0]!.rawTxID(), canonicalTxid(group[0]!))) {
        throw new Error('escrow: open[0] does not survive algosdk decoding unchanged')
    }
    const signed = await signer.signTransactions(txns, [0])
    const payerSigned = signed[0]
    if (signed.length !== 1 || !payerSigned) throw new Error(`escrow: payer signer returned ${signed.length} txns, want 1`)
    const nodeSigned = group[1]!.bytes
    const out = new Uint8Array(payerSigned.length + nodeSigned.length)
    out.set(payerSigned)
    out.set(nodeSigned, payerSigned.length)
    return {
        signedGroup: out,
        txids: txns.map((t) => t.txID()),
        groupId: base32NoPad(txns[0]!.group!),
        payerFeeMicroalgos: txns[0]!.fee,
    }
}
