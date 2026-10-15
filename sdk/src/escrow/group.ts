/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Decoding and group-id checks shared by the payer's open and settle paths,
// both of which receive a group the node built and signed in part.

import { sha512_256 } from '@noble/hashes/sha2.js'
import algosdk, { SignedTransaction, decodeMsgpack, msgpackRawDecodeAsMap, msgpackRawEncode } from 'algosdk'

/**
 * One member of a node-built group as it arrived. A node-signed member is
 * submitted from `bytes`, the member re-encoded from its decoded map rather
 * than from `stxn`: algosdk's model drops any key it does not know for the
 * txn's type, and the node's signature covers every key. `txn` is the
 * transaction in canonical form (empty values omitted, as a txid hashes it),
 * for the keys the model drops.
 */
export interface GroupMember {
    stxn: SignedTransaction
    bytes: Uint8Array
    txn: Map<string, unknown>
}

// Fixed-size byte fields: go-codec omits one when every byte is zero, where a
// variable-length field (note, app args) is omitted only when empty.
const FIXED_BYTES = new Set(['snd', 'rcv', 'close', 'asnd', 'arcv', 'aclose', 'fadd', 'rekey', 'grp', 'gh', 'lx', 'votekey', 'selkey', 'sprfkey'])

// canonical drops what go-codec's omitempty (with RecursiveEmptyCheck) would
// not encode, so a txid taken over the result is the one algod computes.
// Array elements are kept as they are: omitempty applies to fields, not to
// what a slice holds.
function canonical(v: unknown, key: string): unknown {
    if (v === 0 || v === 0n || v === false || v === '' || v == null) return undefined
    if (v instanceof Uint8Array) {
        if (v.length === 0 || (FIXED_BYTES.has(key) && v.every((b) => b === 0))) return undefined
        return v
    }
    if (Array.isArray(v)) return v.length === 0 ? undefined : v.map((e) => (e instanceof Map ? canonicalMap(e) : e))
    if (v instanceof Map) {
        const m = canonicalMap(v)
        return m.size === 0 ? undefined : m
    }
    return v
}

function canonicalMap(m: Map<unknown, unknown>): Map<string, unknown> {
    const out = new Map<string, unknown>()
    for (const [k, v] of m) {
        const c = canonical(v, String(k))
        if (c !== undefined) out.set(String(k), c)
    }
    return out
}

/**
 * decodeSignedGroup reads base64(msgpack([]SignedTxn)), the wire form of a
 * node-built group, without checking its size.
 */
export function decodeSignedGroup(b64: string): GroupMember[] {
    let decoded: unknown
    try {
        decoded = msgpackRawDecodeAsMap(algosdk.base64ToBytes(b64))
    } catch (err) {
        throw new Error(`escrow: decode group: ${err instanceof Error ? err.message : String(err)}`)
    }
    if (!Array.isArray(decoded)) throw new Error('escrow: group must decode to an array')
    return decoded.map((entry: unknown, i) => {
        try {
            // The schema decode turns raw 32-byte fields into Address values,
            // which fromEncodingData alone does not, hence the round trip.
            const bytes = msgpackRawEncode(entry)
            const txn = entry instanceof Map ? entry.get('txn') : undefined
            if (!(txn instanceof Map)) throw new Error('no txn')
            return { stxn: decodeMsgpack(bytes, SignedTransaction), bytes, txn: canonicalMap(txn) }
        } catch (err) {
            throw new Error(`escrow: decode group member ${i}: ${err instanceof Error ? err.message : String(err)}`)
        }
    })
}

/**
 * encodeSignedPair is a two-member group's concatenated signed txns in Go's
 * EncodeOpenGroup / EncodeSettleGroup form, base64(msgpack([]SignedTxn)). A
 * msgpack array of two is one header byte (fixarray 0x92) before its members,
 * so the node is handed exactly the bytes a payer submit sends.
 */
export function encodeSignedPair(signedGroup: Uint8Array): string {
    const wire = new Uint8Array(1 + signedGroup.length)
    wire[0] = 0x92
    wire.set(signedGroup, 1)
    return algosdk.bytesToBase64(wire)
}

export const isZero = (b: Uint8Array) => b.every((x) => x === 0)

export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    return a.length === b.length && a.every((x, i) => x === b[i])
}

export const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')

const TX = new TextEncoder().encode('TX')
const TG = new TextEncoder().encode('TG')

function tagged(tag: Uint8Array, body: Uint8Array): Uint8Array {
    const out = new Uint8Array(tag.length + body.length)
    out.set(tag)
    out.set(body, tag.length)
    return sha512_256(out)
}

/** canonicalTxid is the member's txid as algod computes it, group included. */
export function canonicalTxid(m: GroupMember): Uint8Array {
    return tagged(TX, msgpackRawEncode(m.txn))
}

// Sharing a non-zero gid proves only that the members agree with each other.
// algod admits a group when its gid hashes the txids actually submitted, so a
// node could otherwise show an honest sibling while the gid the payer signs
// commits to another it holds. The txids are taken over the canonical maps,
// not over algosdk's model: the model drops keys it doesn't know for the txn's
// type, and a gid recomputed from it would disagree with Go about a group
// carrying one.
export function groupCommitsToMembers(gid: Uint8Array, group: GroupMember[]): boolean {
    const txids = group.map((m) => {
        const bare = new Map(m.txn)
        bare.delete('grp')
        return tagged(TX, msgpackRawEncode(bare))
    })
    return bytesEqual(gid, tagged(TG, msgpackRawEncode(new Map([['txlist', txids]]))))
}

const BASE32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

/** RFC 4648 base32 without padding, as Go renders a group id. */
export function base32NoPad(b: Uint8Array): string {
    let bits = 0
    let v = 0
    let out = ''
    for (const x of b) {
        v = ((v << 8) | x) & 0xffff
        bits += 8
        while (bits >= 5) {
            bits -= 5
            out += BASE32[(v >>> bits) & 31]
        }
    }
    if (bits > 0) out += BASE32[(v << (5 - bits)) & 31]
    return out
}
