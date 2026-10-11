/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Box keys for the escrow app's BoxMaps. Mirrors proto/go/escrow/boxes.go.
// Go through these helpers rather than building a key by hand: the contract's
// MBR accounting and the on-wire box references assume these exact lengths.

import { decodeAlgorandAddress } from '../ticket/signing.js'
import { concatBytes, utf8 } from '../util/bytes.js'

const TICKET_PREFIX = utf8('t:')
const OPERATOR_PREFIX = utf8('o:')
const NODE_PREFIX = utf8('n:')
const FREE_QUOTA_PREFIX = utf8('q:')

const TICKET_ID_SIZE = 16

function be64(v: bigint): Uint8Array {
    if (v < 0n || v > 0xffff_ffff_ffff_ffffn) throw new RangeError(`uint64 out of range: ${v}`)
    const b = new Uint8Array(8)
    new DataView(b.buffer).setBigUint64(0, v, false)
    return b
}

// ticketBoxKey returns "t:" + the 16-byte raw ticket id. Stricter than Go's
// TicketBoxKey, which concatenates any length: a wrong-length id names a box
// the contract never creates, so a read of it reports "absent" instead of
// failing where the caller can see it.
export function ticketBoxKey(ticketIdRaw: Uint8Array): Uint8Array {
    if (ticketIdRaw.length !== TICKET_ID_SIZE) {
        throw new Error(`ticket id must be ${TICKET_ID_SIZE} bytes (got ${ticketIdRaw.length})`)
    }
    return concatBytes(TICKET_PREFIX, ticketIdRaw)
}

// operatorBoxKey returns "o:" + the operator id as 8-byte big-endian, which is
// how puya encodes a uint64 BoxMap key.
export function operatorBoxKey(operatorId: bigint): Uint8Array {
    return concatBytes(OPERATOR_PREFIX, be64(operatorId))
}

// nodeBoxKey returns "n:" + operatorId_be8 + nodeId_be8. The operator id comes
// first so nodeBoxPrefixForOperator can prefix-scan one operator's nodes.
export function nodeBoxKey(operatorId: bigint, nodeId: bigint): Uint8Array {
    return concatBytes(NODE_PREFIX, be64(operatorId), be64(nodeId))
}

// nodeBoxPrefixForOperator returns "n:" + operatorId_be8, the prefix shared by
// every node box under that operator.
export function nodeBoxPrefixForOperator(operatorId: bigint): Uint8Array {
    return concatBytes(NODE_PREFIX, be64(operatorId))
}

// operatorBoxPrefix and nodeBoxPrefix are the names every operator and every
// node box starts with, for a prefix-filtered box listing. Each call returns a
// fresh copy, so a caller can't rewrite the prefix for every other one.
export function operatorBoxPrefix(): Uint8Array {
    return OPERATOR_PREFIX.slice()
}

export function nodeBoxPrefix(): Uint8Array {
    return NODE_PREFIX.slice()
}

function hasPrefix(name: Uint8Array, prefix: Uint8Array): boolean {
    return prefix.every((b, i) => name[i] === b)
}

function readBe64(b: Uint8Array, off: number): bigint {
    return new DataView(b.buffer, b.byteOffset, b.byteLength).getBigUint64(off, false)
}

// operatorIdFromBoxName is the inverse of operatorBoxKey, for names a box
// listing returns. Undefined for a name that isn't a well-formed operator box
// (wrong prefix or length): no box this contract writes, so a caller skips it.
export function operatorIdFromBoxName(name: Uint8Array): bigint | undefined {
    if (name.length !== OPERATOR_PREFIX.length + 8 || !hasPrefix(name, OPERATOR_PREFIX)) return undefined
    return readBe64(name, OPERATOR_PREFIX.length)
}

// nodeIdsFromBoxName is the inverse of nodeBoxKey, undefined for a name that
// isn't a well-formed node box.
export function nodeIdsFromBoxName(name: Uint8Array): { operatorId: bigint; nodeId: bigint } | undefined {
    if (name.length !== NODE_PREFIX.length + 16 || !hasPrefix(name, NODE_PREFIX)) return undefined
    return { operatorId: readBe64(name, NODE_PREFIX.length), nodeId: readBe64(name, NODE_PREFIX.length + 8) }
}

// freeQuotaBoxKey returns "q:" + the payer's raw 32-byte public key — the
// contract keys the map by Account, whose native encoding is the public key,
// not the base32 address.
export function freeQuotaBoxKey(payerAddr: string): Uint8Array {
    return concatBytes(FREE_QUOTA_PREFIX, decodeAlgorandAddress(payerAddr))
}

// openBoxReferences returns the box names an open() app call must reference,
// all against the called app (app index 0). The operator, node and ticket boxes
// are always present. The free-quota box is added only on a free
// (maxPrice == 0) open: the contract touches it only inside that guard, so on a
// paid open it would be dead weight that writes a stable payer pseudonym onto
// the chain.
export function openBoxReferences(
    operatorId: bigint,
    nodeId: bigint,
    ticketIdRaw: Uint8Array,
    payerAddr: string,
    maxPrice: bigint,
): Uint8Array[] {
    const refs = [operatorBoxKey(operatorId), nodeBoxKey(operatorId, nodeId), ticketBoxKey(ticketIdRaw)]
    if (maxPrice === 0n) refs.push(freeQuotaBoxKey(payerAddr))
    return refs
}
