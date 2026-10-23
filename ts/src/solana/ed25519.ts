/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// The Ed25519 precompile instruction. Mirrors proto/go/solana/ed25519.go.

import { ED25519_PROGRAM_ID, type PublicKey, publicKeyBytes } from './key.js'
import type { Instruction } from './message.js'

// The layout for one signature: the count and a padding byte, one offsets
// record, then the key, the signature and the message, each in the
// instruction's own data.
const DATA_START = 2 + 14
const KEY_AT = DATA_START
const SIG_AT = KEY_AT + 32
const MSG_AT = SIG_AT + 64
// The instruction index meaning the precompile's own data.
const THIS_IX = 0xffff

/**
 * The Ed25519 precompile instruction checking sig, by key, over msg, in the
 * layout the precompile's own builder writes. A program that reads it by
 * introspection, as zs_escrow's protest does, accepts that layout alone, so a
 * signature placed anywhere else fails the transaction.
 */
export function ed25519Verify(key: PublicKey, sig: Uint8Array, msg: Uint8Array): Instruction {
    // Go's Signature and uint16 rule these out.
    if (sig.length !== 64) throw new RangeError(`solana: an Ed25519 signature of ${sig.length} bytes`)
    if (msg.length > 0xffff) throw new RangeError(`solana: an Ed25519 message of ${msg.length} bytes`)
    const data = new Uint8Array(MSG_AT + msg.length)
    data[0] = 1
    const v = new DataView(data.buffer)
    ;[SIG_AT, THIS_IX, KEY_AT, THIS_IX, MSG_AT, msg.length, THIS_IX].forEach((x, i) => v.setUint16(2 + 2 * i, x, true))
    data.set(publicKeyBytes(key), KEY_AT)
    data.set(sig, SIG_AT)
    data.set(msg, MSG_AT)
    return { programId: ED25519_PROGRAM_ID, accounts: [], data }
}
