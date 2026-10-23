/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import "encoding/binary"

// The Ed25519 precompile's layout for one signature: the count and a padding
// byte, one offsets record, then the key, the signature and the message, each
// in the instruction's own data.
const (
	ed25519DataStart = 2 + 14
	ed25519KeyAt     = ed25519DataStart
	ed25519SigAt     = ed25519KeyAt + 32
	ed25519MsgAt     = ed25519SigAt + 64
	// ed25519ThisIx is the instruction index meaning the precompile's own data.
	ed25519ThisIx = 0xffff
)

// Ed25519Verify is the Ed25519 precompile instruction checking sig, by key,
// over msg, in the layout the precompile's own builder writes. A program that
// reads it by introspection, as zs_escrow's protest does, accepts that layout
// alone, so a signature placed anywhere else fails the transaction. It panics
// on a msg past the layout's u16 size, as the TS twin throws; callers pass a
// 32-byte digest.
func Ed25519Verify(key PublicKey, sig Signature, msg []byte) Instruction {
	if len(msg) > 0xffff {
		panic("solana: Ed25519Verify: message past 65535 bytes")
	}
	data := make([]byte, ed25519MsgAt+len(msg))
	data[0] = 1
	for i, v := range []uint16{ed25519SigAt, ed25519ThisIx, ed25519KeyAt, ed25519ThisIx, ed25519MsgAt, uint16(len(msg)), ed25519ThisIx} {
		binary.LittleEndian.PutUint16(data[2+2*i:], v)
	}
	copy(data[ed25519KeyAt:], key[:])
	copy(data[ed25519SigAt:], sig[:])
	copy(data[ed25519MsgAt:], msg)
	return Instruction{ProgramID: Ed25519ProgramID, Data: data}
}
