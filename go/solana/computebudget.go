/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import "encoding/binary"

// The compute budget program's tags, each instruction's first data byte.
const (
	ComputeBudgetSetComputeUnitLimit = 2
	ComputeBudgetSetComputeUnitPrice = 3
)

// SetComputeUnitLimit caps the transaction's compute units. The priority fee
// is charged on the requested limit, and under the runtime's default limit on
// units the transaction never uses.
func SetComputeUnitLimit(units uint32) Instruction {
	data := make([]byte, 5)
	data[0] = ComputeBudgetSetComputeUnitLimit
	binary.LittleEndian.PutUint32(data[1:], units)
	return Instruction{ProgramID: ComputeBudgetProgramID, Data: data}
}

// SetComputeUnitPrice sets the priority fee, in micro-lamports per compute
// unit. A transaction others co-sign sets its own: a fee added after one
// signer signs changes the message the others signed.
func SetComputeUnitPrice(microLamports uint64) Instruction {
	data := make([]byte, 9)
	data[0] = ComputeBudgetSetComputeUnitPrice
	binary.LittleEndian.PutUint64(data[1:], microLamports)
	return Instruction{ProgramID: ComputeBudgetProgramID, Data: data}
}
