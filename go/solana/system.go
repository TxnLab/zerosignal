/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import "encoding/binary"

// SystemTransferTag is the system program's Transfer tag, the first data
// word.
const SystemTransferTag = 2

// SystemTransfer moves lamports from from, which signs, to to. Sending all of
// an account's lamports leaves it empty, which the runtime then deletes; a
// partial send must leave it rent-exempt.
func SystemTransfer(from, to PublicKey, lamports uint64) Instruction {
	data := binary.LittleEndian.AppendUint32(nil, SystemTransferTag)
	return Instruction{
		ProgramID: SystemProgramID,
		Accounts: []AccountMeta{
			{PublicKey: from, IsSigner: true, IsWritable: true},
			{PublicKey: to, IsWritable: true},
		},
		Data: binary.LittleEndian.AppendUint64(data, lamports),
	}
}
