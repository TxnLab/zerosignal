/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import "encoding/binary"

// TokenTransferChecked is SPL Token's TransferChecked tag, the first data
// byte.
const TokenTransferChecked = 12

// TransferChecked moves amount of mint from source to destination, signed by
// authority, the source's owner. The token program refuses it unless
// decimals is the mint's, which is why the open offer uses it rather than
// Transfer: the escrow program checks the instruction's tag and fields.
func TransferChecked(source, mint, destination, authority PublicKey, amount uint64, decimals uint8) Instruction {
	data := make([]byte, 10)
	data[0] = TokenTransferChecked
	binary.LittleEndian.PutUint64(data[1:], amount)
	data[9] = decimals
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts: []AccountMeta{
			{PublicKey: source, IsWritable: true},
			{PublicKey: mint},
			{PublicKey: destination, IsWritable: true},
			{PublicKey: authority, IsSigner: true},
		},
		Data: data,
	}
}

// TokenMintTo is SPL Token's MintTo tag, the first data byte.
const TokenMintTo = 7

// MintTo mints amount of mint to destination, a token account of mint,
// signed by authority, the mint's authority. Only a test mint's authority is
// ever at hand: a localnet's, or devnet's test USDC.
func MintTo(mint, destination, authority PublicKey, amount uint64) Instruction {
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts: []AccountMeta{
			{PublicKey: mint, IsWritable: true},
			{PublicKey: destination, IsWritable: true},
			{PublicKey: authority, IsSigner: true},
		},
		Data: binary.LittleEndian.AppendUint64([]byte{TokenMintTo}, amount),
	}
}

// TokenCloseAccount is SPL Token's CloseAccount tag, its only data byte.
const TokenCloseAccount = 9

// CloseAccount closes account, which must hold no tokens, and sends its rent
// to destination, signed by owner, the account's owner. A payer moving to a
// new key closes its old token account so its rent goes with it.
func CloseAccount(account, destination, owner PublicKey) Instruction {
	return Instruction{
		ProgramID: TokenProgramID,
		Accounts: []AccountMeta{
			{PublicKey: account, IsWritable: true},
			{PublicKey: destination, IsWritable: true},
			{PublicKey: owner, IsSigner: true},
		},
		Data: []byte{TokenCloseAccount},
	}
}

// AssociatedTokenCreateIdempotent is the associated token program's
// CreateIdempotent tag, its only data byte.
const AssociatedTokenCreateIdempotent = 1

// CreateAssociatedTokenAccountIdempotent creates owner's associated token
// account for mint under the classic token program, paid for by payer, and
// succeeds without change when it already exists for owner, so a transaction
// can carry it ahead of a payout without first reading the chain. It fails,
// and with it the whole transaction, when owner has moved that account's
// ownership to another key, which the classic program allows.
func CreateAssociatedTokenAccountIdempotent(payer, owner, mint PublicKey) Instruction {
	ata, _, err := AssociatedTokenAddress(owner, mint)
	if err != nil {
		panic("solana: " + err.Error())
	}
	return Instruction{
		ProgramID: AssociatedTokenProgramID,
		Accounts: []AccountMeta{
			{PublicKey: payer, IsSigner: true, IsWritable: true},
			{PublicKey: ata, IsWritable: true},
			{PublicKey: owner},
			{PublicKey: mint},
			{PublicKey: SystemProgramID},
			{PublicKey: TokenProgramID},
		},
		Data: []byte{AssociatedTokenCreateIdempotent},
	}
}
