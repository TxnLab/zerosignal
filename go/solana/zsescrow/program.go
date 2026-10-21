/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package zsescrow speaks the zs_escrow Solana program: its addresses, its
// instructions, its accounts and its events. Builders derive every program
// address from the ids the caller names, so a caller never passes an address
// the program would refuse.
//
// proto/ts/src/solana/zsescrow is its TypeScript mirror. Both replay the
// fixtures the program's own tests write (testdata/solana_*_vectors.json), and
// the program's IDL sits beside the codec in go/solana/idl.
package zsescrow

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/TxnLab/zerosignal/go/solana"
)

// ProgramID is the program on every cluster it is deployed to today.
var ProgramID = solana.MustPublicKey("2sXCgAPUVAFvmDhXG1pLGA6mjnWpqR521MZTfMnyc9h1")

// Seeds of the program's addresses.
const (
	ConfigSeed         = "config"
	OperatorSeed       = "op"
	NodeSeed           = "node"
	VaultSeed          = "vault"
	StakeVaultSeed     = "stake"
	TicketSeed         = "t"
	EventAuthoritySeed = "__event_authority"
)

// AccountVersion is the version every account this program creates carries.
const AccountVersion = 1

// BaseURLMax is the longest node URL the program stores.
const BaseURLMax = 248

// Deployment is one deployment of the program: its id and the USDC mint its
// Config names. The mint is a parameter because a test cluster has its own.
type Deployment struct {
	Program solana.PublicKey
	Mint    solana.PublicKey
}

func (d Deployment) pda(seeds ...[]byte) (solana.PublicKey, uint8) {
	k, bump, err := solana.FindProgramAddress(seeds, d.Program)
	if err != nil {
		// Every seed list here is fixed-length and under the limits, and a
		// search over 256 bumps finding none has never happened: a panic
		// marks a bug, never an input.
		panic("zsescrow: " + err.Error())
	}
	return k, bump
}

func u64le(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func (d Deployment) Config() solana.PublicKey     { k, _ := d.pda([]byte(ConfigSeed)); return k }
func (d Deployment) StakeVault() solana.PublicKey { k, _ := d.pda([]byte(StakeVaultSeed)); return k }

// EventAuthority signs the program's self-invocations that carry events.
func (d Deployment) EventAuthority() solana.PublicKey {
	k, _ := d.pda([]byte(EventAuthoritySeed))
	return k
}

// Operator is the operator with this id. Ids start at 1.
func (d Deployment) Operator(id uint64) solana.PublicKey {
	k, _ := d.pda([]byte(OperatorSeed), u64le(id))
	return k
}

// Node is the operator's node with this id. Node ids start at 1 within each
// operator and are never reused.
func (d Deployment) Node(operatorID, nodeID uint64) solana.PublicKey {
	k, _ := d.pda([]byte(NodeSeed), u64le(operatorID), u64le(nodeID))
	return k
}

// Vault is the node's USDC token account, which holds its tickets' escrow and
// is its own authority.
func (d Deployment) Vault(node solana.PublicKey) solana.PublicKey {
	k, _ := d.pda([]byte(VaultSeed), node[:])
	return k
}

// Ticket is the node's ticket with this wire ticket id.
func (d Deployment) Ticket(node solana.PublicKey, ticketID [16]byte) solana.PublicKey {
	k, _ := d.pda([]byte(TicketSeed), node[:], ticketID[:])
	return k
}

// TokenAccount is owner's associated USDC account.
func (d Deployment) TokenAccount(owner solana.PublicKey) solana.PublicKey {
	k, _, err := solana.AssociatedTokenAddress(owner, d.Mint)
	if err != nil {
		panic("zsescrow: " + err.Error())
	}
	return k
}

// RefundBumps is the bump of the payer's token account. A settle carries it
// so the program derives the address once instead of searching, a search
// whose length the payer could grind its key to stretch.
type RefundBumps struct {
	PayerATA uint8 `json:"payer_ata"`
}

func (d Deployment) RefundBumps(payer solana.PublicKey) RefundBumps {
	_, ata, err := solana.AssociatedTokenAddress(payer, d.Mint)
	if err != nil {
		panic("zsescrow: " + err.Error())
	}
	return RefundBumps{PayerATA: ata}
}

// AccountDiscriminator is the 8 bytes every account of the named type (say
// "Node") starts with: what a getProgramAccounts memcmp filter matches to read
// one type of the program's accounts.
func AccountDiscriminator(name string) [8]byte { return discriminator("account", name) }

// discriminator is Anchor's: the first 8 bytes of sha256 of a namespaced name.
func discriminator(namespace, name string) [8]byte {
	h := sha256.Sum256([]byte(namespace + ":" + name))
	return [8]byte(h[:8])
}
