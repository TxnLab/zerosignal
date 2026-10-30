/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package solana is the Solana rail's wire layer: keys and base58, program
// derived addresses, and the transaction message codec, legacy and v0 without
// lookup tables (a v0 message with lookups decodes, so a verifier can see and
// refuse it). It is hand-rolled rather than built on solana-go, which would
// bring its dependency tree into every module that builds proto.
//
// proto/ts/src/solana is its TypeScript mirror. Both replay the fixtures the
// zs_escrow program's own tests write (testdata/solana_*_vectors.json), so a
// layout the two languages agree on is also the one the program uses.
package solana

import (
	"bytes"
	"fmt"
)

// PublicKey is an account address: an ed25519 key or a program derived address.
type PublicKey [32]byte

// Hash is a blockhash or a genesis hash.
type Hash [32]byte

// Signature is an ed25519 signature over a message's bytes.
type Signature [64]byte

func (k PublicKey) String() string { return encodeBase58(k[:]) }
func (h Hash) String() string      { return encodeBase58(h[:]) }
func (s Signature) String() string { return encodeBase58(s[:]) }

func (k PublicKey) IsZero() bool { return k == PublicKey{} }

func (k PublicKey) Bytes() []byte { return k[:] }

func (k PublicKey) MarshalText() ([]byte, error) { return []byte(k.String()), nil }

func (k *PublicKey) UnmarshalText(b []byte) error {
	p, err := ParsePublicKey(string(b))
	if err != nil {
		return err
	}
	*k = p
	return nil
}

// Compare orders keys by their bytes, the order the runtime's message
// compiler sorts them in.
func (k PublicKey) Compare(o PublicKey) int { return bytes.Compare(k[:], o[:]) }

// DecodeBase58 decodes s into exactly size bytes. Its error never quotes s,
// so a caller decoding a secret key can report it.
func DecodeBase58(s string, size int) ([]byte, error) { return decodeBase58(s, size) }

func ParsePublicKey(s string) (PublicKey, error) {
	var k PublicKey
	b, err := decodeBase58(s, len(k))
	if err != nil {
		return k, fmt.Errorf("solana: public key %q: %w", short(s), err)
	}
	copy(k[:], b)
	return k, nil
}

// short keeps an error from carrying a whole oversized input.
func short(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// MustPublicKey is ParsePublicKey for compile-time constants.
func MustPublicKey(s string) PublicKey {
	k, err := ParsePublicKey(s)
	if err != nil {
		panic(err)
	}
	return k
}

func ParseHash(s string) (Hash, error) {
	var h Hash
	b, err := decodeBase58(s, len(h))
	if err != nil {
		return h, fmt.Errorf("solana: hash %q: %w", short(s), err)
	}
	copy(h[:], b)
	return h, nil
}

func ParseSignature(s string) (Signature, error) {
	var sig Signature
	b, err := decodeBase58(s, len(sig))
	if err != nil {
		return sig, fmt.Errorf("solana: signature: %w", err)
	}
	copy(sig[:], b)
	return sig, nil
}

// SignatureFromBytes reads a raw signature, such as a signer returns. It
// refuses any length but 64, where a conversion to Signature would panic.
func SignatureFromBytes(b []byte) (Signature, error) {
	var sig Signature
	if len(b) != len(sig) {
		return sig, fmt.Errorf("solana: signature: %d bytes, want %d", len(b), len(sig))
	}
	copy(sig[:], b)
	return sig, nil
}

// The programs and sysvars the rail's transactions name.
var (
	SystemProgramID               = PublicKey{}
	ComputeBudgetProgramID        = MustPublicKey("ComputeBudget111111111111111111111111111111")
	TokenProgramID                = MustPublicKey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
	AssociatedTokenProgramID      = MustPublicKey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
	Ed25519ProgramID              = MustPublicKey("Ed25519SigVerify111111111111111111111111111")
	BPFLoaderUpgradeableProgramID = MustPublicKey("BPFLoaderUpgradeab1e11111111111111111111111")
	SysvarInstructionsID          = MustPublicKey("Sysvar1nstructions1111111111111111111111111")
	SysvarRentID                  = MustPublicKey("SysvarRent111111111111111111111111111111111")
	SysvarClockID                 = MustPublicKey("SysvarC1ock11111111111111111111111111111111")
	AddressLookupTableProgramID   = MustPublicKey("AddressLookupTab1e1111111111111111111111111")
	NameServiceProgramID          = MustPublicKey("namesLPneVptA9Z5rqUDD9tMTWEJwofgaYwp8cawRkX")
	SolTLD                        = MustPublicKey("58PwtjSDuFHuUkYjH9BYnnQKHfwo9reZhC2zMJv9JPkx")
)
