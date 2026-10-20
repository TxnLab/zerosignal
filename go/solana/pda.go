/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import (
	"crypto/sha256"
	"errors"

	"filippo.io/edwards25519"
)

const (
	MaxSeeds      = 16
	MaxSeedLength = 32
)

var (
	ErrSeeds   = errors.New("solana: too many seeds, or a seed over 32 bytes")
	ErrOnCurve = errors.New("solana: seeds give a point on the ed25519 curve")
	ErrNoBump  = errors.New("solana: no bump gives an address off the curve")
)

// CreateProgramAddress is the runtime's create_program_address: the address
// must be off the ed25519 curve, so no private key can sign for it and only
// the program can.
func CreateProgramAddress(seeds [][]byte, program PublicKey) (PublicKey, error) {
	if len(seeds) > MaxSeeds {
		return PublicKey{}, ErrSeeds
	}
	h := sha256.New()
	for _, s := range seeds {
		if len(s) > MaxSeedLength {
			return PublicKey{}, ErrSeeds
		}
		h.Write(s)
	}
	h.Write(program[:])
	h.Write([]byte("ProgramDerivedAddress"))
	var k PublicKey
	h.Sum(k[:0])
	if IsOnCurve(k) {
		return PublicKey{}, ErrOnCurve
	}
	return k, nil
}

// FindProgramAddress is find_program_address: the first bump from 255 down
// to 1 that gives an address off the curve (the runtime never tries 0).
// Programs check the canonical bump, so any other bump names an address the
// program refuses.
func FindProgramAddress(seeds [][]byte, program PublicKey) (PublicKey, uint8, error) {
	if len(seeds) >= MaxSeeds {
		return PublicKey{}, 0, ErrSeeds
	}
	withBump := append(append([][]byte{}, seeds...), []byte{0})
	for bump := 255; bump >= 1; bump-- {
		withBump[len(seeds)][0] = uint8(bump)
		k, err := CreateProgramAddress(withBump, program)
		if err == nil {
			return k, uint8(bump), nil
		}
		if !errors.Is(err, ErrOnCurve) {
			return PublicKey{}, 0, err
		}
	}
	return PublicKey{}, 0, ErrNoBump
}

// IsOnCurve reports whether k decodes as an ed25519 point. Like the runtime's
// curve25519-dalek decompress, it accepts a non-canonical y.
func IsOnCurve(k PublicKey) bool {
	_, err := new(edwards25519.Point).SetBytes(k[:])
	return err == nil
}

// AssociatedTokenAddress is the owner's associated token account for mint
// under the classic token program.
func AssociatedTokenAddress(owner, mint PublicKey) (PublicKey, uint8, error) {
	return FindProgramAddress([][]byte{owner[:], TokenProgramID[:], mint[:]}, AssociatedTokenProgramID)
}
