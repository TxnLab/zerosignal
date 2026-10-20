/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import (
	"bytes"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// VerifyStrict is the runtime's signature check, curve25519-dalek's
// verify_strict: S must be canonical, neither the key nor R may be of small
// order, and the equation is cofactorless, R = [S]B - [k]A compared as
// encoded bytes, so a non-canonical R fails too. ed25519 libraries disagree
// at these edges (Go's crypto/ed25519 accepts a small-order key; @noble's
// default is cofactored), and a payer that accepts a signature the runtime
// refuses believes a transaction will land that never can.
func VerifyStrict(key PublicKey, msg []byte, sig Signature) bool {
	A, err := new(edwards25519.Point).SetBytes(key[:])
	if err != nil {
		return false
	}
	R, err := new(edwards25519.Point).SetBytes(sig[:32])
	if err != nil {
		return false
	}
	if isSmallOrder(A) || isSmallOrder(R) {
		return false
	}
	S, err := edwards25519.NewScalar().SetCanonicalBytes(sig[32:])
	if err != nil {
		return false
	}
	h := sha512.New()
	h.Write(sig[:32])
	h.Write(key[:])
	h.Write(msg)
	k, err := edwards25519.NewScalar().SetUniformBytes(h.Sum(nil))
	if err != nil {
		return false
	}
	minusA := new(edwards25519.Point).Negate(A)
	got := new(edwards25519.Point).VarTimeDoubleScalarBaseMult(k, minusA, S)
	return bytes.Equal(got.Bytes(), sig[:32])
}

func isSmallOrder(p *edwards25519.Point) bool {
	return new(edwards25519.Point).MultByCofactor(p).Equal(edwards25519.NewIdentityPoint()) == 1
}
