/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/solana"
)

// The precompile's offsets record carries the message size as a u16, so
// Ed25519Verify takes a message of 65535 bytes and panics past it, as the TS
// twin throws, rather than writing a size that names a shorter message.
func TestEd25519Verify_MessageSizeBound(t *testing.T) {
	panics := func(n int) (p bool) {
		defer func() { p = recover() != nil }()
		solana.Ed25519Verify(solana.PublicKey{}, solana.Signature{}, make([]byte, n))
		return false
	}
	if panics(0xffff) {
		t.Error("a 65535-byte message panicked")
	}
	if !panics(0x10000) {
		t.Error("a 65536-byte message did not panic")
	}
}
