/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
)

// BytesSigner produces a raw Ed25519 signature over msg under the key
// identified by an Algorand address. Implementations MUST sign msg
// verbatim — no domain prefix, no hashing — so callers retain full
// control over the signing payload (Ticket.Sign / UsageReceipt.Sign
// pass a 32-byte sha256 digest of a domain-tagged canonical body).
//
// This is the seam the node + proxy use to back ticket / payment / ATC
// signing with a mnemonic-loaded keystore (proto/keystore) without
// dragging the keystore implementation into the proto root.
type BytesSigner interface {
	SignBytes(ctx context.Context, address string, msg []byte) ([]byte, error)
}

// Algorand account identifiers are 58-character base32 strings over
// (32-byte Ed25519 public key || 4-byte SHA-512/256 checksum of the pubkey).
// The operator's Algorand account doubles as its ticket-signing identity:
// the ed25519 pubkey underneath the address is what verifies
// Ticket.Sig, and the same private key (held by the node) is what signs.
//
// Using the Algorand account for ticket signing means:
//   - No separate key to provision / publish / rotate.
//   - The on-chain registry entry carries one identifier for both
//     "who gets paid" and "who signed this promise".
//
// Note this is NOT interchangeable with go-algorand-sdk's
// crypto.SignBytes (which prepends "MX" to the raw message). Hayai
// ticket / receipt signatures are raw Ed25519 over a 32-byte sha256
// digest of a domain-tagged canonical body — see ticket.go and
// receipt.go. The signer must expose a raw Ed25519 sign operation, or
// accept the precomputed digest without further framing.
const (
	algoPubKeySize    = ed25519.PublicKeySize // 32
	algoChecksumSize  = 4
	algoAddressRawLen = algoPubKeySize + algoChecksumSize // 36
	algoAddressLen    = 58                                // ceil(36*8/5) with no padding
)

// DecodeAlgorandAddress decodes a 58-character Algorand address into its
// underlying Ed25519 public key, validating the checksum. This is the
// verifier proxies use for Ticket.Verify: the registry publishes only the
// address, and the pubkey is recovered on demand.
func DecodeAlgorandAddress(addr string) (ed25519.PublicKey, error) {
	if len(addr) != algoAddressLen {
		return nil, fmt.Errorf("algorand address length %d, want %d", len(addr), algoAddressLen)
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(addr)
	if err != nil {
		return nil, fmt.Errorf("decode base32 address: %w", err)
	}
	if len(raw) != algoAddressRawLen {
		return nil, fmt.Errorf("decoded address %d bytes, want %d", len(raw), algoAddressRawLen)
	}
	pub := raw[:algoPubKeySize]
	gotChk := raw[algoPubKeySize:]
	wantChk := algorandChecksum(pub)
	if subtle.ConstantTimeCompare(gotChk, wantChk) != 1 {
		return nil, errors.New("algorand address checksum mismatch")
	}
	out := make(ed25519.PublicKey, ed25519.PublicKeySize)
	copy(out, pub)
	return out, nil
}

// EncodeAlgorandAddress is the inverse of DecodeAlgorandAddress.
// Primarily for tests and for tooling that derives an address from a
// generated keypair.
func EncodeAlgorandAddress(pub ed25519.PublicKey) string {
	if len(pub) != algoPubKeySize {
		return ""
	}
	raw := make([]byte, 0, algoAddressRawLen)
	raw = append(raw, pub...)
	raw = append(raw, algorandChecksum(pub)...)
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
}

// algorandChecksum returns the last 4 bytes of SHA-512/256(pub) — the
// checksum Algorand embeds in addresses.
func algorandChecksum(pub []byte) []byte {
	h := sha512.Sum512_256(pub)
	return h[len(h)-algoChecksumSize:]
}

// GenerateAlgorandKeypair returns a fresh Ed25519 keypair and the
// pre-encoded Algorand address for it. The private key signs tickets
// via Ticket.Sign; the address is what goes into the operator registry.
func GenerateAlgorandKeypair() (addr string, pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	pub, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, nil, err
	}
	addr = EncodeAlgorandAddress(pub)
	return addr, pub, priv, nil
}
