/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"
)

// ReadSolanaKeypairFile reads a solana-keygen keypair file: a JSON array of
// the 64 bytes of the seed and the public key. It is for the test clusters'
// authorities (a localnet mint's, a deployer's), which solana-keygen writes;
// a payer's key comes from a phrase. The public half must be the seed's, so a
// hand-edited file can't sign as one key while naming another.
func ReadSolanaKeypairFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var ints []int
	if err := json.Unmarshal(raw, &ints); err != nil {
		return nil, fmt.Errorf("keystore: %s is not a keypair file: %w", path, err)
	}
	b := make([]byte, 0, len(ints))
	for _, v := range ints {
		if v < 0 || v > 255 {
			return nil, fmt.Errorf("keystore: %s is not a keypair file", path)
		}
		b = append(b, byte(v))
	}
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("keystore: %s holds %d bytes, want %d", path, len(b), ed25519.PrivateKeySize)
	}
	key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	if !bytes.Equal(key[ed25519.SeedSize:], b[ed25519.SeedSize:]) {
		return nil, fmt.Errorf("keystore: %s: the public key is not the seed's", path)
	}
	return key, nil
}
