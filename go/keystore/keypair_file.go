/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode"

	"github.com/TxnLab/zerosignal/go/solana"
)

// ReadSolanaKeypairFile reads a solana-keygen keypair file: a JSON array of
// the 64 bytes of the seed and the public key. The public half must be the
// seed's, so a hand-edited file can't sign as one key while naming another.
func ReadSolanaKeypairFile(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	var ints []int
	if err := json.Unmarshal(raw, &ints); err != nil {
		return nil, fmt.Errorf("keystore: %s is not a keypair file: %w", path, err)
	}
	key, err := keypairFromInts(ints)
	clear(ints)
	if err != nil {
		return nil, fmt.Errorf("keystore: %s %w", path, err)
	}
	return key, nil
}

// solanaSecretKey reads s as one of Solana's own secret-key forms, which a
// keystore entry may hold in place of a phrase: a solana-keygen keypair
// file's JSON array, the usual form of a server's key, or the base58 secret
// key Phantom and Solflare export for any account. ok is false for anything
// else, which is left to the phrase path; err is set for what is plainly one
// of those forms but not a key. No error carries s, which is a secret.
func solanaSecretKey(s string) (key ed25519.PrivateKey, ok bool, err error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		var ints []int
		// json's error quotes the byte it stopped at, so it is not wrapped.
		if json.Unmarshal([]byte(s), &ints) != nil {
			return nil, true, errors.New("is not a keypair file's JSON array")
		}
		key, err = keypairFromInts(ints)
		clear(ints)
		return key, true, err
	}
	if strings.ContainsFunc(s, unicode.IsSpace) {
		return nil, false, nil
	}
	b, err := solana.DecodeBase58(s, ed25519.PrivateKeySize)
	if err != nil {
		// One long base58 word is no phrase, so it is reported as the key it
		// was meant to be, such as an export cut short in a copy, rather than
		// as a one-word phrase. A short word is left to the phrase path.
		if len(s) >= minBase58KeyLen && strings.Trim(s, base58Alphabet) == "" {
			return nil, true, errors.New("is base58 but not a 64-byte secret key")
		}
		return nil, false, nil
	}
	defer clear(b)
	key, err = keypairFromBytes(b)
	return key, true, err
}

const (
	base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	// minBase58KeyLen is half an export's 87 or 88 characters: longer than
	// any BIP-39 word, and long enough that a cut export still reads as one.
	minBase58KeyLen = 44
)

func keypairFromInts(ints []int) (ed25519.PrivateKey, error) {
	b := make([]byte, 0, len(ints))
	defer func() { clear(b) }()
	for _, v := range ints {
		if v < 0 || v > 255 {
			return nil, errors.New("is not a keypair file")
		}
		b = append(b, byte(v))
	}
	return keypairFromBytes(b)
}

func keypairFromBytes(b []byte) (ed25519.PrivateKey, error) {
	if len(b) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("holds %d bytes, want %d", len(b), ed25519.PrivateKeySize)
	}
	key := ed25519.NewKeyFromSeed(b[:ed25519.SeedSize])
	if !bytes.Equal(key[ed25519.SeedSize:], b[ed25519.SeedSize:]) {
		return nil, errors.New("is a key whose public half is not the seed's")
	}
	return key, nil
}
