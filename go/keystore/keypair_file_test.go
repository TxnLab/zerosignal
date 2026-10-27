/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadSolanaKeypairFile(t *testing.T) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	write := func(t *testing.T, v any) string {
		t.Helper()
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "k.json")
		if err := os.WriteFile(p, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ints := func(b []byte) []int {
		out := make([]int, len(b))
		for i, v := range b {
			out[i] = int(v)
		}
		return out
	}

	got, err := ReadSolanaKeypairFile(write(t, ints(key)))
	if err != nil || !got.Equal(key) {
		t.Fatalf("got %x, %v; want the key", got, err)
	}
	// 255 is a byte, so a key holding one reads.
	high := ed25519.NewKeyFromSeed([]byte(strings.Repeat("\xff", ed25519.SeedSize)))
	if got, err := ReadSolanaKeypairFile(write(t, ints(high))); err != nil || !got.Equal(high) {
		t.Fatalf("a key with 255 bytes: %x, %v", got, err)
	}

	other := ed25519.NewKeyFromSeed(append(make([]byte, ed25519.SeedSize-1), 1))
	mismatched := append(append([]byte{}, key[:ed25519.SeedSize]...), other[ed25519.SeedSize:]...)
	// The whole public half is checked, its first and last bytes too.
	lastByte := append([]byte{}, key...)
	lastByte[63] ^= 1
	firstByte := append([]byte{}, key...)
	firstByte[32] ^= 1
	for name, tc := range map[string]struct {
		v    any
		want string
	}{
		"not an array":   {map[string]int{"a": 1}, "not a keypair file"},
		"out of range":   {append(ints(key[:63]), 256), "not a keypair file"},
		"negative":       {append(ints(key[:63]), -1), "not a keypair file"},
		"short":          {ints(key[:32]), "holds 32 bytes"},
		"mismatched":     {ints(mismatched), "not the seed's"},
		"last byte off":  {ints(lastByte), "not the seed's"},
		"first byte off": {ints(firstByte), "not the seed's"},
		"long":           {ints(append(append([]byte{}, key...), 0)), "holds 65 bytes"},
	} {
		if _, err := ReadSolanaKeypairFile(write(t, tc.v)); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}

	// The decode error stays reachable for a caller that tells a malformed
	// file from a missing one.
	var ute *json.UnmarshalTypeError
	if _, err := ReadSolanaKeypairFile(write(t, map[string]int{"a": 1})); !errors.As(err, &ute) {
		t.Errorf("not an array: %v, want the JSON error wrapped", err)
	}
}
