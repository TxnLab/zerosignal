/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package keystore

import (
	"context"
	"os"
	"strings"
)

// EnvProvider scans the OS environment for entries whose names end in
// "_MNEMONIC". Each match yields a MnemonicEntry with the "_MNEMONIC"
// suffix stripped so log lines name the source cleanly.
//
// Convention: "OPERATOR_SIGNING_MNEMONIC=<25 words>" loads as Name
// "OPERATOR_SIGNING". The address comes from deriving it; the Name is
// just a label.
//
// EnvProvider is the cheapest path and is always safe to include in the
// provider chain — if no *_MNEMONIC vars are set it returns an empty
// slice and the keystore moves on to the next provider.
type EnvProvider struct{}

// Mnemonics returns every *_MNEMONIC value set in the environment.
// Empty values are skipped (KeyStore.New also skips them, but doing it
// here keeps the slice tidy for tests).
func (EnvProvider) Mnemonics(_ context.Context) ([]MnemonicEntry, error) {
	const suffix = "_MNEMONIC"
	var out []MnemonicEntry
	for _, entry := range os.Environ() {
		key, val, ok := strings.Cut(entry, "=")
		if !ok || val == "" || !strings.HasSuffix(key, suffix) {
			continue
		}
		out = append(out, MnemonicEntry{
			Name:     strings.TrimSuffix(key, suffix),
			Mnemonic: val,
		})
	}
	return out, nil
}
