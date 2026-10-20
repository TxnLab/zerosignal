/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package solana

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The vector file's compact_u16 pairs are written by hand in the generator,
// so they are checked here against the encoder and the reader themselves.
func TestCompactU16MatchesTheVectorFile(t *testing.T) {
	var v struct {
		CompactU16 []struct {
			Value int    `json:"value"`
			Hex   string `json:"hex"`
		} `json:"compact_u16"`
	}
	b, err := os.ReadFile("../../testdata/solana_codec_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.CompactU16) == 0 {
		t.Fatal("no cases")
	}
	for _, c := range v.CompactU16 {
		if got := hex.EncodeToString(appendCompactU16(nil, c.Value)); got != c.Hex {
			t.Errorf("%d encodes as %s, want %s", c.Value, got, c.Hex)
		}
		raw, _ := hex.DecodeString(c.Hex)
		r := reader{b: raw}
		if got := r.compactU16(); got != c.Value || r.err != nil || r.off != len(raw) {
			t.Errorf("%s decodes as %d (%v)", c.Hex, got, r.err)
		}
	}
}
