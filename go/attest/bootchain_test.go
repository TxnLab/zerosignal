/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

const (
	bootTestImage059    = "bd369a8c2f9edb2b52dad48ac8e0b32dde5f1337c423a506b48d07403a7d8033"
	bootTestImageNvidia = "91fd5d69ccee3e5ea4f2aeb8c9b632c4358c4ecfc29ba1aa6fb1e402af209829"
)

// The verdict vectors pin the verifier's use of this; these pin which
// error class each refusal is, which only Go's callers branch on.
func TestVerifyBootChain(t *testing.T) {
	_, quote := loadVectors(t)
	chains := TrustedDstackBootChains()
	if err := VerifyBootChain(quote, bootTestImage059, chains); err != nil {
		t.Fatalf("the capture refused: %v", err)
	}
	if err := VerifyBootChain(quote, strings.ToUpper(bootTestImage059), chains); err != nil {
		t.Errorf("an uppercase os-image-hash refused: %v", err)
	}

	unknown := []struct{ name, osImage string }{
		{"untrusted image", strings.Repeat("ab", 32)},
		{"unmeasured row", bootTestImageNvidia},
		{"empty image", ""},
	}
	for _, c := range unknown {
		if err := VerifyBootChain(quote, c.osImage, chains); !errors.Is(err, ErrBootChainUnknown) {
			t.Errorf("%s: err = %v, want ErrBootChainUnknown", c.name, err)
		}
	}
	// ASCII folding only: the Kelvin sign U+212A folds to k under Unicode
	// rules, which the TypeScript twin's toLowerCase would apply. The TS
	// test carries the same input.
	kRow := chains[0]
	kRow.OSImage = "k"
	if err := VerifyBootChain(quote, "K", []BootChain{kRow}); !errors.Is(err, ErrBootChainUnknown) {
		t.Errorf("Kelvin sign against a row keyed k: err = %v, want ErrBootChainUnknown", err)
	}
	// An empty replayed image must not select a row whose key is empty too.
	blank := chains[0]
	blank.OSImage = ""
	if err := VerifyBootChain(quote, "", []BootChain{blank}); !errors.Is(err, ErrBootChainUnknown) {
		t.Errorf("empty image against an empty-keyed row: err = %v, want ErrBootChainUnknown", err)
	}
	// Each of the four fields that makes a row measured, emptied alone.
	for i, empty := range []func(*BootChain){
		func(b *BootChain) { b.MRTD = "" },
		func(b *BootChain) { b.RTMR1 = "" },
		func(b *BootChain) { b.RTMR2 = "" },
		func(b *BootChain) { b.RTMR0 = nil },
	} {
		row := chains[0]
		empty(&row)
		if err := VerifyBootChain(quote, bootTestImage059, []BootChain{row}); !errors.Is(err, ErrBootChainUnknown) {
			t.Errorf("field %d empty: err = %v, want ErrBootChainUnknown", i, err)
		}
	}

	regs := []struct {
		name string
		get  func([]byte) ([]byte, bool)
	}{
		{"MRTD", QuoteMRTD},
		{"RTMR0", func(q []byte) ([]byte, bool) { return QuoteRTMR(q, 0) }},
		{"RTMR1", func(q []byte) ([]byte, bool) { return QuoteRTMR(q, 1) }},
		{"RTMR2", func(q []byte) ([]byte, bool) { return QuoteRTMR(q, 2) }},
	}
	for _, r := range regs {
		q := bytes.Clone(quote)
		reg, _ := r.get(q)
		reg[len(reg)-1] ^= 1
		if err := VerifyBootChain(q, bootTestImage059, chains); !errors.Is(err, ErrBootChainMismatch) {
			t.Errorf("%s flipped: err = %v, want ErrBootChainMismatch", r.name, err)
		}
	}
	// RTMR3 is the replay's register, not the boot chain's.
	q := bytes.Clone(quote)
	r3, _ := QuoteRTMR(q, 3)
	r3[0] ^= 1
	if err := VerifyBootChain(q, bootTestImage059, chains); err != nil {
		t.Errorf("RTMR3 flipped: refused: %v", err)
	}

	// RTMR2 ends last of the four, so it is the one a short quote misses.
	end := quoteHeaderLen + bodyRTMR0 + 3*48
	if err := VerifyBootChain(quote[:end-1], bootTestImage059, chains); !errors.Is(err, ErrShortQuote) {
		t.Errorf("one byte short: err = %v, want ErrShortQuote", err)
	}
	if err := VerifyBootChain(quote[:end], bootTestImage059, chains); err != nil {
		t.Errorf("exactly long enough: refused: %v", err)
	}
}

func TestTrustedDstackBootChains(t *testing.T) {
	chains := TrustedDstackBootChains()
	var keys []string
	for _, c := range chains {
		keys = append(keys, c.OSImage)
	}
	if !slices.Equal(keys, TrustedDstackOSImages()) {
		t.Errorf("TrustedDstackOSImages = %v, want the boot-chain keys %v", TrustedDstackOSImages(), keys)
	}
	// An image cleared for the root-backdoor carve-out rests on the boot
	// chain pinning its command line, so it must have a measured row.
	for _, img := range OSImagesWithoutSSHDaemon() {
		i := slices.IndexFunc(chains, func(c BootChain) bool { return c.OSImage == img })
		if i < 0 || !chains[i].measured() {
			t.Errorf("%s is in OSImagesWithoutSSHDaemon without a measured boot chain", img)
		}
	}
	chains[0].RTMR0[0] = "mutated"
	if TrustedDstackBootChains()[0].RTMR0[0] == "mutated" {
		t.Error("TrustedDstackBootChains shares its RTMR0 backing array across calls")
	}
}
