/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package imageprice_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/imageprice"
)

func TestNormalizeSize(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"1024x1024", "1024x1024", true},
		{"1024X1024", "1024x1024", true}, // case-insensitive
		{" 1024 x 768 ", "1024x768", true},
		{"1792x1024", "1792x1024", true},
		{"1024*1024", "1024x1024", true},
		{"1024×768", "1024x768", true},
		{"1024/768", "1024x768", true},
		{"1024 768", "1024x768", true},
		{"768", "768x768", true},  // bare N → square
		{"2k", "2048x2048", true}, // Nk shorthand
		{"4k", "4096x4096", true},
		{"16:9", "16:9", true}, // aspect ratio forwarded verbatim
		{"16 : 9", "16:9", true},
		{"", "", false},
		{"auto", "", false},
		{"large", "", false},
		{"1024x", "", false},
		{"+1024x768", "", false}, // strict-digit: sign rejected
	}
	for _, c := range cases {
		got, ok := imageprice.NormalizeSize(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("NormalizeSize(%q) = (%q, %v); want (%q, %v)", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestDimensions(t *testing.T) {
	cases := []struct {
		in   string
		w, h int
		ok   bool
	}{
		{"1024x1024", 1024, 1024, true},
		{"1792x1024", 1792, 1024, true},
		{"768", 768, 768, true},
		{"2k", 2048, 2048, true},
		{"16:9", 0, 0, false}, // ratio → reference, no pixel dims
		{"auto", 0, 0, false},
		{"", 0, 0, false},
		{"30000x30000", imageprice.MaxDimension, imageprice.MaxDimension, true}, // clamped
	}
	for _, c := range cases {
		w, h, ok := imageprice.Dimensions(c.in)
		if w != c.w || h != c.h || ok != c.ok {
			t.Errorf("Dimensions(%q) = (%d, %d, %v); want (%d, %d, %v)", c.in, w, h, ok, c.w, c.h, c.ok)
		}
	}
}

func TestFactor(t *testing.T) {
	cases := []struct {
		size, quality string
		num, den      uint64
	}{
		// Quality tiers at the 1024² reference.
		{"1024x1024", "standard", 1, 1},
		{"1024x1024", "", 1, 1},
		{"1024x1024", "medium", 1, 1},
		{"1024x1024", "auto", 1, 1},
		{"1024x1024", "low", 1, 4},
		{"1024x1024", "high", 4, 1},
		{"1024x1024", "hd", 4, 1},
		// Area scaling at standard quality.
		{"512x512", "standard", 1, 4},   // quarter area
		{"2048x2048", "standard", 4, 1}, // 4× area
		{"2048x2048", "high", 16, 1},    // 4× area × 4× quality
		{"1792x1024", "standard", 7, 4}, // gpt-image landscape
		{"1024x1536", "medium", 3, 2},   // portrait
		{"768", "standard", 9, 16},      // 768² = 9/16 of 1024²
		// Area and quality combine and cancel: quarter area × 4× quality = 1.
		{"512x512", "high", 1, 1},
		// Aspect ratio / auto / unparseable → reference, quality still applies.
		{"16:9", "standard", 1, 1},
		{"auto", "low", 1, 4},
		{"", "high", 4, 1},
	}
	for _, c := range cases {
		num, den := imageprice.Factor(c.size, c.quality)
		if num != c.num || den != c.den {
			t.Errorf("Factor(%q, %q) = %d/%d; want %d/%d", c.size, c.quality, num, den, c.num, c.den)
		}
	}
}

func TestPerImageMicroUSDC(t *testing.T) {
	const rate = 40000 // 0.04 USDC for a 1024²-standard image
	cases := []struct {
		size, quality string
		want          uint64
	}{
		{"1024x1024", "standard", 40000},
		{"1024x1024", "low", 10000},
		{"1024x1024", "high", 160000},
		{"512x512", "standard", 10000},
		{"2048x2048", "standard", 160000}, // ~4×
		{"2048x2048", "high", 640000},     // ~16×
		{"1792x1024", "standard", 70000},  // 7/4
		{"1024x1536", "standard", 60000},  // 3/2
		{"16:9", "standard", 40000},       // reference
	}
	for _, c := range cases {
		got := imageprice.PerImageMicroUSDC(rate, c.size, c.quality)
		if got != c.want {
			t.Errorf("PerImageMicroUSDC(%d, %q, %q) = %d; want %d", rate, c.size, c.quality, got, c.want)
		}
	}
}

func TestPerImageMicroUSDC_CeilRounding(t *testing.T) {
	// rate=7, Factor 9/16 (768²): 7×9/16 = 3.9375 → ceil 4.
	if got := imageprice.PerImageMicroUSDC(7, "768", "standard"); got != 4 {
		t.Errorf("ceil 768²@7 = %d; want 4", got)
	}
	// rate=7, Factor 1/4 (512²): 7/4 = 1.75 → ceil 2.
	if got := imageprice.PerImageMicroUSDC(7, "512x512", "standard"); got != 2 {
		t.Errorf("ceil 512²@7 = %d; want 2", got)
	}
	// rate=7, Factor 7/4 (1792x1024): 7×7/4 = 12.25 → ceil 13.
	if got := imageprice.PerImageMicroUSDC(7, "1792x1024", "standard"); got != 13 {
		t.Errorf("ceil 1792x1024@7 = %d; want 13", got)
	}
}

func TestCostMicroUSDC(t *testing.T) {
	if got := imageprice.CostMicroUSDC(40000, 3, "1024x1024", "standard"); got != 120000 {
		t.Errorf("Cost n=3 = %d; want 120000", got)
	}
	// Per-image ceil then ×n (not combined ceil): 3 × ceil(7×9/16=4) = 12.
	if got := imageprice.CostMicroUSDC(7, 3, "768", "standard"); got != 12 {
		t.Errorf("Cost n=3 @7 768² = %d; want 12", got)
	}
	if got := imageprice.CostMicroUSDC(40000, 0, "1024x1024", "standard"); got != 0 {
		t.Errorf("Cost n=0 = %d; want 0", got)
	}
}

func TestQualityMult_Ordering(t *testing.T) {
	// low < medium < high, comparable via num·otherDen vs otherNum·den.
	ln, ld := imageprice.QualityMult("low")
	mn, md := imageprice.QualityMult("medium")
	hn, hd := imageprice.QualityMult("high")
	if !(ln*md < mn*ld) {
		t.Errorf("low (%d/%d) not < medium (%d/%d)", ln, ld, mn, md)
	}
	if !(mn*hd < hn*md) {
		t.Errorf("medium (%d/%d) not < high (%d/%d)", mn, md, hn, hd)
	}
}
