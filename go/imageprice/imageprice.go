/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package imageprice is the shared, golden-vectored image-pricing primitive:
// it turns an OpenAI-style (size, quality) request into a deterministic
// microUSDC charge, given the operator's per-1024²-standard `imageRate`. It is
// replicated byte-for-byte in proto/ts/src/imageprice and pinned by
// proto/testdata/image_vectors.json, because three sizing paths — the node
// reserve gate, the proxy reserve sizing, and the client reserve sizing — must
// all compute the identical number or the node rejects with
// image_budget_exceeded.
//
// Pricing model (see SPEC.md "Dedicated image route"):
//
//	per_image_microUSDC = ceil(imageRate × Factor(size, quality))
//	Factor = areaScale × qualityMult                       // a reduced rational
//	areaScale = (w·h) / (1024·1024)                        // 2048² ≈ 4× 1024²
//	qualityMult: low 0.25 / medium·standard·auto·"" 1.0 / high·hd 4.0
//
// The reference image is 1024×1024 standard quality (Factor == 1); imageRate is
// the operator's microUSDC price for exactly that image. An aspect-ratio size
// ("16:9"), "auto", or an unparseable/empty size prices at the reference
// (areaScale = 1) so node/proxy/client agree without a per-model default-area
// discovery field.
//
// Nothing here logs — sizes/qualities are request-derived and the privacy
// invariant (node/AGENTS.md) keeps request content out of logs; this package is
// pure and loggless so callers on the hot path can use it freely.
package imageprice

import (
	"fmt"
	"strings"
)

// Reference dimensions: a 1024×1024 "standard"-quality image is the unit
// (Factor == 1). imageRate is the operator's microUSDC price for it.
const (
	RefWidth  = 1024
	RefHeight = 1024

	// MaxDimension caps a parsed pixel dimension used for *pricing* (not for
	// the canonicalized backend string — see NormalizeSize). It bounds the
	// area term so imageRate × num can't overflow uint64, and gives the Go
	// (uint64) and TS (BigInt) sides an identical, well-defined ceiling. No
	// real image backend serves anything near this.
	MaxDimension = 16384

	// maxParseInt bounds a single parsed integer so the Go (strconv) and TS
	// (Number) parses agree exactly: 1,000,000 px is far above any real
	// dimension yet stays exact in a float64 and never overflows an int.
	maxParseInt = 1_000_000
)

// NormalizeSize canonicalizes a loosely-specified size to the backend form
// ("WxH" or a "W:H" ratio token), returning ok=false for empty/unparseable.
// It is the single source of truth for size-string parsing: node
// imagecommon.NormalizeSize delegates here so backend normalization and
// pricing-dimension parsing can't drift. Accepted forms mirror the historical
// node behavior: "WxH" / "W*H" / "W×H" / "W/H" / "W H" (case/space-insensitive),
// a bare N → NxN, an "Nk" shorthand → (N·1024)² square, and a "W:H" aspect
// ratio forwarded verbatim (a ratio has no inherent scale — the backend's
// per-model default area resolves it).
//
// Unlike the pricing path, NormalizeSize does NOT clamp to MaxDimension — it
// hands the backend exactly what was asked (the backend rejects its own
// out-of-range sizes); only Dimensions (pricing) clamps.
func NormalizeSize(size string) (string, bool) {
	w, h, ratio, ok := parseSize(size)
	if !ok {
		return "", false
	}
	if ratio {
		return fmt.Sprintf("%d:%d", w, h), true
	}
	return fmt.Sprintf("%dx%d", w, h), true
}

// Dimensions parses a pricing-relevant pixel size. ok=false for an aspect-ratio
// ("W:H"), "auto", empty, or unparseable input — all of which price at the
// 1024²-standard reference (areaScale = 1). Pixel dimensions are clamped to
// [1, MaxDimension] for overflow safety (identical on the Go and TS sides).
func Dimensions(size string) (w, h int, ok bool) {
	pw, ph, ratio, parsed := parseSize(size)
	if !parsed || ratio {
		return 0, 0, false
	}
	return clampDim(pw), clampDim(ph), true
}

// QualityMult returns the pinned quality multiplier as a rational num/den:
// low → 1/4, high·hd → 4/1, and everything else (""/medium/standard/auto/
// unrecognized) → 1/1. Exposed so callers that clamp a model-chosen quality to
// an operator cap can order tiers (compare num·otherDen vs otherNum·den).
func QualityMult(quality string) (num, den uint64) {
	switch strings.ToLower(strings.TrimSpace(quality)) {
	case "low":
		return 1, 4
	case "high", "hd":
		return 4, 1
	default:
		// "", "medium", "standard", "auto", and any unrecognized value.
		return 1, 1
	}
}

// Factor returns the pricing multiplier for (size, quality) as a reduced
// rational num/den over the 1024²-standard reference (Factor == 1 ⇔ num == den).
func Factor(size, quality string) (num, den uint64) {
	qn, qd := QualityMult(quality)
	w, h, ok := Dimensions(size)
	var area, ref uint64
	if ok {
		area = uint64(w) * uint64(h)
		ref = uint64(RefWidth) * uint64(RefHeight)
	} else {
		// Aspect-ratio / auto / empty / unparseable → the reference image.
		area, ref = 1, 1
	}
	return reduce(area*qn, ref*qd)
}

// PerImageMicroUSDC returns the exact charge for ONE image at the given
// per-1024²-standard imageRate: ceil(imageRate × Factor(size, quality)). Pure
// integer math. imageRate × num stays within uint64 for any realistic rate
// (the reduced num is bounded by the MaxDimension clamp).
func PerImageMicroUSDC(imageRate uint64, size, quality string) uint64 {
	num, den := Factor(size, quality)
	return ceilDiv(imageRate*num, den)
}

// CostMicroUSDC is the charge for n images that all share one size/quality
// (the dedicated-route case): n × PerImageMicroUSDC. Per-image ceiling then
// multiply — the same unit the tool path sums per produced image — so reserve
// and receipt agree byte-for-byte. n < 1 yields 0.
func CostMicroUSDC(imageRate uint64, n int, size, quality string) uint64 {
	if n < 1 {
		return 0
	}
	return uint64(n) * PerImageMicroUSDC(imageRate, size, quality)
}

// --- internals ---------------------------------------------------------------

// parseSize is the shared size parser. ratio=true means w/h are the components
// of a "W:H" aspect ratio (no pixel scale); otherwise w/h are pixels. ok=false
// for empty/unparseable. Mirror of the historical node imagecommon.NormalizeSize
// accept-set, made strict-digit (no sign) and bounded (maxParseInt) so the Go
// and TS ports agree on every input.
func parseSize(size string) (w, h int, ratio, ok bool) {
	s := strings.ToLower(strings.TrimSpace(size))
	if s == "" {
		return 0, 0, false, false
	}
	// Aspect ratio "W:H" — checked before the multiplicative separators so a
	// stray space in "16 : 9" isn't split on " " first.
	if i := strings.Index(s, ":"); i >= 0 {
		if a, okA := parsePosInt(s[:i]); okA {
			if b, okB := parsePosInt(s[i+1:]); okB {
				return a, b, true, true
			}
		}
		return 0, 0, false, false
	}
	for _, sep := range []string{"x", "*", "×", "/", " "} {
		if i := strings.Index(s, sep); i >= 0 {
			a, okA := parsePosInt(s[:i])
			b, okB := parsePosInt(s[i+len(sep):])
			if okA && okB {
				return a, b, false, true
			}
			return 0, 0, false, false
		}
	}
	// "Nk" shorthand → (N·1024)² square. After the separator scan so a
	// "1024k"-style typo doesn't shadow a real "WxH".
	if rest, isK := strings.CutSuffix(s, "k"); isK {
		if n, okN := parsePosInt(rest); okN {
			d := n * 1024
			return d, d, false, true
		}
		return 0, 0, false, false
	}
	if n, okN := parsePosInt(s); okN {
		return n, n, false, true
	}
	return 0, 0, false, false
}

// parsePosInt parses a strictly-decimal positive integer in (0, maxParseInt].
// Strict (no sign, digits only) and bounded so Go and TS agree exactly.
func parsePosInt(s string) (int, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, false
		}
		n = n*10 + int(r-'0')
		if n > maxParseInt {
			return 0, false
		}
	}
	if n <= 0 {
		return 0, false
	}
	return n, true
}

func clampDim(d int) int {
	if d < 1 {
		return 1
	}
	if d > MaxDimension {
		return MaxDimension
	}
	return d
}

func gcd(a, b uint64) uint64 {
	for b != 0 {
		a, b = b, a%b
	}
	return a
}

func reduce(num, den uint64) (uint64, uint64) {
	if num == 0 {
		return 0, 1
	}
	g := gcd(num, den)
	return num / g, den / g
}

// ceilDiv returns ceil(a/b) for b > 0. b is a rational denominator here, always ≥ 1.
func ceilDiv(a, b uint64) uint64 {
	return (a + b - 1) / b
}
