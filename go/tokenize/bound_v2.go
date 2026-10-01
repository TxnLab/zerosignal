/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import (
	"bytes"
	"encoding/json"
	"math"
)

// Bound version 2 — v1's text treatment, plus TRUE image dimensions.
//
// v1 prices every image part the caller didn't annotate at a 2048x2048
// high-detail fallback (2805 tokens), because no client sets width/height on an
// image part and none should: they aren't standard OpenAI fields and a strict
// upstream rejects unknown keys. That fallback is wrong in both directions —
// 3.7x-11x too high for the ordinary 512x512 / 1024x768 paste, and materially
// too LOW for anything above 2048x2048 (a 4096x4096 image really costs ~11k
// tokens). v2 reads the real dimensions out of the image header instead (see
// imagedims.go), so the tile term matches what the model is actually billed.
//
// The TEXT term is deliberately IDENTICAL to v1: ceil(textBytes / 2), where
// textBytes excludes the bytes of any image-URL string. An earlier draft of v2
// also replaced the text term with a character-class run classifier calibrated
// against proto/testdata/tokenize_corpus. That was withdrawn: the constants were
// derived from the same 40 samples they were then validated against, so the
// safety assertion could only ever pass, and the first unseen shapes
// (punctuation-dense text, mixed-case runs, Ethiopic / Georgian / abugida
// scripts, integer-heavy tool schemas) under-counted by up to 3x. Tightening
// the text term needs a corpus an order of magnitude broader and a train/holdout
// split; it is not attempted here. v1's known text-side under-counts (base64,
// hex, emoji, embedded JSON — see proto/testdata/tokenize_corpus.json) therefore
// persist unchanged in v2. They are pre-existing, not introduced here.
//
// Because the image term moves in BOTH directions, v2 is not uniformly smaller
// or larger than v1, which is why the version is negotiated explicitly on the
// wire (ticket.ReserveRequest.InputBoundVersion) rather than inferred.
//
// proto/ts mirrors this file and the node re-computes the same bound to enforce
// the reserve, so any Go/TS disagreement rejects an honest client's request.
// Three sources of disagreement are closed here deliberately — see bomPrefix,
// json.Decoder.UseNumber, and maxImageWalkDepth below.

const (
	// maxImageWalkDepth bounds the recursive search for image parts.
	//
	// It exists for parity, not just safety: JS blows its call stack around
	// 4,000 frames and throws, while Go's encoding/json refuses to decode past
	// ~10,000 nesting levels and returns an error instead. Left alone, a deeply
	// nested body makes one implementation throw and the other fall back —
	// different numbers, or an uncaught exception in the browser. Capping well
	// below both limits makes the two agree by construction.
	//
	// Exceeding it is treated exactly like a parse failure: the whole body falls
	// back to the raw-byte bound, which is conservative (it charges image-URL
	// bytes as text instead of excluding them).
	maxImageWalkDepth = 256

	// imageMaxDimensionPx clamps a header- or caller-declared dimension. Headers
	// are payer-controlled and PNG stores width/height as full 32-bit values, so
	// an unclamped tile count would overflow. 16384 is past any dimension a
	// vision model accepts, and the tile cost at that size already exceeds every
	// context window, so the reserve's own window cap takes over.
	imageMaxDimensionPx = 16384
)

// bomPrefix is a UTF-8 byte order mark. JS decodes request bytes with
// TextDecoder, which STRIPS a leading BOM before JSON.parse; Go hands the raw
// bytes to encoding/json, which rejects them. Stripping it explicitly on both
// sides removes a divergence that otherwise makes the node measure a
// BOM-prefixed body higher than the client reserved for it.
var bomPrefix = []byte{0xEF, 0xBB, 0xBF}

// InputTokenBoundV2 returns a safe upper bound on the input tokens a request
// body will consume: ceil(textBytes / 2) + imageTileTokens + FlatMargin, with
// the tile tokens derived from each image's true pixel dimensions where the body
// carries the bytes to determine them.
func InputTokenBoundV2(body []byte) uint64 {
	body = bytes.TrimPrefix(body, bomPrefix)
	if len(body) == 0 {
		return FlatMargin
	}

	urlBytes, imageTokens, ok := imageStatsV2(body)
	if !ok {
		// Unparseable, or nested past the walk cap: charge every byte as text.
		// Never smaller than the parsed answer, so this direction is safe.
		return saturatingAdd(ceilDivU64(uint64(len(body)), BytesPerToken), FlatMargin)
	}

	textBytes := uint64(len(body))
	if urlBytes < textBytes {
		textBytes -= urlBytes
	} else {
		textBytes = 0
	}
	textTokens := ceilDivU64(textBytes, BytesPerToken)
	return saturatingAdd(saturatingAdd(textTokens, imageTokens), FlatMargin)
}

// imageStatsV2 walks the body for image content parts, returning the total byte
// length of their URL strings (so the caller can exclude them from the text
// bound) and the sum of their vision tile-token costs. ok=false means the body
// could not be walked and the caller must fall back to the raw-byte bound.
func imageStatsV2(body []byte) (urlBytes, tileTokens uint64, ok bool) {
	// UseNumber keeps JSON numbers as their original text instead of decoding
	// them to float64. Two divergences close at once: encoding/json errors on a
	// literal outside float64's range (1e309) where JSON.parse yields Infinity
	// and keeps going, and the float64 -> int conversion that dimension reads
	// used to perform is implementation-defined in Go for out-of-range values
	// (arm64 saturates, amd64 wraps to minInt64), which made the bound
	// architecture-dependent. Numbers are now range-checked as text.
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return 0, 0, false
	}

	var st imageWalkState
	if !st.walk(v, 0) {
		return 0, 0, false
	}
	return st.urlBytes, st.tileTokens, true
}

type imageWalkState struct {
	urlBytes   uint64
	tileTokens uint64
}

// walk accumulates image stats. It returns false if the structure is nested past
// maxImageWalkDepth, which the caller turns into a raw-byte fallback.
func (s *imageWalkState) walk(v any, depth int) bool {
	if depth > maxImageWalkDepth {
		return false
	}
	switch t := v.(type) {
	case map[string]any:
		if typ, ok := t["type"].(string); ok {
			switch lowerASCII(typ) {
			case "image_url", "input_image":
				s.tileTokens = saturatingAdd(s.tileTokens, uint64(imageTokensFromObjectV2(t)))
				s.urlBytes = saturatingAdd(s.urlBytes, uint64(len(imageURLStringFromObject(t))))
				return true
			}
		}
		for _, child := range t {
			if !s.walk(child, depth+1) {
				return false
			}
		}
	case []any:
		for _, child := range t {
			if !s.walk(child, depth+1) {
				return false
			}
		}
	}
	return true
}

// imageDimField reads a caller-declared width/height.
//
// One shared semantic, mirrored exactly in TS: anything that is not a finite
// number, or is below 1, reads as ABSENT (0) rather than as a dimension. That
// matters because a nested `image_url: {"width": 0}` must not erase a valid
// outer value — Go used to adopt any numeric value including 0, negatives and
// fractions, while TS only adopted positives, so the same body produced the
// 2048x2048 fallback on one side and a real size on the other. Values above the
// clamp are clamped here rather than converted, so no out-of-range float ever
// reaches an integer conversion.
func imageDimField(obj map[string]any, key string) int {
	f, ok := jsonNumberValue(obj[key])
	if !ok || math.IsNaN(f) || math.IsInf(f, 0) || f < 1 {
		return 0
	}
	if f > float64(imageMaxDimensionPx) {
		return imageMaxDimensionPx
	}
	return int(f)
}

// jsonNumberValue reads a decoded JSON number. With UseNumber the decoder yields
// json.Number (the original literal); the float64 case covers values produced by
// callers that decoded the body themselves.
func jsonNumberValue(v any) (float64, bool) {
	switch n := v.(type) {
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			// Out of float64 range. JSON.parse would yield +/-Infinity here, and
			// both sides treat a non-finite dimension as absent, so agree on 0
			// unless the literal is a huge POSITIVE one, which clamps.
			if len(n.String()) > 0 && n.String()[0] != '-' {
				return float64(imageMaxDimensionPx), true
			}
			return 0, false
		}
		return f, true
	case float64:
		return n, true
	}
	return 0, false
}

// imageTokensFromObjectV2 prices one image content part with OpenAI's vision
// tile math. Explicit caller-declared dimensions win; otherwise the true
// dimensions are recovered from the image header (imagedims.go). Only when both
// fail does it charge v1's 2048x2048 fallback.
func imageTokensFromObjectV2(obj map[string]any) int {
	detail := ""
	if d, ok := obj["detail"].(string); ok {
		detail = lowerASCII(d)
	}
	width := imageDimField(obj, "width")
	height := imageDimField(obj, "height")

	if iu, ok := obj["image_url"].(map[string]any); ok {
		if d, ok := iu["detail"].(string); ok && d != "" {
			detail = lowerASCII(d)
		}
		if w := imageDimField(iu, "width"); w > 0 {
			width = w
		}
		if h := imageDimField(iu, "height"); h > 0 {
			height = h
		}
	}
	if detail == "" || detail == "auto" {
		detail = imageDefaultDetail
	}
	if detail == "low" {
		return imageTokensLow
	}

	if width <= 0 || height <= 0 {
		if w, h, ok := imageDimsFromURL(imageURLStringFromObject(obj)); ok && w > 0 && h > 0 {
			width, height = w, h
		}
	}
	if width <= 0 {
		width = imageDefaultWidthPx
	}
	if height <= 0 {
		height = imageDefaultHeightPx
	}
	if width > imageMaxDimensionPx {
		width = imageMaxDimensionPx
	}
	if height > imageMaxDimensionPx {
		height = imageMaxDimensionPx
	}

	tilesX := (width + imageTileEdgePx - 1) / imageTileEdgePx
	tilesY := (height + imageTileEdgePx - 1) / imageTileEdgePx
	if tilesX < 1 {
		tilesX = 1
	}
	if tilesY < 1 {
		tilesY = 1
	}
	return imageTokensHighBase + imageTokensHighTile*tilesX*tilesY
}

// imageURLStringFromObject returns the URL of an image part, handling both the
// Responses-API top-level string form and the Chat-Completions nested object.
func imageURLStringFromObject(obj map[string]any) string {
	switch v := obj["image_url"].(type) {
	case string:
		return v
	case map[string]any:
		if u, ok := v["url"].(string); ok {
			return u
		}
	}
	return ""
}

// lowerASCII lowercases the ASCII letters in s. strings.ToLower applies Unicode
// case folding, which is not identical to the TS mirror's toLowerCase() for
// every input; restricting to ASCII removes the question for the type and detail
// discriminants this is used on.
func lowerASCII(s string) string {
	out := []byte(s)
	for i := range out {
		if out[i] >= 'A' && out[i] <= 'Z' {
			out[i] += 'a' - 'A'
		}
	}
	return string(out)
}

// ceilDivU64 is ceil(a/b) without floating point. b is always a non-zero
// constant at every call site.
func ceilDivU64(a, b uint64) uint64 {
	if b == 0 {
		return a
	}
	if a > ^uint64(0)-(b-1) {
		return ^uint64(0) / b
	}
	return (a + b - 1) / b
}
