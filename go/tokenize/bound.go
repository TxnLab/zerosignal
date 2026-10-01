/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package tokenize is the language-neutral, model-agnostic input-token
// bound used to size a reserve's max_price and — critically — to enforce
// that bound at inference time.
//
// InputTokenBound is a deliberate UPPER bound (never an exact tokenizer
// output): overestimates only widen the operator's refund at settlement,
// while underestimates would either truncate inference mid-stream or let a
// payer under-reserve and steal service. The node re-computes this SAME
// bound over the decrypted body to check it against the reserved
// input_count, and the client / proxy compute it to size input_count, so
// the two implementations MUST agree byte-for-byte — proto/ts mirrors this
// file and both sides assert against proto/testdata/tokenize_vectors.json.
package tokenize

import (
	"encoding/json"
	"math"
	"strings"
)

// Bound constants. The bytes-per-token floor of 2 is conservative for any
// modern BPE / SentencePiece vocabulary (English prose ~4 b/t, code ~3-4,
// CJK with multilingual vocab ~2-3, character-level fallbacks ~1-2). The
// flat margin absorbs structural overhead — chat-template tokens, role
// markers, tool-schema wrapping — that the bytes-per-token ratio applied to
// the raw body doesn't see.
const (
	BytesPerToken = 2
	FlatMargin    = 32

	// Image overhead constants per OpenAI's vision pricing. Used because a
	// single image_url can carry thousands of tokens that the bytes/2 bound
	// applied to a URL string would miss by orders of magnitude.
	imageTokensLow       = 85
	imageTokensHighBase  = 85
	imageTokensHighTile  = 170
	imageTileEdgePx      = 512
	imageDefaultDetail   = "high"
	imageDefaultWidthPx  = 2048
	imageDefaultHeightPx = 2048
)

// Bound versions. The version a caller sizes its reserve with rides on the
// reserve request (ReserveRequest.InputBoundVersion) and the node enforces with
// that same version, because v2 is not uniformly smaller than v1: it is tighter
// on prose, tool schemas and images, but deliberately LARGER on the classes v1
// under-counts (base64, hex, emoji, embedded JSON). Inferring the version from
// anything else would reject honest v1 callers on a CJK or base64 body.
const (
	// BoundVersion1 is the original flat ceil(bytes/2) bound. Frozen forever:
	// it is the compatibility floor every pre-9.2 caller sizes against.
	BoundVersion1 uint8 = 1
	// BoundVersion2 is the calibrated bound in bound_v2.go.
	BoundVersion2 uint8 = 2
	// DefaultBoundVersion is what an omitted version means on the wire.
	DefaultBoundVersion = BoundVersion1
)

// SupportedBoundVersion reports whether v is a bound version this build
// implements. A zero value means "unspecified" and resolves to the default.
func SupportedBoundVersion(v uint8) bool {
	return v == 0 || v == BoundVersion1 || v == BoundVersion2
}

// InputTokenBoundVersion computes the bound for an explicit version. The node
// uses it to measure a request with the same function the caller sized it with;
// an unknown version falls back to v1, the widest bound, so an unrecognised
// value can never under-charge.
func InputTokenBoundVersion(body []byte, version uint8) uint64 {
	if version == BoundVersion2 {
		return InputTokenBoundV2(body)
	}
	return InputTokenBound(body)
}

// InputTokenBound returns a safe upper bound on the input tokens a request
// body will consume: ceil(textBytes / 2) + imageTileTokens + FlatMargin,
// where textBytes excludes the bytes of any image-URL strings (those are
// scored by the tile formula instead). A body that doesn't parse as JSON
// still gets the raw-byte text bound (images contribute 0).
//
// FROZEN — this is bound version 1 and every byte of its behaviour is a
// compatibility contract with pre-9.2 callers and nodes. Improvements belong in
// InputTokenBoundV2; changing anything here retroactively rejects requests that
// were sized correctly when they were made.
func InputTokenBound(body []byte) uint64 {
	urlBytes, imageTokens := imageStatsIn(body)
	textBytes := uint64(len(body))
	if urlBytes < textBytes {
		textBytes -= urlBytes
	} else {
		textBytes = 0
	}
	textTokens := uint64(math.Ceil(float64(textBytes) / float64(BytesPerToken)))
	return saturatingAdd(saturatingAdd(textTokens, imageTokens), FlatMargin)
}

// ReserveInputCount computes the input-token count to commit to a reserve:
// the tight body bound plus a tool-loop headroom term (zero unless the
// request carries tools), clamped to a sane floor and — when the operator
// declares a context window — capped at context_window − max_output_count
// (today's worst case, so the reserve is always ≤ the old full-window
// behavior). The cap is applied LAST so the returned value always satisfies
// input + max_output ≤ context_window (inject.FitsContextWindow).
//
// The node uses the same clamp semantics on the caller's already-headroom'd
// value by calling with carriesTools=false and bodyBound=input_count.
func ReserveInputCount(bodyBound uint64, carriesTools bool, maxToolIterations, perIterHeadroom, maxOutput, contextWindow, floor uint64) uint64 {
	headroom := uint64(0)
	if carriesTools {
		headroom = saturatingMul(maxToolIterations, perIterHeadroom)
	}
	want := saturatingAdd(bodyBound, headroom)
	if want < floor {
		want = floor
	}
	// Cap last: a declared context window is the authoritative ceiling and
	// must win over the floor so FitsContextWindow always holds.
	if contextWindow > 0 {
		var ceil uint64
		if contextWindow > maxOutput {
			ceil = contextWindow - maxOutput
		}
		if want > ceil {
			want = ceil
		}
	}
	return want
}

// BodyHasPreviousResponseID reports whether the body carries a non-empty
// previous_response_id — a server-side response chain whose accumulated
// history the node cannot see, so the caller must reserve worst-case for it.
func BodyHasPreviousResponseID(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var peek struct {
		PreviousResponseID string `json:"previous_response_id"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return false
	}
	return peek.PreviousResponseID != ""
}

// BodyHasTools reports whether the body carries a non-empty top-level tools
// array. A malformed body reports false.
//
// This is the general "are there any tools" primitive. It is NOT the tool-loop
// headroom predicate: a caller-executed function tool grows nothing on the
// serving side, because the caller runs it and re-issues a request that is
// measured on its own. Sizing a reserve off this over-reserves every
// coding-agent request by max_tool_iterations × per-iteration headroom — see
// inject.BodyDrivesServerSideToolGrowth, which is what callers should pass as
// ReserveInputCount's carriesTools.
func BodyHasTools(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	var peek struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return false
	}
	return len(peek.Tools) > 0
}

// imageStatsIn walks the body looking for content parts whose `type` is
// "image_url" or "input_image" and returns (urlBytes, tileTokens): the byte
// length of every image-URL string (so the caller can exclude it from the
// bytes-per-token text bound) and the sum of their vision tile-token costs.
// A body that doesn't parse contributes (0, 0).
func imageStatsIn(body []byte) (urlBytes, tileTokens uint64) {
	if len(body) == 0 {
		return 0, 0
	}
	var v any
	if err := json.Unmarshal(body, &v); err != nil {
		return 0, 0
	}
	walkForImages(v, &urlBytes, &tileTokens)
	return urlBytes, tileTokens
}

func walkForImages(v any, urlBytes, tileTokens *uint64) {
	switch t := v.(type) {
	case map[string]any:
		if typ, ok := t["type"].(string); ok {
			switch strings.ToLower(typ) {
			case "image_url", "input_image":
				*tileTokens += uint64(imageTokensFromObject(t))
				*urlBytes += uint64(imageURLBytesFromObject(t))
				return
			}
		}
		for _, child := range t {
			walkForImages(child, urlBytes, tileTokens)
		}
	case []any:
		for _, child := range t {
			walkForImages(child, urlBytes, tileTokens)
		}
	}
}

// imageURLBytesFromObject returns the byte length of the URL string on an
// image part. Handles both shapes: Responses-API top-level
// `"image_url": "<string>"` and Chat-Completions nested
// `"image_url": { "url": "<string>", ... }`.
func imageURLBytesFromObject(obj map[string]any) int {
	switch v := obj["image_url"].(type) {
	case string:
		return len(v)
	case map[string]any:
		if u, ok := v["url"].(string); ok {
			return len(u)
		}
	}
	return 0
}

// imageTokensFromObject reads detail / width / height from either the part
// itself or its nested image_url object (Chat Completions shape) and returns
// the OpenAI tile-math token count. Unknown dimensions fall back to
// 2048×2048 high-detail.
func imageTokensFromObject(obj map[string]any) int {
	detail, width, height := "", 0, 0

	if d, ok := obj["detail"].(string); ok {
		detail = strings.ToLower(d)
	}
	if w, ok := numField(obj, "width"); ok {
		width = w
	}
	if h, ok := numField(obj, "height"); ok {
		height = h
	}
	if iu, ok := obj["image_url"].(map[string]any); ok {
		if d, ok := iu["detail"].(string); ok && d != "" {
			detail = strings.ToLower(d)
		}
		if w, ok := numField(iu, "width"); ok {
			width = w
		}
		if h, ok := numField(iu, "height"); ok {
			height = h
		}
	}
	if detail == "" || detail == "auto" {
		detail = imageDefaultDetail
	}
	if detail == "low" {
		return imageTokensLow
	}
	if width == 0 {
		width = imageDefaultWidthPx
	}
	if height == 0 {
		height = imageDefaultHeightPx
	}
	tilesX := int(math.Ceil(float64(width) / float64(imageTileEdgePx)))
	tilesY := int(math.Ceil(float64(height) / float64(imageTileEdgePx)))
	if tilesX < 1 {
		tilesX = 1
	}
	if tilesY < 1 {
		tilesY = 1
	}
	return imageTokensHighBase + imageTokensHighTile*tilesX*tilesY
}

func numField(obj map[string]any, key string) (int, bool) {
	switch v := obj[key].(type) {
	case float64:
		return int(v), true
	case int:
		return v, true
	}
	return 0, false
}

// saturatingAdd / saturatingMul clamp at the uint64 max instead of wrapping,
// so a pathological body or headroom config can never underflow the cap into
// a tiny reserve.
func saturatingAdd(a, b uint64) uint64 {
	if a > ^uint64(0)-b {
		return ^uint64(0)
	}
	return a + b
}

func saturatingMul(a, b uint64) uint64 {
	if a == 0 || b == 0 {
		return 0
	}
	if a > ^uint64(0)/b {
		return ^uint64(0)
	}
	return a * b
}
