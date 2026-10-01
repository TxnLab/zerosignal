/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize_test

// InputTokenSplitVersion decomposes the bound into the two terms the bound
// sums. Nothing enforces that decomposition at compile time, so a later edit
// to either bound — or to the accessor — could silently make them disagree,
// and the only symptom would be a node projecting usage from a text-byte count
// that no longer matches what it is being compared against.
//
// These tests are that enforcement. The reconstruction identity is asserted
// over every body the parity fixtures and the corpus already carry, which is
// deliberately the awkward set: BOM-prefixed, non-JSON, empty, nested past the
// v2 walk cap, and the whole image-URL family whose bytes are excluded from
// the text term.

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/tokenize"
)

// reconstruct applies the bound's own formula to the split terms.
func reconstruct(textBytes, imageTokens uint64) uint64 {
	textTokens := (textBytes + tokenize.BytesPerToken - 1) / tokenize.BytesPerToken
	return textTokens + imageTokens + tokenize.FlatMargin
}

// splitVersions are the versions the accessor must handle. 0 is on the list
// because it is what an omitted wire value means, and it must resolve to the
// same default the bound resolves it to rather than falling off a switch.
var splitVersions = []uint8{0, tokenize.BoundVersion1, tokenize.BoundVersion2}

// TestInputTokenSplitVersion_ReconstructsBound is the load-bearing test for
// split.go: ceil(textBytes/BytesPerToken) + imageTokens + FlatMargin must equal
// InputTokenBoundVersion for the same body and version. If this fails, the
// accessor has drifted from the bound it claims to decompose.
func TestInputTokenSplitVersion_ReconstructsBound(t *testing.T) {
	check := func(t *testing.T, name string, body []byte) {
		t.Helper()
		for _, v := range splitVersions {
			textBytes, imageTokens := tokenize.InputTokenSplitVersion(body, v)
			got := reconstruct(textBytes, imageTokens)
			want := tokenize.InputTokenBoundVersion(body, v)
			if got != want {
				t.Errorf("%s v%d: split reconstructs %d, bound is %d (textBytes=%d imageTokens=%d)",
					name, v, got, want, textBytes, imageTokens)
			}
		}
	}

	for _, b := range boundBodies {
		t.Run("bound/"+b.name, func(t *testing.T) { check(t, b.name, []byte(b.body)) })
	}
	for _, b := range adversarialBodies(t) {
		t.Run("adversarial/"+b.name, func(t *testing.T) { check(t, b.name, b.body) })
	}
	cf := loadCorpus(t)
	for _, s := range cf.Samples {
		t.Run("corpus/"+s.Name, func(t *testing.T) { check(t, s.Name, readSample(t, s.Name)) })
	}
}

// TestInputTokenSplitVersion_ExcludesImageURLBytes pins the property the node's
// spend gate actually depends on: image-URL bytes are NOT in textBytes, so
// dividing textBytes by an observed prose bytes-per-token ratio cannot be
// skewed by a multi-megabyte base64 data: URL. A regression here would not fail
// the reconstruction test — moving bytes from the text term into the image term
// keeps the sum intact — so it needs its own assertion.
func TestInputTokenSplitVersion_ExcludesImageURLBytes(t *testing.T) {
	const url = "https://example.com/" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.png"
	body := []byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"` +
		url + `","detail":"low"}}]}]}`)

	for _, v := range splitVersions {
		textBytes, imageTokens := tokenize.InputTokenSplitVersion(body, v)
		if textBytes >= uint64(len(body)) {
			t.Errorf("v%d: textBytes %d did not exclude the %d-byte image URL (body %d)",
				v, textBytes, len(url), len(body))
		}
		if textBytes != uint64(len(body))-uint64(len(url)) {
			t.Errorf("v%d: textBytes = %d, want %d", v, textBytes, uint64(len(body))-uint64(len(url)))
		}
		// detail:"low" is a flat charge in both versions, so this also pins that
		// the image term survives the split as tokens rather than being folded
		// into the byte count.
		if imageTokens == 0 {
			t.Errorf("v%d: imageTokens = 0, want the low-detail flat charge", v)
		}
	}
}

// TestInputTokenSplitVersion_UnknownVersionMatchesBound pins that an
// unrecognised version falls back the same way InputTokenBoundVersion does
// (to v1, the widest bound) rather than to whatever the switch happens to
// reach. The two must agree or the node would divide a v1 text term while
// comparing against a v2 bound.
func TestInputTokenSplitVersion_UnknownVersionMatchesBound(t *testing.T) {
	body := []byte(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`)
	for _, v := range []uint8{7, 42, 255} {
		textBytes, imageTokens := tokenize.InputTokenSplitVersion(body, v)
		if got, want := reconstruct(textBytes, imageTokens), tokenize.InputTokenBoundVersion(body, v); got != want {
			t.Errorf("v%d: split reconstructs %d, bound is %d", v, got, want)
		}
	}
}
