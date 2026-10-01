/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import "bytes"

// InputTokenSplitVersion returns the two terms InputTokenBoundVersion sums:
// the text bytes the bytes-per-token ratio is applied to (image-URL bytes
// already excluded), and the vision tile tokens. It is purely an accessor —
// it computes nothing the bound does not already compute internally, and it
// changes no bound.
//
// It exists because the bound's text term is a deliberate UPPER bound
// (BytesPerToken = 2, against ~4 for real prose), which is correct for sizing
// a reserve and wrong for any caller that wants to project realistic usage. A
// caller that has measured actual prompt tokens can divide textBytes by its
// own observed ratio and add imageTokens back unchanged. Splitting the terms
// matters: imageTokens is already genuine token arithmetic, so dividing it by
// a prose bytes-per-token ratio would corrupt it.
//
// The node's tool-loop spend gate is the consumer. Reserve sizing must keep
// using InputTokenBoundVersion — under-sizing a reserve lets a payer steal
// service, which is exactly what the conservative ratio prevents.
//
// The identity
//
//	ceilDivU64(textBytes, BytesPerToken) + imageTokens + FlatMargin
//	  == InputTokenBoundVersion(body, version)
//
// holds for every body and every supported version, and is pinned by
// TestInputTokenSplitVersion_ReconstructsBound over the shared corpus and
// golden vectors. That test is what keeps this accessor from drifting away
// from the frozen bound it decomposes.
func InputTokenSplitVersion(body []byte, version uint8) (textBytes, imageTokens uint64) {
	if version == BoundVersion2 {
		return inputTokenSplitV2(body)
	}
	return inputTokenSplitV1(body)
}

// inputTokenSplitV1 mirrors InputTokenBound's term structure exactly.
func inputTokenSplitV1(body []byte) (textBytes, imageTokens uint64) {
	urlBytes, tileTokens := imageStatsIn(body)
	textBytes = uint64(len(body))
	if urlBytes < textBytes {
		textBytes -= urlBytes
	} else {
		textBytes = 0
	}
	return textBytes, tileTokens
}

// inputTokenSplitV2 mirrors InputTokenBoundV2's term structure exactly,
// including its two early exits: the BOM strip, and the unparseable /
// too-deeply-nested fallback that charges every byte as text with no image
// credit. Reproducing those here rather than approximating them is what makes
// the reconstruction identity hold on the awkward bodies.
func inputTokenSplitV2(body []byte) (textBytes, imageTokens uint64) {
	body = bytes.TrimPrefix(body, bomPrefix)
	if len(body) == 0 {
		return 0, 0
	}
	urlBytes, tileTokens, ok := imageStatsV2(body)
	if !ok {
		return uint64(len(body)), 0
	}
	textBytes = uint64(len(body))
	if urlBytes < textBytes {
		textBytes -= urlBytes
	} else {
		textBytes = 0
	}
	return textBytes, tileTokens
}
