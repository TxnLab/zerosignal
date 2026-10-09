/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import prototokenize "github.com/TxnLab/zerosignal/go/tokenize"

// The reserve-sizing helpers live in the shared proto module so the proxy
// (which sizes input_count) and the node (which re-measures the same bound at
// inference time to enforce it) use one implementation. These thin re-exports
// keep the proxy's call sites on the local `tokenize` package. SafeEstimator's
// default input bound is byte-identical to prototokenize.InputTokenBound —
// TestSafeEstimatorMatchesProto pins that so the two can't silently drift.

// BodyHasPreviousResponseID reports whether the body carries a non-empty
// previous_response_id (a server-side history chain).
func BodyHasPreviousResponseID(body []byte) bool {
	return prototokenize.BodyHasPreviousResponseID(body)
}

// There is deliberately no BodyHasTools re-export: "does the body carry any
// tools" is the wrong predicate for reserve sizing, because a caller-executed
// function tool grows nothing on the serving side. The headroom signal is
// inject.BodyDrivesServerSideToolGrowth — call that directly.

// ReserveInputCount sizes the input_count to escrow: the body bound plus a
// tool-loop headroom term, floored and capped at contextWindow − maxOutput.
// See prototokenize.ReserveInputCount.
func ReserveInputCount(bodyBound uint64, carriesTools bool, maxToolIterations, perIterHeadroom, maxOutput, contextWindow, floor uint64) uint64 {
	return prototokenize.ReserveInputCount(bodyBound, carriesTools, maxToolIterations, perIterHeadroom, maxOutput, contextWindow, floor)
}

// Bound versions, re-exported so dispatch can name them without importing the
// proto package alongside this one. The version a reserve is sized with rides
// on the reserve request and the node re-measures with the same function —
// v2 is tighter than v1 on prose, tool schemas and images, but deliberately
// LARGER on base64, hex, emoji and embedded JSON, so it is never safe to infer.
const (
	BoundVersion1 = prototokenize.BoundVersion1
	BoundVersion2 = prototokenize.BoundVersion2
)

// InputTokenBoundVersion computes the input-token bound for an explicit
// version. See prototokenize.InputTokenBoundVersion.
func InputTokenBoundVersion(body []byte, version uint8) uint64 {
	return prototokenize.InputTokenBoundVersion(body, version)
}
