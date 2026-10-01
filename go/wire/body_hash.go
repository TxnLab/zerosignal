/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import "crypto/sha256"

// BodyHashOfBody returns sha256 of a single non-streaming plaintext
// response body. This is one of two shapes the UsageReceipt binds
// to — see UsageReceipt.BodyHash. The node computes this over
// the plaintext before sealing; the proxy recomputes it over the
// plaintext it just decrypted. A mismatch is evidence that the
// operator signed a receipt for content it didn't deliver (SPEC.md
// § 3b case (e)).
func BodyHashOfBody(body []byte) [sha256.Size]byte {
	return sha256.Sum256(body)
}

// BodyHashFromFrames returns sha256(frames[0] || frames[1] || ...)
// for a streamed response. Frames are concatenated in index order
// with no separator — the sealed SSE stream already guarantees
// ordering via FrameAAD's monotonic index, so the hash does not need
// its own in-band framing.
//
// The node computes this as it emits frames (or over a buffer) and
// signs the UsageReceipt with the result. The proxy accumulates
// decrypted frame plaintexts in index order and recomputes.
func BodyHashFromFrames(frames [][]byte) [sha256.Size]byte {
	h := sha256.New()
	for _, f := range frames {
		_, _ = h.Write(f)
	}
	var out [sha256.Size]byte
	copy(out[:], h.Sum(nil))
	return out
}
