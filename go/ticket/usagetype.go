/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package ticket

// UsageType discriminates the unit a Ticket / UsageReceipt direction is priced
// and metered in (SPEC §3a). It is what lets one request mix units across
// input and output — text-token input with image output (dall-e-3), text-token
// input with second output (Sora) — and lets the on-chain settle route a
// count into the right generic metric bucket (outputUnits[UsageType]) instead
// of the token-only counters.
//
// The discriminators are carried as one byte each inside the signed canonical
// bytes (v2). Money is unaffected: AmountCharged / MaxPrice stay a single
// unit-agnostic microUSDC scalar — UsageType only changes how a count is
// interpreted for sizing and metrics. See SPEC.md "Usage types".
type UsageType uint8

const (
	// UsageTypeNone marks a direction (or the aux output slot) as unused for
	// this request — e.g. a TTS request has no token output.
	UsageTypeNone UsageType = 0
	// UsageTypeTokens — count = tokens; rate = microUSDC per 1,000,000 tokens
	// (current behavior for chat/responses).
	UsageTypeTokens UsageType = 1
	// UsageTypeImages — count = produced image units; rate = microUSDC for one
	// 1024²-standard image scaled by imageprice.Factor(size, quality). NOT flat
	// per image.
	UsageTypeImages UsageType = 2
	// UsageTypeCharacters — count = characters; rate = microUSDC per 1,000,000
	// characters (TTS input).
	UsageTypeCharacters UsageType = 3
	// UsageTypeSeconds — count = whole seconds; rate = microUSDC per second
	// (Whisper input duration, Sora output duration).
	UsageTypeSeconds UsageType = 4
)

// String renders a UsageType for logs/diagnostics (never request content, so
// it stays within the privacy invariant).
func (u UsageType) String() string {
	switch u {
	case UsageTypeNone:
		return "none"
	case UsageTypeTokens:
		return "tokens"
	case UsageTypeImages:
		return "images"
	case UsageTypeCharacters:
		return "characters"
	case UsageTypeSeconds:
		return "seconds"
	default:
		return "unknown"
	}
}
