/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package pricing is the language-neutral, authoritative token-pricing math
// shared by every actor in the protocol: the node prices a reserve with it, and
// the proxy and client verify a signed ticket's price against it before
// escrowing (see VerifyTicketPrice). Because a payer-side verifier must recompute
// exactly what the node signed — any drift refuses honest requests or admits
// over-priced ones — the math lives here once and is pinned cross-implementation
// by proto/testdata/pricing_vectors.json. proto/ts/src/pricing mirrors this file
// byte-for-byte; both sides assert against the same golden vectors.
//
// Two rounding shapes are load-bearing and deliberately different, matching the
// node:
//   - the reserve ceiling (RateBasedMaxPrice) rounds the input and output legs
//     with two SEPARATE ceils;
//   - the settle charge (CeilInputCost) rounds the cached + non-cached input
//     sub-legs together under a SINGLE ceil, so an unset cache_read_rate (== the
//     input rate) reproduces the pre-cache flat charge byte-for-byte.
//
// All money is microUSDC; all rates are microUSDC per 1,000,000 tokens.
package pricing

import (
	"errors"
	"fmt"
	"math"
)

const (
	// RateDenominatorTokens is the per-1,000,000-token denominator: a rate of R
	// microUSDC/1M costs R/1e6 microUSDC per token.
	RateDenominatorTokens = 1_000_000

	// BpsDenominator is the basis-point denominator for the protocol-fee gross-up.
	BpsDenominator = 10_000

	// AlgorandMinTxnFeeMicroAlgos is Algorand's minimum transaction fee, in
	// microALGO, used to size the µALGO component of the minimum charge.
	AlgorandMinTxnFeeMicroAlgos = 1_000
)

// IsLongContext reports whether a request whose signed input_count is inputCount
// falls into the operator's long-context (high) pricing tier. threshold == 0
// means the operator advertises no tier (flat pricing), so this is always false;
// otherwise the request is in the high tier iff inputCount >= threshold. Two
// properties are load-bearing:
//   - the tier is decided by input (prompt) tokens ALONE — never input+output —
//     because only input_count is committed on the ticket at reserve, so the node
//     and the payer-side verifier both resolve the tier from the identical signed
//     value and agree deterministically;
//   - the boundary is INCLUSIVE — a request exactly at threshold pays the high
//     rate — matching xAI's "reaches the listed token threshold" wording.
//
// This is the single boundary definition: the node consults it at reserve to pick
// which rate set to sign onto the ticket's InputRate/OutputRate/CacheReadRate
// fields, and the verifier consults it over the SAME t.InputCount to resolve the
// tier-appropriate advertised comparand. Mirrored byte-for-byte by proto/ts
// isLongContext.
func IsLongContext(inputCount, threshold uint64) bool {
	return threshold > 0 && inputCount >= threshold
}

// checkedMul returns a*b or an error on uint64 overflow.
func checkedMul(a, b uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > math.MaxUint64/b {
		return 0, errors.New("overflow")
	}
	return a * b, nil
}

// ceilMulDiv returns ceil(a*b/d) with overflow detection on the intermediate
// product. d is caller-guaranteed non-zero (always a rate/bps denominator);
// prod+d-1 cannot overflow given the product guard.
func ceilMulDiv(a, b, d uint64) (uint64, error) {
	if a == 0 || b == 0 {
		return 0, nil
	}
	if a > math.MaxUint64/b {
		return 0, errors.New("overflow")
	}
	prod := a * b
	return (prod + d - 1) / d, nil
}

// USDRateToMicroUSDCPer1M converts a USD-per-1M-tokens rate to microUSDC per 1M
// tokens with ceiling rounding. A rate of 0 is free (0, nil); non-finite,
// negative, or overflowing rates error. This is the exact conversion the node
// applies to an operator's configured (and advertised) USD rate, so a verifier
// can reproduce the ticket's signed micro rate from the advertised USD rate.
func USDRateToMicroUSDCPer1M(usdPer1M float64) (uint64, error) {
	if math.IsNaN(usdPer1M) || math.IsInf(usdPer1M, 0) || usdPer1M < 0 {
		return 0, fmt.Errorf("usd_per_1m out of range: %v", usdPer1M)
	}
	if usdPer1M == 0 {
		return 0, nil
	}
	microPer1M := math.Ceil(usdPer1M * 1_000_000)
	if microPer1M > float64(math.MaxUint64) {
		return 0, errors.New("effective rate overflows uint64")
	}
	return uint64(microPer1M), nil
}

// CeilInputCost is the settle-time input leg: ceil((nonCached*inputRate +
// cached*cacheReadRate) / 1e6) — a SINGLE ceil over the combined numerator, not
// two. When cacheReadRate == inputRate (an unset cache rate) the numerator is
// exactly inputTokens*inputRate, reproducing the pre-cache flat cost byte-for-
// byte; because cacheReadRate <= inputRate a single ceil keeps the discounted
// cost <= the flat cost.
func CeilInputCost(nonCached, inputRate, cached, cacheReadRate uint64) (uint64, error) {
	a, err := checkedMul(nonCached, inputRate)
	if err != nil {
		return 0, err
	}
	b, err := checkedMul(cached, cacheReadRate)
	if err != nil {
		return 0, err
	}
	if a > math.MaxUint64-b {
		return 0, errors.New("input cost numerator overflows uint64")
	}
	num := a + b
	if num == 0 {
		return 0, nil
	}
	return (num + RateDenominatorTokens - 1) / RateDenominatorTokens, nil
}

// RateBasedMaxPrice is the reserve-time rate ceiling for a token ticket:
// ceil(inputCount*inputRate/1e6) + ceil(maxOutputCount*outputRate/1e6) — two
// SEPARATE ceils. No cache-read term (the flat input rate is the worst case,
// since cache_read_rate <= input_rate), no min-charge floor, no protocol fee.
func RateBasedMaxPrice(inputCount, maxOutputCount, inputRate, outputRate uint64) (uint64, error) {
	inputCost, err := ceilMulDiv(inputCount, inputRate, RateDenominatorTokens)
	if err != nil {
		return 0, fmt.Errorf("input_tokens * input_rate: %w", err)
	}
	outputCost, err := ceilMulDiv(maxOutputCount, outputRate, RateDenominatorTokens)
	if err != nil {
		return 0, fmt.Errorf("max_output_tokens * output_rate: %w", err)
	}
	if inputCost > math.MaxUint64-outputCost {
		return 0, errors.New("max_price sum overflows uint64")
	}
	return inputCost + outputCost, nil
}

// AlgoTxnFloorMicroUSDC is the µALGO component of the minimum charge:
// ceil(algoTxns * minTxnFee * algoUSD), or 0 when the charge is unpaid, no txns
// are floored, or the oracle is unavailable (algoUSD <= 0). The algoUSD <= 0
// early return precedes the NaN/Inf guard on purpose — a missing/zero oracle
// silently disables the floor; only a positive-but-non-finite oracle errors.
func AlgoTxnFloorMicroUSDC(paid bool, algoTxns uint64, algoUSD float64) (uint64, error) {
	if !paid || algoTxns == 0 || algoUSD <= 0 {
		return 0, nil
	}
	if math.IsNaN(algoUSD) || math.IsInf(algoUSD, 0) {
		return 0, fmt.Errorf("algo_usd out of range: %v", algoUSD)
	}
	costMicroAlgos, err := checkedMul(algoTxns, AlgorandMinTxnFeeMicroAlgos)
	if err != nil {
		return 0, fmt.Errorf("algo_txn_cost: %w", err)
	}
	f := math.Ceil(float64(costMicroAlgos) * algoUSD)
	if f > float64(math.MaxUint64) {
		return 0, errors.New("min_charge algo-txn floor overflows uint64")
	}
	return uint64(f), nil
}

// ReserveMinPrice is the node's reserve-time minimum charge:
// max(ceil(minOutputTokens*outputRate/1e6), AlgoTxnFloorMicroUSDC(...)). The
// oracle-dependent µALGO component means only the node (which holds the live
// ALGO/USD price) computes this; a payer-side verifier bounds the signed
// min_price with MinChargeFloor instead.
func ReserveMinPrice(minOutputTokens, outputRate, algoTxns uint64, algoUSD float64, paid bool) (uint64, error) {
	tokenFloor, err := ceilMulDiv(minOutputTokens, outputRate, RateDenominatorTokens)
	if err != nil {
		return 0, fmt.Errorf("min_charge.output_tokens * output_rate: %w", err)
	}
	algoFloor, err := AlgoTxnFloorMicroUSDC(paid, algoTxns, algoUSD)
	if err != nil {
		return 0, err
	}
	if algoFloor > tokenFloor {
		return algoFloor, nil
	}
	return tokenFloor, nil
}

// GrossUpForFee returns baseMax + ceil(baseMax*feeBps/1e4): the operator's base
// ceiling grossed up by the additive protocol fee (the contract's pfee global,
// in basis points). feeBps == 0 is a pass-through.
func GrossUpForFee(baseMax, feeBps uint64) (uint64, error) {
	if feeBps == 0 {
		return baseMax, nil
	}
	fee, err := ceilMulDiv(baseMax, feeBps, BpsDenominator)
	if err != nil {
		return 0, fmt.Errorf("protocol-fee gross-up: %w", err)
	}
	if baseMax > math.MaxUint64-fee {
		return 0, errors.New("max_price gross-up overflows uint64")
	}
	return baseMax + fee, nil
}

// ExpectedBaseMax is the pre-gross-up escrow ceiling for a token ticket:
// max(RateBasedMaxPrice + extraBaseMicroUSDC, minPrice). extraBaseMicroUSDC is
// any additive per-request budget folded into the base before the floor and fee
// (e.g. an image-tool budget on a /v1/responses ticket); pass 0 for a plain
// token ticket. This is the node's persisted baseMax and the value ChargeFor
// clamps down to at settle.
func ExpectedBaseMax(inputCount, maxOutputCount, inputRate, outputRate, minPrice, extraBaseMicroUSDC uint64) (uint64, error) {
	rateBased, err := RateBasedMaxPrice(inputCount, maxOutputCount, inputRate, outputRate)
	if err != nil {
		return 0, err
	}
	if rateBased > math.MaxUint64-extraBaseMicroUSDC {
		return 0, errors.New("base max overflows uint64")
	}
	base := rateBased + extraBaseMicroUSDC
	if minPrice > base {
		base = minPrice
	}
	return base, nil
}

// ExpectedMaxPrice composes the full reserve-time escrow ceiling for a token
// ticket: GrossUpForFee(ExpectedBaseMax(...), feeBps). This is exactly the value
// the node signs as ticket.max_price, so a verifier asserts
// ticket.max_price == ExpectedMaxPrice(...) with the on-chain feeBps (check C1).
func ExpectedMaxPrice(inputCount, maxOutputCount, inputRate, outputRate, minPrice, extraBaseMicroUSDC, feeBps uint64) (uint64, error) {
	base, err := ExpectedBaseMax(inputCount, maxOutputCount, inputRate, outputRate, minPrice, extraBaseMicroUSDC)
	if err != nil {
		return 0, err
	}
	return GrossUpForFee(base, feeBps)
}

// ToolFeeReserveMicroUSDC is the additive max_price headroom a per-call
// tool-pricing model folds into the reserve (SPEC.md "Per-call tool pricing"),
// so the node and the payer-side verifier compute byte-identical values (it is
// the extraBaseMicroUSDC term ExpectedMaxPrice/ExpectedBaseMax add before the
// fee gross-up). Two worst-case components:
//   - node zs_ built-in fees: maxToolIterations × maxZsRatePerCall (0 when the
//     builtin-tool loop is disabled, i.e. maxToolIterations == 0 — the same
//     condition under which the node omits max_tool_iterations from
//     /v1/zs/details, so the payer-side verifier reproduces 0 too);
//   - vendor server-side tool fees: vendorCallCap × maxVendorRatePerCall, plus
//     the input-token cost of the per-call context inflation
//     (vendorCallCap × vendorTokensPerCall priced at inputRateMicroUSDCPer1M).
//
// Each component is 0 unless the model prices that class of tool, so a model
// with no tool pricing returns 0 and leaves the reserve unchanged. All rates are
// per-call microUSDC; inputRate is microUSDC per 1M tokens (the same rate signed
// into the ticket). Overflow returns an error rather than wrapping.
func ToolFeeReserveMicroUSDC(maxToolIterations, maxZsRatePerCall, vendorCallCap, maxVendorRatePerCall, vendorTokensPerCall, inputRateMicroUSDCPer1M uint64) (uint64, error) {
	var total uint64
	add := func(v uint64) error {
		if v > math.MaxUint64-total {
			return errors.New("tool-fee reserve overflows uint64")
		}
		total += v
		return nil
	}

	if maxZsRatePerCall > 0 && maxToolIterations > 0 {
		fee, err := checkedMul(maxToolIterations, maxZsRatePerCall)
		if err != nil {
			return 0, err
		}
		if err := add(fee); err != nil {
			return 0, err
		}
	}

	if vendorCallCap > 0 {
		if maxVendorRatePerCall > 0 {
			fee, err := checkedMul(vendorCallCap, maxVendorRatePerCall)
			if err != nil {
				return 0, err
			}
			if err := add(fee); err != nil {
				return 0, err
			}
		}
		if vendorTokensPerCall > 0 && inputRateMicroUSDCPer1M > 0 {
			headroom, err := checkedMul(vendorCallCap, vendorTokensPerCall)
			if err != nil {
				return 0, err
			}
			tokFee, err := RateBasedMaxPrice(headroom, 0, inputRateMicroUSDCPer1M, 0)
			if err != nil {
				return 0, err
			}
			if err := add(tokFee); err != nil {
				return 0, err
			}
		}
	}
	return total, nil
}

// MinChargeFloor is the payer-side reference for the signed min_price (check C3):
// max(ceil(minChargeOutputTokens*outputRate/1e6), minChargeMicroUSDC), using the
// ticket's own output_rate and the operator's advertised min-charge basis. The
// µALGO component is bounded by the advertised minChargeMicroUSDC (the operator's
// current published value) rather than recomputed from the oracle. Saturates to
// MaxUint64 on the (unreachable at realistic sizes) overflow so the check
// fails open rather than rejecting.
func MinChargeFloor(minChargeOutputTokens, outputRate, minChargeMicroUSDC uint64) uint64 {
	tokenFloor, err := ceilMulDiv(minChargeOutputTokens, outputRate, RateDenominatorTokens)
	if err != nil {
		return math.MaxUint64
	}
	if minChargeMicroUSDC > tokenFloor {
		return minChargeMicroUSDC
	}
	return tokenFloor
}

// ChargeFor is the settle-time charge for actual usage:
// clamp(max(CeilInputCost(...) + ceil(actualOutput*outputRate/1e6), minPrice),
// 0, baseMax). Zero input and output short-circuit to 0 (inference failure);
// otherwise the charge is floored to minPrice and clamped down to baseMax. It
// never returns an error — any internal overflow falls back to baseMax — matching
// the node's settle behavior (the operator falls back to the base ceiling rather
// than failing the settle).
func ChargeFor(actualInput, cachedInput, actualOutput, inputRate, cacheReadRate, outputRate, minPrice, baseMax uint64) uint64 {
	if actualInput == 0 && actualOutput == 0 {
		return 0
	}

	cached := cachedInput
	if cached > actualInput {
		cached = actualInput
	}
	nonCached := actualInput - cached

	in, err := CeilInputCost(nonCached, inputRate, cached, cacheReadRate)
	if err != nil {
		return baseMax
	}
	out, err := ceilMulDiv(actualOutput, outputRate, RateDenominatorTokens)
	if err != nil {
		return baseMax
	}

	if in > math.MaxUint64-out {
		return baseMax
	}
	charged := in + out
	if charged < minPrice {
		if minPrice > baseMax {
			return baseMax
		}
		charged = minPrice
	}
	if charged > baseMax {
		return baseMax
	}
	return charged
}
