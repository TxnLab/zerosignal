/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package settle

// BpsDenominator is the basis-points denominator (100% = 10_000 bps).
const BpsDenominator = 10_000

// FeeBreakdown is the payer-facing decomposition of a settled request under
// the additive fee model, derived from the operator-signed AmountCharged and
// the open-time fee snapshot stored on the ticket. All amounts are microUSDC.
type FeeBreakdown struct {
	// AmountCharged is the operator's base (net) take — what the operator
	// receives in full. Copied from the signed receipt.
	AmountCharged uint64
	// NetFee is the protocol fee the payer pays ON TOP of AmountCharged. Goes
	// to the treasury.
	NetFee uint64
	// Refund is what the escrow returns to the payer: MaxPrice (grossed up at
	// reserve) minus the operator payout minus the net fee.
	Refund uint64
	// TotalDebit is the payer's actual cost: AmountCharged + NetFee.
	TotalDebit uint64
}

// NetFee returns the protocol fee (microUSDC) charged on top of amountCharged
// for the fixed-at-open rate (feeBps gross, discountBps fee discount), floor for
// floor as the contracts compute it:
//
//	grossFee = floor(amountCharged * feeBps / 10000)
//	netFee   = floor(grossFee * (10000 - discountBps) / 10000)
//
// The Algorand contract's HAY discount is retired and the Solana program has
// none, so discountBps is 0 on every live ticket and netFee is the gross fee.
// Both contracts cap feeBps at 2000, so the uint64 product cannot overflow
// below 2^64 / 2000 microUSDC (about 9.2 billion USDC per charge); the Solana
// program widens to u128 and the two would differ only above that. A
// discountBps > 10000 (impossible on-chain) would wrap the (10000 -
// discountBps) term, so it is clamped here defensively.
func NetFee(amountCharged, feeBps, discountBps uint64) uint64 {
	if discountBps > BpsDenominator {
		discountBps = BpsDenominator
	}
	grossFee := amountCharged * feeBps / BpsDenominator
	return grossFee * (BpsDenominator - discountBps) / BpsDenominator
}

// ComputeFeeBreakdown returns the full payer-facing breakdown for a settled
// request: operator payout (amountCharged), net protocol fee, payer refund, and
// total debit. maxPrice is the escrowed ceiling (grossed up at reserve). When
// amountCharged + netFee exceeds maxPrice (should never happen — the contracts
// assert otherwise — but guards a corrupt/old snapshot), Refund clamps to 0.
func ComputeFeeBreakdown(amountCharged, maxPrice, feeBps, discountBps uint64) FeeBreakdown {
	netFee := NetFee(amountCharged, feeBps, discountBps)
	totalDebit := amountCharged + netFee
	var refund uint64
	if maxPrice > totalDebit {
		refund = maxPrice - totalDebit
	}
	return FeeBreakdown{
		AmountCharged: amountCharged,
		NetFee:        netFee,
		Refund:        refund,
		TotalDebit:    totalDebit,
	}
}
