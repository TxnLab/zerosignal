/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

// BpsDenominator is the basis-points denominator (100% = 10_000 bps),
// mirroring BPS_DENOMINATOR in ZeroSignalEscrow.algo.ts.
const BpsDenominator = 10_000

// FeeBreakdown is the payer-facing decomposition of a settled request under
// the additive fee model, derived from the operator-signed AmountCharged and
// the open-time fee snapshot (FeeBps / DiscountBps) stored on the ticket box.
// All amounts are microUSDC.
type FeeBreakdown struct {
	// AmountCharged is the operator's base (net) take — what the operator
	// receives in full. Copied from the signed receipt.
	AmountCharged uint64
	// NetFee is the protocol fee the payer pays ON TOP of AmountCharged. Goes
	// to the treasury. The HAY fee discount is retired (DiscountBps is always
	// 0), so NetFee always equals the gross fee.
	NetFee uint64
	// Refund is what the escrow returns to the payer: MaxPrice (grossed up at
	// reserve) minus the operator payout minus the net fee.
	Refund uint64
	// TotalDebit is the payer's actual cost: AmountCharged + NetFee.
	TotalDebit uint64
}

// NetFee returns the protocol fee (microUSDC) charged on top of amountCharged
// for the fixed-at-open rate (feeBps gross, discountBps HAY discount). It is a
// byte-for-byte mirror of ZeroSignalEscrow.finalizeSettlement's fee math:
//
//	grossFee = floor(amountCharged * feeBps / 10000)
//	netFee   = floor(grossFee * (10000 - discountBps) / 10000)
//
// feeBps is capped at PROTOCOL_FEE_BPS_MAX (2000) and discountBps at 8000 by
// the contract, so for any realistic amountCharged the uint64 products stay
// well clear of overflow — same assumption the contract's own uint64
// arithmetic makes. A discountBps > 10000 (impossible on-chain) would wrap the
// (10000 - discountBps) term, so it is clamped here defensively.
func NetFee(amountCharged, feeBps, discountBps uint64) uint64 {
	if discountBps > BpsDenominator {
		discountBps = BpsDenominator
	}
	grossFee := amountCharged * feeBps / BpsDenominator
	return grossFee * (BpsDenominator - discountBps) / BpsDenominator
}

// SettleInnerCount returns an upper bound on the number of USDC disbursement
// inner-txns ZeroSignalEscrow.finalizeSettlement will submit for a ticket
// settled at amountCharged against an escrowed maxPrice. Off-chain composers
// use it to size the settle fee to the inners that actually fire instead of
// paying a flat worst case: a free model (amountCharged == maxPrice == 0)
// disburses nothing, and a zero-charge settle (a failed request, refunded in
// full) disburses only the refund.
//
// finalizeSettlement gates each disbursement independently:
//
//	operator payout  if opPayout  > 0, opPayout  = amountCharged
//	treasury fee     if netFee    > 0, netFee    = NetFee(amountCharged, feeBps, discountBps)
//	payer refund     if usdcRefund > 0, usdcRefund = maxPrice - amountCharged - netFee
//
// so the count here is
//
//	(amountCharged > 0 ? 2 : 0) + (maxPrice > amountCharged ? 1 : 0)
//
// which never under-counts because netFee >= 0: the treasury inner can only
// fire when amountCharged > 0, and the refund inner can only fire when
// maxPrice > amountCharged + netFee, which implies maxPrice > amountCharged.
//
// It deliberately does NOT take feeBps, even though ComputeFeeBreakdown above
// mirrors the contract exactly. The authoritative feeBps is the ticket's
// open-time snapshot on its box; a composer on the response hot path has only
// the cached protocol-fee global, and an admin fee rotation mid-ticket makes
// that cached value diverge in the UNDER-funding direction both ways — too high
// zeroes the computed refund while the real refund inner fires, too low zeroes
// the computed netFee while the real treasury inner fires. Either under-pools
// the group fee and reverts the settle. The bound above has no such failure
// mode: it is exact whenever amountCharged == 0, and over-counts by at most one
// slot (feeBps == 0, or a ticket spent exactly to its ceiling).
func SettleInnerCount(amountCharged, maxPrice uint64) uint64 {
	var inners uint64
	if amountCharged > 0 {
		inners += 2 // operator payout + treasury fee
	}
	if maxPrice > amountCharged {
		inners++ // payer refund
	}
	return inners
}

// settleLapsedMaxInners is the value SettleInnerCount saturates at — every
// disbursement fires. Used as the fail-safe when a composer cannot read the
// ticket box to size the fee exactly: over-funding costs one minTxnFee, while
// under-funding reverts the settle on every retry.
const settleLapsedMaxInners uint64 = 3

// ComputeFeeBreakdown returns the full payer-facing breakdown for a settled
// request: operator payout (amountCharged), net protocol fee, payer refund, and
// total debit. maxPrice is the escrowed ceiling (grossed up at reserve). When
// amountCharged + netFee exceeds maxPrice (should never happen — the contract
// asserts otherwise — but guards a corrupt/old snapshot), Refund clamps to 0.
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
