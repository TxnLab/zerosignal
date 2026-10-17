/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import "github.com/TxnLab/zerosignal/go/settle"

// BpsDenominator mirrors BPS_DENOMINATOR in ZeroSignalEscrow.algo.ts. The fee
// math itself is rail-neutral and lives in package settle; what stays here is
// sizing ZeroSignalEscrow's settle group.
const BpsDenominator = settle.BpsDenominator

// FeeBreakdown is settle.FeeBreakdown: ZeroSignalEscrow.finalizeSettlement
// computes the same fee as the Solana program.
type FeeBreakdown = settle.FeeBreakdown

// NetFee is settle.NetFee, floor for floor ZeroSignalEscrow.finalizeSettlement's
// fee math.
func NetFee(amountCharged, feeBps, discountBps uint64) uint64 {
	return settle.NetFee(amountCharged, feeBps, discountBps)
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
// It deliberately does NOT take feeBps, even though ComputeFeeBreakdown
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

// ComputeFeeBreakdown is settle.ComputeFeeBreakdown.
func ComputeFeeBreakdown(amountCharged, maxPrice, feeBps, discountBps uint64) FeeBreakdown {
	return settle.ComputeFeeBreakdown(amountCharged, maxPrice, feeBps, discountBps)
}
