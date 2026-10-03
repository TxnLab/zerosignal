/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"github.com/TxnLab/zerosignal/go/pricing"
)

// admitEstimate is the estimate SpendGuard.Admit is given: the lowest max_price
// any candidate would sign for this request, priced from its advertised rates
// the way the node prices the ticket. ok is false when any candidate cannot be
// priced, and Admit is then skipped: an unpriced candidate's ticket may be the
// cheapest, and Reserve still checks the signed price.
//
// The lowest, not the highest, because Admit refuses before any candidate is
// tried, and a refusal on the dearest could turn away a request a cheaper node
// would have served within the cap. Reserve then skips any candidate whose
// signed ticket is over the cap.
//
// It leaves out the min-charge floor and the per-call tool headroom, which only
// raise max_price. It can still exceed the signed ticket: the node may sign
// below its advertised rate, or clamp input_count to a tighter context window
// of its own, which can also drop it below the long-context threshold.
func (s *Client) admitEstimate(candidates []Operator, model string, body []byte, sizing SizingRequest) (uint64, bool) {
	feeBps, ok := s.feeRateNow()
	if !ok || len(candidates) == 0 {
		return 0, false
	}
	var lowest uint64
	for i, op := range candidates {
		price, ok := advertisedMaxPrice(op, model, body, sizing, feeBps)
		if !ok {
			return 0, false
		}
		if i == 0 || price < lowest {
			lowest = price
		}
	}
	return lowest, true
}

// advertisedMaxPrice is the max_price op would sign at its advertised rates,
// without the min-charge floor or tool headroom.
func advertisedMaxPrice(op Operator, model string, body []byte, sizing SizingRequest, feeBps uint64) (uint64, bool) {
	mc, ok := op.ModelCapacities[model]
	// A zero advertised rate is undeclared, not free.
	if !ok || mc.InputUSDPer1M == 0 || mc.OutputUSDPer1M == 0 {
		return 0, false
	}
	maxOut := EffectiveMaxOutput(op, sizing)
	input, _ := reserveInputCount(op, model, body, maxOut)
	inUSD, outUSD := mc.InputUSDPer1M, mc.OutputUSDPer1M
	if pricing.IsLongContext(input, mc.LongContextThresholdTokens) {
		if mc.LongContextInputUSDPer1M == nil || mc.LongContextOutputUSDPer1M == nil {
			return 0, false
		}
		inUSD, outUSD = *mc.LongContextInputUSDPer1M, *mc.LongContextOutputUSDPer1M
	}
	inRate, err := pricing.USDRateToMicroUSDCPer1M(inUSD)
	if err != nil {
		return 0, false
	}
	outRate, err := pricing.USDRateToMicroUSDCPer1M(outUSD)
	if err != nil {
		return 0, false
	}
	price, err := pricing.ExpectedMaxPrice(input, maxOut, inRate, outRate, 0, 0, feeBps)
	if err != nil {
		return 0, false
	}
	return price, true
}
