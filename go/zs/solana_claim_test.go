/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/solana/zsescrow"
	"github.com/TxnLab/zerosignal/go/ticket"
)

// The claim the payer judges must be the one the node's first half hashes,
// which zsescrow builds from the receipt; a field swapped in the mapping
// would read every honest claim as a contradiction.
func TestSolanaClaimFields_AreTheReceiptsClaim(t *testing.T) {
	r := &ticket.UsageReceipt{
		TicketID: "AAAAAAAAAAAAAAAAAAAAAA==", ActualInputCount: 11, ActualOutputCount: 13, AmountCharged: 17, TtftMs: 19, DecodeMs: 23,
		BodyHash: strings.Repeat("a", 64), OutputUsageType: ticket.UsageTypeTokens, AuxOutputUsageType: ticket.UsageTypeImages, AuxOutputCount: 29,
	}
	if got, want := solanaClaimFields(settleArgsOf(r)), zsescrow.ClaimFromReceipt(r); got != want {
		t.Fatalf("claim fields %+v, want %+v", got, want)
	}
}
