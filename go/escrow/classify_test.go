/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"testing"
	"time"
)

const (
	testExpiresAt = uint64(1_000)
	testGrace     = uint64(100)
	testDeadline  = int64(1_100) // D = expires_at + settlement_grace_seconds
)

func testTicket(status, pendingBy uint64) *TicketRecord {
	return &TicketRecord{
		ExpiresAt:              testExpiresAt,
		SettlementGraceSeconds: testGrace,
		Status:                 status,
		PendingBy:              pendingBy,
	}
}

func TestSettlementDeadline(t *testing.T) {
	got := testTicket(StatusOpen, PendingNone).SettlementDeadline()
	if want := time.Unix(testDeadline, 0); !got.Equal(want) {
		t.Fatalf("SettlementDeadline() = %v, want %v", got, want)
	}
}

// Classify must agree with the contract's asserts for every state the box can
// carry, on both sides of the deadline. The two deadline calls are disjoint:
// refundInactive rejects an operator-side claim ('ticket not refundable') and
// settleLapsed rejects everything else ('ticket not pending settle'), so no
// state may yield both.
func TestClassify(t *testing.T) {
	var (
		before = time.Unix(testDeadline-50, 0)
		atD    = time.Unix(testDeadline, 0)
		after  = time.Unix(testDeadline+50, 0)
	)
	tests := []struct {
		name      string
		status    uint64
		pendingBy uint64
		now       time.Time
		want      Verdict
	}{
		// Settle window open: neither deadline call is legal yet.
		{"open before deadline", StatusOpen, PendingNone, before, VerdictWait},
		{"operator claim before deadline", StatusPendingSettle, PendingByOperator, before, VerdictWait},
		{"payer claim before deadline", StatusPendingSettle, PendingByPayer, before, VerdictWait},

		// The asserts are strictly `latestTimestamp > D`, so exactly at D the
		// window is still open — a refund here would revert.
		{"open exactly at deadline", StatusOpen, PendingNone, atD, VerdictWait},
		{"operator claim exactly at deadline", StatusPendingSettle, PendingByOperator, atD, VerdictWait},

		// Past D, no operator claim → the payer's refundInactive.
		{"open past deadline", StatusOpen, PendingNone, after, VerdictRefund},
		{"payer claim past deadline", StatusPendingSettle, PendingByPayer, after, VerdictRefund},

		// Past D with an operator claim → settleLapsed only.
		{"operator claim past deadline", StatusPendingSettle, PendingByOperator, after, VerdictLapse},

		// Frozen outranks the clock — no method accepts it at any time.
		{"frozen before deadline", StatusFrozen, PendingNone, before, VerdictArbitrate},
		{"frozen past deadline", StatusFrozen, PendingNone, after, VerdictArbitrate},
		{"frozen with operator claim", StatusFrozen, PendingByOperator, after, VerdictArbitrate},

		// States the contract never stores. Unknown, not Wait: inventing a legal
		// call would burn an attempt budget on a guaranteed revert, but calling
		// it Wait would promise the caller that the deadline makes it legal.
		{"pending settle with no side", StatusPendingSettle, PendingNone, after, VerdictUnknown},
		{"settled is never stored", StatusSettled, PendingNone, after, VerdictUnknown},
		{"refunded is never stored", StatusRefunded, PendingNone, after, VerdictUnknown},

		// ...and the clock must not change that. An unrecognized status before D
		// is still Unknown — waiting for D is exactly the false hope Wait implies.
		{"pending settle with no side, before deadline", StatusPendingSettle, PendingNone, before, VerdictUnknown},
		{"settled before deadline", StatusSettled, PendingNone, before, VerdictUnknown},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Classify(testTicket(tc.status, tc.pendingBy), tc.now); got != tc.want {
				t.Fatalf("Classify() = %v, want %v", got, tc.want)
			}
		})
	}
}

// A box's own grace window is authoritative over any deadline recomputed from
// the cached `grace` global, so a non-default grace must move the verdict.
func TestClassifyHonorsPerTicketGrace(t *testing.T) {
	rec := testTicket(StatusOpen, PendingNone)
	rec.SettlementGraceSeconds = 600 // D = 1600, not 1100
	if got := Classify(rec, time.Unix(testDeadline+50, 0)); got != VerdictWait {
		t.Fatalf("Classify() = %v past the default grace but inside the box's own, want %v", got, VerdictWait)
	}
	if got := Classify(rec, time.Unix(1_650, 0)); got != VerdictRefund {
		t.Fatalf("Classify() = %v past the box's own grace, want %v", got, VerdictRefund)
	}
}

func TestVerdictString(t *testing.T) {
	tests := []struct {
		v    Verdict
		want string
	}{
		{VerdictWait, "wait"},
		{VerdictRefund, "refundInactive"},
		{VerdictLapse, "settleLapsed"},
		{VerdictArbitrate, "arbitrate"},
		{VerdictUnknown, "unknown"},
		{Verdict(0), "invalid"},
	}
	for _, tc := range tests {
		if got := tc.v.String(); got != tc.want {
			t.Fatalf("Verdict(%d).String() = %q, want %q", tc.v, got, tc.want)
		}
	}
}
