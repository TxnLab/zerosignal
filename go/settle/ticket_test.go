/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package settle

import (
	"testing"
	"time"
)

// The vectors pin whatever Go answers; this pins what it must answer.
func TestClassify(t *testing.T) {
	const d = 1_800_000_600
	at := time.Unix(d, 0)
	before, after := at.Add(-time.Millisecond), at.Add(time.Millisecond)
	cases := []struct {
		status            Status
		before, at, after Verdict
	}{
		{StatusOpen, VerdictWait, VerdictWait, VerdictRefund},
		{StatusPendingPayer, VerdictWait, VerdictWait, VerdictRefund},
		{StatusPendingOperator, VerdictWait, VerdictWait, VerdictLapse},
		{StatusFrozen, VerdictArbitrate, VerdictArbitrate, VerdictArbitrate},
		{StatusUnrecognized, VerdictUnknown, VerdictUnknown, VerdictUnknown},
		{Status(9), VerdictUnknown, VerdictUnknown, VerdictUnknown},
	}
	for _, c := range cases {
		tk := Ticket{Status: c.status, Deadline: d}
		for _, p := range []struct {
			now  time.Time
			want Verdict
		}{{before, c.before}, {at, c.at}, {after, c.after}} {
			if got := Classify(tk, p.now); got != p.want {
				t.Errorf("status %d at %v: got %v, want %v", c.status, p.now.Sub(at), got, p.want)
			}
		}
	}
}

// A view a decoder forgot to fill must not read as a ticket waiting for its
// deadline.
func TestClassify_ZeroViewIsUnknown(t *testing.T) {
	if got := Classify(Ticket{}, time.Unix(0, 0)); got != VerdictUnknown {
		t.Fatalf("zero Ticket: got %v, want unknown", got)
	}
}

func TestComputeFeeBreakdown_ClampsRefund(t *testing.T) {
	b := ComputeFeeBreakdown(1_000_000, 1_000_000, 500, 0)
	if b.NetFee != 50_000 || b.TotalDebit != 1_050_000 || b.Refund != 0 {
		t.Fatalf("got %+v", b)
	}
}
