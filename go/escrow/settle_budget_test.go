package escrow

import "testing"

// TestRingGapIters pins the off-chain mirror to ZeroSignalEscrow.revenueRingGapIters
// (and the catch-up loop it sizes). Drift here means the composer mis-sizes the
// settle fee, so keep this table in lockstep with the contract.
func TestRingGapIters(t *testing.T) {
	cases := []struct {
		name             string
		lastDay, current uint64
		want             uint64
	}{
		{"first write (sentinel 0)", 0, 100, 0},
		{"same day", 100, 100, 0},
		{"clock regressed (current < last)", 100, 99, 0},
		{"consecutive day (gap 1, no loop)", 100, 101, 0},
		{"gap 2 → 1 iter", 100, 102, 1},
		{"gap 10 → 9 iters", 100, 110, 9},
		{"gap 29 → 28 iters (max loop)", 100, 129, 28},
		{"gap == RevenueBucketCount → full reset, 0", 100, 100 + RevenueBucketCount, 0},
		{"gap > RevenueBucketCount → full reset, 0", 100, 200, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ringGapIters(tc.lastDay, tc.current); got != tc.want {
				t.Fatalf("ringGapIters(%d, %d) = %d, want %d", tc.lastDay, tc.current, got, tc.want)
			}
		})
	}
}

// TestGapOpUpsForIters checks the iteration→op-up conversion and, crucially, the
// SAFETY INVARIANT that the funded op-ups never under-provision the contract.
func TestGapOpUpsForIters(t *testing.T) {
	// Concrete values: ceil(iters*40 / 700).
	for _, tc := range []struct{ iters, want uint64 }{
		{0, 0},
		{1, 1},  // ceil(40/700)
		{17, 1}, // ceil(680/700)
		{18, 2}, // ceil(720/700)
		{35, 2}, // ceil(1400/700)
		{36, 3}, // ceil(1440/700)
		{56, 4}, // ceil(2240/700) — max total iters (two boxes × gap 29)
	} {
		if got := GapOpUpsForIters(tc.iters); got != tc.want {
			t.Errorf("GapOpUpsForIters(%d) = %d, want %d", tc.iters, got, tc.want)
		}
	}

	// SAFETY INVARIANT. finalizeSettlement op-ups until the opcode budget
	// reaches SETTLE_BASE_BUDGET + iters*RING_GAP_OPCODES_PER_ITER, starting from
	// the path's entry budget. The LOWEST finalize entry budget across all paths
	// is the standalone 2-step ack (~326, measured on localnet). The fee funds
	// 1 base op-up + GapOpUpsForIters(iters) extra; assert the budget that grants
	// always covers the contract target, for every reachable iteration count.
	const (
		settleBaseBudget = 560 // mirror of SETTLE_BASE_BUDGET
		worstEntryBudget = 326 // lowest measured finalize entry (standalone ack)
		maxIters         = 2 * (RevenueBucketCount - 1)
	)
	for iters := uint64(0); iters <= maxIters; iters++ {
		fundedOpUps := 1 + GapOpUpsForIters(iters)
		grantedBudget := worstEntryBudget + fundedOpUps*avmOpcodeBudgetPerOpUp
		target := uint64(settleBaseBudget) + iters*ringGapOpcodesPerIter
		if grantedBudget < target {
			t.Fatalf("under-funded at iters=%d: granted %d < target %d (fundedOpUps=%d)",
				iters, grantedBudget, target, fundedOpUps)
		}
	}
}

// TestBoundedRingGapIters checks the two properties that make it usable as an
// upper bound by a caller holding only a LOWER bound on a box's bucketsLastDay
// (the node's own last-settle day): it is monotonically non-increasing in
// lastDay, and it dominates the exact ringGapIters for every actual day at or
// after that lower bound.
func TestBoundedRingGapIters(t *testing.T) {
	const today = 1_000

	for _, tc := range []struct {
		name    string
		lastDay uint64
		want    uint64
	}{
		{"first write (sentinel 0)", 0, 0},
		{"same day", today, 0},
		{"clock regressed", today + 1, 0},
		{"gap 1 (no loop)", today - 1, 0},
		{"gap 2", today - 2, 1},
		{"gap 29 (max loop)", today - 29, 28},
		{"gap == RevenueBucketCount clamps, does NOT reset", today - RevenueBucketCount, RevenueBucketCount - 1},
		{"far past clamps", today - 500, RevenueBucketCount - 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := BoundedRingGapIters(tc.lastDay, today); got != tc.want {
				t.Fatalf("BoundedRingGapIters(%d, %d) = %d, want %d", tc.lastDay, today, got, tc.want)
			}
		})
	}

	// Monotone non-increasing in lastDay. ringGapIters is NOT (its full-wrap
	// reset branch drops back to 0), which is exactly why this variant exists.
	for lastDay := uint64(today - 60); lastDay < today; lastDay++ {
		cur, next := BoundedRingGapIters(lastDay, today), BoundedRingGapIters(lastDay+1, today)
		if next > cur {
			t.Fatalf("not monotone: BoundedRingGapIters(%d)=%d < BoundedRingGapIters(%d)=%d",
				lastDay, cur, lastDay+1, next)
		}
	}

	// Domination: for any actual box day d >= the tracked lower bound, the
	// contract's exact iteration count never exceeds the bound. This is the
	// property ComposeSettleGroup's fee relies on — the operator box can be
	// FRESHER than the node's tracked day (a sibling node settled), and a
	// fresher box can run MORE catch-up iterations than a fully-wrapped one.
	for lowerBound := uint64(today - 60); lowerBound <= today; lowerBound++ {
		bound := BoundedRingGapIters(lowerBound, today)
		for d := lowerBound; d <= today; d++ {
			if exact := ringGapIters(d, today); exact > bound {
				t.Fatalf("bound violated: lowerBound=%d bound=%d, but ringGapIters(%d)=%d",
					lowerBound, bound, d, exact)
			}
		}
	}
}

// TestGroupedSettleOpUpsNeverUnderFund is the grouped-path counterpart to the
// safety invariant in TestGapOpUpsForIters. ComposeSettleGroup funds NO base
// op-up: the grouped finalize's entry opcode budget already clears
// SETTLE_BASE_BUDGET (see the constant's docblock in ZeroSignalEscrow.algo.ts —
// ~725 measured, vs a 560 target), so a steady-state settle op-ups zero times.
// Assume only that guarantee (entry >= SETTLE_BASE_BUDGET) and assert
// GapOpUpsForIters still grants at least the contract's gap-scaled target.
func TestGroupedSettleOpUpsNeverUnderFund(t *testing.T) {
	const (
		settleBaseBudget = 560 // mirror of SETTLE_BASE_BUDGET
		maxIters         = 2 * (RevenueBucketCount - 1)
	)
	for iters := uint64(0); iters <= maxIters; iters++ {
		granted := uint64(settleBaseBudget) + GapOpUpsForIters(iters)*avmOpcodeBudgetPerOpUp
		target := uint64(settleBaseBudget) + iters*ringGapOpcodesPerIter
		if granted < target {
			t.Fatalf("under-funded at iters=%d: granted %d < target %d", iters, granted, target)
		}
	}
	if got := GapOpUpsForIters(0); got != 0 {
		t.Fatalf("steady-state grouped settle must fund 0 op-ups, got %d", got)
	}
}
