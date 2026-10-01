package escrow

import (
	"context"
	"time"
)

// Gap-aware op-up sizing for the single-app-call settle paths (settleLapsed and
// the standalone operator/ack settle). These MIRROR finalizeSettlement's
// gap-aware ensureBudget in contracts/contracts/ZeroSignalEscrow.algo.ts
// (target = SETTLE_BASE_BUDGET + ringGapIters*RING_GAP_OPCODES_PER_ITER) — keep
// them in lockstep with that contract. The contract sizes its opcode-budget
// op-up to the daily-revenue ring's catch-up loop a multi-day-gap settle will
// run; the off-chain composer must fund the matching inner-txn fees (the op-ups
// draw from group credit), or a long-idle node's first settle reverts for want
// of fee. The grouped happy path is unaffected — it carries far more pooled
// budget and does not op-up at steady state (see ComposeSettleGroup).
const (
	// ringGapOpcodesPerIter mirrors the contract's RING_GAP_OPCODES_PER_ITER:
	// an upper bound on the opcode cost of ONE revenue-ring catch-up iteration
	// (bucket zeroing), which the contract runs on BOTH the node and operator
	// boxes.
	ringGapOpcodesPerIter = 40
	// avmOpcodeBudgetPerOpUp is the opcode budget one ensureBudget op-up
	// inner-txn grants (the AVM per-app-call dynamic opcode budget).
	avmOpcodeBudgetPerOpUp = 700
)

// ringGapIters mirrors ZeroSignalEscrow.revenueRingGapIters: the number of
// bucket-zeroing iterations the daily-revenue catch-up loop runs for a box last
// written on day lastDay, evaluated at currentDay. 0 on the first write
// (lastDay==0), same-day, or a full-wrap gap (>= RevenueBucketCount, the O(1)
// reset branch); otherwise gap-1. Keep in lockstep with the contract loop.
//
// Exact, and only safe to call with a box's ACTUAL bucketsLastDay. The wrap
// short-circuit makes it non-monotonic in lastDay — a staler box can score
// FEWER iterations than a fresher one — so a caller holding only a lower bound
// on lastDay must use BoundedRingGapIters instead.
func ringGapIters(lastDay, currentDay uint64) uint64 {
	if lastDay == 0 || currentDay <= lastDay {
		return 0
	}
	gap := currentDay - lastDay
	if gap >= RevenueBucketCount {
		return 0
	}
	return gap - 1
}

// BoundedRingGapIters is the monotone upper-bound form of ringGapIters, for
// callers that know only a LOWER bound on a box's bucketsLastDay (e.g. a node
// tracking the day of its own last settle, which pins both its node box and its
// operator rollup at or after that day). It clamps a full-wrap gap to the
// loop's maximum RevenueBucketCount-1 iterations rather than taking the
// contract's O(1) reset branch.
//
// The clamp is what makes it usable as a bound: with the reset short-circuit,
// a 40-day-stale box scores 0 while a 20-day-stale box scores 19, so
// ringGapIters(lowerBound) can UNDER-state the iterations of a fresher box and
// under-fund the fee. Here, for any actual day d >= lastDay,
// ringGapIters(d, currentDay) <= BoundedRingGapIters(lastDay, currentDay).
func BoundedRingGapIters(lastDay, currentDay uint64) uint64 {
	if lastDay == 0 || currentDay <= lastDay {
		return 0
	}
	if gap := currentDay - lastDay; gap < RevenueBucketCount {
		return gap - 1
	}
	return RevenueBucketCount - 1
}

// GapOpUpsForIters converts a total catch-up iteration count (summed across the
// node + operator boxes) into the number of EXTRA finalize op-up inner-txns to
// fund. ceil(iters * perIter / perOpUp).
//
// The single-app-call finalize always issues one base op-up, which already
// covers the contract SETTLE_BASE_BUDGET; only the gap term is extra. This
// over-funds slightly by design (the contract's base budget leaves ~1 op-up of
// headroom), so a small miscount — e.g. from off-chain/on-chain day-boundary
// skew — cannot under-fund.
//
// The grouped settle issues NO base op-up (its entry opcode budget already
// clears SETTLE_BASE_BUDGET; see the constant's docblock in the contract), yet
// the same conversion bounds it: ensureBudget op-ups until the remaining budget
// reaches SETTLE_BASE_BUDGET + iters*perIter, so with an available budget of at
// least SETTLE_BASE_BUDGET the op-ups it issues are at most
// ceil(iters*perIter / perOpUp) — exactly this value, and 0 at iters == 0.
func GapOpUpsForIters(iters uint64) uint64 {
	if iters == 0 {
		return 0
	}
	return (iters*ringGapOpcodesPerIter + avmOpcodeBudgetPerOpUp - 1) / avmOpcodeBudgetPerOpUp
}

// gapSettleOpUps reads the node + operator boxes' bucketsLastDay and returns the
// extra finalize op-up inner-txns a single-app-call settle must fund so it does
// not revert on group credit when finalize tops the opcode budget up for the
// revenue-ring catch-up loop. Both boxes run that loop, so their iteration
// counts are summed.
//
// Best-effort: a box-read error or an absent box (mid-flight unregister, which
// the contract skips too) contributes 0. The base fee still covers the common
// no-gap settle; the worst case is the pre-feature behavior — a fee-short revert
// on a rare long-gap settle, which the driver's retry / lapse backstop
// re-attempts. Day bucketing uses wall-clock time, which mirrors the contract's
// Global.latestTimestamp closely enough for fee sizing (the result
// over-provisions, so a sub-day clock skew never under-funds).
func (c *Client) gapSettleOpUps(ctx context.Context, operatorID, nodeID uint64) uint64 {
	currentDay := uint64(time.Now().Unix()) / SecondsPerDay
	var iters uint64
	if node, err := ReadNodeBox(ctx, c.AppID, operatorID, nodeID, c.Algod); err == nil && node != nil {
		iters += ringGapIters(node.BucketsLastDay, currentDay)
	}
	if op, err := ReadOperatorBox(ctx, c.AppID, operatorID, c.Algod); err == nil && op != nil {
		iters += ringGapIters(op.BucketsLastDay, currentDay)
	}
	return GapOpUpsForIters(iters)
}
