/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/algorand/go-algorand-sdk/v2/client/v2/common/models"
	"github.com/algorand/go-algorand-sdk/v2/transaction"
	"github.com/algorand/go-algorand-sdk/v2/types"
	"golang.org/x/sync/errgroup"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// fetchOperatorBoxConcurrency caps how many ReadOperatorBox calls run
// against algod at once. The chain enumeration used to be sequential,
// which made callers like the proxy registry (and the TUI's /models
// command behind it) wait a per-operator round-trip for every
// registered operator. A small fan-out collapses that wallclock without
// hammering the algod node — sixteen is well below algod's default
// concurrent-request budget while still hiding network latency for
// realistic operator counts.
const fetchOperatorBoxConcurrency = 16

// RevenueBucketCount is the size of the daily revenue ring buffer on
// each operator record. Mirrors REVENUE_BUCKETS in ZeroSignalEscrow.algo.ts.
const RevenueBucketCount = 30

// OutputUnitsLen is the width of the per-record outputUnits modality vector
// (indexed by ticket.UsageType: 1=Tokens, 2=Images, 3=Characters, 4=Seconds,
// + 3 reserved; slot 0=None is unused). Mirrors OUTPUT_UNITS_LEN in
// ZeroSignalEscrow.algo.ts.
const OutputUnitsLen = 8

// SecondsPerDay is the bucket-day granularity used by the on-chain
// rotation logic. Mirrors SECONDS_PER_DAY in ZeroSignalEscrow.algo.ts.
const SecondsPerDay = 86_400

// BaseURLMax is the maximum length in bytes of OperatorRecord.baseUrl
// (the on-chain field stores it zero-padded to this exact width).
// Mirrors BASE_URL_MAX in ZeroSignalEscrow.algo.ts; every place that bounds
// a base URL against the contract limit should reference this constant
// rather than re-spelling 248.
const BaseURLMax = 248

// Operator status values, mirrored from ZeroSignalEscrow.algo.ts. EVICTED is a
// soft tombstone written by evictOperator — the box and its node boxes
// persist and in-flight tickets still settle, but discovery hides the
// operator and open() reverts. reinstateOperator flips it back to ACTIVE.
const (
	OperatorStatusActive  uint64 = 1
	OperatorStatusEvicted uint64 = 2
)

// Node status values, mirrored from ZeroSignalEscrow.algo.ts.
const (
	NodeStatusActive uint64 = 1
)

// OperatorRecord is the parsed representation of an operator's on-chain box.
// Mirrors the ZeroSignalEscrow.OperatorRecord struct from the smart contract.
//
// The operator is the economic entity: it holds the cold OwnerAddr (payout
// destination) and the rolled-up reliability metrics (the sum/aggregate
// across every node it owns). Per-node identity — signing key, age recipient,
// base URL — lives on NodeRecord (see nodes.go), one box per running node.
type OperatorRecord struct {
	ID            uint64
	OwnerAddr     string // 58-char Algorand address — settlement payout destination
	Status        uint64 // OperatorStatus* (1=active, 2=evicted)
	NFDAppID      uint64
	NextNodeID    uint64 // monotonic per-operator node id counter (next id to assign)
	LiveNodeCount uint64 // node boxes currently alive under this operator

	// ===== Rolled-up reliability metrics =====
	// RecordMetrics is maintained on-chain as the aggregate across every node
	// owned by this operator (finalizeSettlement and the counter bumps write
	// the serving node's box AND this rollup). All counters are
	// lifetime-monotonic; see ZeroSignalEscrow.algo.ts for per-field semantics.
	// Embedded, so every field reads unqualified — and shared with NodeRecord,
	// so a carve lands in one parser instead of two.
	RecordMetrics

	// ===== Operator USDC stake (micro-USDC escrowed in the app) =====
	// Running total of USDC this operator currently has escrowed: the base
	// operator stake plus each live node's incremental stake. createNode adds
	// the node increment, unregisterNode subtracts it (clamped), evictOperator
	// subtracts the slashed cut (sent to the treasury), and unregister refunds
	// the remainder. Mirrors `usdcEscrowed: uint64` in ZeroSignalEscrow.algo.ts.
	UsdcEscrowed uint64

	// ===== Reserved padding (24 raw bytes) =====
	// Mirrors `reservedSlots: arc4.StaticBytes<24>`; carve typed fields out
	// in lockstep with the contract field, keeping total length stable.
	//
	// NOT the last field: LatencySamples was carved from the TAIL END of the
	// original 32 rather than its head, so the residual sits ahead of it. See
	// the contract's OperatorRecord.reservedSlots for why. Read order below
	// must match.
	ReservedSlots [24]byte

	// ===== Mean-TTFT denominator =====
	// LatencySamples is the count of settlements folded into LatencyTotalMs,
	// bumped only inside the contract's outputUsageType==Tokens guard — so it
	// is the exact denominator for the mean TTFT. Do NOT divide LatencyTotalMs
	// by TicketsSettled + TicketsLapsedSettled: those count image / video /
	// other-modality settles that never touched the numerator, understating
	// the mean for any operator taking non-token-primary work. 0 means no
	// token settle has landed since the field shipped (the contract seeds it
	// once, from the old all-modality count, on the first such settle).
	LatencySamples uint64
}

// operatorRecordSize is the byte length of a serialized OperatorRecord in a
// contract box. All fields are fixed-size ABI types (status narrowed to a
// 1-byte arc4.Uint8); ARC-4 tuples are byte-packed with no alignment:
//
//	owner address      32
//	status uint8        1
//	nfdAppId uint64     8
//	nextNodeId uint64   8
//	liveNodeCount       8
//	-- rolled-up reliability metrics (RecordMetrics) --
//	                          432
//	-- operator USDC stake --
//	usdcEscrowed                8
//	-- reserved padding + mean-TTFT denominator (recordTailSize) --
//	reservedSlots[24]          24
//	latencySamples              8
const operatorRecordSize = 32 + 1 + 8 + 8 + 8 + // 57 — owner + status + nfd + nextNodeId + liveNodeCount
	recordMetricsSize + // 432 — the block shared with NodeRecord
	8 + // 8  — usdcEscrowed
	recordTailSize // 32 — reservedSlots[24] (was 32 before the latencySamples carve) + latencySamples
// Total: 57 + 432 + 8 + 32 = 529. The carve is size-neutral by construction —
// if this total moves, the carve was done wrong and every deployed box will
// mis-decode.

func parseOperatorRecord(id uint64, data []byte) (*OperatorRecord, error) {
	if len(data) < operatorRecordSize {
		return nil, fmt.Errorf("operator %d box too short: %d bytes (want %d)", id, len(data), operatorRecordSize)
	}

	var ownerAddr types.Address
	copy(ownerAddr[:], data[0:32])

	rec := &OperatorRecord{
		ID:            id,
		OwnerAddr:     ownerAddr.String(),
		Status:        uint64(data[32]), // arc4.Uint8 — 1 byte
		NFDAppID:      binary.BigEndian.Uint64(data[33:41]),
		NextNodeID:    binary.BigEndian.Uint64(data[41:49]),
		LiveNodeCount: binary.BigEndian.Uint64(data[49:57]),
	}

	// Metrics begin at offset 57. The length-guard above is load-bearing —
	// every read below is unconditional, so keep the guard in sync with any
	// offset change or these reads run past the slice.
	off := 57
	rec.RecordMetrics, off = parseRecordMetrics(data, off)
	rec.UsdcEscrowed = binary.BigEndian.Uint64(data[off : off+8])
	off += 8
	parseRecordTail(data, off, &rec.ReservedSlots, &rec.LatencySamples)
	return rec, nil
}

// windowedRingRevenue sums the daily-revenue ring over the trailing
// windowDays ending at currentDay (inclusive). windowDays must be in [1, 30].
//
// The contract guarantees only fresh-window data is in slots, so this is just
// `sum slots within [currentDay - windowDays + 1, currentDay]` with the
// day-position derived from each slot's index relative to bucketsLastDay.
// Slots whose mapped day is outside the window are skipped (defensive — they
// should already be zero on chain). Shared by OperatorRecord (rollup) and
// NodeRecord (per node).
func windowedRingRevenue(bucketsLastDay uint64, buckets *[RevenueBucketCount]uint64, currentDay, windowDays uint64) uint64 {
	if windowDays == 0 || windowDays > RevenueBucketCount {
		return 0
	}
	// First-ever-write sentinel: nothing recorded yet.
	if bucketsLastDay == 0 {
		return 0
	}
	// If currentDay is in the past relative to bucketsLastDay (clock skew),
	// there's nothing meaningful to report.
	if currentDay < bucketsLastDay {
		return 0
	}
	// Cutoff is inclusive lower bound.
	cutoff := uint64(0)
	if currentDay+1 > windowDays {
		cutoff = currentDay - windowDays + 1
	}
	// If the entire window is older than what's on chain, nothing recorded
	// inside it.
	if bucketsLastDay+RevenueBucketCount <= cutoff {
		return 0
	}
	var total uint64
	// Walk the buckets backward from the most recent up to RevenueBucketCount
	// days, mapping each step to its day index and skipping anything outside
	// [cutoff, currentDay].
	for step := uint64(0); step < RevenueBucketCount; step++ {
		if step > bucketsLastDay {
			break
		}
		dayIdx := bucketsLastDay - step
		if dayIdx < cutoff {
			break
		}
		if dayIdx > currentDay {
			continue
		}
		slot := dayIdx % RevenueBucketCount
		total += buckets[slot]
	}
	return total
}

// ReadOperatorBox fetches and parses a single operator box by ID.
// Returns (nil, nil) when the box does not exist (operator was unregistered).
func ReadOperatorBox(ctx context.Context, appID uint64, operatorID uint64, algodClient protoalgod.Client) (*OperatorRecord, error) {
	box, err := algodClient.SDKClient().GetApplicationBoxByName(appID, OperatorBoxKey(operatorID)).Do(ctx)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch operator %d box: %w", operatorID, err)
	}
	return parseOperatorRecord(operatorID, box.Value)
}

// NextOperatorID calls the contract's readonly nextOperatorIdValue method via
// simulate and returns the value. Operator IDs run from 1 to
// NextOperatorID()-1 (inclusive). senderAddr is any valid on-chain address
// (e.g. the proxy's payer address); it is only used for the simulate call.
func NextOperatorID(ctx context.Context, appID uint64, algodClient protoalgod.Client, senderAddr string) (uint64, error) {
	sender, err := types.DecodeAddress(senderAddr)
	if err != nil {
		return 0, fmt.Errorf("escrow: decode sender addr: %w", err)
	}
	sp, err := algodClient.SuggestedParams(ctx)
	if err != nil {
		return 0, fmt.Errorf("escrow: suggested params: %w", err)
	}
	method, err := MethodByName("nextOperatorIdValue")
	if err != nil {
		return 0, err
	}

	atc := transaction.AtomicTransactionComposer{}
	if err := atc.AddMethodCall(transaction.AddMethodCallParams{
		AppID:           appID,
		Method:          method,
		Sender:          sender,
		SuggestedParams: sp,
		OnComplete:      types.NoOpOC,
		Signer:          transaction.EmptyTransactionSigner{},
	}); err != nil {
		return 0, fmt.Errorf("escrow: atc add nextOperatorIdValue: %w", err)
	}

	result, err := atc.Simulate(ctx, algodClient.SDKClient(), models.SimulateRequest{AllowEmptySignatures: true})
	if err != nil {
		return 0, fmt.Errorf("escrow: simulate nextOperatorIdValue: %w", err)
	}
	if len(result.SimulateResponse.TxnGroups) > 0 {
		if msg := result.SimulateResponse.TxnGroups[0].FailureMessage; msg != "" {
			return 0, fmt.Errorf("escrow: simulate nextOperatorIdValue failed: %s", msg)
		}
	}
	if len(result.MethodResults) != 1 {
		return 0, fmt.Errorf("escrow: simulate nextOperatorIdValue: got %d results, want 1", len(result.MethodResults))
	}
	mr := result.MethodResults[0]
	if mr.DecodeError != nil {
		return 0, fmt.Errorf("escrow: decode nextOperatorIdValue return: %w", mr.DecodeError)
	}
	n, ok := mr.ReturnValue.(uint64)
	if !ok {
		return 0, fmt.Errorf("escrow: nextOperatorIdValue returned %T, want uint64", mr.ReturnValue)
	}
	return n, nil
}

// FetchAllOperators fetches every currently registered operator from the
// contract by calling nextOperatorIdValue then reading each operator box.
// Operators with deleted boxes (unregistered) are silently skipped.
// senderAddr is passed to NextOperatorID for the simulate call.
//
// Box reads run concurrently (capped by fetchOperatorBoxConcurrency) so
// callers don't pay an O(N) round-trip walk against algod. Order is
// preserved by writing each result into its own pre-allocated slot.
func FetchAllOperators(ctx context.Context, appID uint64, algodClient protoalgod.Client, senderAddr string) ([]OperatorRecord, error) {
	// Prefer a single paginated box listing (names+values) when the client
	// supports it — no nextOperatorId simulate and no 404 per tombstoned id.
	// Fall back to the dense id scan below for a client without the capability
	// (test fakes) or an algod too old to return values with the listing.
	if bl, ok := algodClient.(protoalgod.BoxLister); ok {
		recs, err := fetchAllOperatorsBulk(ctx, appID, bl)
		if err == nil {
			return recs, nil
		}
		if !errors.Is(err, protoalgod.ErrBoxValuesUnsupported) {
			return nil, err
		}
	}

	nextID, err := NextOperatorID(ctx, appID, algodClient, senderAddr)
	if err != nil {
		return nil, fmt.Errorf("escrow: fetch operator count: %w", err)
	}
	if nextID <= 1 {
		return nil, nil
	}
	slots := make([]*OperatorRecord, nextID-1)
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fetchOperatorBoxConcurrency)
	for id := uint64(1); id < nextID; id++ {
		id := id
		g.Go(func() error {
			rec, err := ReadOperatorBox(gctx, appID, id, algodClient)
			if err != nil {
				return err
			}
			slots[id-1] = rec
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	out := make([]OperatorRecord, 0, len(slots))
	for _, rec := range slots {
		if rec != nil {
			out = append(out, *rec)
		}
	}
	return out, nil
}

// fetchAllOperatorsBulk lists every `o:` box (name+value) in one paginated
// sweep and parses each, skipping names that aren't well-formed operator boxes.
// Unlike the dense id scan it issues no nextOperatorId simulate and reads no
// tombstoned/unregistered ids (the listing returns only live boxes). Sorted by
// id so the result order matches the dense-scan path.
func fetchAllOperatorsBulk(ctx context.Context, appID uint64, bl protoalgod.BoxLister) ([]OperatorRecord, error) {
	boxes, err := bl.ListApplicationBoxes(ctx, appID, operatorBoxPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]OperatorRecord, 0, len(boxes))
	for i := range boxes {
		id, ok := operatorIDFromBoxName(boxes[i].Name)
		if !ok {
			continue
		}
		rec, err := parseOperatorRecord(id, boxes[i].Value)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, *rec)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// FetchOperatorsByID fetches the specified operator IDs from the contract.
// Returns an error if any requested operator's box is missing.
//
// Like FetchAllOperators, box reads run concurrently with a bounded
// worker pool and stable output ordering.
func FetchOperatorsByID(ctx context.Context, appID uint64, ids []uint64, algodClient protoalgod.Client) ([]OperatorRecord, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	slots := make([]*OperatorRecord, len(ids))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fetchOperatorBoxConcurrency)
	for i, id := range ids {
		i, id := i, id
		g.Go(func() error {
			rec, err := ReadOperatorBox(gctx, appID, id, algodClient)
			if err != nil {
				return err
			}
			if rec == nil {
				return fmt.Errorf("operator %d not found on chain", id)
			}
			slots[i] = rec
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	out := make([]OperatorRecord, 0, len(slots))
	for _, rec := range slots {
		if rec == nil {
			// Unreachable when g.Wait() returned nil — every goroutine
			// either populates its slot or errors. Defensive guard so
			// a future loosening of the in-goroutine error doesn't
			// silently turn into a nil-deref here.
			continue
		}
		out = append(out, *rec)
	}
	return out, nil
}

// isNotFound reports whether an algod error indicates a 404 / box-not-found.
func isNotFound(err error) bool {
	s := err.Error()
	return strings.Contains(s, "404") || strings.Contains(s, "box not found") || strings.Contains(s, "Box not found")
}
