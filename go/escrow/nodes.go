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

	"github.com/algorand/go-algorand-sdk/v2/types"
	"golang.org/x/sync/errgroup"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// NodeRecord is the parsed representation of a node's on-chain box. Mirrors
// the ZeroSignalEscrow.NodeRecord struct from the smart contract. A node is a
// running endpoint owned by an operator: it carries the hot signing key, the
// age recipient, the base URL, and its own per-node reliability metrics. Each
// finalized settlement bumps both the serving node's box (these fields) and
// the operator rollup.
//
// OperatorID / NodeID are not stored in the box — they come from the compound
// box key — and are populated by the parser from the key the caller used.
type NodeRecord struct {
	OperatorID uint64
	NodeID     uint64

	Status      uint64 // NodeStatus* (1=active)
	SigningAddr string // 58-char Algorand address — hot key; signs tickets/receipts, authorizes open/settle
	BaseURL     string

	// ===== Per-node reliability metrics =====
	// The same type the OperatorRecord rollup embeds — this copy scoped to this
	// one node. The Go side is a transparent mirror of
	// ZeroSignalEscrow.algo.ts.
	RecordMetrics

	// UsdcEscrowed is this node's incremental USDC stake (micro-USDC): 0 for the
	// operator's first node, else nodeStakeUsd6 (== micro-USDC) when createNode
	// ran. Refunded (clamped) on unregisterNode. Mirrors `usdcEscrowed: uint64`
	// in ZeroSignalEscrow.algo.ts.
	UsdcEscrowed uint64
	// Staging mirrors `staging: arc4.Uint8` in ZeroSignalEscrow.algo.ts (a 1-byte
	// flag: 0=production, 1=staging). Owner/signer-toggled via setNodeStaging; a
	// staging node still advertises on-chain but is meant to be held out of
	// normal routing/selection. Given its own byte on this fresh deploy rather
	// than carved out of the reserve, which was a full 32 bytes at that point
	// (box +1 B vs the pre-staging layout, a one-time MBR delta). It sits
	// immediately before the reserve, which LatencySamples has since shortened
	// to 24 — see ReservedSlots below.
	Staging uint64
	// ReservedSlots is NOT the last field. LatencySamples was carved from the
	// TAIL END of the original 32-byte blob rather than its head, so the
	// residual sits ahead of it — see the note on the contract's
	// NodeRecord.reservedSlots for why. Read order below must match.
	ReservedSlots [24]byte
	// LatencySamples is the count of settlements folded into LatencyTotalMs.
	// It bumps only inside the contract's outputUsageType==Tokens guard, so it
	// is the exact denominator for this node's mean TTFT. Do NOT divide
	// LatencyTotalMs by TicketsSettled + TicketsLapsedSettled: those count
	// image / video / other-modality settles that never touched the numerator,
	// which understates the mean. 0 means no token settle has landed since the
	// field shipped (the contract seeds it once on the first such settle).
	LatencySamples uint64
}

// nodeRecordSize is the byte length of a serialized NodeRecord in a contract
// box. Fixed-layout, ARC-4 byte-packed (status/baseUrlLen narrowed to 1-byte
// arc4.Uint8):
//
//	status uint8             1
//	signing address         32
//	baseUrlLen uint8          1
//	baseUrl byte[248]       248
//	-- per-node reliability metrics --
//	lastActivityAt … latencyEwmaMs  (12 × uint64) 96
//	totalRevenueGross         8
//	bucketsLastDay            8
//	revenueBuckets[30]      240
//	totalInputTokens          8
//	outputUnits[8]           64
//	tokensPerSecEwma          8
//	usdcEscrowed              8
//	staging uint8             1
//	reservedSlots[24]        24
//	latencySamples            8
//
// encryptionPubKey (the legacy byte[62] anchor age recipient) was removed under
// mandatory forward secrecy — request encryption uses the node's off-chain
// rotating ephemeral key, not an on-chain key.
const nodeRecordSize = 1 + 32 + 1 + BaseURLMax + // 282 — identity/location base
	recordMetricsSize + // 432 — the block shared with OperatorRecord
	8 + // 8  — usdcEscrowed
	1 + // 1  — staging
	recordTailSize // 32 — reservedSlots[24] (was 32 before the latencySamples carve) + latencySamples
// Total: 282 + 432 + 8 + 1 + 32 = 755. The carve is size-neutral by
// construction — if this total moves, the carve was done wrong and every
// deployed box will mis-decode.

func parseNodeRecord(operatorID, nodeID uint64, data []byte) (*NodeRecord, error) {
	if len(data) < nodeRecordSize {
		return nil, fmt.Errorf("node %d/%d box too short: %d bytes (want %d)", operatorID, nodeID, len(data), nodeRecordSize)
	}

	status := uint64(data[0]) // arc4.Uint8 — 1 byte

	var signingAddr types.Address
	copy(signingAddr[:], data[1:33])

	baseURLLen := uint64(data[33]) // arc4.Uint8 — 1 byte
	if baseURLLen > BaseURLMax {
		return nil, fmt.Errorf("node %d/%d baseUrlLen %d exceeds %d", operatorID, nodeID, baseURLLen, BaseURLMax)
	}
	baseURL := strings.TrimRight(string(data[34:34+baseURLLen]), "\x00")

	rec := &NodeRecord{
		OperatorID:  operatorID,
		NodeID:      nodeID,
		Status:      status,
		SigningAddr: signingAddr.String(),
		BaseURL:     baseURL,
	}

	// Metrics begin at offset 282 (1+32+1+248). The length-guard above is
	// load-bearing — keep it in sync with any offset change.
	off := 282
	rec.RecordMetrics, off = parseRecordMetrics(data, off)
	rec.UsdcEscrowed = binary.BigEndian.Uint64(data[off : off+8])
	off += 8
	rec.Staging = uint64(data[off]) // arc4.Uint8 — 1 byte
	off++
	parseRecordTail(data, off, &rec.ReservedSlots, &rec.LatencySamples)
	return rec, nil
}

// ReadNodeBox fetches and parses a single node box by (operatorID, nodeID).
// Returns (nil, nil) when the box does not exist (node was unregistered).
func ReadNodeBox(ctx context.Context, appID, operatorID, nodeID uint64, algodClient protoalgod.Client) (*NodeRecord, error) {
	box, err := algodClient.SDKClient().GetApplicationBoxByName(appID, NodeBoxKey(operatorID, nodeID)).Do(ctx)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetch node %d/%d box: %w", operatorID, nodeID, err)
	}
	return parseNodeRecord(operatorID, nodeID, box.Value)
}

// FetchNodesForOperators reads every live node across the given operators
// using a SINGLE bounded concurrency limiter (fetchOperatorBoxConcurrency) over
// the flat set of (operatorID, nodeID) box reads — so total in-flight algod
// calls stay capped at fetchOperatorBoxConcurrency regardless of how many
// operators run how many nodes (the per-operator + per-node nesting would
// otherwise multiply to ~concurrency² peak reads against a shared algod).
//
// EVICTED operators are skipped: their nodes are never routable (discovery
// hides them and open() reverts), so fetching the boxes is wasted work. Nodes
// with deleted boxes (unregistered) are silently skipped. Output order is
// stable: operator order (as given), then node id ascending.
func FetchNodesForOperators(ctx context.Context, appID uint64, ops []OperatorRecord, algodClient protoalgod.Client) ([]NodeRecord, error) {
	// Prefer a single paginated box listing (names+values) when the client
	// supports it — no 404 per unregistered node id. Fall back to the per-operator
	// dense scan below for a client without the capability (test fakes) or an
	// algod too old to return values with the listing.
	if bl, ok := algodClient.(protoalgod.BoxLister); ok {
		recs, err := fetchAllNodesBulk(ctx, appID, ops, bl)
		if err == nil {
			return recs, nil
		}
		if !errors.Is(err, protoalgod.ErrBoxValuesUnsupported) {
			return nil, err
		}
	}

	// Flat work list of every (operator-slot, node id) read to perform, and a
	// per-operator result slot so output ordering is deterministic.
	type nodeReadRef struct {
		opIdx      int
		operatorID uint64
		nodeID     uint64
	}
	var refs []nodeReadRef
	perOp := make([][]*NodeRecord, len(ops))
	for i, op := range ops {
		if op.Status == OperatorStatusEvicted || op.NextNodeID <= 1 {
			continue
		}
		perOp[i] = make([]*NodeRecord, op.NextNodeID-1)
		for nodeID := uint64(1); nodeID < op.NextNodeID; nodeID++ {
			refs = append(refs, nodeReadRef{opIdx: i, operatorID: op.ID, nodeID: nodeID})
		}
	}
	if len(refs) == 0 {
		return nil, nil
	}
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(fetchOperatorBoxConcurrency)
	for _, r := range refs {
		r := r
		g.Go(func() error {
			rec, err := ReadNodeBox(gctx, appID, r.operatorID, r.nodeID, algodClient)
			if err != nil {
				return err
			}
			perOp[r.opIdx][r.nodeID-1] = rec
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	var out []NodeRecord
	for _, nodes := range perOp {
		for _, rec := range nodes {
			if rec != nil {
				out = append(out, *rec)
			}
		}
	}
	return out, nil
}

// fetchAllNodesBulk lists every `n:` box (name+value) in one paginated sweep and
// keeps only nodes belonging to a non-evicted operator present in ops — the bulk
// counterpart of the per-operator node-id scan, with no simulate and no 404 per
// unregistered node id. Sorted by (operatorID, nodeID) to match the dense path's
// stable order.
func fetchAllNodesBulk(ctx context.Context, appID uint64, ops []OperatorRecord, bl protoalgod.BoxLister) ([]NodeRecord, error) {
	eligible := make(map[uint64]struct{}, len(ops))
	for _, op := range ops {
		if op.Status != OperatorStatusEvicted {
			eligible[op.ID] = struct{}{}
		}
	}
	boxes, err := bl.ListApplicationBoxes(ctx, appID, nodeBoxPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]NodeRecord, 0, len(boxes))
	for i := range boxes {
		operatorID, nodeID, ok := nodeIDsFromBoxName(boxes[i].Name)
		if !ok {
			continue
		}
		if _, keep := eligible[operatorID]; !keep {
			continue // node of an evicted / not-requested operator
		}
		rec, err := parseNodeRecord(operatorID, nodeID, boxes[i].Value)
		if err != nil {
			return nil, err
		}
		if rec != nil {
			out = append(out, *rec)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].OperatorID != out[j].OperatorID {
			return out[i].OperatorID < out[j].OperatorID
		}
		return out[i].NodeID < out[j].NodeID
	})
	return out, nil
}

// FetchAllNodes fetches every live node across every registered, ACTIVE
// operator (evicted operators are skipped — see FetchNodesForOperators). It
// reads all operators first (FetchAllOperators), then fans out over their node
// ranges under one bounded limiter. The returned NodeRecords carry their
// OperatorID/NodeID. senderAddr is passed to NextOperatorID for the simulate
// call.
func FetchAllNodes(ctx context.Context, appID uint64, algodClient protoalgod.Client, senderAddr string) ([]NodeRecord, error) {
	ops, err := FetchAllOperators(ctx, appID, algodClient, senderAddr)
	if err != nil {
		return nil, err
	}
	return FetchNodesForOperators(ctx, appID, ops, algodClient)
}
