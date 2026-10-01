/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/algorand/go-algorand-sdk/v2/types"

	protoalgod "github.com/TxnLab/zerosignal/go/algod"
)

// Ticket status constants, mirrored from ZeroSignalEscrow.algo.ts. Only
// StatusOpen, StatusFrozen, and StatusPendingSettle are ever written
// on-chain — StatusSettled/StatusRefunded correspond to box deletion.
const (
	StatusOpen          uint64 = 1
	StatusSettled       uint64 = 2
	StatusRefunded      uint64 = 3
	StatusFrozen        uint64 = 4
	StatusPendingSettle uint64 = 5
)

// Pending-claim side markers on a TicketRecord, mirrored from the contract.
const (
	PendingNone       uint64 = 0
	PendingByOperator uint64 = 1
	PendingByPayer    uint64 = 2
)

// TicketRecord is the Go mirror of the contract's on-chain TicketRecord box.
// All fields are fixed-size ABI types so the serialized layout is exactly
// ticketRecordSize bytes and can be parsed by offset without ARC-4 machinery.
type TicketRecord struct {
	PayerAddr              string // 58-char Algorand address
	OperatorID             uint64
	NodeID                 uint64
	OperatorOwnerAddr      string // operator owner — settlement payout destination
	NodeSigningAddr        string // serving node's signing key — authorizes open/settle and signs ticket/receipt
	MaxPrice               uint64
	OpenedAt               uint64
	ExpiresAt              uint64
	SettlementGraceSeconds uint64
	Status                 uint64
	PendingAmount          uint64
	PendingBy              uint64
	PendingDigest          [32]byte
	// PendingTtftMs / PendingDecodeMs are the operator-measured timing
	// halves recorded by whichever side posted the first half of settle():
	// time-to-first-token and the decode window (ms). On a non-stream /
	// no-first-token settle, PendingTtftMs carries the total service time
	// and PendingDecodeMs is 0. Compared on the second-half ack alongside
	// PendingAmount and PendingDigest; mismatch freezes the ticket.
	// settleLapsed reads these when crediting the operator's latency +
	// throughput metrics after payer silence.
	PendingTtftMs   uint64
	PendingDecodeMs uint64
	// PendingInputCount / PendingOutputCount are the operator-claimed actual
	// counts — same shape as the settle() ABI args. PendingOutputCount is in
	// units of PendingOutputUsageType. Co-signed via the same match-or-freeze
	// primitive as the timing halves.
	PendingInputCount  uint64
	PendingOutputCount uint64
	// PendingOutputUsageType / PendingAuxOutputUsageType / PendingAuxOutputCount
	// carry the modality routing co-signed at settle: the primary output's
	// UsageType, plus an optional AUX output slot (Images alongside chat tokens
	// on a tool turn; None=0 otherwise) with its count. Stored on-box as two
	// 1-byte arc4.Uint8 discriminators + a uint64 count; parsed back into uint64
	// here. settleLapsed reads these to route outputUnits / gate the speed
	// EWMAs when the payer never acks.
	PendingOutputUsageType    uint64
	PendingAuxOutputUsageType uint64
	PendingAuxOutputCount     uint64

	// FeeBps / DiscountBps are the protocol-fee rate snapshotted onto the
	// ticket at open() and FIXED for its life: FeeBps from the contract's
	// protocolFeeBps global, DiscountBps from getHayDiscount(payer). The
	// contract reads these at settle instead of live state, so the payer's
	// exact debit is a pure function of amountCharged and this fixed rate —
	// netFee = floor(floor(amountCharged·FeeBps/1e4)·(1e4−DiscountBps)/1e4) —
	// knowable with no settle-time chain read. The node reads them via
	// ReadTicketBox to surface the authoritative fee/refund breakdown. See
	// proto/SPEC.md §3a "Open-time fee snapshot".
	FeeBps      uint64
	DiscountBps uint64

	// ReservedSlots mirrors `reservedSlots: arc4.StaticBytes<32>` on the
	// contract-side TicketRecord (ZeroSignalEscrow.algo.ts), zero-initialized
	// at open() time. Slack for future small fields without a fresh
	// deploy: promote bytes here in lockstep with a rename of the contract
	// field (carve typed field(s) out of the head, leave a shorter
	// residual blob). The on-wire length is unchanged as long as the carve
	// stays within 32 bytes, so existing ticket boxes keep parsing. This
	// tail only became possible under puya-ts 1.2.0-beta.42 — earlier
	// builds overflowed V8's max-string limit on any added TicketRecord
	// field. See proto/SPEC.md "Reserved slots".
	ReservedSlots [32]byte
}

// ticketRecordSize is the byte length of a serialized TicketRecord in a
// contract box. Fixed-layout, no ARC-4 length prefixes:
//
// Some bounded fields are stored as narrow ARC-4 ints to save box MBR
// (status/pendingBy as 1-byte Uint8, feeBps/discountBps as 2-byte Uint16);
// ARC-4 tuples are byte-packed with no alignment, so the offsets below follow
// the field order with no padding. Parsed back into uint64 Go fields.
//
//	payer                   32
//	operatorId               8
//	nodeId                   8
//	operatorOwner           32
//	nodeSigning             32
//	maxPrice                 8
//	openedAt                 8
//	expiresAt                8
//	settlementGraceSeconds   8
//	status                   1
//	pendingAmount            8
//	pendingBy                1
//	pendingDigest           32
//	pendingTtftMs            8
//	pendingDecodeMs          8
//	pendingInputCount        8
//	pendingOutputCount       8
//	pendingOutputUsageType   1
//	pendingAuxOutputUsageType 1
//	pendingAuxOutputCount    8
//	feeBps                   2
//	discountBps              2
//	reservedSlots           32
const ticketRecordSize = 32 + 8 + 8 + 32 + 32 + 8 + 8 + 8 + 8 + 1 + 8 + 1 + 32 + 8 + 8 + 8 + 8 + 1 + 1 + 8 + 2 + 2 + 32 // 264

func parseTicketRecord(data []byte) (*TicketRecord, error) {
	if len(data) < ticketRecordSize {
		return nil, fmt.Errorf("ticket box too short: %d bytes (want %d)", len(data), ticketRecordSize)
	}

	var payer types.Address
	copy(payer[:], data[0:32])

	operatorID := binary.BigEndian.Uint64(data[32:40])
	nodeID := binary.BigEndian.Uint64(data[40:48])

	var opOwner types.Address
	copy(opOwner[:], data[48:80])

	var nodeSign types.Address
	copy(nodeSign[:], data[80:112])

	maxPrice := binary.BigEndian.Uint64(data[112:120])
	openedAt := binary.BigEndian.Uint64(data[120:128])
	expiresAt := binary.BigEndian.Uint64(data[128:136])
	grace := binary.BigEndian.Uint64(data[136:144])
	status := uint64(data[144]) // arc4.Uint8 — 1 byte
	pendingAmount := binary.BigEndian.Uint64(data[145:153])
	pendingBy := uint64(data[153]) // arc4.Uint8 — 1 byte

	var pendingDigest [32]byte
	copy(pendingDigest[:], data[154:186])

	pendingTtftMs := binary.BigEndian.Uint64(data[186:194])
	pendingDecodeMs := binary.BigEndian.Uint64(data[194:202])
	pendingInputCount := binary.BigEndian.Uint64(data[202:210])
	pendingOutputCount := binary.BigEndian.Uint64(data[210:218])
	pendingOutputUsageType := uint64(data[218])    // arc4.Uint8 — 1 byte
	pendingAuxOutputUsageType := uint64(data[219]) // arc4.Uint8 — 1 byte
	pendingAuxOutputCount := binary.BigEndian.Uint64(data[220:228])
	feeBps := uint64(binary.BigEndian.Uint16(data[228:230]))      // arc4.Uint16 — 2 bytes
	discountBps := uint64(binary.BigEndian.Uint16(data[230:232])) // arc4.Uint16 — 2 bytes

	var reservedSlots [32]byte
	copy(reservedSlots[:], data[232:264])

	return &TicketRecord{
		PayerAddr:                 payer.String(),
		OperatorID:                operatorID,
		NodeID:                    nodeID,
		OperatorOwnerAddr:         opOwner.String(),
		NodeSigningAddr:           nodeSign.String(),
		MaxPrice:                  maxPrice,
		OpenedAt:                  openedAt,
		ExpiresAt:                 expiresAt,
		SettlementGraceSeconds:    grace,
		Status:                    status,
		PendingAmount:             pendingAmount,
		PendingBy:                 pendingBy,
		PendingDigest:             pendingDigest,
		PendingTtftMs:             pendingTtftMs,
		PendingDecodeMs:           pendingDecodeMs,
		PendingInputCount:         pendingInputCount,
		PendingOutputCount:        pendingOutputCount,
		PendingOutputUsageType:    pendingOutputUsageType,
		PendingAuxOutputUsageType: pendingAuxOutputUsageType,
		PendingAuxOutputCount:     pendingAuxOutputCount,
		FeeBps:                    feeBps,
		DiscountBps:               discountBps,
		ReservedSlots:             reservedSlots,
	}, nil
}

// ReadTicketBox fetches and parses the on-chain ticket box for the given
// 16-byte raw ticket id. Returns (nil, nil) when the box is absent — the
// ticket was finalized and deleted.
//
// Callers diagnosing a failed settleLapsed use this to distinguish
// StatusFrozen (payer posted a disagreeing settle or a protest) from a
// clean ack-settle (box deleted, happy path).
func (c *Client) ReadTicketBox(ctx context.Context, ticketIDRaw []byte) (*TicketRecord, error) {
	if len(ticketIDRaw) != 16 {
		return nil, fmt.Errorf("escrow: ticket id must be 16 bytes (got %d)", len(ticketIDRaw))
	}
	box, err := c.Algod.SDKClient().GetApplicationBoxByName(c.AppID, TicketBoxKey(ticketIDRaw)).Do(ctx)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("escrow: fetch ticket box: %w", err)
	}
	return parseTicketRecord(box.Value)
}

// TicketBox is one live ticket: its raw 16-byte id and the parsed record. The
// id lives only in the box name — it is not a field of TicketRecord — so the
// two travel together.
type TicketBox struct {
	IDRaw  []byte
	Record TicketRecord
}

// UnreadableTicket is a `t:` box the fetch could not turn into a TicketRecord:
// a value these bindings can't parse (they disagree with the deployed app), or —
// on the per-box fallback only — a box read that errored.
//
// Reported alongside the good tickets rather than failing the whole fetch,
// because every caller here acts per-ticket and none needs a complete set: the
// operator's sweep clears each box independently, the payer's CLI lists each
// independently. One poisoned box must not hide the rest — that would mean the
// payer refunds nothing and the operator claims nothing, from a box that may not
// even be theirs (the sweep filters by operator only AFTER this fetch). This is
// the opposite of the operator/node bulk fetchers, where a missing record
// silently degrades routing and failing loud is right.
//
// It is a separate field rather than a silent skip so callers can say what they
// dropped. An unreadable box can't be attributed to a payer either — the payer
// address lives inside the value that failed to parse.
type UnreadableTicket struct {
	IDRaw []byte
	Err   error
}

// TicketFetch is the result of FetchAllTickets: the tickets that parsed, and the
// boxes that didn't.
type TicketFetch struct {
	Tickets    []TicketBox
	Unreadable []UnreadableTicket
}

// FetchAllTickets returns every live ticket box under the escrow app, sorted by
// id. A ticket box exists only until its ticket resolves (settle and refund
// both delete it), so this is the protocol's currently-unresolved set, not its
// history. A returned error means the listing itself failed and nothing is
// known; individual boxes that couldn't be read come back in Unreadable.
//
// It prefers a single prefix-filtered, paginated listing that returns names AND
// values (protoalgod.BoxLister — the same path operator/node discovery uses):
// algod filters to `t:` server-side, so operator (`o:`) and node (`n:`) boxes
// never enter the result or eat a page budget, and the values arrive with the
// names, so there is no per-id round trip. Pagination is internal, so there is
// no cap to pass and nothing is silently truncated. The listing is not a
// round-consistent snapshot though (pages aren't pinned to a round), so a ticket
// can finalize mid-fetch; that race is benign here — every caller is asking
// "what is still unresolved", and a box that resolved underneath us is simply
// one they no longer need to act on.
//
// Falls back to a name-only listing plus a ReadTicketBox per id for a client
// without the capability (in-memory test fakes) or an algod too old to return
// values with a listing. That path is O(N) round trips and subject to algod's
// own server-side box cap, which fails the call outright rather than silently
// truncating.
func (c *Client) FetchAllTickets(ctx context.Context) (TicketFetch, error) {
	if bl, ok := c.Algod.(protoalgod.BoxLister); ok {
		out, err := c.fetchAllTicketsBulk(ctx, bl)
		if err == nil {
			return out, nil
		}
		if !errors.Is(err, protoalgod.ErrBoxValuesUnsupported) {
			return TicketFetch{}, err
		}
	}
	return c.fetchAllTicketsPerBox(ctx)
}

// fetchAllTicketsBulk lists every `t:` box (name+value) in one paginated sweep
// and parses each, skipping names that aren't well-formed ticket boxes.
func (c *Client) fetchAllTicketsBulk(ctx context.Context, bl protoalgod.BoxLister) (TicketFetch, error) {
	boxes, err := bl.ListApplicationBoxes(ctx, c.AppID, ticketBoxPrefix)
	if err != nil {
		return TicketFetch{}, err
	}
	out := TicketFetch{Tickets: make([]TicketBox, 0, len(boxes))}
	for i := range boxes {
		id, ok := ticketIDFromBoxName(boxes[i].Name)
		if !ok {
			continue
		}
		rec, err := parseTicketRecord(boxes[i].Value)
		if err != nil {
			out.Unreadable = append(out.Unreadable, UnreadableTicket{IDRaw: id, Err: err})
			continue
		}
		out.Tickets = append(out.Tickets, TicketBox{IDRaw: id, Record: *rec})
	}
	sortTicketBoxes(out.Tickets)
	sortUnreadable(out.Unreadable)
	return out, nil
}

// fetchAllTicketsPerBox is the capability-less fallback: list box names, then
// read each box. Sorted like the bulk path so callers see one order either way.
func (c *Client) fetchAllTicketsPerBox(ctx context.Context) (TicketFetch, error) {
	resp, err := c.Algod.SDKClient().GetApplicationBoxes(c.AppID).Do(ctx)
	if err != nil {
		return TicketFetch{}, fmt.Errorf("escrow: list application boxes for app %d: %w", c.AppID, err)
	}
	out := TicketFetch{Tickets: make([]TicketBox, 0, len(resp.Boxes))}
	for _, b := range resp.Boxes {
		id, ok := ticketIDFromBoxName(b.Name)
		if !ok {
			continue
		}
		rec, err := c.ReadTicketBox(ctx, id)
		if err != nil {
			// Unlike the bulk path's parse failure, this is a per-box network
			// call: one 500 / timeout / rate-limit must not cost the caller
			// every other ticket.
			out.Unreadable = append(out.Unreadable, UnreadableTicket{IDRaw: id, Err: err})
			continue
		}
		if rec == nil {
			// Finalized between the listing and this read. The bulk path has no
			// such window (values come with the names); here it's benign — the
			// ticket is resolved, which is what the caller wants anyway.
			continue
		}
		out.Tickets = append(out.Tickets, TicketBox{IDRaw: id, Record: *rec})
	}
	sortTicketBoxes(out.Tickets)
	sortUnreadable(out.Unreadable)
	return out, nil
}

func sortUnreadable(boxes []UnreadableTicket) {
	sort.Slice(boxes, func(i, j int) bool {
		return bytes.Compare(boxes[i].IDRaw, boxes[j].IDRaw) < 0
	})
}

func sortTicketBoxes(boxes []TicketBox) {
	sort.Slice(boxes, func(i, j int) bool {
		return bytes.Compare(boxes[i].IDRaw, boxes[j].IDRaw) < 0
	})
}
