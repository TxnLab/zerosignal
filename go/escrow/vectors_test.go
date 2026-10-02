/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

// Cross-impl golden vectors for the pure half of this package: box keys, the
// fixed-offset ticket / operator / node record decoders, the revenue-ring
// window, Classify, and the fee / inner-count / op-up math. Generates
// proto/testdata/escrow_vectors.json; proto/ts/test/escrow-vectors.test.ts
// replays it against proto/ts/src/escrow.
//
// The decoders matter most. Both sides parse the contract's boxes by hand-written
// byte offset, so a layout change can break Go and TS identically wrongly — and
// a TS decoder that drifts from Go's mis-reads a box silently rather than
// failing. The record inputs are filled from a non-repeating byte stream rather
// than realistic values, so no two fields decode to the same value: a decoder
// that reads any field from another field's offset gets a different answer.
//
// Regenerate after an intentional change with:
//
//	cd proto/go && go test ./escrow -run TestEscrowVectors -update

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/algorand/go-algorand-sdk/v2/types"
)

var updateEscrowVectors = flag.Bool("update", false, "regenerate proto/testdata/escrow_vectors.json")

const escrowVectorsPath = "../../testdata/escrow_vectors.json"

// u64 renders a uint64 as a decimal string: JSON numbers lose precision above
// 2^53 in JS, and the pattern-filled records hit that range routinely.
func u64(v uint64) string { return strconv.FormatUint(v, 10) }

func u64s(vs []uint64) []string {
	out := make([]string, len(vs))
	for i, v := range vs {
		out[i] = u64(v)
	}
	return out
}

// patternBytes returns n bytes of a SHA-256 counter stream keyed by seed. A
// simple arithmetic fill repeats every 256 bytes, which made fields 32 u64s
// apart decode identically and let a decoder read one from the other's slot.
func patternBytes(n int, seed byte) []byte {
	b := make([]byte, 0, n+sha256.Size)
	for block := uint32(0); len(b) < n; block++ {
		var in [5]byte
		in[0] = seed
		binary.BigEndian.PutUint32(in[1:], block)
		sum := sha256.Sum256(in[:])
		b = append(b, sum[:]...)
	}
	return b[:n]
}

type boxKeyVectors struct {
	Ticket []struct {
		IDHex  string `json:"ticket_id_hex"`
		KeyHex string `json:"key_hex"`
	} `json:"ticket"`
	Operator []struct {
		OperatorID string `json:"operator_id"`
		KeyHex     string `json:"key_hex"`
	} `json:"operator"`
	Node []struct {
		OperatorID string `json:"operator_id"`
		NodeID     string `json:"node_id"`
		KeyHex     string `json:"key_hex"`
		PrefixHex  string `json:"operator_prefix_hex"`
	} `json:"node"`
	FreeQuota []struct {
		Payer  string `json:"payer"`
		KeyHex string `json:"key_hex"`
	} `json:"free_quota"`
	OpenRefs []struct {
		Name        string   `json:"name"`
		OperatorID  string   `json:"operator_id"`
		NodeID      string   `json:"node_id"`
		TicketIDHex string   `json:"ticket_id_hex"`
		Payer       string   `json:"payer"`
		MaxPrice    string   `json:"max_price"`
		KeysHex     []string `json:"keys_hex"`
	} `json:"open_box_references"`
}

type metricsVector struct {
	LastActivityAt            string   `json:"last_activity_at"`
	TicketsOpened             string   `json:"tickets_opened"`
	TicketsSettled            string   `json:"tickets_settled"`
	TicketsLapsedSettled      string   `json:"tickets_lapsed_settled"`
	TicketsRefundedInactive   string   `json:"tickets_refunded_inactive"`
	TotalRefundedInactiveUsdc string   `json:"total_refunded_inactive_usdc"`
	TicketsProtested          string   `json:"tickets_protested"`
	TotalProtestedUsdc        string   `json:"total_protested_usdc"`
	TicketsFrozenDispute      string   `json:"tickets_frozen_dispute"`
	TotalFrozenDisputeUsdc    string   `json:"total_frozen_dispute_usdc"`
	LatencyTotalMs            string   `json:"latency_total_ms"`
	LatencyEwmaMs             string   `json:"latency_ewma_ms"`
	TotalRevenueGross         string   `json:"total_revenue_gross"`
	BucketsLastDay            string   `json:"buckets_last_day"`
	RevenueBuckets            []string `json:"revenue_buckets"`
	TotalInputTokens          string   `json:"total_input_tokens"`
	OutputUnits               []string `json:"output_units"`
	TokensPerSecEwma          string   `json:"tokens_per_sec_ewma"`
}

func metricsOf(m RecordMetrics) metricsVector {
	return metricsVector{
		LastActivityAt:            u64(m.LastActivityAt),
		TicketsOpened:             u64(m.TicketsOpened),
		TicketsSettled:            u64(m.TicketsSettled),
		TicketsLapsedSettled:      u64(m.TicketsLapsedSettled),
		TicketsRefundedInactive:   u64(m.TicketsRefundedInactive),
		TotalRefundedInactiveUsdc: u64(m.TotalRefundedInactiveUsdc),
		TicketsProtested:          u64(m.TicketsProtested),
		TotalProtestedUsdc:        u64(m.TotalProtestedUsdc),
		TicketsFrozenDispute:      u64(m.TicketsFrozenDispute),
		TotalFrozenDisputeUsdc:    u64(m.TotalFrozenDisputeUsdc),
		LatencyTotalMs:            u64(m.LatencyTotalMs),
		LatencyEwmaMs:             u64(m.LatencyEwmaMs),
		TotalRevenueGross:         u64(m.TotalRevenueGross),
		BucketsLastDay:            u64(m.BucketsLastDay),
		RevenueBuckets:            u64s(m.RevenueBuckets[:]),
		TotalInputTokens:          u64(m.TotalInputTokens),
		OutputUnits:               u64s(m.OutputUnits[:]),
		TokensPerSecEwma:          u64(m.TokensPerSecEwma),
	}
}

type ticketRecordVector struct {
	PayerAddr                 string `json:"payer_addr"`
	OperatorID                string `json:"operator_id"`
	NodeID                    string `json:"node_id"`
	OperatorOwnerAddr         string `json:"operator_owner_addr"`
	NodeSigningAddr           string `json:"node_signing_addr"`
	MaxPrice                  string `json:"max_price"`
	OpenedAt                  string `json:"opened_at"`
	ExpiresAt                 string `json:"expires_at"`
	SettlementGraceSeconds    string `json:"settlement_grace_seconds"`
	Status                    string `json:"status"`
	PendingAmount             string `json:"pending_amount"`
	PendingBy                 string `json:"pending_by"`
	PendingDigestHex          string `json:"pending_digest_hex"`
	PendingTtftMs             string `json:"pending_ttft_ms"`
	PendingDecodeMs           string `json:"pending_decode_ms"`
	PendingInputCount         string `json:"pending_input_count"`
	PendingOutputCount        string `json:"pending_output_count"`
	PendingOutputUsageType    string `json:"pending_output_usage_type"`
	PendingAuxOutputUsageType string `json:"pending_aux_output_usage_type"`
	PendingAuxOutputCount     string `json:"pending_aux_output_count"`
	FeeBps                    string `json:"fee_bps"`
	DiscountBps               string `json:"discount_bps"`
	ReservedSlotsHex          string `json:"reserved_slots_hex"`
}

type operatorRecordVector struct {
	ID               string        `json:"id"`
	OwnerAddr        string        `json:"owner_addr"`
	Status           string        `json:"status"`
	NFDAppID         string        `json:"nfd_app_id"`
	NextNodeID       string        `json:"next_node_id"`
	LiveNodeCount    string        `json:"live_node_count"`
	Metrics          metricsVector `json:"metrics"`
	UsdcEscrowed     string        `json:"usdc_escrowed"`
	ReservedSlotsHex string        `json:"reserved_slots_hex"`
	LatencySamples   string        `json:"latency_samples"`
}

type nodeRecordVector struct {
	OperatorID       string        `json:"operator_id"`
	NodeID           string        `json:"node_id"`
	Status           string        `json:"status"`
	SigningAddr      string        `json:"signing_addr"`
	BaseURL          string        `json:"base_url"`
	Metrics          metricsVector `json:"metrics"`
	UsdcEscrowed     string        `json:"usdc_escrowed"`
	Staging          string        `json:"staging"`
	ReservedSlotsHex string        `json:"reserved_slots_hex"`
	LatencySamples   string        `json:"latency_samples"`
}

// recordCase is one decode input. Exactly one of the record fields is set on
// success; Error is true when the decoder must refuse the bytes.
type recordCase struct {
	Name       string                `json:"name"`
	OperatorID string                `json:"operator_id,omitempty"`
	NodeID     string                `json:"node_id,omitempty"`
	DataHex    string                `json:"data_hex"`
	Error      bool                  `json:"error"`
	Ticket     *ticketRecordVector   `json:"ticket,omitempty"`
	Operator   *operatorRecordVector `json:"operator,omitempty"`
	Node       *nodeRecordVector     `json:"node,omitempty"`
}

type recordVectors struct {
	TicketSize   int          `json:"ticket_record_size"`
	OperatorSize int          `json:"operator_record_size"`
	NodeSize     int          `json:"node_record_size"`
	Tickets      []recordCase `json:"tickets"`
	Operators    []recordCase `json:"operators"`
	Nodes        []recordCase `json:"nodes"`
}

type revenueCase struct {
	Name           string   `json:"name"`
	BucketsLastDay string   `json:"buckets_last_day"`
	RevenueBuckets []string `json:"revenue_buckets"`
	CurrentDay     string   `json:"current_day"`
	WindowDays     string   `json:"window_days"`
	Want           string   `json:"want"`
}

type classifyCase struct {
	Name      string `json:"name"`
	Status    string `json:"status"`
	PendingBy string `json:"pending_by"`
	ExpiresAt string `json:"expires_at"`
	Grace     string `json:"settlement_grace_seconds"`
	NowUnixMs string `json:"now_unix_ms"`
	Verdict   string `json:"verdict"`
}

type feeVectors struct {
	NetFee []struct {
		AmountCharged string `json:"amount_charged"`
		FeeBps        string `json:"fee_bps"`
		DiscountBps   string `json:"discount_bps"`
		Want          string `json:"want"`
	} `json:"net_fee"`
	Breakdown []struct {
		AmountCharged string `json:"amount_charged"`
		MaxPrice      string `json:"max_price"`
		FeeBps        string `json:"fee_bps"`
		DiscountBps   string `json:"discount_bps"`
		NetFee        string `json:"net_fee"`
		Refund        string `json:"refund"`
		TotalDebit    string `json:"total_debit"`
	} `json:"fee_breakdown"`
	SettleInnerCount []struct {
		AmountCharged string `json:"amount_charged"`
		MaxPrice      string `json:"max_price"`
		Want          string `json:"want"`
	} `json:"settle_inner_count"`
	RingGap []struct {
		LastDay    string `json:"last_day"`
		CurrentDay string `json:"current_day"`
		Exact      string `json:"ring_gap_iters"`
		Bounded    string `json:"bounded_ring_gap_iters"`
	} `json:"ring_gap"`
	GapOpUps []struct {
		Iters string `json:"iters"`
		Want  string `json:"want"`
	} `json:"gap_op_ups_for_iters"`
}

type escrowVectorsFile struct {
	Version  int            `json:"version"`
	Comment  string         `json:"comment"`
	BoxKeys  boxKeyVectors  `json:"box_keys"`
	Records  recordVectors  `json:"records"`
	Revenue  []revenueCase  `json:"revenue_windows"`
	Classify []classifyCase `json:"classify"`
	Fees     feeVectors     `json:"fees"`
}

func vectorAddr(seed byte) types.Address {
	var a types.Address
	copy(a[:], patternBytes(32, seed))
	return a
}

func buildBoxKeyVectors() boxKeyVectors {
	var v boxKeyVectors
	for _, id := range [][]byte{bytes.Repeat([]byte{0}, 16), patternBytes(16, 0x11)} {
		v.Ticket = append(v.Ticket, struct {
			IDHex  string `json:"ticket_id_hex"`
			KeyHex string `json:"key_hex"`
		}{hex.EncodeToString(id), hex.EncodeToString(TicketBoxKey(id))})
	}
	for _, id := range []uint64{0, 1, 258, 1<<53 + 1, ^uint64(0)} {
		v.Operator = append(v.Operator, struct {
			OperatorID string `json:"operator_id"`
			KeyHex     string `json:"key_hex"`
		}{u64(id), hex.EncodeToString(OperatorBoxKey(id))})
	}
	for _, p := range [][2]uint64{{1, 1}, {7, 300}, {^uint64(0), 1<<53 + 3}} {
		v.Node = append(v.Node, struct {
			OperatorID string `json:"operator_id"`
			NodeID     string `json:"node_id"`
			KeyHex     string `json:"key_hex"`
			PrefixHex  string `json:"operator_prefix_hex"`
		}{u64(p[0]), u64(p[1]), hex.EncodeToString(NodeBoxKey(p[0], p[1])), hex.EncodeToString(NodeBoxPrefixForOperator(p[0]))})
	}
	for _, seed := range []byte{0x01, 0x80} {
		a := vectorAddr(seed)
		v.FreeQuota = append(v.FreeQuota, struct {
			Payer  string `json:"payer"`
			KeyHex string `json:"key_hex"`
		}{a.String(), hex.EncodeToString(FreeQuotaBoxKey(a))})
	}
	payer := vectorAddr(0x42)
	ticketID := patternBytes(16, 0x33)
	for _, c := range []struct {
		name     string
		maxPrice uint64
	}{{"paid_open_omits_quota_box", 1_500_000}, {"free_open_references_quota_box", 0}} {
		refs := OpenBoxReferences(12, 3, ticketID, payer, c.maxPrice)
		keys := make([]string, len(refs))
		for i, r := range refs {
			keys[i] = hex.EncodeToString(r.Name)
		}
		v.OpenRefs = append(v.OpenRefs, struct {
			Name        string   `json:"name"`
			OperatorID  string   `json:"operator_id"`
			NodeID      string   `json:"node_id"`
			TicketIDHex string   `json:"ticket_id_hex"`
			Payer       string   `json:"payer"`
			MaxPrice    string   `json:"max_price"`
			KeysHex     []string `json:"keys_hex"`
		}{c.name, "12", "3", hex.EncodeToString(ticketID), payer.String(), u64(c.maxPrice), keys})
	}
	return v
}

func ticketVector(r *TicketRecord) *ticketRecordVector {
	return &ticketRecordVector{
		PayerAddr: r.PayerAddr, OperatorID: u64(r.OperatorID), NodeID: u64(r.NodeID),
		OperatorOwnerAddr: r.OperatorOwnerAddr, NodeSigningAddr: r.NodeSigningAddr,
		MaxPrice: u64(r.MaxPrice), OpenedAt: u64(r.OpenedAt), ExpiresAt: u64(r.ExpiresAt),
		SettlementGraceSeconds: u64(r.SettlementGraceSeconds), Status: u64(r.Status),
		PendingAmount: u64(r.PendingAmount), PendingBy: u64(r.PendingBy),
		PendingDigestHex: hex.EncodeToString(r.PendingDigest[:]),
		PendingTtftMs:    u64(r.PendingTtftMs), PendingDecodeMs: u64(r.PendingDecodeMs),
		PendingInputCount: u64(r.PendingInputCount), PendingOutputCount: u64(r.PendingOutputCount),
		PendingOutputUsageType:    u64(r.PendingOutputUsageType),
		PendingAuxOutputUsageType: u64(r.PendingAuxOutputUsageType),
		PendingAuxOutputCount:     u64(r.PendingAuxOutputCount),
		FeeBps:                    u64(r.FeeBps), DiscountBps: u64(r.DiscountBps),
		ReservedSlotsHex: hex.EncodeToString(r.ReservedSlots[:]),
	}
}

func buildRecordVectors(t *testing.T) recordVectors {
	t.Helper()
	v := recordVectors{TicketSize: ticketRecordSize, OperatorSize: operatorRecordSize, NodeSize: nodeRecordSize}

	ticketInputs := []struct {
		name string
		data []byte
	}{
		{"pattern_exact_size", patternBytes(ticketRecordSize, 0x05)},
		{"pattern_trailing_bytes_ignored", patternBytes(ticketRecordSize+6, 0x9b)},
		{"one_byte_short", patternBytes(ticketRecordSize-1, 0x05)},
	}
	for _, in := range ticketInputs {
		c := recordCase{Name: in.name, DataHex: hex.EncodeToString(in.data)}
		if r, err := parseTicketRecord(in.data); err != nil {
			c.Error = true
		} else {
			c.Ticket = ticketVector(r)
		}
		v.Tickets = append(v.Tickets, c)
	}

	opInputs := []struct {
		name string
		id   uint64
		data []byte
	}{
		{"pattern_exact_size", 9, patternBytes(operatorRecordSize, 0x07)},
		{"pattern_trailing_bytes_ignored", 1<<53 + 5, patternBytes(operatorRecordSize+3, 0xc4)},
		{"one_byte_short", 9, patternBytes(operatorRecordSize-1, 0x07)},
	}
	for _, in := range opInputs {
		c := recordCase{Name: in.name, OperatorID: u64(in.id), DataHex: hex.EncodeToString(in.data)}
		if r, err := parseOperatorRecord(in.id, in.data); err != nil {
			c.Error = true
		} else {
			c.Operator = &operatorRecordVector{
				ID: u64(r.ID), OwnerAddr: r.OwnerAddr, Status: u64(r.Status), NFDAppID: u64(r.NFDAppID),
				NextNodeID: u64(r.NextNodeID), LiveNodeCount: u64(r.LiveNodeCount),
				Metrics: metricsOf(r.RecordMetrics), UsdcEscrowed: u64(r.UsdcEscrowed),
				ReservedSlotsHex: hex.EncodeToString(r.ReservedSlots[:]), LatencySamples: u64(r.LatencySamples),
			}
		}
		v.Operators = append(v.Operators, c)
	}

	// Node boxes carry a length-prefixed, zero-padded base URL, so the pattern
	// fill is overwritten there with a real URL to exercise the length byte and
	// the trailing-NUL trim.
	withURL := func(seed byte, url string, declaredLen int, extra int) []byte {
		b := patternBytes(nodeRecordSize+extra, seed)
		b[33] = byte(declaredLen)
		for i := 34; i < 34+BaseURLMax; i++ {
			b[i] = 0
		}
		copy(b[34:], url)
		return b
	}
	const bomURL = "\xef\xbb\xbfhttps://bom.example"
	nodeInputs := []struct {
		name         string
		opID, nodeID uint64
		data         []byte
	}{
		{"pattern_with_url", 4, 2, withURL(0x0d, "https://node.example.com:9090", len("https://node.example.com:9090"), 0)},
		{"declared_length_covers_trailing_nuls", 4, 3, withURL(0x2e, "https://n.example", len("https://n.example")+4, 5)},
		{"url_at_max_length", 1<<53 + 1, 9, withURL(0x61, string(bytes.Repeat([]byte("a"), BaseURLMax)), BaseURLMax, 0)},
		// The contract never clears the slack after the declared length when a
		// shorter URL replaces a longer one, so a decoder must stop at the length
		// byte rather than at the first NUL.
		{"bytes_past_declared_length_ignored", 4, 5, func() []byte {
			b := withURL(0x3a, "https://short.example", len("https://short.example"), 0)
			copy(b[34+len("https://short.example"):34+BaseURLMax], patternBytes(BaseURLMax, 0x3b))
			return b
		}()},
		// A leading U+FEFF is part of the stored URL; a UTF-8 decoder that strips
		// a BOM by default would hand back a different string than Go does.
		{"leading_bom_preserved", 4, 6, withURL(0x4c, bomURL, len(bomURL), 0)},
		{"declared_length_over_max", 4, 2, withURL(0x0d, "https://x", BaseURLMax+1, 0)},
		{"one_byte_short", 4, 2, withURL(0x0d, "https://x", 9, 0)[:nodeRecordSize-1]},
	}
	for _, in := range nodeInputs {
		c := recordCase{Name: in.name, OperatorID: u64(in.opID), NodeID: u64(in.nodeID), DataHex: hex.EncodeToString(in.data)}
		if r, err := parseNodeRecord(in.opID, in.nodeID, in.data); err != nil {
			c.Error = true
		} else {
			c.Node = &nodeRecordVector{
				OperatorID: u64(r.OperatorID), NodeID: u64(r.NodeID), Status: u64(r.Status),
				SigningAddr: r.SigningAddr, BaseURL: r.BaseURL, Metrics: metricsOf(r.RecordMetrics),
				UsdcEscrowed: u64(r.UsdcEscrowed), Staging: u64(r.Staging),
				ReservedSlotsHex: hex.EncodeToString(r.ReservedSlots[:]), LatencySamples: u64(r.LatencySamples),
			}
		}
		v.Nodes = append(v.Nodes, c)
	}

	for _, set := range [][]recordCase{v.Tickets, v.Operators, v.Nodes} {
		var ok, bad int
		for _, c := range set {
			if c.Error {
				bad++
			} else {
				ok++
			}
		}
		if ok == 0 || bad == 0 {
			t.Fatalf("every record kind needs both decoded and refused cases (ok=%d refused=%d)", ok, bad)
		}
	}
	return v
}

func buildRevenueVectors() []revenueCase {
	var buckets [RevenueBucketCount]uint64
	for i := range buckets {
		buckets[i] = uint64(1000 + i*7)
	}
	const last = 20_000 // a day index; slot = day % 30
	// 20_011 sits on slot 1, so a 7-day window ending there walks back across
	// the slot-0 / slot-29 seam.
	const lastNearWrap = 20_011
	cases := []struct {
		name               string
		lastDay, day, days uint64
	}{
		{"window_crosses_ring_wrap", lastNearWrap, lastNearWrap, 7},
		{"window_crosses_ring_wrap_after_gap", lastNearWrap, lastNearWrap + 2, 7},
		{"same_day_24h", last, last, 1},
		{"same_day_7d", last, last, 7},
		{"same_day_30d", last, last, 30},
		{"three_days_later_7d", last, last + 3, 7},
		{"window_entirely_after_last_write", last, last + 40, 7},
		{"clock_behind_last_write", last, last - 1, 7},
		{"never_written", 0, last, 30},
		{"window_zero", last, last, 0},
		{"window_over_ring", last, last, 31},
		{"early_epoch_current_day_below_window", 3, 4, 30},
	}
	out := make([]revenueCase, 0, len(cases))
	for _, c := range cases {
		b := buckets
		out = append(out, revenueCase{
			Name: c.name, BucketsLastDay: u64(c.lastDay), RevenueBuckets: u64s(b[:]),
			CurrentDay: u64(c.day), WindowDays: u64(c.days),
			Want: u64(windowedRingRevenue(c.lastDay, &b, c.day, c.days)),
		})
	}
	return out
}

func buildClassifyVectors() []classifyCase {
	const expires, grace = 1_800_000_000, 600
	deadlineMs := int64(expires+grace) * 1000
	type sc struct {
		name              string
		status, pendingBy uint64
	}
	states := []sc{
		{"open", StatusOpen, PendingNone},
		{"pending_by_payer", StatusPendingSettle, PendingByPayer},
		{"pending_by_operator", StatusPendingSettle, PendingByOperator},
		{"pending_no_side", StatusPendingSettle, PendingNone},
		{"frozen", StatusFrozen, PendingNone},
		{"frozen_with_operator_claim", StatusFrozen, PendingByOperator},
		{"settled_never_written", StatusSettled, PendingNone},
		{"refunded_never_written", StatusRefunded, PendingNone},
		{"future_status", 9, PendingByPayer},
	}
	clocks := []struct {
		name string
		ms   int64
	}{
		{"before_deadline", deadlineMs - 60_000},
		{"at_deadline", deadlineMs},
		{"one_ms_after_deadline", deadlineMs + 1},
		{"long_after_deadline", deadlineMs + 86_400_000},
	}
	var out []classifyCase
	for _, s := range states {
		for _, c := range clocks {
			rec := &TicketRecord{Status: s.status, PendingBy: s.pendingBy, ExpiresAt: expires, SettlementGraceSeconds: grace}
			out = append(out, classifyCase{
				Name: s.name + "/" + c.name, Status: u64(s.status), PendingBy: u64(s.pendingBy),
				ExpiresAt: u64(expires), Grace: u64(grace), NowUnixMs: strconv.FormatInt(c.ms, 10),
				Verdict: Classify(rec, time.UnixMilli(c.ms)).String(),
			})
		}
	}
	return out
}

func buildFeeVectors() feeVectors {
	var v feeVectors
	for _, c := range [][3]uint64{
		{0, 500, 0}, {1, 500, 0}, {19, 500, 0}, {20, 500, 0}, {1_234_567, 500, 0},
		{1_234_567, 2000, 0}, {1_234_567, 500, 2500}, {1_234_567, 500, 8000},
		{1_234_567, 500, 10_000}, {1_234_567, 500, 12_000}, {999_999_999_999, 2000, 0},
	} {
		v.NetFee = append(v.NetFee, struct {
			AmountCharged string `json:"amount_charged"`
			FeeBps        string `json:"fee_bps"`
			DiscountBps   string `json:"discount_bps"`
			Want          string `json:"want"`
		}{u64(c[0]), u64(c[1]), u64(c[2]), u64(NetFee(c[0], c[1], c[2]))})
	}
	for _, c := range [][4]uint64{
		{0, 0, 500, 0}, {0, 2_000_000, 500, 0}, {1_000_000, 2_000_000, 500, 0},
		{1_000_000, 1_050_000, 500, 0}, {1_000_000, 1_000_000, 500, 0}, {1_000_000, 1_020_000, 2000, 0},
	} {
		b := ComputeFeeBreakdown(c[0], c[1], c[2], c[3])
		v.Breakdown = append(v.Breakdown, struct {
			AmountCharged string `json:"amount_charged"`
			MaxPrice      string `json:"max_price"`
			FeeBps        string `json:"fee_bps"`
			DiscountBps   string `json:"discount_bps"`
			NetFee        string `json:"net_fee"`
			Refund        string `json:"refund"`
			TotalDebit    string `json:"total_debit"`
		}{u64(c[0]), u64(c[1]), u64(c[2]), u64(c[3]), u64(b.NetFee), u64(b.Refund), u64(b.TotalDebit)})
	}
	for _, c := range [][2]uint64{{0, 0}, {0, 5}, {5, 5}, {5, 9}, {9, 5}} {
		v.SettleInnerCount = append(v.SettleInnerCount, struct {
			AmountCharged string `json:"amount_charged"`
			MaxPrice      string `json:"max_price"`
			Want          string `json:"want"`
		}{u64(c[0]), u64(c[1]), u64(SettleInnerCount(c[0], c[1]))})
	}
	for _, c := range [][2]uint64{{0, 100}, {100, 100}, {100, 99}, {100, 101}, {100, 102}, {100, 129}, {100, 130}, {100, 131}, {100, 500}} {
		v.RingGap = append(v.RingGap, struct {
			LastDay    string `json:"last_day"`
			CurrentDay string `json:"current_day"`
			Exact      string `json:"ring_gap_iters"`
			Bounded    string `json:"bounded_ring_gap_iters"`
		}{u64(c[0]), u64(c[1]), u64(ringGapIters(c[0], c[1])), u64(BoundedRingGapIters(c[0], c[1]))})
	}
	for _, it := range []uint64{0, 1, 17, 18, 35, 36, 58} {
		v.GapOpUps = append(v.GapOpUps, struct {
			Iters string `json:"iters"`
			Want  string `json:"want"`
		}{u64(it), u64(GapOpUpsForIters(it))})
	}
	return v
}

func buildEscrowVectors(t *testing.T) escrowVectorsFile {
	return escrowVectorsFile{
		Version: 1,
		Comment: "Cross-impl golden vectors for proto/go/escrow's pure half: box keys, fixed-offset record " +
			"decoders, revenue windows, Classify, fee math. uint64 values are decimal strings. Generated by " +
			"proto/go/escrow/vectors_test.go; regenerate with `cd proto/go && go test ./escrow -run TestEscrowVectors -update`.",
		BoxKeys:  buildBoxKeyVectors(),
		Records:  buildRecordVectors(t),
		Revenue:  buildRevenueVectors(),
		Classify: buildClassifyVectors(),
		Fees:     buildFeeVectors(),
	}
}

func TestEscrowVectors(t *testing.T) {
	got, err := json.MarshalIndent(buildEscrowVectors(t), "", "  ")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got = append(got, '\n')
	if *updateEscrowVectors {
		if err := os.WriteFile(escrowVectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", escrowVectorsPath, err)
		}
		t.Logf("wrote %s", escrowVectorsPath)
		return
	}
	want, err := os.ReadFile(escrowVectorsPath)
	if err != nil {
		t.Fatalf("read %s (regenerate with -update): %v", escrowVectorsPath, err)
	}
	if !bytes.Equal(want, got) {
		t.Fatalf("%s is stale: escrow output changed. If intentional, run "+
			"`cd proto/go && go test ./escrow -run TestEscrowVectors -update` "+
			"and port the same change to proto/ts/src/escrow.", escrowVectorsPath)
	}
}
