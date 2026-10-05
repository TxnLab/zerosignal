/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/banding_vectors.json: the responsiveness
// banding a dispatch applies to a price-ordered candidate list, which the TS SDK
// mirrors in sdk/src/routing/banding.ts. Each case is a candidate list and a
// sort mode in, the final order and each candidate's band out.
//
// Scores are emitted rounded to 1e-6 and compared with a tolerance on the TS
// side: Go may fuse a multiply-add into one FMA on some architectures, so the
// last bit of a score can differ from JS. Order, bands and flags are exact; the
// inputs keep every score off a band's .5 boundary so that bit can't move one.
//
//	cd proto/go && go test ./zs -run TestBandingVectors -update

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
)

const bandingVectorsPath = "../../testdata/banding_vectors.json"

type bandingVectorFile struct {
	Comment   string               `json:"comment"`
	Constants bandingVectorConsts  `json:"constants"`
	Medians   []bandingMedianCase  `json:"confidence_weighted_median"`
	Cases     []bandingVectorCase  `json:"cases"`
	Catalogs  []bandingCatalogCase `json:"catalog_confidence"`
}

type bandingVectorConsts struct {
	BandMS            float64 `json:"target_responsiveness_band_ms"`
	MaxBandsFromMed   float64 `json:"max_bands_from_median"`
	DecodeNormTokens  float64 `json:"decode_norm_tokens"`
	LatencyMinSamples int     `json:"latency_min_samples"`
}

type bandingMedianCase struct {
	Values  []float64 `json:"values"`
	Weights []float64 `json:"weights"`
	Want    float64   `json:"want"`
}

type bandingCatalogCase struct {
	// Catalog lists each served model's output modalities; a null entry is a
	// model that declared none.
	Catalog [][]string `json:"catalog"`
	Want    float64    `json:"want"`
}

type bandingCandidate struct {
	// RTTMs and RTTSamples are the payer's own observed round trip to the
	// target; absent RTTMs means no fresh sample.
	RTTMs            *float64   `json:"rtt_ms,omitempty"`
	RTTSamples       int        `json:"rtt_samples,omitempty"`
	TTFTEwmaMs       uint64     `json:"ttft_ewma_ms"`
	TokensPerSecEwma uint64     `json:"tokens_per_sec_ewma"`
	Catalog          [][]string `json:"catalog"`
	Pinned           bool       `json:"pinned"`
}

type bandingDetail struct {
	Index     int     `json:"index"`
	Signal    bool    `json:"signal"`
	Pinned    bool    `json:"pinned"`
	RTTEff    float64 `json:"rtt_eff"`
	TTFTEff   float64 `json:"ttft_eff"`
	DecodeEff float64 `json:"decode_eff"`
	Score     float64 `json:"score"`
	Band      float64 `json:"band"`
}

type bandingVectorCase struct {
	Name       string             `json:"name"`
	Mode       string             `json:"mode"`
	Candidates []bandingCandidate `json:"candidates"`
	// Order is the input indices in final order.
	Order []int `json:"order"`
	// Details is null when no banding ran: price mode, fewer than two
	// candidates, or nobody with any signal.
	Details []bandingDetail `json:"details"`
}

// bandingLatency is a RelayLatency holding only the target aggregates banding reads.
type bandingLatency map[NodeRef]struct {
	ms float64
	n  int
}

func (bandingLatency) RecordRelayedRTT(NodeRef, NodeRef, time.Duration)       {}
func (bandingLatency) RecordDirectRTT(NodeRef, time.Duration)                 {}
func (bandingLatency) RelayLatencyForTarget(NodeRef, NodeRef) (float64, bool) { return 0, false }
func (l bandingLatency) TargetLatency(t NodeRef) (float64, int, bool) {
	s, ok := l[t]
	return s.ms, s.n, ok
}

func bandingOperator(i int, c bandingCandidate) Operator {
	caps := make(map[string]ModelCapacity, len(c.Catalog))
	for j, mods := range c.Catalog {
		caps[fmt.Sprintf("m%d", j)] = ModelCapacity{OutputModalities: mods}
	}
	op := Operator{ID: uint64(i + 1), NodeID: 0, ModelCapacities: caps}
	op.Metrics.LatencyEwmaMs = c.TTFTEwmaMs
	op.Metrics.TokensPerSecEwma = c.TokensPerSecEwma
	return op
}

func round6(x float64) float64 { return math.Round(x*1e6) / 1e6 }

func runBandingCase(c bandingVectorCase) bandingVectorCase {
	ops := make([]Operator, len(c.Candidates))
	lat := bandingLatency{}
	var preferred *Operator
	for i, cand := range c.Candidates {
		ops[i] = bandingOperator(i, cand)
		if cand.RTTMs != nil {
			lat[RefOf(ops[i])] = struct {
				ms float64
				n  int
			}{*cand.RTTMs, cand.RTTSamples}
		}
		if cand.Pinned {
			preferred = &ops[i]
		}
	}
	out, details := bandByResponsiveness(ops, preferred, lat, c.Mode)
	c.Order = make([]int, len(out))
	for k, op := range out {
		c.Order[k] = int(op.ID) - 1
	}
	c.Details = nil
	for k, d := range details {
		c.Details = append(c.Details, bandingDetail{
			Index:     c.Order[k],
			Signal:    d.signal,
			Pinned:    d.pinned,
			RTTEff:    round6(d.rttEff),
			TTFTEff:   round6(d.ttftEff),
			DecodeEff: round6(d.decodeEff),
			Score:     round6(d.score),
			Band:      d.band,
		})
	}
	return c
}

func ms(v float64) *float64 { return &v }

var (
	textOnly  = []string{"text"}
	imageOnly = []string{"image"}
)

// catalogOf is n text models.
func catalogOf(n int) [][]string {
	out := make([][]string, n)
	for i := range out {
		out[i] = textOnly
	}
	return out
}

func bandingInputs() []bandingVectorCase {
	one := catalogOf(1)
	return []bandingVectorCase{
		{Name: "empty list", Mode: "", Candidates: []bandingCandidate{}},
		{Name: "one candidate is a no-op", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 9000, Catalog: one},
		}},
		{Name: "price mode keeps price order", Mode: selection.SortPrice, Candidates: []bandingCandidate{
			{TTFTEwmaMs: 9000, Catalog: one},
			{TTFTEwmaMs: 100, Catalog: one},
		}},
		{Name: "nobody has signal: price order", Mode: "", Candidates: []bandingCandidate{
			{Catalog: one}, {Catalog: one}, {Catalog: one},
		}},
		{Name: "a much faster node passes a cheaper slow one", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 2600, TokensPerSecEwma: 20, Catalog: one},
			{TTFTEwmaMs: 300, TokensPerSecEwma: 90, Catalog: one},
		}},
		{Name: "small differences keep price order", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 420, TokensPerSecEwma: 60, Catalog: one},
			{TTFTEwmaMs: 380, TokensPerSecEwma: 64, Catalog: one},
			{TTFTEwmaMs: 410, TokensPerSecEwma: 58, Catalog: one},
		}},
		{Name: "bands clamp one either side of the median", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 9100, Catalog: one},
			{TTFTEwmaMs: 1100, Catalog: one},
			{TTFTEwmaMs: 2100, Catalog: one},
			{TTFTEwmaMs: 140, Catalog: one},
			{TTFTEwmaMs: 5100, Catalog: one},
		}},
		{Name: "a node with no signal sits in the median band", Mode: "", Candidates: []bandingCandidate{
			{Catalog: one},
			{TTFTEwmaMs: 3100, Catalog: one},
			{TTFTEwmaMs: 1100, Catalog: one},
			{TTFTEwmaMs: 2100, Catalog: one},
		}},
		{Name: "the pinned node stays first however slow", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 9100, Catalog: one, Pinned: true},
			{TTFTEwmaMs: 140, Catalog: one},
			{TTFTEwmaMs: 1100, Catalog: one},
		}},
		{Name: "the pinned node first even when not first in price order", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 140, Catalog: one},
			{TTFTEwmaMs: 1100, Catalog: one},
			{TTFTEwmaMs: 9100, Catalog: one, Pinned: true},
		}},
		{Name: "a broad catalog's speed is discounted toward the median", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 2100, TokensPerSecEwma: 30, Catalog: one},
			{TTFTEwmaMs: 150, TokensPerSecEwma: 200, Catalog: catalogOf(16)},
			{TTFTEwmaMs: 160, TokensPerSecEwma: 190, Catalog: catalogOf(25)},
			{TTFTEwmaMs: 170, TokensPerSecEwma: 180, Catalog: catalogOf(9)},
		}},
		{Name: "image-only models don't dilute", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 2100, Catalog: one},
			{TTFTEwmaMs: 140, Catalog: append(catalogOf(1), imageOnly, imageOnly, imageOnly, imageOnly, imageOnly, imageOnly, imageOnly, imageOnly)},
			{TTFTEwmaMs: 1100, Catalog: one},
		}},
		{Name: "an all-image catalog has no chain signal", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 1100, Catalog: one},
			{TTFTEwmaMs: 140, TokensPerSecEwma: 400, Catalog: [][]string{imageOnly, imageOnly}},
			{TTFTEwmaMs: 2100, Catalog: one},
		}},
		{Name: "an unprobed catalog has no chain signal", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 1100, Catalog: one},
			{TTFTEwmaMs: 140, Catalog: nil},
			{TTFTEwmaMs: 2100, Catalog: one},
		}},
		{Name: "RTT needs the minimum samples", Mode: "", Candidates: []bandingCandidate{
			{RTTMs: ms(1900), RTTSamples: 1, Catalog: one},
			{RTTMs: ms(80), RTTSamples: 1, Catalog: one},
			{RTTMs: ms(120), RTTSamples: LatencyMinSamples, Catalog: one},
		}},
		{Name: "RTT alone bands when trusted", Mode: "", Candidates: []bandingCandidate{
			{RTTMs: ms(1900), RTTSamples: 5, Catalog: one},
			{RTTMs: ms(80), RTTSamples: 5, Catalog: one},
			{RTTMs: ms(860), RTTSamples: 3, Catalog: one},
		}},
		{Name: "RTT confidence ignores catalog breadth", Mode: "", Candidates: []bandingCandidate{
			{RTTMs: ms(1400), RTTSamples: 5, Catalog: catalogOf(16)},
			{RTTMs: ms(80), RTTSamples: 5, Catalog: one},
			{RTTMs: ms(860), RTTSamples: 5, Catalog: one},
		}},
		{Name: "a node with no signal sits in the median band across terms", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 100, TokensPerSecEwma: 16, Catalog: one},
			{TTFTEwmaMs: 2000, TokensPerSecEwma: 320, Catalog: one},
			{TTFTEwmaMs: 3000, TokensPerSecEwma: 8, Catalog: one},
			{Catalog: one},
		}},
		{Name: "a zero-confidence term stays out of the median", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 100, Catalog: one},
			{TTFTEwmaMs: 900, Catalog: nil},
			{TTFTEwmaMs: 3100, Catalog: one},
		}},
		{Name: "latency mode ignores throughput", Mode: selection.SortLatency, Candidates: []bandingCandidate{
			{TTFTEwmaMs: 300, TokensPerSecEwma: 5, Catalog: one},
			{TTFTEwmaMs: 1900, TokensPerSecEwma: 400, Catalog: one},
			{RTTMs: ms(1300), RTTSamples: 4, TTFTEwmaMs: 200, TokensPerSecEwma: 400, Catalog: one},
		}},
		{Name: "throughput mode ignores RTT and TTFT", Mode: selection.SortThroughput, Candidates: []bandingCandidate{
			{RTTMs: ms(40), RTTSamples: 9, TTFTEwmaMs: 90, TokensPerSecEwma: 9, Catalog: one},
			{RTTMs: ms(1900), RTTSamples: 9, TTFTEwmaMs: 4100, TokensPerSecEwma: 300, Catalog: one},
			{TTFTEwmaMs: 150, TokensPerSecEwma: 40, Catalog: one},
		}},
		{Name: "throughput mode with no decode signal: price order", Mode: selection.SortThroughput, Candidates: []bandingCandidate{
			{RTTMs: ms(40), RTTSamples: 9, TTFTEwmaMs: 90, Catalog: one},
			{TTFTEwmaMs: 4100, Catalog: one},
		}},
		{Name: "equal bands keep price order", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 1100, Catalog: one},
			{TTFTEwmaMs: 1050, Catalog: one},
			{TTFTEwmaMs: 1150, Catalog: one},
			{TTFTEwmaMs: 1000, Catalog: one},
		}},
		{Name: "undeclared modalities count toward breadth", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 2100, Catalog: one},
			{TTFTEwmaMs: 140, Catalog: [][]string{nil, nil, nil, nil}},
			{TTFTEwmaMs: 1100, Catalog: one},
		}},
		{Name: "a modality matches case-insensitively", Mode: "", Candidates: []bandingCandidate{
			{TTFTEwmaMs: 2100, Catalog: one},
			{TTFTEwmaMs: 140, Catalog: [][]string{{"image", "TEXT"}, {"Text"}, imageOnly, imageOnly}},
			{TTFTEwmaMs: 1100, Catalog: one},
		}},
	}
}

func bandingMedianInputs() []bandingMedianCase {
	return []bandingMedianCase{
		{Values: nil, Weights: nil},
		{Values: []float64{5}, Weights: []float64{0.3}},
		{Values: []float64{3, 1, 2}, Weights: []float64{1, 1, 1}},
		{Values: []float64{4, 1, 3, 2}, Weights: []float64{1, 1, 1, 1}},
		{Values: []float64{100, 200}, Weights: []float64{0, 0}},
		{Values: []float64{2000, 150, 160, 170}, Weights: []float64{1, 0.25, 0.2, 1 / math.Sqrt(9)}},
		{Values: []float64{10, 10, 30}, Weights: []float64{0.5, 0.25, 1}},
		{Values: []float64{1, 9}, Weights: []float64{3, 1}},
		{Values: []float64{1, 9}, Weights: []float64{1, 3}},
	}
}

func bandingCatalogInputs() []bandingCatalogCase {
	return []bandingCatalogCase{
		{Catalog: nil},
		{Catalog: catalogOf(1)},
		{Catalog: catalogOf(4)},
		{Catalog: catalogOf(16)},
		{Catalog: catalogOf(3)},
		{Catalog: [][]string{imageOnly}},
		{Catalog: [][]string{nil}},
		{Catalog: [][]string{{}, textOnly}},
		{Catalog: [][]string{{"TeXt"}, imageOnly, {"audio"}}},
	}
}

func TestBandingVectors(t *testing.T) {
	f := bandingVectorFile{
		Comment: "Generated by proto/go/zs TestBandingVectors. Scores are rounded to 1e-6; compare them with a tolerance, everything else exactly.",
		Constants: bandingVectorConsts{
			BandMS:            targetResponsivenessBandMS,
			MaxBandsFromMed:   maxBandsFromMedian,
			DecodeNormTokens:  decodeNormTokens,
			LatencyMinSamples: LatencyMinSamples,
		},
	}
	for _, c := range bandingMedianInputs() {
		c.Want = round6(confidenceWeightedMedian(c.Values, c.Weights))
		f.Medians = append(f.Medians, c)
	}
	for _, c := range bandingCatalogInputs() {
		op := bandingOperator(0, bandingCandidate{Catalog: c.Catalog})
		c.Want = round6(catalogConfidence(op))
		f.Catalogs = append(f.Catalogs, c)
	}
	for _, c := range bandingInputs() {
		f.Cases = append(f.Cases, runBandingCase(c))
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(bandingVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(bandingVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("banding differs from %s; if the change is intended, regenerate with -update and review the diff", bandingVectorsPath)
	}
}
