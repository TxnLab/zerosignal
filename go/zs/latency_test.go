/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"math"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
)

func TestBandByResponsiveness(t *testing.T) {
	// catalog builds an n-model capacity map. Only its SIZE matters to banding:
	// catalogConfidence discounts a node's on-chain aggregates by how much other
	// traffic could be diluting them.
	catalog := func(n int) map[string]ModelCapacity {
		caps := make(map[string]ModelCapacity, n)
		for i := range n {
			caps["m"+strconv.Itoa(i)] = ModelCapacity{}
		}
		return caps
	}
	// withCatalog widens a candidate's catalog to n models, diluting its on-chain
	// metrics' confidence to 1/sqrt(n). `catalog` leaves modalities undeclared,
	// which counts toward breadth — the pessimistic reading.
	withCatalog := func(o Operator, n int) Operator {
		o.ModelCapacities = catalog(n)
		return o
	}
	// withMixedCatalog widens a candidate to one TOKEN-output model plus n-1
	// IMAGE-ONLY ones — apparent breadth that cannot be real dilution, since an
	// image settle never folds into latencyEwmaMs / tokensPerSecEwma.
	withMixedCatalog := func(o Operator, n int) Operator {
		caps := map[string]ModelCapacity{"m0": {OutputModalities: []string{"text"}}}
		for i := 1; i < n; i++ {
			caps["img"+strconv.Itoa(i)] = ModelCapacity{OutputModalities: []string{"image"}}
		}
		o.ModelCapacities = caps
		return o
	}
	// op builds a candidate carrying an on-chain TTFT EWMA (ms); 0 = no settled
	// data. Input slice order stands in for the price-first order from selectTargets.
	// The single-model catalog is what makes its on-chain metrics fully trusted
	// (confidence 1) — that node serves nothing else, so nothing dilutes them.
	op := func(id, ttftMs uint64) Operator {
		return Operator{
			ID:              id,
			Metrics:         OperatorMetrics{LatencyEwmaMs: ttftMs},
			ModelCapacities: catalog(1),
		}
	}
	// opTps adds an on-chain decode-throughput EWMA (tokens/sec) on top of TTFT.
	opTps := func(id, ttftMs, tps uint64) Operator {
		return Operator{
			ID:              id,
			Metrics:         OperatorMetrics{LatencyEwmaMs: ttftMs, TokensPerSecEwma: tps},
			ModelCapacities: catalog(1),
		}
	}
	// ids takes bandByResponsiveness's PAIR of return values so every case below
	// calls the production function directly — a thin ops-only wrapper here would
	// be one more thing the dispatch path doesn't use.
	ids := func(ops []Operator, _ []rankDetail) []uint64 {
		out := make([]uint64, len(ops))
		for i, o := range ops {
			out[i] = o.ID
		}
		return out
	}
	// recordRTT folds n network-RTT samples for a node into a store.
	recordRTT := func(s *ChainOperatorSource, id uint64, ms, n int) {
		for range n {
			s.RecordDirectRTT(NodeRef{Op: id}, time.Duration(ms)*time.Millisecond)
		}
	}

	t.Run("bands a slow (high-TTFT) node behind faster peers, regardless of price order", func(t *testing.T) {
		// Price order [1,2,3]; op2 has CPU-grade TTFT and sinks to the tail.
		ops := []Operator{op(1, 200), op(2, 2000), op(3, 200)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 3, 2}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("folds in tokens/sec — a slow-decode node bands behind a fast-decode peer", func(t *testing.T) {
		// Equal TTFT; op2 decodes far slower (20 vs 200 tok/s) → its decode term
		// (32/20·1000 = 1600ms vs 160ms) bands it back.
		ops := []Operator{opTps(1, 100, 200), opTps(2, 100, 20), opTps(3, 100, 200)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 3, 2}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps price order within a band", func(t *testing.T) {
		ops := []Operator{op(1, 100), op(2, 200), op(3, 150)} // all band 0
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("pins the affinity-preferred node first regardless of its band", func(t *testing.T) {
		ops := []Operator{op(1, 2000), op(2, 100), op(3, 100)} // op1 slow but preferred
		pref := op(1, 2000)
		got := ids(bandByResponsiveness(ops, &pref, nil, ""))
		if want := []uint64{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("places an unknown-signal node in the median band (mid-pack)", func(t *testing.T) {
		// op2 has no TTFT and no RTT → median band, between fast op3 and slow op1.
		ops := []Operator{op(1, 5000), op(2, 0), op(3, 100)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{3, 2, 1}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("combines network RTT additively with TTFT", func(t *testing.T) {
		s := &ChainOperatorSource{}
		recordRTT(s, 1, 2000, 2) // op1: small TTFT but a huge network RTT
		recordRTT(s, 2, 100, 2)  // op2: measured too, so the comparison is real
		ops := []Operator{op(1, 100), op(2, 100)}
		got := ids(bandByResponsiveness(ops, nil, s, ""))
		// op1 ≈ 2100ms, op2 ≈ 200ms → op2 leads a band despite equal TTFT.
		if want := []uint64{2, 1}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("an unmeasured node cannot outrank a measured peer on RTT", func(t *testing.T) {
		// The RTT half of the regression the decode term already had: a term we
		// can't fill contributes 0 to a lower-is-faster score, so op2 — which we
		// simply haven't measured — used to read as having zero network latency
		// and jump ahead of the peer we HAVE measured. It now takes op1's RTT as
		// the median, both land in the same band, and price order stands.
		s := &ChainOperatorSource{}
		recordRTT(s, 1, 2000, 2) // only op1 has samples
		ops := []Operator{op(1, 100), op(2, 100)}
		got := ids(bandByResponsiveness(ops, nil, s, ""))
		if want := []uint64{1, 2}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — an unmeasured RTT must not win a band", got, want)
		}
	})

	t.Run("a node with no tokens/sec is mid-pack, not fastest", func(t *testing.T) {
		// The regression. Omitting an unknown decode term contributes 0 to a
		// lower-is-faster score, so op2 used to read as "infinitely fast" and
		// outrank both honest peers — and since decode_ms is self-reported, that
		// made withholding it a costless way to erase the decode penalty.
		//
		// Terms: op1 32/200·1000 = 160ms, op3 32/20·1000 = 1600ms, so the median
		// known decode term is 880ms and op2 is charged that. Equal TTFT, so the
		// order must be fast-decode, unknown, slow-decode.
		ops := []Operator{opTps(1, 100, 200), op(2, 100), opTps(3, 100, 20)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — an unknown decode term must land mid-pack", got, want)
		}
	})

	t.Run("a node with no tokens/sec cannot outrank an honest fast-decode peer", func(t *testing.T) {
		// Two candidates, price order [1,2]: op1 honestly reports 200 tok/s, op2
		// reports none. They must NOT reorder — op2 gets op1's term as the median,
		// so both land in the same band and price order stands. Before the fix op2
		// scored 160ms lower and jumped ahead.
		ops := []Operator{opTps(1, 100, 200), op(2, 100)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 2}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — withholding tokens/sec must not win a band", got, want)
		}
	})

	t.Run("no signal anywhere → price order unchanged", func(t *testing.T) {
		ops := []Operator{op(1, 0), op(2, 0), op(3, 0)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("single candidate is a no-op", func(t *testing.T) {
		got := ids(bandByResponsiveness([]Operator{op(1, 5000)}, nil, nil, ""))
		if want := []uint64{1}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	// --- provider.sort modes (Phase 3) ---

	t.Run("sort=price skips the reband entirely (pure price order)", func(t *testing.T) {
		// op2 has CPU-grade TTFT that would sink it in the default band, but a
		// price sort returns the price-ordered list untouched.
		ops := []Operator{op(1, 200), op(2, 2000), op(3, 200)}
		got := ids(bandByResponsiveness(ops, nil, nil, selection.SortPrice))
		if want := []uint64{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v (price sort must not reorder)", got, want)
		}
	})

	t.Run("sort=latency ranks by first-token time, ignoring decode throughput", func(t *testing.T) {
		// op1: fast TTFT (100), slow decode (10 tok/s → 3200ms); op2: slower TTFT
		// (600), fast decode (500 tok/s → 64ms). Default (combined) puts op2 first
		// on total time; latency mode drops the decode term, so op1's fast first
		// token wins.
		ops := []Operator{opTps(1, 100, 10), opTps(2, 600, 500)}
		if got := ids(bandByResponsiveness(ops, nil, nil, selection.SortLatency)); !reflect.DeepEqual(got, []uint64{1, 2}) {
			t.Errorf("latency: got %v, want [1 2] (first-token wins, decode ignored)", got)
		}
		// Contrast: the default combined score flips them (op2 lower total time).
		if got := ids(bandByResponsiveness(ops, nil, nil, "")); !reflect.DeepEqual(got, []uint64{2, 1}) {
			t.Errorf("default: got %v, want [2 1] (combined score favors op2)", got)
		}
	})

	t.Run("sort=throughput ranks by decode tok/s, ignoring first-token time", func(t *testing.T) {
		// Same ops; throughput mode keeps ONLY the decode term, so op2's faster
		// tok/s wins despite its slower TTFT — the mirror image of latency.
		ops := []Operator{opTps(1, 100, 10), opTps(2, 600, 500)}
		if got := ids(bandByResponsiveness(ops, nil, nil, selection.SortThroughput)); !reflect.DeepEqual(got, []uint64{2, 1}) {
			t.Errorf("throughput: got %v, want [2 1] (decode wins, TTFT ignored)", got)
		}
	})

	// --- catalog-breadth confidence ---

	t.Run("a broad catalog's flattering aggregate can't outrank a cheaper specialist", func(t *testing.T) {
		// The reported bug. op2 serves a hundred models — mostly small and fast —
		// so its on-chain TTFT and tok/s are a mean over that mix rather than
		// figures for the model being routed; op1 serves one, so its numbers ARE
		// that model's. Raw, op2 sits a band ahead and takes the dispatch despite
		// being the pricier operator. Discounted by catalog breadth its edge falls
		// inside op1's band, and the price order (input order) stands.
		//
		// Terms: op1 400 + 32/40·1000 = 1200ms. op2 raw 200 + 32/160·1000 = 400ms,
		// shrunk toward the per-term medians at confidence 1/sqrt(100) = 0.1 →
		// 760ms. Both round to band 2; at full confidence op2 would be band 1.
		ops := []Operator{
			withCatalog(opTps(1, 400, 40), 1),
			withCatalog(opTps(2, 200, 160), 100),
		}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 2}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — a diluted aggregate must not outrank a cheaper narrow-catalog peer", got, want)
		}
	})

	t.Run("diluted aggregates can't outrank a specialist by outnumbering it", func(t *testing.T) {
		// The same bug as above, in the arrangement that actually defeats a
		// one-vote-each median: the broad-catalog nodes are the MAJORITY, so they
		// define the reference point and then sit exactly on it — where the shrink
		// cannot move them at any confidence — while the lone specialist keeps its
		// honest, slower number and gets buried behind both. On a fleet of
		// aggregators that is the normal shape, not a corner case.
		//
		// Weighted, the specialist's confidence-1 vote pulls the reference to
		// ~364ms: it lands at 400 and the pair at ~347, inside one band, so the
		// price order (input order) stands. Unweighted the reference is 200, the
		// pair keeps it in full, and op1 falls to the back.
		ops := []Operator{
			withCatalog(op(1, 400), 1),
			withCatalog(op(2, 200), 100),
			withCatalog(op(3, 200), 100),
		}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{1, 2, 3}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — untrusted values must not define the pack they're measured against", got, want)
		}
	})

	t.Run("image-only models don't dilute a token-speed aggregate", func(t *testing.T) {
		// The same fixture as the dilution case above, except op2's 99 extra models
		// are image-only. The contract folds TTFT and tok/s solely on token-output
		// settles, so those models wrote nothing into the numbers being compared —
		// discounting for them erases a signal that IS about op2's one text model.
		//
		// At full confidence op2's 200 + 32/160·1000 = 400ms sits a band ahead of
		// op1's 1200ms and takes the dispatch. Counted as breadth (confidence 0.1)
		// it shrinks to 760ms, lands in op1's band, and loses on price instead.
		ops := []Operator{
			withCatalog(opTps(1, 400, 40), 1),
			withMixedCatalog(opTps(2, 200, 160), 100),
		}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{2, 1}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — models that can't fold into the metric must not discount it", got, want)
		}
	})

	t.Run("an image-only catalog carries no token-speed evidence", func(t *testing.T) {
		// The other end of the same rule. Every model this node serves settles as
		// image output, so nothing it has ever done touched latencyEwmaMs — whatever
		// the chain reports for it predates its current catalog or came from traffic
		// it no longer serves. Confidence 0, mid-pack, exactly like an undeclared
		// catalog: behind the measured fast peer, ahead of the measured slow one.
		imgOnly := withMixedCatalog(op(2, 100), 1)
		imgOnly.ModelCapacities = map[string]ModelCapacity{
			"img": {OutputModalities: []string{"image"}},
		}
		ops := []Operator{op(1, 5000), imgOnly, op(3, 100)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{3, 2, 1}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — an image-only catalog has no token-stream evidence to trust", got, want)
		}
	})

	t.Run("an undeclared catalog scores no confidence at all", func(t *testing.T) {
		// Unknown breadth means unbounded possible dilution, so the node's on-chain
		// metrics buy it nothing: it lands mid-pack rather than riding a TTFT we
		// have no way to scope. Here that leaves it behind the measured fast peer
		// and ahead of the measured slow one.
		bare := Operator{ID: 2, Metrics: OperatorMetrics{LatencyEwmaMs: 100}}
		ops := []Operator{op(1, 5000), bare, op(3, 100)}
		got := ids(bandByResponsiveness(ops, nil, nil, ""))
		if want := []uint64{3, 2, 1}; !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v — an undeclared catalog must not be trusted", got, want)
		}
	})

	t.Run("clamps responsiveness to one band either side of the pack", func(t *testing.T) {
		// Unclamped, op2's 10s TTFT is band 20 against op1's band 0 — a twenty-band
		// spread no price advantage could survive. Bounded, the whole field spans
		// at most three bands and every finer distinction goes back to price.
		ops := []Operator{op(1, 100), op(2, 10000), op(3, 200)}
		_, ranking := bandByResponsiveness(ops, nil, nil, "")
		if len(ranking) != len(ops) {
			t.Fatalf("ranking = %d details, want %d", len(ranking), len(ops))
		}
		lo, hi := ranking[0].band, ranking[0].band
		for _, d := range ranking {
			lo, hi = min(lo, d.band), max(hi, d.band)
		}
		if hi-lo > 2*maxBandsFromMedian {
			t.Errorf("band spread %v..%v exceeds ±%v around the median", lo, hi, maxBandsFromMedian)
		}
	})
}

func TestConfidenceWeightedMedian(t *testing.T) {
	// The property that makes swapping this in for medianOf safe: at equal
	// weights it IS medianOf, including the average-the-two-middles rule on an
	// even count. Every candidate set where nobody's catalog differs takes this
	// path, so a divergence here would silently re-band the common case.
	t.Run("equal weights reproduce the plain median", func(t *testing.T) {
		for _, vs := range [][]float64{
			{7},
			{10, 20},
			{10, 20, 30},
			{40, 10, 30, 20},
			{5, 5, 5, 5, 5},
			{1600, 160},
		} {
			ws := make([]float64, len(vs))
			for i := range ws {
				ws[i] = 0.1 // an irrational-ish weight, not 1 — the equality must not depend on it
			}
			got, want := confidenceWeightedMedian(vs, ws), medianOf(vs)
			if math.Abs(got-want) > 1e-9 {
				t.Errorf("confidenceWeightedMedian(%v, equal) = %v, want medianOf = %v", vs, got, want)
			}
		}
	})

	t.Run("weight moves the median toward the trusted value", func(t *testing.T) {
		// Two diluted values outvote one trusted value 2:1, so the plain median is
		// theirs outright (200). Weighted, the confidence-1 value carries ~83% of
		// the total and drags the reference most of the way to itself.
		vs := []float64{200, 200, 400}
		ws := []float64{0.1, 0.1, 1}
		if plain := medianOf(vs); plain != 200 {
			t.Fatalf("medianOf = %v, want 200 (test premise)", plain)
		}
		got := confidenceWeightedMedian(vs, ws)
		if got <= 200 || got >= 400 {
			t.Fatalf("confidenceWeightedMedian = %v, want strictly between 200 and 400", got)
		}
		if want := 200 + (0.6-0.15)/0.55*200; math.Abs(got-want) > 1e-9 {
			t.Errorf("confidenceWeightedMedian = %v, want %v", got, want)
		}
	})

	t.Run("degenerate inputs return the medianOf zero", func(t *testing.T) {
		if got := confidenceWeightedMedian(nil, nil); got != 0 {
			t.Errorf("empty = %v, want 0", got)
		}
		if got := confidenceWeightedMedian([]float64{5, 9}, []float64{0, 0}); got != 0 {
			t.Errorf("zero total weight = %v, want 0", got)
		}
	})
}

func TestCatalogConfidence(t *testing.T) {
	caps := func(n int) map[string]ModelCapacity {
		m := make(map[string]ModelCapacity, n)
		for i := range n {
			m["m"+strconv.Itoa(i)] = ModelCapacity{}
		}
		return m
	}
	for _, tc := range []struct {
		name  string
		n     int
		want  float64
		notes string
	}{
		{name: "undeclared catalog is worthless", n: 0, want: 0},
		{name: "a specialist is fully trusted", n: 1, want: 1},
		{name: "four models halve it", n: 4, want: 0.5},
		{name: "sixteen quarter it", n: 16, want: 0.25},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := catalogConfidence(Operator{ModelCapacities: caps(tc.n)})
			if math.Abs(got-tc.want) > 1e-9 {
				t.Errorf("catalogConfidence(%d models) = %v, want %v", tc.n, got, tc.want)
			}
		})
	}
}
