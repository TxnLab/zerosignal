/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/probe_set_vectors.json: which nodes a
// bounded discovery cycle probes (probeSelection) and the recently-demanded
// model list that steers it (RecordModelDemand). The TS SDK mirrors both in
// sdk/src/catalog/probe.ts.
//
//	cd proto/go && go test ./zs -run TestProbeSetVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"
)

const probeSetVectorsPath = "../../testdata/probe_set_vectors.json"

type probeVectorNode struct {
	Op               uint64   `json:"op"`
	Node             uint64   `json:"node"`
	TTFTEwmaMs       uint64   `json:"ttft_ewma_ms"`
	TokensPerSecEwma uint64   `json:"tokens_per_sec_ewma"`
	Models           []string `json:"models"`
	// Unix ms, 0 for never: the last probe attempt and the last answer.
	LastRefreshAtMs int64 `json:"last_refresh_at_ms"`
	ReachableAsOfMs int64 `json:"reachable_as_of_ms"`
}

// probeTriedAtMs is when a vector node was last tried, unless the case says it
// never was.
const probeTriedAtMs = 1_800_000_000_000

type probeVectorCycle struct {
	// ProbeAll is true when the cycle probes every node (Set is then empty).
	ProbeAll bool        `json:"probe_all"`
	Set      [][2]uint64 `json:"set"`
	Cursor   int         `json:"cursor"`
}

type probeSetScenario struct {
	Name       string            `json:"name"`
	Nodes      []probeVectorNode `json:"nodes"`
	Demand     []string          `json:"demand"`
	Budget     int               `json:"budget"`
	TargetTopK int               `json:"target_top_k"`
	Cursor     int               `json:"cursor"`
	// Want is one entry per cycle, each starting from the previous cursor.
	Want []probeVectorCycle `json:"want"`
	// Cycles is how many cycles to run; not emitted.
	Cycles int `json:"-"`
}

type demandScenario struct {
	Name      string   `json:"name"`
	DemandMax int      `json:"demand_max"`
	Record    []string `json:"record"`
	Want      []string `json:"want"`
}

func probeNode(op, node, ttft, tps uint64, models ...string) probeVectorNode {
	if models == nil {
		models = []string{}
	}
	return probeVectorNode{Op: op, Node: node, TTFTEwmaMs: ttft, TokensPerSecEwma: tps, Models: models, LastRefreshAtMs: probeTriedAtMs}
}

// probeFleet is n nodes of operators 1..n, one node each, in (id, node) order,
// with no latency signal and no models, each tried before.
func probeFleet(n int) []probeVectorNode {
	out := make([]probeVectorNode, n)
	for i := range out {
		out[i] = probeNode(uint64(i+1), 1, 0, 0)
	}
	return out
}

// probeUntried marks the nodes of fleet at the given operator ids as never
// tried and never answered.
func probeUntried(fleet []probeVectorNode, ops ...uint64) []probeVectorNode {
	out := append([]probeVectorNode(nil), fleet...)
	for i := range out {
		for _, op := range ops {
			if out[i].Op == op {
				out[i].LastRefreshAtMs, out[i].ReachableAsOfMs = 0, 0
			}
		}
	}
	return out
}

func probeSetScenarios() []probeSetScenario {
	// Five servers of "m" among ten nodes, at distinct speeds.
	served := probeFleet(10)
	served[1] = probeNode(2, 1, 900, 0, "m")
	served[3] = probeNode(4, 1, 300, 50, "m")
	served[5] = probeNode(6, 1, 300, 0, "m")
	served[7] = probeNode(8, 1, 0, 0, "m")
	served[8] = probeNode(9, 1, 100, 0, "m", "other")

	// Integer decode term: 100 + 128000/3 = 42766 in uint64 arithmetic, a tie
	// with a node of 42766ms and no throughput, which node order breaks.
	// Float or rounded division gives 42766.67 or 42767 and puts that node
	// first.
	intDiv := probeFleet(6)
	intDiv[0] = probeNode(1, 1, 100, 3, "m")
	intDiv[1] = probeNode(1, 2, 42766, 0, "m")

	// Equal scores keep (id, node) order.
	ties := probeFleet(6)
	ties[2] = probeNode(3, 1, 500, 0, "m")
	ties[3] = probeNode(3, 2, 500, 0, "m")
	ties[4] = probeNode(5, 1, 500, 0, "m")

	// Thirteen servers of "m", twelve tied with no latency signal. Go's
	// sort.Slice keeps ties in order only up to twelve elements, so this is
	// the size where an unstable sort stops agreeing with TS by luck. The
	// cursor starts the sweep on the three nodes that serve nothing.
	manyTies := probeFleet(16)
	for i := range 13 {
		manyTies[i] = probeNode(uint64(i+1), 1, 0, 0, "m")
	}
	manyTies[12] = probeNode(13, 1, 100, 0, "m")

	// Two demanded models, each served by three nodes.
	twoModels := probeFleet(12)
	for i := range 3 {
		twoModels[i] = probeNode(uint64(i+1), 1, uint64(100+i), 0, "a")
		twoModels[i+3] = probeNode(uint64(i+4), 1, uint64(100+i), 0, "b")
	}

	answeredOrTried := probeUntried(probeFleet(10), 4, 6, 8)
	answeredOrTried[3].ReachableAsOfMs = probeTriedAtMs
	answeredOrTried[5].LastRefreshAtMs = probeTriedAtMs

	return []probeSetScenario{
		{Name: "a fleet within the budget probes every node", Nodes: probeFleet(4), Budget: 4, TargetTopK: 8, Cursor: 2},
		{Name: "no budget probes every node", Nodes: probeFleet(9), Budget: 0, TargetTopK: 8},
		{Name: "the sweep fills the budget from the cursor", Nodes: probeFleet(10), Budget: 4, TargetTopK: 8, Cursor: 3},
		{Name: "the sweep wraps past the last node", Nodes: probeFleet(10), Budget: 4, TargetTopK: 8, Cursor: 8},
		{Name: "successive cycles cover the fleet", Nodes: probeFleet(10), Budget: 3, TargetTopK: 8, Cycles: 4},
		{Name: "a demanded model's fastest servers come first", Nodes: served, Demand: []string{"m"}, Budget: 4, TargetTopK: 2},
		{Name: "a sweep scan over a node already chosen still advances the cursor", Nodes: served, Demand: []string{"m"}, Budget: 5, TargetTopK: 2, Cursor: 8},
		{Name: "demand keeps a quarter of the budget for the sweep", Nodes: served, Demand: []string{"m"}, Budget: 4, TargetTopK: 8},
		{Name: "a budget under four lets demand take all of it", Nodes: served, Demand: []string{"m"}, Budget: 3, TargetTopK: 8, Cursor: 5},
		{Name: "a budget of one", Nodes: served, Demand: []string{"m"}, Budget: 1, TargetTopK: 8, Cursor: 5},
		// Four of the five servers fit, so the one left out is the one ranked last.
		{Name: "a node with no latency signal ranks last", Nodes: served, Demand: []string{"m"}, Budget: 5, TargetTopK: 4},
		// The cursor starts the sweep past both, so only the tie's winner is in.
		{Name: "the decode term divides in integers", Nodes: intDiv, Demand: []string{"m"}, Budget: 4, TargetTopK: 1, Cursor: 2},
		{Name: "equal scores keep node order", Nodes: ties, Demand: []string{"m"}, Budget: 4, TargetTopK: 2},
		{Name: "equal scores keep node order past twelve servers", Nodes: manyTies, Demand: []string{"m"}, Budget: 11, TargetTopK: 8, Cursor: 13},
		{Name: "a demanded model nobody serves is skipped", Nodes: served, Demand: []string{"gone", "m"}, Budget: 4, TargetTopK: 1},
		{Name: "the most recent demand is served first when the cap binds", Nodes: twoModels, Demand: []string{"b", "a"}, Budget: 4, TargetTopK: 3},
		{Name: "demand order reversed", Nodes: twoModels, Demand: []string{"a", "b"}, Budget: 4, TargetTopK: 3},
		{Name: "a cursor past the fleet wraps", Nodes: probeFleet(5), Budget: 2, TargetTopK: 8, Cursor: 12},
		{Name: "a node no refresh has tried comes before the sweep", Nodes: probeUntried(probeFleet(10), 7, 9), Budget: 4, TargetTopK: 8},
		// Operator 4 answered once (a restored catalog) and 6 was tried and
		// never answered: neither is unknown.
		{Name: "a node with an answer or an attempt on record is not untried", Nodes: answeredOrTried, Budget: 4, TargetTopK: 8},
		{Name: "untried nodes share demand's three quarters, and the sweep keeps its quarter", Nodes: probeUntried(probeFleet(10), 5, 6, 7, 8, 9, 10), Budget: 4, TargetTopK: 8},
		{Name: "demand comes before untried nodes", Nodes: probeUntried(served, 1, 10), Demand: []string{"m"}, Budget: 4, TargetTopK: 2, Cursor: 4},
		{Name: "the untried scan starts at the cursor and wraps", Nodes: probeUntried(probeFleet(10), 2, 3, 8, 9), Budget: 4, TargetTopK: 8, Cursor: 5},
		{Name: "an untried backlog rotates across cycles", Nodes: probeUntried(probeFleet(12), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12), Budget: 4, TargetTopK: 8, Cycles: 3},
	}
}

func demandScenarios() []demandScenario {
	return []demandScenario{
		{Name: "most recent first", DemandMax: 32, Record: []string{"a", "b", "c"}},
		{Name: "a repeat moves to the front", DemandMax: 32, Record: []string{"a", "b", "a"}},
		{Name: "past the cap the least recent goes", DemandMax: 3, Record: []string{"a", "b", "c", "a", "d"}},
		{Name: "an empty model is not recorded", DemandMax: 32, Record: []string{"a", "", "b"}},
		{Name: "no cap keeps every model", DemandMax: 0, Record: []string{"a", "b", "c", "d"}},
		{Name: "nothing recorded", DemandMax: 32, Record: []string{}},
	}
}

func runProbeSetScenario(s probeSetScenario) []probeVectorCycle {
	ops := make([]Operator, len(s.Nodes))
	for i, n := range s.Nodes {
		ops[i] = Operator{ID: n.Op, NodeID: n.Node, Models: n.Models}
		ops[i].Metrics.LatencyEwmaMs = n.TTFTEwmaMs
		ops[i].Metrics.TokensPerSecEwma = n.TokensPerSecEwma
		if n.LastRefreshAtMs != 0 {
			ops[i].LastRefreshAt = time.UnixMilli(n.LastRefreshAtMs)
		}
		if n.ReachableAsOfMs != 0 {
			ops[i].ReachableAsOf = time.UnixMilli(n.ReachableAsOfMs)
		}
	}
	cycles := max(s.Cycles, 1)
	cursor := s.Cursor
	out := make([]probeVectorCycle, 0, cycles)
	for range cycles {
		var set map[NodeRef]bool
		set, cursor = probeSelection(ops, s.Demand, s.Budget, s.TargetTopK, cursor)
		c := probeVectorCycle{ProbeAll: set == nil, Set: [][2]uint64{}, Cursor: cursor}
		for ref := range set {
			c.Set = append(c.Set, [2]uint64{ref.Op, ref.Node})
		}
		sort.Slice(c.Set, func(i, j int) bool {
			if c.Set[i][0] != c.Set[j][0] {
				return c.Set[i][0] < c.Set[j][0]
			}
			return c.Set[i][1] < c.Set[j][1]
		})
		out = append(out, c)
	}
	return out
}

func runDemandScenario(s demandScenario) []string {
	p := &DynamicRegistryProvider{demand: make(map[string]int64), demandMax: s.DemandMax}
	for _, m := range s.Record {
		p.RecordModelDemand(m)
	}
	out := p.snapshotDemand()
	if out == nil {
		out = []string{}
	}
	return out
}

func TestProbeSetVectors(t *testing.T) {
	probes := probeSetScenarios()
	for i := range probes {
		if probes[i].Demand == nil {
			probes[i].Demand = []string{}
		}
		probes[i].Want = runProbeSetScenario(probes[i])
	}
	demand := demandScenarios()
	for i := range demand {
		demand[i].Want = runDemandScenario(demand[i])
	}
	f := struct {
		Comment string             `json:"comment"`
		Probe   []probeSetScenario `json:"probe"`
		Demand  []demandScenario   `json:"demand"`
	}{
		Comment: "Generated by proto/go/zs TestProbeSetVectors. probe: nodes in (op, node) order, each with its last probe attempt and last answer in Unix ms (0 for never; a node with neither is untried), demand most-recent first; want is one entry per cycle, each starting from the previous cursor, with set sorted by (op, node). demand: the models recorded in order, want the list most-recent first.",
		Probe:   probes,
		Demand:  demand,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(probeSetVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(probeSetVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("probe selection differs from %s; if the change is intended, regenerate with -update and review the diff", probeSetVectorsPath)
	}
}
