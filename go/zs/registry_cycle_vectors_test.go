/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/registry_cycle_vectors.json: the rules a
// registry cycle applies around the probe pass. carry pins carryWithin (what a
// node not confirmed live this cycle keeps of its last-good capabilities, and
// when that ages out), advertisable pins advertisableAt (which nodes the
// discovery aggregates list), and merge pins a saved catalog, decoded, merged
// into a fresh chain read at boot (decodeCatalog then mergeCatalogAt). The TS
// SDK replays it against sdk/src/registry/registry.ts and persist.ts.
//
//	cd proto/go && go test ./zs -run TestRegistryCycleVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

const registryCycleVectorsPath = "../../testdata/registry_cycle_vectors.json"

const cycleVectorNowMs int64 = 1_800_000_000_000

// cycleOp is the part of an Operator the cycle rules read or write. Times are
// Unix ms, 0 for Go's zero time; empty lists stand for Go's nil, which is what
// a fresh chain row carries. context_windows projects ModelCapacities, which
// the carry moves as a whole.
type cycleOp struct {
	ID                        uint64            `json:"id"`
	NodeID                    uint64            `json:"node_id"`
	Reachable                 bool              `json:"reachable"`
	Probed                    bool              `json:"probed"`
	ReachableAsOfMs           int64             `json:"reachable_as_of_ms"`
	LastRefreshAtMs           int64             `json:"last_refresh_at_ms"`
	Staging                   bool              `json:"staging"`
	SignerSpendableMicroAlgos *uint64           `json:"signer_spendable_microalgos"`
	Models                    []string          `json:"models"`
	ContextWindows            map[string]uint64 `json:"context_windows"`
	BuiltinTools              []string          `json:"builtin_tools"`
	MaxToolIters              int               `json:"max_tool_iters"`
	ToolHeadroomPerIteration  uint64            `json:"tool_headroom_per_iteration"`
	ProtoVersion              string            `json:"proto_version"`
}

func (c cycleOp) operator() Operator {
	op := Operator{
		ID:                        c.ID,
		NodeID:                    c.NodeID,
		OwnerAddr:                 "OWNER" + strconv.FormatUint(c.ID, 10),
		BaseURL:                   "https://n" + strconv.FormatUint(c.ID, 10) + "-" + strconv.FormatUint(c.NodeID, 10) + ".example",
		Reachable:                 c.Reachable,
		Probed:                    c.Probed,
		Staging:                   c.Staging,
		SignerSpendableMicroAlgos: c.SignerSpendableMicroAlgos,
		MaxToolIters:              c.MaxToolIters,
		ToolHeadroomPerIteration:  c.ToolHeadroomPerIteration,
		ProtoVersion:              c.ProtoVersion,
	}
	if c.ReachableAsOfMs != 0 {
		op.ReachableAsOf = time.UnixMilli(c.ReachableAsOfMs).UTC()
	}
	if c.LastRefreshAtMs != 0 {
		op.LastRefreshAt = time.UnixMilli(c.LastRefreshAtMs).UTC()
	}
	if len(c.Models) > 0 {
		op.Models = append([]string(nil), c.Models...)
	}
	if len(c.ContextWindows) > 0 {
		op.ModelCapacities = make(map[string]ModelCapacity, len(c.ContextWindows))
		for m, w := range c.ContextWindows {
			op.ModelCapacities[m] = ModelCapacity{ContextWindow: w}
		}
	}
	for _, t := range c.BuiltinTools {
		op.BuiltinTools = append(op.BuiltinTools, BuiltinToolDef{Type: t})
	}
	return op
}

func cycleOpOf(op Operator) cycleOp {
	c := cycleOp{
		ID:                        op.ID,
		NodeID:                    op.NodeID,
		Reachable:                 op.Reachable,
		Probed:                    op.Probed,
		Staging:                   op.Staging,
		SignerSpendableMicroAlgos: op.SignerSpendableMicroAlgos,
		Models:                    append([]string{}, op.Models...),
		ContextWindows:            map[string]uint64{},
		BuiltinTools:              []string{},
		MaxToolIters:              op.MaxToolIters,
		ToolHeadroomPerIteration:  op.ToolHeadroomPerIteration,
		ProtoVersion:              op.ProtoVersion,
	}
	if !op.ReachableAsOf.IsZero() {
		c.ReachableAsOfMs = op.ReachableAsOf.UnixMilli()
	}
	if !op.LastRefreshAt.IsZero() {
		c.LastRefreshAtMs = op.LastRefreshAt.UnixMilli()
	}
	for m, mc := range op.ModelCapacities {
		c.ContextWindows[m] = mc.ContextWindow
	}
	for _, t := range op.BuiltinTools {
		c.BuiltinTools = append(c.BuiltinTools, t.Type)
	}
	return c
}

func cycleOps(cs []cycleOp) []Operator {
	out := make([]Operator, len(cs))
	for i, c := range cs {
		out[i] = c.operator()
	}
	return out
}

func cycleOpsOf(ops []Operator) []cycleOp {
	out := make([]cycleOp, len(ops))
	for i, op := range ops {
		out[i] = cycleOpOf(op)
	}
	return out
}

// cycleNormalized gives a hand-written cycleOp the empty lists cycleOpOf emits, so
// inputs and outputs read alike in the fixture.
func cycleNormalized(cs []cycleOp) []cycleOp {
	return cycleOpsOf(cycleOps(cs))
}

type carryCase struct {
	Name          string    `json:"name"`
	NowMs         int64     `json:"now_ms"`
	MaxCarryAgeMs int64     `json:"max_carry_age_ms"`
	Prev          []cycleOp `json:"prev"`
	Ops           []cycleOp `json:"ops"`
	Want          []cycleOp `json:"want"`
}

type advertisableCase struct {
	Name          string  `json:"name"`
	NowMs         int64   `json:"now_ms"`
	MaxCarryAgeMs int64   `json:"max_carry_age_ms"`
	AllowStaging  bool    `json:"allow_staging"`
	Op            cycleOp `json:"op"`
	Want          bool    `json:"want"`
}

type mergeCase struct {
	Name          string    `json:"name"`
	NowMs         int64     `json:"now_ms"`
	MaxCarryAgeMs int64     `json:"max_carry_age_ms"`
	SavedCatalog  string    `json:"saved_catalog"`
	Fresh         []cycleOp `json:"fresh"`
	Want          []cycleOp `json:"want"`
}

func cycleU64(v uint64) *uint64 { return &v }

const cycleMinuteMs = int64(time.Minute / time.Millisecond)

var defaultCarryMs = int64(DefaultMaxCarryAge / time.Millisecond)

// cycleLastGood is a node confirmed live asOfMs before now, with capabilities.
// That probe was its last attempt.
func cycleLastGood(id, node uint64, agoMs int64) cycleOp {
	return cycleOp{
		ID: id, NodeID: node, Reachable: true, Probed: true,
		ReachableAsOfMs: cycleVectorNowMs - agoMs,
		LastRefreshAtMs: cycleVectorNowMs - agoMs,
		Models:          []string{"m1", "m2"},
		ContextWindows:  map[string]uint64{"m1": 8192, "m2": 32768},
		BuiltinTools:    []string{"zs_web_search"},
		MaxToolIters:    8, ToolHeadroomPerIteration: 2048,
		ProtoVersion: "9.11",
	}
}

// cycleChainRow is a node as the chain read returns it: identity only.
func cycleChainRow(id, node uint64) cycleOp { return cycleOp{ID: id, NodeID: node} }

func carryCases() []carryCase {
	downLastCycle := cycleLastGood(1, 1, 30*cycleMinuteMs)
	downLastCycle.Reachable, downLastCycle.LastRefreshAtMs = false, cycleVectorNowMs-cycleMinuteMs
	neverLive := cycleLastGood(1, 1, 0)
	neverLive.Reachable, neverLive.ReachableAsOfMs, neverLive.LastRefreshAtMs = false, 0, cycleVectorNowMs-2*cycleMinuteMs
	agedOutTriedSince := cycleLastGood(1, 1, 2*defaultCarryMs)
	agedOutTriedSince.Reachable, agedOutTriedSince.LastRefreshAtMs = false, cycleVectorNowMs-cycleMinuteMs
	failedWithOwn := cycleOp{ID: 1, NodeID: 1, Probed: true, LastRefreshAtMs: cycleVectorNowMs, Models: []string{"own"}, ProtoVersion: "9.12"}
	stamped := cycleChainRow(1, 1)
	stamped.ReachableAsOfMs = cycleVectorNowMs - 5*cycleMinuteMs
	upNow := cycleOp{
		ID: 1, NodeID: 1, Reachable: true, Probed: true, ReachableAsOfMs: cycleVectorNowMs, LastRefreshAtMs: cycleVectorNowMs,
		Models: []string{"fresh"}, ContextWindows: map[string]uint64{"fresh": 4096}, ProtoVersion: "9.11",
	}
	// A probe this cycle that never reached the target (no relay, every hop
	// down) stamps the attempt and nothing else.
	triedNow := cycleChainRow(1, 1)
	triedNow.LastRefreshAtMs = cycleVectorNowMs
	funded := cycleChainRow(1, 1)
	funded.SignerSpendableMicroAlgos = cycleU64(10_000_000)
	// A probe-failed row holding one capability of its own, so each field's
	// keep-what-the-row-has rule is pinned apart from the others.
	failedHolding := func(f func(*cycleOp)) cycleOp {
		c := cycleChainRow(1, 1)
		c.Probed = true
		f(&c)
		return c
	}
	return []carryCase{
		{Name: "an unprobed node inside the window takes its last-good capabilities and carry clock",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)}, Ops: []cycleOp{funded}},
		{Name: "a node probed up this cycle keeps its own",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)}, Ops: []cycleOp{upNow}},
		{Name: "a node last good exactly max_carry_age ago has aged out",
			Prev: []cycleOp{cycleLastGood(1, 1, defaultCarryMs)}, Ops: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a node last good one millisecond inside max_carry_age carries",
			Prev: []cycleOp{cycleLastGood(1, 1, defaultCarryMs-1)}, Ops: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a node never confirmed live carries no capabilities, only its last probe attempt",
			Prev: []cycleOp{neverLive}, Ops: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a node down last cycle carries until its last success ages out, and its last attempt",
			Prev: []cycleOp{downLastCycle}, Ops: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a node aged out of the window still carries its last probe attempt",
			Prev: []cycleOp{agedOutTriedSince}, Ops: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a probe attempt this cycle is kept over the last one",
			Prev: []cycleOp{downLastCycle}, Ops: []cycleOp{triedNow}},
		{Name: "a probe-failed node keeps what it has and takes only what it lacks",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)}, Ops: []cycleOp{failedWithOwn}},
		{Name: "a probe-failed node keeps its own model capacities",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)},
			Ops:  []cycleOp{failedHolding(func(c *cycleOp) { c.ContextWindows = map[string]uint64{"own": 1024} })}},
		{Name: "a probe-failed node keeps its own builtin tools",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)},
			Ops:  []cycleOp{failedHolding(func(c *cycleOp) { c.BuiltinTools = []string{"zs_own_tool"} })}},
		{Name: "a probe-failed node keeps its own max_tool_iters",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)},
			Ops:  []cycleOp{failedHolding(func(c *cycleOp) { c.MaxToolIters = 3 })}},
		{Name: "a probe-failed node keeps its own tool_headroom_per_iteration",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)},
			Ops:  []cycleOp{failedHolding(func(c *cycleOp) { c.ToolHeadroomPerIteration = 512 })}},
		{Name: "a carry clock the row already has is kept",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)}, Ops: []cycleOp{stamped}},
		{Name: "the carry is per node, not per operator",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs)}, Ops: []cycleOp{cycleChainRow(1, 2)}},
		{Name: "no previous snapshot carries nothing",
			Prev: nil, Ops: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "each node of a fleet is judged on its own",
			Prev: []cycleOp{cycleLastGood(1, 1, 10*cycleMinuteMs), cycleLastGood(2, 1, 2*defaultCarryMs), cycleLastGood(3, 1, cycleMinuteMs)},
			Ops:  []cycleOp{cycleChainRow(1, 1), cycleChainRow(2, 1), upNow, cycleChainRow(4, 1)}},
	}
}

func otherWireMajor() string {
	major, _, _ := strings.Cut(wire.ProtoVersion, ".")
	n, err := strconv.Atoi(major)
	if err != nil {
		panic(err)
	}
	return strconv.Itoa(n+1) + ".0"
}

func advertisableCases() []advertisableCase {
	major, _, _ := strings.Cut(wire.ProtoVersion, ".")
	up := cycleOp{ID: 1, NodeID: 1, Reachable: true, Probed: true, ReachableAsOfMs: cycleVectorNowMs, ProtoVersion: wire.ProtoVersion}
	with := func(f func(*cycleOp)) cycleOp {
		c := up
		f(&c)
		return c
	}
	unprobed := func(agoMs int64) cycleOp {
		return with(func(c *cycleOp) { c.Reachable, c.Probed, c.ReachableAsOfMs = false, false, cycleVectorNowMs-agoMs })
	}
	return []advertisableCase{
		{Name: "a node probed up this cycle", Op: up},
		{Name: "a node probed down this cycle, however recent its last success",
			Op: with(func(c *cycleOp) { c.Reachable, c.ReachableAsOfMs = false, cycleVectorNowMs-cycleMinuteMs })},
		{Name: "an unprobed node inside the carry window", Op: unprobed(10 * cycleMinuteMs)},
		{Name: "an unprobed node exactly at the carry window's edge", Op: unprobed(defaultCarryMs)},
		{Name: "an unprobed node one millisecond inside the edge", Op: unprobed(defaultCarryMs - 1)},
		{Name: "an unprobed node never confirmed live, whatever its reachable bit",
			Op: with(func(c *cycleOp) { c.Probed, c.ReachableAsOfMs = false, 0 })},
		{Name: "a staging node the payer has not opted in to", Op: with(func(c *cycleOp) { c.Staging = true })},
		{Name: "a staging node the payer opted in to", AllowStaging: true, Op: with(func(c *cycleOp) { c.Staging = true })},
		{Name: "a node that never said its proto_version", Op: with(func(c *cycleOp) { c.ProtoVersion = "" })},
		{Name: "a node on another wire major", Op: with(func(c *cycleOp) { c.ProtoVersion = otherWireMajor() })},
		{Name: "a node on this major at minor 0", Op: with(func(c *cycleOp) { c.ProtoVersion = major + ".0" })},
		{Name: "a signer known to be below the routing floor",
			Op: with(func(c *cycleOp) { c.SignerSpendableMicroAlgos = cycleU64(selection.MinSignerSpendableMicroAlgos - 1) })},
		{Name: "a signer exactly at the routing floor",
			Op: with(func(c *cycleOp) { c.SignerSpendableMicroAlgos = cycleU64(selection.MinSignerSpendableMicroAlgos) })},
		{Name: "a signer known to hold nothing",
			Op: with(func(c *cycleOp) { c.SignerSpendableMicroAlgos = cycleU64(0) })},
	}
}

func mergeCases(t *testing.T) []mergeCase {
	saved := func(cs ...cycleOp) string {
		data, err := marshalCatalog(cycleOps(cs))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	funded := cycleChainRow(1, 1)
	funded.SignerSpendableMicroAlgos = cycleU64(10_000_000)
	upNow := cycleOp{
		ID: 1, NodeID: 1, Reachable: true, Probed: true, ReachableAsOfMs: cycleVectorNowMs,
		Models: []string{"fresh"}, ContextWindows: map[string]uint64{"fresh": 4096}, ProtoVersion: "9.11",
	}
	return []mergeCase{
		{Name: "a restart restores an unprobed node's saved capabilities, its proto minor floored", MaxCarryAgeMs: defaultCarryMs,
			SavedCatalog: saved(cycleLastGood(1, 1, 20*cycleMinuteMs)), Fresh: []cycleOp{funded}},
		{Name: "a saved node past the carry window is not restored", MaxCarryAgeMs: defaultCarryMs,
			SavedCatalog: saved(cycleLastGood(1, 1, 2*defaultCarryMs)), Fresh: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a node new on chain has nothing to restore", MaxCarryAgeMs: defaultCarryMs,
			SavedCatalog: saved(cycleLastGood(1, 1, 20*cycleMinuteMs)), Fresh: []cycleOp{cycleChainRow(1, 1), cycleChainRow(2, 1)}},
		{Name: "a saved node gone from the chain is dropped", MaxCarryAgeMs: defaultCarryMs,
			SavedCatalog: saved(cycleLastGood(1, 1, 20*cycleMinuteMs), cycleLastGood(9, 1, 20*cycleMinuteMs)), Fresh: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a node the fresh read reached keeps its own", MaxCarryAgeMs: defaultCarryMs,
			SavedCatalog: saved(cycleLastGood(1, 1, 20*cycleMinuteMs)), Fresh: []cycleOp{upNow}},
		{Name: "a zero max_carry_age takes the default window", MaxCarryAgeMs: 0,
			SavedCatalog: saved(cycleLastGood(1, 1, 60*cycleMinuteMs)), Fresh: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a negative max_carry_age takes the default window", MaxCarryAgeMs: -1,
			SavedCatalog: saved(cycleLastGood(1, 1, 60*cycleMinuteMs)), Fresh: []cycleOp{cycleChainRow(1, 1)}},
		{Name: "a shorter max_carry_age ages a saved node out sooner", MaxCarryAgeMs: 30 * cycleMinuteMs,
			SavedCatalog: saved(cycleLastGood(1, 1, 60*cycleMinuteMs)), Fresh: []cycleOp{cycleChainRow(1, 1)}},
	}
}

func TestRegistryCycleVectors(t *testing.T) {
	now := time.UnixMilli(cycleVectorNowMs)

	carry := carryCases()
	for i := range carry {
		c := &carry[i]
		c.NowMs, c.MaxCarryAgeMs = cycleVectorNowMs, defaultCarryMs
		var prev map[NodeRef]Operator
		if c.Prev != nil {
			c.Prev = cycleNormalized(c.Prev)
			snap, err := buildSnapshot(cycleOps(c.Prev))
			if err != nil {
				t.Fatal(err)
			}
			prev = snap.byNode
		}
		c.Ops = cycleNormalized(c.Ops)
		ops := cycleOps(c.Ops)
		if prev != nil {
			carryWithin(prev, ops, now, DefaultMaxCarryAge)
		}
		c.Want = cycleOpsOf(ops)
	}

	adv := advertisableCases()
	for i := range adv {
		c := &adv[i]
		c.NowMs, c.MaxCarryAgeMs = cycleVectorNowMs, defaultCarryMs
		c.Op = cycleOpOf(c.Op.operator())
		c.Want = advertisableAt(c.Op.operator(), now, c.AllowStaging, DefaultMaxCarryAge)
	}

	merge := mergeCases(t)
	for i := range merge {
		c := &merge[i]
		c.NowMs = cycleVectorNowMs
		base, err := decodeCatalog([]byte(c.SavedCatalog))
		if err != nil {
			t.Fatal(err)
		}
		c.Fresh = cycleNormalized(c.Fresh)
		c.Want = cycleOpsOf(mergeCatalogAt(base, cycleOps(c.Fresh), time.Duration(c.MaxCarryAgeMs)*time.Millisecond, now))
	}

	f := struct {
		Comment      string             `json:"comment"`
		Carry        []carryCase        `json:"carry"`
		Advertisable []advertisableCase `json:"advertisable"`
		Merge        []mergeCase        `json:"merge"`
	}{
		Comment:      "Generated by proto/go/zs TestRegistryCycleVectors. Times are Unix ms, 0 for never; an empty list or map is an unset field, as on a fresh chain row. context_windows projects each node's model capacities. carry: a cycle's rows (ops) after the last-good capabilities of prev, the previous snapshot (null for none), are carried onto them at now_ms. advertisable: whether the node surfaces on the discovery aggregates at now_ms. merge: saved_catalog is the persisted catalog as written, decoded (proto_version floored to minor 0) and merged into fresh, a boot's chain read; max_carry_age_ms 0 or negative takes the default.",
		Carry:        carry,
		Advertisable: adv,
		Merge:        merge,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(registryCycleVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(registryCycleVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("registry cycle rules differ from %s; if the change is intended, regenerate with -update and review the diff", registryCycleVectorsPath)
	}
}
