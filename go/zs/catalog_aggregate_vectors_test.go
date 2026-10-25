/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/catalog_aggregate_vectors.json: the
// discovery aggregates a registry serves from its snapshot, each gated by
// advertisableAt. models is aggregateModels, builtin_tools aggregateBuiltinTools
// and model_details aggregateModelDetails, the cross-operator capability union
// behind /v1/models and /v1/zs/details. The TS SDK replays it against
// sdk/src/registry/aggregate.ts.
//
//	cd proto/go && go test ./zs -run TestCatalogAggregateVectors -update

import (
	"bytes"
	"encoding/json"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

const catalogAggregateVectorsPath = "../../testdata/catalog_aggregate_vectors.json"

// aggregateNode is a node as the aggregates read it: the cycle state advertisable
// gates on, and its catalog as its own /v1/zs/details advertised it. bare_models
// are listed with no capability entry, which a node carried from an older
// snapshot can have.
type aggregateNode struct {
	ID                        uint64                        `json:"id"`
	NodeID                    uint64                        `json:"node_id"`
	Reachable                 bool                          `json:"reachable"`
	Probed                    bool                          `json:"probed"`
	ReachableAsOfMs           int64                         `json:"reachable_as_of_ms"`
	Staging                   bool                          `json:"staging"`
	SignerSpendableMicroAlgos *uint64                       `json:"signer_spendable_microalgos"`
	ProtoVersion              string                        `json:"proto_version"`
	BuiltinTools              []string                      `json:"builtin_tools"`
	Models                    []inject.OperatorDetailsModel `json:"models"`
	BareModels                []string                      `json:"bare_models"`
}

func (n aggregateNode) operator() Operator {
	op := Operator{
		ID:                        n.ID,
		NodeID:                    n.NodeID,
		Reachable:                 n.Reachable,
		Probed:                    n.Probed,
		Staging:                   n.Staging,
		SignerSpendableMicroAlgos: n.SignerSpendableMicroAlgos,
		ProtoVersion:              n.ProtoVersion,
	}
	if n.ReachableAsOfMs != 0 {
		op.ReachableAsOf = time.UnixMilli(n.ReachableAsOfMs).UTC()
	}
	for _, t := range n.BuiltinTools {
		op.BuiltinTools = append(op.BuiltinTools, BuiltinToolDef{Type: t})
	}
	for _, m := range n.Models {
		op.Models = append(op.Models, m.ID)
		if op.ModelCapacities == nil {
			op.ModelCapacities = make(map[string]ModelCapacity)
		}
		op.ModelCapacities[m.ID] = modelCapacityOf(m)
	}
	op.Models = append(op.Models, n.BareModels...)
	return op
}

type aggregateCase struct {
	Name          string          `json:"name"`
	NowMs         int64           `json:"now_ms"`
	MaxCarryAgeMs int64           `json:"max_carry_age_ms"`
	AllowStaging  bool            `json:"allow_staging"`
	Nodes         []aggregateNode `json:"nodes"`
	// Models and BuiltinTools are in the aggregate's own first-seen order;
	// ModelDetails, which a Go map orders at random, is sorted by id.
	Models       []string                      `json:"models"`
	BuiltinTools []string                      `json:"builtin_tools"`
	ModelDetails []inject.OperatorDetailsModel `json:"model_details"`
}

// aggUp is a node probed up this cycle, on this build's wire.
func aggUp(id uint64, models ...inject.OperatorDetailsModel) aggregateNode {
	return aggregateNode{
		ID: id, NodeID: 1, Reachable: true, Probed: true, ReachableAsOfMs: cycleVectorNowMs,
		ProtoVersion: wire.ProtoVersion, Models: models,
	}
}

func aggregateCases() []aggregateCase {
	chat := func(id string, in, out float64) inject.OperatorDetailsModel {
		return inject.OperatorDetailsModel{ID: id, InputRateUSDPer1M: in, OutputRateUSDPer1M: out}
	}
	with := func(n aggregateNode, f func(*aggregateNode)) aggregateNode {
		f(&n)
		return n
	}
	gated := func(n aggregateNode) aggregateNode {
		return with(n, func(c *aggregateNode) { c.BuiltinTools = []string{"zs_gated_tool"} })
	}

	// Two operators serving one model, disagreeing on every merged field.
	a := inject.OperatorDetailsModel{
		ID: "m", InputRateUSDPer1M: 2, OutputRateUSDPer1M: 0,
		ContextWindow: 32768, MaxOutputTokens: 0,
		InputModalities: []string{"text"}, OutputModalities: []string{"text"},
		CacheReadRateUSDPer1M:      new(0.5),
		LongContextThresholdTokens: 200000, LongContextInputRateUSDPer1M: new(4.0),
		Reasoning: &inject.ModelReasoning{Supported: false, AllowedEfforts: []string{"low"}, DefaultEffort: "low"},
		ToolUse:   new(false), Tags: []string{"chat", "fast"},
		ImageToolRateMicroUSDC: 40000, ImageToolBaseMicroUSDC: 30000,
		ImageDefaultMicroUSDC: 0, ImageCapMicroUSDC: 90000,
	}
	b := inject.OperatorDetailsModel{
		ID: "m", InputRateUSDPer1M: 1.5, OutputRateUSDPer1M: 6,
		ContextWindow: 8192, MaxOutputTokens: 4096,
		InputModalities: []string{"text", "image"}, OutputModalities: []string{"text"},
		LongContextThresholdTokens:    128000,
		LongContextOutputRateUSDPer1M: new(12.0),
		Reasoning:                     &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}},
		Tags:                          []string{"fast", "code"},
		ImageToolRateMicroUSDC:        50000, ImageEditToolRateMicroUSDC: 60000,
		ImageDefaultMicroUSDC: 20000, ImageCapMicroUSDC: 0,
	}
	freeCache := chat("m", 3, 9)
	freeCache.CacheReadRateUSDPer1M = new(0.0)
	freeCache.ToolUse = new(true)

	imgRated := inject.OperatorDetailsModel{ID: "img", ImageRateMicroUSDC: 30000, OutputModalities: []string{"image"}}
	imgFree := inject.OperatorDetailsModel{ID: "img", ServesImageEdit: true, ImageEditRateMicroUSDC: 0, OutputModalities: []string{"image"}}
	imgEdit := inject.OperatorDetailsModel{ID: "img", ImageEditRateMicroUSDC: 25000, ImageEditDefaultMicroUSDC: 26000, ImageEditCapMicroUSDC: 80000}

	coords := func(fam, quant, variant string, params, active uint64) inject.OperatorDetailsModel {
		m := chat("q", 1, 1)
		m.Coordinates = &inject.ModelCoordinates{Family: fam, Quantization: quant, Variant: variant, Parameters: params, ActiveParameters: active}
		return m
	}
	digest := func(d string) inject.OperatorDetailsModel {
		m := chat("w", 1, 1)
		m.WeightsDigest = d
		return m
	}
	identity := func(source, canonical string) inject.OperatorDetailsModel {
		m := chat("id", 1, 1)
		m.Source, m.CanonicalID = source, canonical
		return m
	}

	// Every rate and image factor declared, scaled by k, so two nodes
	// disagree on each and the lower must win field by field.
	everyRate := func(k float64) inject.OperatorDetailsModel {
		u := func(v float64) uint64 { return uint64(v * k) }
		return inject.OperatorDetailsModel{
			ID: "all", InputRateUSDPer1M: 1 * k, OutputRateUSDPer1M: 2 * k,
			CacheReadRateUSDPer1M:            new(0.5 * k),
			LongContextThresholdTokens:       u(100000),
			LongContextInputRateUSDPer1M:     new(3 * k),
			LongContextOutputRateUSDPer1M:    new(4 * k),
			LongContextCacheReadRateUSDPer1M: new(0.75 * k),
			ImageToolRateMicroUSDC:           u(10000), ImageEditToolRateMicroUSDC: u(11000),
			ImageToolBaseMicroUSDC: u(12000), ImageEditToolBaseMicroUSDC: u(13000),
			ImageRateMicroUSDC: u(14000), ImageEditRateMicroUSDC: u(15000),
			ImageDefaultMicroUSDC: u(16000), ImageEditDefaultMicroUSDC: u(17000),
			ImageCapMicroUSDC: u(18000), ImageEditCapMicroUSDC: u(19000),
		}
	}
	// Lists repeated within one node's advertisement: the union keeps a
	// repeat it appends, as it keeps one already in the first node's list.
	repeatsA := inject.OperatorDetailsModel{
		ID: "dup", InputRateUSDPer1M: 1, OutputRateUSDPer1M: 1,
		InputModalities: []string{"text"},
		Reasoning:       &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "low"}},
	}
	repeatsB := inject.OperatorDetailsModel{
		ID: "dup", InputRateUSDPer1M: 1, OutputRateUSDPer1M: 1,
		InputModalities: []string{"text", "image", "image"},
		Reasoning:       &inject.ModelReasoning{AllowedEfforts: []string{"high", "high"}},
	}
	// Tags as operators actually write them: mixed case, padded, repeated,
	// blank, and in an order the aggregate must not inherit. U+FF21 lowercases
	// to U+FF41, which sorts before U+1F600 by code point and after it by
	// UTF-16 unit. Non-ASCII letters fold and U+00A0 trims, as both languages'
	// standard functions agree on them.
	tagged := func(id string, tags ...string) inject.OperatorDetailsModel {
		m := chat(id, 1, 1)
		m.Tags = tags
		return m
	}
	// Spelled by code point so the source carries no invisible characters.
	r := func(c rune) string { return string(c) }

	unprobed := func(agoMs int64) aggregateNode {
		return with(aggUp(9, chat("carried", 1, 1)), func(c *aggregateNode) {
			c.Reachable, c.Probed, c.ReachableAsOfMs = false, false, cycleVectorNowMs-agoMs
		})
	}

	return []aggregateCase{
		{Name: "an empty fleet lists nothing"},
		{Name: "one node lists its own catalog as advertised",
			Nodes: []aggregateNode{with(aggUp(1, a), func(c *aggregateNode) { c.BuiltinTools = []string{"zs_web_search"} })}},
		{Name: "two operators merge: modalities and tags unioned, sizing and rates the lowest declared, flags ORed",
			Nodes: []aggregateNode{aggUp(1, a), aggUp(2, b)}},
		{Name: "a free cache read beats a discounted one, and an absent one is not free",
			Nodes: []aggregateNode{aggUp(1, a), aggUp(2, freeCache), aggUp(3, chat("m", 1, 1))}},
		{Name: "image routes: any operator serving one makes the aggregate serve it, at the lowest non-zero rate",
			Nodes: []aggregateNode{aggUp(1, imgRated), aggUp(2, imgFree), aggUp(3, imgEdit)}},
		{Name: "every rate and image factor takes the lower of two declared values, whichever node declared it",
			Nodes: []aggregateNode{aggUp(1, everyRate(2)), aggUp(2, everyRate(1)), aggUp(3, everyRate(3))}},
		{Name: "a value a node repeats in a modality or effort list is kept as it repeats",
			Nodes: []aggregateNode{aggUp(1, repeatsA), aggUp(2, repeatsB)}},
		{Name: "tags fold to one lowercase entry each, trimmed, blanks dropped, in code point order",
			Nodes: []aggregateNode{
				aggUp(1, tagged("tags", "NSFW", "zeta", " code ", "", r(0xFF21), "\U0001F600", r(0xA0)+"nbsp"), tagged("blank", "", " ")),
				aggUp(2, tagged("tags", "nsfw", "Code", "code", "Uncensored", "\t", r(0xC9)), tagged("blank", "\t")),
				aggUp(3, tagged("tags")),
			}},
		{Name: "coordinates take each field's majority, and a tie omits it",
			Nodes: []aggregateNode{
				aggUp(1, coords("llama", "q4", "instruct", 8, 0)),
				aggUp(2, coords("llama", "q8", "base", 8, 2)),
				aggUp(3, coords("llama", "", "instruct", 70, 3)),
				aggUp(4, coords("qwen", "", "", 0, 0)),
			}},
		{Name: "coordinates that disagree on every field are dropped",
			Nodes: []aggregateNode{aggUp(1, coords("llama", "q4", "", 8, 0)), aggUp(2, coords("qwen", "q8", "", 7, 0))}},
		{Name: "one published weights digest is the consensus; an operator publishing none breaks nothing",
			Nodes: []aggregateNode{aggUp(1, digest("sha256:aa")), aggUp(2, digest("sha256:aa")), aggUp(3, digest(""))}},
		{Name: "two distinct weights digests are a mismatch with no consensus",
			Nodes: []aggregateNode{aggUp(1, digest("sha256:aa")), aggUp(2, digest("sha256:bb")), aggUp(3, digest("sha256:aa"))}},
		{Name: "sources agree across revision and case, and the first spelling is kept; canonical_id rides only without a source",
			Nodes: []aggregateNode{aggUp(1, identity("hf:Org/Model@abc", "")), aggUp(2, identity("hf:org/model", "org/model")), aggUp(3, identity("", "org/model"))}},
		{Name: "sources naming different repos have no consensus, and the canonical then rides",
			Nodes: []aggregateNode{aggUp(1, identity("hf:org/a", "model-x")), aggUp(2, identity("hf:org/b", "model-x"))}},
		{Name: "canonicals that disagree have no consensus",
			Nodes: []aggregateNode{aggUp(1, identity("", "model-x")), aggUp(2, identity("", "model-y"))}},
		{Name: "models and tools keep the order first seen across nodes, each tool type once",
			Nodes: []aggregateNode{
				with(aggUp(1, chat("b", 1, 1), chat("a", 1, 1)), func(c *aggregateNode) { c.BuiltinTools = []string{"zs_web_read", "zs_web_search"} }),
				with(aggUp(2, chat("c", 1, 1), chat("a", 2, 2)), func(c *aggregateNode) { c.BuiltinTools = []string{"zs_web_search", "zs_image_search"} }),
			}},
		{Name: "a model listed with no capability entry is listed bare",
			Nodes: []aggregateNode{with(aggUp(1, chat("rich", 1, 1)), func(c *aggregateNode) { c.BareModels = []string{"bare"} })}},
		{Name: "a staging node the payer has not opted in to contributes nothing",
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), gated(with(aggUp(2, chat("staged", 1, 1)), func(c *aggregateNode) { c.Staging = true }))}},
		{Name: "a staging node the payer opted in to contributes", AllowStaging: true,
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), gated(with(aggUp(2, chat("staged", 1, 1)), func(c *aggregateNode) { c.Staging = true }))}},
		{Name: "a node on another wire major contributes nothing",
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), gated(with(aggUp(2, chat("m", 0.1, 0.1)), func(c *aggregateNode) { c.ProtoVersion = otherWireMajor() }))}},
		{Name: "a node whose signer is below the routing floor contributes nothing",
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), gated(with(aggUp(2, chat("m", 0.1, 0.1)), func(c *aggregateNode) {
				c.SignerSpendableMicroAlgos = cycleU64(selection.MinSignerSpendableMicroAlgos - 1)
			}))}},
		{Name: "a node probed down this cycle contributes nothing",
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), gated(with(aggUp(2, chat("m", 0.1, 0.1)), func(c *aggregateNode) { c.Reachable = false }))}},
		{Name: "an unprobed node inside the carry window contributes its carried catalog",
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), unprobed(10 * cycleMinuteMs)}},
		{Name: "an unprobed node exactly at the carry window's edge contributes nothing",
			Nodes: []aggregateNode{aggUp(1, chat("m", 1, 1)), unprobed(defaultCarryMs)}},
	}
}

func TestCatalogAggregateVectors(t *testing.T) {
	now := time.UnixMilli(cycleVectorNowMs)
	cases := aggregateCases()
	for i := range cases {
		c := &cases[i]
		c.NowMs, c.MaxCarryAgeMs = cycleVectorNowMs, defaultCarryMs
		if c.Nodes == nil {
			c.Nodes = []aggregateNode{}
		}
		ops := make([]Operator, len(c.Nodes))
		for j, n := range c.Nodes {
			if n.BuiltinTools == nil {
				c.Nodes[j].BuiltinTools = []string{}
			}
			if n.Models == nil {
				c.Nodes[j].Models = []inject.OperatorDetailsModel{}
			}
			if n.BareModels == nil {
				c.Nodes[j].BareModels = []string{}
			}
			ops[j] = n.operator()
		}
		keep := func(op Operator) bool { return advertisableAt(op, now, c.AllowStaging, DefaultMaxCarryAge) }

		c.Models = append([]string{}, aggregateModels(ops, keep)...)
		c.BuiltinTools = []string{}
		for _, td := range aggregateBuiltinTools(ops, keep) {
			c.BuiltinTools = append(c.BuiltinTools, td.Type)
		}
		c.ModelDetails = append([]inject.OperatorDetailsModel{}, aggregateModelDetails(ops, keep)...)
		sort.Slice(c.ModelDetails, func(i, j int) bool { return c.ModelDetails[i].ID < c.ModelDetails[j].ID })
	}

	f := struct {
		Comment string          `json:"comment"`
		Cases   []aggregateCase `json:"cases"`
	}{
		Comment: "Generated by proto/go/zs TestCatalogAggregateVectors. Each node's catalog is its /v1/zs/details models as advertised; bare_models are listed with no capability entry. A node contributes only when advertisable at now_ms (registry_cycle_vectors.json pins that gate). models and builtin_tools (types) are in first-seen order; model_details is the cross-operator capability union, sorted by id.",
		Cases:   cases,
	}
	out, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(catalogAggregateVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(catalogAggregateVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("catalog aggregates differ from %s; if the change is intended, regenerate with -update and review the diff", catalogAggregateVectorsPath)
	}
}
