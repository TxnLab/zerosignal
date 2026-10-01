/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection_test

// Cross-impl parity test for the selection policy. Generates / verifies
// proto/testdata/selection_vectors.json — a language-neutral fixture pinning
// the ordered target candidates, the relay pick, and the diagnostics produced
// by SelectTargets / SelectRelay for a battery of fixed inputs. proto/ts loads
// the same file and asserts its TypeScript port produces identical results, so
// any drift between the Go and TS selection logic fails on both sides.
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./selection -run TestSelectionVectors -update
//
// Without -update, this asserts the on-disk file matches current Go output.

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/selection_vectors.json")

const vectorsPath = "../../testdata/selection_vectors.json"

type targetExpected struct {
	OperatorIDs []uint64              `json:"operator_ids"`
	NodeIDs     []uint64              `json:"node_ids"`
	Diagnostics selection.Diagnostics `json:"diagnostics"`
}

type targetCase struct {
	Name        string                `json:"name"`
	Operators   []selection.Operator  `json:"operators"`
	Constraints selection.Constraints `json:"constraints"`
	Preferred   *selection.Operator   `json:"preferred,omitempty"`
	Expected    targetExpected        `json:"expected"`
}

type relayExpected struct {
	RelayID *uint64 `json:"relay_id,omitempty"`
	NoRelay bool    `json:"no_relay"`
}

type relayCase struct {
	Name      string               `json:"name"`
	Operators []selection.Operator `json:"operators"`
	TargetID  uint64               `json:"target_id"`
	Seed      uint64               `json:"seed"`
	Expected  relayExpected        `json:"expected"`
}

// deriveCase pins the pure DeriveMaxOutput function (inputs → output) so the Go
// and TS implementations agree on the per-operator reservation independently of
// SelectTargets — the proxy and client call it directly on the reserve leg.
type deriveCase struct {
	Name          string `json:"name"`
	ContextWindow uint64 `json:"context_window"`
	DeclaredMax   uint64 `json:"declared_max"`
	BaseCeiling   uint64 `json:"base_ceiling"`
	Expected      uint64 `json:"expected"`
}

type selectionVectorsFile struct {
	Version     int          `json:"version"`
	Comment     string       `json:"comment"`
	TargetCases []targetCase `json:"target_cases"`
	RelayCases  []relayCase  `json:"relay_cases"`
	DeriveCases []deriveCase `json:"derive_cases"`
}

// baseOp is a model-"m1"-serving, reachable, current-version operator with no
// declared capacity (unbounded) and no tools. Cases tweak fields from here.
func baseOp(id uint64, owner string) selection.Operator {
	return selection.Operator{
		ID:              id,
		OwnerAddr:       owner,
		BaseURL:         fmt.Sprintf("https://op%d.example", id),
		ProtoVersion:    wire.ProtoVersion,
		Reachable:       true,
		Models:          []string{"m1"},
		ModelCapacities: map[string]selection.ModelCapacity{},
		BuiltinTools:    []string{},
	}
}

func chatConstraints() selection.Constraints {
	return selection.Constraints{
		Model:           "m1",
		InputTokens:     100,
		MaxOutputTokens: 100,
		Endpoint:        selection.EndpointChatCompletions,
		AffinityPolicy:  selection.AffinityNone,
		// Written explicitly, even though nil would resolve to the same true,
		// so every vector carries the field and the TS mirror is pinned on the
		// value rather than on its own default. Only matters when Order is set;
		// the order cases that pin set it false.
		AllowFallbacks: new(true),
	}
}

// opRef builds a node-specific caller ref; allRef builds an operator-only
// (match-all-nodes) ref — the two OperatorRef forms the caller lists use.
func opRef(operatorID, nodeID uint64) selection.OperatorRef {
	return selection.OperatorRef{OperatorID: operatorID, NodeID: nodeID}
}
func allRef(operatorID uint64) selection.OperatorRef {
	return selection.OperatorRef{OperatorID: operatorID, MatchAllNodes: true}
}

func uptr(v uint64) *uint64 { return &v }

// deriveConstraints builds chat constraints for the caller-omitted-max_output
// path: MaxOutputUnspecified switches the sizing filter to per-operator
// derivation against baseCeiling.
//
// MaxOutputTokens is deliberately NON-ZERO here even though the caller sent no
// max_output. That mirrors production — the proxy keeps its flat estimate
// populated while DeriveMaxOutput is set, as the describeMiss display value —
// and it is what makes these vectors able to tell the two branches apart. With
// it left at 0, `Flat` and the derived value agree on every case by
// coincidence, and a "let the flat value win when it's set" edit produces
// identical output on every fixture while silently reverting per-operator
// derivation to one guessed ceiling for the whole pool. That disagreement
// between the filter and the escrow has no failover; it is discovered after
// escrow.open.
func deriveConstraints(inputTokens, baseCeiling uint64) selection.Constraints {
	c := chatConstraints()
	c.InputTokens = inputTokens
	c.MaxOutputTokens = 32000
	c.MaxOutputUnspecified = true
	c.MaxOutputCeiling = baseCeiling
	return c
}

func buildTargetCases() []targetCase {
	cases := []targetCase{
		{
			Name:        "basic_three",
			Operators:   []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: chatConstraints(),
		},
		{
			Name: "sizing_miss",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 100}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// Per-operator input sizing: a small-window operator that the v1
			// measurement excludes but the v2 measurement admits. Both nodes
			// declare the same window; only the 9.2 one gets filtered on the
			// tighter number, which is the whole point — an image request must
			// stop being routed away from operators that can serve it.
			Name: "input_tokens_v2_per_operator",
			Operators: func() []selection.Operator {
				old, new := baseOp(1, "A"), baseOp(2, "B")
				old.ProtoVersion = "9.1"
				new.ProtoVersion = "9.2"
				cap := map[string]selection.ModelCapacity{"m1": {ContextWindow: 3000}}
				old.ModelCapacities, new.ModelCapacities = cap, cap
				return []selection.Operator{old, new}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				// v1 measures an image at the 2048x2048 fallback, v2 at its real
				// size. 2950 + 100 exceeds the 3000 window (FitsContextWindow is
				// inclusive); 300 + 100 does not.
				c.InputTokens, c.InputTokensV2, c.MaxOutputTokens = 2950, 300, 100
				return c
			}(),
		},
		{
			// The same constraints with no v2 measurement supplied: every
			// operator falls back to InputTokens, so BOTH are excluded. Pins that
			// the field is opt-in and absent means pre-9.2 behaviour.
			Name: "input_tokens_v2_absent_filters_on_v1",
			Operators: func() []selection.Operator {
				old, new := baseOp(1, "A"), baseOp(2, "B")
				old.ProtoVersion, new.ProtoVersion = "9.1", "9.2"
				cap := map[string]selection.ModelCapacity{"m1": {ContextWindow: 3000}}
				old.ModelCapacities, new.ModelCapacities = cap, cap
				return []selection.Operator{old, new}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.MaxOutputTokens = 2950, 100
				return c
			}(),
		},
		{
			Name: "version_blocked",
			Operators: func() []selection.Operator {
				ops := []selection.Operator{baseOp(1, "A"), baseOp(2, "B")}
				for i := range ops {
					ops[i].ProtoVersion = "1.0"
				}
				return ops
			}(),
			Constraints: chatConstraints(),
		},
		{
			Name:        "tee_blocked",
			Operators:   []selection.Operator{baseOp(1, "A"), baseOp(2, "B")},
			Constraints: func() selection.Constraints { c := chatConstraints(); c.RequireTEE = true; return c }(),
		},
		{
			Name: "tee_filter",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.TEEAttested = true
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints { c := chatConstraints(); c.RequireTEE = true; return c }(),
		},
		{
			// All nodes are staging and the caller didn't opt in → StagingBlocked
			// (the model is served, just only by nodes held out of production).
			Name: "staging_blocked",
			Operators: func() []selection.Operator {
				ops := []selection.Operator{baseOp(1, "A"), baseOp(2, "B")}
				for i := range ops {
					ops[i].Staging = true
				}
				return ops
			}(),
			Constraints: chatConstraints(),
		},
		{
			// Default routing drops the staging node (op 2) and keeps production.
			Name: "staging_filter",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.Staging = true
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// AllowStaging keeps the staging node alongside production (no
			// exclusion; normal price/id ordering applies).
			Name: "staging_allowed",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.Staging = true
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints { c := chatConstraints(); c.AllowStaging = true; return c }(),
		},
		{
			// The floor is exclusive on the low side: op2 one microAlgo short is
			// dropped, op3 exactly at the floor is kept, op1 (never read) is kept.
			Name: "signer_underfunded_filter",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.SignerSpendableMicroAlgos = uptr(selection.MinSignerSpendableMicroAlgos - 1)
				op3 := baseOp(3, "C")
				op3.SignerSpendableMicroAlgos = uptr(selection.MinSignerSpendableMicroAlgos)
				return []selection.Operator{baseOp(1, "A"), op2, op3}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// A zero reading is a real reading, not "unknown" — the TS mirror must
			// not read it as falsy.
			Name: "signer_underfunded_zero_dropped",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.SignerSpendableMicroAlgos = uptr(0)
				return []selection.Operator{baseOp(1, "A"), op2}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// Every serving node is known-broke → SignerUnderfundedBlocked, with
			// RegistryCount still reporting that the model IS served.
			Name: "signer_underfunded_blocked",
			Operators: func() []selection.Operator {
				ops := []selection.Operator{baseOp(1, "A"), baseOp(2, "B")}
				for i := range ops {
					ops[i].SignerSpendableMicroAlgos = uptr(1_000_000)
				}
				return ops
			}(),
			Constraints: chatConstraints(),
		},
		{
			// Staging runs first, so a pool where every node is both staging and
			// broke reports the staging cause (the one the caller can act on). A
			// mixed pool — a broke production node beside a funded staging one —
			// reports the funding cause instead; the filters are sequential.
			Name: "signer_underfunded_staging_precedence",
			Operators: func() []selection.Operator {
				ops := []selection.Operator{baseOp(1, "A"), baseOp(2, "B")}
				for i := range ops {
					ops[i].Staging = true
					ops[i].SignerSpendableMicroAlgos = uptr(0)
				}
				return ops
			}(),
			Constraints: chatConstraints(),
		},
		{
			// Funding runs before max_price: op2 is cheap but broke, op1 funded
			// but over the cap. Funding-first drops op2, then price drops op1 →
			// PriceBlocked. The reverse order would report SignerUnderfundedBlocked.
			Name: "signer_underfunded_before_price",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 9}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1}}
				op2.SignerSpendableMicroAlgos = uptr(0)
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.MaxInputUSDPer1M = 5
				return c
			}(),
		},
		{
			// A tool loop pinned (prefer) to a node that has since drained: the
			// pin yields instead of floating the broke node back to the front.
			Name: "signer_underfunded_affinity_prefer_not_floated",
			Operators: func() []selection.Operator {
				op3 := baseOp(3, "C")
				op3.SignerSpendableMicroAlgos = uptr(0)
				return []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), op3}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityPrefer
				return c
			}(),
			Preferred: func() *selection.Operator {
				o := baseOp(3, "C")
				o.SignerSpendableMicroAlgos = uptr(0)
				return &o
			}(),
		},
		{
			// Same drain under strict: blocked with the funding cause, not
			// AffinityBlocked (which the proxy reports as a sizing conflict).
			Name: "signer_underfunded_affinity_strict_blocked",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.SignerSpendableMicroAlgos = uptr(0)
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator {
				o := baseOp(2, "B")
				o.SignerSpendableMicroAlgos = uptr(0)
				return &o
			}(),
		},
		{
			// Broke AND outgrown under strict: the permanent fit refusal wins over
			// the retryable funding one, so the caller isn't sent into a backoff
			// that ends in the same 400.
			Name:      "signer_underfunded_affinity_strict_nonfitting",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator {
				o := baseOp(2, "B")
				o.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 100}}
				o.SignerSpendableMicroAlgos = uptr(0)
				return &o
			}(),
		},
		{
			// Broke AND excluded by the caller's `only` under strict: the caller's
			// own conflict is reported, not the funding one.
			Name:      "signer_underfunded_affinity_strict_ref_excluded",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Only = []selection.OperatorRef{allRef(1)}
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator {
				o := baseOp(3, "C")
				o.SignerSpendableMicroAlgos = uptr(0)
				return &o
			}(),
		},
		{
			// An all-broke pool stops at the funding step: the strict pin to a
			// funded staging node the caller didn't opt into must not be
			// resurrected by the affinity step after it.
			Name: "signer_underfunded_blocks_before_affinity",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.SignerSpendableMicroAlgos = uptr(0)
				op9 := baseOp(9, "I")
				op9.Staging = true
				return []selection.Operator{op2, op9}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(9, "I"); o.Staging = true; return &o }(),
		},
		{
			// An all-broke pool reports the funding cause alone; the later tool
			// step never sees the empty list.
			Name: "signer_underfunded_blocks_before_tools",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.SignerSpendableMicroAlgos = uptr(0)
				return []selection.Operator{op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.RequestedTools = []string{"zs_web_search"}
				c.RequireTools = true
				return c
			}(),
		},
		{
			Name: "tool_partition",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.BuiltinTools = []string{"zs_web_search"}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.RequestedTools = []string{"zs_web_search"}
				return c
			}(),
		},
		{
			Name:      "affinity_prefer",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityPrefer
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); return &o }(),
		},
		{
			// Operator 3 runs two nodes (node 1, node 2); preferred is the
			// exact node (3, 1). The fix: the preferred node leads, and the
			// SIBLING node (3, 2) stays in the fallback tail — keying the
			// prefer-dedup by (id, node_id), not id, so it isn't dropped.
			Name: "affinity_prefer_multinode",
			Operators: []selection.Operator{
				baseOp(1, "A"),
				baseOp(2, "B"),
				func() selection.Operator { o := baseOp(3, "C"); o.NodeID = 1; return o }(),
				func() selection.Operator { o := baseOp(3, "C"); o.NodeID = 2; return o }(),
			},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityPrefer
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); o.NodeID = 1; return &o }(),
		},
		{
			Name:      "affinity_strict_fit",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(2, "B"); return &o }(),
		},
		{
			Name:      "affinity_strict_block",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator {
				o := baseOp(2, "B")
				o.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 100}}
				return &o
			}(),
		},
		{
			Name:        "registry_empty",
			Operators:   []selection.Operator{baseOp(1, "A"), baseOp(2, "B")},
			Constraints: func() selection.Constraints { c := chatConstraints(); c.Model = "mX"; return c }(),
		},
		{
			Name:      "image_unsupported",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Endpoint = selection.EndpointImages
				return c
			}(),
		},
		{
			Name: "image_ok",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Endpoint = selection.EndpointImages
				return c
			}(),
		},
		{
			// Image-endpoint price sort: ordered by the per-image microUSDC rate,
			// not the token rates (which are 0 on an image model and would rank
			// every candidate "undeclared"). op3 declares a FREE route (rate 0)
			// and must rank FIRST — the serves-image filter already proved it
			// serves, so 0 is free, not undeclared.
			Name: "image_price_sort",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 90}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 50}}
				op3 := baseOp(3, "C")
				op3.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 0}}
				return []selection.Operator{op1, op2, op3}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Endpoint = selection.EndpointImages
				return c
			}(),
		},
		{
			// Edit route sorts on its own rate. op1 is cheaper to generate but
			// dearer to edit, so the edit endpoint must invert the gen ordering.
			Name: "image_edit_price_sort",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageEdit: true, ImageRateMicroUSDC: 10, ImageEditRateMicroUSDC: 80}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageEdit: true, ImageRateMicroUSDC: 99, ImageEditRateMicroUSDC: 20}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Endpoint = selection.EndpointImageEdits
				return c
			}(),
		},
		{
			// A caller's per-1M-TOKEN ceiling must not filter an image-endpoint
			// request: image models carry zero token rates, so applying it would
			// PriceBlock every operator. Both survive, ordered by image rate.
			Name: "image_token_ceiling_ignored",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 70}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 30}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Endpoint = selection.EndpointImages
				c.MaxInputUSDPer1M = 1
				c.MaxOutputUSDPer1M = 1
				return c
			}(),
		},
		{
			// Price base sort: cheapest EXPECTED REQUEST COST first, undeclared
			// (0 on either axis) last. At 100 in / 100 out: op1 = 9·100 + 1·100 =
			// 1000, op2 = 5·100 + 10·100 = 1500.
			Name: "price_sort",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 9, OutputUSDPer1M: 1}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 5, OutputUSDPer1M: 10}}
				op3 := baseOp(3, "C") // undeclared rates → sorts last
				return []selection.Operator{op1, op2, op3}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// Fractional price axis: pins the float arithmetic across Go↔TS so a
			// future one-sided refactor (e.g. truncating rates to microUSDC ints,
			// or reassociating the cost expression) breaks the vector. At 100/100:
			// op1 = 1000, op2 = 575, op3 = 1075.
			Name: "price_sort_fractional",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 2.5, OutputUSDPer1M: 7.5}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 2.5, OutputUSDPer1M: 3.25}}
				op3 := baseOp(3, "C")
				op3.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1.75, OutputUSDPer1M: 9}}
				return []selection.Operator{op1, op2, op3}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// The regression the cost comparison replaced. Axis-by-axis returned on
			// the first differing axis, so op1's cheaper INPUT rate won every
			// request. On this output-heavy one (100 in / 10k out) op1 costs
			// 0.01·100 + 50·10000 = 500001 against op2's 0.02·100 + 0.05·10000 =
			// 502 — a thousandfold difference the old ordering inverted.
			Name: "price_sort_output_heavy",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 0.01, OutputUSDPer1M: 50}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 0.02, OutputUSDPer1M: 0.05}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.MaxOutputTokens = 100, 10_000
				return c
			}(),
		},
		{
			// The caller's stated max_output is the output weight; with 10 output
			// tokens against 1000 input, op1's cheap input rate wins:
			// op1 = 1·1000 + 100·10 = 2000, op2 = 10·1000 + 1·10 = 10010.
			// price_sort_output_weight_derived is the same pair with the weight
			// unstated, and must come out the other way round.
			Name: "price_sort_output_weight_stated",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 100}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 10, OutputUSDPer1M: 1}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.MaxOutputTokens = 1_000, 10
				return c
			}(),
		},
		{
			// Unstated max_output falls back to outputNormTokens (1000), which
			// flips the same pair: op1 = 1·1000 + 100·1000 = 101000, op2 =
			// 10·1000 + 1·1000 = 11000. Pins that the derived branch does NOT use
			// the per-operator effectiveMaxOutput, which would price the identical
			// request differently for each operator.
			Name: "price_sort_output_weight_derived",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 100}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 10, OutputUSDPer1M: 1}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.MaxOutputTokens = 1_000, 0
				c.MaxOutputUnspecified = true
				c.MaxOutputCeiling = 32_768
				return c
			}(),
		},
		{
			// Pins the EXACT value of outputNormTokens across Go↔TS, which the
			// ordering cases above can't: they stay correct for any norm in a wide
			// band, so a one-sided drift to 999 or 1024 would pass them all. Here
			// the two operators cost exactly the same at 500 input tokens IFF the
			// norm is 1000 (op1 = 2·500 + 0.5·1000 = 1500, op2 = 1·500 + 1·1000 =
			// 1500), so the result is the id-order tiebreak [1, 2]. At any smaller
			// norm op2 is strictly cheaper and the order inverts.
			Name: "price_sort_output_norm_boundary",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 2, OutputUSDPer1M: 0.5}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 1}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.MaxOutputTokens = 500, 0
				c.MaxOutputUnspecified = true
				c.MaxOutputCeiling = 32_768
				return c
			}(),
		},
		{
			// Half a price list can't be priced: op2 declares a very cheap input
			// rate and no output rate, so its cost is +Inf and it sorts LAST.
			// Axis-by-axis used to rank it first on the input axis alone.
			Name: "price_sort_partial_declaration",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 100, OutputUSDPer1M: 100}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: chatConstraints(),
		},
		{
			// A caller that measured NOTHING still gets input pricing. Both client
			// entry points size this way on purpose (the model picker and the
			// dispatch candidate list, `input_tokens: 0`), so without the norm the
			// input term vanishes and op1's 100x input rate is free: it would win
			// on its cheaper output rate alone, and the client would order this
			// pair the opposite way from the proxy, which measures. At the norm:
			// op1 = 100·1000 + 1·1000 = 101000, op2 = 1·1000 + 2·1000 = 3000.
			Name: "price_sort_unmeasured_input_still_priced",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 100, OutputUSDPer1M: 1}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 2}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.InputTokensV2, c.MaxOutputTokens = 0, 0, 0
				return c
			}(),
		},
		{
			// Pins the EXACT value of inputNormTokens, which the case above can't:
			// that one stays correct for any norm. Here the two cost the same at
			// 500 stated output tokens IFF the norm is 1000 (op1 = 0.5·1000 +
			// 2·500 = 1500, op2 = 1·1000 + 1·500 = 1500), so the result is the
			// id-order tiebreak [1, 2]. At any LARGER norm op2 is strictly cheaper
			// and the order inverts, so a one-sided drift upward breaks the vector.
			Name: "price_sort_input_norm_boundary",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 0.5, OutputUSDPer1M: 2}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 1}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.InputTokensV2, c.MaxOutputTokens = 0, 0, 500
				return c
			}(),
		},
		{
			// The input weight is REQUEST-level, not per-operator. These two
			// advertise identical rates and differ only in proto version, so
			// weighing by effectiveInputTokens would measure op1 at v1's 2950 and
			// op2 at v2's 300 and rank op2 an order of magnitude cheaper — on a
			// reserve bound, when the bill is the same consumed tokens either way.
			// Both must price at v2's 300 and fall to the id tiebreak. Listed
			// op2-first so the pre-fix order [2, 1] isn't also the input order.
			// Contrast input_tokens_v2_per_operator, where the same split IS
			// per-operator: that's the fit filter, which must agree with what each
			// operator's escrow locks.
			Name: "price_sort_input_weight_is_request_level",
			Operators: func() []selection.Operator {
				op1, op2 := baseOp(1, "A"), baseOp(2, "B")
				op1.ProtoVersion, op2.ProtoVersion = "9.1", "9.2"
				caps := map[string]selection.ModelCapacity{"m1": {ContextWindow: 100_000, InputUSDPer1M: 10, OutputUSDPer1M: 10}}
				op1.ModelCapacities, op2.ModelCapacities = caps, caps
				return []selection.Operator{op2, op1}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens, c.InputTokensV2, c.MaxOutputTokens = 2950, 300, 100
				return c
			}(),
		},
		{
			// In-loop image-tool partition: with a gen budget, the tool-capable
			// operator (op2) is preferred over a cheaper toolless one (op1),
			// since the partition dominates the price sort.
			Name: "image_tool_partition",
			Operators: func() []selection.Operator {
				// Both axes declared, so the two are genuinely price-ordered
				// (a missing axis prices as +Inf and the partition would be
				// dominating a tie rather than a price advantage).
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 1}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 100, OutputUSDPer1M: 100, OffersImageGenTool: true}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Endpoint = selection.EndpointResponses
				c.ImageToolGenBudget = 2
				return c
			}(),
		},
		{
			// Caller `only` allowlist: only op2 survives the model-serving pool.
			Name:      "only_allowlist",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Only = []selection.OperatorRef{allRef(2)}
				return c
			}(),
		},
		{
			// `only` matches nobody serving the model → ProviderPinBlocked (NOT
			// RegistryCount==0; operators do advertise m1, the pin excluded them).
			Name:      "only_pin_blocked",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Only = []selection.OperatorRef{allRef(99)}
				return c
			}(),
		},
		{
			// `ignore` denylist drops op2; op1/op3 remain (price-tie → id order).
			Name:      "ignore_denylist",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Ignore = []selection.OperatorRef{allRef(2)}
				return c
			}(),
		},
		{
			// `order` with fallbacks: op3 floats to front, the rest follow in
			// their prior (price/id) order.
			Name:      "order_prefer_fallback",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(3)}
				return c
			}(),
		},
		{
			// `order` with AllowFallbacks UNSET — the caller who sends
			// provider.order and omits allow_fallbacks. It must stay a soft
			// reorder: op3 floats to the front, op1/op2 follow, nothing is
			// dropped and ProviderPinBlocked stays false.
			//
			// This is the one case that pins the default rather than the field.
			// Every other vector writes allow_fallbacks explicitly, so the Go
			// nil ⇒ true accessor and the TS `?? true` were both free to invert
			// — turning a preference into a hard pin, surfacing as a 503
			// no_pinned_operator instead of a route, in both languages at once.
			// The emitted vector deliberately OMITS the key, which is what
			// exercises the TS side's default.
			Name:      "order_soft_default_unset",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(3)}
				c.AllowFallbacks = nil
				return c
			}(),
		},
		{
			// `order` + AllowFallbacks=false: pin to exactly op3, drop the tail.
			Name:      "order_strict_pin",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(3)}
				c.AllowFallbacks = new(false)
				return c
			}(),
		},
		{
			// `order` + AllowFallbacks=false matching nobody → ProviderPinBlocked.
			Name:      "order_strict_block",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(99)}
				c.AllowFallbacks = new(false)
				return c
			}(),
		},
		{
			// Operator-only ref pulls ALL of op3's nodes to the front, in their
			// existing (price/id/node) order; op1/op2 follow.
			Name: "order_all_nodes_multinode",
			Operators: []selection.Operator{
				baseOp(1, "A"),
				baseOp(2, "B"),
				func() selection.Operator { o := baseOp(3, "C"); o.NodeID = 1; return o }(),
				func() selection.Operator { o := baseOp(3, "C"); o.NodeID = 2; return o }(),
			},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(3)}
				return c
			}(),
		},
		{
			// max_price input ceiling 6: op2 (5) passes; op1 (9) and op3
			// (undeclared → treated as too expensive) are dropped.
			Name: "max_price_filter",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 9, OutputUSDPer1M: 1}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 5, OutputUSDPer1M: 10}}
				op3 := baseOp(3, "C") // undeclared rates
				return []selection.Operator{op1, op2, op3}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.MaxInputUSDPer1M = 6
				return c
			}(),
		},
		{
			// max_price ceiling below every advertised rate → PriceBlocked.
			Name: "max_price_block",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 9}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 5}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.MaxInputUSDPer1M = 1
				return c
			}(),
		},
		{
			// require_tools turns the tool partition into a hard filter: only op2
			// advertises the requested tool, so it's the only survivor.
			Name: "require_tools_filter",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.BuiltinTools = []string{"zs_web_search"}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.RequestedTools = []string{"zs_web_search"}
				c.RequireTools = true
				return c
			}(),
		},
		{
			// require_tools and nobody advertises the tool → ToolUnsupported.
			Name:      "require_tools_block",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.RequestedTools = []string{"zs_web_search"}
				c.RequireTools = true
				return c
			}(),
		},
		{
			// `only` excludes the affinity-preferred op3 under PREFER: the soft
			// preference yields to the hard allowlist → just op1, no block.
			Name:      "only_affinity_prefer_yield",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Only = []selection.OperatorRef{allRef(1)}
				c.AffinityPolicy = selection.AffinityPrefer
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); return &o }(),
		},
		{
			// `only` excludes the affinity-preferred op3 under STRICT: a hard
			// conflict the caller must resolve → AffinityBlocked.
			Name:      "only_affinity_strict_block",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Only = []selection.OperatorRef{allRef(1)}
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); return &o }(),
		},
		{
			// Precedence affinity > caller-order under a SOFT (fallbacks) order:
			// order pins op1 to the front, then the affinity-preferred op3 floats
			// ahead of it → [op3, op1, op2]. Locks "a continuation pin leads over
			// a fallbacks-allowed order".
			Name:      "order_with_affinity_prefer",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(1)}
				c.AffinityPolicy = selection.AffinityPrefer
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); return &o }(),
		},
		{
			// HARD (no-fallback) order naming op1 but NOT the affinity-preferred
			// op3, under PREFER. The order is a hard pin, so the soft affinity
			// must YIELD rather than resurrect the excluded op3 → [op1]. Guards
			// the affinity-vs-no-fallback-order fix: before it, prefer floated op3
			// (excluded by the order) back to the front.
			Name:      "order_strict_affinity_prefer_yield",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(1)}
				c.AllowFallbacks = new(false)
				c.AffinityPolicy = selection.AffinityPrefer
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); return &o }(),
		},
		{
			// Same hard order under STRICT affinity: two hard constraints collide
			// (the order admits only op1; the continuation lives on op3) →
			// AffinityBlocked, NOT a silent route to the excluded op3. Before the
			// fix this returned [op3], overriding the caller's no-fallback order.
			Name:      "order_strict_affinity_strict_block",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Order = []selection.OperatorRef{allRef(1)}
				c.AllowFallbacks = new(false)
				c.AffinityPolicy = selection.AffinityStrict
				return c
			}(),
			Preferred: func() *selection.Operator { o := baseOp(3, "C"); return &o }(),
		},
		{
			// Node-specific ignore: op3 runs nodes 1 and 2; ignoring (3,1) drops
			// only that node, leaving the sibling (3,2) eligible. Exercises
			// node-granular matching (the allRef cases only cover operator-wide).
			Name: "ignore_node_specific",
			Operators: []selection.Operator{
				baseOp(1, "A"),
				baseOp(2, "B"),
				func() selection.Operator { o := baseOp(3, "C"); o.NodeID = 1; return o }(),
				func() selection.Operator { o := baseOp(3, "C"); o.NodeID = 2; return o }(),
			},
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.Ignore = []selection.OperatorRef{opRef(3, 1)}
				return c
			}(),
		},
		{
			// max_price OUTPUT axis: op1's output rate (20) exceeds the ceiling
			// (5) and is dropped; op2 (output 3) passes. No input ceiling set.
			Name: "max_price_output_axis",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 20}}
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 3}}
				return []selection.Operator{op1, op2}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.MaxOutputUSDPer1M = 5
				return c
			}(),
		},
		{
			// Derive mode: caller omitted max_output. op2 declares a small window
			// (4096); at a flat 8192 ceiling it would be dropped (100+8192>4096),
			// but the per-operator derivation reserves ctx/4=1024 for it, so
			// 100+1024<=4096 fits and all three survive. This is the small-window
			// operator the proportionate fallback exists to keep.
			Name: "derive_small_window_fits",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 4096}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: deriveConstraints(100, 8192),
		},
		{
			// The SAME small-window op2 under the OLD flat behavior (caller
			// unspecified is NOT set, a flat 8192 is charged): 100+8192>4096 drops
			// op2 as a sizing miss. Documents the contrast the derive mode fixes.
			Name: "derive_flat_would_block",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 4096}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: func() selection.Constraints {
				c := chatConstraints()
				c.InputTokens = 100
				c.MaxOutputTokens = 8192
				return c
			}(),
		},
		{
			// Declared max_output_tokens is authoritative over the proportionate
			// slice: op2 declares window 4096 AND max_output 4000. Derivation
			// returns the declared 4000 (not ctx/4=1024), so 200+4000>4096 drops
			// it. Proves DeriveMaxOutput takes the declared cap verbatim — if it
			// wrongly used ctx/4 the operator would have fit.
			Name: "derive_declared_over_proportionate_block",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 4096, MaxOutputTokens: 4000}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: deriveConstraints(200, 8192),
		},
		{
			// The shared default ceiling doesn't clamp a mid-size window's slice:
			// op2 has a 40000 window, ctx/4 = 10000, and DefaultMaxOutputCeiling
			// (32768) is well above it, so the derived reservation is the full
			// 10000 → 31000+10000>40000 drops op2. Contrast with the low-ceiling
			// sibling below, where 8192 clamps the same window's slice and it fits.
			Name: "derive_default_ceiling_headroom_block",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 40000}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: deriveConstraints(31000, selection.DefaultMaxOutputCeiling),
		},
		{
			// Same 40000 window under a low base ceiling: 8192 clamps ctx/4 (10000)
			// down to 8192, so 31000+8192<=40000 fits and op2 survives. Together
			// with the case above this pins the ceiling clamp itself.
			Name: "derive_low_ceiling_headroom_fits",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 40000}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: deriveConstraints(31000, 8192),
		},
		{
			// Identical to the case above except ReasoningSupported is set, and the
			// outcome is identical: reasoning no longer raises the ceiling (there is
			// one ceiling now, at the value the reasoning branch used). Pins
			// ModelCapacity.ReasoningSupported as dormant so a re-introduced
			// special case fails the vectors on both sides.
			Name: "derive_reasoning_no_longer_raises",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 40000, ReasoningSupported: true}}
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			Constraints: deriveConstraints(31000, 8192),
		},
	}

	for i := range cases {
		tr := selection.SelectTargets(cases[i].Operators, cases[i].Constraints, cases[i].Preferred)
		ids := make([]uint64, 0, len(tr.Operators))
		nodeIDs := make([]uint64, 0, len(tr.Operators))
		for _, op := range tr.Operators {
			ids = append(ids, op.ID)
			nodeIDs = append(nodeIDs, op.NodeID)
		}
		cases[i].Expected = targetExpected{OperatorIDs: ids, NodeIDs: nodeIDs, Diagnostics: tr.Diagnostics}
	}
	return cases
}

func buildRelayCases() []relayCase {
	cases := []relayCase{
		{
			Name:      "relay_basic_seed0",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			TargetID:  1,
			Seed:      0,
		},
		{
			Name:      "relay_basic_seed1",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "B"), baseOp(3, "C")},
			TargetID:  1,
			Seed:      1,
		},
		{
			Name:      "relay_single_operator",
			Operators: []selection.Operator{baseOp(1, "A")},
			TargetID:  1,
			Seed:      0,
		},
		{
			Name:      "relay_same_owner_excluded",
			Operators: []selection.Operator{baseOp(1, "A"), baseOp(2, "A")},
			TargetID:  1,
			Seed:      0,
		},
		{
			// Reachability is a soft preference: with a reachable peer (op3)
			// available, the unreachable op2 is NOT chosen even at seed 0
			// (reachable pool = [3]). It stays eligible only as a fallback.
			Name: "relay_prefers_reachable",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.Reachable = false
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			TargetID: 1,
			Seed:     0,
		},
		{
			// No reachable peer → fall back to the not-known-reachable set
			// rather than ErrNoRelay (the cold-start path). Eligible fallback
			// = [2,3] → seed 0 → 2.
			Name: "relay_all_unreachable_fallback",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.Reachable = false
				op3 := baseOp(3, "C")
				op3.Reachable = false
				return []selection.Operator{baseOp(1, "A"), op2, op3}
			}(),
			TargetID: 1,
			Seed:     0,
		},
		{
			Name: "relay_version_excluded",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.ProtoVersion = "1.0"
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			TargetID: 1,
			Seed:     0,
		},
		{
			// Signer funding is a TARGET gate only: a relay pays no fee, so a
			// broke node stays relay-eligible. Eligible = [2,3] → seed 0 → 2,
			// the broke one.
			Name: "relay_underfunded_still_eligible",
			Operators: func() []selection.Operator {
				op2 := baseOp(2, "B")
				op2.SignerSpendableMicroAlgos = uptr(0)
				return []selection.Operator{baseOp(1, "A"), op2, baseOp(3, "C")}
			}(),
			TargetID: 1,
			Seed:     0,
		},
		{
			// Public-IP /16 diversity: op2 shares the target's /16 (203.0.*)
			// and is excluded; op3 is in a different /16 (203.1.*) and is the
			// only eligible relay. Exercises the diverseSubnet exclusion branch
			// — every hostname case treats /16 as unknowable. Pins the Go↔TS
			// octet comparison.
			Name: "relay_public_subnet_excluded",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.BaseURL = "https://203.0.113.5"
				op2 := baseOp(2, "B")
				op2.BaseURL = "https://203.0.200.9"
				op3 := baseOp(3, "C")
				op3.BaseURL = "https://203.1.0.9"
				return []selection.Operator{op1, op2, op3}
			}(),
			TargetID: 1,
			Seed:     0,
		},
		{
			// Private-IP /16 is NOT excluded (same-subnet is the norm on a
			// localnet), so op2 stays eligible despite sharing the target's
			// 10.0.* /16. Pins the Go↔TS isPublicIPv4 logic — the bit most
			// likely to drift between net.IP.IsPrivate() and the ts reimpl.
			Name: "relay_private_subnet_eligible",
			Operators: func() []selection.Operator {
				op1 := baseOp(1, "A")
				op1.BaseURL = "https://10.0.1.5"
				op2 := baseOp(2, "B")
				op2.BaseURL = "https://10.0.99.9"
				return []selection.Operator{op1, op2}
			}(),
			TargetID: 1,
			Seed:     0,
		},
	}

	for i := range cases {
		var target selection.Operator
		for _, op := range cases[i].Operators {
			if op.ID == cases[i].TargetID {
				target = op
			}
		}
		relay, err := selection.SelectRelay(cases[i].Operators, target, cases[i].Seed)
		if err != nil {
			cases[i].Expected = relayExpected{NoRelay: true}
		} else {
			cases[i].Expected = relayExpected{RelayID: uptr(relay.ID)}
		}
	}
	return cases
}

// buildDeriveCases pins the pure DeriveMaxOutput function across Go↔TS. Each row
// is (contextWindow, declaredMax, baseCeiling) → expected — the same three
// branches the target derive-mode cases exercise indirectly, but isolated so the
// proxy/client reserve leg (which calls DeriveMaxOutput directly) is pinned too.
//
// The default_ceiling_* rows are the routing-parity pin: proxy and client both
// pass DefaultMaxOutputCeiling, so these are the numbers that must match between
// them for the sizing filter and the reserve leg to agree about the same
// operator. They are also the rows the client's hand-rolled copy
// (client/src/stream/config.ts) is checked against by hand — it does not import
// the shared function, so nothing but this table keeps it honest.
func buildDeriveCases() []deriveCase {
	cases := []deriveCase{
		// Neither declared → flat base ceiling.
		{Name: "flat_fallback", ContextWindow: 0, DeclaredMax: 0, BaseCeiling: 8192},
		// Declared cap is authoritative (window ignored).
		{Name: "declared_verbatim", ContextWindow: 128000, DeclaredMax: 4096, BaseCeiling: 8192},
		// Proportionate slice ctx/4, clamped by the floor.
		{Name: "proportionate_floor", ContextWindow: 512, DeclaredMax: 0, BaseCeiling: 8192},
		{Name: "proportionate_below_floor", ContextWindow: 100, DeclaredMax: 0, BaseCeiling: 8192},
		// Proportionate slice ctx/4, unclamped (between floor and ceiling).
		{Name: "proportionate_mid", ContextWindow: 16000, DeclaredMax: 0, BaseCeiling: 8192},
		// Proportionate slice clamped by the base ceiling (ctx/4 > 8192).
		{Name: "proportionate_ceiling", ContextWindow: 128000, DeclaredMax: 0, BaseCeiling: 8192},
		// The shared ceiling every caller passes, across the window sizes that
		// used to diverge between proxy (32000) and client (4096).
		{Name: "default_ceiling_flat", ContextWindow: 0, DeclaredMax: 0, BaseCeiling: selection.DefaultMaxOutputCeiling},
		{Name: "default_ceiling_small_window", ContextWindow: 2048, DeclaredMax: 0, BaseCeiling: selection.DefaultMaxOutputCeiling},
		{Name: "default_ceiling_mid_window", ContextWindow: 32768, DeclaredMax: 0, BaseCeiling: selection.DefaultMaxOutputCeiling},
		{Name: "default_ceiling_large_window", ContextWindow: 262144, DeclaredMax: 0, BaseCeiling: selection.DefaultMaxOutputCeiling},
		// A declared cap still wins under the default ceiling — the whole point of
		// getting operators to declare context.max_output_tokens.
		{Name: "default_ceiling_declared_wins", ContextWindow: 262144, DeclaredMax: 65536, BaseCeiling: selection.DefaultMaxOutputCeiling},
	}
	for i := range cases {
		cases[i].Expected = selection.DeriveMaxOutput(
			cases[i].ContextWindow, cases[i].DeclaredMax, cases[i].BaseCeiling)
	}
	return cases
}

func buildVectors() *selectionVectorsFile {
	return &selectionVectorsFile{
		Version: 4,
		Comment: "Cross-impl parity vectors for the hayai operator/relay selection policy. " +
			"Regenerate via: cd proto/go && go test ./selection -run TestSelectionVectors -update. " +
			"Loaded by proto/go/selection/vectors_test.go and proto/ts/test/selection-vectors.test.ts.",
		TargetCases: buildTargetCases(),
		RelayCases:  buildRelayCases(),
		DeriveCases: buildDeriveCases(),
	}
}

func TestSelectionVectors(t *testing.T) {
	v := buildVectors()
	got, err := json.MarshalIndent(v, "", "    ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	got = append(got, '\n')

	if *updateVectors {
		if err := os.WriteFile(vectorsPath, got, 0o644); err != nil {
			t.Fatalf("write %s: %v", vectorsPath, err)
		}
		t.Logf("wrote %s (%d bytes)", vectorsPath, len(got))
		return
	}

	want, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v\n(run `cd proto/go && go test ./selection -run TestSelectionVectors -update` to generate)", vectorsPath, err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s drifted from current Go output\n(run `cd proto/go && go test ./selection -run TestSelectionVectors -update` to regenerate)", vectorsPath)
	}
}
