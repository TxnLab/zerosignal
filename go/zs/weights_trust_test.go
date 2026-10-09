/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"reflect"
	"strconv"
	"testing"
)

const (
	digestReal = "sha256:aaaa"
	digestFake = "sha256:bbbb"
)

// wop builds a candidate serving `model` with the given digest under the given
// owner. An empty digest is an operator that publishes none — the hosted
// passthrough case (grok/gpt/claude have no local weights to hash).
func wop(id uint64, owner, model, digest string) Operator {
	return Operator{
		ID:              id,
		NodeID:          1,
		OwnerAddr:       owner,
		ModelCapacities: map[string]ModelCapacity{model: {WeightsDigest: digest}},
	}
}

// wids is the candidate order by operator id.
func wids(ops []Operator, _ []NodeRef) []uint64 {
	out := make([]uint64, len(ops))
	for i, o := range ops {
		out[i] = o.ID
	}
	return out
}

func TestWeightsConsensus(t *testing.T) {
	const m = "kimi-k3"
	cases := []struct {
		name string
		ops  []Operator
		want string
	}{{
		name: "majority of distinct owners sets the reference",
		ops: []Operator{
			wop(1, "OWNER_A", m, digestReal),
			wop(2, "OWNER_B", m, digestReal),
			wop(3, "OWNER_C", m, digestFake),
		},
		want: digestReal,
	}, {
		// Two claims, no minority: with one publisher on each side there is
		// nothing to call a contradiction, so neither is demoted.
		name: "one owner each is not a consensus",
		ops: []Operator{
			wop(1, "OWNER_A", m, digestReal),
			wop(2, "OWNER_B", m, digestFake),
		},
		want: "",
	}, {
		// The legitimate-divergence guard: two camps of equal standing mean we
		// do not know which is right, so nobody may be picked as the villain.
		name: "a tie for the lead yields no consensus",
		ops: []Operator{
			wop(1, "OWNER_A", m, digestReal),
			wop(2, "OWNER_B", m, digestReal),
			wop(3, "OWNER_C", m, digestFake),
			wop(4, "OWNER_D", m, digestFake),
		},
		want: "",
	}, {
		// The sybil rule. One owner's five nodes are one opinion; counting them
		// as five would let a single operator manufacture a majority against an
		// honest peer for the price of extra node registrations.
		name: "one owner's many nodes count once",
		ops: []Operator{
			wop(1, "OWNER_A", m, digestFake),
			wop(2, "OWNER_A", m, digestFake),
			wop(3, "OWNER_A", m, digestFake),
			wop(4, "OWNER_A", m, digestFake),
			wop(5, "OWNER_B", m, digestReal),
		},
		want: "",
	}, {
		name: "a lone publisher is not a consensus",
		ops: []Operator{
			wop(1, "OWNER_A", m, digestReal),
			wop(2, "OWNER_B", m, ""),
			wop(3, "OWNER_C", m, ""),
		},
		want: "",
	}, {
		name: "nobody publishes",
		ops: []Operator{
			wop(1, "OWNER_A", m, ""),
			wop(2, "OWNER_B", m, ""),
		},
		want: "",
	}, {
		// A hand-written pin in caps agrees with the digest it matches; reading
		// it as a contradiction would demote an operator for its shift key.
		name: "case-insensitive",
		ops: []Operator{
			wop(1, "OWNER_A", m, "SHA256:AAAA"),
			wop(2, "OWNER_B", m, digestReal),
			wop(3, "OWNER_C", m, digestFake),
		},
		want: digestReal,
	}, {
		// Distinctness can't be established without an owner, so these operators
		// supply no evidence — leaving one real publisher, which is not a
		// consensus.
		name: "operators with no owner address are not evidence",
		ops: []Operator{
			wop(1, "", m, digestFake),
			wop(2, "", m, digestFake),
			wop(3, "OWNER_C", m, digestReal),
		},
		want: "",
	}, {
		name: "digests for another model do not vote",
		ops: []Operator{
			wop(1, "OWNER_A", "other", digestReal),
			wop(2, "OWNER_B", "other", digestReal),
			wop(3, "OWNER_C", m, digestFake),
		},
		want: "",
	}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := weightsConsensus(tc.ops, m); got != tc.want {
				t.Fatalf("weightsConsensus = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDemoteContradictedWeights(t *testing.T) {
	const m = "kimi-k3"
	// The scenario this whole file exists for: three operators agree on the
	// model's real digest, a fourth advertises something else while charging the
	// same price, and it is FIRST in the price order — the position a substituted
	// cheap model buys.
	honest := []Operator{
		wop(2, "OWNER_B", m, digestReal),
		wop(3, "OWNER_C", m, digestReal),
		wop(4, "OWNER_D", m, digestReal),
	}
	liar := wop(1, "OWNER_A", m, digestFake)

	t.Run("the contradicted candidate goes to the tail", func(t *testing.T) {
		ops := append([]Operator{liar}, honest...)
		got := wids(demoteContradictedWeights(ops, nil, ops, m))
		if want := []uint64{2, 3, 4, 1}; !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	})

	t.Run("demoted, never dropped", func(t *testing.T) {
		// A model only the liar serves must stay reachable: the payer picking a
		// worse operator is a preference, being unable to route at all is an
		// outage. The hard exclusion (NodeExcluder) is reserved for a node
		// contradicting its own signature.
		ops := []Operator{liar, wop(9, "OWNER_Z", m, digestReal)}
		evidence := append([]Operator{liar}, honest...)
		out, refs := demoteContradictedWeights(ops, nil, evidence, m)
		if len(out) != 2 {
			t.Fatalf("candidate dropped: got %d, want 2", len(out))
		}
		if len(refs) != 1 || refs[0].Op != 1 {
			t.Fatalf("demoted refs = %v, want operator 1", refs)
		}
	})

	t.Run("relative order is preserved within each group", func(t *testing.T) {
		// The input order is the price order selectTargets produced, so a stable
		// partition is what keeps price deciding among equals.
		ops := []Operator{
			wop(5, "OWNER_E", m, digestFake),
			honest[0],
			liar,
			honest[1],
		}
		got := wids(demoteContradictedWeights(ops, nil, append(ops, honest[2]), m))
		if want := []uint64{2, 3, 5, 1}; !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	})

	t.Run("silence is free", func(t *testing.T) {
		// The passthrough case. An operator serving a closed-weights frontier
		// model has no digest and never can, so publishing nothing must cost
		// nothing even when peers publish.
		quiet := wop(7, "OWNER_G", m, "")
		ops := append([]Operator{quiet}, honest...)
		got := wids(demoteContradictedWeights(ops, nil, ops, m))
		if want := []uint64{7, 2, 3, 4}; !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	})

	t.Run("no consensus demotes nobody", func(t *testing.T) {
		ops := []Operator{liar, honest[0]}
		got := wids(demoteContradictedWeights(ops, nil, ops, m))
		if want := []uint64{1, 2}; !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	})

	t.Run("a passed pin is exempt", func(t *testing.T) {
		// The parameter is reserved for a genuine session continuation, where the
		// pinned node is the only correct route. The dispatch path passes nil —
		// see the call site — so this pins the primitive, not the policy.
		ops := append([]Operator{liar}, honest...)
		got := wids(demoteContradictedWeights(ops, &liar, ops, m))
		if want := []uint64{1, 2, 3, 4}; !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	})

	t.Run("the tool-affinity pin does NOT exempt at the dispatch call site", func(t *testing.T) {
		// The regression this guards: exempting `preferredOp` would make the
		// demerit inert for a payer mid-tool-loop with the contradicted operator
		// — the one who is paying for the substituted model, across every turn of
		// the loop. pickCandidates must keep passing nil.
		ops := append([]Operator{liar}, honest...)
		got := wids(demoteContradictedWeights(ops, nil, ops, m))
		if want := []uint64{2, 3, 4, 1}; !reflect.DeepEqual(got, want) {
			t.Fatalf("order = %v, want %v", got, want)
		}
	})

	t.Run("the vote spans the registry, not the eligible slice", func(t *testing.T) {
		// The liar is the only candidate left after the caller's price ceiling
		// excluded its peers. Narrowing the vote to that slice would hand it the
		// lead; the wider registry still knows what the model is.
		ops := []Operator{liar, wop(8, "OWNER_H", m, digestFake)}
		evidence := append(append([]Operator{}, ops...), honest...)
		out, refs := demoteContradictedWeights(ops, nil, evidence, m)
		if len(refs) != 2 {
			t.Fatalf("demoted %d, want both candidates", len(refs))
		}
		if got := wids(out, nil); !reflect.DeepEqual(got, []uint64{1, 8}) {
			t.Fatalf("order = %v, want the input order preserved", got)
		}
	})

	t.Run("a lone contradicted candidate is kept but still reported", func(t *testing.T) {
		// Nothing to reorder, and that is exactly why the report matters: being
		// routed to the ONLY operator that contradicts its peers is when the
		// payer most wants to hear about it. A len<2 short-circuit would make
		// this the one case that logs nothing.
		ops := []Operator{liar}
		out, refs := demoteContradictedWeights(ops, nil, append([]Operator{liar}, honest...), m)
		if len(out) != 1 || out[0].ID != 1 {
			t.Fatalf("candidates = %v, want the lone candidate kept", wids(out, nil))
		}
		if len(refs) != 1 || refs[0].Op != 1 {
			t.Fatalf("demoted refs = %v, want operator 1 reported", refs)
		}
	})

	t.Run("an empty candidate list is a no-op", func(t *testing.T) {
		out, refs := demoteContradictedWeights(nil, nil, honest, m)
		if len(out) != 0 || refs != nil {
			t.Fatalf("got (%v, %v), want no candidates and no refs", out, refs)
		}
	})
}

// TestWeightsConsensusScalesWithOwners pins the sybil property as a property
// rather than one example: adding nodes under one owner never moves the
// consensus, however many are added.
func TestWeightsConsensusScalesWithOwners(t *testing.T) {
	const m = "kimi-k3"
	ops := []Operator{
		wop(100, "OWNER_HONEST_1", m, digestReal),
		wop(101, "OWNER_HONEST_2", m, digestReal),
	}
	for i := range 50 {
		sybil := wop(uint64(200+i), "OWNER_LIAR", m, digestFake)
		sybil.NodeID = uint64(i)
		ops = append(ops, sybil)
	}
	if got := weightsConsensus(ops, m); got != digestReal {
		t.Fatalf("weightsConsensus = %q, want the honest digest to survive %d sybil nodes", got, 50)
	}
	// And the same fleet under 50 distinct owners DOES take the lead — the cost
	// of the attack is registering them, not running them.
	distinct := ops[:2]
	for i := range 50 {
		distinct = append(distinct, wop(uint64(300+i), "OWNER_LIAR_"+strconv.Itoa(i), m, digestFake))
	}
	if got := weightsConsensus(distinct, m); got != digestFake {
		t.Fatalf("weightsConsensus = %q, want %q once the owners are distinct", got, digestFake)
	}
}
