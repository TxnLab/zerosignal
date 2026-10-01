/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection_test

import (
	"errors"
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

func op(id uint64, owner string) selection.Operator {
	return selection.Operator{
		ID:              id,
		OwnerAddr:       owner,
		BaseURL:         "https://op.example",
		ProtoVersion:    wire.ProtoVersion,
		Reachable:       true,
		Models:          []string{"m1"},
		ModelCapacities: map[string]selection.ModelCapacity{},
	}
}

func cc() selection.Constraints {
	return selection.Constraints{Model: "m1", Endpoint: selection.EndpointChatCompletions, AffinityPolicy: selection.AffinityNone}
}

func ids(ops []selection.Operator) []uint64 {
	out := make([]uint64, 0, len(ops))
	for _, o := range ops {
		out = append(out, o.ID)
	}
	return out
}

func TestEligibleRelays_IsSelectRelayPool(t *testing.T) {
	ops := []selection.Operator{op(1, "A"), op(2, "B"), op(3, "C")}
	target := ops[0]
	pool := selection.EligibleRelays(ops, target)
	if got := ids(pool); !reflect.DeepEqual(got, []uint64{2, 3}) {
		t.Fatalf("EligibleRelays = %v, want [2 3] (target excluded, sorted by id)", got)
	}
	// The extraction is behavior-preserving: SelectRelay is EligibleRelays
	// indexed by seed, so every seed must agree with indexing the pool.
	for seed := uint64(0); seed < 6; seed++ {
		relay, err := selection.SelectRelay(ops, target, seed)
		if err != nil {
			t.Fatalf("SelectRelay(seed=%d): %v", seed, err)
		}
		if want := pool[seed%uint64(len(pool))]; relay.ID != want.ID {
			t.Errorf("seed %d: SelectRelay=%d, EligibleRelays index=%d", seed, relay.ID, want.ID)
		}
	}
}

func TestSelectTargets_BasicPreservesOrder(t *testing.T) {
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), op(2, "B"), op(3, "C")}, cc(), nil)
	if want := []uint64{1, 2, 3}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v", ids(got.Operators), want)
	}
	if got.Diagnostics.RegistryCount != 3 {
		t.Errorf("RegistryCount = %d, want 3", got.Diagnostics.RegistryCount)
	}
}

func TestSelectTargets_RegistryEmpty(t *testing.T) {
	c := cc()
	c.Model = "nope"
	got := selection.SelectTargets([]selection.Operator{op(1, "A")}, c, nil)
	if len(got.Operators) != 0 || got.Diagnostics.RegistryCount != 0 {
		t.Errorf("got %+v, want empty with RegistryCount 0", got)
	}
}

func TestSelectTargets_SizingMiss(t *testing.T) {
	small := op(2, "B")
	small.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 100}}
	c := cc()
	c.InputTokens, c.MaxOutputTokens = 100, 100 // needs 200 > 100
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), small, op(3, "C")}, c, nil)
	if want := []uint64{1, 3}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v", ids(got.Operators), want)
	}
	if len(got.Diagnostics.SizingMisses) != 1 || got.Diagnostics.SizingMisses[0].OperatorID != 2 {
		t.Errorf("SizingMisses = %+v, want one for op 2", got.Diagnostics.SizingMisses)
	}
}

func TestSelectTargets_VersionBlocked(t *testing.T) {
	a, b := op(1, "A"), op(2, "B")
	a.ProtoVersion, b.ProtoVersion = "1.0", "1.0"
	got := selection.SelectTargets([]selection.Operator{a, b}, cc(), nil)
	if len(got.Operators) != 0 || !got.Diagnostics.VersionBlocked {
		t.Errorf("got %+v, want empty + VersionBlocked", got)
	}
}

func TestSelectTargets_TEE(t *testing.T) {
	c := cc()
	c.RequireTEE = true
	if got := selection.SelectTargets([]selection.Operator{op(1, "A")}, c, nil); !got.Diagnostics.TEEBlocked {
		t.Errorf("want TEEBlocked, got %+v", got)
	}
	attested := op(2, "B")
	attested.TEEAttested = true
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), attested}, c, nil)
	if want := []uint64{2}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v", ids(got.Operators), want)
	}
}

func TestSelectTargets_Staging(t *testing.T) {
	staging := op(2, "B")
	staging.Staging = true

	// Default (AllowStaging false): the staging node is dropped, production kept.
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), staging, op(3, "C")}, cc(), nil)
	if want := []uint64{1, 3}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (staging node excluded by default)", ids(got.Operators), want)
	}

	// Every model-serving node is staging → StagingBlocked, empty result.
	allStaging := selection.SelectTargets([]selection.Operator{staging}, cc(), nil)
	if len(allStaging.Operators) != 0 || !allStaging.Diagnostics.StagingBlocked {
		t.Errorf("got %+v, want empty + StagingBlocked", allStaging)
	}

	// AllowStaging keeps the staging node alongside production.
	c := cc()
	c.AllowStaging = true
	allowed := selection.SelectTargets([]selection.Operator{op(1, "A"), staging, op(3, "C")}, c, nil)
	if want := []uint64{1, 2, 3}; !reflect.DeepEqual(ids(allowed.Operators), want) {
		t.Errorf("ids = %v, want %v (staging node included when allowed)", ids(allowed.Operators), want)
	}
}

func TestSignerUnderfunded_Boundary(t *testing.T) {
	floor := selection.MinSignerSpendableMicroAlgos
	u := func(v uint64) *uint64 { return &v }
	cases := []struct {
		name string
		in   *uint64
		want bool
	}{
		{"never read", nil, false},
		{"zero", u(0), true},
		{"one short", u(floor - 1), true},
		{"at floor", u(floor), false},
		{"max", u(^uint64(0)), false},
	}
	for _, tc := range cases {
		if got := selection.SignerUnderfunded(tc.in); got != tc.want {
			t.Errorf("%s: SignerUnderfunded = %v, want %v", tc.name, got, tc.want)
		}
		o := op(1, "A")
		o.SignerSpendableMicroAlgos = tc.in
		if got := o.SignerUnderfunded(); got != tc.want {
			t.Errorf("%s: Operator.SignerUnderfunded = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSelectTargets_SignerUnderfunded(t *testing.T) {
	zero := uint64(0)
	broke := op(2, "B")
	broke.SignerSpendableMicroAlgos = &zero

	got := selection.SelectTargets([]selection.Operator{op(1, "A"), broke, op(3, "C")}, cc(), nil)
	if want := []uint64{1, 3}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (broke signer excluded)", ids(got.Operators), want)
	}

	// No constraint opts back in: neither AllowStaging nor RequireTEE (with the
	// broke node attested, so the TEE step keeps it) resurrects it.
	c := cc()
	c.AllowStaging = true
	all := selection.SelectTargets([]selection.Operator{broke}, c, nil)
	if len(all.Operators) != 0 || !all.Diagnostics.SignerUnderfundedBlocked || all.Diagnostics.RegistryCount != 1 {
		t.Errorf("AllowStaging: got %+v, want empty + SignerUnderfundedBlocked with RegistryCount 1", all)
	}
	attested := broke
	attested.TEEAttested = true
	c = cc()
	c.RequireTEE = true
	if tee := selection.SelectTargets([]selection.Operator{attested}, c, nil); len(tee.Operators) != 0 || !tee.Diagnostics.SignerUnderfundedBlocked {
		t.Errorf("RequireTEE: got %+v, want empty + SignerUnderfundedBlocked", tee)
	}

	// Relay eligibility is untouched — the relay pays no fee.
	if pool := selection.EligibleRelays([]selection.Operator{op(1, "A"), broke}, op(1, "A")); len(pool) != 1 || pool[0].ID != 2 {
		t.Errorf("EligibleRelays = %v, want [2] (a broke signer still relays)", ids(pool))
	}
}

func TestSelectTargets_ToolPartition(t *testing.T) {
	tooled := op(2, "B")
	tooled.BuiltinTools = []string{"zs_web_search"}
	c := cc()
	c.RequestedTools = []string{"zs_web_search"}
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), tooled, op(3, "C")}, c, nil)
	if want := []uint64{2, 1, 3}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (tool-supporting op first)", ids(got.Operators), want)
	}
}

func TestSelectTargets_AffinityPrefer(t *testing.T) {
	c := cc()
	c.AffinityPolicy = selection.AffinityPrefer
	pref := op(3, "C")
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), op(2, "B"), op(3, "C")}, c, &pref)
	if want := []uint64{3, 1, 2}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (preferred first)", ids(got.Operators), want)
	}
}

func TestSelectTargets_AffinityStrictBlockAndPin(t *testing.T) {
	c := cc()
	c.AffinityPolicy = selection.AffinityStrict
	pin := op(2, "B")
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), op(2, "B")}, c, &pin)
	if want := []uint64{2}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (strict pin)", ids(got.Operators), want)
	}

	c2 := c
	c2.InputTokens, c2.MaxOutputTokens = 100, 100
	misfit := op(2, "B")
	misfit.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ContextWindow: 100}}
	got2 := selection.SelectTargets([]selection.Operator{op(1, "A"), misfit}, c2, &misfit)
	if len(got2.Operators) != 0 || !got2.Diagnostics.AffinityBlocked {
		t.Errorf("got %+v, want empty + AffinityBlocked", got2)
	}
}

// A no-fallback Order names exactly the legal set and must bind a tool-affinity
// continuation too: the affinity-preferred operator, when the Order excludes it,
// must NOT be resurrected. Regression for the case where the Order matched a
// DIFFERENT operator (so step 10 doesn't short-circuit) — strict must block,
// prefer must yield to the order rather than float the excluded preferred.
func TestSelectTargets_NoFallbackOrderBindsAffinityPreferred(t *testing.T) {
	ops := []selection.Operator{op(1, "A"), op(3, "C")}
	pref := op(3, "C") // continuation target the caller's order excludes

	// strict: two hard constraints collide → AffinityBlocked, empty result.
	cs := cc()
	cs.AffinityPolicy = selection.AffinityStrict
	cs.Order = []selection.OperatorRef{{OperatorID: 1, MatchAllNodes: true}}
	cs.AllowFallbacks = new(false)
	if got := selection.SelectTargets(ops, cs, &pref); len(got.Operators) != 0 || !got.Diagnostics.AffinityBlocked {
		t.Errorf("strict: got ids=%v affinity_blocked=%v, want empty + AffinityBlocked",
			ids(got.Operators), got.Diagnostics.AffinityBlocked)
	}

	// prefer: the order is a hard pin, so the soft affinity yields → [1], not [3].
	cp := cc()
	cp.AffinityPolicy = selection.AffinityPrefer
	cp.Order = []selection.OperatorRef{{OperatorID: 1, MatchAllNodes: true}}
	cp.AllowFallbacks = new(false)
	if got := selection.SelectTargets(ops, cp, &pref); !reflect.DeepEqual(ids(got.Operators), []uint64{1}) {
		t.Errorf("prefer: got %v, want [1] (yield to the no-fallback order, not the excluded preferred)",
			ids(got.Operators))
	}
}

func TestSelectTargets_ImageEndpoint(t *testing.T) {
	c := cc()
	c.Endpoint = selection.EndpointImages
	if got := selection.SelectTargets([]selection.Operator{op(1, "A")}, c, nil); !got.Diagnostics.ImageEndpointUnsupported {
		t.Errorf("want ImageEndpointUnsupported, got %+v", got)
	}
	imgOp := op(2, "B")
	imgOp.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true}}
	got := selection.SelectTargets([]selection.Operator{op(1, "A"), imgOp}, c, nil)
	if want := []uint64{2}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v", ids(got.Operators), want)
	}
}

// priced builds an operator whose m1 capacity carries the given USD/1M rates.
func priced(id uint64, owner string, in, out float64) selection.Operator {
	o := op(id, owner)
	o.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: in, OutputUSDPer1M: out}}
	return o
}

// sized returns constraints for a request of the given shape, so the price
// comparison has real token counts to weigh each rate axis by.
func sized(inputTokens, maxOutput uint64) selection.Constraints {
	c := cc()
	c.InputTokens, c.MaxOutputTokens = inputTokens, maxOutput
	return c
}

func TestSelectTargets_PriceSort(t *testing.T) {
	// Cheapest expected request cost first; undeclared (0) sorts last.
	// 10k in / 1k out: op1 = 5·10k + 10·1k = 60k, op2 = 9·10k + 1·1k = 91k.
	cheap := priced(1, "A", 5, 10)
	pricey := priced(2, "B", 9, 1)
	undeclared := op(3, "C") // rates 0 → sort last
	got := selection.SelectTargets([]selection.Operator{undeclared, pricey, cheap}, sized(10_000, 1_000), nil)
	if want := []uint64{1, 2, 3}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (cheapest total cost first, undeclared last)", ids(got.Operators), want)
	}

	// The regression this replaced. Comparing axis-by-axis returns on the first
	// differing axis, so op1's cheaper INPUT rate won every request — including
	// this output-heavy one, where it costs a thousand times more to run.
	// 100 in / 10k out: op1 = 0.01·100 + 50·10k = 500001, op2 = 0.02·100 + 0.05·10k = 502.
	cheapIn := priced(1, "A", 0.01, 50)
	cheapOut := priced(2, "B", 0.02, 0.05)
	got2 := selection.SelectTargets([]selection.Operator{cheapIn, cheapOut}, sized(100, 10_000), nil)
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got2.Operators), want) {
		t.Errorf("ids = %v, want %v (output-heavy request must weigh the output rate)", ids(got2.Operators), want)
	}

	// The output weight is the caller's max_output when they stated one, and
	// outputNormTokens when they didn't — enough to flip which operator is
	// cheaper. Same pair, same input tokens, opposite winners.
	shortOut := priced(1, "A", 1, 100) // cheap input, expensive output
	longOut := priced(2, "B", 10, 1)   // expensive input, cheap output
	pair := []selection.Operator{shortOut, longOut}
	got3 := selection.SelectTargets(pair, sized(1_000, 10), nil)
	if want := []uint64{1, 2}; !reflect.DeepEqual(ids(got3.Operators), want) {
		t.Errorf("ids = %v, want %v (10 output tokens → the cheap-input operator wins)", ids(got3.Operators), want)
	}
	derived := sized(1_000, 0)
	derived.MaxOutputUnspecified = true
	got4 := selection.SelectTargets(pair, derived, nil)
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got4.Operators), want) {
		t.Errorf("ids = %v, want %v (unspecified max_output → the norm weight flips it)", ids(got4.Operators), want)
	}

	// An undeclared OUTPUT rate sorts last even behind a very cheap input rate:
	// half a price list can't be priced, and an unknown price is too expensive.
	// Axis-by-axis used to rank op2 first on its 1-vs-100 input rate.
	full := priced(1, "A", 100, 100)
	halfDeclared := priced(2, "B", 1, 0)
	got5 := selection.SelectTargets([]selection.Operator{full, halfDeclared}, sized(1_000, 1_000), nil)
	if want := []uint64{1, 2}; !reflect.DeepEqual(ids(got5.Operators), want) {
		t.Errorf("ids = %v, want %v (a partly-undeclared price sorts last)", ids(got5.Operators), want)
	}

	// Equal cost → smallest id wins (and the base sort is stable).
	got6 := selection.SelectTargets([]selection.Operator{priced(2, "B", 5, 8), priced(1, "A", 5, 8)}, sized(1_000, 1_000), nil)
	if want := []uint64{1, 2}; !reflect.DeepEqual(ids(got6.Operators), want) {
		t.Errorf("ids = %v, want %v (equal rates → smallest id)", ids(got6.Operators), want)
	}
}

// The two token weights are per-REQUEST. Anything per-operator prices the
// identical request differently for two operators advertising identical rates,
// which is a routing bias dressed as a price.
func TestSelectTargets_PriceSort_WeightsAreRequestLevel(t *testing.T) {
	// A caller that measured nothing still gets input pricing. Both client entry
	// points size this way deliberately (`input_tokens: 0`), so dropping the term
	// there would order this pair the opposite way from the proxy, which measures
	// — and the two are required to route identically.
	ruinousInput := priced(1, "A", 100, 1)
	balanced := priced(2, "B", 1, 2)
	got := selection.SelectTargets([]selection.Operator{ruinousInput, balanced}, sized(0, 0), nil)
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (unmeasured input must still be priced, not free)", ids(got.Operators), want)
	}

	// The input weight is NOT effectiveInputTokens. These advertise identical
	// rates and differ only in proto version, so weighing per-operator would
	// measure op1 at v1's 2950 and op2 at v2's 300 and rank op2 ~10x cheaper — on
	// a reserve bound, when the bill is the same consumed tokens either way. The
	// 9.2 op is listed FIRST so the biased order [2,1] isn't also the input order.
	oldOp, newOp := priced(1, "A", 10, 10), priced(2, "B", 10, 10)
	oldOp.ProtoVersion, newOp.ProtoVersion = "9.1", "9.2"
	c := sized(2_950, 100)
	c.InputTokensV2 = 300
	got2 := selection.SelectTargets([]selection.Operator{newOp, oldOp}, c, nil)
	if want := []uint64{1, 2}; !reflect.DeepEqual(ids(got2.Operators), want) {
		t.Errorf("ids = %v, want %v (identical rates must cost the same regardless of proto version)", ids(got2.Operators), want)
	}
}

func TestSelectTargets_ImageToolPartition(t *testing.T) {
	// Both rate axes are declared: the price comparison weighs expected request
	// cost, so an operator missing either axis prices as +Inf and the ordering
	// under test here would be a tie broken by id rather than by price.
	cheapToolless := op(1, "A")
	cheapToolless.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 1, OutputUSDPer1M: 1}}
	pricyTooled := op(2, "B")
	pricyTooled.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 100, OutputUSDPer1M: 100, OffersImageGenTool: true}}

	// No budget → price ordering (cheaper first), image-tool factor ignored.
	got := selection.SelectTargets([]selection.Operator{cheapToolless, pricyTooled}, cc(), nil)
	if want := []uint64{1, 2}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("no budget: ids = %v, want %v (price ordering)", ids(got.Operators), want)
	}

	// Gen budget → tool-capable first despite the higher price (partition
	// dominates price).
	c := cc()
	c.ImageToolGenBudget = 2
	got2 := selection.SelectTargets([]selection.Operator{cheapToolless, pricyTooled}, c, nil)
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got2.Operators), want) {
		t.Errorf("gen budget: ids = %v, want %v (tool-capable first)", ids(got2.Operators), want)
	}

	// Per-tool requirement: an edit-only operator is NOT gen-capable, so a
	// gen-only budget does not prefer it.
	editOnly := op(3, "C")
	editOnly.ModelCapacities = map[string]selection.ModelCapacity{"m1": {OffersImageEditTool: true}}
	got3 := selection.SelectTargets([]selection.Operator{cheapToolless, editOnly}, c, nil)
	if want := []uint64{1, 3}; !reflect.DeepEqual(ids(got3.Operators), want) {
		t.Errorf("gen budget, edit-only peer: ids = %v, want %v (edit-only not gen-capable)", ids(got3.Operators), want)
	}

	// OR across budgeted tools: with both budgets, EITHER factor counts.
	c2 := cc()
	c2.ImageToolGenBudget, c2.ImageToolEditBudget = 2, 2
	got4 := selection.SelectTargets([]selection.Operator{cheapToolless, editOnly}, c2, nil)
	if want := []uint64{3, 1}; !reflect.DeepEqual(ids(got4.Operators), want) {
		t.Errorf("gen+edit budget: ids = %v, want %v (edit-capable preferred via OR)", ids(got4.Operators), want)
	}

	// Among two tool-capable operators, price still orders within the bucket.
	cheapTooled := op(4, "D")
	cheapTooled.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 10, OutputUSDPer1M: 10, OffersImageGenTool: true}}
	got5 := selection.SelectTargets([]selection.Operator{pricyTooled, cheapTooled}, c, nil)
	if want := []uint64{4, 2}; !reflect.DeepEqual(ids(got5.Operators), want) {
		t.Errorf("two tool-capable: ids = %v, want %v (cheaper tool-capable first)", ids(got5.Operators), want)
	}
}

func TestSelectRelay_RotatesBySeed(t *testing.T) {
	ops := []selection.Operator{op(1, "A"), op(2, "B"), op(3, "C")}
	target := ops[0]
	// eligible (sorted by id) = [2, 3]
	r0, err := selection.SelectRelay(ops, target, 0)
	if err != nil || r0.ID != 2 {
		t.Errorf("seed 0: got %v err %v, want relay 2", r0, err)
	}
	r1, err := selection.SelectRelay(ops, target, 1)
	if err != nil || r1.ID != 3 {
		t.Errorf("seed 1: got %v err %v, want relay 3", r1, err)
	}
	r2, err := selection.SelectRelay(ops, target, 2)
	if err != nil || r2.ID != 2 {
		t.Errorf("seed 2 (wraps): got %v err %v, want relay 2", r2, err)
	}
}

func TestSelectRelay_NoEligible(t *testing.T) {
	// single operator → no relay
	if _, err := selection.SelectRelay([]selection.Operator{op(1, "A")}, op(1, "A"), 0); !errors.Is(err, selection.ErrNoRelay) {
		t.Errorf("single operator: want ErrNoRelay, got %v", err)
	}
	// only a same-owner peer → excluded → no relay
	ops := []selection.Operator{op(1, "A"), op(2, "A")}
	if _, err := selection.SelectRelay(ops, ops[0], 0); !errors.Is(err, selection.ErrNoRelay) {
		t.Errorf("same-owner peer: want ErrNoRelay, got %v", err)
	}
}

func TestSelectRelay_PrefersReachableExcludesIncompatible(t *testing.T) {
	unreach := op(2, "B")
	unreach.Reachable = false // eligible only as fallback (not preferred)
	oldver := op(3, "C")
	oldver.ProtoVersion = "1.0" // excluded — lacks the relay route
	good := op(4, "D")          // reachable + compatible → preferred
	ops := []selection.Operator{op(1, "A"), unreach, oldver, good}
	// reachable pool (target=1, oldver excluded) = [4]; unreach(2) is fallback.
	for _, seed := range []uint64{0, 1, 7} {
		r, err := selection.SelectRelay(ops, ops[0], seed)
		if err != nil || r.ID != 4 {
			t.Errorf("seed %d: got %v err %v, want reachable relay 4 (unreachable 2 not preferred)", seed, r, err)
		}
	}

	// With no reachable relay, fall back to the not-known-reachable set rather
	// than failing — this is the cold-start path.
	a, b := op(1, "A"), op(2, "B")
	a.Reachable, b.Reachable = false, false
	r, err := selection.SelectRelay([]selection.Operator{a, b}, a, 0)
	if err != nil || r.ID != 2 {
		t.Errorf("all-unreachable fallback: got %v err %v, want relay 2", r, err)
	}
}

// TestSelectRelay_SubnetDiversity covers the one diverseSubnet branch that
// actually excludes a relay: two literal IPv4 hosts sharing the first two
// octets. Every other relay test/vector uses hostname base URLs, where /16 is
// unknowable and treated as diverse — so without this the exclusion path is
// dead code from the test suite's perspective. Asserts the expected behavior
// independently of the golden vectors (which only pin TS-matches-Go).
func TestSelectRelay_SubnetDiversity(t *testing.T) {
	// Public IPv4 hosts: the /16 rule applies. (203.0.113.0/24 etc. are
	// reserved-for-docs but not private/loopback, so net.IP treats them as
	// public — same as a real routable address.)
	target := op(1, "A")
	target.BaseURL = "https://203.0.113.5"
	sameSubnet := op(2, "B") // 203.0.* → same /16 as target → excluded
	sameSubnet.BaseURL = "https://203.0.200.9"
	diffSubnet := op(3, "C") // 203.1.* → different /16 → eligible
	diffSubnet.BaseURL = "https://203.1.0.9"

	relay, err := selection.SelectRelay([]selection.Operator{target, sameSubnet, diffSubnet}, target, 0)
	if err != nil || relay.ID != 3 {
		t.Fatalf("got %v err %v, want relay 3 (only one in a diverse /16)", relay, err)
	}

	// With only the same-/16 public peer available, no relay is eligible.
	if _, err := selection.SelectRelay([]selection.Operator{target, sameSubnet}, target, 0); !errors.Is(err, selection.ErrNoRelay) {
		t.Errorf("same-/16 public peer only: want ErrNoRelay, got %v", err)
	}

	// Private/loopback hosts: /16 is NOT applied (same-subnet is the norm on a
	// localnet), so a same-/16 private peer stays eligible — otherwise privacy
	// mode would be unusable on a local fleet.
	pTarget := op(1, "A")
	pTarget.BaseURL = "https://10.0.1.5"
	pPeer := op(2, "B")
	pPeer.BaseURL = "https://10.0.99.9" // same /16, but private → still eligible
	if relay, err := selection.SelectRelay([]selection.Operator{pTarget, pPeer}, pTarget, 0); err != nil || relay.ID != 2 {
		t.Errorf("private same-/16 peers: got %v err %v, want relay 2 (private → not excluded)", relay, err)
	}
	// Loopback too (the localnet 127.0.0.1 case the user hit).
	lTarget := op(1, "A")
	lTarget.BaseURL = "http://127.0.0.1:9001"
	lPeer := op(2, "B")
	lPeer.BaseURL = "http://127.0.0.1:9002"
	if relay, err := selection.SelectRelay([]selection.Operator{lTarget, lPeer}, lTarget, 0); err != nil || relay.ID != 2 {
		t.Errorf("loopback peers: got %v err %v, want relay 2 (loopback → not excluded)", relay, err)
	}

	// Hostname base URLs are unverifiable → never excluded on subnet.
	hTarget := op(1, "A")
	hPeer := op(2, "B")
	if relay, err := selection.SelectRelay([]selection.Operator{hTarget, hPeer}, hTarget, 0); err != nil || relay.ID != 2 {
		t.Errorf("hostname peers: got %v err %v, want relay 2 (subnet unknowable → diverse)", relay, err)
	}
}

// On the dedicated image endpoints the price sort keys off the per-image
// microUSDC rate. An image model's token rates are 0, so the token sort would
// tie every candidate at +Inf and fall through to id order.
func TestSelectTargets_ImagePriceSort(t *testing.T) {
	imgCC := func() selection.Constraints {
		c := cc()
		c.Endpoint = selection.EndpointImages
		return c
	}

	// Free route (rate 0) ranks FIRST, not last: the serves-image filter already
	// proved op3 serves the endpoint, so 0 is "free", not "undeclared".
	dear := op(1, "A")
	dear.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 90}}
	mid := op(2, "B")
	mid.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 50}}
	free := op(3, "C")
	free.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 0}}

	got := selection.SelectTargets([]selection.Operator{dear, mid, free}, imgCC(), nil)
	if want := []uint64{3, 2, 1}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (free first, then cheapest image rate)", ids(got.Operators), want)
	}

	// Token rates must not influence the image ordering: give the dearer image
	// operator the cheapest token rates and confirm it still sorts last.
	dear2 := op(1, "A")
	dear2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 90, InputUSDPer1M: 0.01, OutputUSDPer1M: 0.01}}
	cheap2 := op(2, "B")
	cheap2.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 10, InputUSDPer1M: 99, OutputUSDPer1M: 99}}
	got2 := selection.SelectTargets([]selection.Operator{dear2, cheap2}, imgCC(), nil)
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got2.Operators), want) {
		t.Errorf("ids = %v, want %v (image rate wins over token rates)", ids(got2.Operators), want)
	}
}

// The edit endpoint orders by the edit rate, independently of the gen rate.
func TestSelectTargets_ImageEditPriceSort(t *testing.T) {
	c := cc()
	c.Endpoint = selection.EndpointImageEdits

	cheapGenDearEdit := op(1, "A")
	cheapGenDearEdit.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageEdit: true, ImageRateMicroUSDC: 10, ImageEditRateMicroUSDC: 80}}
	dearGenCheapEdit := op(2, "B")
	dearGenCheapEdit.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageEdit: true, ImageRateMicroUSDC: 99, ImageEditRateMicroUSDC: 20}}

	got := selection.SelectTargets([]selection.Operator{cheapGenDearEdit, dearGenCheapEdit}, c, nil)
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (cheapest EDIT rate first)", ids(got.Operators), want)
	}
}

// A caller's USD-per-1M-token ceiling is meaningless on an image route and must
// not filter it. Applying it would PriceBlock every image operator, since their
// token rates are necessarily 0 (→ +Inf under priceRank).
func TestSelectTargets_ImageEndpointIgnoresTokenCeiling(t *testing.T) {
	c := cc()
	c.Endpoint = selection.EndpointImages
	c.MaxInputUSDPer1M = 1
	c.MaxOutputUSDPer1M = 1

	a := op(1, "A")
	a.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 70}}
	b := op(2, "B")
	b.ModelCapacities = map[string]selection.ModelCapacity{"m1": {ServesImageGen: true, ImageRateMicroUSDC: 30}}

	got := selection.SelectTargets([]selection.Operator{a, b}, c, nil)
	if got.Diagnostics.PriceBlocked {
		t.Error("PriceBlocked set on an image endpoint; the token ceiling must not apply there")
	}
	if want := []uint64{2, 1}; !reflect.DeepEqual(ids(got.Operators), want) {
		t.Errorf("ids = %v, want %v (both survive, cheapest image rate first)", ids(got.Operators), want)
	}

	// The same ceiling still bites on a chat endpoint.
	cChat := cc()
	cChat.MaxInputUSDPer1M = 1
	chatA := op(1, "A")
	chatA.ModelCapacities = map[string]selection.ModelCapacity{"m1": {InputUSDPer1M: 50}}
	gotChat := selection.SelectTargets([]selection.Operator{chatA}, cChat, nil)
	if !gotChat.Diagnostics.PriceBlocked {
		t.Error("chat endpoint: a 50 USD/1M rate must still be blocked by a ceiling of 1")
	}
}
