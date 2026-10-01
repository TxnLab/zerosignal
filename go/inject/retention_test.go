/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

// The JSON KEY is as much a wire contract as the values, and nothing else pins
// it: consumers reference the Go field, and the TS side reads the string
// `retention` in a file no Go test compiles. Renaming the tag would leave every
// Go suite green while every node advertised a field no client reads.
func TestOperatorDetailsModel_RetentionWireKey(t *testing.T) {
	b, err := json.Marshal(inject.OperatorDetailsModel{ID: "m", Retention: inject.RetentionNoUpstream})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if !strings.Contains(string(b), `"retention":"no_upstream"`) {
		t.Errorf("retention is not carried as `\"retention\"`; client/src/stream/operator-details.ts reads that key: %s", b)
	}

	// omitempty, so a node with no signal is byte-identical to a pre-field one.
	b, err = json.Marshal(inject.OperatorDetailsModel{ID: "m"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(b), "retention") {
		t.Errorf("an empty retention tier still emits a key: %s", b)
	}
}

// The wire strings and their order are the contract, and they are hand-mirrored
// in client/src/operators/retention.ts — which proto/ts does not cover, so
// nothing else can notice the two drifting. Pinned as LITERALS rather than
// derived from KnownRetentionTiers(), because a test that reads the same slice
// it is checking cannot notice that slice changing. The TS side has the twin of
// this test against the same literals.
func TestKnownRetentionTiers(t *testing.T) {
	want := []string{
		"tee_attested",
		"upstream_confirmed",
		"upstream_enforced",
		"no_upstream",
		"operator_declared",
	}
	if got := inject.KnownRetentionTiers(); !slices.Equal(got, want) {
		t.Errorf("KnownRetentionTiers() = %q, want %q (order is meaningful — strongest evidence first)", got, want)
	}
}

// The constants must equal the wire strings. Without this a rename that also
// updated the slice above would pass while changing what goes on the wire.
func TestRetentionConstantsAreTheWireStrings(t *testing.T) {
	for got, want := range map[string]string{
		inject.RetentionTEEAttested:       "tee_attested",
		inject.RetentionUpstreamConfirmed: "upstream_confirmed",
		inject.RetentionUpstreamEnforced:  "upstream_enforced",
		inject.RetentionNoUpstream:        "no_upstream",
		inject.RetentionOperatorDeclared:  "operator_declared",
	} {
		if got != want {
			t.Errorf("constant is %q, want %q", got, want)
		}
	}
}

// Two tiers collapsing into one value is invisible to any table test that
// derives its expectation from the constants — the same identity-collapse the
// usage-probe sentinels needed a dedicated test for.
func TestRetentionTiersAreDistinct(t *testing.T) {
	seen := map[string]bool{}
	for _, tier := range inject.KnownRetentionTiers() {
		if seen[tier] {
			t.Fatalf("duplicate retention tier %q; two tiers share a wire value and consumers cannot tell them apart", tier)
		}
		seen[tier] = true
	}
	if len(seen) != 5 {
		t.Errorf("got %d distinct tiers, want 5", len(seen))
	}
}

func TestIsKnownRetention(t *testing.T) {
	// The accepted set, pinned to LITERALS. Iterating KnownRetentionTiers() here
	// reads both sides out of the same slice — `Contains(s, x) for x in s`, which
	// cannot fail for any definition of s — so it looked like coverage and was
	// none.
	for _, tier := range []string{
		inject.RetentionTEEAttested,
		inject.RetentionUpstreamConfirmed,
		inject.RetentionUpstreamEnforced,
		inject.RetentionNoUpstream,
		inject.RetentionOperatorDeclared,
	} {
		if !inject.IsKnownRetention(tier) {
			t.Errorf("IsKnownRetention(%q) = false", tier)
		}
	}
	// Empty is unknown, and so is anything a node invented — the filter is what
	// stops a node minting its own reassuring label. The last three CONTAIN a
	// real tier: without them every rejection fixture is disjoint from the
	// accepted set, so a containment check passes as readily as an equality one
	// and a node advertising `tee_attested — and we mean it` walks through.
	for _, v := range []string{
		"", "retained", "TEE_ATTESTED", "fully_private", "zdr",
		"tee_attested — and we mean it", "xtee_attested", "no_upstream (definitely)",
	} {
		if inject.IsKnownRetention(v) {
			t.Errorf("IsKnownRetention(%q) = true", v)
		}
	}
}

// The combine for a model whose prompt reaches both routes. Every pair is
// stated as a literal, because the rule is deliberately NOT "weaker by rank" —
// the tiers rank by evidence but also make different claims, and ranking alone
// keeps `no_upstream` ("reaches nobody") for a pair where the other route
// demonstrably sends the prompt somewhere.
func TestCombineRetention(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		// Identical routes: unchanged.
		{inject.RetentionNoUpstream, inject.RetentionNoUpstream, inject.RetentionNoUpstream},
		{inject.RetentionTEEAttested, inject.RetentionTEEAttested, inject.RetentionTEEAttested},

		// Both keep the prompt local, so only the evidence differs — half
		// attested and half promised is promised.
		{inject.RetentionTEEAttested, inject.RetentionNoUpstream, inject.RetentionNoUpstream},
		{inject.RetentionNoUpstream, inject.RetentionTEEAttested, inject.RetentionNoUpstream},

		// One route leaves: its tier binds, because it is the only one that
		// describes where the prompt actually went. `no_upstream` has stopped
		// being true and must not survive, even though it outranks nothing.
		{inject.RetentionNoUpstream, inject.RetentionUpstreamConfirmed, inject.RetentionUpstreamConfirmed},
		{inject.RetentionUpstreamConfirmed, inject.RetentionNoUpstream, inject.RetentionUpstreamConfirmed},
		{inject.RetentionTEEAttested, inject.RetentionUpstreamEnforced, inject.RetentionUpstreamEnforced},
		{inject.RetentionNoUpstream, inject.RetentionOperatorDeclared, inject.RetentionOperatorDeclared},

		// Both leave: the weakest link.
		{inject.RetentionUpstreamConfirmed, inject.RetentionUpstreamEnforced, inject.RetentionUpstreamEnforced},
		{inject.RetentionUpstreamEnforced, inject.RetentionOperatorDeclared, inject.RetentionOperatorDeclared},

		// Unknown on either side yields unknown: a route that promises nothing
		// makes the pair promise nothing.
		{"", inject.RetentionTEEAttested, ""},
		{inject.RetentionTEEAttested, "", ""},
		{"", "", ""},
		{"invented", inject.RetentionNoUpstream, ""},
	} {
		if got := inject.CombineRetention(tc.a, tc.b); got != tc.want {
			t.Errorf("CombineRetention(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// Order must not change the answer — the two routes are peers, and a caller
// passing them the other way round would otherwise advertise a different tier
// for the same config.
func TestCombineRetention_IsSymmetric(t *testing.T) {
	all := append(inject.KnownRetentionTiers(), "", "invented")
	for _, a := range all {
		for _, b := range all {
			if x, y := inject.CombineRetention(a, b), inject.CombineRetention(b, a); x != y {
				t.Errorf("CombineRetention(%q,%q)=%q but (%q,%q)=%q", a, b, x, b, a, y)
			}
		}
	}
}

// The result must always be one the pair can actually support: never stronger
// than either input on the destination axis, and never a value a consumer would
// have to filter out.
func TestCombineRetention_NeverStrengthensTheClaim(t *testing.T) {
	staysLocal := map[string]bool{
		inject.RetentionTEEAttested: true,
		inject.RetentionNoUpstream:  true,
	}
	all := append(inject.KnownRetentionTiers(), "", "invented")
	for _, a := range all {
		for _, b := range all {
			got := inject.CombineRetention(a, b)
			if got != "" && !inject.IsKnownRetention(got) {
				t.Errorf("CombineRetention(%q,%q) = %q, not a known tier", a, b, got)
			}
			// "reaches nobody" may only survive when it is true of BOTH.
			if staysLocal[got] && !(staysLocal[a] && staysLocal[b]) {
				t.Errorf("CombineRetention(%q,%q) = %q claims the prompt stays local when one route leaves", a, b, got)
			}
		}
	}
}

// The returned slice must be the caller's own, or a consumer sorting it for
// display reorders the canonical set for everyone in the process.
func TestKnownRetentionTiersIsACopy(t *testing.T) {
	got := inject.KnownRetentionTiers()
	got[0] = "clobbered"
	if inject.KnownRetentionTiers()[0] != inject.RetentionTEEAttested {
		t.Error("KnownRetentionTiers() shares backing storage with the package-level set")
	}
}
