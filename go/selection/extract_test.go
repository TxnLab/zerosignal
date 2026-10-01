/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection_test

import (
	"reflect"
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
)

func TestExtractRequestedBuiltinTools(t *testing.T) {
	cases := []struct {
		name string
		body string
		want []string
	}{
		{"none", `{"model":"m1"}`, nil},
		{"empty tools", `{"tools":[]}`, nil},
		{
			"hayai and non-hayai, order preserved",
			`{"tools":[{"type":"function"},{"type":"zs_web_search"},{"type":"zs_image_search"}]}`,
			[]string{"zs_web_search", "zs_image_search"},
		},
		{
			// Parity guard: a bare "zs_" type must be INCLUDED, matching
			// the TS mirror's `startsWith('zs_')`. The old `len>3` Go guard
			// silently dropped it and diverged from TS.
			"bare zs_ prefix is included",
			`{"tools":[{"type":"zs_"}]}`,
			[]string{"zs_"},
		},
		{"malformed body", `{not json`, nil},
		{"tool without type", `{"tools":[{"foo":"bar"},{"type":"zs_x"}]}`, []string{"zs_x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := selection.ExtractRequestedBuiltinTools([]byte(tc.body))
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("ExtractRequestedBuiltinTools(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// TestParseOperatorRef mirrors proto/ts/test/extract.test.ts (parseOperatorRef)
// so the proxy and client/ resolve a caller ref string identically. Both forms
// and every malformed shape must agree.
func TestParseOperatorRef(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want selection.OperatorRef
		ok   bool
	}{
		{"operator only", "1234", selection.OperatorRef{OperatorID: 1234, MatchAllNodes: true}, true},
		{"operator and node", "1234:2", selection.OperatorRef{OperatorID: 1234, NodeID: 2}, true},
		{"node zero is explicit", "5:0", selection.OperatorRef{OperatorID: 5, NodeID: 0}, true},
		{"whitespace trimmed", "  7 : 3 ", selection.OperatorRef{OperatorID: 7, NodeID: 3}, true},
		{"empty", "", selection.OperatorRef{}, false},
		{"non-numeric operator", "abc", selection.OperatorRef{}, false},
		{"non-numeric node", "1:x", selection.OperatorRef{}, false},
		{"extra colon", "1:2:3", selection.OperatorRef{}, false},
		{"negative", "-1", selection.OperatorRef{}, false},
		{"trailing colon", "1:", selection.OperatorRef{}, false},
		{"leading colon", ":2", selection.OperatorRef{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := selection.ParseOperatorRef(tc.in)
			if ok != tc.ok || got != tc.want {
				t.Errorf("ParseOperatorRef(%q) = (%+v, %v), want (%+v, %v)", tc.in, got, ok, tc.want, tc.ok)
			}
		})
	}
}

// TestExtractRoutingPreferences mirrors proto/ts/test/extract.test.ts
// (extractRoutingPreferences). The key invariants: an absent/garbage provider
// defaults AllowFallbacks=true; malformed refs are skipped; unknown sort/relay
// and non-positive ceilings normalize away.
func TestExtractRoutingPreferences(t *testing.T) {
	t.Run("no provider defaults", func(t *testing.T) {
		got := selection.ExtractRoutingPreferences([]byte(`{"model":"m1"}`))
		if got.AllowFallbacks != nil {
			t.Fatalf("AllowFallbacks = %v, want nil (the caller said nothing)", *got.AllowFallbacks)
		}
		if !got.FallbacksAllowed() {
			t.Fatalf("FallbacksAllowed() = false, want true (default with no provider)")
		}
		if got.Order != nil || got.Only != nil || got.Ignore != nil {
			t.Fatalf("ref lists should be nil, got order=%v only=%v ignore=%v", got.Order, got.Only, got.Ignore)
		}
		if got.Sort != "" || got.Relay != "" {
			t.Fatalf("sort/relay should be empty, got sort=%q relay=%q", got.Sort, got.Relay)
		}
	})

	t.Run("full provider object", func(t *testing.T) {
		body := `{"model":"m1","provider":{
			"order":["3:1","x","2"],
			"only":["1","9:9"],
			"ignore":["7"],
			"allow_fallbacks":false,
			"max_price":{"input":2.5,"output":6},
			"require_tools":true,
			"sort":"THROUGHPUT",
			"relay":" off "
		}}`
		got := selection.ExtractRoutingPreferences([]byte(body))
		wantOrder := []selection.OperatorRef{{OperatorID: 3, NodeID: 1}, {OperatorID: 2, MatchAllNodes: true}}
		if !reflect.DeepEqual(got.Order, wantOrder) {
			t.Errorf("Order = %+v, want %+v (malformed 'x' skipped)", got.Order, wantOrder)
		}
		wantOnly := []selection.OperatorRef{{OperatorID: 1, MatchAllNodes: true}, {OperatorID: 9, NodeID: 9}}
		if !reflect.DeepEqual(got.Only, wantOnly) {
			t.Errorf("Only = %+v, want %+v", got.Only, wantOnly)
		}
		if got.AllowFallbacks == nil {
			t.Errorf("AllowFallbacks = nil, want an explicit false (the caller sent one)")
		} else if got.FallbacksAllowed() {
			t.Errorf("FallbacksAllowed() = true, want false (explicit)")
		}
		if got.MaxInputUSDPer1M != 2.5 || got.MaxOutputUSDPer1M != 6 {
			t.Errorf("max price = (%v,%v), want (2.5,6)", got.MaxInputUSDPer1M, got.MaxOutputUSDPer1M)
		}
		if !got.RequireTools {
			t.Errorf("RequireTools = false, want true")
		}
		if got.Sort != selection.SortThroughput {
			t.Errorf("Sort = %q, want %q (case-insensitive)", got.Sort, selection.SortThroughput)
		}
		if got.Relay != selection.RelayOff {
			t.Errorf("Relay = %q, want %q (trimmed)", got.Relay, selection.RelayOff)
		}
	})

	t.Run("unknown sort/relay and negative ceiling normalize away", func(t *testing.T) {
		body := `{"provider":{"sort":"fastest","relay":"maybe","max_price":{"input":-1}}}`
		got := selection.ExtractRoutingPreferences([]byte(body))
		if got.Sort != "" || got.Relay != "" {
			t.Errorf("sort=%q relay=%q, want both empty", got.Sort, got.Relay)
		}
		if got.MaxInputUSDPer1M != 0 {
			t.Errorf("MaxInputUSDPer1M = %v, want 0 (negative ignored)", got.MaxInputUSDPer1M)
		}
	})

	// Parity guard: a mistyped field (or array element) must discard only
	// itself, never the rest of the object. A typed-struct unmarshal would bail
	// on the first type error and drop everything — this case pins the
	// field/element-resilient behavior so Go and the ts mirror stay in lockstep
	// on a malformed `provider`. Mirrors the same case in extract.test.ts.
	t.Run("malformed fields are isolated, not all-or-nothing", func(t *testing.T) {
		body := `{"provider":{
			"order":[3,"5"],
			"only":["7"],
			"max_price":{"input":"x","output":4},
			"allow_fallbacks":"nope"
		}}`
		got := selection.ExtractRoutingPreferences([]byte(body))
		wantOrder := []selection.OperatorRef{{OperatorID: 5, MatchAllNodes: true}}
		if !reflect.DeepEqual(got.Order, wantOrder) {
			t.Errorf("Order = %+v, want %+v (numeric element 3 skipped, \"5\" kept)", got.Order, wantOrder)
		}
		wantOnly := []selection.OperatorRef{{OperatorID: 7, MatchAllNodes: true}}
		if !reflect.DeepEqual(got.Only, wantOnly) {
			t.Errorf("Only = %+v, want %+v (survives the malformed siblings)", got.Only, wantOnly)
		}
		if got.MaxInputUSDPer1M != 0 || got.MaxOutputUSDPer1M != 4 {
			t.Errorf("max price = (%v,%v), want (0,4) (bad input ignored, good output kept)",
				got.MaxInputUSDPer1M, got.MaxOutputUSDPer1M)
		}
		if got.AllowFallbacks != nil {
			t.Errorf("AllowFallbacks = %v, want nil (a non-bool value is ignored, not recorded)", *got.AllowFallbacks)
		}
		if !got.FallbacksAllowed() {
			t.Errorf("FallbacksAllowed() = false, want true (non-bool value ignored → default)")
		}
	})
}

// TestRoutingPreferencesAllowsOperator mirrors proto/ts/test/extract.test.ts
// (routingPreferencesAllowOperator). It pins the continuation-conflict check
// the proxy/client use before honoring a previous_response_id pin: only/ignore
// and a no-fallback order are hard; a fallbacks-allowed order never blocks.
func TestRoutingPreferencesAllowsOperator(t *testing.T) {
	op := selection.Operator{ID: 3, NodeID: 1}
	allRef := func(id uint64) selection.OperatorRef {
		return selection.OperatorRef{OperatorID: id, MatchAllNodes: true}
	}
	cases := []struct {
		name  string
		prefs selection.RoutingPreferences
		want  bool
	}{
		// Rows that used to spell AllowFallbacks: true now leave it unset — the
		// zero value IS the caller default, which is the point of the pointer.
		// "unset order never blocks" is the regression: as a plain bool, a
		// literal that named an Order and omitted the flag hard-excluded the
		// continuation target.
		{"no constraints", selection.RoutingPreferences{}, true},
		{"ignore matches → blocked", selection.RoutingPreferences{Ignore: []selection.OperatorRef{allRef(3)}}, false},
		{"only names op → allowed", selection.RoutingPreferences{Only: []selection.OperatorRef{{OperatorID: 3, NodeID: 1}}}, true},
		{"only excludes op → blocked", selection.RoutingPreferences{Only: []selection.OperatorRef{allRef(9)}}, false},
		{"no-fallback order names op → allowed", selection.RoutingPreferences{AllowFallbacks: new(false), Order: []selection.OperatorRef{allRef(3)}}, true},
		{"no-fallback order excludes op → blocked", selection.RoutingPreferences{AllowFallbacks: new(false), Order: []selection.OperatorRef{allRef(9)}}, false},
		{"unset order never blocks", selection.RoutingPreferences{Order: []selection.OperatorRef{allRef(9)}}, true},
		{"explicitly-allowed order never blocks", selection.RoutingPreferences{AllowFallbacks: new(true), Order: []selection.OperatorRef{allRef(9)}}, true},
		{"node-specific only excludes sibling node", selection.RoutingPreferences{Only: []selection.OperatorRef{{OperatorID: 3, NodeID: 2}}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.prefs.AllowsOperator(op); got != tc.want {
				t.Errorf("AllowsOperator(%+v) = %v, want %v", tc.prefs, got, tc.want)
			}
		})
	}
}
