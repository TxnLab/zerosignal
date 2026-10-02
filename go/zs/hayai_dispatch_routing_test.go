/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/selection"
	"github.com/TxnLab/zerosignal/go/wire"
)

// routingOp builds a current-version operator serving one model with the given
// advertised USD/1M rates and built-in tools. Context window is generous so the
// sizing filter never interferes with the routing-preference assertions.
func routingOp(id uint64, model string, inUSD, outUSD float64, tools ...string) Operator {
	tds := make([]BuiltinToolDef, 0, len(tools))
	for _, t := range tools {
		tds = append(tds, BuiltinToolDef{Type: t})
	}
	return Operator{
		ID:      id,
		BaseURL: "http://op.example",
		Models:  []string{model},
		ModelCapacities: map[string]ModelCapacity{
			model: {ContextWindow: 128_000, MaxOutputTokens: 16_384, InputUSDPer1M: inUSD, OutputUSDPer1M: outUSD},
		},
		ProtoVersion: wire.ProtoVersion,
		BuiltinTools: tds,
	}
}

func minimalRoutingServer(t *testing.T, ops []Operator) *Client {
	t.Helper()
	registry, err := NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("NewStaticRegistryProvider: %v", err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &Client{
		cfg:              Config{Privacy: PrivacyDirect, Affinity: Affinity{Policy: AffinityNone}},
		log:              log,
		registryProvider: registry,
	}
}

const routingModel = "gpt-4o-mini"

func routingPick(t *testing.T, srv *Client, prefs selection.RoutingPreferences) pickResult {
	t.Helper()
	pick, err := srv.pickCandidates(
		context.Background(), endpointChatCompletions, routingModel,
		[]byte(`{"model":"`+routingModel+`"}`),
		SizingRequest{Model: routingModel, InputTokens: 100, MaxOutputTokens: 100},
		false, selection.ImageToolBudgets{}, prefs,
	)
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	return pick
}

func opIDs(pick pickResult) []uint64 {
	out := make([]uint64, len(pick.Operators))
	for i, op := range pick.Operators {
		out[i] = op.ID
	}
	return out
}

func allRef(id uint64) selection.OperatorRef {
	return selection.OperatorRef{OperatorID: id, MatchAllNodes: true}
}

func TestPickCandidates_Routing_OnlyAllowlist(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
		routingOp(3, routingModel, 0, 0),
	})
	pick := routingPick(t, srv, selection.RoutingPreferences{Only: []selection.OperatorRef{allRef(2)}})
	if got := opIDs(pick); len(got) != 1 || got[0] != 2 {
		t.Fatalf("only=[2] expected [2]; got %v (ProviderPinBlocked=%v)", got, pick.ProviderPinBlocked)
	}
}

func TestPickCandidates_Routing_OnlyMatchesNobody_ProviderPinBlocked(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
	})
	pick := routingPick(t, srv, selection.RoutingPreferences{Only: []selection.OperatorRef{allRef(99)}})
	if !pick.ProviderPinBlocked {
		t.Fatalf("expected ProviderPinBlocked; got operators %v", opIDs(pick))
	}
	if len(pick.Operators) != 0 {
		t.Errorf("operators should be empty; got %v", opIDs(pick))
	}
	// RegistryCount stays the pre-filter model-serving count (operators DO
	// advertise the model; the pin excluded them) — distinct from no_operator.
	if pick.RegistryCount == 0 {
		t.Errorf("RegistryCount should reflect the model-serving pool, not 0")
	}
}

func TestPickCandidates_Routing_IgnoreDenylist(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
		routingOp(3, routingModel, 0, 0),
	})
	pick := routingPick(t, srv, selection.RoutingPreferences{Ignore: []selection.OperatorRef{allRef(2)}})
	got := opIDs(pick)
	if len(got) != 2 || got[0] != 1 || got[1] != 3 {
		t.Fatalf("ignore=[2] expected [1 3]; got %v", got)
	}
}

func TestPickCandidates_Routing_OrderStrictPinAndBlock(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
		routingOp(3, routingModel, 0, 0),
	})
	// order=[3] + no fallbacks → exactly [3].
	pick := routingPick(t, srv, selection.RoutingPreferences{AllowFallbacks: new(false), Order: []selection.OperatorRef{allRef(3)}})
	if got := opIDs(pick); len(got) != 1 || got[0] != 3 {
		t.Fatalf("order=[3] no-fallback expected [3]; got %v", got)
	}
	// order=[99] + no fallbacks → nobody → ProviderPinBlocked.
	pick = routingPick(t, srv, selection.RoutingPreferences{AllowFallbacks: new(false), Order: []selection.OperatorRef{allRef(99)}})
	if !pick.ProviderPinBlocked || len(pick.Operators) != 0 {
		t.Fatalf("order=[99] no-fallback expected ProviderPinBlocked+empty; got %v block=%v", opIDs(pick), pick.ProviderPinBlocked)
	}
}

func TestPickCandidates_Routing_MaxPriceFilterAndBlock(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 9, 1),
		routingOp(2, routingModel, 5, 10),
		routingOp(3, routingModel, 0, 0), // undeclared → treated as too expensive
	})
	// input ceiling 6 → only op2 (5) survives.
	pick := routingPick(t, srv, selection.RoutingPreferences{MaxInputUSDPer1M: 6})
	if got := opIDs(pick); len(got) != 1 || got[0] != 2 {
		t.Fatalf("max_price input=6 expected [2]; got %v", got)
	}
	// ceiling below everyone → PriceBlocked.
	pick = routingPick(t, srv, selection.RoutingPreferences{MaxInputUSDPer1M: 1})
	if !pick.PriceBlocked || len(pick.Operators) != 0 {
		t.Fatalf("max_price input=1 expected PriceBlocked+empty; got %v block=%v", opIDs(pick), pick.PriceBlocked)
	}
}

func TestPickCandidates_Routing_RequireToolsFilterAndBlock(t *testing.T) {
	srv := minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0, "zs_web_search"),
		routingOp(3, routingModel, 0, 0),
	})
	// require_tools + a request asking for zs_web_search → only op2 survives.
	// RequestedTools is derived from the body, so pass it in the body here.
	pick, err := srv.pickCandidates(
		context.Background(), endpointChatCompletions, routingModel,
		[]byte(`{"model":"`+routingModel+`","tools":[{"type":"zs_web_search"}]}`),
		SizingRequest{Model: routingModel, InputTokens: 100, MaxOutputTokens: 100},
		false, selection.ImageToolBudgets{},
		selection.RoutingPreferences{RequireTools: true},
	)
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if got := opIDs(pick); len(got) != 1 || got[0] != 2 {
		t.Fatalf("require_tools expected [2]; got %v (ToolUnsupported=%v)", got, pick.ToolUnsupported)
	}

	// Nobody advertises the tool → ToolUnsupported.
	srv = minimalRoutingServer(t, []Operator{
		routingOp(1, routingModel, 0, 0),
		routingOp(2, routingModel, 0, 0),
	})
	pick, err = srv.pickCandidates(
		context.Background(), endpointChatCompletions, routingModel,
		[]byte(`{"model":"`+routingModel+`","tools":[{"type":"zs_web_search"}]}`),
		SizingRequest{Model: routingModel, InputTokens: 100, MaxOutputTokens: 100},
		false, selection.ImageToolBudgets{},
		selection.RoutingPreferences{RequireTools: true},
	)
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	if !pick.ToolUnsupported || len(pick.Operators) != 0 {
		t.Fatalf("require_tools with no capable op expected ToolUnsupported+empty; got %v block=%v", opIDs(pick), pick.ToolUnsupported)
	}
}

// A previous_response_id continuation pins the exact serving operator; a caller
// `only`/`ignore`/no-fallback-`order` that excludes it is an unsatisfiable
// conflict, surfaced as ProviderPinBlocked (NOT silently re-routed, NOT honored
// against the caller's hard pin).
func TestPickCandidates_Routing_ResponseIDPinConflict(t *testing.T) {
	const model = "gpt-test"
	op := versionOp(7, model, wire.ProtoVersion)
	srv := minimalRoutingServer(t, []Operator{op})
	srv.responseAffinity = NewIDAffinity(16, time.Minute, time.Now)
	srv.responseAffinity.Record(op.ID, op.NodeID, []string{"rid"})
	body := []byte(`{"model":"gpt-test","previous_response_id":"rid","input":[]}`)
	sizing := SizingRequest{Model: model, InputTokens: 1, MaxOutputTokens: 1}

	// Caller allows ONLY operator 9 — which is not the continuation target (7).
	conflict := selection.RoutingPreferences{Only: []selection.OperatorRef{allRef(9)}}
	pick, err := srv.pickCandidates(context.Background(), endpointResponses, model, body, sizing,
		false, selection.ImageToolBudgets{}, conflict)
	if err != nil {
		t.Fatalf("pickCandidates: %v", err)
	}
	// A continuation conflict is a client contradiction (→ 400), NOT a
	// pool-availability pin miss (ProviderPinBlocked → 503).
	if !pick.PinConflict || pick.ProviderPinBlocked || len(pick.Operators) != 0 {
		t.Fatalf("conflicting only-pin expected PinConflict+empty (not ProviderPinBlocked); got %v conflict=%v block=%v",
			opIDs(pick), pick.PinConflict, pick.ProviderPinBlocked)
	}
	if !strings.Contains(pick.PinConflictReason, "previous_response_id") {
		t.Errorf("reason should explain the continuation conflict; got %q", pick.PinConflictReason)
	}

	// Control: a compatible pin (only the continuation operator) resolves cleanly.
	ok := selection.RoutingPreferences{Only: []selection.OperatorRef{allRef(7)}}
	pick, err = srv.pickCandidates(context.Background(), endpointResponses, model, body, sizing,
		false, selection.ImageToolBudgets{}, ok)
	if err != nil {
		t.Fatalf("pickCandidates (control): %v", err)
	}
	if pick.PinConflict || len(pick.Operators) != 1 || pick.Operators[0].ID != 7 {
		t.Fatalf("non-conflicting pin should resolve [7]; got %v conflict=%v", opIDs(pick), pick.PinConflict)
	}
}

// resolveUsePrivacy maps (config privacy, allow-override, caller relay pref) to
// the effective per-request relay decision. "required" always forces a relay;
// "off" disables it only when the override is permitted; "auto"/"" keeps config.
func TestResolveUsePrivacy(t *testing.T) {
	cases := []struct {
		name          string
		configPrivacy bool
		allowOverride bool
		relayPref     string
		want          bool
	}{
		{"auto keeps config on", true, true, selection.RelayAuto, true},
		{"auto keeps config off", false, true, "", false},
		{"empty keeps config on", true, true, "", true},
		{"required forces relay even when config off", false, true, selection.RelayRequired, true},
		{"required forces relay even when override forbidden", false, false, selection.RelayRequired, true},
		{"off disables when override allowed", true, true, selection.RelayOff, false},
		{"off ignored when override forbidden (config on)", true, false, selection.RelayOff, true},
		{"off ignored when override forbidden (config off stays off)", false, false, selection.RelayOff, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolveUsePrivacy(tc.configPrivacy, tc.allowOverride, tc.relayPref); got != tc.want {
				t.Errorf("resolveUsePrivacy(privacy=%v, allowOverride=%v, pref=%q) = %v, want %v",
					tc.configPrivacy, tc.allowOverride, tc.relayPref, got, tc.want)
			}
		})
	}
}

// End-to-end: a turn must report each routing-preference diagnostic as its
// own code. Exercises the `provider`-object parse path (the field rides in the
// request body).
func TestDispatchHayai_RoutingPreferences_Statuses(t *testing.T) {
	cases := []struct {
		name     string
		ops      []Operator
		body     string
		wantKind Kind
		wantCode string
	}{
		{
			name:     "only pin matches nobody → no_pinned_operator",
			ops:      []Operator{routingOp(1, routingModel, 0, 0), routingOp(2, routingModel, 0, 0)},
			body:     `{"model":"` + routingModel + `","max_completion_tokens":100,"provider":{"only":["99"]}}`,
			wantKind: KindNoRoute,
			wantCode: "no_pinned_operator",
		},
		{
			name:     "max_price excludes all → price_ceiling_exceeded",
			ops:      []Operator{routingOp(1, routingModel, 9, 1), routingOp(2, routingModel, 5, 10)},
			body:     `{"model":"` + routingModel + `","max_completion_tokens":100,"provider":{"max_price":{"input":1}}}`,
			wantKind: KindPriceRejected,
			wantCode: "price_ceiling_exceeded",
		},
		{
			name:     "require_tools with no capable op → no_tool_capacity",
			ops:      []Operator{routingOp(1, routingModel, 0, 0), routingOp(2, routingModel, 0, 0)},
			body:     `{"model":"` + routingModel + `","max_completion_tokens":100,"tools":[{"type":"zs_web_search"}],"provider":{"require_tools":true}}`,
			wantKind: KindNoRoute,
			wantCode: "no_tool_capacity",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := minimalRoutingServer(t, tc.ops)
			srv.tokenizer = testTokenizer()
			ze := turnErr(t, srv, tc.body)
			if ze.Code != tc.wantCode || ze.Kind != tc.wantKind {
				t.Fatalf("error = %s/%s, want %s/%s (%s)", ze.Kind, ze.Code, tc.wantKind, tc.wantCode, ze.Message)
			}
		})
	}
}
