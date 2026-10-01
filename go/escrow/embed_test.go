/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package escrow

import (
	"encoding/json"
	"slices"
	"testing"
)

// TestApprovalErrorMessage_NilSpecIsSafe pins a guard that enrichSubmitError
// now depends on by name. It dropped its own spec-parse-failure branch because
// GetSpec returns a nil *Spec on failure and this lookup is nil-safe — so
// deleting the guard turns every submit failure on a binary with an unparseable
// embedded ARC-56 into a nil-pointer panic inside the settlement driver and the
// proxy's dispatch path, with all three suites green. Nothing else executes it.
func TestApprovalErrorMessage_NilSpecIsSafe(t *testing.T) {
	var s *Spec
	if msg, ok := s.ApprovalErrorMessage(1); ok || msg != "" {
		t.Errorf("nil spec returned (%q, %v), want (\"\", false)", msg, ok)
	}
	if got := s.ApprovalErrorMessages(); got != nil {
		t.Errorf("nil spec returned %v, want nil", got)
	}
}

// TestApprovalErrorMessages_ContractHolds pins the three properties the
// accessor promises, because a caller uses it to assert its classifier over
// the WHOLE contract and each property is silently load-bearing for that.
//
//   - Complete: a filtered return degrades the caller's complement test back
//     into the hand-picked sample it was written to replace, and the caller
//     can't notice — it counts its positives, not the negatives it swept.
//   - Distinct: several asserts already compile to multiple PCs, so a caller
//     counting matches would double-count the day one of the ones it cares
//     about gains a second call site.
//   - Sorted: the source is a map, so without it a failing complement test
//     names a different message on every run.
func TestApprovalErrorMessages_ContractHolds(t *testing.T) {
	spec, err := GetSpec()
	if err != nil {
		t.Fatal(err)
	}
	msgs := spec.ApprovalErrorMessages()

	if !slices.IsSorted(msgs) {
		t.Error("messages are not sorted; a failure would name a different one each run")
	}
	if dedup := slices.Compact(slices.Clone(msgs)); len(dedup) != len(msgs) {
		t.Errorf("messages contain %d duplicates; the accessor promises distinct", len(msgs)-len(dedup))
	}
	// Completeness against the SOURCE, not a floor. A floor leaves every
	// message above it droppable for free — and the ones a filter would most
	// plausibly remove are the near-misses a caller's classifier is being
	// swept for (the deposit*/mbrPayment* family, next door to the MBR-pool
	// guards). Re-derive the distinct count straight from the embedded JSON so
	// the two can only agree by actually agreeing.
	want := distinctApprovalMessagesFromRawARC56(t)
	if len(msgs) != len(want) {
		t.Errorf("accessor returned %d distinct messages, the embedded ARC-56 has %d — the accessor is filtering",
			len(msgs), len(want))
	}
	for _, w := range want {
		if !slices.Contains(msgs, w) {
			t.Errorf("messages missing %q", w)
		}
	}
}

// distinctApprovalMessagesFromRawARC56 re-parses the embedded spec by hand so
// the completeness check above has an independent count to compare against
// rather than one derived from the accessor it is testing.
func distinctApprovalMessagesFromRawARC56(t *testing.T) []string {
	t.Helper()
	var raw struct {
		SourceInfo struct {
			Approval struct {
				SourceInfo []struct {
					ErrorMessage string `json:"errorMessage"`
				} `json:"sourceInfo"`
			} `json:"approval"`
		} `json:"sourceInfo"`
	}
	if err := json.Unmarshal(ZeroSignalEscrowARC56, &raw); err != nil {
		t.Fatalf("parse embedded ARC-56: %v", err)
	}
	seen := map[string]struct{}{}
	var out []string
	for _, e := range raw.SourceInfo.Approval.SourceInfo {
		if e.ErrorMessage == "" {
			continue
		}
		if _, dup := seen[e.ErrorMessage]; dup {
			continue
		}
		seen[e.ErrorMessage] = struct{}{}
		out = append(out, e.ErrorMessage)
	}
	if len(out) == 0 {
		t.Fatal("embedded ARC-56 carries no approval error messages")
	}
	return out
}

// TestSpec_LoadsAllExpectedMethods pins the contract surface this
// package knows about. Any rename or removal in ZeroSignalEscrow.algo.ts
// surfaces here at rebuild time rather than at deploy time.
func TestSpec_LoadsAllExpectedMethods(t *testing.T) {
	s, err := GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	if s.ContractName != "ZeroSignalEscrow" {
		t.Errorf("contract name = %q, want ZeroSignalEscrow", s.ContractName)
	}
	want := []string{
		"createApplication",
		"updateApplication",
		"init",
		"setPaused",
		"setSettlementGraceDefault",
		"setMaxDisputeExcerptBytes",
		"setProtocolFeeBps",
		"setOperatorStakeUsd6",
		"setNodeStakeUsd6",
		"adminUnregisterOperator",
		"createOperator",
		"updateOperator",
		"unregisterOperator",
		"evictOperator",
		"reinstateOperator",
		"createNode",
		"unregisterNode",
		"open",
		"settle",
		"settleLapsed",
		"refundInactive",
		"protest",
		"nextOperatorIdValue",
		"ticket",
		"mbrForOperator",
		"mbrForNode",
		"mbrForTicket",
		"protocolFeeBpsValue",
		"operatorStakeUsd6Value",
		"nodeStakeUsd6Value",
		"requiredOperatorStakeUsdc",
		"requiredNodeStakeUsdc",
	}
	for _, name := range want {
		if _, ok := s.Methods[name]; !ok {
			t.Errorf("missing method %q in spec", name)
		}
	}
}

func TestMethodSelector_Uniqueness(t *testing.T) {
	s, err := GetSpec()
	if err != nil {
		t.Fatalf("GetSpec: %v", err)
	}
	seen := make(map[string]string, len(s.Methods))
	for name, m := range s.Methods {
		sel := string(m.GetSelector())
		if other, dup := seen[sel]; dup {
			t.Errorf("selector collision: %s and %s both emit %x", name, other, sel)
		}
		seen[sel] = name
	}
	// Belt-and-braces: every method has a 4-byte selector.
	for name, m := range s.Methods {
		if got := len(m.GetSelector()); got != 4 {
			t.Errorf("%s: selector len = %d, want 4", name, got)
		}
	}
}

func TestMethodByName_Unknown(t *testing.T) {
	if _, err := MethodByName("totallyMadeUp"); err == nil {
		t.Fatal("expected error for unknown method")
	}
}

func TestMethodSelector_Roundtrip(t *testing.T) {
	sel, err := MethodSelector("open")
	if err != nil {
		t.Fatalf("MethodSelector(open): %v", err)
	}
	if len(sel) != 4 {
		t.Fatalf("open selector length = %d, want 4", len(sel))
	}
	// Selector is deterministic — a second call returns the same bytes.
	sel2, _ := MethodSelector("open")
	if string(sel) != string(sel2) {
		t.Fatal("selector not deterministic across calls")
	}
}
