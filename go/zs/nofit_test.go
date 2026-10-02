/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"strings"
	"testing"
)

// TestDescribeMiss covers the pure formatter that picks which limit
// each operator was rejected against. The branches mirror Fits's check
// order — context-window first, max_output cap second — and a 0 limit
// must not be blamed as the cause (Fits treats 0 as unbounded).
//
// The gap math reads the miss's own EffectiveMaxOutput, never
// req.MaxOutputTokens — so req carries a deliberately large flat display
// ceiling (a flat display ceiling the caller never sent) that must NOT
// leak into any message; a regression to req.MaxOutputTokens would blow every
// expected number up by ~32k.
func TestDescribeMiss(t *testing.T) {
	req := SizingRequest{Model: "m", InputTokens: 8, MaxOutputTokens: 32000, DeriveMaxOutput: true}
	cases := []struct {
		name string
		miss sizingMiss
		want string
	}{
		{
			name: "context_window violation",
			miss: sizingMiss{OperatorID: 7, ContextWindow: 4, EffectiveMaxOutput: 128},
			want: "op 7: context_window=4 (request needs 136)",
		},
		{
			name: "max_output_tokens violation",
			miss: sizingMiss{OperatorID: 11, MaxOutputTokens: 64, EffectiveMaxOutput: 128},
			want: "op 11: max_output_tokens=64 (over by 64)",
		},
		{
			name: "context_window prioritised over max_output",
			miss: sizingMiss{OperatorID: 13, ContextWindow: 4, MaxOutputTokens: 64, EffectiveMaxOutput: 128},
			want: "op 13: context_window=4 (request needs 136)",
		},
		{
			// Derive mode: the operator was fit-checked against its own derived
			// ctx/4=1024 slice, not the flat 32000. The reported gap must be the
			// derived one (8+1024=1032), proving the flat display ceiling is ignored.
			name: "derive mode uses per-operator effective, not flat ceiling",
			miss: sizingMiss{OperatorID: 15, ContextWindow: 512, EffectiveMaxOutput: 1024},
			want: "op 15: context_window=512 (request needs 1032)",
		},
		{
			name: "all-zero (defensive fallback)",
			miss: sizingMiss{OperatorID: 17},
			want: "op 17: declared capacity does not fit (context_window=0, max_output_tokens=0)",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := describeMiss(tc.miss, req); got != tc.want {
				t.Errorf("describeMiss = %q\nwant %q", got, tc.want)
			}
		})
	}
}

// TestNoFitMaxOutputLabel pins the no-fit header's max_output rendering: the
// concrete flat value when the caller specified one, and a non-numeric
// "derived-per-operator" marker in derive mode (where there is no single
// request-level ceiling — each operator got its own, shown in the breakdown).
func TestNoFitMaxOutputLabel(t *testing.T) {
	if got := noFitMaxOutputLabel(SizingRequest{MaxOutputTokens: 4096}); got != "4096" {
		t.Errorf("flat label = %q, want 4096", got)
	}
	derive := SizingRequest{MaxOutputTokens: 32000, DeriveMaxOutput: true}
	if got := noFitMaxOutputLabel(derive); got != "derived-per-operator" {
		t.Errorf("derive label = %q, want derived-per-operator", got)
	}
	// The flat display ceiling must not leak into the header.
	head := formatNoFitMessage("m", SizingRequest{Model: "m", InputTokens: 8, MaxOutputTokens: 32000, DeriveMaxOutput: true}, nil)
	if strings.Contains(head, "32000") {
		t.Errorf("derive-mode header leaked the flat ceiling: %q", head)
	}
}

// TestFormatNoFitMessage_NoMissesPreservesOriginalLine pins the
// backwards-compatible behaviour: when no per-operator misses were
// captured (e.g. the registry is empty for some other reason and we
// somehow reach this branch), the message body is exactly the original
// "no operator serves" line. Clients that string-match on that prefix
// keep working.
func TestFormatNoFitMessage_NoMissesPreservesOriginalLine(t *testing.T) {
	req := SizingRequest{Model: "m", InputTokens: 5, MaxOutputTokens: 7}
	got := formatNoFitMessage("m", req, nil)
	want := "no operator serves m with input_tokens=5 max_output_tokens=7"
	if got != want {
		t.Errorf("formatNoFitMessage = %q\nwant %q", got, want)
	}
}
