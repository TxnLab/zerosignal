/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
)

// TestFitsContextWindowFor_NearUint64Max covers the arithmetic the shared
// vectors cannot reach, since TS numbers stop well short of it: a ceiling whose
// 3x would overflow admits any input, and just under it the product is exact.
func TestFitsContextWindowFor_NearUint64Max(t *testing.T) {
	const max = ^uint64(0)
	cases := []struct {
		name                     string
		input, maxOutput, window uint64
		want                     bool
	}{
		{"3x the ceiling overflows", max, 1, max, true},
		{"3x the ceiling is exactly max", max, 1, max/3 + 1, true},
		{"at 3x a ceiling just under it", max - 3, 1, max / 3, true},
		{"one past 3x that ceiling", max - 2, 1, max / 3, false},
	}
	for _, c := range cases {
		if got := selection.FitsContextWindowFor("9.11", c.input, c.maxOutput, c.window); got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
	if selection.FitsContextWindowFor("9.10", max, 1, max) {
		t.Error("a pre-9.11 operator was offered input past its window")
	}
}

// TestServesModel_EmptyServesNothing pins the eligibility rule shared byte-for-
// byte with proto/go/zs/operator.go and proto/ts servesModel: an empty
// Models list serves NOTHING regardless of Reachable (no wildcard), and a
// non-empty list serves only its members.
func TestServesModel_EmptyServesNothing(t *testing.T) {
	cases := []struct {
		name      string
		models    []string
		reachable bool
		query     string
		want      bool
	}{
		{"empty+reachable serves nothing", nil, true, "m1", false},
		{"empty+unreachable serves nothing", nil, false, "m1", false},
		{"empty slice+reachable serves nothing", []string{}, true, "m1", false},
		{"member matches", []string{"m1", "m2"}, true, "m2", true},
		{"non-member misses", []string{"m1", "m2"}, true, "m3", false},
		{"member matches even if unreachable", []string{"m1"}, false, "m1", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			op := selection.Operator{Models: c.models, Reachable: c.reachable}
			if got := op.ServesModel(c.query); got != c.want {
				t.Errorf("ServesModel(%q) with models=%v reachable=%v = %v, want %v",
					c.query, c.models, c.reachable, got, c.want)
			}
		})
	}
}
