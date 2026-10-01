/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/selection"
)

// TestServesModel_EmptyServesNothing pins the eligibility rule shared byte-for-
// byte with proxy/internal/hayai/operator.go and proto/ts servesModel: an empty
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
