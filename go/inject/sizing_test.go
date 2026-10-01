/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import "testing"

func TestFitsContextWindow(t *testing.T) {
	tests := []struct {
		name                  string
		input, maxOut, window uint64
		want                  bool
	}{
		{"window zero is unbounded", 1 << 40, 1 << 40, 0, true},
		{"exact fit", 50, 50, 100, true},
		{"one under", 50, 49, 100, true},
		{"one over", 50, 51, 100, false},
		{"zero in and out", 0, 0, 100, true},
		{"overflow sum must not fit", 1 << 63, 1 << 63, 200, false},
		{"just under max uint64 — no overflow, does not fit", ^uint64(0) - 1, 1, 100, false},
	}
	for _, tc := range tests {
		if got := FitsContextWindow(tc.input, tc.maxOut, tc.window); got != tc.want {
			t.Errorf("%s: FitsContextWindow(%d,%d,%d) = %v, want %v",
				tc.name, tc.input, tc.maxOut, tc.window, got, tc.want)
		}
	}
}
