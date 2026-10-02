/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transform

import "testing"

func TestSSEFrame_IsEmpty(t *testing.T) {
	cases := []struct {
		name  string
		frame SSEFrame
		want  bool
	}{
		{"zero value", SSEFrame{}, true},
		{"data present", SSEFrame{Data: []byte("x")}, false},
		{"event present", SSEFrame{Event: "x"}, false},
		{"id present", SSEFrame{ID: "x"}, false},
		{"retry present", SSEFrame{Retry: 1}, false},
		{"comment present", SSEFrame{Comment: "x"}, false},
		{"zero-length data slice still empty", SSEFrame{Data: []byte{}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.frame.IsEmpty(); got != tc.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tc.want)
			}
		})
	}
}
