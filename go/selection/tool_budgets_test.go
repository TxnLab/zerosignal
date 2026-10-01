/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package selection

import "testing"

func TestParseToolBudgets(t *testing.T) {
	cases := []struct {
		name     string
		body     string
		wantGen  uint64
		wantEdit uint64
	}{
		{
			name:     "both tools",
			body:     `{"model":"gpt-4o","tool_budgets":{"zs_image_generation":{"max_n":4},"zs_image_edit":{"max_n":2}}}`,
			wantGen:  4,
			wantEdit: 2,
		},
		{
			name:    "generation only",
			body:    `{"tool_budgets":{"zs_image_generation":{"max_n":3}}}`,
			wantGen: 3,
		},
		{
			name: "absent",
			body: `{"model":"gpt-4o"}`,
		},
		{
			name: "malformed yields zero",
			body: `{"tool_budgets":"nonsense"}`,
		},
		{
			name: "unrelated tool ignored",
			body: `{"tool_budgets":{"zs_web_search":{"max_n":9}}}`,
		},
		{
			name: "not json",
			body: `not json`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := ParseToolBudgets([]byte(tc.body))
			if b.GenerationMaxN != tc.wantGen {
				t.Errorf("GenerationMaxN = %d, want %d", b.GenerationMaxN, tc.wantGen)
			}
			if b.EditMaxN != tc.wantEdit {
				t.Errorf("EditMaxN = %d, want %d", b.EditMaxN, tc.wantEdit)
			}
		})
	}
}
