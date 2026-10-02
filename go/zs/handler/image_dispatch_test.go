/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"strings"
	"testing"
)

func TestParseImageRequestN_Default(t *testing.T) {
	n, _, _, err := parseImageRequestN([]byte(`{"model":"sdxl","prompt":"x"}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("n = %d, want 1 (default)", n)
	}
}

func TestParseImageRequestN_Explicit(t *testing.T) {
	n, _, _, err := parseImageRequestN([]byte(`{"model":"sdxl","prompt":"x","n":4}`))
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 {
		t.Errorf("n = %d, want 4", n)
	}
}

func TestParseImageRequestN_Invalid(t *testing.T) {
	cases := []struct {
		name string
		body string
		want string
	}{
		{"malformed JSON", `not json`, "invalid JSON"},
		{"n zero", `{"n":0}`, "n must be"},
		{"n negative", `{"n":-1}`, "n must be"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, err := parseImageRequestN([]byte(tc.body))
			if err == nil {
				t.Fatalf("want error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want substring %q", err, tc.want)
			}
		})
	}
}
