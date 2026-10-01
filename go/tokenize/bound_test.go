/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/tokenize"
)

func TestInputTokenBound_TextOnly(t *testing.T) {
	// 40 bytes of text ⇒ ceil(40/2)=20 + flat margin 32 = 52.
	body := []byte("0123456789012345678901234567890123456789")
	if got := tokenize.InputTokenBound(body); got != 20+tokenize.FlatMargin {
		t.Fatalf("bound = %d, want %d", got, 20+tokenize.FlatMargin)
	}
}

func TestInputTokenBound_EmptyIsMargin(t *testing.T) {
	if got := tokenize.InputTokenBound(nil); got != tokenize.FlatMargin {
		t.Fatalf("bound(nil) = %d, want %d", got, tokenize.FlatMargin)
	}
}

func TestReserveInputCount(t *testing.T) {
	cases := []struct {
		name           string
		bound          uint64
		tools          bool
		iters, perIter uint64
		maxOut, window uint64
		floor          uint64
		want           uint64
	}{
		{"plain no headroom", 500, false, 20, 4000, 4096, 1_000_000, 256, 500},
		{"tools add headroom", 500, true, 20, 4000, 4096, 1_000_000, 256, 500 + 20*4000},
		{"clamp at window", 2_000_000, false, 0, 0, 4096, 1_000_000, 256, 1_000_000 - 4096},
		{"floor no window", 10, false, 0, 0, 100, 0, 256, 256},
		{"cap beats floor", 10, false, 0, 0, 8000, 8100, 256, 100},
		{"window <= maxout returns 0", 100, false, 0, 0, 5000, 4096, 256, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := tokenize.ReserveInputCount(c.bound, c.tools, c.iters, c.perIter, c.maxOut, c.window, c.floor)
			if got != c.want {
				t.Fatalf("ReserveInputCount = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBodyHasPreviousResponseID(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{``, false},
		{`{"model":"m"}`, false},
		{`{"previous_response_id":""}`, false},
		{`{"previous_response_id":"resp_123"}`, true},
		{`not json`, false},
	}
	for _, c := range cases {
		if got := tokenize.BodyHasPreviousResponseID([]byte(c.body)); got != c.want {
			t.Errorf("BodyHasPreviousResponseID(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}

func TestBodyHasTools(t *testing.T) {
	cases := []struct {
		body string
		want bool
	}{
		{``, false},
		{`{"model":"m"}`, false},
		{`{"tools":[]}`, false},
		{`{"tools":[{"type":"function"}]}`, true},
		{`not json`, false},
	}
	for _, c := range cases {
		if got := tokenize.BodyHasTools([]byte(c.body)); got != c.want {
			t.Errorf("BodyHasTools(%q) = %v, want %v", c.body, got, c.want)
		}
	}
}
