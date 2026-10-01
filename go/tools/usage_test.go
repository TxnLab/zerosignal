/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"math"
	"testing"
)

// TestGeneratedOutputTokens covers the two provider conventions the rule
// exists to reconcile, plus the corroboration guards that keep an unfamiliar
// upstream from inflating a charge.
func TestGeneratedOutputTokens(t *testing.T) {
	cases := []struct {
		name                               string
		prompt, completion, reasoning, tot uint64
		want                               uint64
	}{
		// xAI/grok: total == prompt + completion + reasoning, so completion
		// carries visible output only and reasoning must be added. These are
		// the counts from the grok-4.5 turn that motivated the rule.
		{"grok excludes reasoning", 2497, 7, 153, 2657, 160},
		// OpenAI: total == prompt + completion, reasoning already inside
		// completion. Adding it would double-bill the reasoning tokens.
		{"openai includes reasoning", 2497, 160, 153, 2657, 160},
		// A non-reasoning turn on a reasoning-capable model.
		{"no reasoning reported", 100, 50, 0, 150, 50},
		// No corroboration available: leave completion alone rather than
		// guessing. Under-billing is the safe direction.
		{"total absent", 100, 7, 153, 0, 7},
		{"total below prompt", 100, 7, 153, 50, 7},
		// The gap is smaller than the reasoning count, so the provider can't
		// be excluding reasoning; crediting it would overshoot the total.
		{"gap too small to explain reasoning", 100, 7, 153, 200, 7},
		// A larger-than-explained gap still credits ONLY reasoning — never the
		// raw total-minus-prompt difference — so a bogus total can't inflate.
		{"oversized gap credits reasoning only", 100, 7, 153, 9999, 160},
		// Overflow guard: the corroboration test must not run on a saturated sum.
		{"completion+reasoning overflows", 0, math.MaxUint64, 153, math.MaxUint64, math.MaxUint64},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := GeneratedOutputTokens(c.prompt, c.completion, c.reasoning, c.tot); got != c.want {
				t.Fatalf("GeneratedOutputTokens(%d,%d,%d,%d) = %d, want %d",
					c.prompt, c.completion, c.reasoning, c.tot, got, c.want)
			}
		})
	}
}

// TestGeneratedOutputTokensIdempotent asserts the property that makes it safe
// to normalize at a parse boundary and again downstream: once reasoning has
// been credited, re-running the rule over the credited count no longer
// corroborates and returns it unchanged. Without this, a usage value that
// crosses two normalization points would bill reasoning twice.
func TestGeneratedOutputTokensIdempotent(t *testing.T) {
	const prompt, completion, reasoning, total = 2497, 7, 153, 2657
	once := GeneratedOutputTokens(prompt, completion, reasoning, total)
	twice := GeneratedOutputTokens(prompt, once, reasoning, total)
	if once != 160 || twice != once {
		t.Fatalf("not idempotent: once = %d (want 160), twice = %d", once, twice)
	}
}

// TestChatUsageDecodesReasoning pins the wire shape end-to-end: the verbatim
// grok-4.5 usage object must decode and bill 160, not the 7 the raw
// completion_tokens field reports.
func TestChatUsageDecodesReasoning(t *testing.T) {
	const raw = `{"prompt_tokens":2497,"completion_tokens":7,"total_tokens":2657,` +
		`"prompt_tokens_details":{"text_tokens":2497,"audio_tokens":0,"image_tokens":0,"cached_tokens":128},` +
		`"completion_tokens_details":{"reasoning_tokens":153,"audio_tokens":0,` +
		`"accepted_prediction_tokens":0,"rejected_prediction_tokens":0},` +
		`"num_sources_used":0,"cost_in_usd_ticks":57364000}`

	var u ChatUsage
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := u.ReasoningTokens(); got != 153 {
		t.Fatalf("ReasoningTokens() = %d, want 153", got)
	}
	if got := u.CachedTokens(); got != 128 {
		t.Fatalf("CachedTokens() = %d, want 128", got)
	}
	if got := u.GeneratedOutputTokens(); got != 160 {
		t.Fatalf("GeneratedOutputTokens() = %d, want 160 (completion 7 + reasoning 153)", got)
	}
}

// TestResponsesUsageDecodesReasoning is the Responses-shape twin, using the
// output_tokens_details spelling.
func TestResponsesUsageDecodesReasoning(t *testing.T) {
	const raw = `{"input_tokens":2497,"output_tokens":7,"total_tokens":2657,` +
		`"input_tokens_details":{"cached_tokens":128},` +
		`"output_tokens_details":{"reasoning_tokens":153}}`

	var u ResponsesUsage
	if err := json.Unmarshal([]byte(raw), &u); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got := u.ReasoningTokens(); got != 153 {
		t.Fatalf("ReasoningTokens() = %d, want 153", got)
	}
	if got := u.GeneratedOutputTokens(); got != 160 {
		t.Fatalf("GeneratedOutputTokens() = %d, want 160", got)
	}
}

// TestUsageWithoutDetailsIsUnchanged guards the accessors against a usage
// object that omits the details sub-objects entirely — the common
// non-reasoning case, which must not gain tokens.
func TestUsageWithoutDetailsIsUnchanged(t *testing.T) {
	var chat ChatUsage
	if err := json.Unmarshal([]byte(`{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}`), &chat); err != nil {
		t.Fatalf("unmarshal chat: %v", err)
	}
	if got := chat.GeneratedOutputTokens(); got != 20 {
		t.Fatalf("chat GeneratedOutputTokens() = %d, want 20", got)
	}

	var resp ResponsesUsage
	if err := json.Unmarshal([]byte(`{"input_tokens":10,"output_tokens":20,"total_tokens":30}`), &resp); err != nil {
		t.Fatalf("unmarshal responses: %v", err)
	}
	if got := resp.GeneratedOutputTokens(); got != 20 {
		t.Fatalf("responses GeneratedOutputTokens() = %d, want 20", got)
	}
}
