/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestPreserveThinking_ZAIOptsIn(t *testing.T) {
	out, err := PreserveThinking([]byte(`{"model":"glm-5.2","messages":[]}`), DialectZAI)
	if err != nil {
		t.Fatalf("PreserveThinking: %v", err)
	}
	var obj struct {
		Thinking struct {
			Type          string `json:"type"`
			ClearThinking *bool  `json:"clear_thinking"`
		} `json:"thinking"`
	}
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("parse: %v\n%s", err, out)
	}
	if obj.Thinking.Type != "enabled" {
		t.Errorf("thinking.type = %q, want %q", obj.Thinking.Type, "enabled")
	}
	// Explicitly false, not merely absent — absent means "cleared" upstream,
	// which is the failure this exists to prevent.
	if obj.Thinking.ClearThinking == nil || *obj.Thinking.ClearThinking {
		t.Errorf("thinking.clear_thinking = %v, want false", obj.Thinking.ClearThinking)
	}
}

// An unknown field is a 400 on a strict upstream, so this must never fire
// outside the dialect it was written for.
func TestPreserveThinking_OtherDialectsUntouched(t *testing.T) {
	const body = `{"model":"m","messages":[]}`
	// Derived from KnownDialects, not hand-listed: a hand-written copy silently
	// gives every dialect added after it zero coverage, which is exactly what
	// happened to DialectOpenRouter.
	for _, d := range KnownDialects() {
		if d == DialectZAI {
			continue
		}
		out, err := PreserveThinking([]byte(body), d)
		if err != nil {
			t.Fatalf("%s: %v", d, err)
		}
		if string(out) != body {
			t.Errorf("%s: body mutated, want byte-identical:\n%s", d, out)
		}
	}
}

// A caller who expressed a preference keeps it — same principle as
// DefaultStoreFalse.
func TestPreserveThinking_ExplicitCallerValuePreserved(t *testing.T) {
	const body = `{"model":"glm-5.2","thinking":{"type":"disabled"}}`
	out, err := PreserveThinking([]byte(body), DialectZAI)
	if err != nil {
		t.Fatalf("PreserveThinking: %v", err)
	}
	if string(out) != body {
		t.Errorf("caller thinking object was overwritten:\n%s", out)
	}
	if strings.Contains(string(out), "clear_thinking") {
		t.Errorf("injected into a caller-supplied object:\n%s", out)
	}
}

func TestPreserveThinking_NonJSONUnchanged(t *testing.T) {
	for _, body := range []string{"", "not json", `["array"]`} {
		out, err := PreserveThinking([]byte(body), DialectZAI)
		if err != nil {
			t.Fatalf("%q: %v", body, err)
		}
		if string(out) != body {
			t.Errorf("%q mutated to %q", body, out)
		}
	}
}

func TestInferDialect_ZAI(t *testing.T) {
	for _, u := range []string{
		"https://api.z.ai/api/paas/v4",
		"https://API.Z.AI/api/paas/v4",
		"https://open.bigmodel.cn/api/paas/v4",
	} {
		if got := InferDialect(u); got != DialectZAI {
			t.Errorf("InferDialect(%q) = %q, want %q", u, got, DialectZAI)
		}
	}
	// z.ai and x.ai differ by one letter in the same label position.
	for _, u := range []string{"https://api.openai.com/v1", "https://api.x.ai/v1", "http://localhost:8000/v1"} {
		if got := InferDialect(u); got == DialectZAI {
			t.Errorf("InferDialect(%q) wrongly matched z.ai", u)
		}
	}
}
