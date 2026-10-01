/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

import (
	"encoding/json"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

// fieldValue reads one top-level numeric field, reporting whether it is present
// at all — the difference between "left alone" and "never added" is exactly what
// several cases below turn on.
func fieldValue(t *testing.T, body []byte, field string) (uint64, bool) {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	raw, ok := obj[field]
	if !ok {
		return 0, false
	}
	var n uint64
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatalf("field %q is not a uint64: %s", field, raw)
	}
	return n, true
}

// Each of the three OpenAI spellings is lowered on its own. Missing one is the
// whole failure mode: a Responses-API body naming max_output_tokens sails past a
// clamp that only knows max_tokens.
func TestClampMaxOutputLowersEachFieldName(t *testing.T) {
	for _, field := range inject.MaxOutputFields() {
		t.Run(field, func(t *testing.T) {
			body := []byte(`{"model":"m","` + field + `":65536}`)
			out, _, err := inject.ClampMaxOutput(body, 32768)
			if err != nil {
				t.Fatalf("ClampMaxOutput: %v", err)
			}
			got, ok := fieldValue(t, out, field)
			if !ok {
				t.Fatalf("%s missing from result", field)
			}
			if got != 32768 {
				t.Errorf("%s = %d, want 32768", field, got)
			}
		})
	}
}

// A body carrying more than one spelling must come out self-consistent. Lowering
// only the one an extractor would have picked leaves the others high, and the
// request that was clamped for escrow then asks the upstream for the original
// number anyway.
func TestClampMaxOutputLowersEveryPresentField(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":65536,"max_completion_tokens":50000,"max_output_tokens":40000}`)
	out, _, err := inject.ClampMaxOutput(body, 32768)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	for _, field := range inject.MaxOutputFields() {
		got, ok := fieldValue(t, out, field)
		if !ok {
			t.Fatalf("%s missing from result", field)
		}
		if got != 32768 {
			t.Errorf("%s = %d, want 32768", field, got)
		}
	}
}

// The reported value is what the caller asked for — the number an operator needs
// to see in the log when a user reports being unable to route. Across several
// spellings it is the largest one lowered, not whichever field happened to sort
// first.
func TestClampMaxOutputReportsTheRequestedValue(t *testing.T) {
	body := []byte(`{"model":"m","max_completion_tokens":40000,"max_tokens":65536}`)
	_, requested, err := inject.ClampMaxOutput(body, 32768)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	if requested != 65536 {
		t.Errorf("requested = %d, want 65536", requested)
	}

	// Nothing lowered ⇒ 0, which is what the call site gates its log line on.
	if _, requested, err = inject.ClampMaxOutput([]byte(`{"max_tokens":1024}`), 32768); err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	} else if requested != 0 {
		t.Errorf("requested = %d with nothing to lower, want 0", requested)
	}
}

// The clamp is one-directional. Raising a caller's value would hand the upstream
// a bigger budget than it asked for and inflate the escrow against it.
func TestClampMaxOutputNeverRaises(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":1024}`)
	out, _, err := inject.ClampMaxOutput(body, 32768)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	got, _ := fieldValue(t, out, "max_tokens")
	if got != 1024 {
		t.Errorf("max_tokens = %d, want 1024 (unchanged)", got)
	}
	// Nothing was lowered, so the input bytes come back verbatim rather than
	// through a remarshal that would reorder keys for no reason.
	if string(out) != string(body) {
		t.Errorf("body was remarshaled with nothing to lower: %s", out)
	}
}

// Equal-to-ceiling is not over the ceiling. An off-by-one here would rewrite
// every already-correct body in the pool.
func TestClampMaxOutputLeavesExactCeilingAlone(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":32768}`)
	out, _, err := inject.ClampMaxOutput(body, 32768)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	if string(out) != string(body) {
		t.Errorf("body changed at exactly the ceiling: %s", out)
	}
}

// Adding an absent field would defeat derive mode one layer up, which sizes the
// reserve per-operator and is strictly better than a flat guessed ceiling.
func TestClampMaxOutputDoesNotAddAnAbsentField(t *testing.T) {
	body := []byte(`{"model":"m","messages":[]}`)
	out, _, err := inject.ClampMaxOutput(body, 32768)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	for _, field := range inject.MaxOutputFields() {
		if _, ok := fieldValue(t, out, field); ok {
			t.Errorf("%s was added to a body that omitted it", field)
		}
	}
}

// ceiling == 0 is "no cap known" — every operator serving the model is unbounded
// — so the caller's value must survive untouched.
func TestClampMaxOutputZeroCeilingIsANoOp(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":65536}`)
	out, _, err := inject.ClampMaxOutput(body, 0)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	if string(out) != string(body) {
		t.Errorf("body changed under a zero ceiling: %s", out)
	}
}

// The remarshal must not drop anything the caller sent — this body travels on to
// the seal and the upstream.
func TestClampMaxOutputPreservesOtherFields(t *testing.T) {
	body := []byte(`{"model":"m","max_tokens":65536,"stream":true,"temperature":0.7,` +
		`"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function"}]}`)
	out, _, err := inject.ClampMaxOutput(body, 32768)
	if err != nil {
		t.Fatalf("ClampMaxOutput: %v", err)
	}
	var got, want map[string]any
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if err := json.Unmarshal(body, &want); err != nil {
		t.Fatalf("unmarshal input: %v", err)
	}
	want["max_tokens"] = float64(32768)
	if len(got) != len(want) {
		t.Fatalf("field count = %d, want %d (%v)", len(got), len(want), got)
	}
	for k, w := range want {
		if g, ok := got[k]; !ok {
			t.Errorf("%s dropped by the remarshal", k)
		} else if k != "messages" && k != "tools" {
			if g != w {
				t.Errorf("%s = %v, want %v", k, g, w)
			}
		}
	}
	if len(got["messages"].([]any)) != 1 || len(got["tools"].([]any)) != 1 {
		t.Errorf("nested arrays did not survive: %s", out)
	}
}

// A value that isn't a plain non-negative integer is malformed for the caller's
// own API. The estimator rejects it one layer up; rewriting it here would mask
// the error behind a number the caller never sent.
func TestClampMaxOutputLeavesMalformedValuesAlone(t *testing.T) {
	for name, body := range map[string]string{
		"null":     `{"max_tokens":null}`,
		"string":   `{"max_tokens":"65536"}`,
		"negative": `{"max_tokens":-1}`,
		"float":    `{"max_tokens":65536.5}`,
		"object":   `{"max_tokens":{"n":65536}}`,
	} {
		t.Run(name, func(t *testing.T) {
			out, _, err := inject.ClampMaxOutput([]byte(body), 32768)
			if err != nil {
				t.Fatalf("ClampMaxOutput: %v", err)
			}
			if string(out) != body {
				t.Errorf("malformed value rewritten: got %s, want %s", out, body)
			}
		})
	}
}

// Bodies with no ceiling field shape to lower pass through. An upstream LLM
// rejects them outright, so failing here would only turn a clear upstream error
// into an opaque proxy one.
func TestClampMaxOutputPassesThroughNonObjects(t *testing.T) {
	for name, body := range map[string]string{
		"empty":     ``,
		"not json":  `--multipart-form-data--`,
		"array":     `[{"max_tokens":65536}]`,
		"json null": `null`,
	} {
		t.Run(name, func(t *testing.T) {
			out, _, err := inject.ClampMaxOutput([]byte(body), 32768)
			if err != nil {
				t.Fatalf("ClampMaxOutput: %v", err)
			}
			if string(out) != body {
				t.Errorf("body changed: got %q, want %q", out, body)
			}
		})
	}
}
