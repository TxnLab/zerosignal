/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// maxOutputFields are the three OpenAI field names that carry a completion
// ceiling: `max_completion_tokens` (current Chat Completions), `max_tokens`
// (legacy Chat Completions and the legacy completions endpoint), and
// `max_output_tokens` (Responses API). Any layer that reads or rewrites the
// caller's output ceiling must cover all three, or a body that uses the name it
// missed slips through unchanged.
var maxOutputFields = [...]string{"max_completion_tokens", "max_tokens", "max_output_tokens"}

// MaxOutputFields returns the field names ClampMaxOutput rewrites, for callers
// that need to assert over the same set. A fresh copy each call rather than an
// exported array: a package-level exported array is still assignable element-wise
// by any importer, and one that redefined an entry would silently change what
// every other importer clamps.
func MaxOutputFields() []string {
	fields := maxOutputFields
	return fields[:]
}

// ClampMaxOutput lowers every output-ceiling field in an OpenAI-compatible
// request body to ceiling. It never raises a value and never adds a field the
// caller omitted. The second return is the largest value it lowered, or 0 when
// it lowered nothing — what the caller actually asked for, which is the number
// worth logging when a user reports being unable to route.
//
// The point is that `max_tokens` is an upper BOUND on generation, not a demand:
// a caller asking for "at most 65536" is served correctly by an operator that
// will generate at most 32768 — it still gets at most what it asked for. Without
// this, an over-large ceiling is an eligibility predicate rather than a bound,
// and a caller whose tool ships a model card more generous than anything the
// pool advertises can never route at all.
//
// EVERY present field is lowered, not just the first one a reader would pick
// (cf. the proxy's extractMaxOutput precedence). A body carrying two of them
// must stay self-consistent whichever name the node's upstream honors — leaving
// the others high is how the request that got clamped for escrow ends up asking
// the provider for the original number anyway.
//
// A field whose value isn't a plain non-negative integer is left alone: it is
// malformed for the caller's own API and the estimator rejects it one layer up,
// so rewriting it would only mask the error. ceiling == 0 means "no cap known"
// and is a no-op.
//
// Non-JSON bodies and JSON whose top level isn't an object are returned
// unchanged — an upstream LLM rejects them outright, so there is no ceiling
// field shape to lower. The returned slice is a freshly-marshaled copy only when
// something was lowered; callers may store or modify it without affecting the
// input.
func ClampMaxOutput(body []byte, ceiling uint64) ([]byte, uint64, error) {
	if len(body) == 0 || ceiling == 0 {
		return body, 0, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, 0, nil
	}

	clamped := json.RawMessage(strconv.FormatUint(ceiling, 10))
	var requested uint64
	for _, field := range maxOutputFields {
		raw, ok := obj[field]
		if !ok {
			continue
		}
		var n uint64
		if err := json.Unmarshal(raw, &n); err != nil {
			continue
		}
		if n <= ceiling {
			continue
		}
		obj[field] = clamped
		requested = max(requested, n)
	}
	if requested == 0 {
		return body, 0, nil
	}

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal body: %w", err)
	}
	return out, requested, nil
}
