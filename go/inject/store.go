/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// DefaultStoreFalse rewrites an OpenAI-compatible request body so the
// top-level `store` field defaults to `false` when the caller omitted
// it. An explicit caller value (true or false) is preserved unchanged
// — the caller has the choice whether to allow upstream retention.
//
// Hayai's protocol-level promise is therefore "non-retention by
// default": clients that don't know or care about `store` get the
// privacy-preserving behavior, while clients that need server-side
// retention features (e.g. Responses API `previous_response_id`
// continuation, which requires the upstream provider to retain the
// prior response) can opt in by sending `store: true` explicitly.
// Operators that require unconditional non-retention should layer
// their own enforcement on top of this default.
//
// Both the Chat Completions and Responses APIs accept a top-level
// boolean `store` that asks the provider to retain the request for
// dashboards / evals / fine-tuning. The default-to-false rule keeps a
// curl one-liner or unsophisticated SDK from silently inheriting an
// upstream provider's default (OpenAI defaults to retention) while
// still letting deliberate clients opt in.
//
// Non-JSON bodies and JSON bodies whose top level isn't an object are
// returned unchanged: an upstream LLM rejects them outright, so there
// is no `store` field shape to set and no plaintext for any provider
// to retain. The returned byte slice is a freshly-marshaled copy when
// the body was modified — callers are free to store or modify it
// without affecting the input.
func DefaultStoreFalse(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}

	// `store: null` is treated as "field omitted" rather than "explicit
	// caller value": OpenAI's null-handling falls back to its default
	// (store=true), which would silently defeat the safety net for
	// callers who serialized a nil/None field by accident.
	if v, ok := obj["store"]; ok && string(bytes.TrimSpace(v)) != "null" {
		return body, nil
	}
	obj["store"] = json.RawMessage("false")

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}

// ForceStoreFalse is DefaultStoreFalse without the opt-in: it sets
// `store: false` unconditionally, overriding an explicit `store: true`
// from the caller.
//
// It exists for one deployment shape, and outside that shape it is the
// wrong function. Under an attested passthrough posture (SPEC §3e,
// `plaintext_terminates: named_upstream`) the node forwards decrypted
// prompts to an upstream account the OPERATOR owns. Upstream retention
// is then precisely the channel through which an operator reads prompts
// back — while every attestation claim they make stays literally true,
// because the measurement covers the node, not the third party's
// storage. Leaving `store` caller-controlled there means the payer's
// privacy depends on the payer having thought about a field they have
// no reason to know exists.
//
// The cost is stated rather than hidden: Responses-API
// `previous_response_id` continuation is unavailable on such a node,
// because it requires exactly the retention this refuses. That belongs
// in the operator guide and in the posture block's documented meaning
// — not discovered by a client at runtime.
//
// Everywhere else, DefaultStoreFalse is correct and this is not: it
// takes a decision away from a caller who may have a legitimate reason
// to make it.
func ForceStoreFalse(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}

	// Already false: return the ORIGINAL bytes rather than a
	// remarshalled copy. Re-marshalling reorders keys, and on the
	// node's path this body is what the receipt's body_hash is
	// computed over downstream — an unnecessary rewrite is a
	// gratuitous risk on a hash the proxy verifies end-to-end.
	if v, ok := obj["store"]; ok && string(bytes.TrimSpace(v)) == "false" {
		return body, nil
	}
	obj["store"] = json.RawMessage("false")

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}
