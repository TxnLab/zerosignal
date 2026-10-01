/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// SafetyIdentifierPrefix tags strings produced by SafetyIdentifierFor so
// downstream observers can distinguish zs-derived identifiers from
// anything else a client might place in OpenAI's safety_identifier field.
const SafetyIdentifierPrefix = "zs:"

// SafetyIdentifierFor returns the value the node places in OpenAI's
// `safety_identifier` request field when the caller hasn't supplied one.
// It is HMAC-SHA256 of the payer's Algorand address under an
// operator-scoped secret `key`, base64-encoded and tagged with the "zs:"
// prefix — so the raw address never appears in OpenAI's request logs and
// the length is predictable regardless of address encoding upstream.
//
// Format: "zs:" + base64(HMAC-SHA256(key, addr)). Deterministic for a
// fixed (key, address) pair and stable across restarts, because the node
// derives `key` once from its long-lived signing key.
//
// The key MUST be operator/node-scoped and secret. A bare hash of the
// address (no key) is deterministic *globally*, so two operators both
// injecting it would send OpenAI the SAME identifier for the same payer,
// letting a shared upstream join one payer's traffic across the whole
// fleet. Keying by a per-node secret makes the same payer produce a
// DIFFERENT identifier at each node, and — the key being secret — one an
// upstream cannot recompute even if it independently learns the address.
//
// Why the node, not the proxy: the node is the only party that can
// *verify* who paid — it inspects the tx_id against algod. The proxy
// knows who it intended to pay with, but the node knows who actually
// paid. Putting injection on the node side means OpenAI's safety signal
// is grounded in the verified-on-chain payer, not in a proxy claim.
//
// OpenAI uses safety_identifier as a stable-per-user signal for their
// abuse / rate-limiting models. Without it, every request from a single
// proxy looks like one monolithic user — which triggers rate limits and
// degrades the quality of OpenAI's safety classification. With the
// Algorand payer as the grain, OpenAI sees distinct identifiers per
// independently-funded caller, which is the correct granularity for a
// paid-inference system.
func SafetyIdentifierFor(key []byte, algorandAddr string) string {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(algorandAddr))
	return SafetyIdentifierPrefix + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// InjectSafetyIdentifier rewrites an OpenAI-compatible request body to
// include a `safety_identifier` field if one isn't already present. A
// client-supplied value is always preserved — the node only fills in the
// default, it never overrides finer-grained identifiers the client may
// have chosen.
//
// Non-JSON bodies and JSON bodies whose top level isn't an object are
// returned unchanged. This keeps the helper safe to call on any request
// path without needing to know the exact OpenAI endpoint shape.
//
// The returned byte slice is a freshly-marshaled copy — callers are free
// to store or modify it without affecting the input.
func InjectSafetyIdentifier(body []byte, identifier string) ([]byte, error) {
	if identifier == "" || len(body) == 0 {
		return body, nil
	}

	// Parse as a generic object so unknown fields (model, messages, tools,
	// stream, response_format, tool_choice, etc.) are passed through
	// verbatim via json.RawMessage. This avoids accidentally coercing or
	// reformatting anything the client sent.
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		// Not a JSON object at the top level — leave it alone. The
		// upstream will decide whether to reject it; we're not in the
		// validation business here.
		return body, nil
	}

	if _, alreadyPresent := obj["safety_identifier"]; alreadyPresent {
		return body, nil
	}

	idJSON, err := json.Marshal(identifier)
	if err != nil {
		return nil, fmt.Errorf("marshal safety_identifier: %w", err)
	}
	obj["safety_identifier"] = idJSON

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}
