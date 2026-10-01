/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"
)

// DropRoutingPreferences removes the top-level `provider` object from an
// OpenAI-compatible request body. `provider` is the caller's OpenRouter-style
// routing-preference hint (parsed by selection.ExtractRoutingPreferences): it
// guides which operator/node the proxy/client dispatches to and must NEVER
// reach the node or the upstream LLM, which would reject the unknown field (the
// strict vLLM/SGLang pydantic path) or silently forward it. The caller parses
// the preferences first, then strips the field pre-seal so the AAD / admission
// tag commit to the cleaned body — the same pre-seal discipline as
// DefaultStoreFalse / DropEmptyTools.
//
// Non-JSON bodies and JSON whose top level isn't an object are returned
// unchanged (the upstream rejects them anyway). A body without a `provider`
// key is returned unchanged. The returned slice is a freshly-marshaled copy
// only when the body was modified.
func DropRoutingPreferences(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}

	if _, ok := obj["provider"]; !ok {
		return body, nil
	}

	delete(obj, "provider")

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}

// The two `provider` keys that carry OpenRouter's per-request privacy posture,
// and the values EnforceUpstreamPrivacy pins them to. Named rather than
// inlined so the wire strings appear once: a typo in either is silent — the
// request succeeds, routed exactly as it would have been without the key.
const (
	providerZDRKey            = "zdr"
	providerDataCollectionKey = "data_collection"
	providerDataCollectionDen = "deny"
)

// EnforceUpstreamPrivacy pins zero-data-retention and no-training onto an
// outbound OpenRouter request, by force-setting `provider.zdr: true` and
// `provider.data_collection: "deny"`. It is the OpenRouter half of the
// node's "ZDR wherever the upstream supports it" rule; the xAI half is a
// response-header check in the node's provider, because the two upstreams
// expose the guarantee in opposite directions (xAI CONFIRMS what its org
// already set, OpenRouter lets the request DECIDE).
//
// Why setting it per request is sufficient — i.e. why nothing here has to read
// the operator's OpenRouter ZDR / DATA-POLICY settings, which no API exposes
// anyway: OpenRouter's privacy stack is documented as tighten-only. The
// request-level `zdr` is an OR with the account-wide and guardrail settings
// ("can only ensure ZDR is enabled, not override account-wide or guardrail
// enforcement"), and guardrails themselves "can only ever get more
// restrictive". So an operator who has enabled nothing still gets ZDR on every
// request the node sends, and one who has enabled more keeps it.
// `data_collection` precedence is NOT documented, but "deny" is the restrictive
// value under either reading (override or AND), so the ambiguity cannot produce
// a weaker outcome.
//
// READ THAT SUFFICIENCY NARROWLY — it is about the ROUTING FILTER, which these
// keys provably dominate, and it is the whole of what this function claims. Two
// things it does not reach, both recorded on RetentionUpstreamEnforced because
// they bound what that tier may be read to mean:
//
//   - The broker's OWN storage is a different control — an account-level prompt
//     logging opt-in these keys do not set, and which no API exposes either. So
//     "the dashboard stops mattering" is true of the half this pin dominates and
//     false as a general statement; don't compress it.
//   - Nothing observes the outcome. The constraint rides out and no
//     confirmation rides back, unlike the xAI half's per-response header, so an
//     upstream that ignored it looks exactly like one that obeyed.
//
// Neither weakens the pin — it is still strictly better than sending nothing,
// and it is the strongest thing available for this upstream. They bound the
// CLAIM, which is why a posture that must name the single party that read the
// prompt cannot be built on it.
//
// A model with no ZDR endpoint at all becomes unroutable rather than
// unprotected — that is the intended trade, and the node's boot check reports
// it up front instead of leaving it to fail per request.
//
// WHETHER to call this is the node's policy, not this function's. Called with
// DialectOpenRouter it is unconditional and takes no argument that could weaken
// it. The reference node applies it by default and gives operators one opt-out
// (`llm.allow_upstream_retention`) for exactly the trade above — a model
// OpenRouter has no zero-retention route for — and a node that takes it stops
// advertising `upstream_enforced`, so what a payer is told still matches what
// the node sends. That coupling is the node's to maintain; this function only
// guarantees that when it runs, it cannot be talked out of either key.
//
// OVERRIDE, NOT MERGE, for the two keys: the proxy strips a caller's `provider`
// object pre-seal (DropRoutingPreferences), but a client speaking straight to a
// node does not, so a caller-supplied `data_collection: "allow"` has to lose.
// Every other key in the object — `order`, `only`, `ignore`, `sort`,
// `max_price`, `allow_fallbacks` — is routing rather than privacy and survives
// untouched.
//
// FAIL-CLOSED, unlike the rest of this package. The other mutators forward the
// body unchanged when they cannot parse it, because each is an optimization of
// upstream behavior and a paid request should not die for one. This one is the
// privacy guarantee itself: forwarding a body it could not annotate is exactly
// the outcome it exists to prevent, so a body that is not a JSON object, or
// whose `provider` is not an object, returns an error. Callers turn that into a
// refusal before any bytes reach the upstream. An empty body is the one
// exception — there is no prompt in it to protect.
//
// A dialect other than DialectOpenRouter is a no-op: no other upstream reads
// these keys, and sending them would be an unknown field on the strict
// vLLM/SGLang pydantic path. Idempotent — a second pass rewrites the same two
// values.
func EnforceUpstreamPrivacy(body []byte, d Dialect) ([]byte, error) {
	if d != DialectOpenRouter || len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("parse body to enforce upstream privacy: %w", err)
	}
	// A top-level `null` decodes into a map as (nil map, NIL ERROR) — the one
	// non-object body that reaches this point without erroring above. Assigning
	// into it panics, so this is the difference between a refusal and a dropped
	// connection on every egress path this mutator guards.
	if obj == nil {
		return nil, fmt.Errorf("parse body to enforce upstream privacy: body is not a JSON object")
	}

	fields := map[string]json.RawMessage{}
	if raw, ok := obj["provider"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("parse provider object to enforce upstream privacy: %w", err)
		}
	}

	fields[providerZDRKey] = json.RawMessage(`true`)
	fields[providerDataCollectionKey] = json.RawMessage(`"` + providerDataCollectionDen + `"`)

	enc, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("remarshal provider object: %w", err)
	}
	obj["provider"] = enc

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}

// providerACIVerifiedKey is the ACI/1 serving constraint (spec §5.3).
//
// The aggregator REJECTS any unrecognized `aci_`-prefixed sibling with
// invalid_request_error rather than ignoring it — so a typo here does not
// degrade to an unconstrained request, it fails every request. That is the
// right direction, and it is why the string appears once.
const providerACIVerifiedKey = "aci_verified"

// PinACIVerified sets `provider.aci_verified: true` on an outbound body, the
// ACI/1 constraint requiring the aggregator to serve through a verified
// attested session (spec §5.3).
//
// IT IS THE PRE-FLIGHT HALF OF THE UPSTREAM-ATTESTATION GUARANTEE. The signed
// receipt proves after the fact where a prompt went; this decides, before a
// byte is forwarded, that it may only go somewhere verified — which is what
// makes the receipt's own `upstream.verified.required` true. Without it the
// aggregator falls back to the deployment's setting, serves best-effort when
// that is off, and records the outcome as merely informational. The
// constraint only tightens: it cannot loosen a deployment that already
// requires verification.
//
// A SECOND, LESS OBVIOUS EFFECT, load-bearing for the receipt half: a request
// carrying a §5.3 constraint is never committed early, so the response always
// carries X-Receipt-Id. An unconstrained STREAMING request MAY omit it,
// leaving the caller to rediscover the receipt by response id.
//
// NOT DIALECT-GATED, unlike EnforceUpstreamPrivacy. Whether an upstream speaks
// ACI/1 is not a property of its URL — it is the operator's configured claim,
// appraised at boot against a real attestation — so the caller decides and
// this function does not second-guess it.
//
// FAIL-CLOSED, for the same reason EnforceUpstreamPrivacy is: forwarding a
// body it could not annotate is the outcome it exists to prevent. Every other
// key in `provider` survives untouched. Idempotent.
func PinACIVerified(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("parse body to pin aci_verified: %w", err)
	}
	// A top-level `null` decodes to a nil map with a NIL error, and
	// assigning into it panics — the difference between a refusal and a
	// dropped connection on every egress path this guards.
	if obj == nil {
		return nil, fmt.Errorf("parse body to pin aci_verified: body is not a JSON object")
	}

	fields := map[string]json.RawMessage{}
	if raw, ok := obj["provider"]; ok && !isJSONNull(raw) {
		if err := json.Unmarshal(raw, &fields); err != nil {
			return nil, fmt.Errorf("parse provider object to pin aci_verified: %w", err)
		}
	}
	fields[providerACIVerifiedKey] = json.RawMessage(`true`)

	enc, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("remarshal provider object: %w", err)
	}
	obj["provider"] = enc

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}
