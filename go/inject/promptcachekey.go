/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"fmt"
)

// DropPromptCacheKey removes the top-level `prompt_cache_key` field from an
// OpenAI-compatible request body.
//
// `prompt_cache_key` is OpenAI's opt-in hint for routing a request to the cache
// shard that already holds its prefix. Clients derive it from things that do not
// change across a conversation — Hermes Agent uses a digest of (session id,
// system prompt, tool schemas) — so one value is stable for a whole session and
// IDENTICAL whichever operator serves any given turn.
//
// Be precise about what that does and does not buy an adversary, because the
// obvious framing is wrong: the proxy does NOT rotate targets per turn.
// selection.SelectTargets is deterministic (price sort, id tiebreak) and
// affinity deliberately PINS one operator across tool rounds and
// previous_response_id continuations; the per-request random draw in this
// protocol is relay selection, not target selection. And any operator that
// serves a turn already decrypts the whole conversation history and reads
// payer_addr off the verified payment, so two operators who each served a turn
// can join them on prompt prefix or payer without help.
//
// What the field adds is an EXACT-MATCH join key: a short opaque token, cheap to
// log and index, that survives context truncation, prompt edits and compaction —
// the cases where prefix matching stops working. It is also a token the caller
// never meant as an identifier, so nothing on its path treats it as one. That
// makes it gratuitous rather than catastrophic, and gratuitous is the easy call:
// a target CAN change between turns (registry, price, reachability or a caller
// routing preference), the request crosses a relay, and nothing downstream needs
// the value. SafetyIdentifierFor answers the same question the other way, keying
// its identifier per node so the same payer looks different at each one; see its
// comment on why a globally-deterministic identifier would let a shared upstream
// join one payer's traffic across the fleet.
//
// Stripping costs the payer the shard hint, not prompt caching itself: upstreams
// that cache do so on the prompt prefix regardless, and the node's own request
// to the provider carries the same prefix either way. Recovering the hint
// without the join would mean rewriting the value per operator under a secret
// the operator cannot recompute (HMAC, as SafetyIdentifierFor does) rather than
// dropping it; that is a larger change and is not what this does.
//
// Note the node's responses-to-chat translator already drops this field
// (node/internal/llm/responsestochat), so on an emulating node it never reached
// the upstream anyway. This strip is what stops it reaching the node at all, and
// covers the natively-Responses backends the translator never sees.
//
// Non-JSON bodies and JSON whose top level isn't an object are returned
// unchanged — the upstream rejects those anyway, and this helper is not in the
// validation business. A body without the key is returned unchanged. The
// returned slice is a freshly-marshaled copy only when the body was modified.
//
// Callers strip pre-seal, so the AAD / admission tag commit to the cleaned body
// — the same discipline as DefaultStoreFalse / DropEmptyTools /
// DropRoutingPreferences.
func DropPromptCacheKey(body []byte) ([]byte, error) {
	if len(body) == 0 {
		return body, nil
	}

	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body, nil
	}

	if _, ok := obj["prompt_cache_key"]; !ok {
		return body, nil
	}

	delete(obj, "prompt_cache_key")

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}
