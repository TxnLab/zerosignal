/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"encoding/json"
	"fmt"
)

// The input-image clamp, shared by /v1/chat/completions and /v1/responses.
//
// The two endpoints differ in exactly three things: which top-level array
// holds the turns ("messages" vs "input"), which content-part type names an
// image ("image_url" vs "input_image"), and which of those turns may be shed
// from. Everything else — count across the whole array, shed oldest-first,
// preserve an image's sibling parts, drop a turn whose content empties, report
// what was actually shed — is one algorithm, so it is written once.
//
// contentPartType already claimed to be the single source of truth for the
// part-type literal across both files; the extraction had simply stopped one
// level too low, leaving the 38-line drop pass and the 21-line count pass
// duplicated above it.

// shedEligible reports whether an element of the turn array may have images
// shed from it. It never affects COUNTING — an ineligible turn's images still
// count toward the cap, because the upstream will still see them.
type shedEligible func(element json.RawMessage) bool

// allTurnsEligible is the Responses-side predicate: every input[] item may be
// shed from. Named rather than passed as nil so the absence of a restriction
// is a stated decision at the call site, not an omission.
func allTurnsEligible(json.RawMessage) bool { return true }

// userTurnsOnly is the Chat-side predicate. Non-user messages are structurally
// load-bearing — a tool message is bound to a preceding assistant tool_call by
// id, and removing it would orphan that call and draw a *different* 400 from
// strict upstreams — so they are counted but never touched.
func userTurnsOnly(msg json.RawMessage) bool { return chatMessageRole(msg) == "user" }

// clampInputImages caps the number of image content parts in body's turn array
// at max, shedding oldest-first from eligible turns only.
//
// It returns the number of images ACTUALLY shed, which is not always the
// surplus: when the eligible turns cannot cover it (a cap exceeded by images
// in ineligible turns, or a turn whose JSON does not parse), the body may
// still exceed max. The node gates its upstream retry on dropped > 0, so
// reporting the surplus rather than the shed count would make that gate lie.
//
// max <= 0 means "no cap": body is returned byte-for-byte unchanged. Likewise
// when it already fits, when arrayKey is absent, or when arrayKey holds a bare
// string (which carries no image).
func clampInputImages(body []byte, max int, arrayKey, partType string, eligible shedEligible) (out []byte, dropped int, err error) {
	if max <= 0 {
		return body, 0, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, 0, fmt.Errorf("parse body: %w", err)
	}
	raw, ok := obj[arrayKey]
	if !ok {
		return body, 0, nil
	}
	var turns []json.RawMessage
	if err := json.Unmarshal(raw, &turns); err != nil {
		return body, 0, nil
	}
	// Count every image the upstream will see, across ALL turns, to size the
	// surplus…
	total := 0
	for _, t := range turns {
		total += countInputImages(t, partType)
	}
	if total <= max {
		return body, 0, nil
	}
	// …but shed only from eligible turns, oldest→newest, parts oldest→newest.
	// The newest images (the just-produced tool image; the latest upload) are
	// reached last, so they survive.
	toDrop := total - max
	kept := make([]json.RawMessage, 0, len(turns))
	for _, t := range turns {
		if toDrop == 0 || !eligible(t) {
			kept = append(kept, t)
			continue
		}
		trimmed, removed, empty := dropInputImages(t, toDrop, partType)
		toDrop -= removed
		if empty {
			continue
		}
		kept = append(kept, trimmed)
	}
	newTurns, err := json.Marshal(kept)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal %s: %w", arrayKey, err)
	}
	obj[arrayKey] = newTurns
	out, err = json.Marshal(obj)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal body: %w", err)
	}
	return out, (total - max) - toDrop, nil
}

// countInputImages returns how many parts of type partType a turn's content
// array holds. Turns with string or absent content hold none.
func countInputImages(turn json.RawMessage, partType string) int {
	var obj struct {
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal(turn, &obj); err != nil {
		return 0
	}
	if len(obj.Content) == 0 || obj.Content[0] != '[' {
		return 0
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(obj.Content, &parts); err != nil {
		return 0
	}
	n := 0
	for _, p := range parts {
		if contentPartType(p) == partType {
			n++
		}
	}
	return n
}

// dropInputImages removes up to limit parts of type partType (oldest-first)
// from a turn's content array. It returns the rewritten turn, how many it
// removed, and whether the content became empty (so the caller can omit the
// whole turn). A turn with string or absent content is returned unchanged.
func dropInputImages(turn json.RawMessage, limit int, partType string) (json.RawMessage, int, bool) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(turn, &obj); err != nil {
		return turn, 0, false
	}
	rawContent, ok := obj["content"]
	if !ok || len(rawContent) == 0 || rawContent[0] != '[' {
		return turn, 0, false
	}
	var parts []json.RawMessage
	if err := json.Unmarshal(rawContent, &parts); err != nil {
		return turn, 0, false
	}
	removed := 0
	kept := make([]json.RawMessage, 0, len(parts))
	for _, p := range parts {
		if removed < limit && contentPartType(p) == partType {
			removed++
			continue
		}
		kept = append(kept, p)
	}
	if removed == 0 {
		return turn, 0, false
	}
	if len(kept) == 0 {
		return nil, removed, true
	}
	newContent, err := json.Marshal(kept)
	if err != nil {
		return turn, 0, false
	}
	obj["content"] = newContent
	rebuilt, err := json.Marshal(obj)
	if err != nil {
		return turn, 0, false
	}
	return rebuilt, removed, false
}
