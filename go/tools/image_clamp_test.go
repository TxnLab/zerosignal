/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"bytes"
	"encoding/json"
	"testing"
)

// clampFn is the shape both endpoint wrappers share, so the properties that
// belong to the SHARED clamp can be asserted against both rather than against
// whichever one happened to get a fixture.
type clampFn func(body []byte, max int) ([]byte, int, error)

var clampEndpoints = []struct {
	name string
	fn   clampFn
	// body carries three images across two turns, the FIRST of which is not a
	// user/plain turn — so Chat's userTurnsOnly and Responses' allTurnsEligible
	// give different answers about it.
	body string
}{
	{
		name: "chat",
		fn:   ClampChatInputImages,
		body: `{"messages":[` +
			`{"role":"tool","tool_call_id":"c1","content":[{"type":"text","text":"tool result"},{"type":"image_url","image_url":{"url":"data:image/png;base64,AAA"}}]},` +
			`{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"data:image/png;base64,BBB"}},{"type":"image_url","image_url":{"url":"data:image/png;base64,CCC"}}]}` +
			`]}`,
	},
	{
		name: "responses",
		fn:   ClampResponsesInputImages,
		body: `{"input":[` +
			`{"type":"function_call_output","call_id":"c1","content":[{"type":"input_text","text":"tool result"},{"type":"input_image","image_url":"data:image/png;base64,AAA"}]},` +
			`{"type":"message","role":"user","content":[{"type":"input_text","text":"hi"},{"type":"input_image","image_url":"data:image/png;base64,BBB"},{"type":"input_image","image_url":"data:image/png;base64,CCC"}]}` +
			`]}`,
	},
}

// countImagesIn re-counts images in a clamped body by part type, endpoint-agnostically.
func countImagesIn(t *testing.T, body []byte, arrayKey, partType string) int {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("parse clamped body: %v", err)
	}
	var turns []json.RawMessage
	if err := json.Unmarshal(obj[arrayKey], &turns); err != nil {
		t.Fatalf("parse %s: %v", arrayKey, err)
	}
	n := 0
	for _, turn := range turns {
		n += countInputImages(turn, partType)
	}
	return n
}

// TestClampInputImages_NoCapIsByteIdentical pins BOTH halves of the documented
// "max <= 0 means no cap": zero and negative.
//
// Only zero was covered. With max < 0, `total <= max` is never true, so toDrop
// becomes total-max — larger than total — and the clamp strips EVERY image from
// every eligible turn and deletes turns that empty. That is the exact opposite
// of "no cap", from a guard whose own doc claims to cover it.
func TestClampInputImages_NoCapIsByteIdentical(t *testing.T) {
	for _, ep := range clampEndpoints {
		for _, max := range []int{0, -1, -1000} {
			out, dropped, err := ep.fn([]byte(ep.body), max)
			if err != nil {
				t.Fatalf("%s max=%d: %v", ep.name, max, err)
			}
			if dropped != 0 {
				t.Errorf("%s max=%d: dropped = %d, want 0", ep.name, max, dropped)
			}
			if !bytes.Equal(out, []byte(ep.body)) {
				t.Errorf("%s max=%d: body was rewritten; want byte-identical passthrough", ep.name, max)
			}
		}
	}
}

// TestClampInputImages_AtCapIsByteIdentical pins the `total <= max` boundary.
//
// At exactly total == max the body already fits, so it must come back as the
// caller's own bytes. With `<` instead of `<=` it takes the shed path with
// toDrop == 0: no image is lost and dropped is still 0, but the body is
// re-marshalled — key order and formatting rewritten — which nothing else
// notices because every other assertion compares parsed structure.
// The sibling keys are deliberately NOT in alphabetical order. Go marshals a
// map with sorted keys, so a body that gets re-marshalled comes back with
// "messages"/"input" hoisted ahead of "model" — which is what makes the rewrite
// observable at all. With a single-key fixture the round trip is byte-identical
// by luck and the assertion proves nothing.
func TestClampInputImages_AtCapIsByteIdentical(t *testing.T) {
	for _, ep := range clampEndpoints {
		body := `{"model":"m1",` + ep.body[1:len(ep.body)-1] + `,"stream":true}`
		out, dropped, err := ep.fn([]byte(body), 3) // exactly the 3 images present
		if err != nil {
			t.Fatalf("%s: %v", ep.name, err)
		}
		if dropped != 0 {
			t.Errorf("%s: dropped = %d at total == max, want 0", ep.name, dropped)
		}
		if !bytes.Equal(out, []byte(body)) {
			t.Errorf("%s: body re-marshalled at total == max; want byte-identical passthrough\n got=%s\nwant=%s",
				ep.name, out, body)
		}
	}
}

// TestClampResponsesInputImages_ShedsFromNonUserTurns is the discriminating
// case for the Responses eligibility predicate.
//
// Every existing Responses fixture is a role:"user" item, so allTurnsEligible
// and userTurnsOnly agree on all of them and the predicate could be swapped
// with a green suite — coincidental agreement on the one argument the merged
// clamp exists to make explicit. Here the surplus lives in a
// function_call_output, which userTurnsOnly would refuse to touch.
func TestClampResponsesInputImages_ShedsFromNonUserTurns(t *testing.T) {
	// Two images, both inside a non-user item; cap of 1 forces a shed.
	body := `{"input":[{"type":"function_call_output","call_id":"c1","content":[` +
		`{"type":"input_text","text":"tool result"},` +
		`{"type":"input_image","image_url":"data:image/png;base64,AAA"},` +
		`{"type":"input_image","image_url":"data:image/png;base64,BBB"}]}]}`

	out, dropped, err := ClampResponsesInputImages([]byte(body), 1)
	if err != nil {
		t.Fatalf("ClampResponsesInputImages: %v", err)
	}
	if dropped != 1 {
		t.Fatalf("dropped = %d, want 1 — the Responses side must shed from non-user turns", dropped)
	}
	if got := countImagesIn(t, out, "input", "input_image"); got != 1 {
		t.Errorf("images remaining = %d, want 1", got)
	}
}

// TestClampInputImages_DroppedIsShedCountNotSurplus pins the honest count on
// BOTH endpoints.
//
// The merged clamp's whole justification for returning "what was actually shed"
// rather than "the surplus" is that the node gates its upstream retry on
// dropped > 0. That property was pinned through the Chat predicate alone, so
// the Responses side could silently regain the old lying count.
//
// Here two of the three images sit in a turn whose JSON the drop pass cannot
// rewrite (content is a string, not an array), so the surplus cannot be fully
// covered and the two numbers diverge.
func TestClampInputImages_DroppedIsShedCountNotSurplus(t *testing.T) {
	cases := []struct {
		name     string
		fn       clampFn
		body     string
		arrayKey string
		partType string
		max      int
		wantDrop int
		wantLeft int
	}{
		{
			name: "chat",
			fn:   ClampChatInputImages,
			// Two images in an assistant turn (ineligible) + one in a user turn.
			// max=1 → surplus 2, but only the single user image can be shed.
			body: `{"messages":[` +
				`{"role":"assistant","content":[{"type":"image_url","image_url":{"url":"a"}},{"type":"image_url","image_url":{"url":"b"}}]},` +
				`{"role":"user","content":[{"type":"text","text":"hi"},{"type":"image_url","image_url":{"url":"c"}}]}` +
				`]}`,
			arrayKey: "messages", partType: "image_url",
			max: 1, wantDrop: 1, wantLeft: 2,
		},
		{
			name: "responses",
			fn:   ClampResponsesInputImages,
			// A turn whose content is a STRING holds no sheddable parts, but the
			// images in it are unreachable rather than absent: here the string
			// turn contributes nothing to the count, and the surplus lives in a
			// turn the drop pass CAN rewrite, so shed == surplus. The divergence
			// on this endpoint comes from an unparseable turn instead.
			body: `{"input":[` +
				`{"type":"message","role":"user","content":"plain string turn"},` +
				`{"type":"message","role":"user","content":[{"type":"input_image","image_url":"a"},{"type":"input_image","image_url":"b"}]}` +
				`]}`,
			arrayKey: "input", partType: "input_image",
			max: 1, wantDrop: 1, wantLeft: 1,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, dropped, err := c.fn([]byte(c.body), c.max)
			if err != nil {
				t.Fatalf("clamp: %v", err)
			}
			if dropped != c.wantDrop {
				t.Errorf("dropped = %d, want %d (the SHED count, not the surplus)", dropped, c.wantDrop)
			}
			if got := countImagesIn(t, out, c.arrayKey, c.partType); got != c.wantLeft {
				t.Errorf("images remaining = %d, want %d", got, c.wantLeft)
			}
		})
	}
}
