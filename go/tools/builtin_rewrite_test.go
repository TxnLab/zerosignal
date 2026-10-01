/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"bytes"
	"testing"
)

// rewriteFn is the shape both endpoint wrappers share. Collapsing their bodies
// into one shared walk made the tolerance rules a SINGLE point of failure for
// both endpoints at once, so they are asserted against both.
type rewriteFn func([]byte, map[BuiltinToolType]BuiltinToolDef) ([]byte, map[string]BuiltinToolType, error)

var rewriteEndpoints = []struct {
	name string
	fn   rewriteFn
}{
	{"chat", RewriteBuiltinToolsChat},
	{"responses", RewriteBuiltinToolsResponses},
}

// TestRewriteBuiltinTools_MalformedBodiesArePassedThrough pins the tolerance
// the shared walk documents as "deliberate and uniform": an empty body, a
// non-object body, and a `tools` that is not an array are all the upstream's
// to reject, not this helper's — matching InjectSafetyIdentifier.
//
// Each of those three branches could be flipped to return an error with the
// whole suite green, which would turn a body the node currently forwards
// untouched into a hard failure on BOTH endpoints simultaneously.
func TestRewriteBuiltinTools_MalformedBodiesArePassedThrough(t *testing.T) {
	bodies := []struct {
		name string
		body []byte
	}{
		{"nil", nil},
		{"empty", []byte{}},
		{"not json", []byte("not json at all")},
		{"json but not an object", []byte(`["tools"]`)},
		{"tools is an object", []byte(`{"tools":{"type":"zs_web_search"}}`)},
		{"tools is a string", []byte(`{"tools":"zs_web_search"}`)},
		{"tools absent", []byte(`{"model":"m1"}`)},
	}
	for _, ep := range rewriteEndpoints {
		for _, b := range bodies {
			out, names, err := ep.fn(b.body, sampleDefs())
			if err != nil {
				t.Errorf("%s/%s: err = %v, want nil (malformed input is the upstream's to reject)", ep.name, b.name, err)
				continue
			}
			if !bytes.Equal(out, b.body) {
				t.Errorf("%s/%s: body rewritten (%q); want byte-identical passthrough", ep.name, b.name, out)
			}
			if names == nil {
				t.Errorf("%s/%s: name map is nil; want empty and non-nil so callers can index it", ep.name, b.name)
			}
			if len(names) != 0 {
				t.Errorf("%s/%s: names = %v, want empty", ep.name, b.name, names)
			}
		}
	}
}

// TestRewriteBuiltinTools_NoBuiltinToolIsByteIdentical pins the !changed early
// return. Both wrappers document that a body needing no rewrite comes back
// byte-identical — but the existing coverage compares parsed structure, so an
// always-re-marshal would pass while silently reordering the caller's keys on
// every ordinary tool-carrying request.
func TestRewriteBuiltinTools_NoBuiltinToolIsByteIdentical(t *testing.T) {
	// Keys deliberately out of alphabetical order: Go marshals maps with sorted
	// keys, so a re-marshalled body hoists "tools" ahead of "model" and the
	// difference is visible. A single-key fixture round-trips identically by
	// luck and would assert nothing.
	body := []byte(`{"model":"m1","tools":[{"type":"function","function":{"name":"user_fn"}}],"stream":true}`)
	for _, ep := range rewriteEndpoints {
		out, names, err := ep.fn(body, sampleDefs())
		if err != nil {
			t.Fatalf("%s: %v", ep.name, err)
		}
		if len(names) != 0 {
			t.Errorf("%s: names = %v, want empty (no hayai built-in present)", ep.name, names)
		}
		if !bytes.Equal(out, body) {
			t.Errorf("%s: body re-marshalled when nothing needed rewriting\n got=%s\nwant=%s", ep.name, out, body)
		}
	}
}
