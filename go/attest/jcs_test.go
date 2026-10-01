/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package attest

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestJCS_RefusesWhatItCannotCanonicalize.
//
// EVERY CASE HERE IS ONE NO LIVE DOCUMENT CONTAINS, and that is the point.
// The ACI keyset this canonicalizer exists to digest is all-ASCII strings and
// small integers, so the live path exercises only the easy half of RFC 8785.
// An earlier revision of this code (in proxy's aci probe) asserted its
// refusal discipline in a COMMENT and was wrong in four ways — negative zero,
// integers past 2^53, U+2028/U+2029, and invalid UTF-8 — while running green
// against a real gateway, because the gateway never sent any of them.
//
// Each of those four produced a well-formed but WRONG digest. From outside,
// that is indistinguishable from an honest verifier catching a lying peer,
// which is the worst available failure direction: the bug looks like the
// feature working.
func TestJCS_RefusesWhatItCannotCanonicalize(t *testing.T) {
	// From code points, never source literals: the two characters these
	// cases are about are invisible, and a test whose fixtures you cannot
	// see is one nobody can check by reading it.
	sep28, sep29 := string(rune(0x2028)), string(rune(0x2029))

	for _, tc := range []struct {
		name, doc, wantIn string
	}{
		{"negative zero", `{"n":-0}`, "§3.2.2.2"},
		{"beyond 2^53", `{"n":9007199254740993}`, "§3.2.2.2"},
		{"non-integer", `{"n":1.5}`, "§3.2.2.2"},
		{"exponent", `{"n":1e3}`, "§3.2.2.2"},
		{"U+2028 in a value", `{"s":"a` + sep28 + `b"}`, "U+2028"},
		{"U+2029 in a value", `{"s":"a` + sep29 + `b"}`, "U+2029"},
		{"U+2028 in a key", `{"a` + sep28 + `b":1}`, "non-ASCII object key"},
		{"non-ASCII key", `{"é":1}`, "non-ASCII object key"},
		{"trailing content", `{"a":1} {"b":2}`, "trailing content"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JCSCanonicalize(json.RawMessage(tc.doc))
			if err == nil {
				t.Fatalf("canonicalized %s to %q; want a refusal naming %s",
					tc.doc, got, tc.wantIn)
			}
			// Sentinel, so a caller can tell "cannot verify" from
			// "does not match" — they lead to opposite conclusions
			// about the peer.
			if !errors.Is(err, ErrJCSUnsupported) {
				t.Errorf("refusal does not wrap ErrJCSUnsupported, so a caller cannot "+
					"distinguish it from a mismatch: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("refused, but the message does not name %q, so it does not tell "+
					"the reader which clause it could not satisfy: %v", tc.wantIn, err)
			}
		})
	}

	// THE ACCEPT SIDE OF THE 2^53 BOUND. The table above pins …993 as a
	// refusal, which a `>=` in place of the `>` also satisfies — so the bound
	// itself was unpinned, and tightening it by one turns every integer at 2^53
	// into "cannot verify". 2^53 is exactly representable as a double and its
	// decimal literal is identical to its ES Number::toString form, so §3.2.2.2
	// is satisfiable here and refusing it would be wrong.
	t.Run("exactly 2^53 is accepted", func(t *testing.T) {
		const doc = `{"n":9007199254740992}`
		got, err := JCSCanonicalize(json.RawMessage(doc))
		if err != nil {
			t.Fatalf("refused 2^53, which is exactly representable: %v", err)
		}
		if string(got) != doc {
			t.Errorf("got %q, want %q", got, doc)
		}
	})

	// THE U+FFFD SUBSTITUTION CLASS, ASSERTED THROUGH THE PUBLIC API.
	//
	// This used to be one subtest calling jcsWriteString directly, on the
	// reasoning that "invalid UTF-8 cannot arrive as a Go string through
	// encoding/json — the decoder substitutes U+FFFD first". That reasoning was
	// correct and was the bug: it describes a guard NO CALLER CAN REACH, and
	// meanwhile all three inputs below canonicalized to the same
	// `{"s":"�"}` with a nil error. sha256(JCS(doc)) was therefore not
	// injective over exactly the class the canonicalizer was written to refuse,
	// so one signature covered several documents and a conformant peer (which
	// either errors or emits `\ud800` per ES2019 well-formed stringify) would
	// read as a liar.
	//
	// The guard moved to jcsCheckRaw, on the raw bytes before any decode, and
	// these assert it where a caller actually is. Each case is a DISTINCT input
	// that previously shared one output.
	for _, tc := range []struct {
		name   string
		raw    string
		wantIn string
	}{
		{"raw invalid UTF-8 byte", "{\"s\":\"a\xffb\"}", "not valid UTF-8"},
		{"lone high surrogate escape", `{"s":"\ud800"}`, "high surrogate"},
		{"lone low surrogate escape", `{"s":"\udead"}`, "low surrogate"},
		{"high surrogate followed by a plain char", `{"s":"\ud800x"}`, "high surrogate"},
		// A real SECOND ESCAPE, not a plain char. This case read `\ud800A`
		// until 2026-09-25 — the same input shape as the line above it, so the
		// table held two copies of one case and nothing walked the low-surrogate
		// range check at all.
		{"high surrogate followed by a non-surrogate escape", `{"s":"\ud800A"}`, "high surrogate"},
		// THE THREE RANGE BOUNDARIES, each its own case because each is one
		// comparison away and all three previously canonicalized to `{"s":"�"}`
		// with a nil error — the exact non-injectivity this guard exists for.
		{"the LAST low surrogate, alone", `{"s":"\udfff"}`, "low surrogate"},
		{"two low surrogates", `{"s":"\udc00\udc00"}`, "low surrogate"},
		{"two high surrogates", `{"s":"\ud800\ud800"}`, "high surrogate"},
		{"invalid UTF-8 in a KEY", "{\"a\xffb\":1}", "not valid UTF-8"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := JCSCanonicalize(json.RawMessage(tc.raw))
			if err == nil {
				t.Fatalf("canonicalized %q to %q; Go substitutes U+FFFD, so this hashes "+
					"bytes the peer never sent", tc.raw, got)
			}
			if !errors.Is(err, ErrJCSUnsupported) {
				t.Errorf("refusal does not wrap ErrJCSUnsupported: %v", err)
			}
			if !strings.Contains(err.Error(), tc.wantIn) {
				t.Errorf("refused, but the message does not name %q: %v", tc.wantIn, err)
			}
		})
	}

	// The paired form must still be ACCEPTED, or the fix above is just a
	// refusal of all astral-plane text — and every emoji in a document would
	// become "cannot verify".
	t.Run("a VALID surrogate pair is accepted", func(t *testing.T) {
		got, err := JCSCanonicalize(json.RawMessage(`{"s":"😀"}`))
		if err != nil {
			t.Fatalf("refused a well-formed surrogate pair (U+1F600): %v", err)
		}
		if want := "{\"s\":\"\U0001F600\"}"; string(got) != want {
			t.Errorf("got %q, want %q — §3.2.2.1 requires the literal code point", got, want)
		}
	})

	// THE ESCAPED FORM, which is the one the scanner above actually walks. The
	// subtest before this one carries U+1F600 as a literal in the Go source, so
	// the raw bytes hold no backslash and the surrogate scanner never runs —
	// the accept path (advancing past BOTH escapes of a valid pair) was
	// reachable by no test at all. A scanner that advanced by the wrong amount
	// would refuse every astral-plane character written in escaped form, which
	// is "cannot verify this upstream" for any document carrying one.
	t.Run("a valid surrogate pair in ESCAPED form is accepted", func(t *testing.T) {
		got, err := JCSCanonicalize(json.RawMessage(`{"s":"😀"}`))
		if err != nil {
			t.Fatalf("refused an escaped well-formed pair (U+1F600): %v", err)
		}
		if want := "{\"s\":\"\U0001F600\"}"; string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	// An escaped BACKSLASH followed by the text "uD800" is not an escape, and
	// must not be refused. Without this, the scanner's run-counting is unpinned.
	t.Run("an escaped backslash before uD800 is literal text", func(t *testing.T) {
		got, err := JCSCanonicalize(json.RawMessage(`{"s":"\\ud800"}`))
		if err != nil {
			t.Fatalf("refused a literal backslash followed by \"ud800\": %v", err)
		}
		if want := `{"s":"\\ud800"}`; string(got) != want {
			t.Errorf("got %q, want %q", got, want)
		}
	})

	// A STRAY CLOSING BRACKET, which dec.More() cannot see.
	//
	// More() is `err == nil && c != ']' && c != '}'`, so these two bytes were
	// invisible to the trailing-content guard and `{"a":1}}` canonicalized to
	// `{"a":1}` — the exact digest collision that guard names as its reason to
	// exist.
	for _, raw := range []string{`{"a":1}}`, `{"a":1}]`, `[1]]`, `[1]}`} {
		t.Run("stray closer "+raw, func(t *testing.T) {
			got, err := JCSCanonicalize(json.RawMessage(raw))
			if err == nil {
				t.Fatalf("canonicalized %q to %q — two documents differing only after the "+
					"first value now share a digest", raw, got)
			}
			if !errors.Is(err, ErrJCSUnsupported) {
				t.Errorf("refusal does not wrap ErrJCSUnsupported: %v", err)
			}
		})
	}

	// Trailing WHITESPACE is not trailing content. Without this the fix above
	// could be "refuse anything after the value", which would reject a
	// pretty-printed document the peer legitimately sent.
	t.Run("trailing whitespace is accepted", func(t *testing.T) {
		if _, err := JCSCanonicalize(json.RawMessage("{\"a\":1}\n  \t")); err != nil {
			t.Fatalf("refused trailing whitespace: %v", err)
		}
	})

	// THE POSITIVE HALF. Without it a canonicalizer that refused
	// EVERYTHING passes every case above, and the live checks then fail
	// for a reason nobody could attribute.
	t.Run("canonicalizes a keyset-shaped document", func(t *testing.T) {
		got, err := JCSCanonicalize(json.RawMessage(
			`{"b":[1,-2,null,true],"a":"x<&>y","not_after":1790498751,"z":{"k":""}}`))
		if err != nil {
			t.Fatalf("refused a document it must accept: %v", err)
		}
		// Keys sorted, no whitespace, and the HTML trio left alone —
		// the one escaping difference SetEscapeHTML(false) removes.
		const want = `{"a":"x<&>y","b":[1,-2,null,true],"not_after":1790498751,"z":{"k":""}}`
		if string(got) != want {
			t.Errorf("canonical form:\n  got  %s\n  want %s", got, want)
		}
	})

	// Key order in the INPUT must not reach the output, which is the
	// single property every caller depends on and the one a
	// "canonicalizer" that merely re-encoded would still get right by
	// accident on an already-sorted document.
	t.Run("input key order does not survive", func(t *testing.T) {
		a, err := JCSCanonicalize(json.RawMessage(`{"z":1,"a":2}`))
		if err != nil {
			t.Fatal(err)
		}
		b, err := JCSCanonicalize(json.RawMessage(`{"a":2,"z":1}`))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("two orderings of one document canonicalized differently: %s vs %s", a, b)
		}
	})
}
