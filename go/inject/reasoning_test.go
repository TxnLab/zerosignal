/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"bytes"
	"encoding/json"
	"testing"
)

// blob is a real xAI reasoning blob, captured off the wire. Its exact bytes
// are the point of every assertion below: the upstream rejects the request
// if it comes back altered, so the one thing this mutator may never do is
// touch it.
const blob = "ZavGVTkgRFZppDCIKxD9SuMKWcraxNOKbaYr4WyB6cX8cdK/J3rIuqTRPy+uLiVXbqfNenfYdf0Gux6EIoRbGjIidAATyTWcqoSC8bMLjVcHSugOxqvzvXWkHgYNajGBQcTh8geuQJsD6PnAHmYXrr6IlL6FRhAdmRkor9fn83lWRfsUwQ"

// codexReplay is the shape Codex sends back — `status` dropped, a null
// `content` added. Verbatim from a failing turn.
func codexReplay() []byte {
	return []byte(`{"model":"grok-4.5","stream":true,"input":[
		{"type":"message","id":"msg_1","role":"user","content":[{"type":"input_text","text":"what is index.html"}]},
		{"type":"reasoning","id":"rs_120ad21d","summary":[{"type":"summary_text","text":"checking"}],"content":null,"encrypted_content":"` + blob + `"},
		{"type":"function_call","id":"fc_1","name":"exec_command","arguments":"{}","call_id":"call-1"}
	]}`)
}

// reasoningItemAt decodes input[i] for assertions.
func reasoningItemAt(t *testing.T, body []byte, i int) map[string]json.RawMessage {
	t.Helper()
	var obj struct {
		Input []json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("parse body: %v\n%s", err, body)
	}
	if i >= len(obj.Input) {
		t.Fatalf("input has %d items, want index %d", len(obj.Input), i)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(obj.Input[i], &fields); err != nil {
		t.Fatalf("parse item %d: %v", i, err)
	}
	return fields
}

// TestNormalizeReasoningItems_RepairsCodexReplay is the whole reason this
// mutator exists: without it xAI refuses the request outright and the
// second turn of every tool-calling conversation dies.
func TestNormalizeReasoningItems_RepairsCodexReplay(t *testing.T) {
	out := NormalizeReasoningItems(codexReplay())
	item := reasoningItemAt(t, out, 1)

	if got := string(item["status"]); got != `"completed"` {
		t.Errorf("status = %s, want \"completed\"", got)
	}
	if _, ok := item["content"]; ok {
		t.Errorf("null content survived: %s", item["content"])
	}
	// The blob is what the upstream decodes. Byte-identical or nothing.
	var got string
	if err := json.Unmarshal(item["encrypted_content"], &got); err != nil {
		t.Fatalf("encrypted_content not a string: %v", err)
	}
	if got != blob {
		t.Errorf("encrypted_content was altered:\n got %q\nwant %q", got, blob)
	}
	// Neighbours are passed through untouched.
	if u := reasoningItemAt(t, out, 0); string(u["type"]) != `"message"` {
		t.Errorf("user message mangled: %s", u["type"])
	}
	if f := reasoningItemAt(t, out, 2); string(f["call_id"]) != `"call-1"` {
		t.Errorf("function_call mangled: %s", f["call_id"])
	}
}

// TestNormalizeReasoningItems_LeavesCorrectShapeAlone: the shape xAI itself
// emits must round-trip byte-for-byte, or the mutator is the thing breaking
// clients that were already doing it right.
func TestNormalizeReasoningItems_LeavesCorrectShapeAlone(t *testing.T) {
	in := []byte(`{"input":[{"id":"rs_1","summary":[],"type":"reasoning","status":"completed","encrypted_content":"` + blob + `"}]}`)
	if out := NormalizeReasoningItems(in); !bytes.Equal(out, in) {
		t.Errorf("already-correct body was rewritten:\n got %s\nwant %s", out, in)
	}
}

// TestNormalizeReasoningItems_SkipsItemsWithoutBlob: a reasoning item with
// no encrypted_content has nothing an upstream can fail to decode, so
// rewriting it is churn with no upside.
func TestNormalizeReasoningItems_SkipsItemsWithoutBlob(t *testing.T) {
	for _, tc := range []struct{ name, item string }{
		{"absent", `{"type":"reasoning","id":"rs_1","content":null}`},
		{"null", `{"type":"reasoning","id":"rs_1","content":null,"encrypted_content":null}`},
		{"empty", `{"type":"reasoning","id":"rs_1","content":null,"encrypted_content":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(`{"input":[` + tc.item + `]}`)
			if out := NormalizeReasoningItems(in); !bytes.Equal(out, in) {
				t.Errorf("blobless item was rewritten:\n got %s\nwant %s", out, in)
			}
		})
	}
}

// TestNormalizeReasoningItems_LeavesCompactionItemsAlone: reasoning is not
// the only item type that carries an encrypted_content blob — xAI's
// `compaction` item does too, and its shape is documented separately. The
// evidence for the repair is about reasoning items specifically, so
// stamping a `status` onto a compaction item would be exactly the
// unfounded opinion this mutator is built to avoid.
func TestNormalizeReasoningItems_LeavesCompactionItemsAlone(t *testing.T) {
	in := []byte(`{"input":[{"type":"compaction","content":null,"encrypted_content":"` + blob + `"}]}`)
	if out := NormalizeReasoningItems(in); !bytes.Equal(out, in) {
		t.Errorf("compaction item was rewritten:\n got %s\nwant %s", out, in)
	}
}

// TestNormalizeReasoningItems_PreservesUnknownFields: the item shape is the
// upstream's, not ours — a field we've never heard of must survive, since
// it may well be part of what the blob is bound to.
func TestNormalizeReasoningItems_PreservesUnknownFields(t *testing.T) {
	in := []byte(`{"input":[{"type":"reasoning","id":"rs_1","content":null,"future_field":{"a":[1,2]},"encrypted_content":"` + blob + `"}]}`)
	item := reasoningItemAt(t, NormalizeReasoningItems(in), 0)
	if got := string(item["future_field"]); got != `{"a":[1,2]}` {
		t.Errorf("future_field = %s, want {\"a\":[1,2]}", got)
	}
}

// TestNormalizeReasoningItems_Idempotent: the node re-runs this on every
// turn, and a client may replay an already-repaired item.
func TestNormalizeReasoningItems_Idempotent(t *testing.T) {
	once := NormalizeReasoningItems(codexReplay())
	twice := NormalizeReasoningItems(once)
	if !bytes.Equal(once, twice) {
		t.Errorf("not idempotent:\nonce  %s\ntwice %s", once, twice)
	}
}

// TestNormalizeReasoningItems_FailsSoft: this is a compatibility fixup, not
// a validator. Letting the upstream reject a malformed body beats this
// function inventing an opinion about it.
func TestNormalizeReasoningItems_FailsSoft(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ``},
		{"not json", `not json at all`},
		{"top level array", `[1,2,3]`},
		{"no input (chat body)", `{"model":"m","messages":[{"role":"user","content":"hi"}]}`},
		{"input not an array", `{"input":"a string"}`},
		{"item not an object", `{"input":["bare string",42]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.body)
			if out := NormalizeReasoningItems(in); !bytes.Equal(out, in) {
				t.Errorf("body was altered:\n got %s\nwant %s", out, in)
			}
		})
	}
}

// hasReasoningKey decodes and looks for the top-level key. A substring search
// for "reasoning" answers a different question and gets it wrong in both
// directions — `include: ["reasoning.encrypted_content"]` contains the word
// while carrying no object, and a key can be escaped.
func hasReasoningKey(t *testing.T, body []byte) bool {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("parse body: %v\n%s", err, body)
	}
	_, ok := obj["reasoning"]
	return ok
}

// clientAutoBody is what the client puts on the wire with its reasoning depth
// on "Auto" — a summary request and deliberately no effort, so the model
// reasons at its own default depth. Verbatim shape from stream/pipeline.ts.
const clientAutoBody = `{"model":"google/gemini-3.7-flash","input":"hi","stream":true,` +
	`"max_output_tokens":64,"include":["reasoning.encrypted_content"],` +
	`"reasoning":{"summary":"auto"}}`

// The production failure: through OpenRouter that object reads as an explicit
// disable, and a mandatory-reasoning endpoint 400s the whole request.
func TestStripNonDirectiveReasoning_DropsClientAutoObject(t *testing.T) {
	out, err := StripNonDirectiveReasoning([]byte(clientAutoBody), DialectOpenRouter)
	if err != nil {
		t.Fatalf("StripNonDirectiveReasoning: %v", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatalf("parse shaped body: %v\n%s", err, out)
	}
	if _, ok := obj["reasoning"]; ok {
		t.Errorf("reasoning survived; the upstream will still refuse this request:\n%s", out)
	}
	// hasReasoningKey is the only thing standing between three other tests and
	// vacuity — including the guard that keeps Idempotent from being a
	// tautology — so pin it here, in the one test that doesn't use it. A helper
	// that always answers false would leave all four green.
	if !hasReasoningKey(t, []byte(clientAutoBody)) {
		t.Fatal("hasReasoningKey cannot see a reasoning object; every test that uses it is vacuous")
	}
	// The other half: dropping one key may not disturb the request around it.
	// The KEY SET, not a sample of it — checking four named fields says nothing
	// about a fifth the mutator also swept up, and `include` (which is what
	// gives NormalizeReasoningItems anything to normalize) is the one most
	// likely to be caught by a future "tidy the reasoning-adjacent keys" edit.
	var in map[string]json.RawMessage
	if err := json.Unmarshal([]byte(clientAutoBody), &in); err != nil {
		t.Fatalf("parse input body: %v", err)
	}
	delete(in, "reasoning")
	for k := range in {
		if _, ok := obj[k]; !ok {
			t.Errorf("%s was dropped along with reasoning:\n%s", k, out)
		}
	}
	for k := range obj {
		if _, ok := in[k]; !ok {
			t.Errorf("%s appeared out of nowhere:\n%s", k, out)
		}
	}
	// Values too — a shaper that kept the keys and blanked them would satisfy
	// the set comparison above.
	for k, want := range map[string]string{
		"model":             `"google/gemini-3.7-flash"`,
		"input":             `"hi"`,
		"stream":            `true`,
		"max_output_tokens": `64`,
		"include":           `["reasoning.encrypted_content"]`,
	} {
		if got := string(obj[k]); got != want {
			t.Errorf("%s = %s, want %s\n%s", k, got, want, out)
		}
	}
}

// The function strips when no RECOGNIZED DIRECTIVE is present — which is not
// the same predicate as "the object holds only a summary", and the two agree on
// every other case in this file. An unrecognized key does not make reasoning
// enabled upstream, so the object still reads as a disable and must still go;
// narrowing this to literal summary-only would restore the 400 under a name
// that sounds more careful.
func TestStripNonDirectiveReasoning_StripsUnrecognizedKeys(t *testing.T) {
	for _, tc := range []struct{ name, reasoning string }{
		{"summary beside an unrecognized key", `{"summary":"auto","verbosity":"high"}`},
		{"no summary at all", `{"foo":"bar"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(`{"model":"m","reasoning":` + tc.reasoning + `}`)
			out, err := StripNonDirectiveReasoning(in, DialectOpenRouter)
			if err != nil {
				t.Fatalf("StripNonDirectiveReasoning: %v", err)
			}
			if hasReasoningKey(t, out) {
				t.Errorf("object survived on unrecognized keys alone:\n%s", out)
			}
		})
	}
}

// An empty object is the same "no directive" case as summary-only, and reads
// the same way upstream.
func TestStripNonDirectiveReasoning_DropsEmptyObject(t *testing.T) {
	out, err := StripNonDirectiveReasoning([]byte(`{"model":"m","reasoning":{}}`), DialectOpenRouter)
	if err != nil {
		t.Fatalf("StripNonDirectiveReasoning: %v", err)
	}
	if hasReasoningKey(t, out) {
		t.Errorf("empty reasoning object survived:\n%s", out)
	}
}

// A caller who set any field OpenRouter reads has expressed an intent about
// reasoning, and this mutator does not get a vote — INCLUDING an explicit
// disable, where the upstream's 400 is the honest answer to what was asked.
func TestStripNonDirectiveReasoning_KeepsDirectiveObjects(t *testing.T) {
	for _, tc := range []struct{ name, reasoning string }{
		{"effort", `{"summary":"auto","effort":"low"}`},
		{"explicit disable", `{"enabled":false}`},
		{"explicit enable", `{"summary":"auto","enabled":true}`},
		{"exclude", `{"summary":"auto","exclude":true}`},
		{"token budget", `{"max_tokens":1024}`},
		// Presence, not value: a directive whose value is null still counts, so
		// tightening the check to "present and non-null" is a behavior change
		// and not the cleanup it looks like.
		{"null-valued directive", `{"summary":"auto","effort":null}`},
		{"context", `{"context":"prior"}`},
		{"mode", `{"mode":"thinking"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(`{"model":"m","reasoning":` + tc.reasoning + `}`)
			out, err := StripNonDirectiveReasoning(in, DialectOpenRouter)
			if err != nil {
				t.Fatalf("StripNonDirectiveReasoning: %v", err)
			}
			if !bytes.Equal(out, in) {
				t.Errorf("body was altered:\n got %s\nwant %s", out, in)
			}
		})
	}
}

// Everywhere else the object is honored or harmlessly ignored, and stripping it
// would cost the client the reasoning summaries it asked for. The body here is
// the one that fails through OpenRouter, so a dialect gate that stopped working
// shows up as a diff.
func TestStripNonDirectiveReasoning_OnlyOpenRouter(t *testing.T) {
	// Derived, not hand-listed: a hand-written copy of the dialect set is the
	// same fork KnownDialects exists to end, and a seventh dialect would
	// silently get no "must not be stripped" coverage.
	for _, d := range KnownDialects() {
		if d == DialectOpenRouter {
			continue
		}
		t.Run(string(d), func(t *testing.T) {
			in := []byte(clientAutoBody)
			out, err := StripNonDirectiveReasoning(in, d)
			if err != nil {
				t.Fatalf("StripNonDirectiveReasoning: %v", err)
			}
			if !bytes.Equal(out, in) {
				t.Errorf("body was altered for %q:\n got %s\nwant %s", d, out, in)
			}
		})
	}
}

func TestStripNonDirectiveReasoning_Idempotent(t *testing.T) {
	once, err := StripNonDirectiveReasoning([]byte(clientAutoBody), DialectOpenRouter)
	if err != nil {
		t.Fatalf("first pass: %v", err)
	}
	// Idempotence over a first pass that did nothing is a tautology — a
	// function that never strips would satisfy the comparison below.
	if hasReasoningKey(t, once) {
		t.Fatal("first pass did not strip; the second-pass comparison proves nothing")
	}
	twice, err := StripNonDirectiveReasoning(once, DialectOpenRouter)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if !bytes.Equal(twice, once) {
		t.Errorf("second pass altered the body:\n got %s\nwant %s", twice, once)
	}
}

// A compatibility fixup, not a validator: anything it doesn't understand goes
// upstream untouched, where a real error beats an invented opinion.
func TestStripNonDirectiveReasoning_FailsSoft(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ``},
		{"not json", `not json at all`},
		{"top level array", `[1,2,3]`},
		{"no reasoning key", `{"model":"m","input":"hi"}`},
		{"reasoning null", `{"model":"m","reasoning":null}`},
		{"reasoning a string", `{"model":"m","reasoning":"auto"}`},
		{"reasoning an array", `{"model":"m","reasoning":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			in := []byte(tc.body)
			out, err := StripNonDirectiveReasoning(in, DialectOpenRouter)
			if err != nil {
				t.Fatalf("StripNonDirectiveReasoning: %v", err)
			}
			if !bytes.Equal(out, in) {
				t.Errorf("body was altered:\n got %s\nwant %s", out, in)
			}
		})
	}
}
