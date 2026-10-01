/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"strings"
	"testing"
)

// testSafetyKey is a fixed operator-scoped key so the golden value below is
// reproducible; production derives the key from the node's signing key.
var testSafetyKey = []byte("zs-safety-test-key")

func TestSafetyIdentifierFor_Deterministic(t *testing.T) {
	a := SafetyIdentifierFor(testSafetyKey, "ADDR")
	b := SafetyIdentifierFor(testSafetyKey, "ADDR")
	if a != b {
		t.Errorf("non-deterministic: %q vs %q", a, b)
	}
}

func TestSafetyIdentifierFor_DistinctInputs(t *testing.T) {
	a := SafetyIdentifierFor(testSafetyKey, "ADDR-1")
	b := SafetyIdentifierFor(testSafetyKey, "ADDR-2")
	if a == b {
		t.Errorf("collision on distinct inputs: %q", a)
	}
}

func TestSafetyIdentifierFor_DistinctKeysDivergeForSameAddr(t *testing.T) {
	// The whole point of keying: the SAME payer address under two different
	// operator keys must produce different identifiers, so a shared upstream
	// can't join one payer's traffic across operators by identifier equality.
	a := SafetyIdentifierFor([]byte("operator-A-key"), "SAMEADDR")
	b := SafetyIdentifierFor([]byte("operator-B-key"), "SAMEADDR")
	if a == b {
		t.Errorf("same identifier under distinct keys: %q — keying is not in effect", a)
	}
}

func TestSafetyIdentifierFor_HasPrefix(t *testing.T) {
	if !strings.HasPrefix(SafetyIdentifierFor(testSafetyKey, "x"), SafetyIdentifierPrefix) {
		t.Errorf("missing %q prefix", SafetyIdentifierPrefix)
	}
}

func TestSafetyIdentifierFor_StableForKnownInput(t *testing.T) {
	// Pin the output for a known (key, address) pair so accidental changes to
	// the HMAC construction or encoding are caught. If this test needs to be
	// updated, it's a signal that downstream consumers (including OpenAI's
	// abuse models) will see a different identifier for the same payer.
	got := SafetyIdentifierFor(testSafetyKey, "TESTOPERATORADDR")
	const want = "zs:EI6o+85set6/Emyygr5sOVnHu3jhBAwcE0UpA4GHJ/8="
	if got != want {
		t.Errorf("safety_identifier drift:\n  got:  %q\n  want: %q", got, want)
	}
}

func TestInjectSafetyIdentifier_AddsWhenMissing(t *testing.T) {
	in := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`)
	out, err := InjectSafetyIdentifier(in, "zs:abc")
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["safety_identifier"] != "zs:abc" {
		t.Errorf("safety_identifier = %v, want zs:abc", obj["safety_identifier"])
	}
	if obj["model"] != "gpt-test" {
		t.Errorf("model = %v", obj["model"])
	}
}

func TestInjectSafetyIdentifier_PreservesClientSupplied(t *testing.T) {
	in := []byte(`{"model":"gpt-test","safety_identifier":"client-set-user-42"}`)
	out, err := InjectSafetyIdentifier(in, "zs:abc")
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	_ = json.Unmarshal(out, &obj)
	if obj["safety_identifier"] != "client-set-user-42" {
		t.Errorf("client value overridden: %v", obj["safety_identifier"])
	}
}

func TestInjectSafetyIdentifier_NoopWhenIdentifierEmpty(t *testing.T) {
	in := []byte(`{"model":"gpt-test"}`)
	out, err := InjectSafetyIdentifier(in, "")
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Errorf("body changed despite empty identifier: %s", out)
	}
}

func TestInjectSafetyIdentifier_NonObjectPassthrough(t *testing.T) {
	cases := []string{
		`[1,2,3]`,
		`"just-a-string"`,
		`42`,
		`not json`,
		``,
	}
	for _, c := range cases {
		got, err := InjectSafetyIdentifier([]byte(c), "zs:abc")
		if err != nil {
			t.Errorf("input %q: err = %v", c, err)
			continue
		}
		if string(got) != c {
			t.Errorf("input %q changed to %q", c, got)
		}
	}
}

func TestInjectSafetyIdentifier_PreservesRawSubFields(t *testing.T) {
	// Sub-objects / arrays must round-trip byte-identical through the
	// map[string]json.RawMessage pathway so we're not re-encoding nested
	// JSON and potentially reordering keys or re-spacing floats.
	in := []byte(`{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f"}}]}`)
	out, err := InjectSafetyIdentifier(in, "zs:abc")
	if err != nil {
		t.Fatal(err)
	}
	var outObj map[string]json.RawMessage
	_ = json.Unmarshal(out, &outObj)
	if string(outObj["messages"]) != `[{"role":"user","content":"hi"}]` {
		t.Errorf("messages mutated: %s", outObj["messages"])
	}
	if string(outObj["tools"]) != `[{"type":"function","function":{"name":"f"}}]` {
		t.Errorf("tools mutated: %s", outObj["tools"])
	}
}
