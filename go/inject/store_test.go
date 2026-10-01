/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"testing"
)

func TestDefaultStoreFalse_AddsWhenMissing(t *testing.T) {
	in := []byte(`{"model":"gpt-test","messages":[{"role":"user","content":"hi"}]}`)
	out, err := DefaultStoreFalse(in)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	v, ok := obj["store"]
	if !ok {
		t.Fatalf("store not added; body = %s", out)
	}
	if v != false {
		t.Errorf("store = %v, want false", v)
	}
	if obj["model"] != "gpt-test" {
		t.Errorf("model = %v", obj["model"])
	}
}

func TestDefaultStoreFalse_PreservesExplicitTrue(t *testing.T) {
	in := []byte(`{"model":"gpt-test","store":true}`)
	out, err := DefaultStoreFalse(in)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	_ = json.Unmarshal(out, &obj)
	if obj["store"] != true {
		t.Errorf("client store=true was not preserved: %v", obj["store"])
	}
}

func TestDefaultStoreFalse_TreatsNullAsOmitted(t *testing.T) {
	// A client that serialized `nil`/`None` as `"store": null` would,
	// under the upstream's null-handling, default back to retention. The
	// safety net must catch that case the same as a missing field.
	in := []byte(`{"model":"gpt-test","store":null}`)
	out, err := DefaultStoreFalse(in)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["store"] != false {
		t.Errorf("store = %v, want false (null should have been treated as omitted)", obj["store"])
	}
}

func TestDefaultStoreFalse_PreservesExplicitFalse(t *testing.T) {
	in := []byte(`{"model":"gpt-test","store":false}`)
	out, err := DefaultStoreFalse(in)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	_ = json.Unmarshal(out, &obj)
	if obj["store"] != false {
		t.Errorf("store mutated away from false: %v", obj["store"])
	}
}

func TestDefaultStoreFalse_NonObjectPassthrough(t *testing.T) {
	cases := []string{
		`[1,2,3]`,
		`"just-a-string"`,
		`42`,
		`not json`,
		``,
	}
	for _, c := range cases {
		got, err := DefaultStoreFalse([]byte(c))
		if err != nil {
			t.Errorf("input %q: err = %v", c, err)
			continue
		}
		if string(got) != c {
			t.Errorf("input %q changed to %q", c, got)
		}
	}
}

func TestDefaultStoreFalse_PreservesRawSubFields(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"f"}}]}`)
	out, err := DefaultStoreFalse(in)
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
	if string(outObj["store"]) != "false" {
		t.Errorf("store = %s, want false", outObj["store"])
	}
}

// The whole reason ForceStoreFalse exists is that DefaultStoreFalse
// does NOT do this. Run both over the same inputs so the difference is
// the assertion — a table pinning only the forcing side would still
// pass if someone made the two functions identical, and the resulting
// node would quietly break `previous_response_id` for every caller.
func TestForceStoreFalse_VsDefault(t *testing.T) {
	cases := []struct {
		name          string
		in            string
		wantDefault   string // what DefaultStoreFalse leaves in `store`
		wantForced    string // what ForceStoreFalse leaves in `store`
		mustDiverge   bool
		wantUnchanged bool // ForceStoreFalse must return the input bytes as-is
	}{
		{
			name:        "explicit true is the whole point",
			in:          `{"model":"m","store":true}`,
			wantDefault: "true",
			wantForced:  "false",
			mustDiverge: true,
		},
		{
			name:        "omitted lands in the same place",
			in:          `{"model":"m"}`,
			wantDefault: "false",
			wantForced:  "false",
		},
		{
			name:        "null is not an explicit value on either",
			in:          `{"model":"m","store":null}`,
			wantDefault: "false",
			wantForced:  "false",
		},
		{
			// KEY ORDER IS DELIBERATELY NON-ALPHABETICAL. json.Marshal
			// emits map keys sorted, so `{"model":…,"store":…}` is
			// reproduced byte-for-byte by a remarshal and the
			// wantUnchanged assertion below cannot fail on it — it
			// would pass with the early return deleted, leaving the
			// property unprotected. With "store" first, only genuinely
			// returning the input bytes preserves them.
			//
			// The property matters because this body's body_hash is
			// verified end-to-end by the proxy: rewriting a body we had
			// no reason to touch is a gratuitous risk on that hash.
			name:          "already false is returned untouched",
			in:            `{"store":false,"model":"m"}`,
			wantDefault:   "false",
			wantForced:    "false",
			wantUnchanged: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			def, err := DefaultStoreFalse([]byte(tc.in))
			if err != nil {
				t.Fatalf("DefaultStoreFalse: %v", err)
			}
			forced, err := ForceStoreFalse([]byte(tc.in))
			if err != nil {
				t.Fatalf("ForceStoreFalse: %v", err)
			}
			if got := storeField(t, def); got != tc.wantDefault {
				t.Errorf("DefaultStoreFalse store = %s, want %s", got, tc.wantDefault)
			}
			if got := storeField(t, forced); got != tc.wantForced {
				t.Errorf("ForceStoreFalse store = %s, want %s", got, tc.wantForced)
			}
			if tc.mustDiverge && storeField(t, def) == storeField(t, forced) {
				t.Error("the two functions agreed on the one input that distinguishes them")
			}
			if tc.wantUnchanged && string(forced) != tc.in {
				t.Errorf("body was remarshalled needlessly\n got: %s\nwant: %s", forced, tc.in)
			}
		})
	}
}

func TestForceStoreFalse_PreservesRawSubFields(t *testing.T) {
	in := []byte(`{"messages":[{"role":"user","content":"hi"}],"store":true,"tools":[{"type":"function","function":{"name":"f"}}]}`)
	out, err := ForceStoreFalse(in)
	if err != nil {
		t.Fatal(err)
	}
	var outObj map[string]json.RawMessage
	if err := json.Unmarshal(out, &outObj); err != nil {
		t.Fatal(err)
	}
	if string(outObj["messages"]) != `[{"role":"user","content":"hi"}]` {
		t.Errorf("messages mutated: %s", outObj["messages"])
	}
	if string(outObj["tools"]) != `[{"type":"function","function":{"name":"f"}}]` {
		t.Errorf("tools mutated: %s", outObj["tools"])
	}
	if string(outObj["store"]) != "false" {
		t.Errorf("store = %s, want false", outObj["store"])
	}
}

func TestForceStoreFalse_NonJSONUnchanged(t *testing.T) {
	// Same contract as DefaultStoreFalse: an upstream rejects these
	// outright, so there is no `store` shape to set and no plaintext
	// for any provider to retain.
	for _, in := range []string{"", "not json", `["an","array"]`, `"a string"`} {
		out, err := ForceStoreFalse([]byte(in))
		if err != nil {
			t.Errorf("ForceStoreFalse(%q): %v", in, err)
		}
		if string(out) != in {
			t.Errorf("ForceStoreFalse(%q) = %q, want unchanged", in, out)
		}
	}
}

func storeField(t *testing.T, body []byte) string {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("unmarshal %s: %v", body, err)
	}
	v, ok := obj["store"]
	if !ok {
		return "<absent>"
	}
	return string(v)
}
