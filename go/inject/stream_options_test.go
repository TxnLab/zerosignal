/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"testing"
)

func TestInjectStreamOptionsIncludeUsage_AddsWhenAbsent(t *testing.T) {
	in := []byte(`{"model":"gpt-test","stream":true,"messages":[{"role":"user","content":"hi"}]}`)
	out, injected, err := InjectStreamOptionsIncludeUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	if !injected {
		t.Fatal("injected = false, want true")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		t.Fatal(err)
	}
	var so map[string]any
	if err := json.Unmarshal(obj["stream_options"], &so); err != nil {
		t.Fatalf("stream_options: %v", err)
	}
	if so["include_usage"] != true {
		t.Errorf("include_usage = %v, want true", so["include_usage"])
	}
	if string(obj["messages"]) != `[{"role":"user","content":"hi"}]` {
		t.Errorf("messages mutated: %s", obj["messages"])
	}
}

func TestInjectStreamOptionsIncludeUsage_EmptyObjectGetsIncludeUsage(t *testing.T) {
	in := []byte(`{"model":"m","stream_options":{}}`)
	out, injected, err := InjectStreamOptionsIncludeUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	if !injected {
		t.Fatal("injected = false, want true")
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(out, &obj)
	var so map[string]any
	_ = json.Unmarshal(obj["stream_options"], &so)
	if so["include_usage"] != true {
		t.Errorf("include_usage = %v, want true", so["include_usage"])
	}
}

func TestInjectStreamOptionsIncludeUsage_PreservesOtherStreamOptionKeys(t *testing.T) {
	in := []byte(`{"model":"m","stream_options":{"some_future_flag":"keep"}}`)
	out, injected, err := InjectStreamOptionsIncludeUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	if !injected {
		t.Fatal("injected = false, want true")
	}
	var obj map[string]json.RawMessage
	_ = json.Unmarshal(out, &obj)
	var so map[string]any
	_ = json.Unmarshal(obj["stream_options"], &so)
	if so["include_usage"] != true {
		t.Errorf("include_usage = %v, want true", so["include_usage"])
	}
	if so["some_future_flag"] != "keep" {
		t.Errorf("some_future_flag = %v, want keep", so["some_future_flag"])
	}
}

func TestInjectStreamOptionsIncludeUsage_RespectsExplicitTrue(t *testing.T) {
	in := []byte(`{"model":"m","stream_options":{"include_usage":true}}`)
	out, injected, err := InjectStreamOptionsIncludeUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	if injected {
		t.Errorf("injected = true, want false (client already asked for it)")
	}
	if string(out) != string(in) {
		t.Errorf("body changed: %s", out)
	}
}

func TestInjectStreamOptionsIncludeUsage_RespectsExplicitFalse(t *testing.T) {
	in := []byte(`{"model":"m","stream_options":{"include_usage":false}}`)
	out, injected, err := InjectStreamOptionsIncludeUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	if injected {
		t.Errorf("injected = true, want false (client explicit opt-out)")
	}
	if string(out) != string(in) {
		t.Errorf("body changed: %s", out)
	}
}

func TestInjectStreamOptionsIncludeUsage_StreamOptionsNotObject(t *testing.T) {
	in := []byte(`{"model":"m","stream_options":"nope"}`)
	out, injected, err := InjectStreamOptionsIncludeUsage(in)
	if err != nil {
		t.Fatal(err)
	}
	if injected {
		t.Errorf("injected = true, want false")
	}
	if string(out) != string(in) {
		t.Errorf("body changed: %s", out)
	}
}

func TestInjectStreamOptionsIncludeUsage_NonObjectPassthrough(t *testing.T) {
	cases := []string{
		`[1,2,3]`,
		`"just-a-string"`,
		`42`,
		`not json`,
		``,
	}
	for _, c := range cases {
		got, injected, err := InjectStreamOptionsIncludeUsage([]byte(c))
		if err != nil {
			t.Errorf("input %q: err = %v", c, err)
			continue
		}
		if injected {
			t.Errorf("input %q: injected = true", c)
		}
		if string(got) != c {
			t.Errorf("input %q changed to %q", c, got)
		}
	}
}
