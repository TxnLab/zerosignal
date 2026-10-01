/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

import (
	"encoding/json"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

func TestDropRoutingPreferences(t *testing.T) {
	t.Run("strips provider, preserves the rest", func(t *testing.T) {
		body := `{"model":"m1","provider":{"only":["3"]},"messages":[{"role":"user","content":"hi"}]}`
		out, err := inject.DropRoutingPreferences([]byte(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		if _, ok := obj["provider"]; ok {
			t.Errorf("provider not stripped: %s", out)
		}
		if _, ok := obj["model"]; !ok {
			t.Errorf("model dropped: %s", out)
		}
		if _, ok := obj["messages"]; !ok {
			t.Errorf("messages dropped: %s", out)
		}
	})

	t.Run("no provider key → returned unchanged", func(t *testing.T) {
		body := []byte(`{"model":"m1"}`)
		out, err := inject.DropRoutingPreferences(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("body changed: got %s want %s", out, body)
		}
	})

	t.Run("non-JSON body → unchanged", func(t *testing.T) {
		body := []byte(`not json`)
		out, err := inject.DropRoutingPreferences(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("non-JSON body changed: %s", out)
		}
	})

	t.Run("empty body → unchanged", func(t *testing.T) {
		out, err := inject.DropRoutingPreferences(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(out) != 0 {
			t.Errorf("empty body changed: %s", out)
		}
	})
}

// providerFields decodes the outbound body's `provider` object. Every
// assertion below goes through it rather than substring-matching the raw
// bytes: encoding/json escapes, and a Contains check on a re-marshalled body
// passes whether or not the injection happened.
func providerFields(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		t.Fatalf("output not valid JSON: %v (%s)", err, body)
	}
	raw, ok := obj["provider"]
	if !ok {
		t.Fatalf("no provider object in output: %s", body)
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("provider not an object: %v (%s)", err, raw)
	}
	return fields
}

func assertPrivacyPinned(t *testing.T, body []byte) {
	t.Helper()
	f := providerFields(t, body)
	if got := f["zdr"]; got != true {
		t.Errorf("provider.zdr = %#v, want true (%s)", got, body)
	}
	if got := f["data_collection"]; got != "deny" {
		t.Errorf("provider.data_collection = %#v, want \"deny\" (%s)", got, body)
	}
}

func TestEnforceUpstreamPrivacy(t *testing.T) {
	t.Run("adds both keys when there is no provider object", func(t *testing.T) {
		body := []byte(`{"model":"x-ai/grok-4.6","messages":[{"role":"user","content":"hi"}]}`)
		out, err := inject.EnforceUpstreamPrivacy(body, inject.DialectOpenRouter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertPrivacyPinned(t, out)

		var obj map[string]json.RawMessage
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		for _, k := range []string{"model", "messages"} {
			if _, ok := obj[k]; !ok {
				t.Errorf("top-level %q dropped: %s", k, out)
			}
		}
	})

	t.Run("overrides a caller trying to opt out", func(t *testing.T) {
		body := []byte(`{"model":"m","provider":{"zdr":false,"data_collection":"allow"}}`)
		out, err := inject.EnforceUpstreamPrivacy(body, inject.DialectOpenRouter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertPrivacyPinned(t, out)
	})

	t.Run("preserves the caller's routing keys", func(t *testing.T) {
		body := []byte(`{"model":"m","provider":{"order":["a","b"],"only":["c"],"sort":"price","allow_fallbacks":false}}`)
		out, err := inject.EnforceUpstreamPrivacy(body, inject.DialectOpenRouter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertPrivacyPinned(t, out)

		f := providerFields(t, out)
		if got, ok := f["order"].([]any); !ok || len(got) != 2 || got[0] != "a" {
			t.Errorf("provider.order mangled: %#v", f["order"])
		}
		if got, ok := f["only"].([]any); !ok || len(got) != 1 || got[0] != "c" {
			t.Errorf("provider.only mangled: %#v", f["only"])
		}
		if f["sort"] != "price" {
			t.Errorf("provider.sort = %#v, want \"price\"", f["sort"])
		}
		if f["allow_fallbacks"] != false {
			t.Errorf("provider.allow_fallbacks = %#v, want false", f["allow_fallbacks"])
		}
	})

	t.Run("null provider is treated as absent", func(t *testing.T) {
		out, err := inject.EnforceUpstreamPrivacy([]byte(`{"model":"m","provider":null}`), inject.DialectOpenRouter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		assertPrivacyPinned(t, out)
	})

	t.Run("idempotent", func(t *testing.T) {
		once, err := inject.EnforceUpstreamPrivacy([]byte(`{"model":"m"}`), inject.DialectOpenRouter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		twice, err := inject.EnforceUpstreamPrivacy(once, inject.DialectOpenRouter)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(once) != string(twice) {
			t.Errorf("not idempotent:\n once: %s\ntwice: %s", once, twice)
		}
	})

	// Every other dialect must be untouched: no other upstream reads these
	// keys, and the strict vLLM/SGLang pydantic path rejects unknown fields.
	t.Run("no-op on every other dialect", func(t *testing.T) {
		body := []byte(`{"model":"m","messages":[]}`)
		for _, d := range inject.KnownDialects() {
			if d == inject.DialectOpenRouter {
				continue
			}
			out, err := inject.EnforceUpstreamPrivacy(body, d)
			if err != nil {
				t.Fatalf("dialect %s: unexpected error: %v", d, err)
			}
			if string(out) != string(body) {
				t.Errorf("dialect %s: body changed: %s", d, out)
			}
		}
	})

	// BOTH empty forms. Every caller today passes a literal nil for a bodyless
	// request, so `len(body) == 0` and `body == nil` agree on all of them — and
	// a zero-length non-nil slice, which a buffered read or a `[]byte("")`
	// produces, would then take the parse path and become a hard 403 refusal on
	// a request that has nothing to annotate.
	t.Run("empty body is unchanged", func(t *testing.T) {
		for name, body := range map[string][]byte{"nil": nil, "zero-length": {}} {
			t.Run(name, func(t *testing.T) {
				out, err := inject.EnforceUpstreamPrivacy(body, inject.DialectOpenRouter)
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if len(out) != 0 {
					t.Errorf("empty body changed: %s", out)
				}
			})
		}
	})

	// The fail-closed departure from every other mutator in this package.
	// Forwarding a body this could not annotate is the exact outcome it
	// exists to prevent, so an unparseable body is an error rather than a
	// pass-through.
	t.Run("fails closed on a body it cannot annotate", func(t *testing.T) {
		for name, body := range map[string]string{
			"not JSON":             `not json`,
			"JSON but not object":  `["a"]`,
			"provider is a string": `{"model":"m","provider":"only-groq"}`,
			"provider is an array": `{"model":"m","provider":["groq"]}`,
			// The one non-object body that does NOT error out of
			// json.Unmarshal: decoding `null` into a map yields a nil map and a
			// nil error, so it used to walk straight into the assignment and
			// PANIC. Every other case here takes the parse-error path, which is
			// why the whole table passed while the one crashing input was
			// missing from it.
			"top-level null": `null`,
		} {
			t.Run(name, func(t *testing.T) {
				out, err := inject.EnforceUpstreamPrivacy([]byte(body), inject.DialectOpenRouter)
				if err == nil {
					t.Fatalf("want error, got body: %s", out)
				}
				if out != nil {
					t.Errorf("want nil body alongside the error, got: %s", out)
				}
			})
		}
	})
}
