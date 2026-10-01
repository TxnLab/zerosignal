/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

func TestDropPromptCacheKey(t *testing.T) {
	t.Run("strips prompt_cache_key, preserves the rest", func(t *testing.T) {
		body := `{"model":"m1","prompt_cache_key":"pck_9f2c","input":"hi","store":false}`
		out, err := inject.DropPromptCacheKey([]byte(body))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(out, &obj); err != nil {
			t.Fatalf("output not valid JSON: %v", err)
		}
		if _, ok := obj["prompt_cache_key"]; ok {
			t.Errorf("prompt_cache_key not stripped: %s", out)
		}
		for _, key := range []string{"model", "input", "store"} {
			if _, ok := obj[key]; !ok {
				t.Errorf("%s dropped: %s", key, out)
			}
		}
	})

	// The whole point is that the value never leaves the proxy — a strip that
	// merely blanked or renamed the field would still hand two operators a join
	// key, so assert on the serialized bytes, not just the parsed map.
	t.Run("the value is absent from the serialized body", func(t *testing.T) {
		out, err := inject.DropPromptCacheKey([]byte(`{"prompt_cache_key":"pck_dead10cc","model":"m1"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(string(out), "pck_dead10cc") || strings.Contains(string(out), "prompt_cache_key") {
			t.Errorf("cache key survived the strip: %s", out)
		}
	})

	// A caller that sent the field explicitly as null still meant to send it;
	// dropping the key is the same outcome either way and must not error.
	t.Run("null value is dropped too", func(t *testing.T) {
		out, err := inject.DropPromptCacheKey([]byte(`{"prompt_cache_key":null,"model":"m1"}`))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if strings.Contains(string(out), "prompt_cache_key") {
			t.Errorf("null cache key not stripped: %s", out)
		}
	})

	// Keys are deliberately NOT in alphabetical order: encoding/json sorts map
	// keys on re-marshal, so a single-key or already-sorted fixture round-trips
	// byte-identically and would pass even with the early return deleted. This
	// is what pins the godoc's "freshly-marshaled copy only when modified".
	t.Run("no prompt_cache_key → returned byte-identical, not re-marshaled", func(t *testing.T) {
		body := []byte(`{"model":"m1","a":1}`)
		out, err := inject.DropPromptCacheKey(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("body was re-marshaled: got %s want %s", out, body)
		}
	})

	// Only the top level is OpenAI's field. A same-named key nested in caller
	// content is not the correlator and must not be touched — rewriting message
	// content would change what the model sees.
	t.Run("a nested same-named key is left alone", func(t *testing.T) {
		body := []byte(`{"model":"m1","metadata":{"prompt_cache_key":"theirs"}}`)
		out, err := inject.DropPromptCacheKey(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !strings.Contains(string(out), "theirs") {
			t.Errorf("nested value was stripped: %s", out)
		}
	})

	t.Run("non-JSON body → unchanged", func(t *testing.T) {
		body := []byte(`not json`)
		out, err := inject.DropPromptCacheKey(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("non-JSON body changed: %s", out)
		}
	})

	t.Run("JSON array top level → unchanged", func(t *testing.T) {
		body := []byte(`[{"prompt_cache_key":"x"}]`)
		out, err := inject.DropPromptCacheKey(body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(out) != string(body) {
			t.Errorf("array body changed: %s", out)
		}
	})

	t.Run("empty body → unchanged", func(t *testing.T) {
		out, err := inject.DropPromptCacheKey(nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(out) != 0 {
			t.Errorf("empty body changed: %s", out)
		}
	})
}
