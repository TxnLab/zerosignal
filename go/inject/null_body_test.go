// Copyright (c) 2026. TxnLab Inc.
// SPDX-License-Identifier: Apache-2.0

package inject

import "testing"

// JSON null decodes without error into a nil map, so a mutator that writes
// into a decoded request must check for it. The payer writes the body.
func TestNullBody_MutatorsPassItThrough(t *testing.T) {
	null := []byte(`null`)

	t.Run("PreserveThinking", func(t *testing.T) {
		got, err := PreserveThinking(null, DialectZAI)
		if err != nil || string(got) != "null" {
			t.Errorf("got %s, %v; want the body unchanged", got, err)
		}
	})
	t.Run("InjectSafetyIdentifier", func(t *testing.T) {
		got, err := InjectSafetyIdentifier(null, "id")
		if err != nil || string(got) != "null" {
			t.Errorf("got %s, %v; want the body unchanged", got, err)
		}
	})
	t.Run("InjectStreamOptionsIncludeUsage", func(t *testing.T) {
		got, changed, err := InjectStreamOptionsIncludeUsage(null)
		if err != nil || changed || string(got) != "null" {
			t.Errorf("got %s, %v, %v; want the body unchanged", got, changed, err)
		}
	})
	// A null stream_options reads as omitted, so it gets the injection.
	t.Run("InjectStreamOptionsIncludeUsage null stream_options", func(t *testing.T) {
		got, changed, err := InjectStreamOptionsIncludeUsage([]byte(`{"stream_options":null}`))
		if err != nil || !changed || string(got) != `{"stream_options":{"include_usage":true}}` {
			t.Errorf("got %s, %v, %v; want include_usage injected", got, changed, err)
		}
	})
}
