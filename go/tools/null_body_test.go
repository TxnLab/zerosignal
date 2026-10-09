// Copyright (c) 2026. TxnLab Inc.
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"encoding/json"
	"testing"
)

// JSON null decodes without error into a nil map, so each helper that writes
// into a decoded body must check for it. The upstream provider writes the
// replies and the payer the requests; a panic on either ends a paid turn with
// no receipt.
func TestNullBodies_PassThroughOrError(t *testing.T) {
	null := []byte(`null`)
	cites := []ToolEffect{{Citations: []CitationEffect{{URL: "https://a.example", Title: "Alpha"}}}}

	t.Run("SetChatUsage", func(t *testing.T) {
		if got := SetChatUsage(null, 1, 2, 0); string(got) != "null" {
			t.Errorf("got %s, want the body unchanged", got)
		}
	})
	t.Run("SetResponsesUsage", func(t *testing.T) {
		if got := SetResponsesUsage(null, 1, 2, 0); string(got) != "null" {
			t.Errorf("got %s, want the body unchanged", got)
		}
	})
	// Only a null message needs the guard; the others are safe because each
	// lookup misses before anything is written, which a reorder could undo.
	for _, body := range []string{`null`, `{"choices":[null]}`, `{"choices":[{"message":null}]}`} {
		t.Run("SpliceEffectsChatBody "+body, func(t *testing.T) {
			got, err := SpliceEffectsChatBody([]byte(body), cites)
			if err != nil || string(got) != body {
				t.Errorf("got %s, %v; want the body unchanged", got, err)
			}
		})
	}
	t.Run("AppendToolMessagesChat", func(t *testing.T) {
		if got, err := AppendToolMessagesChat(null, json.RawMessage(`{"role":"assistant"}`), nil); err == nil || got != nil {
			t.Errorf("got %s, %v; want no body and an error", got, err)
		}
	})
	t.Run("AppendFunctionCallOutputsResponses", func(t *testing.T) {
		if got, err := AppendFunctionCallOutputsResponses(null, nil, nil); err == nil || got != nil {
			t.Errorf("got %s, %v; want no body and an error", got, err)
		}
	})
	t.Run("RepairChatAssistantWithRecoveredCalls", func(t *testing.T) {
		got, _, err := RepairChatAssistantWithRecoveredCalls(json.RawMessage(`null`), LeakScan{}, leakNames, leakDefs)
		if err != nil {
			t.Fatalf("repair: %v", err)
		}
		var msg struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(got, &msg); err != nil || msg.Role != "assistant" {
			t.Errorf("got %s, want an assistant message", got)
		}
	})
}
