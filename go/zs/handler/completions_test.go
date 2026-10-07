/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"testing"
)

func TestChatRequestFromCompletions_StringPrompt(t *testing.T) {
	in := []byte(`{"model":"gpt-4","prompt":"Hello there","max_tokens":16,"stream":true,"temperature":0.5}`)
	out, terr := chatRequestFromCompletions(in)
	if terr != nil {
		t.Fatalf("translate: %v", terr)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := got["prompt"]; ok {
		t.Error("prompt should be removed")
	}
	// Shared fields ride through untouched.
	for _, k := range []string{"model", "max_tokens", "stream", "temperature"} {
		if _, ok := got[k]; !ok {
			t.Errorf("field %q should pass through", k)
		}
	}
	var msgs []map[string]string
	if err := json.Unmarshal(got["messages"], &msgs); err != nil {
		t.Fatalf("messages: %v", err)
	}
	if len(msgs) != 1 || msgs[0]["role"] != "user" || msgs[0]["content"] != "Hello there" {
		t.Errorf("messages = %+v, want one user message with the prompt", msgs)
	}
}

func TestChatRequestFromCompletions_SingleElementArrayPrompt(t *testing.T) {
	out, terr := chatRequestFromCompletions([]byte(`{"model":"m","prompt":["only one"]}`))
	if terr != nil {
		t.Fatalf("translate: %v", terr)
	}
	var got map[string]json.RawMessage
	_ = json.Unmarshal(out, &got)
	var msgs []map[string]string
	_ = json.Unmarshal(got["messages"], &msgs)
	if msgs[0]["content"] != "only one" {
		t.Errorf("content = %q, want %q", msgs[0]["content"], "only one")
	}
}

func TestChatRequestFromCompletions_DropsIncompatibleFields(t *testing.T) {
	in := []byte(`{"model":"m","prompt":"x","echo":true,"best_of":3,"suffix":"END","logprobs":5}`)
	out, terr := chatRequestFromCompletions(in)
	if terr != nil {
		t.Fatalf("translate: %v", terr)
	}
	var got map[string]json.RawMessage
	_ = json.Unmarshal(out, &got)
	for _, k := range []string{"echo", "best_of", "suffix", "logprobs"} {
		if _, ok := got[k]; ok {
			t.Errorf("field %q should be dropped (chat-incompatible)", k)
		}
	}
}

func TestChatRequestFromCompletions_Errors(t *testing.T) {
	cases := []struct {
		name string
		body string
		code string
	}{
		{"not json", `not json`, "invalid_json"},
		{"missing prompt", `{"model":"m"}`, "missing_prompt"},
		{"multi-element array", `{"model":"m","prompt":["a","b"]}`, "unsupported_prompt"},
		{"token-id prompt", `{"model":"m","prompt":[1,2,3]}`, "unsupported_prompt"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, terr := chatRequestFromCompletions([]byte(tc.body))
			if terr == nil {
				t.Fatalf("expected error, got nil")
			}
			if terr.code != tc.code {
				t.Errorf("code = %q, want %q", terr.code, tc.code)
			}
		})
	}
}

func TestCompletionsResponseFromChat_NonStream(t *testing.T) {
	chat := []byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"the answer"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	out := completionsResponseFromChat(chat)

	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var obj string
	_ = json.Unmarshal(got["object"], &obj)
	if obj != "text_completion" {
		t.Errorf("object = %q, want text_completion", obj)
	}
	// usage and model preserved verbatim.
	if _, ok := got["usage"]; !ok {
		t.Error("usage should be preserved")
	}
	var choices []map[string]json.RawMessage
	_ = json.Unmarshal(got["choices"], &choices)
	if len(choices) != 1 {
		t.Fatalf("choices len = %d, want 1", len(choices))
	}
	if _, ok := choices[0]["message"]; ok {
		t.Error("message should be replaced by text")
	}
	var text string
	_ = json.Unmarshal(choices[0]["text"], &text)
	if text != "the answer" {
		t.Errorf("text = %q, want %q", text, "the answer")
	}
	var fr string
	_ = json.Unmarshal(choices[0]["finish_reason"], &fr)
	if fr != "stop" {
		t.Errorf("finish_reason = %q, want stop", fr)
	}
}

func TestCompletionsChunkFromChat_Stream(t *testing.T) {
	// role-only first delta → empty text.
	first := completionsChunkFromChat([]byte(`{"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"},"finish_reason":null}]}`))
	assertStreamText(t, first, "", "text_completion")

	// content delta → text carries the content.
	mid := completionsChunkFromChat([]byte(`{"id":"c","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"Hello"},"finish_reason":null}]}`))
	assertStreamText(t, mid, "Hello", "text_completion")
}

func TestCompletionsChunkFromChat_UsageChunkPassesObject(t *testing.T) {
	// Final usage chunk has empty choices; object is still rewritten, usage kept.
	out := completionsChunkFromChat([]byte(`{"id":"c","object":"chat.completion.chunk","choices":[],"usage":{"total_tokens":9}}`))
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var obj string
	_ = json.Unmarshal(got["object"], &obj)
	if obj != "text_completion" {
		t.Errorf("object = %q, want text_completion", obj)
	}
	if _, ok := got["usage"]; !ok {
		t.Error("usage should be preserved on the usage chunk")
	}
}

func TestReshapeChatToText_PassThroughNonChat(t *testing.T) {
	// Error envelopes and non-chat shapes must be returned byte-identical so a
	// sealed upstream error still reaches the client unchanged.
	for _, in := range []string{
		`{"error":{"message":"boom","type":"server_error"}}`,
		`{"object":"list","data":[]}`,
		`not even json`,
	} {
		if got := completionsResponseFromChat([]byte(in)); string(got) != in {
			t.Errorf("non-chat body changed:\n in = %s\nout = %s", in, got)
		}
		if got := completionsChunkFromChat([]byte(in)); string(got) != in {
			t.Errorf("non-chat chunk changed:\n in = %s\nout = %s", in, got)
		}
	}
}

// A node's body is untrusted: a null choice decodes to a nil map, which the
// reshape must not write into. It passes through unchanged, like any other
// shape that isn't a chat completion.
func TestReshapeChatToText_NullChoicePassesThrough(t *testing.T) {
	for _, tc := range []struct {
		in        string
		streaming bool
	}{
		{`{"object":"chat.completion","choices":[null]}`, false},
		{`{"object":"chat.completion","choices":[{"index":0,"message":{"content":"a"}},null]}`, false},
		{`{"object":"chat.completion.chunk","choices":[null]}`, true},
		{`{"choices":[null]}`, true},
	} {
		var got []byte
		if tc.streaming {
			got = completionsChunkFromChat([]byte(tc.in))
		} else {
			got = completionsResponseFromChat([]byte(tc.in))
		}
		if string(got) != tc.in {
			t.Errorf("%s: changed to %s", tc.in, got)
		}
	}
}

// An empty choice is an object, so the null guard must not catch it: it is
// still a chat choice with no text.
func TestReshapeChatToText_EmptyChoiceIsReshaped(t *testing.T) {
	whole := completionsResponseFromChat([]byte(`{"object":"chat.completion","choices":[{}]}`))
	if string(whole) != `{"choices":[{"logprobs":null,"text":""}],"object":"text_completion"}` {
		t.Errorf("whole reply = %s", whole)
	}
	assertStreamText(t, completionsChunkFromChat([]byte(`{"object":"chat.completion.chunk","choices":[{}]}`)), "", "text_completion")
}

func assertStreamText(t *testing.T, out []byte, wantText, wantObj string) {
	t.Helper()
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	var obj string
	_ = json.Unmarshal(got["object"], &obj)
	if obj != wantObj {
		t.Errorf("object = %q, want %q", obj, wantObj)
	}
	var choices []map[string]json.RawMessage
	_ = json.Unmarshal(got["choices"], &choices)
	if len(choices) != 1 {
		t.Fatalf("choices len = %d, want 1", len(choices))
	}
	if _, ok := choices[0]["delta"]; ok {
		t.Error("delta should be replaced by text")
	}
	var text string
	_ = json.Unmarshal(choices[0]["text"], &text)
	if text != wantText {
		t.Errorf("text = %q, want %q", text, wantText)
	}
}
