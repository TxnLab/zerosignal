/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"net/http"
)

// clientFormat is the OpenAI API shape the *client* used, which can differ from
// the wire endpoint the proxy actually dispatches to. Today the only divergence
// is the legacy /v1/completions endpoint, which the proxy emulates: it seals a
// translated /v1/chat/completions request (so the node, relays, ticket, and
// wire all see an ordinary chat request) and reshapes the node's chat response
// back into text-completion shape on the way out to the client.
//
// formatChat (the zero value) means "no translation" — the client shape equals
// the wire shape. It is threaded alongside `endpoint` through the dispatch and
// the two response-write seams (buildHayaiNonStreamResponder /
// buildHayaiFrameFactory) so the reshape happens only for legacy-completions
// requests.
type clientFormat int

const (
	formatChat clientFormat = iota
	formatLegacyCompletions
)

// completionsTranslateError is a request-translation failure that maps cleanly
// onto an OpenAI-shaped error envelope. The handler renders it via
// writeOpenAIError before any operator is contacted (no reserve is spent).
type completionsTranslateError struct {
	status  int
	errType string
	code    string
	msg     string
}

func (e *completionsTranslateError) Error() string { return e.msg }

// handleCompletions emulates the legacy OpenAI /v1/completions ("text
// completion") endpoint on top of the chat-completions pipeline. The legacy
// request (`{"model", "prompt", ...}`) is translated into a chat request
// (`{"model", "messages":[{"role":"user","content":prompt}], ...}`) and then
// dispatched exactly like /v1/chat/completions — sealed opaquely, routed to a
// node as a POST /v1/chat/completions (which is what the relay allow-list and
// the node already accept), and the chat response is reshaped back into
// text-completion shape at the response-write seams (see clientFormat).
//
// This is intentionally proxy-only: no node, relay, or wire-format change is
// needed because on the wire it is an ordinary chat request. The trade-off is
// that completions are served by chat models (chat-templated upstreams), so a
// caller expecting raw base-model continuation gets chat semantics. See
// proxy/README.md.
func (s *Server) handleCompletions(w http.ResponseWriter, r *http.Request) {
	body, ok := readClientBody(w, r)
	if !ok {
		return
	}
	_ = r.Body.Close()

	chatBody, terr := chatRequestFromCompletions(body)
	if terr != nil {
		writeOpenAIError(w, terr.status, terr.errType, terr.code, terr.msg)
		return
	}
	// Dispatch as a chat request (the node/relay/wire never learn it began as a
	// completions call); formatLegacyCompletions tells the response seams to
	// reshape chat → text on the way back to this client.
	s.dispatchHayai(w, r, endpointChatCompletions, chatBody, formatLegacyCompletions)
}

// chatRequestFromCompletions translates a legacy /v1/completions request body
// into an equivalent /v1/chat/completions body. The prompt becomes a single
// user message; completions-only and chat-incompatible top-level fields are
// stripped; every other field (model, max_tokens, temperature, top_p, n,
// stream, stream_options, stop, presence_penalty, frequency_penalty,
// logit_bias, seed, user, safety_identifier, …) is shared shape and rides
// through untouched so the chat pipeline (model extraction, stream peek, token
// estimation, the pre-seal mutators) sees a normal chat body.
//
// Only a string prompt (or a single-element string array) is supported. Array
// prompts of length > 1 and integer-token prompts cannot be faithfully mapped
// to one chat conversation, so they are rejected with a clear error rather than
// silently mis-served.
func chatRequestFromCompletions(body []byte) ([]byte, *completionsTranslateError) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, &completionsTranslateError{http.StatusBadRequest, "invalid_request_error", "invalid_json", "request body is not valid JSON"}
	}
	promptRaw, ok := raw["prompt"]
	if !ok {
		return nil, &completionsTranslateError{http.StatusBadRequest, "invalid_request_error", "missing_prompt", "request body has no prompt field"}
	}
	prompt, terr := completionsPromptText(promptRaw)
	if terr != nil {
		return nil, terr
	}

	// Drop completions-only fields (echo/best_of/suffix) and `logprobs`, whose
	// type differs between the two APIs (an integer top-N count on completions
	// vs a boolean on chat) — forwarding it would make a strict upstream 422.
	// The prompt itself is replaced by `messages`.
	for _, k := range []string{"prompt", "echo", "best_of", "suffix", "logprobs"} {
		delete(raw, k)
	}
	msgs, err := json.Marshal([]map[string]string{{"role": "user", "content": prompt}})
	if err != nil {
		return nil, &completionsTranslateError{http.StatusInternalServerError, "proxy_error", "translate_request", "failed to build chat request"}
	}
	raw["messages"] = msgs

	out, err := json.Marshal(raw)
	if err != nil {
		return nil, &completionsTranslateError{http.StatusInternalServerError, "proxy_error", "translate_request", "failed to build chat request"}
	}
	return out, nil
}

// completionsPromptText extracts the prompt text from a /v1/completions
// `prompt` field. Accepts a JSON string or a single-element array of strings;
// rejects multi-element arrays and integer-token prompts (which the chat shim
// can't represent as one conversation).
func completionsPromptText(raw json.RawMessage) (string, *completionsTranslateError) {
	var str string
	if err := json.Unmarshal(raw, &str); err == nil {
		return str, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		if len(arr) == 1 {
			return arr[0], nil
		}
		return "", &completionsTranslateError{http.StatusBadRequest, "invalid_request_error", "unsupported_prompt",
			"the /v1/completions compatibility shim accepts only a single string prompt (array and token-id prompts are not supported)"}
	}
	return "", &completionsTranslateError{http.StatusBadRequest, "invalid_request_error", "unsupported_prompt",
		"the /v1/completions compatibility shim accepts only a single string prompt (array and token-id prompts are not supported)"}
}

// completionsResponseFromChat reshapes a non-streaming chat-completions
// response into a text-completion response. It is defensive: anything that
// isn't a chat completion (error envelopes, unexpected shapes) is returned
// unchanged, so sealed upstream errors still reach the client verbatim.
func completionsResponseFromChat(plaintext []byte) []byte {
	if out, ok := reshapeChatToText(plaintext, false); ok {
		return out
	}
	return plaintext
}

// completionsChunkFromChat reshapes a single streaming chat-completions chunk
// (the JSON after `data: `) into a text-completion chunk. Like its non-stream
// sibling it passes through anything that isn't a chat chunk (error frames,
// `[DONE]` never reaches here as JSON).
func completionsChunkFromChat(plaintext []byte) []byte {
	if out, ok := reshapeChatToText(plaintext, true); ok {
		return out
	}
	return plaintext
}

// reshapeChatToText converts a chat-completion(.chunk) JSON object into the
// text-completion shape: `object` becomes "text_completion" and each choice's
// `message`/`delta` (streaming) object is replaced by a flat `text` field
// carrying its content. Index, finish_reason, and any other choice fields are
// preserved. Returns ok=false (caller passes the input through unchanged) for
// anything that doesn't look like a chat completion — error envelopes, missing
// choices, or an unrecognized `object`.
func reshapeChatToText(plaintext []byte, streaming bool) ([]byte, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(plaintext, &raw) != nil {
		return nil, false
	}
	if _, isErr := raw["error"]; isErr {
		return nil, false
	}
	var obj string
	if r, ok := raw["object"]; ok {
		_ = json.Unmarshal(r, &obj)
	}
	want := "chat.completion"
	if streaming {
		want = "chat.completion.chunk"
	}
	choicesRaw, hasChoices := raw["choices"]
	// Translate only a recognized chat object, or an object-less body that still
	// carries a choices array (lenient for the rare upstream that omits
	// `object`). Everything else is left alone.
	if obj != want && !(obj == "" && hasChoices) {
		return nil, false
	}

	if hasChoices {
		var choices []map[string]json.RawMessage
		if err := json.Unmarshal(choicesRaw, &choices); err != nil {
			return nil, false
		}
		srcKey := "message"
		if streaming {
			srcKey = "delta"
		}
		for _, ch := range choices {
			text := ""
			if msgRaw, ok := ch[srcKey]; ok {
				var m struct {
					Content *string `json:"content"`
				}
				if json.Unmarshal(msgRaw, &m) == nil && m.Content != nil {
					text = *m.Content
				}
				delete(ch, srcKey)
			}
			tb, err := json.Marshal(text)
			if err != nil {
				return nil, false
			}
			ch["text"] = tb
			// Completions choices carry a `logprobs` slot (null when not
			// requested); chat may omit it. Default it so SDKs that read the
			// field unconditionally don't trip.
			if _, ok := ch["logprobs"]; !ok {
				ch["logprobs"] = json.RawMessage("null")
			}
		}
		cb, err := json.Marshal(choices)
		if err != nil {
			return nil, false
		}
		raw["choices"] = cb
	}
	raw["object"] = json.RawMessage(`"text_completion"`)

	out, err := json.Marshal(raw)
	if err != nil {
		return nil, false
	}
	return out, true
}
