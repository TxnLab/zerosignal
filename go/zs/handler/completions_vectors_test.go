/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

// Generates / verifies proto/testdata/completions_vectors.json: the legacy
// /v1/completions emulation byte for byte, the request rewritten to chat and
// the chat reply reshaped back, so the SDK's zs.fetch rewrites the same bytes
// the same way. Bodies are base64 because the cases carry bytes that are not
// UTF-8, which a JSON string can't hold.
//
//	cd proto/go && go test ./zs/handler -run TestCompletionsVectors -update

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

const completionsVectorsPath = "../../../testdata/completions_vectors.json"

type completionsRequestCase struct {
	Name    string `json:"name"`
	BodyB64 string `json:"body_b64"`
	// OutB64 is the chat request, when the translation succeeds.
	OutB64 string `json:"out_b64,omitempty"`
	// The OpenAI error otherwise.
	Status  int    `json:"status,omitempty"`
	Type    string `json:"type,omitempty"`
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"`
}

type completionsReplyCase struct {
	Name      string `json:"name"`
	Streaming bool   `json:"streaming"`
	InB64     string `json:"in_b64"`
	// OutB64 is what the client sees: the reshape, or the input unchanged.
	OutB64 string `json:"out_b64"`
	// Reshaped is false where the input passed through unchanged.
	Reshaped bool `json:"reshaped"`
}

type completionsVectors struct {
	Requests []completionsRequestCase `json:"requests"`
	Replies  []completionsReplyCase   `json:"replies"`
}

// esc is a JSON \u escape, spelled so no tool decodes it into the character.
func esc(hex4 string) string { return "\\" + "u" + hex4 }

// nested is a value nested depth arrays deep.
func nested(depth int) string { return strings.Repeat("[", depth) + strings.Repeat("]", depth) }

func completionsRequestInputs() []struct{ name, body string } {
	lineSep := string(rune(0x2028))
	return []struct{ name, body string }{
		{"a string prompt", `{"model":"m","prompt":"hi","max_tokens":5}`},
		{"a one-string array prompt", `{"model":"m","prompt":["hi"]}`},
		{"a one-string array prompt with escapes", `{"prompt":["<x>"]}`},
		{"an array holding null", `{"model":"m","prompt":[null]}`},
		{"a null prompt", `{"model":"m","prompt":null}`},
		{"an empty prompt", `{"prompt":""}`},
		{"two strings", `{"model":"m","prompt":["a","b"]}`},
		{"an empty array", `{"model":"m","prompt":[]}`},
		{"token ids", `{"model":"m","prompt":[1,2]}`},
		{"one token id", `{"prompt":[1]}`},
		{"a string then a number", `{"prompt":["a",1]}`},
		{"an object prompt", `{"model":"m","prompt":{"a":1}}`},
		{"a number prompt", `{"prompt":5}`},
		{"a boolean prompt", `{"prompt":true}`},
		{"no prompt", `{"model":"m"}`},
		{"an empty object", `{}`},
		{"the prompt key in another case", `{"model":"m","Prompt":"hi"}`},
		{"not JSON", `{"model":`},
		{"empty", ``},
		{"top-level null", `null`},
		{"top-level array", `[]`},
		{"top-level string", `"x"`},
		{"a byte-order mark", string([]byte{0xef, 0xbb, 0xbf}) + `{"prompt":"p"}`},
		{"whitespace around the document", " \n\t{\"prompt\":\"p\"}\r\n "},
		{"drops the completions-only fields",
			`{"model":"m","prompt":"p","echo":true,"best_of":2,"suffix":"s","logprobs":3,"stream":true,"stream_options":{"include_usage":true},"stop":["\n"]}`},
		{"replaces messages", `{"prompt":"p","messages":[{"role":"system","content":"x"}]}`},
		{"compacts and escapes the other values",
			`{ "model" : "m" , "user" : "<a & b>" , "metadata" : { "z" : 1 , "a" : [ 1.0 , 1E5 , -0 , 1e-7 ] } , "prompt" : "p" }`},
		{"keeps a nested duplicate and its order", `{"metadata":{"b":1,"a":2,"b":3},"prompt":"p"}`},
		{"escapes the prompt as Go does",
			`{"prompt":"<b> & \"q\" \\ \t ` + esc("0001") + ` ` + esc("0008") + ` ` + esc("000c") + ` ` + esc("001f") + ` ` +
				esc("2028") + ` ` + lineSep + ` ` + esc("2029") + ` ` + string([]byte{0x7f}) + `"}`},
		{"a raw line separator in another value", `{"user":"a` + lineSep + `b","prompt":"p"}`},
		{"a raw paragraph separator in another value", `{"user":"a` + string(rune(0x2029)) + `b","prompt":"p"}`},
		{"whitespace of every kind inside a value", "{\"metadata\":{\"a\":\t[1,\n2]\r,\"b\" : \"x\"},\"prompt\":\"p\"}"},
		{"an escaped quote before a space in another value", `{"user":"a\" b\\ c ","prompt":"p"}`},
		{"invalid UTF-8 in another value", `{"user":"a` + string([]byte{0xff, 0xfe}) + `b","prompt":"p"}`},
		{"a truncated rune in another value", `{"user":"a` + string([]byte{0xe2, 0x80}) + `","prompt":"p"}`},
		{"invalid UTF-8 in the prompt", `{"prompt":"a` + string([]byte{0xff}) + `b` + string([]byte{0xe2, 0x80}) + `"}`},
		{"a lone surrogate in the prompt", `{"prompt":"` + esc("d800") + `x"}`},
		{"a lone low surrogate in the prompt", `{"prompt":"x` + esc("dc00") + `"}`},
		{"a surrogate pair in the prompt", `{"prompt":"` + esc("d83d") + esc("de00") + `"}`},
		{"a lone surrogate in another value is kept as written", `{"user":"` + esc("d800") + `","prompt":"p"}`},
		{"two prompts, the last wins", `{"prompt":"a","prompt":"b"}`},
		{"a later null prompt", `{"prompt":"a","prompt":null}`},
		{"a later bad prompt", `{"prompt":"a","prompt":[1,2]}`},
		{"a duplicate key, the last wins", `{"model":"a","prompt":"p","model":"b"}`},
		{"an escaped key", `{"mod` + esc("0065") + `l":"m","prompt":"p"}`},
		{"an escaped key meets a plain one", `{"model":"a","mod` + esc("0065") + `l":"b","prompt":"p"}`},
		{"an escaped prompt key", `{"pr` + esc("006f") + `mpt":"p"}`},
		{"a key with a lone surrogate", `{"` + esc("dc00") + `":1,"prompt":"p"}`},
		{"a key with invalid UTF-8", `{"k` + string([]byte{0xff}) + `":1,"prompt":"p"}`},
		{"keys sorted by UTF-8 bytes",
			`{"` + string(rune(0x1f600)) + `":1,"` + string(rune(0xff01)) + `":2,"z":3,"` + string(rune(0xe9)) + `":4,"prompt":"p"}`},
		{"a key needing escapes", `{"a<b":1,"t\tc":2,"q\"":3,"prompt":"p"}`},
		{"nested at the depth limit", `{"x":` + nested(9999) + `,"prompt":"p"}`},
		{"nested past the depth limit", `{"x":` + nested(10000) + `,"prompt":"p"}`},
		{"a control byte in a string", "{\"prompt\":\"a\x01b\"}"},
	}
}

func completionsReplyInputs() []struct {
	name      string
	streaming bool
	body      string
} {
	lineSep := string(rune(0x2028))
	choice := `[{"index":0,"message":{"content":"a"}}]`
	return []struct {
		name      string
		streaming bool
		body      string
	}{
		{"a completion", false,
			`{"id":"c1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"hi"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`},
		{"two choices", false,
			`{"object":"chat.completion","choices":[{"index":0,"message":{"content":"a"}},{"index":1,"message":{"content":"b"},"finish_reason":"length"}]}`},
		{"a chunk", true, `{"id":"c1","object":"chat.completion.chunk","choices":[{"index":0,"delta":{"content":"h"},"finish_reason":null}]}`},
		{"a chunk with no content", true, `{"object":"chat.completion.chunk","choices":[{"index":0,"delta":{"role":"assistant"}}]}`},
		{"a chunk carrying a message", true, `{"object":"chat.completion.chunk","choices":[{"index":0,"message":{"content":"m"}}]}`},
		{"a usage chunk", true, `{"object":"chat.completion.chunk","choices":[],"usage":{"prompt_tokens":1}}`},
		{"a completion read as a chunk", true, `{"object":"chat.completion","choices":` + choice + `}`},
		{"a chunk read as a completion", false, `{"object":"chat.completion.chunk","choices":[{"delta":{"content":"a"}}]}`},
		{"an error envelope", false, `{"error":{"message":"x","type":"server_error"}}`},
		{"an error beside choices", false, `{"error":null,"object":"chat.completion","choices":` + choice + `}`},
		{"an error frame", true, `{"error":{"message":"x"}}`},
		{"an escaped error key", false, `{"err` + esc("006f") + `r":1,"object":"chat.completion","choices":` + choice + `}`},
		{"an error key in another case", false, `{"Error":1,"object":"chat.completion","choices":` + choice + `}`},
		{"no object, with choices", false, `{"choices":` + choice + `}`},
		{"no object, no choices", false, `{"id":"x"}`},
		{"an unknown object", false, `{"object":"response","choices":` + choice + `}`},
		{"an object that is not a string", false, `{"object":5,"choices":[]}`},
		{"a null object", false, `{"object":null,"choices":[]}`},
		{"the object key in another case", false, `{"Object":"chat.completion","choices":` + choice + `}`},
		{"an escaped object value", false, `{"object":"chat.` + esc("0063") + `ompletion","choices":` + choice + `}`},
		{"two objects, the last wins", false, `{"object":"x","object":"chat.completion","choices":` + choice + `}`},
		{"choices null", false, `{"object":"chat.completion","choices":null}`},
		{"choices empty", false, `{"object":"chat.completion","choices":[]}`},
		{"choices an object", false, `{"object":"chat.completion","choices":{}}`},
		{"choices a string", false, `{"object":"chat.completion","choices":"x"}`},
		{"a null choice", false, `{"object":"chat.completion","choices":[null]}`},
		{"a null choice after a good one", false, `{"object":"chat.completion","choices":[{"message":{"content":"a"}},null]}`},
		{"a choice that is a number", false, `{"object":"chat.completion","choices":[1]}`},
		{"a choice that is an array", false, `{"object":"chat.completion","choices":[[]]}`},
		{"an escaped choices key", false, `{"object":"chat.completion","cho` + esc("0069") + `ces":` + choice + `}`},
		{"two choices keys, the last wins", false, `{"object":"chat.completion","choices":[1],"choices":` + choice + `}`},
		{"an empty choice", false, `{"object":"chat.completion","choices":[{}]}`},
		{"a null message", false, `{"object":"chat.completion","choices":[{"message":null}]}`},
		{"a message that is an array", false, `{"object":"chat.completion","choices":[{"message":[1]}]}`},
		{"a message that is a string", false, `{"object":"chat.completion","choices":[{"message":"hi"}]}`},
		{"a null content", false, `{"object":"chat.completion","choices":[{"message":{"content":null}}]}`},
		{"a content that is not a string", false,
			`{"object":"chat.completion","choices":[{"message":{"content":[{"type":"text","text":"a"}]}}]}`},
		{"the content key in another case", false, `{"object":"chat.completion","choices":[{"message":{"CONTENT":"a"}}]}`},
		{"two contents, the last wins", false, `{"object":"chat.completion","choices":[{"message":{"content":"a","content":"b"}}]}`},
		{"a later content in another case", false, `{"object":"chat.completion","choices":[{"message":{"content":"a","Content":"b"}}]}`},
		{"a later null content", false, `{"object":"chat.completion","choices":[{"message":{"content":"a","content":null}}]}`},
		{"a later null content key in another case", false, `{"object":"chat.completion","choices":[{"message":{"content":"a","Content":null}}]}`},
		{"a later content of the wrong type", false, `{"object":"chat.completion","choices":[{"message":{"content":"a","content":1}}]}`},
		{"a wrong-typed content, then a good one", false, `{"object":"chat.completion","choices":[{"message":{"content":1,"content":"b"}}]}`},
		{"an escaped content key", false, `{"object":"chat.completion","choices":[{"message":{"cont` + esc("0065") + `nt":"a"}}]}`},
		{"other message fields of the wrong type", false, `{"object":"chat.completion","choices":[{"message":{"role":1,"content":"a"}}]}`},
		{"two messages, the last wins", false, `{"object":"chat.completion","choices":[{"message":{"content":"a"},"message":{"content":"b"}}]}`},
		{"a choice that already has text", false, `{"object":"chat.completion","choices":[{"text":"old","message":{"content":"a"}}]}`},
		{"logprobs kept", false, `{"object":"chat.completion","choices":[{"logprobs":{"content":[]},"message":{"content":"a"}}]}`},
		{"a null logprobs kept", false, `{"object":"chat.completion","choices":[{"logprobs":null,"message":{"content":"a"}}]}`},
		{"other choice fields kept", false,
			`{"object":"chat.completion","choices":[{"finish_reason":"stop","index":3,"zeta":{"b":1,"a":2},"message":{"content":"a"}}]}`},
		{"HTML in the content and elsewhere", false,
			`{"id":"<x>","object":"chat.completion","choices":[{"message":{"content":"<b> & c"}}]}`},
		{"a raw line separator in the content and elsewhere", false,
			`{"id":"a` + lineSep + `b","object":"chat.completion","choices":[{"message":{"content":"c` + lineSep + `d"}}]}`},
		{"invalid UTF-8 in the content", false,
			`{"object":"chat.completion","choices":[{"message":{"content":"a` + string([]byte{0xff}) + `b"}}]}`},
		{"invalid UTF-8 elsewhere", false,
			`{"id":"a` + string([]byte{0xff, 0xc3}) + `","object":"chat.completion","choices":` + choice + `}`},
		{"a lone surrogate in the content", false,
			`{"object":"chat.completion","choices":[{"message":{"content":"` + esc("d800") + `"}}]}`},
		{"a lone surrogate elsewhere is kept as written", false,
			`{"id":"` + esc("d800") + `","object":"chat.completion","choices":` + choice + `}`},
		{"control characters in the content", false,
			`{"object":"chat.completion","choices":[{"message":{"content":"\t\n` + esc("0001") + esc("0008") + esc("000c") + `\"\\/"}}]}`},
		{"whitespace compacted", false,
			"{\n  \"object\" : \"chat.completion\" ,\n  \"choices\" : [ { \"index\" : 0 , \"message\" : { \"content\" : \"a b\" } } ] ,\n  \"x\" : [ 1 , { \"y\" : \" \" } ]\n}\n"},
		{"numbers kept as written", false, `{"object":"chat.completion","created":1.0e3,"n":-0,"choices":[{"index":0E0,"message":{"content":"a"}}]}`},
		{"keys sorted by UTF-8 bytes", false,
			`{"` + string(rune(0x1f600)) + `":1,"` + string(rune(0xff01)) + `":2,"object":"chat.completion","choices":[{"` +
				string(rune(0x1f600)) + `":1,"` + string(rune(0xff01)) + `":2,"message":{"content":"a"}}]}`},
		{"a key with invalid UTF-8", false, `{"k` + string([]byte{0xff}) + `":1,"object":"chat.completion","choices":` + choice + `}`},
		{"a key with a lone surrogate", false, `{"` + esc("d800") + `":1,"object":"chat.completion","choices":` + choice + `}`},
		{"a key needing escapes", false, `{"a<b":1,"object":"chat.completion","choices":[{"c&d":2,"message":{"content":"a"}}]}`},
		{"not JSON", false, `{"object":`},
		{"empty", false, ``},
		{"the DONE sentinel", true, `[DONE]`},
		{"a byte-order mark", false, string([]byte{0xef, 0xbb, 0xbf}) + `{"object":"chat.completion","choices":[]}`},
		{"top-level null", false, `null`},
		{"top-level array", false, `[]`},
		{"nested at the depth limit", false, `{"x":` + nested(9999) + `,"object":"chat.completion","choices":[]}`},
		{"nested past the depth limit", false, `{"x":` + nested(10000) + `,"object":"chat.completion","choices":[]}`},
		{"a choice nested at the depth limit", false, `{"object":"chat.completion","choices":[{"x":` + nested(9997) + `}]}`},
		{"an image reply", false, `{"created":1,"data":[{"b64_json":"AAAA"}]}`},
	}
}

func b64(s []byte) string { return base64.StdEncoding.EncodeToString(s) }

func TestCompletionsVectors(t *testing.T) {
	var got completionsVectors
	for _, in := range completionsRequestInputs() {
		c := completionsRequestCase{Name: in.name, BodyB64: b64([]byte(in.body))}
		out, terr := chatRequestFromCompletions([]byte(in.body))
		if terr != nil {
			c.Status, c.Type, c.Code, c.Message = terr.status, terr.errType, terr.code, terr.msg
		} else {
			c.OutB64 = b64(out)
		}
		got.Requests = append(got.Requests, c)
	}
	for _, in := range completionsReplyInputs() {
		out, ok := reshapeChatToText([]byte(in.body), in.streaming)
		if !ok {
			out = []byte(in.body)
		}
		got.Replies = append(got.Replies, completionsReplyCase{
			Name: in.name, Streaming: in.streaming, InB64: b64([]byte(in.body)), OutB64: b64(out), Reshaped: ok,
		})
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(completionsVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(completionsVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(want, out) {
		t.Fatalf("translation differs from %s; if the change is intended, regenerate with -update and review the diff", completionsVectorsPath)
	}
}
