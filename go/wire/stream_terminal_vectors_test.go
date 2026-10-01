/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire_test

// Cross-impl parity test for terminal-frame classification. Generates /
// verifies proto/testdata/stream_vectors.json — a language-neutral fixture
// pinning ClassifyStreamFrame. proto/ts loads the same file and asserts
// equality, so drift between the Go side (proxy) and the TS side (client)
// fails on both.
//
// This is a payer-safety invariant, not a rendering one: a consumer that
// misses a terminal frame tears the stream down before the `zs-receipt` /
// `zs-settle-group` tail, and the ticket then lapses into whatever the
// operator claimed, unverified. See SPEC.md § 5.3 "Consuming the settlement
// tail".
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./wire -run TestStreamTerminalVectors -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"testing"

	"github.com/TxnLab/zerosignal/go/wire"
)

var updateStreamVectors = flag.Bool("update", false, "regenerate proto/testdata/stream_vectors.json")

const streamVectorsPath = "../../testdata/stream_vectors.json"

type streamFrameVector struct {
	Name     string `json:"name"`
	API      string `json:"api"`
	Frame    string `json:"frame"`
	Terminal bool   `json:"terminal"`
	Error    bool   `json:"error"`
	Message  string `json:"message"`
}

type streamVectorsFile struct {
	Version int                 `json:"version"`
	Comment string              `json:"comment"`
	Frames  []streamFrameVector `json:"frames"`
}

// Frames are stored as raw JSON strings rather than hex: every case is
// human-readable UTF-8, and a reviewer changing this file should be able to
// see what shape they are asserting about.
var streamFrameCases = []struct {
	name  string
	api   wire.StreamAPI
	frame string
}{
	// --- content: must NOT be terminal, or a mid-stream disconnect would
	// stop cancelling promptly and leave nodes generating for nobody.
	{"chat content delta", wire.StreamAPIChat, `{"id":"c","object":"chat.completion.chunk","choices":[{"delta":{"content":"hi"}}]}`},
	{"chat delta with null finish_reason", wire.StreamAPIChat, `{"choices":[{"index":0,"delta":{"content":"hi"},"finish_reason":null}]}`},
	// A model emitting the word "stop" clears the value prefilter but has no
	// finish_reason of its own — pins that the parse fallback reads the field,
	// not the text.
	{"chat delta saying stop", wire.StreamAPIChat, `{"choices":[{"index":0,"delta":{"content":"stop"},"finish_reason":null}]}`},
	{"chat delta mentioning error", wire.StreamAPIChat, `{"choices":[{"delta":{"content":"the error was X"}}]}`},
	{"chat usage-only chunk", wire.StreamAPIChat, `{"choices":[],"usage":{"prompt_tokens":3}}`},
	{"responses output delta", wire.StreamAPIResponses, `{"type":"response.output_text.delta","delta":"hi"}`},
	{"responses delta mentioning error", wire.StreamAPIResponses, `{"type":"response.output_text.delta","delta":"error"}`},
	{"responses created", wire.StreamAPIResponses, `{"type":"response.created","response":{"id":"resp_1"}}`},

	// --- tool rounds: the node keeps generating, so NOT terminal.
	{"chat finish_reason tool_calls", wire.StreamAPIChat, `{"choices":[{"finish_reason":"tool_calls"}]}`},
	{"responses tool call in progress", wire.StreamAPIResponses, `{"type":"response.zs_tool_call.in_progress","id":"tc_1"}`},
	// A status frame carrying an action (SPEC 5.3.1) is still just a status
	// frame — the added query/sources must not make it look terminal.
	{"responses tool call with action", wire.StreamAPIResponses, `{"type":"response.zs_tool_call.completed","item_id":"zstc_1","tool":"zs_web_search","action":{"type":"search","query":"algorand tps","sources":[{"type":"url","url":"https://a.example"}]}}`},
	// A model-chosen query that IS a terminal type string clears the
	// substring prefilter, so the confirming parse is the only thing between
	// "a user asked about the Responses API" and a flipped payer-safety
	// verdict. Content must never steer it — only the frame's own `type`.
	{"responses tool call action query mimicking terminal", wire.StreamAPIResponses, `{"type":"response.zs_tool_call.in_progress","item_id":"zstc_1","tool":"zs_web_search","action":{"type":"search","query":"response.completed"}}`},
	// The same collision on the pre-9.4 surface it has always had: a delta
	// whose text quotes the event name.
	{"responses delta quoting a terminal type", wire.StreamAPIResponses, `{"type":"response.output_text.delta","delta":"response.completed"}`},

	// --- generation-terminal.
	{"chat finish_reason stop", wire.StreamAPIChat, `{"choices":[{"finish_reason":"stop"}]}`},
	{"chat finish_reason stop spaced", wire.StreamAPIChat, `{"choices":[{"finish_reason": "stop"}]}`},
	{"chat finish_reason length", wire.StreamAPIChat, `{"choices":[{"finish_reason":"length"}]}`},
	// Past the fast-path needles, so these exercise the parse fallback. Missing
	// them would silently disarm the settlement-tail drain for any emitter that
	// spaces or pretty-prints its JSON differently.
	{"chat finish_reason stop spaced both sides", wire.StreamAPIChat, `{"choices":[{"finish_reason" : "stop"}]}`},
	{"chat finish_reason length prettified", wire.StreamAPIChat, "{\n  \"choices\": [\n    {\n      \"finish_reason\":\t\"length\"\n    }\n  ]\n}"},
	// n>1 sampling: a terminal sibling must not be hidden by a still-running
	// choice ahead of it.
	{"chat finish_reason stop on second choice", wire.StreamAPIChat, `{"choices":[{"index":0,"finish_reason":null},{"index":1,"finish_reason" : "stop"}]}`},
	{"responses completed", wire.StreamAPIResponses, `{"type":"response.completed","response":{"id":"resp_1"}}`},
	{"responses incomplete", wire.StreamAPIResponses, `{"type":"response.incomplete","response":{"incomplete_details":{"reason":"max_output_tokens"}}}`},
	{"responses failed", wire.StreamAPIResponses, `{"type":"response.failed","response":{"error":{"code":"x","message":"nope"}}}`},
	// Truncated mid-frame, but it mentions a terminal type. The confirming
	// parse can't run, so it must fail TOWARD terminal: a missed terminal
	// makes the consumer cancel and drop the settlement tail, while a
	// spurious one only arms the drain early. Both impls answer identically
	// for every non-object document — Go folds JSON `null` in with the parse
	// errors precisely so it can't diverge from TS's asRecord().
	{"responses truncated frame mentioning a terminal type", wire.StreamAPIResponses, `{"type":"response.completed","response":{"id":`},
	// The chat side answers the SAME question the OPPOSITE way, and that
	// divergence is deliberate but was pinned by nothing in either language —
	// the literal was free to flip, in the direction that drops the settlement
	// tail, with every suite green. This frame clears both chat prefilters
	// (`"finish_reason"` and `"stop"`), dodges every fast-path needle (the
	// space before the colon), and does not parse. Anyone harmonizing the two
	// classifiers must change this vector deliberately, in both languages.
	{"chat truncated frame mentioning a terminal finish_reason", wire.StreamAPIChat, `{"choices":[{"finish_reason" : "stop"`},
	// The same truncation in the COMPACT spelling, which does hit a fast-path
	// needle — and so answers terminal where the spaced one above answers
	// non-terminal. This pair is the only thing that distinguishes the fast
	// path from the parse fallback: they agree on every well-formed input, so
	// without it the entire needle list could be deleted with a green suite,
	// and a truncated vLLM/OpenAI stop frame would stop arming the drain.
	{"chat truncated frame matching a fast-path needle", wire.StreamAPIChat, `{"choices":[{"finish_reason":"stop"`},
	// Parses as an object, clears both prefilters, but `choices` is not an
	// array — the chat confirm step's other non-terminal exit, previously
	// unreached by any vector. The `"length"` here is what gets it past the
	// second prefilter without being a finish_reason.
	{"chat object whose choices is not an array", wire.StreamAPIChat, `{"choices":{"0":{"finish_reason" : "stop"}},"note":"length"}`},
	// A junk element ahead of a terminal sibling. Both impls skip the
	// non-object and keep scanning (Go `continue`, TS `continue`); returning
	// early instead would hide the terminal and strand the settlement tail.
	// That parity claim was prose in both languages until this vector.
	//
	// The junk must be a STRING, not `null`: JSON null unmarshals into a Go map
	// without error (leaving it nil), so a null element never reaches the skip
	// branch at all and pins nothing.
	{"chat junk choice before a terminal sibling", wire.StreamAPIChat, `{"choices":["junk",{"finish_reason" : "stop"}]}`},
	// …and the null element on its own, which takes the OTHER path: it parses,
	// yields a nil map, and reads as a choice with no finish_reason. Distinct
	// from the string case above and previously unpinned in both languages.
	{"chat null choice before a terminal sibling", wire.StreamAPIChat, `{"choices":[null,{"finish_reason" : "stop"}]}`},

	// --- error frames: terminal AND error. The chat case is the one that
	// stranded ticket ldHkQ5X… — an upstream 400 the client closed on.
	{"chat error envelope", wire.StreamAPIChat, `{"error":{"message":"invalid temperature: only 1 is allowed for this model","type":"invalid_request_error"}}`},
	{"chat error without message", wire.StreamAPIChat, `{"error":{"code":"x"}}`},
	// Prettified upstream error: pins that the message-less fallback is
	// whitespace-normalized, which is the only way Go (echoes wire bytes) and
	// TS (JSON.stringify round-trip) can agree byte-for-byte.
	{"chat error without message prettified", wire.StreamAPIChat, `{"error": { "code": "x", "nested": { "a": 1 } }}`},
	{"chat error null", wire.StreamAPIChat, `{"error":null,"choices":[]}`},
	{"responses error event", wire.StreamAPIResponses, `{"type":"error","code":"context_length_exceeded","message":"too long"}`},
	{"responses error event without message", wire.StreamAPIResponses, `{"type":"error","code":"x"}`},
	// Off-type members alongside a real error. A typed Go probe struct used to
	// fail the whole document on any one of these and report the frame as
	// ordinary content, while the duck-typed TS mirror still saw the error —
	// a cross-impl split in the unsafe direction (Go = the proxy = no drain).
	{"responses error event with non-string message", wire.StreamAPIResponses, `{"type":"error","code":"x","message":123}`},
	{"chat error envelope with non-string type", wire.StreamAPIChat, `{"type":123,"error":{"message":"boom"}}`},
	{"chat error envelope with non-string top-level message", wire.StreamAPIChat, `{"error":{"message":"boom"},"message":42}`},

	// --- malformed / unrelated.
	{"not json", wire.StreamAPIChat, `nope`},
	{"empty object", wire.StreamAPIChat, `{}`},
}

func TestStreamTerminalVectors(t *testing.T) {
	got := streamVectorsFile{
		Version: 1,
		Comment: "Terminal-frame classification for streamed responses (SPEC.md 5.3, 'Consuming the settlement tail'). Generated by proto/go/wire/stream_terminal_vectors_test.go; consumed by proto/ts/test/stream-terminal-vectors.test.ts. Regenerate: cd proto/go && go test ./wire -run TestStreamTerminalVectors -update",
	}
	for _, c := range streamFrameCases {
		v := wire.ClassifyStreamFrame([]byte(c.frame), c.api)
		got.Frames = append(got.Frames, streamFrameVector{
			Name:     c.name,
			API:      string(c.api),
			Frame:    c.frame,
			Terminal: v.Terminal,
			Error:    v.Error,
			Message:  v.Message,
		})
	}
	encoded, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateStreamVectors {
		if err := os.WriteFile(streamVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s (%d frames)", streamVectorsPath, len(got.Frames))
		return
	}

	onDisk, err := os.ReadFile(streamVectorsPath)
	if err != nil {
		t.Fatalf("read %s: %v (regenerate: cd proto/go && go test ./wire -run TestStreamTerminalVectors -update)", streamVectorsPath, err)
	}
	if !bytes.Equal(bytes.TrimSpace(onDisk), bytes.TrimSpace(encoded)) {
		t.Fatalf("%s is out of date with ClassifyStreamFrame.\nIf the change was intentional, regenerate AND port the same change to proto/ts/src/wire/streamTerminal.ts:\n  cd proto/go && go test ./wire -run TestStreamTerminalVectors -update", streamVectorsPath)
	}
}

// Assertions the vectors file can't make on its own: the invariants a future
// edit must not break, stated as properties rather than as recorded output.
func TestStreamTerminalInvariants(t *testing.T) {
	// Error implies Terminal — the whole point. Every node error path writes
	// the error frame, then the zero-cost receipt, then [DONE].
	for _, c := range streamFrameCases {
		v := wire.ClassifyStreamFrame([]byte(c.frame), c.api)
		if v.Error && !v.Terminal {
			t.Errorf("%s: Error without Terminal — the settlement tail would be dropped", c.name)
		}
		if !v.Error && v.Message != "" {
			t.Errorf("%s: Message set without Error", c.name)
		}
	}
	// tool_calls must never be terminal: the node runs the tool and keeps
	// generating, so draining on it would pin a disconnected request open for
	// the full drain timeout instead of cancelling. Both spellings — the second
	// reaches the parse fallback, which must read the value rather than settle
	// for "mentions finish_reason".
	for _, frame := range []string{
		`{"choices":[{"finish_reason":"tool_calls"}]}`,
		`{"choices":[{"finish_reason" : "tool_calls"}],"stop":"length"}`,
	} {
		if v := wire.ClassifyStreamFrame([]byte(frame), wire.StreamAPIChat); v.Terminal {
			t.Errorf("finish_reason tool_calls classified terminal: %s", frame)
		}
	}
}
