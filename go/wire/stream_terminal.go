/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package wire

import (
	"bytes"
	"encoding/json"
)

// Terminal-frame classification for streamed responses (SPEC.md § 5.3,
// "Consuming the settlement tail").
//
// Why this lives in proto rather than in each consumer: a stream's settlement
// tail (`zs-settle-group`, `zs-receipt`, `[DONE]`) arrives *after* the frame
// that tells a human the answer is done. A consumer that tears the stream
// down on that frame never reads the receipt — so it cannot verify the
// operator's charge, cannot protest it, and cannot co-sign the atomic settle.
// The ticket then lapses into whatever the operator unilaterally claimed,
// because `settleLapsed` reads payer silence as acceptance. Which frames are
// terminal is therefore a *payer-safety* property of the protocol, not a
// rendering detail, and both the reference proxy and the reference client MUST
// answer it identically. Golden-vectored across Go/TS via
// proto/testdata/stream_vectors.json.
//
// Deliberately NOT part of the sealed-frame plumbing: this operates on the
// already-decrypted plaintext of an `event: zs` frame, and says nothing about
// AEAD, counters, or AAD.

// StreamAPI selects which upstream event vocabulary a frame is read against.
// A string (not an iota) so the golden vectors carry the same token in both
// languages.
type StreamAPI string

const (
	// StreamAPIChat is /v1/chat/completions — terminal on a choice's
	// finish_reason, errors as {"error": {...}}.
	StreamAPIChat StreamAPI = "chat"
	// StreamAPIResponses is /v1/responses — terminal on the response.*
	// lifecycle events, errors as the union's {"type":"error"} member.
	StreamAPIResponses StreamAPI = "responses"
)

// FrameVerdict is what a decrypted content frame means for stream lifecycle.
type FrameVerdict struct {
	// Terminal is true when the node has finished producing output and the
	// settlement tail is next on the wire. A consumer MUST keep reading after
	// a Terminal frame until `[DONE]` / stream end (bounded by its own idle
	// timeout) even if its caller has gone away.
	Terminal bool
	// Error is true when this frame is an error envelope rather than content.
	// Implies Terminal — every node error path writes the error frame, then
	// the zero-cost receipt, then `[DONE]`, then returns.
	Error bool
	// Message is the operator/upstream error text when Error is true, else "".
	// Control-plane, not completion content — a consumer may log it (the
	// reference proxy does; see proxy/AGENTS.md for why that carve-out is
	// narrow) but MUST NOT treat it as licence to log frame content.
	Message string
}

// Fast-path markers for a terminal chat-completions frame: compact (vLLM and
// OpenAI, the common case) and single-space JSON forms. "tool_calls" is
// deliberately excluded — the node runs the tool and keeps generating, so it is
// NOT complete. A miss here is not the answer, only the end of the cheap path:
// chatGenerationComplete falls through to a real parse, because failing to
// recognize a terminal frame is this classifier's UNSAFE direction (the
// consumer cancels and drops the settlement tail).
var chatGenerationCompleteTokens = [][]byte{
	[]byte(`"finish_reason":"stop"`),
	[]byte(`"finish_reason": "stop"`),
	[]byte(`"finish_reason":"length"`),
	[]byte(`"finish_reason": "length"`),
}

// The /v1/responses lifecycle events the node follows with the settlement
// tail.
const (
	responsesTypeCompleted  = "response.completed"
	responsesTypeIncomplete = "response.incomplete"
	responsesTypeFailed     = "response.failed"
)

// Prefilter needles: each terminal type in its quoted JSON-string form.
// Derived from the constants above so the two can't drift. A hit means the
// frame MENTIONS a terminal type somewhere; responsesGenerationComplete then
// confirms it is the frame's own discriminator.
var responsesGenerationCompleteTokens = [][]byte{
	[]byte(`"` + responsesTypeCompleted + `"`),
	[]byte(`"` + responsesTypeIncomplete + `"`),
	[]byte(`"` + responsesTypeFailed + `"`),
}

// ClassifyStreamFrame reports whether a decrypted `event: zs` frame ends the
// node's generation, and whether it is an error envelope.
//
// Substring checks before any JSON parse: this runs on every content frame on
// the streaming hot path, and the overwhelmingly common case (a content delta)
// must cost a couple of memchr sweeps, not an unmarshal.
func ClassifyStreamFrame(plaintext []byte, api StreamAPI) FrameVerdict {
	if msg, ok := StreamErrorMessage(plaintext); ok {
		return FrameVerdict{Terminal: true, Error: true, Message: msg}
	}
	if api == StreamAPIResponses {
		if responsesGenerationComplete(plaintext) {
			return FrameVerdict{Terminal: true}
		}
		return FrameVerdict{}
	}
	if chatGenerationComplete(plaintext) {
		return FrameVerdict{Terminal: true}
	}
	return FrameVerdict{}
}

// mentionsAny reports whether plaintext contains any of tokens — the cheap
// substring sweep both generation-complete classifiers open with.
func mentionsAny(plaintext []byte, tokens [][]byte) bool {
	for _, t := range tokens {
		if bytes.Contains(plaintext, t) {
			return true
		}
	}
	return false
}

// confirmTerminal is the parse half both generation-complete classifiers share:
// decode the frame as a JSON object and let confirm read its own discriminator.
//
// onUnparseable is what the frame means when it is not a JSON object at all,
// and the two callers deliberately pass OPPOSITE values — so the divergence is
// an argument you can see at the call site rather than a policy each body
// restates. Neither answer is the safe one in general: failing to recognize a
// terminal frame makes the consumer cancel and drop the settlement tail, while
// a spurious terminal only arms the drain early.
//
// `top == nil` is the JSON-`null` document: it unmarshals into a map without
// error, leaving the map nil. Folding it in with the parse failures keeps this
// uniform — anything that is not a JSON *object* takes onUnparseable — and
// keeps it identical to the TS mirror, where asRecord() can't tell null from a
// string or an array.
func confirmTerminal(plaintext []byte, onUnparseable bool, confirm func(top map[string]json.RawMessage) bool) bool {
	var top map[string]json.RawMessage
	if json.Unmarshal(plaintext, &top) != nil || top == nil {
		return onUnparseable
	}
	return confirm(top)
}

// responsesGenerationComplete reports whether a /v1/responses frame IS one of
// the lifecycle terminals — not merely one that mentions the name.
//
// A substring prefilter guards a real parse, the same shape as the chat path:
// a frame that never mentions a terminal type can't be one, so ordinary
// deltas still cost a couple of memchr sweeps. What gets past it is rare —
// the single real terminal frame per stream, plus the odd frame whose own
// content quotes an event name — and affords an unmarshal.
//
// The parse is not decoration. These frames carry text nobody on this side
// chose: as of proto 9.4 a tool-round status frame embeds the model's own
// search query (SPEC § 5.3.1 `action`), and `{"query":"response.completed"}`
// matches the prefilter exactly; an output_text delta quoting the event name
// does the same. Reading the top-level `type` is what separates "this frame
// is the terminal" from "this frame talks about one". Without it a user who
// asks about the Responses API mid-conversation flips the verdict, which is
// user-controllable input steering a payer-safety signal.
//
// Unparseable input answers TRUE here: the prefilter has already established
// that the bytes mention a terminal type, so "malformed and mentions one" is
// the right place to be generous. The chat path answers false to the same
// question — see chatGenerationComplete for why nobody has reconciled them.
func responsesGenerationComplete(plaintext []byte) bool {
	if !mentionsAny(plaintext, responsesGenerationCompleteTokens) {
		return false
	}
	return confirmTerminal(plaintext, true, func(top map[string]json.RawMessage) bool {
		switch rawString(top["type"]) {
		case responsesTypeCompleted, responsesTypeIncomplete, responsesTypeFailed:
			return true
		}
		return false
	})
}

// chatGenerationComplete reports whether a chat-completions frame carries a
// terminal finish_reason on any choice.
//
// Two prefilters guard a real parse. A frame that never mentions finish_reason
// can't be terminal, and a normal delta chunk mentions it only as
// `"finish_reason":null` — carrying neither terminal value — so the hot path
// still costs substring sweeps alone. Anything that gets past both is rare
// enough (roughly one frame per stream) to afford an unmarshal, and paying for
// it is how `{"finish_reason" : "stop"}` from an unusually-spaced emitter still
// arms the drain instead of silently disarming it.
//
// The prefilters are matched byte-for-byte by the TS mirror, including the fact
// that they read the *raw* bytes: a frame that escapes its way out of them
// (`"stop"`) is classified non-terminal by both implementations. That is a
// deliberate bound on cost, and parity matters more here than either answer.
//
// Unparseable input answers FALSE, the opposite of the responses path, and the
// TS mirror reproduces the asymmetry faithfully — so it is a design divergence
// inside the classifier rather than a port bug. Harmonizing it is a behaviour
// change on both languages (the chat parse-failure branch is unvectored in
// both) and has not been argued through; until it is, the two answers stay as
// they are, spelled as the onUnparseable argument rather than as two bodies
// that quietly disagree.
func chatGenerationComplete(plaintext []byte) bool {
	if mentionsAny(plaintext, chatGenerationCompleteTokens) {
		return true
	}
	if !bytes.Contains(plaintext, []byte(`"finish_reason"`)) {
		return false
	}
	if !bytes.Contains(plaintext, []byte(`"stop"`)) && !bytes.Contains(plaintext, []byte(`"length"`)) {
		return false
	}
	return confirmTerminal(plaintext, false, func(top map[string]json.RawMessage) bool {
		var choices []json.RawMessage
		if json.Unmarshal(top["choices"], &choices) != nil {
			return false
		}
		for _, raw := range choices {
			var choice map[string]json.RawMessage
			if json.Unmarshal(raw, &choice) != nil {
				// Not an object — skip it rather than failing the frame, so one
				// junk element can't hide a terminal sibling. Mirrors the TS
				// `continue`.
				continue
			}
			switch rawString(choice["finish_reason"]) {
			case "stop", "length":
				return true
			}
		}
		return false
	})
}

// rawString decodes a raw JSON member as a string, yielding "" for an absent,
// null, or non-string member.
//
// This is the Go spelling of the TS mirror's `typeof x === 'string' ? x : ”`,
// and it exists because the obvious alternative — a typed probe struct — is
// wrong in a way that only shows up cross-implementation: encoding/json fails
// the WHOLE document on a single type mismatch, so one numeric "type" or
// non-string "message" alongside a real error object made Go report the frame
// as ordinary content while TS still saw the error. Decoding member-by-member
// keeps the two lenient in the same way.
func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// StreamErrorMessage returns the operator/upstream error message when
// plaintext is an error envelope in either wire shape, else ("", false):
//
//   - chat completions: {"error": {...}} with no "choices"
//   - /v1/responses:    {"type":"error", "code": …, "message": …} — the
//     Responses event union's error member, which carries no top-level
//     "error" key at all
//
// Shape-sniffing rather than api-dispatched on purpose: it is also the
// classifier for non-stream bodies and pre-envelope error bodies, which use
// the chat shape on both endpoints. The two shapes are disjoint, so accepting
// either costs nothing and removes a way to hold it wrong.
//
// Split out from ClassifyStreamFrame because the reference proxy logs the
// message on a frame it has already classified, and re-parsing to get it back
// would be wasteful.
func StreamErrorMessage(plaintext []byte) (string, bool) {
	// Cheap prefilter. `"error"` appears as the key in the chat shape and as
	// the *value* of "type" in the Responses shape, so one substring covers
	// both.
	if !bytes.Contains(plaintext, []byte(`"error"`)) {
		return "", false
	}
	// Raw members, not a typed probe struct — see rawString for why the typed
	// version diverged from the TS mirror in the unsafe direction.
	var top map[string]json.RawMessage
	if json.Unmarshal(plaintext, &top) != nil {
		return "", false
	}
	// Responses-API error event. `type` is the union discriminator, so an exact
	// "error" match cannot collide with a content event — the terminal failure
	// events are typed response.failed / response.incomplete and nest their
	// error object under "response", not at the top level.
	if rawString(top["type"]) == "error" {
		if msg := rawString(top["message"]); msg != "" {
			return msg, true
		}
		return "error", true
	}
	// An error envelope has a non-null "error" object and no "choices" — a real
	// chunk/response carries choices (the usage-only chunk carries "choices":[],
	// so a present-but-empty choices is still not an error).
	errRaw, hasError := top["error"]
	if !hasError || len(errRaw) == 0 || string(bytes.TrimSpace(errRaw)) == "null" {
		return "", false
	}
	if _, hasChoices := top["choices"]; hasChoices {
		return "", false
	}
	var errObj map[string]json.RawMessage
	if json.Unmarshal(errRaw, &errObj) == nil {
		if msg := rawString(errObj["message"]); msg != "" {
			return msg, true
		}
	}
	// Object present but no string message (e.g. nested/odd shape) — surface
	// the error object itself so the operator still sees the cause. Compacted
	// rather than echoed raw, because the TS mirror can only produce this via
	// JSON.stringify(JSON.parse(…)), which is whitespace-free; both preserve
	// the wire's key order (Go re-emits the same bytes, JS preserves insertion
	// order), so compaction gets the two to agree on the shapes that actually
	// occur — and the vectors pin that.
	//
	// It does NOT make them byte-identical in general: Go echoes the wire's
	// number and escape spelling while a JSON.parse/stringify round-trip
	// renormalizes both (`1e3` → `1000`, `é` → `é`). That residue is
	// accepted, not overlooked. Message is a log/display string on both sides;
	// Terminal and Error are the cross-implementation guarantees, and neither
	// depends on this branch. Do not start deriving behavior from Message
	// without closing the gap first.
	var compact bytes.Buffer
	if json.Compact(&compact, errRaw) != nil {
		return string(errRaw), true
	}
	return compact.String(), true
}
