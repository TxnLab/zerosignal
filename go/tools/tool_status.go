/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
)

// Hayai tool-round status event type strings. Emitted by the node
// during server-side execution of a hayai built-in tool so the client
// can render an "in progress" indicator during an otherwise silent
// tool round. Both events are sealed like any other streaming frame —
// they ride the `event: zs` SSE channel and increment the sealer's
// frame counter.
//
// Shape mirrors OpenAI's Responses-API built-in tool events (e.g.
// response.web_search_call.in_progress). Unknown Responses event types
// pass cleanly through openai-go's union-deserializer, so a client
// that doesn't know about hayai types still sees them as events it
// can ignore.
const (
	StatusEventToolCallInProgress = "response.zs_tool_call.in_progress"
	StatusEventToolCallCompleted  = "response.zs_tool_call.completed"
)

// StatusEventImageProgress is a sealed streaming event the node emits while
// a built-in image tool's generation/edit is still in flight, so the client
// can render a determinate progress bar in place of the indeterminate
// spinner. Like the tool-call status events above it rides the `event: zs`
// SSE channel, increments the sealer's frame counter, and is folded into the
// receipt body_hash — so it MUST be sealed + receipt-collected like any other
// data frame, never emitted plaintext (that would desync the proxy's frame
// index / body_hash). It carries only sampling-step counters — no prompt or
// image content. Emitted zero-or-more times between a call's in_progress and
// completed frames; its ItemID matches that pair so the client correlates the
// progress with the right placeholder. A client that doesn't know the type
// sees an event it can ignore.
const StatusEventImageProgress = "response.zs_image.progress"

// StatusEventImagePartial is a sealed streaming event carrying an intermediate
// (latent-preview) render frame for an in-flight built-in image tool, so the
// client can show the image resolving as it generates. Unlike the numeric
// progress event this carries image CONTENT (base64), so — like every other
// content frame — it MUST be sealed and folded into the receipt body_hash,
// never emitted plaintext (a relay must not read a partial render). ItemID
// matches the owning call's in_progress/completed status pair. Emitted
// zero-or-more times (operator-throttled); an unaware client ignores it.
const StatusEventImagePartial = "response.zs_image.partial"

// ToolCallStatusFrame is the plaintext payload inside a sealed hayai
// status SSE frame. The outer wire frame is `event: zs\ndata:
// <sealed JSON>\n\n` per SPEC.md §5.3; this struct is the JSON
// unmarshal target for the sealed plaintext.
//
// Action (optional) says what the round is doing — the search query, the
// page URL, the sources found — so a client can render "Searching for X"
// and list results instead of a bare "Searching the web". Its shape
// mirrors OpenAI's web_search_call.action; see tool_action.go. It is
// absent whenever the tool has nothing to show, the arguments didn't
// parse, or the value is not yet safe to advertise (zs_web_read before
// its provenance gate has run).
type ToolCallStatusFrame struct {
	Type        string      `json:"type"`
	ItemID      string      `json:"item_id"`
	OutputIndex int         `json:"output_index"`
	Tool        string      `json:"tool"`
	CallID      string      `json:"call_id,omitempty"`
	Action      *ToolAction `json:"action,omitempty"`
}

// NewStatusItemID returns a fresh opaque identifier for a ZeroSignal
// tool-round status event. Prefix chosen so a debugger grepping SSE
// logs can immediately tell it from OpenAI's built-in tool item IDs
// (which look like `ws_...`, `fs_...`, etc.).
func NewStatusItemID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "zstc_" + hex.EncodeToString(b[:])
}

// MarshalToolCallStatus produces the sealable plaintext JSON for one
// status event. Centralised here so node emitters and any client-side
// parsers agree on the exact shape without copy-pasting keys.
func MarshalToolCallStatus(eventType, itemID, tool, callID string, outputIndex int) ([]byte, error) {
	return MarshalToolCallStatusWithAction(eventType, itemID, tool, callID, outputIndex, nil)
}

// MarshalToolCallStatusWithAction is MarshalToolCallStatus plus the
// optional action describing what the round is doing. A nil action
// marshals byte-identically to MarshalToolCallStatus, so a tool with
// nothing to show — and any peer built before actions existed — sees the
// original shape.
func MarshalToolCallStatusWithAction(eventType, itemID, tool, callID string, outputIndex int, action *ToolAction) ([]byte, error) {
	frame := ToolCallStatusFrame{
		Type:        eventType,
		ItemID:      itemID,
		OutputIndex: outputIndex,
		Tool:        tool,
		CallID:      callID,
		Action:      action,
	}
	return json.Marshal(frame)
}

// ImageProgressFrame is the plaintext payload inside a sealed image-progress
// SSE frame (see StatusEventImageProgress). Value/Max are the current stage's
// sampling-step counter (e.g. 12 of 20); a client renders Value/Max as a
// percentage. Node is the backend's stage label (e.g. a ComfyUI node id /
// class) — advisory, omitted when empty. ItemID correlates the frame with
// the owning call's in_progress/completed status pair.
type ImageProgressFrame struct {
	Type   string `json:"type"`
	ItemID string `json:"item_id"`
	Value  int    `json:"value"`
	Max    int    `json:"max"`
	Node   string `json:"node,omitempty"`
}

// MarshalImageProgress produces the sealable plaintext JSON for one
// image-progress event. Centralised here so the node emitter and any
// client-side parser agree on the exact shape without copy-pasting keys.
func MarshalImageProgress(itemID string, value, max int, node string) ([]byte, error) {
	frame := ImageProgressFrame{
		Type:   StatusEventImageProgress,
		ItemID: itemID,
		Value:  value,
		Max:    max,
		Node:   node,
	}
	return json.Marshal(frame)
}

// ImagePartialFrame is the plaintext payload inside a sealed image-partial
// frame (see StatusEventImagePartial). PartialImageB64 is base64-encoded
// image bytes (a low-res preview render); Mime is its content type
// (image/jpeg or image/png). The field name mirrors the forward-looking
// `partial_image_b64` the client diagnostics redactor already anticipates.
type ImagePartialFrame struct {
	Type            string `json:"type"`
	ItemID          string `json:"item_id"`
	PartialImageB64 string `json:"partial_image_b64"`
	Mime            string `json:"mime,omitempty"`
}

// MarshalImagePartial produces the sealable plaintext JSON for one
// image-partial (preview) event. Centralised here so the node emitter and any
// client-side parser agree on the exact shape without copy-pasting keys.
func MarshalImagePartial(itemID, partialImageB64, mime string) ([]byte, error) {
	frame := ImagePartialFrame{
		Type:            StatusEventImagePartial,
		ItemID:          itemID,
		PartialImageB64: partialImageB64,
		Mime:            mime,
	}
	return json.Marshal(frame)
}

// StatusEventImageCompleted is the terminal sealed frame of a streamed image
// response (the dedicated /v1/images/* routes under stream:true). It carries
// the final image payload — the same {created, data:[{b64_json,...}]} body the
// buffered route returns — so a client reading the stream recovers the exact
// result. Sealed + receipt-collected like every content frame. Emitted once,
// immediately before the zs-receipt frame + [DONE].
const StatusEventImageCompleted = "response.zs_image.completed"

// ImageCompletedFrame is the plaintext payload inside a sealed image-completed
// frame. Response is the buffered image JSON ({created, data:[...]}) verbatim,
// nested so a client parses frame.response the same way it parses today's
// buffered body. ItemID matches the stream's progress/partial frames.
type ImageCompletedFrame struct {
	Type     string          `json:"type"`
	ItemID   string          `json:"item_id"`
	Response json.RawMessage `json:"response"`
}

// MarshalImageCompleted wraps a buffered image response body into the terminal
// image-completed frame. response must be valid JSON ({created,data:[...]}).
func MarshalImageCompleted(itemID string, response []byte) ([]byte, error) {
	frame := ImageCompletedFrame{
		Type:     StatusEventImageCompleted,
		ItemID:   itemID,
		Response: json.RawMessage(response),
	}
	return json.Marshal(frame)
}
