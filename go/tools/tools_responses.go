/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// RewriteBuiltinToolsResponses walks body.tools[] and replaces every
// {"type":"zs_*"} entry with the Responses-flavor function tool shape:
// {"type":"function","name":"<name>","description":"...","parameters":{...}}.
//
// This is the node-side enforcement point of the SPEC §3d contract: the
// client's opt-in payload is the bare {"type":"zs_*"}, and this
// rewriter is the single place name/description/parameters are populated
// from the node's authoritative registry (defs). Anything the client may
// have set on the entry beyond `type` is implicitly dropped because each
// matching entry is replaced wholesale, not merged.
//
// The function-tool shape differs from Chat Completions — Responses hoists
// name/description/parameters to the top level rather than nesting them
// under a `function` key. Otherwise the rewriter mirrors the chat variant:
// unknown zs_* types error, non-hayai entries pass through, and the
// return value is byte-identical to the input when no rewrite is needed.
func RewriteBuiltinToolsResponses(body []byte, defs map[BuiltinToolType]BuiltinToolDef) (rewritten []byte, builtinNames map[string]BuiltinToolType, err error) {
	return rewriteBuiltinTools(body, defs, marshalResponsesFunctionTool)
}

func marshalResponsesFunctionTool(def BuiltinToolDef) (json.RawMessage, error) {
	obj := map[string]json.RawMessage{
		"type": json.RawMessage(`"function"`),
	}
	nameJSON, err := json.Marshal(def.Name)
	if err != nil {
		return nil, err
	}
	obj["name"] = nameJSON
	if def.Description != "" {
		descJSON, err := json.Marshal(def.Description)
		if err != nil {
			return nil, err
		}
		obj["description"] = descJSON
	}
	if len(def.Parameters) > 0 {
		obj["parameters"] = def.Parameters
	}
	return json.Marshal(obj)
}

// ExtractToolCallsResponses parses a non-streaming /v1/responses body,
// returns the raw output[] items (byte-exact for re-append), the
// function_call items as ToolCall entries, and the response status.
//
// A Responses-API body can carry many output items — message items,
// function_call items, reasoning items, and so on. The tool loop only
// cares about function_call items; the rest are forwarded verbatim in
// assistantItems so the next iteration's input[] preserves the full
// assistant turn.
func ExtractToolCallsResponses(resp []byte) (assistantItems []json.RawMessage, calls []ToolCall, status string, err error) {
	var top struct {
		Output []json.RawMessage `json:"output"`
		Status string            `json:"status"`
	}
	if err := json.Unmarshal(resp, &top); err != nil {
		return nil, nil, "", fmt.Errorf("parse responses body: %w", err)
	}
	for _, item := range top.Output {
		var typed struct {
			Type      string `json:"type"`
			CallID    string `json:"call_id"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}
		if err := json.Unmarshal(item, &typed); err == nil && typed.Type == "function_call" {
			// Extra (extra_content) is intentionally omitted: the raw item is
			// appended to assistantItems verbatim below and re-appended
			// byte-exact (AppendFunctionCallOutputsResponses), so any opaque
			// per-call state is already preserved. These ToolCalls are used
			// only for dispatch.
			calls = append(calls, ToolCall{
				ID:        typed.CallID,
				Name:      typed.Name,
				Arguments: typed.Arguments,
			})
		}
		assistantItems = append(assistantItems, item)
	}
	return assistantItems, calls, top.Status, nil
}

// SanitizeIncompleteBuiltinCallsResponses removes built-in function_call
// output items that cannot be dispatched as written — see
// CompleteToolArguments for the two defects and what `truncated` governs.
// Client-defined calls, non-call output items, and complete built-in calls are
// preserved byte-for-byte inside output[].
//
// Callers should re-run ExtractToolCallsResponses on the returned body before
// dispatch and replay so a dropped call cannot leave an orphaned
// function_call_output in the next request.
func SanitizeIncompleteBuiltinCallsResponses(resp []byte, builtinNames map[string]BuiltinToolType, truncated bool) (rewritten []byte, dropped int, err error) {
	if len(resp) == 0 || len(builtinNames) == 0 {
		return resp, 0, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &obj); err != nil {
		return nil, 0, fmt.Errorf("parse responses body: %w", err)
	}
	dropped, err = sanitizeResponsesOutputMap(obj, builtinNames, truncated)
	if err != nil {
		return nil, 0, err
	}
	if dropped == 0 {
		return resp, 0, nil
	}
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal responses body: %w", err)
	}
	return out, dropped, nil
}

// SanitizeIncompleteBuiltinCallsResponsesEvent is the STREAMING twin, for a
// terminal event (`response.completed` / `.incomplete` / `.failed`) whose
// nested `response` carries the round's full output snapshot.
//
// It exists because that snapshot is a second, easily-missed way a built-in
// call reaches the client. The per-item `response.output_item.added` frame for
// a zs_* call is classified FrameToolCallBuiltin and never written — but the
// terminal repeats the same call inside `response.output`, and a Responses
// client reads a `function_call` there as one IT must execute and answer with
// a `function_call_output`. For a node built-in there is nothing it can do.
//
// Only `response.output` is rewritten; `status`, `usage` and
// `incomplete_details` are untouched, because the round's outcome is
// legitimate — it is only the un-dispatched call that must not be advertised.
func SanitizeIncompleteBuiltinCallsResponsesEvent(frame []byte, builtinNames map[string]BuiltinToolType, truncated bool) (rewritten []byte, dropped int, err error) {
	if len(frame) == 0 || len(builtinNames) == 0 {
		return frame, 0, nil
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(frame, &event); err != nil {
		return nil, 0, fmt.Errorf("parse responses event: %w", err)
	}
	rawResponse, ok := event["response"]
	if !ok {
		return frame, 0, nil
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rawResponse, &resp); err != nil {
		return nil, 0, fmt.Errorf("parse responses event body: %w", err)
	}
	dropped, err = sanitizeResponsesOutputMap(resp, builtinNames, truncated)
	if err != nil {
		return nil, 0, err
	}
	if dropped == 0 {
		return frame, 0, nil
	}
	encodedResponse, err := json.Marshal(resp)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal responses event body: %w", err)
	}
	event["response"] = encodedResponse
	out, err := json.Marshal(event)
	if err != nil {
		return nil, 0, fmt.Errorf("remarshal responses event: %w", err)
	}
	return out, dropped, nil
}

// sanitizeResponsesOutputMap rewrites obj["output"] in place, dropping the
// built-in function_call items that cannot be dispatched. Shared so the
// body-level and terminal-event helpers can never disagree about what an
// undispatchable call is.
func sanitizeResponsesOutputMap(obj map[string]json.RawMessage, builtinNames map[string]BuiltinToolType, truncated bool) (dropped int, err error) {
	rawOutput, ok := obj["output"]
	if !ok {
		return 0, nil
	}
	var output []json.RawMessage
	if err := json.Unmarshal(rawOutput, &output); err != nil {
		return 0, fmt.Errorf("parse responses output: %w", err)
	}
	kept := make([]json.RawMessage, 0, len(output))
	for _, item := range output {
		var shaped struct {
			Type      string `json:"type"`
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		}
		if json.Unmarshal(item, &shaped) == nil && shaped.Type == "function_call" {
			if _, builtin := builtinNames[shaped.Name]; builtin && !CompleteToolArguments(shaped.Arguments, truncated) {
				dropped++
				continue
			}
		}
		kept = append(kept, item)
	}
	if dropped == 0 {
		return 0, nil
	}
	encodedOutput, err := json.Marshal(kept)
	if err != nil {
		return 0, fmt.Errorf("remarshal responses output: %w", err)
	}
	obj["output"] = encodedOutput
	return dropped, nil
}

// AppendFunctionCallOutputsResponses takes a /v1/responses request body,
// appends the assistant output[] items onto input[] verbatim, then
// appends one {"type":"function_call_output","call_id":X,"output":Y}
// entry per result. Returns the rewritten body for the next upstream call.
//
// Responses mutates input[] rather than messages[]; the shape is a
// mixed list of role-tagged messages, function_call items, and
// function_call_output items.
func AppendFunctionCallOutputsResponses(body []byte, assistantItems []json.RawMessage, results []ToolResult) ([]byte, error) {
	// The image variant with no attachments IS this function — its
	// per-result image block is skipped entirely when attachments is nil.
	// Written as a delegation rather than a copy because the two bodies had
	// already been maintained side by side, line for line, with only the
	// image block differing.
	return AppendImageToolOutputsResponses(body, assistantItems, results, nil)
}

// ImageToolFeedbackNote is the framing text prepended (as an input_text
// content part) to the synthetic user message that carries an image-tool
// result back to the model. Without it, models read a bare input_image
// user turn as a fresh upload from the human — they can't tell the image
// is the result of the tool THEY just called, nor that it was already
// shown to the user, so they ask "what would you like me to do with this
// image?" instead of responding naturally. The note is phrased as an
// out-of-band system note inside the user turn (the only role that
// reliably carries images across providers and the responses→chat shim).
const ImageToolFeedbackNote = "[Automated note — this is NOT a message from the user] " +
	"The image below was just produced by the image tool you called, and it has " +
	"already been displayed to the user. Do not treat it as a new upload or ask the " +
	"user to describe it. Respond naturally about the image (a brief caption is plenty), " +
	"then wait for the user's next instruction — only call an image tool again if the " +
	"user explicitly asks for another image or a change."

// AppendImageToolOutputsResponses is the image-tool variant of
// AppendFunctionCallOutputsResponses. Like the base helper it
// appends the assistant output[] items verbatim and one
// {"type":"function_call_output","call_id":X,"output":Y} per result, but
// for any result that produced images it ALSO appends a synthetic user
// message carrying a framing note + each image as content parts:
//
//	{"type":"message","role":"user","content":[
//	  {"type":"input_text","text":"<ImageToolFeedbackNote>"},
//	  {"type":"input_image","image_url":"data:image/png;base64,<b64>","detail":"auto"}]}
//
// so the next upstream turn can see (and edit / describe) the image the
// tool just produced AND understands it's the tool's own result, already
// shown to the user. The function_call_output.output stays a short JSON
// status STRING — `output` is reliably a string across providers, and
// the image rides as a separate input item, which every Responses
// implementation accepts.
//
// attachments is parallel to results: attachments[i] holds the images
// result i produced (nil/empty for non-image tools, in which case this
// behaves exactly like AppendFunctionCallOutputsResponses). A nil or
// short attachments slice is tolerated — a missing index is treated as
// "no images".
func AppendImageToolOutputsResponses(body []byte, assistantItems []json.RawMessage, results []ToolResult, attachments [][]ImageAttachment) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil, fmt.Errorf("parse body: %w", err)
	}
	var input []json.RawMessage
	if raw, ok := obj["input"]; ok {
		if err := json.Unmarshal(raw, &input); err != nil {
			var s string
			if err2 := json.Unmarshal(raw, &s); err2 == nil {
				msgObj := map[string]json.RawMessage{
					"role":    json.RawMessage(`"user"`),
					"content": mustMarshal(s),
				}
				encoded, _ := json.Marshal(msgObj)
				input = []json.RawMessage{encoded}
			} else {
				return nil, fmt.Errorf("parse input: %w", err)
			}
		}
	}
	input = append(input, assistantItems...)
	for i, r := range results {
		item := map[string]json.RawMessage{
			"type": json.RawMessage(`"function_call_output"`),
		}
		idJSON, err := json.Marshal(r.ToolCallID)
		if err != nil {
			return nil, err
		}
		item["call_id"] = idJSON
		outJSON, err := json.Marshal(r.Content)
		if err != nil {
			return nil, err
		}
		item["output"] = outJSON
		encoded, err := json.Marshal(item)
		if err != nil {
			return nil, err
		}
		input = append(input, encoded)

		if i >= len(attachments) || len(attachments[i]) == 0 {
			continue
		}
		imgParts := make([]json.RawMessage, 0, len(attachments[i]))
		for _, att := range attachments[i] {
			if att.B64 == "" {
				continue
			}
			mime := att.MIME
			if mime == "" {
				mime = "image/png"
			}
			part := map[string]json.RawMessage{
				"type":      json.RawMessage(`"input_image"`),
				"image_url": mustMarshal("data:" + mime + ";base64," + att.B64),
				// `detail` is optional on the live OpenAI REST API (defaults to
				// "auto") but `Required` on the SDK's ResponseInputImageParam
				// TypedDict — and vLLM-served /v1/responses backends validate
				// input items against those Pydantic models, rejecting an
				// input_image without it. Omitting it cascades into a pile of
				// union-member validation errors (the opaque "N validation
				// errors … {'loc': ('body','input','str')…}" 400 seen on the
				// post-image-tool continuation). Emit "auto" explicitly.
				"detail": json.RawMessage(`"auto"`),
			}
			pj, err := json.Marshal(part)
			if err != nil {
				return nil, err
			}
			imgParts = append(imgParts, pj)
		}
		if len(imgParts) == 0 {
			continue
		}
		// Lead with the framing note so the model knows this image is the
		// result of its own tool call and is already shown to the user.
		framePart, err := json.Marshal(map[string]json.RawMessage{
			"type": json.RawMessage(`"input_text"`),
			"text": mustMarshal(ImageToolFeedbackNote),
		})
		if err != nil {
			return nil, err
		}
		content := make([]json.RawMessage, 0, len(imgParts)+1)
		content = append(content, framePart)
		content = append(content, imgParts...)
		msg := map[string]json.RawMessage{
			"type":    json.RawMessage(`"message"`),
			"role":    json.RawMessage(`"user"`),
			"content": mustMarshal(content),
		}
		mj, err := json.Marshal(msg)
		if err != nil {
			return nil, err
		}
		input = append(input, mj)
	}
	newInput, err := json.Marshal(input)
	if err != nil {
		return nil, fmt.Errorf("remarshal input: %w", err)
	}
	obj["input"] = newInput
	return json.Marshal(obj)
}

// LatestResponsesInputImage scans a /v1/responses request body's input[]
// for the most recent input_image content part and returns its image_url
// (a `data:` URL or http(s) URL). The zs_image_edit tool uses this to
// resolve "edit the image we're already looking at" when the model calls
// it without supplying an image — covering both an image fed back earlier
// in the same tool loop and one a client carried forward from a prior turn
// (so "generate a corgi" then, next turn, "give it a blue hat" works). It
// walks items newest-first and, within an item, parts newest-first.
// ok=false when input[] has no input_image (or input is a bare string).
func LatestResponsesInputImage(body []byte) (imageURL string, ok bool) {
	var obj struct {
		Input json.RawMessage `json:"input"`
	}
	if err := json.Unmarshal(body, &obj); err != nil || len(obj.Input) == 0 {
		return "", false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(obj.Input, &items); err != nil {
		return "", false // string input carries no image
	}
	for i := len(items) - 1; i >= 0; i-- {
		var item struct {
			Content json.RawMessage `json:"content"`
		}
		if err := json.Unmarshal(items[i], &item); err != nil {
			continue
		}
		// content is either a bare string (no image) or an array of parts.
		if len(item.Content) == 0 || item.Content[0] != '[' {
			continue
		}
		var parts []struct {
			Type     string          `json:"type"`
			ImageURL json.RawMessage `json:"image_url"`
		}
		if err := json.Unmarshal(item.Content, &parts); err != nil {
			continue
		}
		for j := len(parts) - 1; j >= 0; j-- {
			if parts[j].Type != "input_image" {
				continue
			}
			if url := imageURLFromRaw(parts[j].ImageURL); url != "" {
				return url, true
			}
		}
	}
	return "", false
}

// imageURLFromRaw extracts the URL from an input_image's image_url field,
// which is a bare string on the Responses API ("data:…" / "https://…") but
// an object {"url":"…"} on the Chat Completions shape — tolerate both.
func imageURLFromRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			return s
		}
		return ""
	}
	var o struct {
		URL string `json:"url"`
	}
	if json.Unmarshal(raw, &o) == nil {
		return o.URL
	}
	return ""
}

// ClampResponsesInputImages caps the number of input_image content parts a
// /v1/responses request body's input[] carries to at most max, removing the
// OLDEST images first so the most recent one — a freshly tool-produced image,
// or the latest user upload — is always retained.
//
// It exists because the Responses tool loop feeds tool-produced images back
// into the same input[] that already holds the user's uploads (see
// AppendImageToolOutputsResponses). A vision upstream caps images per prompt
// (vLLM's limit_mm_per_prompt — "At most N image(s) may be provided in one
// prompt."), so the accumulated count can overflow that cap mid-loop and 400.
//
// max <= 0 means "no cap": body is returned byte-for-byte unchanged. The body
// is likewise returned unchanged when it already fits, when input[] is absent,
// or when input[] is a bare string (which carries no image). dropped reports
// how many input_image parts were removed.
//
// When an image is dropped, its sibling parts (a user message's input_text, the
// tool-feedback framing note) are preserved; a message whose content becomes
// empty after the drop is removed entirely so no empty-content item reaches the
// upstream's input validator.
func ClampResponsesInputImages(body []byte, max int) (out []byte, dropped int, err error) {
	// allTurnsEligible: this side has no structural adjacency to protect, so
	// every input[] item may be shed from. If that ever gains a restriction,
	// swap the predicate — the shared clamp already reports what it actually
	// shed rather than the surplus, so the node's dropped > 0 retry gate stays
	// honest without a second edit.
	return clampInputImages(body, max, "input", "input_image", allTurnsEligible)
}

// contentPartType reads the "type" of a single content part, "" on malformed
// JSON. Single source of truth for the part-type literal (input_image on
// Responses, image_url on Chat) across the count and drop passes in both this
// file and tools_chat.go.
func contentPartType(part json.RawMessage) string {
	var p struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(part, &p) != nil {
		return ""
	}
	return p.Type
}

func mustMarshal(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// SetResponsesUsage rewrites the `usage` field on a non-streaming
// /v1/responses body so it reports aggregate totals across every
// tool-loop iteration. Uses Responses-API field names (input_tokens,
// output_tokens, total_tokens).
func SetResponsesUsage(resp []byte, input, output, cached uint64) []byte {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(resp, &obj); err != nil {
		return resp
	}
	usage := map[string]any{
		"input_tokens":  input,
		"output_tokens": output,
		"total_tokens":  input + output,
	}
	if cached > 0 {
		usage["input_tokens_details"] = map[string]uint64{"cached_tokens": cached}
	}
	b, err := json.Marshal(usage)
	if err != nil {
		return resp
	}
	obj["usage"] = b
	out, err := json.Marshal(obj)
	if err != nil {
		return resp
	}
	return out
}

// ResponsesToolCallStitcher stitches streaming /v1/responses events into
// a coherent list of function_call items, plus whatever output_text
// content appeared, while classifying each frame for the tool loop.
//
// The Responses API is event-typed rather than delta-typed: the stream
// emits `response.output_item.added`, `response.output_text.delta`,
// `response.function_call_arguments.delta`, `response.output_item.done`,
// `response.completed`, and a handful of error variants. The stitcher
// tracks items by `item_id` and assembles function_call arguments as
// they stream.
// One entry per item, reached only through entryFor: items holds the state and
// order holds the sequence, and the two are written together in one place.
// They used to be joined by a third map of raw item bytes plus a per-entry copy
// of the same bytes, get-or-created at five call sites; the per-entry copy was
// never read and had already fallen out of step with the map on the terminal
// path, and any one of the five sites forgetting its order append would drop
// the item from both ToolCalls() and OutputItems() silently.
type ResponsesToolCallStitcher struct {
	items       map[string]*responsesStitchEntry
	order       []string
	contentBuf  bytes.Buffer
	status      string
	usage       ResponsesUsage
	sawTerminal bool
	// messageItemID / messageOutputIndex / hasMessageItem track the
	// currently-open assistant message item — set on a
	// response.output_item.added event whose item.type=="message". The
	// streaming tool loop uses CurrentMessageItem() at the FrameContent
	// transition to anchor synthetic annotation frames to the right item.
	messageItemID      string
	messageOutputIndex int
	hasMessageItem     bool
	// builtinNames is the map from function name to hayai built-in type,
	// as populated by RewriteBuiltinToolsResponses. The stitcher uses
	// it to classify each tool-call frame as FrameToolCallBuiltin or
	// FrameToolCallClient so the streaming tool loop can suppress or
	// forward the frame accordingly. nil / empty map means "no hayai
	// tools registered" — every tool call is classified as client.
	builtinNames map[string]BuiltinToolType
}

type responsesStitchEntry struct {
	ItemID   string
	CallID   string
	Name     string
	ArgsBuf  bytes.Buffer
	ItemType string
	// Raw is the verbatim item object as the upstream emitted it, latest
	// wins: output_item.added, then output_item.done, then the terminal
	// response.completed overlay. OutputItems re-appends it byte-exact and
	// only synthesizes when it is absent.
	//
	// The terminal overlay updates ONLY this, never the stitched
	// Name/CallID/ArgsBuf. That asymmetry is load-bearing: replay uses the
	// terminal copy, dispatch uses the stitched one.
	Raw json.RawMessage
	// Extra is the verbatim `extra_content` object from the function_call
	// item — provider-opaque per-call state (Gemini's thought_signature)
	// the upstream requires echoed back. The raw-item re-append path
	// (OutputItems) preserves it byte-exact already; this is captured only
	// so the synthesize fallback (no raw item) can replay it too.
	Extra json.RawMessage
}

// NewResponsesToolCallStitcher returns a ready-to-use stitcher.
// builtinNames is the name→type map from RewriteBuiltinToolsResponses;
// pass nil or an empty map when no hayai built-ins are registered and
// every tool call should be treated as client-defined.
func NewResponsesToolCallStitcher(builtinNames map[string]BuiltinToolType) *ResponsesToolCallStitcher {
	return &ResponsesToolCallStitcher{
		items:        map[string]*responsesStitchEntry{},
		builtinNames: builtinNames,
	}
}

// entryFor returns the entry for key, creating it — and appending key to the
// order — on first sight. Every event handler goes through here: the order
// append is what puts an item in ToolCalls() and OutputItems() at all, and it
// is not something a handler should be able to forget.
//
// itemType seeds ItemType on creation only. An existing entry keeps whatever
// type it already carries; handlers that have authoritative type information
// overwrite it themselves, under their own rules.
func (s *ResponsesToolCallStitcher) entryFor(key, itemType string) *responsesStitchEntry {
	if entry, ok := s.items[key]; ok {
		return entry
	}
	entry := &responsesStitchEntry{ItemID: key, ItemType: itemType}
	s.items[key] = entry
	s.order = append(s.order, key)
	return entry
}

// classifyToolCall returns FrameToolCallBuiltin when name is a known hayai
// built-in and FrameToolCallClient otherwise. The decision is made per
// tool call (by function name), so a response that mixes a hayai and a
// client-defined call into one iteration gets each fragment classified
// on its own merits.
func (s *ResponsesToolCallStitcher) classifyToolCall(name string) FrameClassification {
	if name == "" {
		// Name hasn't been observed yet. The Responses API spec says
		// output_item.added carries the function name, but llama.cpp /
		// some Qwen tool-call modes delay the name until a later event
		// (output_item.done or the completed overlay). Classifying as
		// FrameToolCallClient in that window would forward hayai tool
		// fragments to the wire before we know they're hayai. Return
		// FrameUnknown so the tool-loop buffers the fragment — once the
		// name resolves, subsequent frames classify authoritatively and
		// the buffered head is either discarded (hayai) or flushed at
		// iteration end (legitimate client tool).
		return FrameUnknown
	}
	if _, ok := s.builtinNames[name]; ok {
		return FrameToolCallBuiltin
	}
	// Defense-in-depth: the `zs_` prefix is a reserved namespace for
	// node-owned transport tools (see IsBuiltinToolType). Any call with
	// that prefix MUST NOT reach the client — if the rewriter was
	// skipped or the names map is stale, suppressing still preserves the
	// wire invariant. The internal tool loop will surface an
	// unknown_builtin_tool error when it tries to dispatch.
	if IsBuiltinToolType(name) {
		return FrameToolCallBuiltin
	}
	return FrameToolCallClient
}

// Observe feeds one SSE data payload (minus the `data:` prefix) into
// the stitcher and returns the classification for the tool loop.
//
// Events we care about and the classification they produce:
//
//   - response.output_item.added  (item.type == "function_call")  → FrameToolCallBuiltin or FrameToolCallClient
//   - response.output_item.added  (item.type == "message")         → FrameUnknown
//   - response.output_text.delta                                   → FrameContent
//   - response.function_call_arguments.delta                       → FrameToolCallBuiltin or FrameToolCallClient
//   - response.function_call_arguments.done                        → FrameToolCallBuiltin or FrameToolCallClient
//   - response.output_item.done                                    → FrameUnknown
//   - response.completed                                           → FrameTerminal (with usage)
//   - response.error / response.failed / response.incomplete       → FrameTerminal
//   - response.zs_tool_call.in_progress / .completed            → FrameStatus
//   - everything else                                              → FrameUnknown
//
// Tool-call frames are split by whether the function name is a hayai
// built-in (suppress from wire, execute server-side) or a client-
// defined function (forward to wire, client executes). See
// classifyToolCall for how the split is decided.
func (s *ResponsesToolCallStitcher) Observe(frame []byte) FrameClassification {
	trimmed := bytes.TrimSpace(frame)
	if len(trimmed) == 0 {
		return FrameUnknown
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(trimmed, &envelope); err != nil {
		return FrameUnknown
	}
	switch envelope.Type {
	case "response.output_item.added":
		var ev struct {
			OutputIndex int `json:"output_index"`
			Item        struct {
				ID           string          `json:"id"`
				Type         string          `json:"type"`
				CallID       string          `json:"call_id"`
				Name         string          `json:"name"`
				Arguments    string          `json:"arguments"`
				ExtraContent json.RawMessage `json:"extra_content"`
				Raw          json.RawMessage `json:"-"`
			} `json:"item"`
		}
		var raw struct {
			Item json.RawMessage `json:"item"`
		}
		if err := json.Unmarshal(trimmed, &ev); err != nil {
			return FrameUnknown
		}
		_ = json.Unmarshal(trimmed, &raw)
		if ev.Item.Type == "message" && ev.Item.ID != "" {
			// Capture the open assistant message — the streaming tool
			// loop anchors synthetic annotation frames to this item.
			// output_index is whatever upstream emitted; some test
			// fixtures omit it, in which case 0 is the safe default
			// (single-message responses are by far the common case).
			s.messageItemID = ev.Item.ID
			s.messageOutputIndex = ev.OutputIndex
			s.hasMessageItem = true
		}
		// llama.cpp omits the `id` field on function_call items and only
		// publishes `call_id`. Fall back to call_id as the stitch key so
		// the subsequent arguments.delta events (whose item_id matches
		// this call_id) correlate to the same entry.
		itemKey := ev.Item.ID
		if itemKey == "" {
			itemKey = ev.Item.CallID
		}
		if itemKey == "" {
			return FrameUnknown
		}
		entry := s.entryFor(itemKey, "")
		entry.ItemType = ev.Item.Type
		if ev.Item.CallID != "" {
			entry.CallID = ev.Item.CallID
		}
		if ev.Item.Name != "" {
			entry.Name = ev.Item.Name
		}
		if ev.Item.Arguments != "" {
			entry.ArgsBuf.Reset()
			entry.ArgsBuf.WriteString(ev.Item.Arguments)
		}
		if len(entry.Extra) == 0 && len(ev.Item.ExtraContent) > 0 {
			entry.Extra = ev.Item.ExtraContent
		}
		if len(raw.Item) > 0 {
			entry.Raw = raw.Item
		}
		if ev.Item.Type == "function_call" {
			return s.classifyToolCall(entry.Name)
		}
		return FrameUnknown

	case "response.output_text.delta":
		var ev struct {
			Delta string `json:"delta"`
		}
		if err := json.Unmarshal(trimmed, &ev); err == nil && ev.Delta != "" {
			s.contentBuf.WriteString(ev.Delta)
		}
		return FrameContent

	case "response.function_call_arguments.delta":
		var ev struct {
			ItemID string `json:"item_id"`
			Delta  string `json:"delta"`
		}
		if err := json.Unmarshal(trimmed, &ev); err != nil {
			return FrameUnknown
		}
		// Seeded "function_call" because some backends skip output_item.added
		// entirely and this is the first sight of the item.
		entry := s.entryFor(ev.ItemID, "function_call")
		if ev.Delta != "" {
			entry.ArgsBuf.WriteString(ev.Delta)
		}
		return s.classifyToolCall(entry.Name)

	case "response.function_call_arguments.done":
		var ev struct {
			ItemID    string `json:"item_id"`
			Arguments string `json:"arguments"`
		}
		if err := json.Unmarshal(trimmed, &ev); err != nil {
			return s.classifyToolCall("")
		}
		entry := s.entryFor(ev.ItemID, "function_call")
		// Prefer the authoritative final arguments string when upstream
		// provides one — some backends emit deltas AND the complete
		// arguments on the done event.
		if ev.Arguments != "" {
			entry.ArgsBuf.Reset()
			entry.ArgsBuf.WriteString(ev.Arguments)
		}
		return s.classifyToolCall(entry.Name)

	case "response.output_item.done":
		var ev struct {
			Item struct {
				ID           string          `json:"id"`
				Type         string          `json:"type"`
				CallID       string          `json:"call_id"`
				Name         string          `json:"name"`
				Arguments    string          `json:"arguments"`
				ExtraContent json.RawMessage `json:"extra_content"`
			} `json:"item"`
		}
		var raw struct {
			Item json.RawMessage `json:"item"`
		}
		isFunctionCall := false
		entryName := ""
		if err := json.Unmarshal(trimmed, &ev); err == nil {
			// Same id-vs-call_id fallback as output_item.added — llama.cpp
			// omits `id` on function_call items entirely.
			itemKey := ev.Item.ID
			if itemKey == "" {
				itemKey = ev.Item.CallID
			}
			if itemKey != "" {
				entry := s.entryFor(itemKey, ev.Item.Type)
				// The terminal frame is authoritative for item metadata.
				// llama.cpp emits output_item.added with an empty type/name
				// and only populates them here; without this update the
				// entry stays with an empty ItemType and ToolCalls() filters
				// it out, which drives iterations=0 even when a tool call
				// actually occurred.
				if ev.Item.Type != "" {
					entry.ItemType = ev.Item.Type
				}
				if ev.Item.CallID != "" {
					entry.CallID = ev.Item.CallID
				}
				if ev.Item.Name != "" {
					entry.Name = ev.Item.Name
				}
				if ev.Item.Arguments != "" {
					entry.ArgsBuf.Reset()
					entry.ArgsBuf.WriteString(ev.Item.Arguments)
				}
				if len(entry.Extra) == 0 && len(ev.Item.ExtraContent) > 0 {
					entry.Extra = ev.Item.ExtraContent
				}
				_ = json.Unmarshal(trimmed, &raw)
				if len(raw.Item) > 0 {
					entry.Raw = raw.Item
				}
				isFunctionCall = entry.ItemType == "function_call" || ev.Item.Type == "function_call"
				entryName = entry.Name
			}
		}
		// The terminal frame of a function_call item re-carries the full
		// item payload (name, call_id, arguments). Classifying it as
		// FrameUnknown leaks the tool-call metadata to the client after
		// the arguments.delta/done frames were already suppressed. Route
		// it through the same hayai-vs-client decision as the other
		// function_call frames.
		if isFunctionCall {
			return s.classifyToolCall(entryName)
		}
		return FrameUnknown

	case "response.completed":
		var ev struct {
			Response struct {
				Status string            `json:"status"`
				Usage  ResponsesUsage    `json:"usage"`
				Output []json.RawMessage `json:"output"`
			} `json:"response"`
		}
		if err := json.Unmarshal(trimmed, &ev); err == nil {
			s.status = ev.Response.Status
			s.usage = ev.Response.Usage
			s.overlayTerminalOutput(ev.Response.Output)
		}
		s.sawTerminal = true
		return FrameTerminal

	case "response.error", "response.failed", "response.incomplete":
		// Mirror the response.completed case: parse usage and overlay
		// any output items on the stitcher's rawItems. A request that
		// hit max_output_tokens (response.incomplete) or got part-way
		// before failing did real compute the operator should be billed
		// for; if we leave s.usage at zero the receipt path bills zero
		// and refunds the payer for work the operator actually performed.
		var ev struct {
			Response struct {
				Status string            `json:"status"`
				Usage  ResponsesUsage    `json:"usage"`
				Output []json.RawMessage `json:"output"`
			} `json:"response"`
		}
		if err := json.Unmarshal(trimmed, &ev); err == nil {
			s.status = ev.Response.Status
			s.usage = ev.Response.Usage
			s.overlayTerminalOutput(ev.Response.Output)
		}
		s.sawTerminal = true
		return FrameTerminal

	case "response.zs_tool_call.in_progress", "response.zs_tool_call.completed":
		return FrameStatus

	default:
		return FrameUnknown
	}
}

// overlayTerminalOutput folds the output[] items carried on a terminal
// event (response.completed / .failed / .incomplete) onto the stitched
// rawItems so the assistant re-append ordering stays authoritative. Some
// providers only emit the final form of an item on the terminal event.
//
// An id we already stitched from the streaming events gets its rawItem
// updated in place (same order slot) — the terminal copy is the
// authoritative final form.
//
// A NEW id we never saw streaming is kept ONLY when it is not a
// function_call. A function_call surfacing for the first time on the
// terminal event was never executed by the streaming tool loop
// (ToolCalls reads only entries stitched from streaming events, which set
// ItemType), so it has no function_call_output — re-appending it to the
// next input[] emits an orphan function_call the upstream rejects. This
// also de-dupes a backend that regenerates a tool call's id/call_id
// between its streaming events and response.completed (e.g. a
// chatcmpl-tool-* engine id leaking into the terminal event): without the
// skip the same call lands twice — once executed via the streamed id,
// once orphaned via the terminal id. Messages that only appear on the
// terminal event are still captured. A reasoning item that only appears on
// the terminal event is captured too, EXCEPT when a tool call was already
// stitched from streaming — see the reasoning skip in the loop body for why
// (a regenerated-id reasoning copy that would duplicate and mis-order).
func (s *ResponsesToolCallStitcher) overlayTerminalOutput(output []json.RawMessage) {
	// Did the streaming events already stitch a tool call? Computed once
	// before the loop (streaming is finished by the terminal event) and
	// gates the reasoning skip below.
	sawToolCall := false
	for _, e := range s.items {
		if e != nil && e.ItemType == "function_call" {
			sawToolCall = true
			break
		}
	}
	for _, raw := range output {
		var ident struct {
			ID   string `json:"id"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(raw, &ident); err != nil || ident.ID == "" {
			continue
		}
		if _, ok := s.items[ident.ID]; !ok {
			if ident.Type == "function_call" {
				continue
			}
			// A reasoning item surfacing for the first time on the terminal
			// event, AFTER tool calls were already stitched from streaming, is
			// a backend that regenerated the reasoning item's id between its
			// streaming event and response.completed (vLLM/Gemma emit the same
			// reasoning twice — streaming as e.g. a92c…, terminal as rs_…).
			// Appending it to the tail lands it after the function_call and its
			// eventual function_call_output, duplicating the reasoning and
			// corrupting the reasoning→call→output order the model expects,
			// which makes the model re-enter planning and loop. Skip it — the
			// streamed copy, correctly positioned before the call, is
			// authoritative. Mirrors the function_call regenerated-id skip
			// above. A matching id (the normal case) still updates in place.
			if ident.Type == "reasoning" && sawToolCall {
				continue
			}
		}
		// Updates ONLY Raw, never the stitched Name/CallID/ArgsBuf — see the
		// note on responsesStitchEntry.Raw for why that asymmetry is
		// deliberate. The get-or-create runs after the two skips above, which
		// is why this reaches entryFor rather than opening with it.
		s.entryFor(ident.ID, "").Raw = raw
	}
}

// Status returns the terminal status string from response.completed
// (e.g. "completed", "failed"). Empty until a terminal event is
// observed.
func (s *ResponsesToolCallStitcher) Status() string { return s.status }

// CurrentMessageItem returns the id and output_index of the assistant
// message item this stream has opened, plus ok=true once
// response.output_item.added(type=message) has been observed. The
// streaming tool loop calls this on its FrameContent transition to
// anchor synthetic response.output_text.annotation.added frames to the
// right item. Returns ok=false when no message item has opened yet —
// the caller should skip the annotation flush in that case.
func (s *ResponsesToolCallStitcher) CurrentMessageItem() (id string, outputIndex int, ok bool) {
	return s.messageItemID, s.messageOutputIndex, s.hasMessageItem
}

// Usage returns the aggregate usage reported by the terminal
// response.completed event. Zero values before the terminal event.
func (s *ResponsesToolCallStitcher) Usage() ResponsesUsage { return s.usage }

// Content returns the visible assistant text accumulated across this
// iteration's response.output_text.delta events. The tool loop reads it to
// detect native tool-call markup the upstream failed to parse into structured
// calls (see ScanLeakedToolCalls). This is the path a client on the Responses
// API takes, including under translate_responses_to_chat.
func (s *ResponsesToolCallStitcher) Content() string { return s.contentBuf.String() }

// ToolCalls returns every function_call item that appeared in the
// stream, in first-observed order.
func (s *ResponsesToolCallStitcher) ToolCalls() []ToolCall {
	out := make([]ToolCall, 0)
	for _, id := range s.order {
		e := s.items[id]
		if e == nil || e.ItemType != "function_call" {
			continue
		}
		out = append(out, ToolCall{
			ID:        e.CallID,
			Name:      e.Name,
			Arguments: e.ArgsBuf.String(),
			Extra:     e.Extra,
		})
	}
	return out
}

// OutputItems returns the raw assistant output items in the order they
// appeared, for byte-exact re-append to the next iteration's input[].
// For stream events where only a final state is available on
// response.completed, that version is used; otherwise the item from
// output_item.added is used. Non-final items are synthesized for
// function_call entries observed via arguments.delta only (rare; some
// backends skip the .added event).
func (s *ResponsesToolCallStitcher) OutputItems() []json.RawMessage {
	out := make([]json.RawMessage, 0, len(s.order))
	for _, id := range s.order {
		e := s.items[id]
		if e == nil {
			continue
		}
		if len(e.Raw) > 0 {
			out = append(out, e.Raw)
			continue
		}
		// Synthesize a function_call item from the stitched pieces. This
		// branch only triggers when a backend emitted
		// function_call_arguments.delta without a preceding
		// output_item.added — not typical, but we stay correct.
		if e.ItemType != "function_call" || e.CallID == "" || e.Name == "" {
			continue
		}
		synth := map[string]json.RawMessage{
			"type": json.RawMessage(`"function_call"`),
		}
		idJSON, _ := json.Marshal(e.ItemID)
		synth["id"] = idJSON
		callJSON, _ := json.Marshal(e.CallID)
		synth["call_id"] = callJSON
		nameJSON, _ := json.Marshal(e.Name)
		synth["name"] = nameJSON
		argsJSON, _ := json.Marshal(e.ArgsBuf.String())
		synth["arguments"] = argsJSON
		// Replay provider-opaque per-call state verbatim (e.g. Gemini's
		// thought_signature). The raw-item branch above preserves it
		// already; this fallback rebuilds from typed fields and would
		// otherwise drop it.
		if len(e.Extra) > 0 {
			synth["extra_content"] = e.Extra
		}
		enc, _ := json.Marshal(synth)
		out = append(out, enc)
	}
	return out
}
