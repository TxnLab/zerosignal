/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"encoding/json"
	"math"
	"regexp"
	"strings"
)

// decoder turns a node's decrypted frames into typed events. It reads the
// dialect the endpoint answers in: Responses API events on /v1/responses, Chat
// Completions chunks on /v1/chat/completions, and the image routes' zs_image
// events. Anything it does not model is left to the Frame that carried it.
//
// Every node frame is untrusted. A frame that does not parse yields no events
// rather than an error, and each field is read on its own, so one field of an
// unexpected type costs that field alone: the Frame still reaches the caller,
// and the receipt is what settles the charge.
type decoder struct {
	responses bool
	images    bool

	// finished is set by the node's sealed word that generation ended: a chat
	// finish_reason, a response.completed or response.incomplete, an image
	// route's completed event, or a whole reply. The plaintext [DONE] that
	// follows a stream is not authenticated, so it is not evidence.
	finished bool
	// answered is set by anything a caller would show as the answer: text
	// that is not blank, a refusal, a tool call, or an image. Reasoning is
	// not one.
	answered   bool
	finish     string
	incomplete string
	// failure is the first error the node reported inside its response.
	failure *Error

	// fnCalls maps a Responses function_call item to its call id and name,
	// which its argument deltas do not repeat.
	fnCalls map[string]fnCall
	// zsCalls maps a zs tool call's item to its call id and tool, which its
	// completed event does not repeat.
	zsCalls map[string]fnCall
	// chatCalls maps a chat tool call's index to its id and name, which only
	// its first chunk carries.
	chatCalls map[int]fnCall
}

type fnCall struct{ id, name string }

func newDecoder(endpoint string) *decoder {
	return &decoder{
		responses: endpoint == endpointResponses,
		images:    endpoint == endpointImages || endpoint == endpointImageEdits,
	}
}

// outcome is how the turn ends once its response is over: the error the node
// reported, else Done if the node said generation ended, else an interrupted
// turn, since nothing authenticated says the answer is whole.
func (d *decoder) outcome() (Done, *Error) {
	switch {
	case d.failure != nil:
		return Done{}, d.failure
	case d.finished:
		return Done{FinishReason: d.finish, IncompleteReason: d.incomplete, Empty: !d.answered}, nil
	default:
		return Done{}, newError("stream_interrupted", "the stream ended before the node said generation finished")
	}
}

// frame decodes one streamed frame.
func (d *decoder) frame(data []byte) []Event {
	top := object(data)
	if top == nil || d.noteFailure(top) {
		return nil
	}
	if d.responses || d.images {
		return d.responsesEvent(top)
	}
	return d.chatChunk(top)
}

// body decodes a single-body reply. A whole reply is generation's end.
func (d *decoder) body(data []byte) []Event {
	d.finished = true
	top := object(data)
	if top == nil || d.noteFailure(top) {
		return nil
	}
	switch {
	case d.images:
		d.answered = d.answered || len(array(top["data"])) > 0
		return nil
	case d.responses:
		return d.responsesBody(top)
	default:
		return d.chatBody(top)
	}
}

// noteFailure records an error the node reported in place of content: the
// Responses API's error and response.failed events, or a chat error envelope
// (an "error" that is not null, and no "choices"). It reports whether top was
// one.
//
// The node's code is kept on a ProviderError, never as the Error's Code: it
// is the node's choice, and an SDK code there would be read as the SDK's own
// finding (a node could send "wallet_unfunded").
func (d *decoder) noteFailure(top map[string]json.RawMessage) bool {
	var errObj map[string]json.RawMessage
	switch str(top["type"]) {
	case "error":
		errObj = top
	case "response.failed":
		errObj = object(object(top["response"])["error"])
	default:
		raw, ok := top["error"]
		if !ok || isNull(raw) {
			return false
		}
		if _, ok := top["choices"]; ok {
			return false
		}
		errObj = object(raw)
		if errObj == nil {
			// A bare string or other non-object still means the reply failed.
			errObj = map[string]json.RawMessage{"message": raw}
		}
	}
	if d.failure == nil {
		pe := &ProviderError{Code: codeString(errObj["code"]), Message: str(errObj["message"])}
		msg := pe.Message
		if msg == "" {
			msg = "the provider behind the node failed"
		}
		d.failure = &Error{Kind: KindUpstream, Code: "upstream_error", Message: msg, Err: pe}
	}
	return true
}

// responsesEvent decodes one Responses API event, or an image route's zs_image
// event, which share its shape.
func (d *decoder) responsesEvent(top map[string]json.RawMessage) []Event {
	switch str(top["type"]) {
	case "response.output_item.added":
		it, ok := item(top["item"])
		if !ok {
			return nil
		}
		if it.Type == "function_call" {
			d.answered = true
			f := object(it.Raw)
			if d.fnCalls == nil {
				d.fnCalls = map[string]fnCall{}
			}
			d.fnCalls[it.ID] = fnCall{str(f["call_id"]), str(f["name"])}
		}
		return []Event{ItemOpened{Item: it}}
	case "response.output_item.done":
		it, ok := item(top["item"])
		if !ok {
			return nil
		}
		if isImageItem(it) {
			d.answered = true
		}
		return []Event{ItemClosed{Item: it}}
	case "response.output_text.delta":
		id, delta := str(top["item_id"]), str(top["delta"])
		d.noteAnswer(delta)
		return []Event{TextDelta{ItemID: id, Delta: delta}}
	case "response.refusal.delta":
		// A refusal is an answer, but not answer text: it stays in the Frame.
		d.noteAnswer(str(top["delta"]))
		return nil
	case "response.reasoning_text.delta", "response.reasoning_summary_text.delta":
		return []Event{ReasoningDelta{ItemID: str(top["item_id"]), Delta: str(top["delta"])}}
	case "response.function_call_arguments.delta":
		id := str(top["item_id"])
		fc := d.fnCalls[id]
		return []Event{ToolCallDelta{ItemID: id, CallID: fc.id, Name: fc.name, ArgumentsDelta: str(top["delta"])}}
	case "response.output_text.annotation.added":
		ann := top["annotation"]
		if isNull(ann) {
			return nil
		}
		return []Event{AnnotationAdded{ItemID: str(top["item_id"]), Annotation: ann}}
	case "response.zs_tool_call.in_progress":
		id := str(top["item_id"])
		fc := fnCall{str(top["call_id"]), str(top["tool"])}
		if d.zsCalls == nil {
			d.zsCalls = map[string]fnCall{}
		}
		d.zsCalls[id] = fc
		d.answered = true
		action, icons := toolAction(top["action"])
		return []Event{ToolStatus{ItemID: id, CallID: fc.id, Name: fc.name, State: ToolInProgress, Action: action, Icons: icons}}
	case "response.zs_tool_call.completed":
		id := str(top["item_id"])
		fc := d.zsCalls[id]
		action, icons := toolAction(top["action"])
		return []Event{ToolStatus{ItemID: id, CallID: fc.id, Name: fc.name, State: ToolCompleted, Action: action, Icons: icons}}
	case "response.zs_image.progress":
		return []Event{ImageProgress{ItemID: str(top["item_id"]), Value: int(num(top["value"])), Max: int(num(top["max"]))}}
	case "response.zs_image.partial":
		b64 := str(top["partial_image_b64"])
		if b64 == "" {
			return nil
		}
		return []Event{ImagePartial{ItemID: str(top["item_id"]), B64: b64, MIME: str(top["mime"])}}
	case "response.zs_image.completed":
		d.finished = true
		d.answered = d.answered || len(array(object(top["response"])["data"])) > 0
		return nil
	case "response.completed", "response.incomplete":
		return d.responseEnd(object(top["response"]))
	}
	return nil
}

// responseEnd records a Responses API response's status, which ends
// generation, and returns its usage.
func (d *decoder) responseEnd(r map[string]json.RawMessage) []Event {
	d.finished = true
	d.finish = str(r["status"])
	if d.finish == "incomplete" {
		d.incomplete = str(object(r["incomplete_details"])["reason"])
		if d.incomplete == "" {
			d.incomplete = "incomplete"
		}
	}
	u := object(r["usage"])
	if u == nil {
		return nil
	}
	return []Event{Usage{
		InputTokens:     num(u["input_tokens"]),
		OutputTokens:    num(u["output_tokens"]),
		ReasoningTokens: num(object(u["output_tokens_details"])["reasoning_tokens"]),
		Source:          usageSourceResponse,
	}}
}

// responsesBody decodes a whole Responses API reply as the events its stream
// would have carried, one item at a time.
func (d *decoder) responsesBody(top map[string]json.RawMessage) []Event {
	var evs []Event
	for _, raw := range array(top["output"]) {
		it, ok := item(raw)
		if !ok {
			continue
		}
		f := object(raw)
		evs = append(evs, ItemOpened{Item: it})
		switch it.Type {
		case "message":
			for _, part := range array(f["content"]) {
				p := object(part)
				switch str(p["type"]) {
				case "output_text":
					text := str(p["text"])
					d.noteAnswer(text)
					evs = append(evs, TextDelta{ItemID: it.ID, Delta: text})
					for _, a := range array(p["annotations"]) {
						evs = append(evs, AnnotationAdded{ItemID: it.ID, Annotation: a})
					}
				case "refusal":
					d.noteAnswer(str(p["refusal"]))
				}
			}
		case "reasoning":
			for _, part := range append(array(f["summary"]), array(f["content"])...) {
				evs = append(evs, ReasoningDelta{ItemID: it.ID, Delta: str(object(part)["text"])})
			}
		case "function_call":
			d.answered = true
			evs = append(evs, ToolCallDelta{ItemID: it.ID, CallID: str(f["call_id"]), Name: str(f["name"]), ArgumentsDelta: str(f["arguments"])})
		default:
			if isImageItem(it) {
				d.answered = true
			}
		}
		evs = append(evs, ItemClosed{Item: it})
	}
	return append(evs, d.responseEnd(top)...)
}

// chatChunk decodes one Chat Completions chunk.
func (d *decoder) chatChunk(top map[string]json.RawMessage) []Event {
	var evs []Event
	for _, ch := range firstChoices(top) {
		evs = append(evs, d.chatPart(object(ch["delta"]), true)...)
		if r := str(ch["finish_reason"]); r != "" {
			d.finished = true
			d.finish = r
		}
	}
	return append(evs, chatUsage(top)...)
}

// chatBody decodes a whole Chat Completions reply.
func (d *decoder) chatBody(top map[string]json.RawMessage) []Event {
	var evs []Event
	for _, ch := range firstChoices(top) {
		evs = append(evs, d.chatPart(object(ch["message"]), false)...)
		d.finish = str(ch["finish_reason"])
	}
	return append(evs, chatUsage(top)...)
}

// firstChoices returns the choices of a chunk or reply that are its first,
// index 0. The events this decodes into carry no choice index, so a request
// for several choices (n > 1) is decoded for the first alone; the rest reach
// the caller only as Frames.
func firstChoices(top map[string]json.RawMessage) []map[string]json.RawMessage {
	var out []map[string]json.RawMessage
	for _, raw := range array(top["choices"]) {
		ch := object(raw)
		if ch == nil {
			continue
		}
		// An absent index is the first choice; one that is present must be 0.
		if idx, ok := ch["index"]; ok && string(bytes.TrimSpace(idx)) != "0" {
			continue
		}
		out = append(out, ch)
	}
	return out
}

// chatPart decodes a delta or a whole message. In a stream a tool call's id
// and name arrive on its first chunk alone, keyed by its index.
func (d *decoder) chatPart(p map[string]json.RawMessage, streamed bool) []Event {
	if p == nil {
		return nil
	}
	var evs []Event
	// reasoning is vLLM's field; reasoning_content is DeepSeek's and the older
	// vLLM name. A backend may send both with the same text, so one is read, the
	// one the node's own translator prefers.
	r := str(p["reasoning_content"])
	if r == "" {
		r = str(p["reasoning"])
	}
	if r != "" {
		evs = append(evs, ReasoningDelta{Delta: r})
	}
	if c := contentText(p["content"]); c != "" {
		d.noteAnswer(c)
		evs = append(evs, TextDelta{Delta: c})
	}
	d.noteAnswer(str(p["refusal"]))
	for _, raw := range array(p["tool_calls"]) {
		tc := object(raw)
		if tc == nil {
			continue
		}
		d.answered = true
		fn := object(tc["function"])
		fc := fnCall{str(tc["id"]), str(fn["name"])}
		if streamed {
			idx := int(num(tc["index"]))
			if d.chatCalls == nil {
				d.chatCalls = map[int]fnCall{}
			}
			prev := d.chatCalls[idx]
			if fc.id == "" {
				fc.id = prev.id
			}
			if fc.name == "" {
				fc.name = prev.name
			}
			d.chatCalls[idx] = fc
		}
		evs = append(evs, ToolCallDelta{CallID: fc.id, Name: fc.name, ArgumentsDelta: str(fn["arguments"])})
	}
	return evs
}

// contentText reads chat content as a string, or as an array of text parts,
// which some providers send.
func contentText(raw json.RawMessage) string {
	if s := str(raw); s != "" {
		return s
	}
	var b strings.Builder
	for _, part := range array(raw) {
		p := object(part)
		if t := str(p["type"]); t == "text" || t == "output_text" {
			b.WriteString(str(p["text"]))
		}
	}
	return b.String()
}

func chatUsage(top map[string]json.RawMessage) []Event {
	u := object(top["usage"])
	if u == nil {
		return nil
	}
	return []Event{Usage{
		InputTokens:     num(u["prompt_tokens"]),
		OutputTokens:    num(u["completion_tokens"]),
		ReasoningTokens: num(object(u["completion_tokens_details"])["reasoning_tokens"]),
		Source:          usageSourceResponse,
	}}
}

// noteAnswer records s as an answer unless it is blank.
func (d *decoder) noteAnswer(s string) {
	if strings.TrimSpace(s) != "" {
		d.answered = true
	}
}

// usageSourceResponse marks counts the response itself reported, as opposed
// to the receipt's billed figures in ReceiptVerified.
const usageSourceResponse = "response"

// item reads a Responses output item. A function_call may carry only its
// call_id, which then stands in for the id, as the client does.
func item(raw json.RawMessage) (Item, bool) {
	f := object(raw)
	typ := str(f["type"])
	if typ == "" {
		return Item{}, false
	}
	id := str(f["id"])
	if id == "" {
		id = str(f["call_id"])
	}
	return Item{ID: id, Type: typ, Raw: raw}, true
}

// isImageItem reports a zs image tool's finished item that holds an image.
func isImageItem(it Item) bool {
	if it.Type != "zs_image_generation_call" && it.Type != "zs_image_edit_call" {
		return false
	}
	f := object(it.Raw)
	return str(f["result"]) != "" || len(array(f["results"])) > 0
}

// Icon limits, the client's (client/src/stream/pipeline.ts
// parseZsToolCallIcons), which mirror the node's own: a node chooses these
// bytes, and a caller may render them.
const (
	maxIcons         = 12
	maxIconB64Chars  = (16*1024 + 2) / 3 * 4 // 16 KiB decoded
	maxIconsB64Chars = 96 * 1024
)

var (
	iconHostRE = regexp.MustCompile(`^[a-z0-9._\-:\[\]]{1,253}$`)
	// Standard base64 alone: a data URL is built by concatenation, so the
	// alphabet is what keeps it a data URL and nothing else.
	iconB64RE = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	iconMIMEs = map[string]bool{
		"image/x-icon": true, "image/png": true, "image/gif": true, "image/jpeg": true, "image/webp": true,
	}
)

// toolAction splits a zs tool call's action into the action without its
// icons, and the icons by host as data URLs. The icons are checked as the
// client checks them, in the order the node sent them; no SVG, which can
// carry script.
func toolAction(raw json.RawMessage) (json.RawMessage, map[string]string) {
	action := object(raw)
	if action == nil {
		return nil, nil
	}
	iconsRaw := action["icons"]
	delete(action, "icons")
	var out json.RawMessage
	if len(action) > 0 {
		out, _ = json.Marshal(action)
	}
	var icons map[string]string
	total := 0
	for _, kv := range orderedObject(iconsRaw) {
		if len(icons) >= maxIcons {
			break
		}
		host := kv.key
		ic := object(kv.val)
		mime, b64 := str(ic["mime"]), str(ic["data_b64"])
		switch {
		case !iconHostRE.MatchString(host),
			!iconMIMEs[mime],
			len(b64) == 0 || len(b64) > maxIconB64Chars,
			total+len(b64) > maxIconsB64Chars,
			!iconB64RE.MatchString(b64):
			continue
		}
		if icons == nil {
			icons = map[string]string{}
		}
		icons[host] = "data:" + mime + ";base64," + b64
		total += len(b64)
	}
	return out, icons
}

type keyVal struct {
	key string
	val json.RawMessage
}

// orderedObject reads a JSON object's members in the order they were sent,
// which a map loses. A member a host repeats keeps its first place and last
// value, as in JavaScript.
func orderedObject(raw json.RawMessage) []keyVal {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var out []keyVal
	at := map[string]int{}
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return out
		}
		key, _ := t.(string)
		var val json.RawMessage
		if dec.Decode(&val) != nil {
			return out
		}
		if i, ok := at[key]; ok {
			out[i].val = val
			continue
		}
		at[key] = len(out)
		out = append(out, keyVal{key, val})
	}
	return out
}

// object parses raw as a JSON object, or returns nil.
func object(raw []byte) map[string]json.RawMessage {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// array parses raw as a JSON array, or returns nil.
func array(raw json.RawMessage) []json.RawMessage {
	var a []json.RawMessage
	if json.Unmarshal(raw, &a) != nil {
		return nil
	}
	return a
}

func str(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	return s
}

// num reads a non-negative whole number, or 0. Token counts and indexes are
// never fractional, so a fraction is a malformed field, not a rounding; past
// 2^53 a float no longer holds a whole number exactly.
func num(raw json.RawMessage) uint64 {
	var f float64
	if json.Unmarshal(raw, &f) != nil || f < 0 || f != math.Trunc(f) || f > 1<<53 {
		return 0
	}
	return uint64(f)
}

func isNull(raw json.RawMessage) bool {
	t := bytes.TrimSpace(raw)
	return len(t) == 0 || string(t) == "null"
}

// codeString renders an error code the node sent as a string or a number. A
// null is no code: OpenAI's error envelope sends one routinely, and decoding
// it into a number would read as code 0.
func codeString(raw json.RawMessage) string {
	if s := str(raw); s != "" {
		return s
	}
	var f float64
	if isNull(raw) || json.Unmarshal(raw, &f) != nil {
		return ""
	}
	if f == 0 {
		// -0 too, as JavaScript renders it.
		return "0"
	}
	b, _ := json.Marshal(f)
	return string(b)
}
