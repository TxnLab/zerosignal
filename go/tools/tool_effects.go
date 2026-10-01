/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tools

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

// Hayai tool-call marker item types. Mirror OpenAI's `web_search_call`
// shape — a top-level item that appears in the Responses output[] (and
// streamed via response.output_item.added/.done) so the client can see
// THAT a tool ran without seeing query/results. The marker rides through
// the same crypto/seal/receipt machinery as every other output item;
// the proxy strips it from any subsequent input[] (StripBuiltinCallMarkers)
// so a multi-turn replay never feeds an unknown item type to a provider.
const (
	MarkerTypeWebSearchCall   = "zs_web_search_call"
	MarkerTypeWebReadCall     = "zs_web_read_call"
	MarkerTypeImageSearchCall = "zs_image_search_call"
	// MarkerTypeImageGenerationCall / MarkerTypeImageEditCall mark the
	// zs_image_generation / zs_image_edit built-in tool rounds.
	// Unlike the search markers — which stay payload-free — these
	// carry the generated image's base64 in a `result` field (see
	// MarshalImageMarkerItem) so a client can render the produced image
	// directly, mirroring OpenAI's native `image_generation_call` item.
	MarkerTypeImageGenerationCall = "zs_image_generation_call"
	MarkerTypeImageEditCall       = "zs_image_edit_call"
)

// Marker item statuses. "completed" is set on a successful tool round;
// "failed" is set when the tool returned an error so the client trace
// reflects the same outcome the loop saw.
const (
	MarkerStatusCompleted = "completed"
	MarkerStatusFailed    = "failed"
)

// CitationEffect carries one URL/title pair the client should surface as
// a citation annotation on the final assistant message. StartIndex and
// EndIndex are advisory — the node currently emits zero-range
// annotations anchored at the start of the message because most models
// don't echo URLs literally and substring matching is fragile. A future
// best-effort substring scan can populate real ranges without breaking
// existing consumers.
type CitationEffect struct {
	URL        string `json:"url"`
	Title      string `json:"title,omitempty"`
	StartIndex int    `json:"start_index"`
	EndIndex   int    `json:"end_index"`
}

// ToolEffect is the side-channel a hayai built-in tool emits alongside
// its LLM-facing content string. Citations populate the annotations
// array on the final message; CallItem is the raw JSON of a marker item
// inserted into output[] so the client trace records that a tool ran.
//
// Effects are accumulated across iterations of one tool loop and applied
// once at the end (non-streaming: SpliceEffectsResponsesBody) or emitted
// as synthetic SSE frames (streaming: see node/internal/server/stream_tool_loop.go).
//
// Action describes what the round actually did (query / URL / sources) for
// the completed status frame. It is nil unless the tool ran to success —
// the loop sets it immediately before storing the effect, and only when
// the tool returned no error, so all three failure shapes leave it nil:
// an unknown tool, a zs_web_read the provenance gate refused, and a call
// that dispatched but failed (a 503, a timeout, the tool's own SSRF
// check). The gate says a fetch was *permitted*; only a clean return says
// it *happened*, and the completed frame's URL means the latter. See
// ActionForCallPreflight.
type ToolEffect struct {
	Citations []CitationEffect
	CallItem  json.RawMessage
	Action    *ToolAction
}

// NewMarkerCallID returns a fresh opaque identifier for a hayai tool
// marker item. Distinct prefix from NewStatusItemID so logs are easy to
// disambiguate: marker items live in output[]; status items ride the
// zs_tool_call.in_progress/completed event channel.
func NewMarkerCallID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return "hycall_" + hex.EncodeToString(b[:])
}

// MarshalMarkerItem produces the JSON shape used inside output[] (non-
// streaming) and inside the `item` field of output_item.added/done
// (streaming). The shape is intentionally minimal — type/id/status, no
// query, no results — matching OpenAI's web_search_call convention.
func MarshalMarkerItem(itemType, id, status string) (json.RawMessage, error) {
	if itemType == "" || id == "" || status == "" {
		return nil, fmt.Errorf("marker item: type/id/status required")
	}
	return json.Marshal(map[string]string{
		"type":   itemType,
		"id":     id,
		"status": status,
	})
}

// MarshalImageMarkerItem produces the marker JSON for the
// zs_image_generation / zs_image_edit tool rounds. It mirrors
// MarshalMarkerItem's type/id/status shape but adds the produced images:
//
//   - `result`  = the FIRST image's base64 — mirrors OpenAI's native
//     `image_generation_call.result` so a client (or older hayai build)
//     that reads only `result` still renders one image.
//   - `results` = ALL images' base64 (one tool call can produce n>1);
//     clients that know the field iterate it to render every image.
//
// b64s is the raw base64 of each image (no data-URL prefix); mime (e.g.
// "image/png") is included as a hint when non-empty. On a failed round
// (or no images) callers pass an empty/nil b64s and `result`/`results`
// are omitted.
//
// The base64 payloads are response content the paying client receives
// over the sealed wire; like every tool result they MUST NOT be written
// to logs/traces/metrics (node/AGENTS.md privacy invariant).
func MarshalImageMarkerItem(itemType, id, status string, b64s []string, mime string) (json.RawMessage, error) {
	if itemType == "" || id == "" || status == "" {
		return nil, fmt.Errorf("image marker item: type/id/status required")
	}
	m := map[string]any{
		"type":   itemType,
		"id":     id,
		"status": status,
	}
	// Drop any empty entries defensively so a partial backend response
	// can't inject blank images.
	imgs := make([]string, 0, len(b64s))
	for _, b := range b64s {
		if b != "" {
			imgs = append(imgs, b)
		}
	}
	if len(imgs) > 0 {
		m["result"] = imgs[0]
		m["results"] = imgs
		if mime != "" {
			m["output_format"] = mime
		}
	}
	return json.Marshal(m)
}

// MarshalMarkerItemAddedFrame produces the sealable plaintext JSON for a
// `response.output_item.added` SSE event carrying a zs_*_call marker.
// The streaming tool loop emits one of these immediately before the
// matching .done frame so a client SDK observing standard Responses
// events sees the marker open and close like any other output item.
func MarshalMarkerItemAddedFrame(outputIndex int, item json.RawMessage) ([]byte, error) {
	frame := map[string]json.RawMessage{
		"type":         json.RawMessage(`"response.output_item.added"`),
		"output_index": mustMarshal(outputIndex),
		"item":         item,
	}
	return json.Marshal(frame)
}

// MarshalMarkerItemDoneFrame is the .done counterpart to .added. Both
// frames carry the same marker payload; the pair lets a client SDK
// commit the item when .done arrives.
func MarshalMarkerItemDoneFrame(outputIndex int, item json.RawMessage) ([]byte, error) {
	frame := map[string]json.RawMessage{
		"type":         json.RawMessage(`"response.output_item.done"`),
		"output_index": mustMarshal(outputIndex),
		"item":         item,
	}
	return json.Marshal(frame)
}

// MarshalAnnotationAddedFrame produces the sealable plaintext JSON for a
// `response.output_text.annotation.added` event. itemID/outputIndex
// reference the open assistant message; annotationIndex is a 0-based
// counter the loop maintains across multiple citations on the same
// message. The annotation payload uses OpenAI's `url_citation` shape so
// the TUI's existing citation renderer (tui/main.go) consumes it
// without changes.
func MarshalAnnotationAddedFrame(itemID string, outputIndex, contentIndex, annotationIndex int, c CitationEffect) ([]byte, error) {
	if itemID == "" {
		return nil, fmt.Errorf("annotation frame: item_id required")
	}
	annotation := map[string]any{
		"type":        "url_citation",
		"url":         c.URL,
		"start_index": c.StartIndex,
		"end_index":   c.EndIndex,
	}
	if c.Title != "" {
		annotation["title"] = c.Title
	}
	annJSON, err := json.Marshal(annotation)
	if err != nil {
		return nil, err
	}
	frame := map[string]json.RawMessage{
		"type":             json.RawMessage(`"response.output_text.annotation.added"`),
		"item_id":          mustMarshal(itemID),
		"output_index":     mustMarshal(outputIndex),
		"content_index":    mustMarshal(contentIndex),
		"annotation_index": mustMarshal(annotationIndex),
		"annotation":       annJSON,
	}
	return json.Marshal(frame)
}

// SpliceEffectsResponsesBody applies accumulated tool effects onto a
// non-streaming /v1/responses body. It (a) inserts each effect's
// CallItem into output[] immediately before the final message item and
// (b) appends each citation onto the message's first output_text content
// block as a url_citation annotation.
//
// The body is parsed, mutated, and re-marshaled. When effects is empty
// or no message item exists, the body is returned unchanged so this is
// safe to call unconditionally.
func SpliceEffectsResponsesBody(body []byte, effects []ToolEffect) ([]byte, error) {
	if len(effects) == 0 {
		return body, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		// Not a JSON object — leave the body alone (matches the
		// tolerance other helpers like InjectSafetyIdentifier exhibit).
		return body, nil
	}
	rawOutput, ok := obj["output"]
	if !ok {
		return body, nil
	}
	var output []json.RawMessage
	if err := json.Unmarshal(rawOutput, &output); err != nil {
		return body, nil
	}

	// Locate the LAST message item — that's the final assistant turn,
	// the only one we annotate. Earlier message items (if any) belong
	// to a preceding iteration's reasoning trail and stay byte-identical.
	msgIdx := -1
	for i := len(output) - 1; i >= 0; i-- {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(output[i], &typed); err != nil {
			continue
		}
		if typed.Type == "message" {
			msgIdx = i
			break
		}
	}

	// Collect non-nil call items in effect order (preserves call order
	// across iterations).
	var markers []json.RawMessage
	var allCitations []CitationEffect
	for _, e := range effects {
		if len(e.CallItem) > 0 {
			markers = append(markers, e.CallItem)
		}
		allCitations = append(allCitations, e.Citations...)
	}

	if msgIdx >= 0 && len(allCitations) > 0 {
		annotated, err := annotateMessageItem(output[msgIdx], allCitations)
		if err == nil {
			output[msgIdx] = annotated
		}
	}

	// Insert markers right before the final message item (or at the end
	// when there's no message item — defensive; in practice the final
	// iteration always produces a message).
	if len(markers) > 0 {
		insertAt := msgIdx
		if insertAt < 0 {
			insertAt = len(output)
		}
		newOutput := make([]json.RawMessage, 0, len(output)+len(markers))
		newOutput = append(newOutput, output[:insertAt]...)
		newOutput = append(newOutput, markers...)
		newOutput = append(newOutput, output[insertAt:]...)
		output = newOutput
	}

	newOutputJSON, err := json.Marshal(output)
	if err != nil {
		return nil, fmt.Errorf("remarshal output: %w", err)
	}
	obj["output"] = newOutputJSON
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}

// flattenCitations concatenates the Citations from every effect in
// effects into a single slice, preserving order. Used by the Chat-side
// renderers (SpliceEffectsChatBody and MarshalChatCitationsContentDelta)
// before passing into renderCitationsMarkdown, which dedups by URL.
func flattenCitations(effects []ToolEffect) []CitationEffect {
	var all []CitationEffect
	for _, e := range effects {
		all = append(all, e.Citations...)
	}
	return all
}

// escapeMarkdownLinkText backslash-escapes characters that would
// terminate or re-enter a markdown link's text segment ("[...]").
// CommonMark allows any ASCII punctuation to be backslash-escaped; we
// neutralise `[` and `]` (which would open / close a nested link
// reference) and `\` (the escape char itself). Everything else passes
// through untouched so titles like "[Updated] Article" render as
// `\[Updated\] Article` and parse cleanly across renderers.
func escapeMarkdownLinkText(s string) string {
	if !strings.ContainsAny(s, `[]\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r == '[' || r == ']' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// escapeMarkdownLinkURL backslash-escapes characters that would
// terminate the angle-bracket form of a markdown link destination
// ("<...>"). Per CommonMark §6.6, `<...>` may contain spaces and
// escaped pointy brackets; raw `<`, `>`, line endings, or unescaped
// backslashes break the destination. URLs almost never contain raw
// `<` or `>` (RFC 3986 reserves them for percent-encoding), but
// defensive escaping costs nothing.
func escapeMarkdownLinkURL(s string) string {
	if !strings.ContainsAny(s, "<>\\") {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	for _, r := range s {
		if r == '<' || r == '>' || r == '\\' {
			b.WriteByte('\\')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// renderCitationsMarkdown formats a citations bundle into a markdown
// "Sources" block for embedding in Chat Completions assistant content.
// Chat has no annotations field on its message shape, so the only legal
// surface for citations is the content string itself; this is the
// canonical rendering used by both the non-streaming splice
// (SpliceEffectsChatBody) and the streaming synthetic-delta emit
// (MarshalChatCitationsContentDelta) so the two paths produce
// byte-identical output.
//
// Returns "" when there's nothing to render (empty input, all entries
// have empty URL, all entries duplicate each other). Output starts
// with a leading "\n\n" so it can be appended directly onto an existing
// content string; callers handling the no-prior-content case strip the
// prefix themselves.
//
// Deduplicates by URL preserving first-seen order so multiple
// iterations citing the same source don't repeat. URLs are emitted
// using the angle-bracket form (`[title](<url>)`) so destinations
// containing parens — e.g. Wikipedia article URLs — don't break the
// link parser. Titles are backslash-escaped on `]` so bracketed
// prefixes like "[Updated] Article" survive intact.
func renderCitationsMarkdown(citations []CitationEffect) string {
	if len(citations) == 0 {
		return ""
	}
	seen := make(map[string]struct{}, len(citations))
	type item struct {
		title string
		url   string
	}
	var items []item
	for _, c := range citations {
		if c.URL == "" {
			continue
		}
		if _, dup := seen[c.URL]; dup {
			continue
		}
		seen[c.URL] = struct{}{}
		title := c.Title
		if title == "" {
			title = c.URL
		}
		items = append(items, item{title: title, url: c.URL})
	}
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\n\n**Sources:**\n")
	for i, it := range items {
		fmt.Fprintf(&b, "%d. [%s](<%s>)\n", i+1, escapeMarkdownLinkText(it.title), escapeMarkdownLinkURL(it.url))
	}
	return b.String()
}

// SpliceEffectsChatBody applies accumulated tool effects onto a non-
// streaming /v1/chat/completions body by appending a markdown Sources
// block onto choices[0].message.content. CallItem is intentionally
// dropped — Chat has no output[]/items shape to host a marker, and
// surfacing one as a synthetic tool_calls entry would confuse clients
// expecting only model-emitted tool_calls.
//
// The body is parsed, mutated, and re-marshaled. When effects is empty
// (or contains no citations after dedup), or when the body has no
// choices / no first-choice message, the body is returned unchanged so
// this is safe to call unconditionally.
//
// If the existing message.content is missing or null, the rendered
// markdown's leading "\n\n" is stripped so the Sources block becomes
// the entire content rather than starting with two blank lines.
func SpliceEffectsChatBody(body []byte, effects []ToolEffect) ([]byte, error) {
	if len(effects) == 0 {
		return body, nil
	}
	md := renderCitationsMarkdown(flattenCitations(effects))
	if md == "" {
		return body, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		// Tolerate non-JSON bodies — same posture as
		// SpliceEffectsResponsesBody.
		return body, nil
	}
	rawChoices, ok := obj["choices"]
	if !ok {
		return body, nil
	}
	var choices []json.RawMessage
	if err := json.Unmarshal(rawChoices, &choices); err != nil {
		return body, nil
	}
	if len(choices) == 0 {
		return body, nil
	}
	var choice map[string]json.RawMessage
	if err := json.Unmarshal(choices[0], &choice); err != nil {
		return body, nil
	}
	rawMsg, ok := choice["message"]
	if !ok {
		return body, nil
	}
	var msg map[string]json.RawMessage
	if err := json.Unmarshal(rawMsg, &msg); err != nil {
		return body, nil
	}
	var existing string
	if rawContent, ok := msg["content"]; ok {
		// content can be a string or null. Tolerate both.
		var s *string
		if err := json.Unmarshal(rawContent, &s); err == nil && s != nil {
			existing = *s
		}
	}
	var newContent string
	if existing == "" {
		newContent = strings.TrimPrefix(md, "\n\n")
	} else {
		newContent = existing + md
	}
	contentJSON, err := json.Marshal(newContent)
	if err != nil {
		return nil, fmt.Errorf("marshal content: %w", err)
	}
	msg["content"] = contentJSON
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("marshal message: %w", err)
	}
	choice["message"] = msgJSON
	choiceJSON, err := json.Marshal(choice)
	if err != nil {
		return nil, fmt.Errorf("marshal choice: %w", err)
	}
	choices[0] = choiceJSON
	newChoices, err := json.Marshal(choices)
	if err != nil {
		return nil, fmt.Errorf("marshal choices: %w", err)
	}
	obj["choices"] = newChoices
	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("remarshal body: %w", err)
	}
	return out, nil
}

// annotateMessageItem appends url_citation annotations onto the first
// output_text content block of a message item. The original item bytes
// are returned unchanged when the shape doesn't have a content[] / no
// output_text block — citations are an enrichment, never load-bearing.
func annotateMessageItem(item json.RawMessage, citations []CitationEffect) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(item, &obj); err != nil {
		return item, err
	}
	rawContent, ok := obj["content"]
	if !ok {
		return item, nil
	}
	var content []json.RawMessage
	if err := json.Unmarshal(rawContent, &content); err != nil {
		return item, nil
	}
	textIdx := -1
	for i, c := range content {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(c, &typed); err != nil {
			continue
		}
		if typed.Type == "output_text" {
			textIdx = i
			break
		}
	}
	if textIdx < 0 {
		return item, nil
	}
	var part map[string]json.RawMessage
	if err := json.Unmarshal(content[textIdx], &part); err != nil {
		return item, err
	}
	var existing []json.RawMessage
	if rawAnn, ok := part["annotations"]; ok {
		_ = json.Unmarshal(rawAnn, &existing)
	}
	for _, c := range citations {
		annotation := map[string]any{
			"type":        "url_citation",
			"url":         c.URL,
			"start_index": c.StartIndex,
			"end_index":   c.EndIndex,
		}
		if c.Title != "" {
			annotation["title"] = c.Title
		}
		b, err := json.Marshal(annotation)
		if err != nil {
			return item, err
		}
		existing = append(existing, b)
	}
	annJSON, err := json.Marshal(existing)
	if err != nil {
		return item, err
	}
	part["annotations"] = annJSON
	partJSON, err := json.Marshal(part)
	if err != nil {
		return item, err
	}
	content[textIdx] = partJSON
	contentJSON, err := json.Marshal(content)
	if err != nil {
		return item, err
	}
	obj["content"] = contentJSON
	return json.Marshal(obj)
}

// StripBuiltinCallMarkers scrubs built-in zs_*_call marker items from the
// `input[]` array of a /v1/responses request body. The proxy/node
// emits these markers in the response so the client trace reflects
// that a tool ran; if the client replays its conversation history on
// the next turn, those markers must NOT reach the upstream provider —
// providers reject unknown item types or, worse, surface them in
// follow-up output. This helper is idempotent and a no-op when the body
// has no input[], no array shape, or no markers.
func StripBuiltinCallMarkers(body []byte) []byte {
	if len(body) == 0 {
		return body
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return body
	}
	rawInput, ok := obj["input"]
	if !ok {
		return body
	}
	var input []json.RawMessage
	if err := json.Unmarshal(rawInput, &input); err != nil {
		return body
	}
	filtered := input[:0]
	stripped := false
	for _, item := range input {
		var typed struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(item, &typed); err == nil && isBuiltinCallMarkerType(typed.Type) {
			stripped = true
			continue
		}
		filtered = append(filtered, item)
	}
	if !stripped {
		return body
	}
	newInput, err := json.Marshal(filtered)
	if err != nil {
		return body
	}
	obj["input"] = newInput
	out, err := json.Marshal(obj)
	if err != nil {
		return body
	}
	return out
}

// isBuiltinCallMarkerType reports whether t is one of the recognised
// built-in zs_*_call marker item types. Tied to the explicit list rather than
// IsBuiltinToolType because the latter also matches request-side tool
// types (zs_web_search) which we do NOT want to silently strip from
// input[] — those are tool definitions on a fresh turn, not stale
// markers from a prior response.
func isBuiltinCallMarkerType(t string) bool {
	switch t {
	case MarkerTypeWebSearchCall, MarkerTypeWebReadCall, MarkerTypeImageSearchCall,
		MarkerTypeImageGenerationCall, MarkerTypeImageEditCall:
		return true
	}
	return false
}
