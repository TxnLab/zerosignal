/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

// Generates / verifies proto/testdata/stream_events_vectors.json: a node's
// decrypted frames (or a whole reply) in, the typed events and the turn's end
// out. A port of the decoder replays it to decode the same frames the same
// way.
//
//	cd proto/go && go test ./zs -run TestStreamEventVectors -update

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"testing"
)

// updateVectors regenerates the fixture of whichever vector test -run selects.
var updateVectors = flag.Bool("update", false, "regenerate the selected test's proto/testdata vectors")

const eventVectorsPath = "../../testdata/stream_events_vectors.json"

type eventVectorCase struct {
	Name     string `json:"name"`
	Endpoint string `json:"endpoint"`
	// Frames is a stream's decrypted frames in order; Body is a whole reply.
	// Exactly one is set. Both are text, since some are deliberately not JSON
	// and a port must read a number as it was written, not as a JSON parser
	// re-wrote it.
	Frames []string `json:"frames,omitempty"`
	Body   string   `json:"body,omitempty"`

	Events []map[string]any `json:"events"`
	// End is {"done": {...}} or {"error": {...}}.
	End map[string]any `json:"end"`
}

// pngB64 is a valid base64 payload for an icon.
const pngB64 = "iVBORw0KGgo="

func eventVectorInputs() []eventVectorCase {
	f := func(s ...string) []string { return s }
	const (
		resp  = endpointResponses
		chat  = endpointChatCompletions
		image = endpointImages
	)
	cases := []eventVectorCase{
		// Responses API, streamed.
		{Name: "responses text with annotation and usage", Endpoint: resp, Frames: f(
			`{"type":"response.created","response":{"id":"resp_1","status":"in_progress"}}`,
			`{"type":"response.output_item.added","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant","content":[]}}`,
			`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"Hel"}`,
			`{"type":"response.output_text.delta","item_id":"msg_1","output_index":0,"content_index":0,"delta":"lo"}`,
			`{"type":"response.output_text.annotation.added","item_id":"msg_1","annotation":{"type":"url_citation","url":"https://example.com","title":"Ex","start_index":0,"end_index":5}}`,
			`{"type":"response.output_item.done","output_index":0,"item":{"id":"msg_1","type":"message","role":"assistant"}}`,
			`{"type":"response.completed","response":{"id":"resp_1","status":"completed","usage":{"input_tokens":12,"output_tokens":7,"output_tokens_details":{"reasoning_tokens":3}}}}`,
		)},
		{Name: "responses reasoning only is empty", Endpoint: resp, Frames: f(
			`{"type":"response.output_item.added","item":{"id":"rs_1","type":"reasoning"}}`,
			`{"type":"response.reasoning_summary_text.delta","item_id":"rs_1","delta":"Thinking"}`,
			`{"type":"response.reasoning_text.delta","item_id":"rs_1","delta":" more"}`,
			`{"type":"response.output_item.done","item":{"id":"rs_1","type":"reasoning"}}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses blank text is empty", Endpoint: resp, Frames: f(
			`{"type":"response.output_text.delta","item_id":"msg_1","delta":" \n\t"}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses function call", Endpoint: resp, Frames: f(
			`{"type":"response.output_item.added","item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"get_weather","arguments":""}}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"{\"city\":"}`,
			`{"type":"response.function_call_arguments.delta","item_id":"fc_1","delta":"\"Oslo\"}"}`,
			`{"type":"response.output_item.done","item":{"id":"fc_1","type":"function_call","call_id":"call_1","name":"get_weather","arguments":"{\"city\":\"Oslo\"}"}}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses function call identified by call_id alone", Endpoint: resp, Frames: f(
			`{"type":"response.output_item.added","item":{"type":"function_call","call_id":"call_9","name":"lookup"}}`,
			`{"type":"response.function_call_arguments.delta","item_id":"call_9","delta":"{}"}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses zs tool call with icons", Endpoint: resp, Frames: f(
			`{"type":"response.zs_tool_call.in_progress","item_id":"zs_1","call_id":"zcall_1","tool":"zs_web_search","action":{"type":"search","query":"oslo weather","icons":{"example.com":{"mime":"image/png","data_b64":"`+pngB64+`"},"evil.com":{"mime":"image/svg+xml","data_b64":"`+pngB64+`"},"BAD HOST":{"mime":"image/png","data_b64":"`+pngB64+`"},"broken.com":{"mime":"image/png","data_b64":"!!!"}}}}`,
			`{"type":"response.zs_tool_call.completed","item_id":"zs_1","action":{"type":"search","sources":[{"url":"https://example.com"}]}}`,
			`{"type":"response.output_text.delta","item_id":"msg_1","delta":"Sunny."}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses incomplete with reason", Endpoint: resp, Frames: f(
			`{"type":"response.output_text.delta","item_id":"msg_1","delta":"Partial"}`,
			`{"type":"response.incomplete","response":{"status":"incomplete","incomplete_details":{"reason":"max_output_tokens"},"usage":{"input_tokens":5,"output_tokens":100}}}`,
		)},
		{Name: "responses incomplete without details", Endpoint: resp, Frames: f(
			`{"type":"response.incomplete","response":{"status":"incomplete"}}`,
		)},
		{Name: "responses error event", Endpoint: resp, Frames: f(
			`{"type":"response.output_text.delta","item_id":"msg_1","delta":"Hi"}`,
			`{"type":"error","code":"server_error","message":"the model crashed"}`,
		)},
		{Name: "responses error event without code", Endpoint: resp, Frames: f(
			`{"type":"error","message":"overloaded"}`,
		)},
		{Name: "responses failed", Endpoint: resp, Frames: f(
			`{"type":"response.failed","response":{"status":"failed","error":{"code":"rate_limit_exceeded","message":"slow down"}}}`,
		)},
		{Name: "responses image tool result is an answer", Endpoint: resp, Frames: f(
			`{"type":"response.zs_image.progress","item_id":"ig_1","value":3,"max":10}`,
			`{"type":"response.zs_image.partial","item_id":"ig_1","partial_image_b64":"`+pngB64+`","mime":"image/png"}`,
			`{"type":"response.output_item.done","item":{"id":"ig_1","type":"zs_image_generation_call","results":["`+pngB64+`"],"output_format":"png"}}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses ignores what it does not model", Endpoint: resp, Frames: f(
			`not json`,
			`[1,2,3]`,
			`null`,
			`{"type":"response.content_part.added","item_id":"msg_1"}`,
			`{"type":"response.output_text.done","item_id":"msg_1","text":"x"}`,
			`{"type":"response.output_item.added"}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},

		// Responses API, one body.
		// OpenAI's own bodies carry "error": null.
		{Name: "responses body", Endpoint: resp, Body: string(`{"id":"resp_2","status":"completed","error":null,"output":[
			{"id":"rs_1","type":"reasoning","summary":[{"type":"summary_text","text":"Plan"}],"content":[{"type":"reasoning_text","text":"Detail"}]},
			{"id":"msg_1","type":"message","content":[{"type":"output_text","text":"Answer","annotations":[{"type":"url_citation","url":"https://example.com"}]}]},
			{"id":"fc_1","type":"function_call","call_id":"call_1","name":"f","arguments":"{}"}
		],"usage":{"input_tokens":3,"output_tokens":4}}`)},
		{Name: "responses body incomplete", Endpoint: resp, Body: string(`{"status":"incomplete","incomplete_details":{"reason":"content_filter"},"output":[]}`)},
		{Name: "responses body error", Endpoint: resp, Body: string(`{"error":{"code":"server_error","message":"boom"}}`)},
		{Name: "responses body edited image in result is an answer", Endpoint: resp, Body: string(`{"status":"completed","output":[{"id":"ie_1","type":"zs_image_edit_call","result":"` + pngB64 + `"}]}`)},
		{Name: "responses edited image in result is an answer", Endpoint: resp, Frames: f(
			`{"type":"response.output_item.done","item":{"id":"ie_1","type":"zs_image_edit_call","result":"`+pngB64+`"}}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "the first error the node reports wins", Endpoint: resp, Frames: f(
			`{"type":"error","code":"first_code","message":"first"}`,
			`{"type":"error","code":"second_code","message":"second"}`,
		)},
		{Name: "a bare string error still fails the reply", Endpoint: chat, Body: string(`{"error":"gateway exploded"}`)},
		{Name: "a null annotation is dropped", Endpoint: resp, Frames: f(
			`{"type":"response.output_text.annotation.added","item_id":"msg_1","annotation":null}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "an empty partial image is dropped", Endpoint: resp, Frames: f(
			`{"type":"response.zs_image.partial","item_id":"ig_1","partial_image_b64":""}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "token counts up to 2^53 are kept", Endpoint: resp, Frames: f(
			`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":9007199254740992,"output_tokens":9007199254740994}}}`,
		)},

		// Chat Completions, streamed.
		{Name: "chat text and usage chunk", Endpoint: chat, Frames: f(
			`{"id":"c1","choices":[{"index":0,"delta":{"role":"assistant","content":""}}]}`,
			`{"id":"c1","choices":[{"index":0,"delta":{"content":"Hel"}}]}`,
			`{"id":"c1","choices":[{"index":0,"delta":{"content":"lo"},"finish_reason":"stop"}]}`,
			`{"id":"c1","choices":[],"usage":{"prompt_tokens":9,"completion_tokens":2,"completion_tokens_details":{"reasoning_tokens":5}}}`,
		)},
		{Name: "chat reasoning in both field names, then text", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"reasoning_content":"Let me"}}]}`,
			`{"choices":[{"index":0,"delta":{"reasoning":" think"}}]}`,
			`{"choices":[{"index":0,"delta":{"reasoning":" twice","reasoning_content":" once"}}]}`,
			`{"choices":[{"index":0,"delta":{"content":"42"},"finish_reason":"stop"}]}`,
		)},
		{Name: "chat reasoning only is empty", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"reasoning":"Hmm"}}]}`,
			`{"choices":[{"index":0,"delta":{"content":"  "},"finish_reason":"length"}]}`,
		)},
		{Name: "chat parallel tool calls", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_a","type":"function","function":{"name":"a","arguments":""}}]}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":1,"id":"call_b","type":"function","function":{"name":"b","arguments":"{}"}}]}}]}`,
			`{"choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"function":{"arguments":"{\"x\":1}"}}]}}]}`,
			`{"choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}`,
		)},
		{Name: "chat decodes the first choice alone", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"content":"A"}},{"index":1,"delta":{"content":"B"}}]}`,
			`{"choices":[{"index":1,"delta":{"content":"C"},"finish_reason":"length"}]}`,
			`{"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`,
		)},
		{Name: "chat error envelope with a numeric code", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"content":"Hi"}}]}`,
			`{"error":{"message":"upstream timed out","code":504}}`,
		)},
		{Name: "chat null error beside choices is not an error", Endpoint: chat, Frames: f(
			`{"error":null,"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}`,
		)},
		{Name: "chat error beside choices is not an error", Endpoint: chat, Frames: f(
			`{"error":{"message":"x"},"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}`,
		)},
		{Name: "chat choice without an index is the first", Endpoint: chat, Frames: f(
			`{"choices":[{"delta":{"content":"Hi"},"finish_reason":"stop"}]}`,
		)},

		// Chat Completions, one body.
		{Name: "chat body with tool calls", Endpoint: chat, Body: string(`{"choices":[{"index":0,"message":{"role":"assistant","content":null,"reasoning_content":"Need data","tool_calls":[{"id":"call_1","type":"function","function":{"name":"f","arguments":"{\"q\":1}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":6}}`)},
		{Name: "chat body error", Endpoint: chat, Body: string(`{"error":{"message":"bad","type":"server_error"}}`)},

		// Image routes.
		{Name: "image stream", Endpoint: image, Frames: f(
			`{"type":"response.zs_image.progress","value":1,"max":4}`,
			`{"type":"response.zs_image.partial","partial_image_b64":"`+pngB64+`"}`,
			`{"type":"response.zs_image.completed","response":{"data":[{"b64_json":"`+pngB64+`","output_format":"png"}]}}`,
		)},
		{Name: "image body", Endpoint: image, Body: string(`{"created":1,"data":[{"b64_json":"` + pngB64 + `"}]}`)},
		{Name: "image body without images is empty", Endpoint: image, Body: string(`{"created":1,"data":[]}`)},
		{Name: "image edit stream", Endpoint: endpointImageEdits, Frames: f(
			`{"type":"response.zs_image.progress","value":1,"max":4}`,
			`{"type":"response.zs_image.completed","response":{"data":[{"b64_json":"`+pngB64+`"}]}}`,
		)},
		{Name: "image edit body", Endpoint: endpointImageEdits, Body: string(`{"created":1,"data":[{"b64_json":"` + pngB64 + `"}]}`)},

		// The turn's end rests on the node's sealed word alone.
		{Name: "chat cut before a finish_reason is interrupted", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"content":"Hel"}}]}`,
		)},
		{Name: "responses cut before completed is interrupted", Endpoint: resp, Frames: f(
			`{"type":"response.output_text.delta","item_id":"msg_1","delta":"Hel"}`,
		)},
		{Name: "a node error code stays the node's", Endpoint: chat, Frames: f(
			`{"error":{"message":"too long","code":"context_length_exceeded"}}`,
		)},

		// Answers that are not text.
		{Name: "responses refusal is an answer", Endpoint: resp, Frames: f(
			`{"type":"response.refusal.delta","item_id":"msg_1","delta":"I can't help with that."}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		)},
		{Name: "responses body refusal is an answer", Endpoint: resp, Body: string(`{"status":"completed","output":[{"id":"msg_1","type":"message","content":[{"type":"refusal","refusal":"No."}]}]}`)},
		{Name: "chat refusal is an answer", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"refusal":"No."},"finish_reason":"stop"}]}`,
		)},

		// One field of an unexpected type costs that field alone.
		{Name: "chat content as text parts", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"content":[{"type":"text","text":"Hi"},{"type":"image_url","image_url":{"url":"x"}},{"type":"output_text","text":" there"}]},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1}}`,
		)},
		{Name: "malformed numbers do not cost the status", Endpoint: resp, Frames: f(
			`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":1.5,"output_tokens":"7"}}}`,
		)},
		{Name: "chat choice with a malformed index is skipped", Endpoint: chat, Frames: f(
			`{"choices":[{"index":"0","delta":{"content":"skipped"}},{"index":0,"delta":{"content":"kept"},"finish_reason":"stop"}]}`,
		)},
	}
	cases = append(cases, edgeVectorInputs()...)
	return append(cases, iconVectorInputs()...)
}

// edgeVectorInputs pins how a field of an unexpected value reads, where a port
// reading parsed JSON could otherwise take a shortcut.
func edgeVectorInputs() []eventVectorCase {
	f := func(s ...string) []string { return s }
	const (
		resp  = endpointResponses
		chat  = endpointChatCompletions
		image = endpointImages
	)
	completed := `{"type":"response.completed","response":{"status":"completed"}}`
	return []eventVectorCase{
		{Name: "an error without a message gets the default", Endpoint: chat, Body: `{"error":{"code":"x"}}`},
		{Name: "response.failed without an error object", Endpoint: resp, Frames: f(`{"type":"response.failed","response":{}}`)},
		{Name: "a null error code is no code", Endpoint: chat, Body: `{"error":{"message":"bad","type":"invalid_request_error","param":null,"code":null}}`},
		{Name: "a null code on an error event is no code", Endpoint: resp, Frames: f(`{"type":"error","code":null,"message":"x"}`)},
		{Name: "a negative zero code reads as 0", Endpoint: resp, Frames: f(`{"type":"error","code":-0,"message":"x"}`)},
		{Name: "a body that is an array still ends the reply", Endpoint: resp, Body: `[]`},
		{Name: "a body that is a string still ends the reply", Endpoint: chat, Body: `"x"`},
		{Name: "an error of false still fails the reply", Endpoint: chat, Body: `{"error":false}`},
		{Name: "an empty-string error still fails the reply", Endpoint: chat, Body: `{"error":""}`},
		{Name: "a null choices beside an error is not a failure", Endpoint: chat, Frames: f(
			`{"error":{"message":"x"},"choices":null}`,
			`{"choices":[{"index":0,"delta":{"content":"ok"},"finish_reason":"stop"}]}`,
		)},
		{Name: "content after an error still decodes and the error stands", Endpoint: resp, Frames: f(
			`{"type":"error","code":"server_error","message":"first"}`,
			`{"type":"error","code":"other","message":"second"}`,
			`{"type":"response.output_text.delta","item_id":"m","delta":"late"}`,
			completed,
		)},
		{Name: "negative numbers read as zero", Endpoint: resp, Frames: f(
			`{"type":"response.zs_image.progress","item_id":"i","value":-0,"max":-1e-400}`,
			`{"type":"response.completed","response":{"status":"completed","usage":{"input_tokens":-3,"output_tokens":-0,"output_tokens_details":{"reasoning_tokens":-1e-400}}}}`,
		)},
		{Name: "a negative zero in a body reads as zero", Endpoint: resp, Body: `{"status":"completed","usage":{"input_tokens":-0,"output_tokens":2}}`},
		{Name: "an image route's completion without data is empty", Endpoint: image, Frames: f(`{"type":"response.zs_image.completed","response":{}}`)},
		{Name: "an action holding only icons is no action", Endpoint: resp, Frames: f(
			`{"type":"response.zs_tool_call.in_progress","item_id":"zs_1","call_id":"c","tool":"zs_web_search","action":{"icons":{"a.example":{"mime":"image/png","data_b64":"`+pngB64+`"}}}}`,
			completed,
		)},
		{Name: "a chat body without choices keeps its usage", Endpoint: chat, Body: `{"usage":{"prompt_tokens":3,"completion_tokens":0}}`},
		{Name: "a responses body holding only a function call is an answer", Endpoint: resp, Body: `{"status":"completed","output":[{"id":"fc_1","type":"function_call","call_id":"c1","name":"f","arguments":"{}"}]}`},
		// Blank is Go's unicode.IsSpace: U+0085 is space, U+FEFF is not.
		{Name: "a next-line character is blank", Endpoint: resp, Frames: f(
			`{"type":"response.output_text.delta","item_id":"m","delta":"\u0085"}`,
			completed,
		)},
		{Name: "a zero-width no-break space is not blank", Endpoint: resp, Frames: f(
			// The escape is split so no editor writes the character itself,
			// which Go refuses in source.
			`{"type":"response.output_text.delta","item_id":"m","delta":"\u`+`feff"}`,
			completed,
		)},
		{Name: "a blank chat answer is empty", Endpoint: chat, Frames: f(
			`{"choices":[{"index":0,"delta":{"content":"\u0085\u` + `3000"},"finish_reason":"stop"}]}`,
		)},
	}
}

// iconVectorInputs pins the icon checks a port must apply in the same order:
// the count cap, the per-icon and total size caps, the order the node sent
// the hosts in, the base64 alphabet and the host pattern.
func iconVectorInputs() []eventVectorCase {
	icon := func(mime, b64 string) string {
		return `{"mime":"` + mime + `","data_b64":"` + b64 + `"}`
	}
	frame := func(members ...string) []string {
		return []string{
			`{"type":"response.zs_tool_call.in_progress","item_id":"zs_1","call_id":"c","tool":"zs_web_search","action":{"type":"search","icons":{` +
				strings.Join(members, ",") + `}}}`,
			`{"type":"response.completed","response":{"status":"completed"}}`,
		}
	}
	var thirteen []string
	for i := range 13 {
		// Hosts sent in reverse alphabetical order, so a port that sorts them
		// keeps a different twelve.
		thirteen = append(thirteen, fmt.Sprintf(`"h%02d.example":%s`, 12-i, icon("image/png", pngB64)))
	}
	full := strings.Repeat("A", maxIconB64Chars)
	return []eventVectorCase{
		{Name: "icons: at most twelve, in the order sent", Endpoint: endpointResponses, Frames: frame(thirteen...)},
		{Name: "icons: the per-icon size cap", Endpoint: endpointResponses, Frames: frame(
			`"at.example":`+icon("image/png", full),
			`"over.example":`+icon("image/png", full+"AAAA"),
		)},
		{Name: "icons: an icon past the total cap is skipped, not the rest", Endpoint: endpointResponses, Frames: frame(
			`"a.example":`+icon("image/png", full),
			`"b.example":`+icon("image/png", full),
			`"c.example":`+icon("image/png", full),
			`"d.example":`+icon("image/png", full),
			`"e.example":`+icon("image/png", full),
			`"small.example":`+icon("image/png", pngB64),
		)},
		{Name: "icons: a set exactly at the total cap is kept", Endpoint: endpointResponses, Frames: frame(
			`"a.example":`+icon("image/png", full),
			`"b.example":`+icon("image/png", full),
			`"c.example":`+icon("image/png", full),
			`"d.example":`+icon("image/png", full),
			`"rest.example":`+icon("image/png", strings.Repeat("A", maxIconsB64Chars-4*maxIconB64Chars)),
		)},
		{Name: "icons: a host named __proto__ is an ordinary host", Endpoint: endpointResponses, Frames: frame(
			`"__proto__":`+icon("image/png", pngB64),
			`"after.example":`+icon("image/png", pngB64),
		)},
		{Name: "icons: a repeated host keeps its last value", Endpoint: endpointResponses, Frames: frame(
			`"dup.example":`+icon("image/png", pngB64),
			`"other.example":`+icon("image/png", pngB64),
			`"dup.example":`+icon("image/gif", pngB64),
		)},
		{Name: "icons: standard base64 alphabet only", Endpoint: endpointResponses, Frames: frame(
			`"newline.example":`+icon("image/png", `iVBO\nRw0KGgo=`),
			`"url-safe.example":`+icon("image/png", "iVBO-_w0KGgo="),
			`"triple-pad.example":`+icon("image/png", "iVBORw0KGgo==="),
			`"double-pad.example":`+icon("image/png", "iVBORw0KGg=="),
		)},
		{Name: "icons: host pattern and raster types", Endpoint: endpointResponses, Frames: frame(
			`"Upper.example":`+icon("image/png", pngB64),
			`"[::1]:8080":`+icon("image/x-icon", pngB64),
			`"svg.example":`+icon("image/svg+xml", pngB64),
			`"webp.example":`+icon("image/webp", pngB64),
			`"not-an-object.example":"x"`,
		)},
		{Name: "icons: a host of at most 253 characters", Endpoint: endpointResponses, Frames: frame(
			`"`+strings.Repeat("a", 253)+`":`+icon("image/png", pngB64),
			`"`+strings.Repeat("b", 254)+`":`+icon("image/png", pngB64),
		)},
	}
}

// runEventVector decodes one case's input and records the outcome in the
// vectors' own JSON form, which names every field so a port in another
// language matches it without Go's field names.
func runEventVector(c eventVectorCase) eventVectorCase {
	d := newDecoder(c.Endpoint)
	var evs []Event
	if c.Body != "" {
		evs = d.body([]byte(c.Body))
	} else {
		for _, fr := range c.Frames {
			evs = append(evs, d.frame([]byte(fr))...)
		}
	}
	c.Events = []map[string]any{}
	for _, ev := range evs {
		c.Events = append(c.Events, vectorEvent(ev))
	}
	if done, err := d.outcome(); err != nil {
		e := map[string]any{"kind": string(err.Kind), "code": err.Code, "message": err.Message}
		if pe, ok := err.Err.(*ProviderError); ok {
			e["provider_code"] = pe.Code
		}
		c.End = map[string]any{"error": e}
	} else {
		c.End = map[string]any{"done": map[string]any{
			"finish_reason": done.FinishReason, "incomplete_reason": done.IncompleteReason, "empty": done.Empty,
		}}
	}
	return c
}

func vectorEvent(ev Event) map[string]any {
	m := map[string]any{"type": ev.EventType()}
	raw := func(r json.RawMessage) any {
		if r == nil {
			return nil
		}
		var v any
		_ = json.Unmarshal(r, &v)
		return v
	}
	switch e := ev.(type) {
	case ItemOpened:
		m["item_id"], m["item_type"] = e.Item.ID, e.Item.Type
	case ItemClosed:
		m["item_id"], m["item_type"] = e.Item.ID, e.Item.Type
	case TextDelta:
		m["item_id"], m["delta"] = e.ItemID, e.Delta
	case ReasoningDelta:
		m["item_id"], m["delta"] = e.ItemID, e.Delta
	case ToolCallDelta:
		m["item_id"], m["call_id"], m["name"], m["arguments_delta"] = e.ItemID, e.CallID, e.Name, e.ArgumentsDelta
	case AnnotationAdded:
		m["item_id"], m["annotation"] = e.ItemID, raw(e.Annotation)
	case ToolStatus:
		icons := e.Icons
		if icons == nil {
			icons = map[string]string{}
		}
		m["item_id"], m["call_id"], m["name"], m["state"], m["action"], m["icons"] = e.ItemID, e.CallID, e.Name, string(e.State), raw(e.Action), icons
	case ImageProgress:
		m["item_id"], m["value"], m["max"] = e.ItemID, e.Value, e.Max
	case ImagePartial:
		m["item_id"], m["b64"], m["mime"] = e.ItemID, e.B64, e.MIME
	case Usage:
		m["input_tokens"], m["output_tokens"], m["reasoning_tokens"], m["source"] = e.InputTokens, e.OutputTokens, e.ReasoningTokens, e.Source
	default:
		m["unexpected"] = true
	}
	return m
}

func TestStreamEventVectors(t *testing.T) {
	var got []eventVectorCase
	for _, c := range eventVectorInputs() {
		got = append(got, runEventVector(c))
	}
	out, err := json.MarshalIndent(got, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	out = append(out, '\n')

	if *updateVectors {
		if err := os.WriteFile(eventVectorsPath, out, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(eventVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	// Compare decoded, so formatting is not the contract.
	var a, b any
	if err := json.Unmarshal(want, &a); err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(out, &b)
	wantNorm, _ := json.Marshal(a)
	gotNorm, _ := json.Marshal(b)
	if !bytes.Equal(wantNorm, gotNorm) {
		t.Fatalf("decoder output differs from %s; if the change is intended, regenerate with -update and review the diff", eventVectorsPath)
	}
}
