/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	prototokenize "github.com/TxnLab/zerosignal/go/tokenize"
)

func TestReserveInputCount(t *testing.T) {
	op := Operator{
		ModelCapacities: map[string]ModelCapacity{
			"big":   {ContextWindow: 1_000_000},
			"nowin": {},
		},
		MaxToolIters:             10,
		ToolHeadroomPerIteration: 4000,
	}
	plain := []byte(`{"model":"big","messages":[{"role":"user","content":"a small question"}]}`)
	plainBound := prototokenize.InputTokenBound(plain)
	// The floor applies when the body bound is below reserveMinInputCount.
	wantPlain := plainBound
	if wantPlain < reserveMinInputCount {
		wantPlain = reserveMinInputCount
	}

	// Plain question against a 1M model: no tools → the (floored) body bound,
	// NOT the full window. This is the headline fix — a few hundred tokens
	// reserved instead of ~1M.
	if got, _ := reserveInputCount(op, "big", plain, 4096); got != wantPlain {
		t.Errorf("plain reserve = %d, want %d (floored body bound, not the full window)", got, wantPlain)
	}
	// The floor's value, as a literal: zs-node v0.25.0 and earlier sign 256 for
	// a short request, and anything below 256/1.1 here fails their tickets'
	// input_count_bound. The client's RESERVE_MIN_INPUT_COUNT is the same 256.
	empty := []byte(`{"messages":[]}`)
	if got, _ := reserveInputCount(op, "big", empty, 4096); got != 256 {
		t.Errorf("empty-body reserve = %d, want the 256 floor", got)
	}

	// zs_ built-in: the NODE runs the chat→tool→chat loop, so the conversation
	// grows inside this one reserve — bound + MaxToolIters × headroom = +40000.
	withZs := []byte(`{"model":"big","messages":[{"role":"user","content":"go"}],"tools":[{"type":"zs_web_search"}]}`)
	zsBound := prototokenize.InputTokenBound(withZs)
	if got, _ := reserveInputCount(op, "big", withZs, 4096); got != zsBound+10*4000 {
		want := zsBound + 10*4000
		t.Errorf("zs_ tool reserve = %d, want %d (bound + iters×headroom)", got, want)
	}

	// Vendor-hosted tool: the UPSTREAM re-prefills each result into the context
	// inside a single completion, so the headroom still applies. mcp carries no
	// per-call fee and must STILL reserve — context inflation and per-call
	// pricing are separate axes.
	for _, hosted := range []string{"web_search", "mcp"} {
		body := []byte(`{"model":"big","messages":[{"role":"user","content":"go"}],"tools":[{"type":"` + hosted + `"}]}`)
		bound := prototokenize.InputTokenBound(body)
		if got, _ := reserveInputCount(op, "big", body, 4096); got != bound+10*4000 {
			want := bound + 10*4000
			t.Errorf("hosted %q reserve = %d, want %d (bound + iters×headroom)", hosted, got, want)
		}
	}

	// Caller-executed tools drive NO growth on the serving side: the agent runs
	// the tool and re-issues, and that request is measured and paid for on its
	// own. This is the coding-agent / client-side-MCP case — Claude Code and
	// friends expand their MCP servers into plain function tools before sending.
	// Reserving iters×headroom for it saturates back to the full context window
	// on most models, which is the full-window lock this sizing exists to avoid.
	callerExecuted := []string{
		`{"type":"function","function":{"name":"x"}}`,
		`{"type":"local_shell"}`,
		`{"type":"apply_patch"}`,
		`{"type":"computer_use"}`,
		`{"type":"bash_20250124"}`,
		`{"type":"text_editor_20250124"}`,
	}
	for _, entry := range callerExecuted {
		body := []byte(`{"model":"big","messages":[{"role":"user","content":"go"}],"tools":[` + entry + `]}`)
		bound := prototokenize.InputTokenBound(body)
		want := bound // these bodies are tiny, so the floor is what actually lands
		if want < reserveMinInputCount {
			want = reserveMinInputCount
		}
		if got, _ := reserveInputCount(op, "big", body, 4096); got != want {
			t.Errorf("caller-executed %s reserve = %d, want %d (no headroom)", entry, got, want)
		}
	}

	// A mixed body takes the headroom: one growth-driving tool is enough.
	mixed := []byte(`{"model":"big","messages":[{"role":"user","content":"go"}],"tools":[{"type":"function","function":{"name":"x"}},{"type":"zs_web_search"}]}`)
	mixedBound := prototokenize.InputTokenBound(mixed)
	if got, _ := reserveInputCount(op, "big", mixed, 4096); got != mixedBound+10*4000 {
		want := mixedBound + 10*4000
		t.Errorf("mixed reserve = %d, want %d (a zs_ tool among function tools still loops)", got, want)
	}

	// A body whose bound exceeds the window is capped at contextWindow − max_output.
	huge := []byte(`{"model":"big","messages":[{"role":"user","content":"` +
		strings.Repeat("x", 4_000_000) + `"}]}`)
	if got, _ := reserveInputCount(op, "big", huge, 4096); got != uint64(1_000_000-4096) {
		t.Errorf("capped reserve = %d, want %d", got, uint64(1_000_000-4096))
	}

	// previous_response_id chain reserves the full worst case.
	chain := []byte(`{"model":"big","previous_response_id":"resp_1","input":[{"role":"user","content":"next"}]}`)
	if got, _ := reserveInputCount(op, "big", chain, 4096); got != uint64(1_000_000-4096) {
		t.Errorf("chain reserve = %d, want %d (full window)", got, uint64(1_000_000-4096))
	}

	// No declared window: falls through to the (floored) body bound.
	if got, _ := reserveInputCount(op, "nowin", plain, 4096); got != wantPlain {
		t.Errorf("no-window reserve = %d, want %d", got, wantPlain)
	}
}

// TestReserveInputCountBoundVersionGate pins the per-operator bound selection.
//
// The gate is asymmetric and that asymmetry is the whole point. v2 reads an
// image's true dimensions instead of v1's flat 2048x2048 fallback, so it is
// smaller for an ordinary paste and LARGER for anything above the fallback.
// Sizing v2 against a pre-9.2 node therefore risks a hard failure — the node
// measures the same body with v1 and can see the reserve as under-declared —
// while sizing v1 against a 9.2 node merely mis-sizes. So the gate must fail
// toward v1 on anything it cannot positively establish as >= 9.2.
func TestReserveInputCountBoundVersionGate(t *testing.T) {
	body := pngDataURLBody(t, 512, 512)

	newOp := func(version string) Operator {
		return Operator{
			ProtoVersion:    version,
			ModelCapacities: map[string]ModelCapacity{"big": {ContextWindow: 1_000_000}},
		}
	}

	for _, tc := range []struct {
		name    string
		version string
		want    uint8
	}{
		{"9.2 target uses v2", "9.2", prototokenize.BoundVersion2},
		{"newer minor uses v2", "9.7", prototokenize.BoundVersion2},
		{"9.1 target stays on v1", "9.1", prototokenize.BoundVersion1},
		{"9.0 target stays on v1", "9.0", prototokenize.BoundVersion1},
		{"unprobed peer stays on v1", "", prototokenize.BoundVersion1},
		{"unparseable version stays on v1", "not-a-version", prototokenize.BoundVersion1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, version := reserveInputCount(newOp(tc.version), "big", body, 4096)
			if version != tc.want {
				t.Fatalf("bound version = %d, want %d", version, tc.want)
			}
			wantCount := prototokenize.InputTokenBoundVersion(body, tc.want)
			if wantCount < reserveMinInputCount {
				wantCount = reserveMinInputCount
			}
			if got != wantCount {
				t.Errorf("count = %d, want %d (the %d bound)", got, wantCount, tc.want)
			}
		})
	}

	// The tightening is real: on an ordinary pasted image, a 9.2 target reserves
	// strictly less than the 2048x2048 fallback would.
	v1Count, _ := reserveInputCount(newOp("9.1"), "big", body, 4096)
	v2Count, _ := reserveInputCount(newOp("9.2"), "big", body, 4096)
	if v2Count >= v1Count {
		t.Errorf("a 9.2 target should reserve less for a 512px image: v1=%d v2=%d", v1Count, v2Count)
	}
}

// pngDataURLBody builds a request body carrying one PNG of the given size as a
// data URL. Real bytes are needed because v1 and v2 differ only where v2 can
// READ the dimensions out of the header: v1 charges its flat 2048x2048 fallback
// (2805 tokens) for any image the caller didn't annotate, so a small image makes
// v2 smaller and an image above 2048x2048 makes v2 LARGER.
func pngDataURLBody(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{uint8(x % 256), uint8(y % 256), 128, 255})
		}
	}
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatalf("encode png: %v", err)
	}
	return []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url",` +
		`"image_url":{"url":"data:image/png;base64,` +
		base64.StdEncoding.EncodeToString(buf.Bytes()) + `"}}]}]}`)
}
