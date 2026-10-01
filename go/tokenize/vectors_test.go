/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize_test

// Cross-impl byte-parity test for the reserve-sizing bound. Generates /
// verifies proto/testdata/tokenize_vectors.json — a language-neutral
// fixture that pins InputTokenBound and ReserveInputCount. proto/ts loads
// the same file and asserts equality, so any drift between the Go
// (node enforcement / proxy sizing) and TS (client sizing) implementations
// fails on both sides. The bound MUST match across languages or the node's
// inference-time budget check would reject an honest client's request.
//
// To regenerate after an intentional change:
//
//	cd proto/go && go test ./tokenize -run TestVectors -update
//
// Without -update, this test asserts the on-disk file matches what the
// current code produces and fails with a regen hint otherwise.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/tokenize"
)

var updateVectors = flag.Bool("update", false, "regenerate proto/testdata/tokenize_vectors.json")

const tokenizeVectorsPath = "../../testdata/tokenize_vectors.json"

type inputBoundVector struct {
	Name     string `json:"name"`
	BodyHex  string `json:"body_hex"`
	Expected uint64 `json:"expected"`
	// ExpectedV2 pins InputTokenBoundV2 for the same body. v2 is not uniformly
	// smaller than v1 — it is larger on images above the 2048x2048 fallback —
	// so both are pinned separately.
	ExpectedV2 uint64 `json:"expected_v2"`
	// V1Divergent marks a body where the two v1 implementations are KNOWN to
	// disagree with each other. `expected` then records only what Go produces
	// and the TS side skips the v1 assertion; `expected_v2` is still a strict
	// parity contract.
	//
	// These are pre-existing v1 defects that the adversarial bodies surfaced,
	// left unfixed on purpose: v1 is the compatibility floor every pre-9.2 node
	// and caller computes. Fixing it would make a NEW caller disagree with a
	// DEPLOYED node on inputs where they currently agree — trading a rare
	// existing failure for a new one. v2 handles all of these correctly; the
	// flag exists so the hole is recorded rather than hidden by omitting the
	// body from the fixture.
	V1Divergent bool `json:"v1_divergent,omitempty"`
}

// corpusBoundVector pins both bounds over a calibration-corpus sample, keyed by
// file name rather than inline hex: the samples run to tens of kilobytes
// (real PNG/JPEG/WebP payloads) and inlining them would bloat the fixture. This
// is what cross-checks the image header parser between Go and TS — a format
// whose dimensions one side reads and the other doesn't shows up here as a
// mismatch rather than as rejected requests in production.
type corpusBoundVector struct {
	Sample     string `json:"sample"`
	Expected   uint64 `json:"expected"`
	ExpectedV2 uint64 `json:"expected_v2"`
}

type reserveInputCountVector struct {
	Name              string `json:"name"`
	BodyBound         uint64 `json:"body_bound"`
	CarriesTools      bool   `json:"carries_tools"`
	MaxToolIterations uint64 `json:"max_tool_iterations"`
	PerIterHeadroom   uint64 `json:"per_iter_headroom"`
	MaxOutput         uint64 `json:"max_output"`
	ContextWindow     uint64 `json:"context_window"`
	Floor             uint64 `json:"floor"`
	Expected          uint64 `json:"expected"`
}

type tokenizeVectorsFile struct {
	Version           int                       `json:"version"`
	Comment           string                    `json:"comment"`
	InputTokenBound   []inputBoundVector        `json:"input_token_bound"`
	CorpusBound       []corpusBoundVector       `json:"corpus_bound"`
	ReserveInputCount []reserveInputCountVector `json:"reserve_input_count"`
}

// boundBodies are the fixed inputs for the InputTokenBound vectors. Keeping
// them as literal JSON strings makes the fixture human-auditable; the hex is
// derived at build time.
var boundBodies = []struct {
	name string
	body string
}{
	{"empty", ""},
	{"plain_text", `{"model":"m","messages":[{"role":"user","content":"hello world, this is a small question"}]}`},
	{"chat_nested_image_high", `{"messages":[{"role":"user","content":[{"type":"text","text":"describe"},{"type":"image_url","image_url":{"url":"https://example.com/cat.png","detail":"high","width":1024,"height":768}}]}]}`},
	{"responses_input_image_low", `{"input":[{"role":"user","content":[{"type":"input_image","image_url":"https://example.com/dog.png","detail":"low"}]}]}`},
	{"image_no_dims_default", `{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AAAA"}}]}]}`},
	{"not_json", `this is not json at all — raw bytes`},
}

// adversarialBodies pin Go/TS agreement on inputs that a hand-written mirror
// gets wrong. Every one of these was a REAL divergence found by differential
// fuzzing after the first version of this fixture shipped green — the fixture
// had no `data:` URL in it at all, so the entire image path was uncovered.
// Bodies are built programmatically because several need bytes that don't
// survive as JSON string literals.
func adversarialBodies(t *testing.T) []struct {
	name string
	body []byte
} {
	t.Helper()
	png := smallPNG(t, 1024, 768)
	flat := base64.StdEncoding.EncodeToString(png)

	// MIME-wrapped base64: Go's decoder silently skips newlines, @scure/base
	// rejects them, so this read true dimensions on one side and the fallback on
	// the other. It is what Java's MIME encoder and `openssl base64` emit.
	var wrapped strings.Builder
	for i := 0; i < len(flat); i += 76 {
		end := i + 76
		if end > len(flat) {
			end = len(flat)
		}
		wrapped.WriteString(flat[i:end])
		wrapped.WriteString(`\n`)
	}

	imgBody := func(url string, extra string) []byte {
		return []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url"` +
			extra + `,"image_url":{"url":"` + url + `"}}]}]}`)
	}

	// Nested dimensions of 0 must not erase the outer value: Go used to adopt
	// any numeric nested value, TS only positives.
	nestedZero := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url",` +
		`"width":1000,"height":1000,"image_url":{"url":"https://x/y.png","width":0,"height":0}}]}]}`)
	// A dimension far above the clamp. Deliberately 1e9 and not something like
	// 1e19: v2 clamps either one, but v1 has NO clamp and its unbounded tile
	// math overflows differently in each language once the value leaves int
	// range (see TestV1DivergesOnOutOfRangeDimension). This fixture is a strict
	// parity contract for BOTH versions, so it stays inside the range where v1
	// is well-defined.
	hugeDim := []byte(`{"model":"m","messages":[{"role":"user","content":[{"type":"image_url",` +
		`"width":1e9,"height":1e9,"image_url":{"url":"https://x/y.png"}}]}]}`)

	deep := `{"a":` + strings.Repeat(`[`, 600) + `"x"` + strings.Repeat(`]`, 600) + `}`

	return []struct {
		name string
		body []byte
	}{
		{"img_png_flat_base64", imgBody("data:image/png;base64,"+flat, "")},
		{"img_png_mime_wrapped", imgBody("data:image/png;base64,"+wrapped.String(), "")},
		{"img_png_leading_newline", imgBody(`data:image/png;base64,\n`+flat, "")},
		{"img_gif_untrusted_header", imgBody("data:image/gif;base64,"+
			base64.StdEncoding.EncodeToString(tinyGIFClaiming1x1(t)), "")},
		{"img_nested_zero_dims", nestedZero},
		{"img_huge_dims", hugeDim},
		// All-padding payload: the TS trailing-'=' strip was a catastrophic
		// backtracking regex, 2.8s per part at this length.
		{"img_all_padding", imgBody("data:image/png;base64,"+strings.Repeat("=", 4096)+"A", "")},
		{"img_low_detail_wins", imgBody("data:image/png;base64,"+flat, `,"detail":"low"`)},
		{"bom_prefixed", append([]byte{0xEF, 0xBB, 0xBF}, []byte(`{"model":"m","messages":[{"role":"user","content":"hello world"}]}`)...)},
		{"number_out_of_float64_range", []byte(`{"model":"m","temperature":1e309,"messages":[{"role":"user","content":"hi"}]}`)},
		{"deeply_nested", []byte(deep)},
	}
}

// v1DivergentBodies names the adversarial bodies where Go's and TypeScript's v1
// implementations disagree with each other. See inputBoundVector.V1Divergent.
//
//   - img_nested_zero_dims: Go's v1 adopts a nested width/height of 0 and falls
//     back to 2048x2048 (2910); TS's v1 ignores non-positive values and keeps the
//     outer 1000x1000 (870). Go is the node, so it measures MORE than the client
//     reserved — a rejection. v2 fixes this with one shared "below 1 reads as
//     absent" rule.
var v1DivergentBodies = map[string]bool{
	"img_nested_zero_dims": true,
}

// smallPNG builds a real PNG of the given size (smooth, so it stays small).
func smallPNG(t *testing.T, w, h int) []byte {
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
	return buf.Bytes()
}

// tinyGIFClaiming1x1 is a GIF whose Logical Screen Descriptor says 1x1 while the
// frame is larger — the shape that let a payer under-reserve 36x before GIF was
// dropped from the sniffer. The bound must charge the fallback here.
func tinyGIFClaiming1x1(t *testing.T) []byte {
	t.Helper()
	return []byte("GIF89a\x01\x00\x01\x00\xf0\x00\x00" +
		"\x00\x00\x00\xff\xff\xff,\x00\x00\x00\x00\x00\x10\x00\x10\x00\x00;")
}

func reserveCases() []reserveInputCountVector {
	return []reserveInputCountVector{
		{Name: "plain_no_tools", BodyBound: 500, CarriesTools: false, MaxToolIterations: 20, PerIterHeadroom: 4000, MaxOutput: 4096, ContextWindow: 1_000_000, Floor: 256},
		{Name: "tools_add_headroom", BodyBound: 500, CarriesTools: true, MaxToolIterations: 20, PerIterHeadroom: 4000, MaxOutput: 4096, ContextWindow: 1_000_000, Floor: 256},
		{Name: "clamp_at_window", BodyBound: 2_000_000, CarriesTools: false, MaxToolIterations: 20, PerIterHeadroom: 4000, MaxOutput: 4096, ContextWindow: 1_000_000, Floor: 256},
		{Name: "floor_no_window", BodyBound: 10, CarriesTools: false, MaxToolIterations: 0, PerIterHeadroom: 0, MaxOutput: 100, ContextWindow: 0, Floor: 256},
		{Name: "cap_beats_floor", BodyBound: 10, CarriesTools: false, MaxToolIterations: 0, PerIterHeadroom: 0, MaxOutput: 8000, ContextWindow: 8100, Floor: 256},
		{Name: "no_window_tools", BodyBound: 1000, CarriesTools: true, MaxToolIterations: 5, PerIterHeadroom: 4000, MaxOutput: 1024, ContextWindow: 0, Floor: 256},
		{Name: "window_le_maxoutput", BodyBound: 100, CarriesTools: false, MaxToolIterations: 0, PerIterHeadroom: 0, MaxOutput: 5000, ContextWindow: 4096, Floor: 256},
	}
}

// corpusBoundVectors pins both bounds over every calibration-corpus sample.
// Sorted by name so the fixture is stable across filesystems.
func corpusBoundVectors(t *testing.T) []corpusBoundVector {
	t.Helper()
	entries, err := os.ReadDir(corpusDirPath)
	if err != nil {
		t.Fatalf("read corpus dir: %v", err)
	}
	out := make([]corpusBoundVector, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(corpusDirPath, e.Name()))
		if err != nil {
			t.Fatalf("read corpus sample %s: %v", e.Name(), err)
		}
		out = append(out, corpusBoundVector{
			Sample:     strings.TrimSuffix(e.Name(), ".json"),
			Expected:   tokenize.InputTokenBound(body),
			ExpectedV2: tokenize.InputTokenBoundV2(body),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sample < out[j].Sample })
	return out
}

func buildTokenizeVectors(t *testing.T) *tokenizeVectorsFile {
	t.Helper()
	bounds := make([]inputBoundVector, 0, len(boundBodies))
	for _, b := range boundBodies {
		body := []byte(b.body)
		bounds = append(bounds, inputBoundVector{
			Name:       b.name,
			BodyHex:    hex.EncodeToString(body),
			Expected:   tokenize.InputTokenBound(body),
			ExpectedV2: tokenize.InputTokenBoundV2(body),
		})
	}
	for _, b := range adversarialBodies(t) {
		bounds = append(bounds, inputBoundVector{
			Name:        b.name,
			BodyHex:     hex.EncodeToString(b.body),
			Expected:    tokenize.InputTokenBound(b.body),
			ExpectedV2:  tokenize.InputTokenBoundV2(b.body),
			V1Divergent: v1DivergentBodies[b.name],
		})
	}
	rc := reserveCases()
	for i := range rc {
		c := &rc[i]
		c.Expected = tokenize.ReserveInputCount(c.BodyBound, c.CarriesTools, c.MaxToolIterations, c.PerIterHeadroom, c.MaxOutput, c.ContextWindow, c.Floor)
	}
	return &tokenizeVectorsFile{
		Version: 2,
		Comment: "Cross-impl parity vectors for reserve input-token sizing, both bound versions. " +
			"Regenerate via: cd proto/go && go test ./tokenize -run TestVectors -update. " +
			"Loaded by proto/go/tokenize/vectors_test.go and proto/ts/test/tokenize-vectors.test.ts. " +
			"corpus_bound entries reference proto/testdata/tokenize_corpus/<sample>.json.",
		InputTokenBound:   bounds,
		CorpusBound:       corpusBoundVectors(t),
		ReserveInputCount: rc,
	}
}

func TestVectors(t *testing.T) {
	want := buildTokenizeVectors(t)
	encoded, err := json.MarshalIndent(want, "", "  ")
	if err != nil {
		t.Fatalf("marshal vectors: %v", err)
	}
	encoded = append(encoded, '\n')

	if *updateVectors {
		if err := os.WriteFile(tokenizeVectorsPath, encoded, 0o644); err != nil {
			t.Fatalf("write vectors: %v", err)
		}
		t.Logf("wrote %s", tokenizeVectorsPath)
		return
	}

	onDisk, err := os.ReadFile(tokenizeVectorsPath)
	if err != nil {
		t.Fatalf("read vectors (regenerate with -update): %v", err)
	}
	if !bytes.Equal(bytes.TrimRight(onDisk, "\n"), bytes.TrimRight(encoded, "\n")) {
		t.Fatalf("%s is stale — regenerate with: cd proto/go && go test ./tokenize -run TestVectors -update", tokenizeVectorsPath)
	}
}
