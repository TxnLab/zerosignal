/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package tokenize

import (
	"bytes"
	"encoding/base64"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"testing"

	prototokenize "github.com/TxnLab/zerosignal/go/tokenize"
)

// The bound itself is tested exhaustively in proto/go/tokenize (golden vectors
// plus a real-tokenizer corpus). What matters here is that SafeEstimator
// DELEGATES rather than carrying its own copy — the copy is what used to drift.
func TestSafeEstimator_DelegatesToProtoBound(t *testing.T) {
	bodies := [][]byte{
		[]byte(`{"messages":[{"role":"user","content":"hello world"}]}`),
		[]byte(`{"messages":[{"role":"user","content":[{"type":"image_url","image_url":{"url":"data:image/png;base64,AA"}}]}]}`),
		[]byte(`{"input":[{"role":"user","content":[{"type":"input_image","detail":"low"}]}]}`),
	}
	for _, body := range bodies {
		est, err := SafeEstimator{}.Estimate(Request{Body: body})
		if err != nil {
			t.Fatalf("estimate: %v", err)
		}
		if want := prototokenize.InputTokenBound(body); est.InputTokens != want {
			t.Errorf("default estimator = %d, want proto v1 bound %d", est.InputTokens, want)
		}
	}
}

// BoundVersion selects which shared bound runs. Dispatch sizes per-operator, so
// this only pins that the field is honoured rather than ignored. The two bounds
// differ only where v2 can read an image's true dimensions, so the body needs a
// real data URL rather than prose.
func TestSafeEstimator_BoundVersion(t *testing.T) {
	body := pngDataURLBody(t, 512, 512)
	v1, err := SafeEstimator{BoundVersion: BoundVersion1}.Estimate(Request{Body: body})
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	v2, err := SafeEstimator{BoundVersion: BoundVersion2}.Estimate(Request{Body: body})
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if v1.InputTokens != prototokenize.InputTokenBound(body) {
		t.Errorf("v1 = %d, want %d", v1.InputTokens, prototokenize.InputTokenBound(body))
	}
	if v2.InputTokens != prototokenize.InputTokenBoundV2(body) {
		t.Errorf("v2 = %d, want %d", v2.InputTokens, prototokenize.InputTokenBoundV2(body))
	}
	if v2.InputTokens >= v1.InputTokens {
		t.Errorf("v2 should be tighter than v1 on a readable 512px image: v1=%d v2=%d",
			v1.InputTokens, v2.InputTokens)
	}
	// The zero value is the wire default — version 1.
	zero, _ := SafeEstimator{}.Estimate(Request{Body: body})
	if zero.InputTokens != v1.InputTokens {
		t.Errorf("zero value must mean v1: got %d want %d", zero.InputTokens, v1.InputTokens)
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

func TestSafeEstimator_MaxOutputFromBody(t *testing.T) {
	body := []byte(`{"max_completion_tokens":256}`)
	est, err := SafeEstimator{}.Estimate(Request{Body: body})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.MaxOutputTokens != 256 {
		t.Fatalf("MaxOutputTokens = %d, want 256", est.MaxOutputTokens)
	}
}

// Regression at this layer: a large base64 data URL was once counted BOTH as
// text (len(body)/2) and as image tile tokens, inflating an image request's
// reservation ~200x. Both bound versions must exclude the URL bytes.
func TestSafeEstimator_DataURLNotDoubleCounted(t *testing.T) {
	const payloadSize = 200_000
	pad := strings.Repeat("A", payloadSize)
	body := []byte(`{"input":[{"role":"user","content":[` +
		`{"type":"input_image","image_url":"data:image/png;base64,` + pad + `","detail":"high"}` +
		`]}]}`)

	for _, v := range []uint8{BoundVersion1, BoundVersion2} {
		est, err := SafeEstimator{BoundVersion: v}.Estimate(Request{Body: body})
		if err != nil {
			t.Fatalf("v%d estimate: %v", v, err)
		}
		if est.InputTokens > uint64(payloadSize/2) {
			t.Fatalf("v%d InputTokens = %d looks like the data URL was counted as text (payload=%d)",
				v, est.InputTokens, payloadSize)
		}
		// The tile cost must still be there on top of the (now tiny) text bound.
		if est.InputTokens < 85+170 {
			t.Fatalf("v%d InputTokens = %d dropped the image contribution entirely", v, est.InputTokens)
		}
	}
}

func TestSafeEstimator_UnparseableBody(t *testing.T) {
	// A body that isn't JSON surfaces as a tokenize error — dispatch
	// turns this into 502 proxy_error rather than guessing past it.
	// The real defense is that the node would reject the same body
	// with 400; we want both sides to agree the request is broken.
	body := []byte("not json at all")
	if _, err := (SafeEstimator{}).Estimate(Request{Body: body}); err == nil {
		t.Fatalf("expected error for non-JSON body")
	}
}

func TestExtractMaxOutput(t *testing.T) {
	tests := []struct {
		name string
		body string
		want uint64
	}{
		{"none", `{}`, 0},
		{"max_tokens", `{"max_tokens":100}`, 100},
		{"max_completion_tokens", `{"max_completion_tokens":200}`, 200},
		{"max_output_tokens", `{"max_output_tokens":300}`, 300},
		{"completion_wins", `{"max_tokens":100,"max_completion_tokens":200}`, 200},
	}
	for _, tc := range tests {
		got, err := extractMaxOutput([]byte(tc.body))
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: got %d want %d", tc.name, got, tc.want)
		}
	}
}

func TestRegistry_LookupReturnsDefault(t *testing.T) {
	reg := NewRegistry()
	if reg.Lookup("nope") == nil {
		t.Fatalf("default tokenizer should never be nil")
	}
	reg.Register("fake", fakeTokenizer{out: 7})
	est, err := reg.Lookup("fake").Estimate(Request{})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.InputTokens != 7 {
		t.Fatalf("override not honored: %d", est.InputTokens)
	}
}

func TestRegistry_DefaultMaxOutput(t *testing.T) {
	reg := NewRegistry()
	if _, ok := reg.DefaultMaxOutput("x"); ok {
		t.Fatalf("unset default should not be ok")
	}
	reg.SetDefaultMaxOutput("x", 512)
	n, ok := reg.DefaultMaxOutput("x")
	if !ok || n != 512 {
		t.Fatalf("got %d ok=%v want 512 true", n, ok)
	}
	reg.SetDefaultMaxOutput("x", 0)
	if _, ok := reg.DefaultMaxOutput("x"); ok {
		t.Fatalf("zero should clear default")
	}
}

func TestEstimateWithRegistry_DefaultKicksIn(t *testing.T) {
	reg := NewRegistry()
	reg.Register("m", fakeTokenizer{out: 42})
	reg.SetDefaultMaxOutput("m", 777)
	est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`), Endpoint: EndpointChatCompletions})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.InputTokens != 42 || est.MaxOutputTokens != 777 {
		t.Fatalf("got %+v want input=42 max=777", est)
	}
}

func TestEstimateWithRegistry_BodyWinsOverDefault(t *testing.T) {
	reg := NewRegistry()
	reg.Register("m", fakeTokenizer{out: 10, maxOut: 500})
	reg.SetDefaultMaxOutput("m", 999)
	est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`)})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.MaxOutputTokens != 500 {
		t.Fatalf("body should win: got %d", est.MaxOutputTokens)
	}
}

func TestEstimateWithRegistry_MaxOutputRequired(t *testing.T) {
	reg := NewRegistry()
	reg.Register("m", fakeTokenizer{out: 10, maxOut: 0})
	_, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`)})
	if !errors.Is(err, ErrMaxOutputRequired) {
		t.Fatalf("expected ErrMaxOutputRequired, got %v", err)
	}
}

func TestEstimateWithRegistry_UnknownModelGetsDefault(t *testing.T) {
	// An empty registry must NOT reject unknown models — escrow settles
	// for actual usage so any model gets the safe estimator.
	// But a missing default max output still trips ErrMaxOutputRequired.
	reg := NewRegistry()
	_, err := EstimateWithRegistry(reg, Request{Model: "anything", Body: []byte(`{}`)})
	if !errors.Is(err, ErrMaxOutputRequired) {
		t.Fatalf("expected ErrMaxOutputRequired for unknown model with no default, got %v", err)
	}
	// With a default in place, the request goes through.
	reg.SetDefaultMaxOutput("anything", 256)
	est, err := EstimateWithRegistry(reg, Request{Model: "anything", Body: []byte(`{"hi":1}`)})
	if err != nil {
		t.Fatalf("with default: %v", err)
	}
	if est.MaxOutputTokens != 256 {
		t.Fatalf("MaxOutputTokens = %d, want 256", est.MaxOutputTokens)
	}
	if est.InputTokens == 0 {
		t.Fatalf("InputTokens should be non-zero")
	}
}

func TestBuildRegistry_LoadsDefaults(t *testing.T) {
	reg := BuildRegistry(map[string]uint64{
		"a": 64,
		"b": 128,
		"c": 0, // zero entries should not be stored
	}, 0)
	if n, ok := reg.DefaultMaxOutput("a"); !ok || n != 64 {
		t.Errorf("a: got %d ok=%v want 64 true", n, ok)
	}
	if n, ok := reg.DefaultMaxOutput("b"); !ok || n != 128 {
		t.Errorf("b: got %d ok=%v want 128 true", n, ok)
	}
	if _, ok := reg.DefaultMaxOutput("c"); ok {
		t.Errorf("c: zero entry should have been skipped")
	}
}

func TestEstimateWithRegistry_FallbackKicksIn(t *testing.T) {
	// No per-model default, but a global fallback is configured: an
	// omitting request gets the fallback instead of ErrMaxOutputRequired.
	reg := BuildRegistry(nil, 4096)
	est, err := EstimateWithRegistry(reg, Request{Model: "anything", Body: []byte(`{"hi":1}`)})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.MaxOutputTokens != 4096 {
		t.Fatalf("MaxOutputTokens = %d, want 4096 (fallback)", est.MaxOutputTokens)
	}
}

func TestEstimateWithRegistry_PerModelBeatsFallback(t *testing.T) {
	reg := BuildRegistry(map[string]uint64{"m": 256}, 4096)
	est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`)})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.MaxOutputTokens != 256 {
		t.Fatalf("per-model default should win over fallback: got %d", est.MaxOutputTokens)
	}
}

func TestEstimateWithRegistry_BodyBeatsFallback(t *testing.T) {
	reg := BuildRegistry(nil, 4096)
	reg.Register("m", fakeTokenizer{out: 10, maxOut: 500})
	est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`)})
	if err != nil {
		t.Fatalf("estimate: %v", err)
	}
	if est.MaxOutputTokens != 500 {
		t.Fatalf("body should win over fallback: got %d", est.MaxOutputTokens)
	}
}

func TestEstimateWithRegistry_ZeroFallbackFailsClosed(t *testing.T) {
	// A fallback of 0 preserves the fail-closed behavior.
	reg := BuildRegistry(nil, 0)
	_, err := EstimateWithRegistry(reg, Request{Model: "anything", Body: []byte(`{}`)})
	if !errors.Is(err, ErrMaxOutputRequired) {
		t.Fatalf("expected ErrMaxOutputRequired with zero fallback, got %v", err)
	}
}

// TestEstimateWithRegistry_DeriveModeFlags pins WHEN the estimate switches to
// per-operator derive mode: only the omitted-and-no-per-model-default path (case
// 3) sets DeriveMaxOutput; a caller-specified max, a per-model default, and the
// fail-closed path all leave it flat. MaxOutputCeiling carries the fallback for
// the reserve leg's DeriveMaxOutput call.
func TestEstimateWithRegistry_DeriveModeFlags(t *testing.T) {
	t.Run("omitted_no_default_derives", func(t *testing.T) {
		reg := BuildRegistry(nil, 8192)
		est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{"hi":1}`)})
		if err != nil {
			t.Fatalf("estimate: %v", err)
		}
		if !est.DeriveMaxOutput {
			t.Fatalf("omitted max + fallback should derive per-operator")
		}
		if est.MaxOutputCeiling != 8192 || est.MaxOutputTokens != 8192 {
			t.Fatalf("ceiling/display = %d/%d, want 8192/8192", est.MaxOutputCeiling, est.MaxOutputTokens)
		}
	})
	t.Run("caller_specified_is_flat", func(t *testing.T) {
		reg := BuildRegistry(nil, 8192)
		reg.Register("m", fakeTokenizer{out: 10, maxOut: 500})
		est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`)})
		if err != nil {
			t.Fatalf("estimate: %v", err)
		}
		if est.DeriveMaxOutput || est.MaxOutputTokens != 500 {
			t.Fatalf("caller-specified must stay flat: derive=%v max=%d", est.DeriveMaxOutput, est.MaxOutputTokens)
		}
	})
	t.Run("per_model_default_is_flat", func(t *testing.T) {
		reg := BuildRegistry(map[string]uint64{"m": 256}, 8192)
		est, err := EstimateWithRegistry(reg, Request{Model: "m", Body: []byte(`{}`)})
		if err != nil {
			t.Fatalf("estimate: %v", err)
		}
		if est.DeriveMaxOutput || est.MaxOutputTokens != 256 {
			t.Fatalf("per-model default must stay flat: derive=%v max=%d", est.DeriveMaxOutput, est.MaxOutputTokens)
		}
	})
}

// fakeTokenizer is a non-network implementation used by registry tests.
type fakeTokenizer struct {
	out    uint64
	maxOut uint64
}

func (f fakeTokenizer) Estimate(_ Request) (Estimate, error) {
	return Estimate{InputTokens: f.out, MaxOutputTokens: f.maxOut}, nil
}
