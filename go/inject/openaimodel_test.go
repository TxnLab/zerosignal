/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package inject

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// The wire shape is a cross-repo contract — the proxy and the node both serve
// it and third-party clients decode it — so it is pinned as a literal here
// rather than assembled from the struct under test, which would rename right
// along with a typo.
func TestOpenAIModelFromDetails_WireShape(t *testing.T) {
	d := OperatorDetailsModel{
		ID:                    "google/gemma-5.2",
		InputRateUSDPer1M:     0.1,
		OutputRateUSDPer1M:    0.4,
		CacheReadRateUSDPer1M: new(0.01),
		ContextWindow:         131072,
		MaxOutputTokens:       32768,
		InputModalities:       []string{"text", "image"},
		OutputModalities:      []string{"text"},
		Reasoning:             &ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}, DefaultEffort: "low"},
		ToolUse:               new(true),
		Source:                "hf:google/gemma-5.2@abc123",
	}

	got, err := json.Marshal(OpenAIModelFromDetails(d, "zerosignal", 0))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"id":"google/gemma-5.2","object":"model","created":0,"owned_by":"zerosignal",` +
		`"hugging_face_id":"google/gemma-5.2","context_length":131072,` +
		`"architecture":{"input_modalities":["text","image"],"output_modalities":["text"]},` +
		`"pricing":{"prompt":"0.0000001","completion":"0.0000004","input_cache_read":"0.00000001"},` +
		`"top_provider":{"context_length":131072,"max_completion_tokens":32768},` +
		`"reasoning":{"supported":true,"allowed_efforts":["low","high"],"default_effort":"low"},` +
		`"tool_use":true}`
	if string(got) != want {
		t.Errorf("json =\n %s\nwant\n %s", got, want)
	}
}

// A model with nothing advertised must still produce OpenAI's four official
// fields plus a pricing object — an absent `pricing` would read as "unpriced"
// where a free model is a real thing an operator advertises.
func TestOpenAIModelFromDetails_BareModelKeepsOfficialFieldsAndPricing(t *testing.T) {
	got, err := json.Marshal(OpenAIModelFromDetails(OperatorDetailsModel{ID: "m"}, "operator", 1700000000))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"id":"m","object":"model","created":1700000000,"owned_by":"operator",` +
		`"pricing":{"prompt":"0","completion":"0"}}`
	if string(got) != want {
		t.Errorf("json = %s, want %s", got, want)
	}
}

// The nil-vs-zero rule on the cache-read rate is the one place a "0" and an
// absent field mean different things, so assert BOTH directions — asserting
// only the omission would pass on a builder that never sets the field at all.
func TestOpenAIModelFromDetails_FreeCacheReadIsZeroNotOmitted(t *testing.T) {
	free := OpenAIModelFromDetails(OperatorDetailsModel{ID: "m", CacheReadRateUSDPer1M: new(0.0)}, "operator", 0)
	if free.Pricing.InputCacheRead != "0" {
		t.Errorf("free cache read = %q, want %q", free.Pricing.InputCacheRead, "0")
	}
	raw, err := json.Marshal(free)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded struct {
		Pricing map[string]string `json:"pricing"`
	}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := decoded.Pricing["input_cache_read"]; !ok {
		t.Errorf("free cache read was omitted from %s", raw)
	}

	undiscounted := OpenAIModelFromDetails(OperatorDetailsModel{ID: "m"}, "operator", 0)
	if undiscounted.Pricing.InputCacheRead != "" {
		t.Errorf("undiscounted cache read = %q, want omitted", undiscounted.Pricing.InputCacheRead)
	}
}

func TestUSDPerToken(t *testing.T) {
	tests := []struct {
		name     string
		usdPer1M float64
		want     string
	}{
		// The first three are the float-noise regression: dividing by 1e6 in
		// float64 renders 0.1 as "0.00000010000000000000001", 0.4 as
		// "0.00000040000000000000003", and 3 as "0.0000030000000000000004".
		{"typical", 0.1, "0.0000001"},
		{"typical output rate", 0.4, "0.0000004"},
		{"whole dollars", 3, "0.000003"},
		{"large", 75, "0.000075"},
		{"three significant decimals", 0.375, "0.000000375"},
		{"free", 0, "0"},
		// Scientific notation parses fine but is not what a consumer of this
		// schema has ever been handed; a tiny rate must still render decimal.
		{"tiny stays decimal", 0.0001, "0.0000000001"},
		// Above $1/token the point lands inside the integer digits — the other
		// branch of the shift, and the one where a trailing-zero bug shows.
		{"one dollar per token", 1000000, "1"},
		{"trailing zeros trimmed", 2500000, "2.5"},
		{"fraction crosses the point", 1234.5, "0.0012345"},
		// Exactly six integer digits puts the point at 0 — the branch boundary.
		// Relaxing `point > 0` to `>= 0` emits ".1" here and nothing else moves.
		{"point lands at zero", 100000, "0.1"},
		// Six integer digits PLUS a fraction: the only shape where reading the
		// shifted digits off intPart instead of intPart+fracPart loses data.
		{"integer digits and a fraction", 1000000.5, "1.0000005"},
		{"negative folds to free", -1, "0"},
		// The `!(v > 0)` spelling IS the NaN guard, and the readability
		// refactor to `v <= 0` is invisible without this row: NaN would render
		// as the unparseable "0.000NaN".
		{"NaN folds to free", math.NaN(), "0"},
		{"positive infinity folds to free", math.Inf(1), "0"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := usdPerToken(tc.usdPer1M); got != tc.want {
				t.Errorf("usdPerToken(%v) = %q, want %q", tc.usdPer1M, got, tc.want)
			}
		})
	}
}

func TestHuggingFaceRepo(t *testing.T) {
	tests := []struct {
		name   string
		source string
		want   string
	}{
		{"plain", "hf:google/gemma-5.2", "google/gemma-5.2"},
		{"revision stripped", "hf:google/gemma-5.2@abc123", "google/gemma-5.2"},
		{"whitespace", "  hf:google/gemma-5.2  ", "google/gemma-5.2"},
		{"no scheme", "google/gemma-5.2", ""},
		{"other scheme", "oci:google/gemma-5.2", ""},
		{"no org", "hf:gemma-5.2", ""},
		{"empty org", "hf:/gemma-5.2", ""},
		{"empty model", "hf:google/", ""},
		{"extra segment", "hf:google/gemma/5.2", ""},
		{"empty", "", ""},
		// These reach the proxy inside a REMOTE operator's advertisement, with
		// nothing having validated them, and a consumer renders the result as a
		// huggingface.co link. The org/model split alone accepts every one.
		{"interior space", "hf: google/gemma", ""},
		{"query string", "hf:google/gemma?x=1", ""},
		{"embedded newline", "hf:google/gemma\nX-Evil: 1", ""},
		{"traversal", "hf:../etc/passwd", ""},
		{"percent escape", "hf:google/gemma%2F..", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := huggingFaceRepo(tc.source); got != tc.want {
				t.Errorf("huggingFaceRepo(%q) = %q, want %q", tc.source, got, tc.want)
			}
		})
	}
}

// Source and CanonicalID are mutually exclusive upstream, but the builder must
// enforce the precedence itself: a malformed source that yields no
// hugging_face_id has to fall through to the canonical slug, or a model with
// both loses every identity key.
func TestOpenAIModelFromDetails_IdentityPrecedence(t *testing.T) {
	tests := []struct {
		name             string
		source           string
		canonical        string
		wantHF, wantSlug string
	}{
		{"source wins", "hf:google/gemma-5.2", "google/gemma", "google/gemma-5.2", ""},
		{"canonical only", "", "xai/grok-4.5", "", "xai/grok-4.5"},
		{"malformed source falls through", "hf:gemma", "xai/grok-4.5", "", "xai/grok-4.5"},
		{"neither", "", "", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OpenAIModelFromDetails(OperatorDetailsModel{ID: "m", Source: tc.source, CanonicalID: tc.canonical}, "operator", 0)
			if got.HuggingFaceID != tc.wantHF {
				t.Errorf("hugging_face_id = %q, want %q", got.HuggingFaceID, tc.wantHF)
			}
			if got.CanonicalSlug != tc.wantSlug {
				t.Errorf("canonical_slug = %q, want %q", got.CanonicalSlug, tc.wantSlug)
			}
		})
	}
}

// A dedicated-image-route model is billed per image, which this shape cannot
// carry; its token rates are zero by construction (ResolveModelPricing never
// inherits default_pricing for an image block). Emitting them would publish a
// $0.10/image model as free on an unauthenticated public GET.
func TestOpenAIModelFromDetails_ImageRouteModelPublishesNoPricing(t *testing.T) {
	imageOnly := OperatorDetailsModel{
		ID:                 "sdxl",
		ServesImageGen:     true,
		ImageRateMicroUSDC: 100_000,
		InputModalities:    []string{"text"},
		OutputModalities:   []string{"image"},
	}
	got, err := json.Marshal(OpenAIModelFromDetails(imageOnly, "operator", 0))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes := string(got); strings.Contains(bytes, "pricing") {
		t.Errorf("image-route model published a price: %s", bytes)
	}

	// An image-route model DOES carry token rates in practice:
	// ResolveModelPricing returns an explicit `pricing:` block before it reaches
	// the tokenless branch for an `image:` model, and the node's validator
	// permits declaring both. So the guard must not key off the rates being
	// zero — the repo's own sdxl-image fixture is exactly this shape.
	priced := imageOnly
	priced.InputRateUSDPer1M = 0
	priced.OutputRateUSDPer1M = 0.5
	if got := OpenAIModelFromDetails(priced, "operator", 0); got.Pricing != nil {
		t.Errorf("image-route model with a declared output rate published %+v, want omitted", got.Pricing)
	}
	bothRates := imageOnly
	bothRates.InputRateUSDPer1M = 0.1
	bothRates.OutputRateUSDPer1M = 0.4
	if got := OpenAIModelFromDetails(bothRates, "operator", 0); got.Pricing != nil {
		t.Errorf("image-route model with token rates published %+v, want omitted", got.Pricing)
	}

	// ServesImageEdit is the other half of the eligibility signal; dropping it
	// from the guard leaves an edit-only model publishing itself as free.
	editOnly := OperatorDetailsModel{ID: "edit", ServesImageEdit: true, ImageEditRateMicroUSDC: 50_000}
	if got := OpenAIModelFromDetails(editOnly, "operator", 0); got.Pricing != nil {
		t.Errorf("edit-only model pricing = %+v, want omitted", got.Pricing)
	}
}

// A deliberately-free CHAT model is a supported shape, and on a node an emitted
// "0" is a real advertised rate — so `{"prompt":"0","completion":"0"}` is the
// right answer for one. It stops being right the moment the model also charges
// per in-loop image or per tool call: those surcharges have no field here, and
// image_tools mandates a non-zero rate. Such models deliberately do NOT set
// ServesImageGen (that flag is the dedicated-route signal), so the first branch
// of the guard cannot see them.
func TestOpenAIModelFromDetails_FreeTokensWithASurchargePublishNoPricing(t *testing.T) {
	free := OperatorDetailsModel{ID: "free-chat", ContextWindow: 8192}
	if got := OpenAIModelFromDetails(free, "operator", 0); got.Pricing == nil || got.Pricing.Prompt != "0" {
		t.Errorf("free chat model pricing = %+v, want an explicit \"0\"", got.Pricing)
	}

	tests := []struct {
		name string
		mut  func(*OperatorDetailsModel)
	}{
		{"in-loop image generation", func(d *OperatorDetailsModel) { d.ImageToolRateMicroUSDC = 40_000 }},
		{"in-loop image edit", func(d *OperatorDetailsModel) { d.ImageEditToolRateMicroUSDC = 40_000 }},
		{"priced tool call", func(d *OperatorDetailsModel) {
			d.ToolCallRatesMicroUSDC = map[string]uint64{"web_search": 2_500}
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := free
			tc.mut(&d)
			if got := OpenAIModelFromDetails(d, "operator", 0); got.Pricing != nil {
				t.Errorf("pricing = %+v, want omitted — the model is not free", got.Pricing)
			}
			// A model with REAL token rates and the same surcharge still
			// publishes them: they describe the token side truthfully.
			d.InputRateUSDPer1M, d.OutputRateUSDPer1M = 0.1, 0.4
			if got := OpenAIModelFromDetails(d, "operator", 0); got.Pricing == nil || got.Pricing.Prompt != "0.0000001" {
				t.Errorf("token-priced model pricing = %+v, want its rates published", got.Pricing)
			}
		})
	}
}

// An empty catalog is a documented steady state, not an error — a node whose
// backend is unreachable advertises zero models. A nil Data marshals to
// `"data":null`, which a client iterating the list reads as null, not as an
// empty array.
func TestNewOpenAIModelList_EmptyMarshalsAsArray(t *testing.T) {
	got, err := json.Marshal(NewOpenAIModelList(0))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	const want = `{"object":"list","data":[]}`
	if string(got) != want {
		t.Errorf("json = %s, want %s", got, want)
	}
}

// architecture is present when EITHER modality list is declared. The guard is
// the same either-or shape as top_provider's below, and an `||` quietly
// narrowed to `&&` drops the modality signal for every one-sided declaration —
// which is most image models.
func TestOpenAIModelFromDetails_ArchitecturePresence(t *testing.T) {
	tests := []struct {
		name        string
		in, out     []string
		wantPresent bool
	}{
		{"both", []string{"text"}, []string{"text"}, true},
		{"input only", []string{"text", "image"}, nil, true},
		{"output only", nil, []string{"image"}, true},
		{"neither", nil, nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OpenAIModelFromDetails(
				OperatorDetailsModel{ID: "m", InputModalities: tc.in, OutputModalities: tc.out}, "operator", 0)
			if (got.Architecture != nil) != tc.wantPresent {
				t.Fatalf("architecture present = %v, want %v", got.Architecture != nil, tc.wantPresent)
			}
			if got.Architecture == nil {
				return
			}
			if len(got.Architecture.InputModalities) != len(tc.in) || len(got.Architecture.OutputModalities) != len(tc.out) {
				t.Errorf("architecture = %+v, want in %v / out %v", *got.Architecture, tc.in, tc.out)
			}
		})
	}
}

// top_provider exists only to carry max_completion_tokens, so it must appear
// when EITHER sizing field is declared and vanish when neither is.
func TestOpenAIModelFromDetails_TopProviderPresence(t *testing.T) {
	tests := []struct {
		name        string
		ctx, maxOut uint64
		want        bool
	}{
		{"both", 131072, 32768, true},
		{"context only", 131072, 0, true},
		{"max output only", 0, 32768, true},
		{"neither", 0, 0, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := OpenAIModelFromDetails(OperatorDetailsModel{ID: "m", ContextWindow: tc.ctx, MaxOutputTokens: tc.maxOut}, "operator", 0)
			if (got.TopProvider != nil) != tc.want {
				t.Fatalf("top_provider present = %v, want %v", got.TopProvider != nil, tc.want)
			}
			if got.TopProvider == nil {
				return
			}
			if got.TopProvider.ContextLength != tc.ctx || got.TopProvider.MaxCompletionTokens != tc.maxOut {
				t.Errorf("top_provider = %+v, want {%d %d}", *got.TopProvider, tc.ctx, tc.maxOut)
			}
		})
	}
}
