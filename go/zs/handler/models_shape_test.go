/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/inject"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

func modelsRegistry(t *testing.T, ops []hayai.Operator) *hayai.StaticRegistryProvider {
	t.Helper()
	reg, err := hayai.NewStaticRegistryProvider(ops)
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	return reg
}

func getJSON(t *testing.T, path string, h func(http.ResponseWriter, *http.Request)) []byte {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.SetPathValue("id", pathModelID(path))
	w := httptest.NewRecorder()
	h(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("GET %s status = %d, body %s", path, w.Result().StatusCode, w.Body.String())
	}
	return w.Body.Bytes()
}

// pathModelID extracts the {id...} wildcard the real mux would have set, so a
// handler test exercises the same input as a routed request.
func pathModelID(path string) string {
	id, _ := strings.CutPrefix(path, "/v1/models/")
	if id == path {
		return ""
	}
	return id
}

// feeWallet is a fakeWallet that also advertises a protocol fee — the optional
// capability Server.feeRateNow gates on.
type feeWallet struct{ *fakeWallet }

func (feeWallet) ProtocolFeeBps(_ context.Context) (uint64, error) { return 1000, nil }

// feeServer builds a proxy whose protocol fee is KNOWN, at feeBps.
//
// Both halves are needed and for different reasons. feeRateNow type-asserts the
// wallet for feeRateCapable BEFORE reading the cache, so a plain fake leaves
// the fee permanently unknown — under which modelEntryFor publishes no price at
// all, and every pricing assertion below would be testing the wrong branch. And
// the cache must be SEEDED rather than filled through the wallet: a cold read
// returns (0, false) and kicks an ASYNC refresh, so fetching the rate the
// production way would race that goroutine. A non-stale entry takes
// feeRateCache.get's fast path and never refreshes.
func feeServer(t *testing.T, ops []hayai.Operator, feeBps uint64) *Server {
	t.Helper()
	s := testServer(testConfig(), Options{
		RegistryProvider: modelsRegistry(t, ops),
		Wallet:           feeWallet{&fakeWallet{}},
	})
	s.feeRate.mu.Lock()
	s.feeRate.feeBps, s.feeRate.ok, s.feeRate.fetchedAt = feeBps, true, time.Now()
	s.feeRate.mu.Unlock()
	return s
}

// richOperator serves one model with every advertisable field declared, so a
// projection that drops one has somewhere to show up.
//
// Source is deliberately NOT the model id: with the two equal, a builder
// returning `HuggingFaceID: d.ID` would satisfy every assertion and neither the
// scheme strip nor the revision drop would be pinned.
func richOperator() hayai.Operator {
	return hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"gemma-5.2-q8"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"gemma-5.2-q8": {
				ContextWindow:     131072,
				MaxOutputTokens:   32768,
				InputModalities:   []string{"text", "image"},
				OutputModalities:  []string{"text"},
				InputUSDPer1M:     0.1,
				OutputUSDPer1M:    0.4,
				CacheReadUSDPer1M: new(0.01),
				ToolUse:           new(true),
				Reasoning:         &inject.ModelReasoning{Supported: true, AllowedEfforts: []string{"low", "high"}, DefaultEffort: "low"},
				Source:            "hf:google/gemma-5.2@abc123",
			},
		},
	}
}

// The enriched fields must actually reach the wire from a real registry — the
// gap this closes is that /v1/models carried the id and modalities and nothing
// a client needs to size a request or price it. Asserted as decoded VALUES, not
// presence: an entry that carries `context_length: 0` is the bug.
func TestHandleListModels_CarriesCapabilityAndPricing(t *testing.T) {
	// Zero bps: a real, known fee that leaves the rates at their declared
	// values, so this test reads the projection and the gross-up tests below
	// read the arithmetic.
	s := feeServer(t, []hayai.Operator{richOperator()}, 0)

	var body inject.OpenAIModelList
	if err := json.Unmarshal(getJSON(t, "/v1/models", s.handleListModels), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Data) != 1 {
		t.Fatalf("data = %+v, want 1 entry", body.Data)
	}
	got := body.Data[0]

	if got.ID != "gemma-5.2-q8" || got.Object != "model" || got.OwnedBy != "zerosignal" {
		t.Errorf("official fields = %+v", got)
	}
	if got.ContextLength != 131072 {
		t.Errorf("context_length = %d, want 131072", got.ContextLength)
	}
	if got.TopProvider == nil {
		t.Fatalf("top_provider absent from %+v", got)
	}
	if got.TopProvider.ContextLength != 131072 || got.TopProvider.MaxCompletionTokens != 32768 {
		t.Errorf("top_provider = %+v, want {131072 32768}", *got.TopProvider)
	}
	if got.Pricing == nil {
		t.Fatalf("pricing absent from %+v", got)
	}
	if got.Pricing.Prompt != "0.0000001" || got.Pricing.Completion != "0.0000004" {
		t.Errorf("pricing = %+v, want prompt 0.0000001 / completion 0.0000004", got.Pricing)
	}
	if got.Pricing.InputCacheRead != "0.00000001" {
		t.Errorf("input_cache_read = %q, want 0.00000001", got.Pricing.InputCacheRead)
	}
	if got.ToolUse == nil || !*got.ToolUse {
		t.Errorf("tool_use = %v, want true", got.ToolUse)
	}
	if got.Reasoning == nil {
		t.Fatalf("reasoning absent from %+v", got)
	}
	if !got.Reasoning.Supported || len(got.Reasoning.AllowedEfforts) != 2 {
		t.Errorf("reasoning = %+v", got.Reasoning)
	}
	// DefaultEffort is dropped by AllModelDetails, not by this endpoint: one
	// default has no cross-operator meaning, so the proxy aggregate omits it and
	// /v1/zs/details does the same. Pinned so a future aggregation change that
	// starts emitting one operator's default is noticed here too.
	if got.Reasoning.DefaultEffort != "" {
		t.Errorf("default_effort = %q, want empty on the cross-operator aggregate", got.Reasoning.DefaultEffort)
	}
	// The scheme is stripped and the @revision dropped — neither of which the
	// model id could have supplied.
	if got.HuggingFaceID != "google/gemma-5.2" {
		t.Errorf("hugging_face_id = %q, want google/gemma-5.2", got.HuggingFaceID)
	}
	if got.Architecture == nil {
		t.Fatalf("architecture absent from %+v", got)
	}
	if strings.Join(got.Architecture.InputModalities, ",") != "text,image" ||
		strings.Join(got.Architecture.OutputModalities, ",") != "text" {
		t.Errorf("architecture = %+v, want in [text image] / out [text]", *got.Architecture)
	}
}

// On the cross-operator aggregate a zero rate means "nobody declared one",
// never "free": AllModelDetails keeps the lowest *declared, non-zero* rate and
// folds input and output INDEPENDENTLY, so either side can be zero on its own.
// Publishing the other side beside a "0" claims free tokens for a rate nobody
// set, on the surface whose whole meaning is "this is what it costs".
func TestHandleListModels_PricingIsOmittedUnlessBothRatesAreDeclared(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"neither", "input-only", "output-only", "priced"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			// Declared window, no rate — an operator whose capability probe
			// landed without pricing.
			"neither":     {ContextWindow: 8192},
			"input-only":  {ContextWindow: 8192, InputUSDPer1M: 3},
			"output-only": {ContextWindow: 8192, OutputUSDPer1M: 15},
			"priced":      {ContextWindow: 8192, InputUSDPer1M: 3, OutputUSDPer1M: 15},
		},
	}
	s := feeServer(t, []hayai.Operator{op}, 0)

	var list inject.OpenAIModelList
	if err := json.Unmarshal(getJSON(t, "/v1/models", s.handleListModels), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	byID := map[string]inject.OpenAIModel{}
	for _, m := range list.Data {
		byID[m.ID] = m
	}
	if len(byID) != 4 {
		t.Fatalf("data = %+v, want all four models", list.Data)
	}
	for _, id := range []string{"neither", "input-only", "output-only"} {
		if got := byID[id]; got.Pricing != nil {
			t.Errorf("%s published %+v, want no pricing object", id, got.Pricing)
		}
	}
	// The guard must not swallow a real price — without this half, deleting the
	// pricing object entirely would pass.
	if got := byID["priced"]; got.Pricing == nil || got.Pricing.Prompt != "0.000003" {
		t.Errorf("priced model pricing = %+v, want prompt 0.000003", got.Pricing)
	}
}

// OpenRouter's pricing object has no fee field and its whole meaning is "this
// is what it costs", so the proxy publishes the payer-net rate. The pre-fee
// number would understate every reader's cost by the protocol fee with nothing
// on the response to correct it.
func TestHandleListModels_PricingIsGrossedUpByTheProtocolFee(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {InputUSDPer1M: 3, OutputUSDPer1M: 15, CacheReadUSDPer1M: new(0.3)},
		},
	}
	s := feeServer(t, []hayai.Operator{op}, 1000) // 10%

	var list inject.OpenAIModelList
	if err := json.Unmarshal(getJSON(t, "/v1/models", s.handleListModels), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Data) != 1 || list.Data[0].Pricing == nil {
		t.Fatalf("data = %+v", list.Data)
	}
	got := list.Data[0].Pricing
	// $3.00 and $15.00 per 1M at +10% ⇒ $3.30 and $16.50, as USD per token.
	if got.Prompt != "0.0000033" || got.Completion != "0.0000165" {
		t.Errorf("pricing = %+v, want prompt 0.0000033 / completion 0.0000165", got)
	}
	if got.InputCacheRead != "0.00000033" {
		t.Errorf("input_cache_read = %q, want 0.00000033", got.InputCacheRead)
	}

	// The cache-read rate reaches modelEntryFor behind a pointer. Both in-tree
	// providers allocate that pointer fresh per call so nothing aliases today,
	// but the shared builder documents its result as aliasing its input, and a
	// provider that memoized the aggregate would have the gross-up compound on
	// every request. memoizingRegistry is that provider; the second read must
	// return the same number.
	memo := &memoizingRegistry{inner: modelsRegistry(t, []hayai.Operator{op})}
	s2 := testServer(testConfig(), Options{RegistryProvider: memo, Wallet: feeWallet{&fakeWallet{}}})
	s2.feeRate.mu.Lock()
	s2.feeRate.feeBps, s2.feeRate.ok, s2.feeRate.fetchedAt = 1000, true, time.Now()
	s2.feeRate.mu.Unlock()

	var first, second inject.OpenAIModelList
	if err := json.Unmarshal(getJSON(t, "/v1/models", s2.handleListModels), &first); err != nil {
		t.Fatalf("decode first: %v", err)
	}
	if err := json.Unmarshal(getJSON(t, "/v1/models", s2.handleListModels), &second); err != nil {
		t.Fatalf("decode second: %v", err)
	}
	if first.Data[0].Pricing.InputCacheRead != second.Data[0].Pricing.InputCacheRead {
		t.Errorf("second read = %q, first = %q — the gross-up wrote through to the provider's own value",
			second.Data[0].Pricing.InputCacheRead, first.Data[0].Pricing.InputCacheRead)
	}
}

// memoizingRegistry returns the SAME OperatorDetailsModel values on every call,
// pointers included — the shape a caching provider would have, and the only one
// under which a write-through in modelEntryFor is observable.
type memoizingRegistry struct {
	inner  *hayai.StaticRegistryProvider
	cached []inject.OperatorDetailsModel
}

func (m *memoizingRegistry) Operators(ctx context.Context, model string) ([]hayai.Operator, error) {
	return m.inner.Operators(ctx, model)
}

func (m *memoizingRegistry) Resolve(ctx context.Context, opID, nodeID uint64) (hayai.Operator, error) {
	return m.inner.Resolve(ctx, opID, nodeID)
}
func (m *memoizingRegistry) AllModels(ctx context.Context) []string { return m.inner.AllModels(ctx) }
func (m *memoizingRegistry) AllBuiltinTools(ctx context.Context) []hayai.BuiltinToolDef {
	return m.inner.AllBuiltinTools(ctx)
}

func (m *memoizingRegistry) AllModelDetails(ctx context.Context) []inject.OperatorDetailsModel {
	if m.cached == nil {
		m.cached = m.inner.AllModelDetails(ctx)
	}
	return m.cached
}
func (m *memoizingRegistry) AllNodeVersions(ctx context.Context) []string {
	return m.inner.AllNodeVersions(ctx)
}
func (m *memoizingRegistry) AllOperators(ctx context.Context) []hayai.Operator {
	return m.inner.AllOperators(ctx)
}
func (m *memoizingRegistry) ReprobeEphemeral(ctx context.Context, op hayai.Operator) (hayai.Operator, bool) {
	return m.inner.ReprobeEphemeral(ctx, op)
}
func (m *memoizingRegistry) RecordModelDemand(model string) { m.inner.RecordModelDemand(model) }

// A fee the proxy has not learned yet publishes NO price rather than the raw
// operator rate. This is the state at startup — and an OpenAI-compatible client
// fetches the catalog once, at connect time, which is exactly when the proxy is
// coldest. Falling back to the raw rate would emit the understated number the
// gross-up exists to prevent, and this shape has no fee field in which to say
// the number is provisional.
func TestHandleListModels_ColdFeePublishesNoPrice(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"m"},
		ModelCapacities: map[string]hayai.ModelCapacity{
			"m": {ContextWindow: 8192, InputUSDPer1M: 3, OutputUSDPer1M: 15},
		},
	}
	// testServer's wallet is not feeRateCapable, so the fee is never known.
	s := testServer(testConfig(), Options{RegistryProvider: modelsRegistry(t, []hayai.Operator{op})})

	var list inject.OpenAIModelList
	if err := json.Unmarshal(getJSON(t, "/v1/models", s.handleListModels), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("data = %+v, want 1 entry", list.Data)
	}
	if got := list.Data[0]; got.Pricing != nil {
		t.Errorf("pricing = %+v, want omitted while the fee is unknown", got.Pricing)
	}
	// Everything that does not depend on the fee still ships.
	if list.Data[0].ContextLength != 8192 {
		t.Errorf("context_length = %d, want 8192 — only the price is withheld", list.Data[0].ContextLength)
	}
}

// The two surfaces must not be able to tell a client different things about the
// same model, so compare the raw BYTES rather than a few fields — a field the
// list gains and the get doesn't would pass any spot check. Run under a
// NON-UNIT fee: the list computes the gross factor once outside its loop and
// the get computes it per request, so a unit fee would make the one value that
// can differ between the two paths invisible to the comparison.
func TestHandleGetModel_ByteIdenticalToListEntry(t *testing.T) {
	s := feeServer(t, []hayai.Operator{richOperator()}, 1000)

	var list struct {
		Data []json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(getJSON(t, "/v1/models", s.handleListModels), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Data) != 1 {
		t.Fatalf("data = %v, want 1 entry", list.Data)
	}
	// Guard the guard: with no price on either side the byte comparison could
	// not see the gross-up at all.
	if !strings.Contains(string(list.Data[0]), `"pricing"`) {
		t.Fatalf("fixture published no pricing, so this test cannot see the gross-up: %s", list.Data[0])
	}

	single := getJSON(t, "/v1/models/gemma-5.2-q8", s.handleGetModel)
	// Both are encoded with json.Encoder, which appends a newline.
	want := append([]byte(list.Data[0]), '\n')
	if string(single) != string(want) {
		t.Errorf("get =\n %s\nlist entry =\n %s", single, want)
	}
}

// A model advertised with no capability detail is still served rather than
// 404ed, and publishes no price. (It does still get a details entry — the
// aggregate creates one from the zero-value capacity — so the AllModels-only
// case is TestModelEndpoints_ModelWithoutDetailsIsStillServed's job, not this
// one.)
func TestHandleGetModel_BareModelIsFoundNot404(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: true, ProtoVersion: wire.ProtoVersion,
		Models: []string{"bare"},
	}
	s := feeServer(t, []hayai.Operator{op}, 1000)

	var got inject.OpenAIModel
	if err := json.Unmarshal(getJSON(t, "/v1/models/bare", s.handleGetModel), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.ID != "bare" || got.Object != "model" {
		t.Errorf("entry = %+v", got)
	}
	// No pricing object: on the proxy aggregate a zero rate means "nobody
	// declared one", never "free" — see modelEntryFor.
	if got.Pricing != nil {
		t.Errorf("pricing = %+v, want omitted on a model with no declared rate", got.Pricing)
	}
}

// splitRegistry advertises a model in AllModels that AllModelDetails does not
// carry. Both in-tree providers derive the two aggregates from one loop, so
// nothing reachable through them separates the sets — but the endpoints are
// written against the RegistryProvider interface, and the pairing is exactly
// the kind an implementation is free to break.
type splitRegistry struct{ errRegistry }

func (splitRegistry) AllModels(_ context.Context) []string { return []string{"listed-only"} }

// A model in AllModels but not AllModelDetails must be listed and gettable, not
// 404ed: AllModels is what the discovery surface publishes, so answering 404
// for one of its ids contradicts the list the same client just read.
func TestModelEndpoints_ModelWithoutDetailsIsStillServed(t *testing.T) {
	s := testServer(testConfig(), Options{RegistryProvider: splitRegistry{}})

	var list inject.OpenAIModelList
	if err := json.Unmarshal(getJSON(t, "/v1/models", s.handleListModels), &list); err != nil {
		t.Fatalf("decode list: %v", err)
	}
	if len(list.Data) != 1 || list.Data[0].ID != "listed-only" {
		t.Fatalf("data = %+v, want one bare listed-only entry", list.Data)
	}

	var single inject.OpenAIModel
	if err := json.Unmarshal(getJSON(t, "/v1/models/listed-only", s.handleGetModel), &single); err != nil {
		t.Fatalf("decode get: %v", err)
	}
	if single.ID != "listed-only" || single.Object != "model" {
		t.Errorf("entry = %+v", single)
	}
}

// An empty registry must marshal `"data":[]`, never `"data":null` — every
// operator being unreachable is a documented steady state, and a client
// iterating the list would see null.
func TestHandleListModels_EmptyRegistryMarshalsAsArray(t *testing.T) {
	op := hayai.Operator{
		ID: 1, OwnerAddr: "A", BaseURL: "http://a", Reachable: false,
		Models: []string{"stale"},
	}
	s := testServer(testConfig(), Options{RegistryProvider: modelsRegistry(t, []hayai.Operator{op})})

	body := getJSON(t, "/v1/models", s.handleListModels)
	if got := strings.TrimSpace(string(body)); got != `{"object":"list","data":[]}` {
		t.Errorf("body = %s", got)
	}
}

// grossRate is hand-mirrored in internal/connect (unexported there, so it can't
// be called from here). Pin the shared behaviour against literals at this end:
// the rounding is what keeps the two from publishing different digits for one
// model, and dropping it emits 0.0000033000000000000003.
func TestGrossRate(t *testing.T) {
	tests := []struct {
		name        string
		usdPer1M    float64
		grossFactor float64
		want        float64
	}{
		{"unit factor is identity", 3, 1, 3},
		{"ten percent", 3, 1.1, 3.3},
		{"ten percent on a large rate", 15, 1.1, 16.5},
		{"rounds to the microUSDC", 0.3, 1.1, 0.33},
		{"free stays free", 0, 1.1, 0},
		// A remote operator's rate is unvalidated, and one this large overflows
		// the multiply to +Inf — which usdPerToken renders "0", an affirmative
		// claim of FREE. Collapsing to 0 routes it to modelEntryFor's zero rule,
		// i.e. no price at all, which is the honest answer for an absurd rate.
		{"overflow collapses to unknown", math.MaxFloat64, 1.1, 0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := grossRate(tc.usdPer1M, tc.grossFactor); got != tc.want {
				t.Errorf("grossRate(%v, %v) = %v, want %v", tc.usdPer1M, tc.grossFactor, got, tc.want)
			}
		})
	}
}
