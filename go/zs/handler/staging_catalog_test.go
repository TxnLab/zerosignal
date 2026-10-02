/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// The proxy's discovery surface must agree with its routing: SelectTargets
// refuses a staging node as a target unless zs.allow_staging is set, so listing
// its models advertises capacity dispatch then answers with 503
// no_production_operator. These pin the handler half of that rule; the provider
// half lives in proto/go/zs/registry_staging_test.go.

// catalogOp is a REACHABLE model-serving node, optionally flagged staging.
// Distinct from stagingOp in hayai_dispatch_staging_test.go, which leaves
// Reachable false — fine for pickCandidates, but the catalog aggregates gate on
// reachability first and would drop every fixture before staging was consulted.
//
// Probed and ReachableAsOf are both set because the two providers ask different
// questions: the static one reads Reachable alone, while the dynamic one (what
// production ships) needs either a fresh probe this cycle or a ReachableAsOf
// inside the carry window. A fixture with only Reachable set passes every static
// assertion and is dropped entirely by the dynamic provider.
func catalogOp(id uint64, model string, staging bool) hayai.Operator {
	return hayai.Operator{
		ID: id, OwnerAddr: "A", BaseURL: "http://op.example",
		Reachable: true, Probed: true, ReachableAsOf: time.Now(),
		Models: []string{model},
		ModelCapacities: map[string]hayai.ModelCapacity{
			model: {
				ContextWindow:   128_000,
				MaxOutputTokens: 16_384,
				InputUSDPer1M:   1.0,
				OutputUSDPer1M:  2.0,
			},
		},
		Staging:      staging,
		ProtoVersion: wire.ProtoVersion,
	}
}

// catalogServer wires a Server whose registry and config agree on allow_staging
// — the two must be threaded from the same value in production (app.go), so a
// fixture that sets only one would test a state that cannot occur.
func catalogServer(t *testing.T, allowStaging bool, ops ...hayai.Operator) *Server {
	t.Helper()
	return catalogServerWith(t, allowStaging, &refusingReserveClient{}, ops...)
}

// catalogServerWith is catalogServer over rc. A request that routes ends at
// rc's refusal, before any payment.
func catalogServerWith(t *testing.T, allowStaging bool, rc hayai.ReserveClient, ops ...hayai.Operator) *Server {
	t.Helper()
	reg, err := hayai.NewStaticRegistryProviderWithConfig(ops, hayai.StaticRegistryConfig{AllowStaging: allowStaging})
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	cfg := testConfig()
	cfg.AllowStaging = allowStaging
	return testServer(cfg, Options{RegistryProvider: reg, ReserveClient: rc, Tokenizer: testTokenizer(), Wallet: &fakeWallet{}})
}

func listedModelIDs(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	w := httptest.NewRecorder()
	s.handleListModels(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/models status = %d, body %s", w.Code, w.Body.String())
	}
	var out struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode /v1/models: %v", err)
	}
	ids := make(map[string]bool, len(out.Data))
	for _, m := range out.Data {
		ids[m.ID] = true
	}
	return ids
}

func getModelStatus(t *testing.T, s *Server, id string) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/models/"+id, nil)
	req.SetPathValue("id", id)
	w := httptest.NewRecorder()
	s.handleGetModel(w, req)
	return w.Code
}

func TestHandleListModels_StagingOnlyModelIsNotListed(t *testing.T) {
	s := catalogServer(t, false,
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	)

	ids := listedModelIDs(t, s)
	if !ids["prod-model"] {
		t.Errorf("/v1/models omitted prod-model; got %v", ids)
	}
	if ids["staging-only"] {
		t.Errorf("/v1/models listed staging-only, which dispatch would 503; got %v", ids)
	}
}

// TestHandleGetModel_StagingOnlyModelIs404 keeps the two model endpoints
// consistent: handleGetModel's membership check is AllModels, so a model the
// list omits must 404 rather than 200 on a bare entry.
func TestHandleGetModel_StagingOnlyModelIs404(t *testing.T) {
	s := catalogServer(t, false,
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	)

	if got := getModelStatus(t, s, "prod-model"); got != http.StatusOK {
		t.Errorf("GET /v1/models/prod-model = %d, want 200", got)
	}
	if got := getModelStatus(t, s, "staging-only"); got != http.StatusNotFound {
		t.Errorf("GET /v1/models/staging-only = %d, want 404 (must match the list)", got)
	}
}

func TestModelEndpoints_StagingListedWhenAllowed(t *testing.T) {
	s := catalogServer(t, true,
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	)

	if ids := listedModelIDs(t, s); !ids["staging-only"] {
		t.Errorf("/v1/models omitted staging-only with allow_staging on; got %v", ids)
	}
	if got := getModelStatus(t, s, "staging-only"); got != http.StatusOK {
		t.Errorf("GET /v1/models/staging-only = %d, want 200 with allow_staging on", got)
	}
}

// --- /v1/zs/operators ---

func operatorsPayload(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/zs/operators", nil)
	w := httptest.NewRecorder()
	s.handleHayaiOperators(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/zs/operators status = %d, body %s", w.Code, w.Body.String())
	}
	// Decoded loosely on purpose: `staging` is omitempty, and a struct decode
	// cannot tell an absent key from a false one — which is exactly the
	// distinction the default case asserts.
	var out struct {
		Operators []map[string]any `json:"operators"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode /v1/zs/operators: %v", err)
	}
	return out.Operators
}

func TestHandleHayaiOperators_DropsStagingNodesByDefault(t *testing.T) {
	ops := operatorsPayload(t, catalogServer(t, false,
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	))

	if len(ops) != 1 {
		t.Fatalf("got %d operators, want 1 (the staging node is held out)", len(ops))
	}
	if id, _ := ops[0]["operator_id"].(float64); id != 1 {
		t.Errorf("operator_id = %v, want 1", ops[0]["operator_id"])
	}
	if _, present := ops[0]["staging"]; present {
		t.Errorf("production entry carries a `staging` key; omitempty should drop it: %v", ops[0])
	}
}

func TestHandleHayaiOperators_MarksStagingWhenAllowed(t *testing.T) {
	ops := operatorsPayload(t, catalogServer(t, true,
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	))

	if len(ops) != 2 {
		t.Fatalf("got %d operators, want 2 with allow_staging on", len(ops))
	}
	byID := map[float64]map[string]any{}
	for _, op := range ops {
		id, _ := op["operator_id"].(float64)
		byID[id] = op
	}
	if staging, _ := byID[2]["staging"].(bool); !staging {
		t.Errorf("staging node 2 not marked `staging: true`: %v", byID[2])
	}
	if _, present := byID[1]["staging"]; present {
		t.Errorf("production node 1 carries a `staging` key: %v", byID[1])
	}
}

// --- the invariant the split exists to protect ---

// TestStagingCatalogAndDispatchAgree states in one place what was previously
// only true of the dispatch half: the proxy advertises exactly what it routes
// to. Both surfaces are driven from one Server and one fixture, so they cannot
// drift apart without failing here.
func TestStagingCatalogAndDispatchAgree(t *testing.T) {
	ops := []hayai.Operator{
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	}

	t.Run("knob off", func(t *testing.T) {
		s := catalogServer(t, false, ops...)

		ids := listedModelIDs(t, s)
		if !ids["prod-model"] || ids["staging-only"] {
			t.Fatalf("/v1/models = %v, want prod-model only", ids)
		}
		if code, body := postChat(t, s, "staging-only"); code != http.StatusServiceUnavailable ||
			!strings.Contains(body, `"no_production_operator"`) {
			t.Errorf("POST staging-only = %d %s, want 503 no_production_operator", code, body)
		}
	})

	t.Run("knob on", func(t *testing.T) {
		rc := &refusingReserveClient{}
		s := catalogServerWith(t, true, rc, ops...)

		if ids := listedModelIDs(t, s); !ids["staging-only"] {
			t.Fatalf("/v1/models = %v, want staging-only listed once opted in", ids)
		}
		// Routable too: the request reaches the staging node's reserve, where
		// the fixture's refusal ends it before payment.
		postChat(t, s, "staging-only")
		if len(rc.ops) == 0 || rc.ops[0].ID != 2 {
			t.Errorf("reserves went to %v, want the staging node 2", rc.ops)
		}
	})
}

func postChat(t *testing.T, s *Server, model string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, endpointChatCompletions, `{"model":"`+model+`","max_completion_tokens":100}`))
	return w.Code, w.Body.String()
}

// frozenSource is an hayai.OperatorSource that always returns the same fleet, so
// a DynamicRegistryProvider can be driven without a chain.
type frozenSource struct{ ops []hayai.Operator }

func (f *frozenSource) Fetch(context.Context) ([]hayai.Operator, error) {
	return append([]hayai.Operator(nil), f.ops...), nil
}

// dynamicCatalogServer is catalogServer over the provider production actually
// ships. The two providers implement the aggregates SEPARATELY
// (registry_dynamic.go vs registry.go), so a handler test on the static one
// exercises code no payer ever runs.
func dynamicCatalogServer(t *testing.T, allowStaging bool, ops ...hayai.Operator) *Server {
	t.Helper()
	reg, err := hayai.NewDynamicRegistryProvider(&frozenSource{ops: ops}, ops, hayai.DynamicRegistryConfig{
		RefreshInterval: time.Hour,
		RefreshTimeout:  time.Second,
		MaxCacheAge:     time.Hour,
		AllowStaging:    allowStaging,
	}, silentLogger())
	if err != nil {
		t.Fatalf("NewDynamicRegistryProvider: %v", err)
	}
	cfg := testConfig()
	cfg.AllowStaging = allowStaging
	return testServer(cfg, Options{RegistryProvider: reg, ReserveClient: &refusingReserveClient{}, Tokenizer: testTokenizer(), Wallet: &fakeWallet{}})
}

// TestDiscoveryHandlersOverDynamicRegistry is the shipped-path pin, and the one
// that makes the two halves of the gate agree on a single Server.
//
// The aggregates read the value captured in DynamicRegistryConfig at
// construction; handleHayaiOperators reads Config.AllowStaging live. In the
// proxy both come from its hayai.allow_staging setting (registryConfigFor,
// pinned in its internal/app). If they ever diverge, the proxy routes to a staging node while
// hiding it from its own catalog — which is the split this whole gate exists to
// close, so it is asserted here across one Server rather than left to a comment.
func TestDiscoveryHandlersOverDynamicRegistry(t *testing.T) {
	ops := []hayai.Operator{
		catalogOp(1, "prod-model", false),
		catalogOp(2, "staging-only", true),
	}

	t.Run("knob off", func(t *testing.T) {
		s := dynamicCatalogServer(t, false, ops...)

		ids := listedModelIDs(t, s)
		if !ids["prod-model"] || ids["staging-only"] {
			t.Errorf("/v1/models = %v, want prod-model only", ids)
		}
		if got := getModelStatus(t, s, "staging-only"); got != http.StatusNotFound {
			t.Errorf("GET /v1/models/staging-only = %d, want 404", got)
		}
		if dirs := operatorsPayload(t, s); len(dirs) != 1 {
			t.Errorf("/v1/zs/operators = %d entries, want 1 (staging held out)", len(dirs))
		}
		if names := detailsModelIDs(t, s); names["staging-only"] {
			t.Errorf("/v1/zs/details listed staging-only: %v", names)
		}
	})

	t.Run("knob on", func(t *testing.T) {
		s := dynamicCatalogServer(t, true, ops...)

		if ids := listedModelIDs(t, s); !ids["staging-only"] {
			t.Errorf("/v1/models = %v, want staging-only listed", ids)
		}
		if got := getModelStatus(t, s, "staging-only"); got != http.StatusOK {
			t.Errorf("GET /v1/models/staging-only = %d, want 200", got)
		}
		dirs := operatorsPayload(t, s)
		if len(dirs) != 2 {
			t.Fatalf("/v1/zs/operators = %d entries, want 2", len(dirs))
		}
		var marked bool
		for _, d := range dirs {
			if id, _ := d["operator_id"].(float64); id == 2 {
				marked, _ = d["staging"].(bool)
			}
		}
		if !marked {
			t.Errorf("/v1/zs/operators did not mark node 2 `staging: true`: %v", dirs)
		}
		if names := detailsModelIDs(t, s); !names["staging-only"] {
			t.Errorf("/v1/zs/details omitted staging-only: %v", names)
		}
	})
}

// detailsModelIDs reads the model ids off the aggregate /v1/zs/details view.
func detailsModelIDs(t *testing.T, s *Server) map[string]bool {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/v1/zs/details", nil)
	w := httptest.NewRecorder()
	s.handleHayaiDetails(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /v1/zs/details status = %d, body %s", w.Code, w.Body.String())
	}
	var out struct {
		Models []struct {
			ID string `json:"id"`
		} `json:"models"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode /v1/zs/details: %v", err)
	}
	ids := make(map[string]bool, len(out.Models))
	for _, m := range out.Models {
		ids[m.ID] = true
	}
	return ids
}

// proto/SPEC.md: the staging flag "gates TARGET selection only. Staging nodes
// remain usable as relays, since a relay forwards bytes and runs no
// inference." The relay pool keeping them is pinned in zs
// (TestRelayPoolKeepsStagingNodes); this is the payer-facing directory, which
// hides them.
func TestOperatorsDirectoryHidesStagingNodes(t *testing.T) {
	s := catalogServer(t, false,
		catalogOp(1, "staging-only", true),
		catalogOp(2, "staging-only", true),
	)
	// The payer-facing directory hides them while relaying keeps them, so this
	// is the deliberate asymmetry rather than a missing filter.
	if ops := operatorsPayload(t, s); len(ops) != 0 {
		t.Fatalf("/v1/zs/operators = %d entries, want 0 while allow_staging is off", len(ops))
	}
}
