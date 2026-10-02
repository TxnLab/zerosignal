/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/TxnLab/zerosignal/go/inject"
)

func TestDetailsQuery(t *testing.T) {
	cases := []struct {
		name   string
		model  string
		expand []string
		want   string
	}{
		{"empty", "", nil, ""},
		{"model only", "alpha", nil, "?model=alpha"},
		{"expand only", "", []string{"coordinates", "digest"}, "?expand=coordinates%2Cdigest"},
		{"both", "alpha", []string{"coordinates"}, "?expand=coordinates&model=alpha"},
		{"model with slash escaped", "Qwen/Qwen2.5-7B", []string{"digest"}, "?expand=digest&model=Qwen%2FQwen2.5-7B"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := detailsQuery(tc.model, tc.expand); got != tc.want {
				t.Errorf("detailsQuery(%q, %v) = %q, want %q", tc.model, tc.expand, got, tc.want)
			}
		})
	}
}

// TestFetchModel_ForwardsQueryAndDecodes stands up a fake node and asserts
// FetchModel sends the scoped ?model=&expand= query and decodes the node's
// (deep) response — the deep-path proxy drill-in primitive.
func TestFetchModel_ForwardsQueryAndDecodes(t *testing.T) {
	var gotPath, gotModel, gotExpand string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotModel = r.URL.Query().Get("model")
		gotExpand = r.URL.Query().Get("expand")
		w.Header().Set("Content-Type", "application/json")
		// Echo a scoped, deep-enriched entry the way a node would.
		_ = json.NewEncoder(w).Encode(inject.OperatorDetails{
			OperatorID: 7,
			Models: []inject.OperatorDetailsModel{{
				ID:            "Qwen/Qwen2.5-7B",
				WeightsDigest: "sha256:abc",
				Coordinates:   &inject.ModelCoordinates{Family: "Qwen/Qwen2.5-7B", Parameters: 7_615_616_512},
			}},
		})
	}))
	defer srv.Close()

	c := NewDetailsClient(srv.Client(), 0)
	got, err := c.FetchModel(context.Background(), srv.URL, "Qwen/Qwen2.5-7B", []string{"coordinates", "digest"}, nil)
	if err != nil {
		t.Fatalf("FetchModel: %v", err)
	}

	if gotPath != "/v1/zs/details" {
		t.Errorf("path = %q, want /v1/zs/details", gotPath)
	}
	if gotModel != "Qwen/Qwen2.5-7B" {
		t.Errorf("forwarded model = %q", gotModel)
	}
	if gotExpand != "coordinates,digest" {
		t.Errorf("forwarded expand = %q, want coordinates,digest", gotExpand)
	}
	if len(got.Models) != 1 || got.Models[0].ID != "Qwen/Qwen2.5-7B" {
		t.Fatalf("decoded models = %+v", got.Models)
	}
	if got.Models[0].Coordinates == nil || got.Models[0].Coordinates.Parameters != 7_615_616_512 {
		t.Errorf("deep coordinates not decoded: %+v", got.Models[0].Coordinates)
	}
	if got.Models[0].WeightsDigest != "sha256:abc" {
		t.Errorf("weights_digest = %q", got.Models[0].WeightsDigest)
	}
}

// TestFetch_LeanProbeUnchanged confirms the bare Fetch still hits the
// unqueried endpoint (no regression from the refactor).
func TestFetch_LeanProbeUnchanged(t *testing.T) {
	var gotRawQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRawQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(inject.OperatorDetails{OperatorID: 1})
	}))
	defer srv.Close()

	c := NewDetailsClient(srv.Client(), 0)
	got, err := c.Fetch(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotRawQuery != "" {
		t.Errorf("lean probe sent query %q, want none", gotRawQuery)
	}
	if got.OperatorID != 1 {
		t.Errorf("operator_id = %d", got.OperatorID)
	}
}
