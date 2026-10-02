/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// getPath runs one GET through the mux and returns status + body.
func getPath(t *testing.T, s *Server, path string) (int, string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
	return w.Result().StatusCode, w.Body.String()
}

// Host-relative /models must be indistinguishable from /v1/models. Clients that
// derive the discovery URL from the host rather than the API root — JetBrains AI
// Assistant does, while POSTing chat to /v1/chat/completions in the same session
// — otherwise get Go's default "404 page not found", which isn't even JSON.
//
// Asserted as EQUIVALENCE rather than against a fixed model list on purpose: the
// property that matters is "both spellings reach the same handler", and it holds
// whatever the registry happens to be advertising.
func TestRoutes_HostRelativeModelsAlias(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	wantStatus, wantBody := getPath(t, s, "/v1/models")
	if wantStatus != http.StatusOK {
		t.Fatalf("GET /v1/models = %d, want 200 (control)", wantStatus)
	}
	gotStatus, gotBody := getPath(t, s, "/models")
	if gotStatus != wantStatus || gotBody != wantBody {
		t.Errorf("GET /models = %d %s; want identical to /v1/models (%d %s)",
			gotStatus, gotBody, wantStatus, wantBody)
	}
}

// The alias covers the per-model lookup too, and must use the same {id...}
// trailing wildcard — a single-segment {id} would 404 on an id with an embedded
// slash (e.g. "google/gemma-5.2") before the handler ever ran.
func TestRoutes_HostRelativeModelGetAlias(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	for _, id := range []string{"gpt-test", "google/gemma-5.2"} {
		wantStatus, wantBody := getPath(t, s, "/v1/models/"+id)
		gotStatus, gotBody := getPath(t, s, "/models/"+id)
		if gotStatus != wantStatus || gotBody != wantBody {
			t.Errorf("GET /models/%s = %d %s; want identical to the /v1 form (%d %s)",
				id, gotStatus, gotBody, wantStatus, wantBody)
		}
		// Whatever the answer is, it must not be net/http's non-JSON default —
		// that unparseable body is the whole reason the alias exists.
		if !isJSONBody(gotBody) {
			t.Errorf("GET /models/%s returned a non-JSON body: %q", id, gotBody)
		}
	}
}

// isJSONBody reports whether the body's first non-space byte opens a JSON object
// or array, i.e. that it is not net/http's bare "404 page not found" text.
func isJSONBody(b string) bool {
	for _, c := range b {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return true
		default:
			return false
		}
	}
	return false
}

// POST endpoints get NO host-relative alias: there the version prefix is part of
// the protocol contract, and accepting both spellings would imply
// /chat/completions is a supported address.
func TestRoutes_NoHostRelativePostAlias(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/chat/completions", `{"model":"gpt-test"}`))
	if w.Result().StatusCode != http.StatusNotFound {
		t.Errorf("POST /chat/completions = %d, want 404 (no alias for POST routes)", w.Result().StatusCode)
	}
}
