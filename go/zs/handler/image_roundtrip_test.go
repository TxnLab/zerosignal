/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// TestDispatchHayai_Image_RoundTrip is the proxy-side e2e for the
// image-generation route: client POSTs OpenAI-shape JSON →
// dispatchHayai picks the operator → reserves with the synthetic-token
// sizing (image_n on the rate basis) → seals the request → forwards to the
// node (here, a fakeNode that handleSealed-decrypts and returns a
// canned image response) → unseals and returns to the client.
//
// Covers the path the unit tests can't:
//
//   - the dispatchHayai image branch (skips estimateTokens, parses n)
//   - the per-operator reserve override that swaps in
//     image_n / image_size / image_quality for the rate reserve
//   - the proxy correctly URL-routes the sealed body to
//     <op>/v1/images/generations (not chat/responses)
func TestDispatchHayai_Image_RoundTrip(t *testing.T) {
	canned := []byte(`{"created":1700000000,"data":[{"b64_json":"aGVsbG8="}]}`)
	const (
		factor uint64 = 100_000
		n             = 2
	)

	var seenBody []byte
	var seenPath string
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: canned,
		onRequest: func(r *http.Request, b []byte) {
			seenBody = append([]byte(nil), b...)
			seenPath = r.URL.Path
		},
	})

	// Re-skin the fake operator as an image-only operator: declare
	// the model, hydrate ModelCapacities with the synthetic-token
	// factor, mark Reachable so any "skip unreachable" guards pass.
	// Mutate BEFORE setupHayai — it copies n.operator into the
	// static registry, so post-setup edits wouldn't propagate.
	node.operator.Models = []string{"sdxl-test"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"sdxl-test": {
			InputModalities:    []string{"text"},
			OutputModalities:   []string{"image"},
			ImageRateMicroUSDC: factor,
			OutputUSDPer1M:     0.5,
		},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	clientBody := `{"model":"sdxl-test","prompt":"a cat","n":2,"size":"512x512"}`
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/images/generations", clientBody))

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), canned) {
		t.Errorf("client body = %q, want %q", w.Body.Bytes(), canned)
	}

	// Node must have been hit on the right URL — proxy routes the
	// path it dispatched (endpointImages), not the chat URL.
	if seenPath != "/v1/images/generations" {
		t.Errorf("node saw path %q, want /v1/images/generations", seenPath)
	}

	// Node saw the decrypted body — but the proxy injects
	// `store: false` when omitted (SPEC.md "Upstream retention"),
	// so the order is the JSON key sort.
	var sawReq map[string]any
	if err := json.Unmarshal(seenBody, &sawReq); err != nil {
		t.Fatalf("node body not JSON: %v\n%s", err, seenBody)
	}
	if sawReq["model"] != "sdxl-test" {
		t.Errorf("node body model = %v", sawReq["model"])
	}
	if got, _ := sawReq["n"].(float64); int(got) != n {
		t.Errorf("node body n = %v, want %d", sawReq["n"], n)
	}

	// Three calls: GET /v1/zs/details probe (StaticRegistryProvider
	// doesn't run one), POST /v1/zs/reserve, POST /v1/images/generations.
	// With the static provider only the latter two reach the node.
	if node.callCount != 2 {
		t.Errorf("node.callCount = %d, want 2 (reserve + image-gen)", node.callCount)
	}
}

// TestDispatchHayai_Image_SkipsOperatorMissingFactor — operators
// advertising the image model but lacking an image rate (ServesImageGen false) are skipped
// so the proxy doesn't size-reserve with a zero factor. With only one
// such operator the dispatch ends in operators_busy (no candidates
// landed a ticket).
func TestDispatchHayai_Image_SkipsOperatorMissingFactor(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	node.operator.Models = []string{"sdxl-test"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"sdxl-test": {
			OutputModalities: []string{"image"},
			// ImageRateMicroUSDC intentionally unset — defensive case.
		},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, clientReq(http.MethodPost, "/v1/images/generations",
		`{"model":"sdxl-test","prompt":"x","n":1}`))

	if w.Result().StatusCode == http.StatusOK {
		t.Errorf("status = 200, want 4xx/5xx — operator was skipped, dispatch must fail")
	}
	// Reserve must NOT have been attempted on the skipped operator.
	if node.callCount > 0 {
		t.Errorf("node.callCount = %d, want 0 — skipped operator should never get a reserve", node.callCount)
	}
}
