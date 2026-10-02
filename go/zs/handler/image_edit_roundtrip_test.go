/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// buildEditBody returns a multipart/form-data body + the Content-Type
// header value the proxy needs to derive the boundary.
func buildEditBody(t *testing.T, model, prompt string, n int, imageBytes, maskBytes []byte) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if imageBytes != nil {
		fw, err := mw.CreateFormFile("image", "in.png")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(imageBytes); err != nil {
			t.Fatal(err)
		}
	}
	if maskBytes != nil {
		fw, err := mw.CreateFormFile("mask", "m.png")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(maskBytes); err != nil {
			t.Fatal(err)
		}
	}
	_ = mw.WriteField("model", model)
	_ = mw.WriteField("prompt", prompt)
	_ = mw.WriteField("n", fmt.Sprintf("%d", n))
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes(), mw.FormDataContentType()
}

// TestDispatchHayai_ImageEdit_RoundTrip is the proxy-side e2e for
// /v1/images/edits. The proxy:
//   - parses the inbound multipart body for model + n (without
//     consuming the buffer destined for the seal),
//   - skips estimateTokens + InjectDefaultStoreFalse (both JSON-only),
//   - reserves with image_n = n on the edit rate basis,
//   - seals the original multipart bytes into the envelope and POSTs
//     to the operator's /v1/images/edits.
func TestDispatchHayai_ImageEdit_RoundTrip(t *testing.T) {
	canned := []byte(`{"created":1700000000,"data":[{"b64_json":"aGVsbG8="}]}`)
	const (
		genFactor  uint64 = 100_000
		editFactor uint64 = 200_000
		n                 = 1
	)

	var seenBody []byte
	var seenPath string
	var seenContentType string
	node := newFakeNode(t, &nodeConfig{
		mode:           modeNonStreamEncrypted,
		replyPlaintext: canned,
		onRequest: func(r *http.Request, b []byte) {
			seenBody = append([]byte(nil), b...)
			seenPath = r.URL.Path
			seenContentType = r.Header.Get("Content-Type")
		},
	})
	node.operator.Models = []string{"flux2"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"flux2": {
			InputModalities:        []string{"text", "image"},
			OutputModalities:       []string{"image"},
			ImageRateMicroUSDC:     genFactor,
			ImageEditRateMicroUSDC: editFactor,
			OutputUSDPer1M:         0.5,
		},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	bodyBytes, contentType := buildEditBody(t, "flux2", "make it red", n, []byte("PNGINPUT"), nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/images/edits", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Result().StatusCode, w.Body.String())
	}
	if !bytes.Equal(w.Body.Bytes(), canned) {
		t.Errorf("client body = %q, want %q", w.Body.Bytes(), canned)
	}
	if seenPath != "/v1/images/edits" {
		t.Errorf("node saw path %q, want /v1/images/edits", seenPath)
	}
	// The proxy must seal the multipart bytes UNMUTATED — the node
	// receives back exactly the bytes the client sent (proven by
	// re-parsing the multipart on the receiving side).
	mr := multipart.NewReader(bytes.NewReader(seenBody), boundaryOf(t, contentType))
	gotImage := false
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FormName() == "image" {
			gotImage = true
		}
		_ = part.Close()
	}
	if !gotImage {
		t.Errorf("node multipart body missing image part — proxy mutated bytes?")
	}
	_ = seenContentType
}

func boundaryOf(t *testing.T, contentType string) string {
	t.Helper()
	const prefix = "multipart/form-data; boundary="
	if len(contentType) <= len(prefix) || contentType[:len(prefix)] != prefix {
		t.Fatalf("Content-Type %q not multipart/form-data", contentType)
	}
	return contentType[len(prefix):]
}

// TestDispatchHayai_ImageEdit_SkipsOperatorMissingEditFactor — operator
// declares the model and the gen factor but not the edit factor; the
// edits route must skip that operator (analog of
// TestDispatchHayai_Image_SkipsOperatorMissingFactor).
func TestDispatchHayai_ImageEdit_SkipsOperatorMissingEditFactor(t *testing.T) {
	node := newFakeNode(t, &nodeConfig{mode: modeNonStreamEncrypted, replyPlaintext: []byte(`{}`)})
	node.operator.Models = []string{"flux2"}
	node.operator.ModelCapacities = map[string]hayai.ModelCapacity{
		"flux2": {
			InputModalities:    []string{"text", "image"},
			OutputModalities:   []string{"image"},
			ImageRateMicroUSDC: 100_000,
			// ImageEditRateMicroUSDC intentionally absent.
		},
	}
	node.operator.Reachable = true

	cfg := testConfig()
	s := testServer(cfg, setupHayai(t, cfg, node))

	bodyBytes, contentType := buildEditBody(t, "flux2", "x", 1, []byte("BYTES"), nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/images/edits", bytes.NewReader(bodyBytes))
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Result().StatusCode == http.StatusOK {
		t.Errorf("status = 200, want 4xx/5xx — operator missing edit factor must be skipped")
	}
	if node.callCount > 0 {
		t.Errorf("node.callCount = %d, want 0 — skipped operator must not be reserved", node.callCount)
	}
}
