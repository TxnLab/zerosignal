/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/TxnLab/zerosignal/go/wire"
)

const testOperatorBaseURL = "https://op.example.com"

func TestBuildOperatorRequest_NoBearerInjected(t *testing.T) {
	// The proxy never injects bearer auth — admission is via the on-chain seal.
	s := testServer(testConfig(), Options{})

	client := http.Header{"Authorization": []string{"Bearer client-key"}}
	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/v1/chat/completions", []byte(`{}`), "application/json", client)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty, got %q", got)
	}
}

func TestBuildOperatorRequest_AcceptHayai(t *testing.T) {
	s := testServer(testConfig(), Options{})

	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/v1/chat/completions", []byte(`{}`), wire.EncryptedContentType, nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	accept := req.Header.Get("Accept")
	if !strings.Contains(accept, wire.EncryptedContentType) {
		t.Errorf("Accept missing hayai MIME: %q", accept)
	}
	if !strings.Contains(accept, "application/json") {
		t.Errorf("Accept missing application/json: %q", accept)
	}
}

func TestBuildOperatorRequest_AcceptPlaintext(t *testing.T) {
	s := testServer(testConfig(), Options{})

	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/v1/chat/completions", []byte(`{}`), "application/json", nil)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
}

func TestBuildOperatorRequest_HopByHopStripped(t *testing.T) {
	s := testServer(testConfig(), Options{})

	hops := http.Header{
		"Connection":         []string{"keep-alive"},
		"Keep-Alive":         []string{"timeout=5"},
		"Transfer-Encoding":  []string{"chunked"},
		"Upgrade":            []string{"websocket"},
		"Proxy-Authenticate": []string{"x"},
	}
	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/x", []byte(`{}`), "application/json", hops)
	if err != nil {
		t.Fatal(err)
	}
	for k := range hops {
		if v := req.Header.Get(k); v != "" {
			t.Errorf("%s should have been stripped, got %q", k, v)
		}
	}
}

func TestBuildOperatorRequest_ClientHeadersForwarded(t *testing.T) {
	s := testServer(testConfig(), Options{})

	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/x", []byte(`{}`), "application/json", http.Header{"X-Request-ID": []string{"r1"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("X-Request-ID"); got != "r1" {
		t.Errorf("X-Request-ID = %q", got)
	}
}

func TestBuildOperatorRequest_AuthInExtraHeadersDropped(t *testing.T) {
	// Even if a transformer sneaks an Authorization header into the
	// extras map, buildOperatorRequest must silently drop it — the
	// proxy never authenticates to the operator with a bearer token.
	s := testServer(testConfig(), Options{})

	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/x", []byte(`{}`), "application/json",
		http.Header{"authorization": []string{"Bearer leaked"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := req.Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization should be empty, got %q", got)
	}
}

func TestBuildOperatorRequest_EmptyBody(t *testing.T) {
	s := testServer(testConfig(), Options{})

	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodGet, "/v1/models", nil, "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if req.Body != nil && req.Body != http.NoBody {
		b, _ := io.ReadAll(req.Body)
		if len(b) != 0 {
			t.Errorf("GET body not empty: %q", b)
		}
	}
}

func TestBuildOperatorRequest_URL(t *testing.T) {
	s := testServer(testConfig(), Options{})

	req, err := s.buildOperatorRequest(context.Background(), testOperatorBaseURL, http.MethodPost, "/v1/chat/completions", []byte(`{}`), "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.String(); got != testOperatorBaseURL+"/v1/chat/completions" {
		t.Errorf("URL = %q", got)
	}
	if req.Method != http.MethodPost {
		t.Errorf("Method = %q", req.Method)
	}
}

func TestCopyResponseHeaders_StripsHopByHop(t *testing.T) {
	src := http.Header{
		"Connection":        []string{"keep-alive"},
		"Transfer-Encoding": []string{"chunked"},
		"Content-Type":      []string{"application/json"},
		"X-Cool":            []string{"yes"},
	}
	dst := http.Header{}
	copyResponseHeaders(dst, src)

	if dst.Get("Connection") != "" {
		t.Error("Connection leaked")
	}
	if dst.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding leaked")
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type dropped")
	}
	if dst.Get("X-Cool") != "yes" {
		t.Error("X-Cool dropped")
	}
}
