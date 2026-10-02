/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package transform

import (
	"bytes"
	"context"
	"net/http"
	"testing"
)

func TestPassthrough_TransformRequest(t *testing.T) {
	pt := Passthrough{}
	body := []byte("hello")
	headers := http.Header{"X-Test": []string{"v"}}

	newBody, newHeaders, err := pt.TransformRequest(context.Background(), "/v1/x", body, headers)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(newBody, body) {
		t.Errorf("body = %q, want %q", newBody, body)
	}
	if got := newHeaders.Get("X-Test"); got != "v" {
		t.Errorf("header X-Test = %q, want %q", got, "v")
	}
}

func TestPassthrough_TransformResponse(t *testing.T) {
	pt := Passthrough{}
	body := []byte("response")

	newBody, err := pt.TransformResponse(context.Background(), "/v1/x", body, http.Header{})
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if !bytes.Equal(newBody, body) {
		t.Errorf("body = %q, want %q", newBody, body)
	}
}

func TestPassthrough_TransformStreamChunk(t *testing.T) {
	pt := Passthrough{}
	in := SSEFrame{Event: "e", Data: []byte("d"), ID: "1"}

	out, err := pt.TransformStreamChunk(context.Background(), "/v1/x", in)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if out.Event != in.Event || !bytes.Equal(out.Data, in.Data) || out.ID != in.ID {
		t.Errorf("frame mismatch: got %+v, want %+v", out, in)
	}
}
