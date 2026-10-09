/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"mime/multipart"
	"testing"
)

func TestStreamableRequest(t *testing.T) {
	cases := []struct {
		name string
		body string
		want bool
	}{
		{"stream true", `{"stream":true}`, true},
		{"stream false", `{"stream":false}`, false},
		{"missing", `{}`, false},
		{"null", `{"stream":null}`, false},
		{"invalid JSON", `{not-json`, false},
		{"stream with siblings", `{"model":"x","stream":true,"temperature":0}`, true},
		{"stream as string", `{"stream":"true"}`, false},
		{"empty", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := streamableRequest([]byte(tc.body)); got != tc.want {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestParseImageEditMultipart(t *testing.T) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("image", "in.png")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("X")); err != nil {
		t.Fatal(err)
	}
	_ = mw.WriteField("model", "flux2")
	_ = mw.WriteField("prompt", "hello")
	_ = mw.WriteField("n", "3")
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	model, n, _, _, _, err := parseImageEditMultipart(mw.FormDataContentType(), buf.Bytes())
	if err != nil {
		t.Fatalf("parseImageEditMultipart: %v", err)
	}
	if model != "flux2" {
		t.Errorf("model = %q", model)
	}
	if n != 3 {
		t.Errorf("n = %d", n)
	}
}
