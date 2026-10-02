/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func TestWriteOpenAIError_Shape(t *testing.T) {
	w := httptest.NewRecorder()
	writeOpenAIError(w, 418, "proxy_error", "teapot", "i am a teapot")

	if got := w.Result().StatusCode; got != 418 {
		t.Errorf("status = %d", got)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("content-type = %q", ct)
	}

	var env openAIErrorEnvelope
	if err := json.NewDecoder(w.Body).Decode(&env); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if env.Error.Message != "i am a teapot" {
		t.Errorf("message = %q", env.Error.Message)
	}
	if env.Error.Type != "proxy_error" {
		t.Errorf("type = %q", env.Error.Type)
	}
	if env.Error.Code != "teapot" {
		t.Errorf("code = %q", env.Error.Code)
	}
}

func TestWriteOpenAIError_CodeOmittedWhenEmpty(t *testing.T) {
	w := httptest.NewRecorder()
	writeOpenAIError(w, 500, "proxy_error", "", "boom")

	// Decode as a generic map to verify the `code` key is absent.
	var raw map[string]any
	if err := json.NewDecoder(w.Body).Decode(&raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	errMap, _ := raw["error"].(map[string]any)
	if _, present := errMap["code"]; present {
		t.Error("code key should be omitted when empty")
	}
}
