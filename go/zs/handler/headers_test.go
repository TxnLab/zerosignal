/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"net/http"
	"testing"
)

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
