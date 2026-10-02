/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newShutdownTestServer(token string, onShutdown func()) *Server {
	return &Server{
		log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
		shutdownToken: token,
		shutdown:      onShutdown,
	}
}

func postShutdown(s *Server, remoteAddr, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/shutdown", nil)
	req.RemoteAddr = remoteAddr
	if token != "" {
		req.Header.Set("X-Shutdown-Token", token)
	}
	rec := httptest.NewRecorder()
	s.handleShutdown(rec, req)
	return rec
}

func TestHandleShutdownValid(t *testing.T) {
	called := make(chan struct{}, 1)
	s := newShutdownTestServer("secret", func() { called <- struct{}{} })

	rec := postShutdown(s, "127.0.0.1:54321", "secret")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown callback was not invoked")
	}
}

func TestHandleShutdownRejects(t *testing.T) {
	cases := []struct {
		name       string
		remoteAddr string
		token      string
		wantCode   int
	}{
		{"wrong token", "127.0.0.1:5", "nope", http.StatusForbidden},
		{"missing token", "127.0.0.1:5", "", http.StatusForbidden},
		{"non-loopback caller", "203.0.113.7:5", "secret", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fired := make(chan struct{}, 1)
			s := newShutdownTestServer("secret", func() { fired <- struct{}{} })

			rec := postShutdown(s, tc.remoteAddr, tc.token)
			if rec.Code != tc.wantCode {
				t.Fatalf("status = %d, want %d", rec.Code, tc.wantCode)
			}
			// A rejected request must never reach the trigger.
			time.Sleep(50 * time.Millisecond)
			select {
			case <-fired:
				t.Fatal("shutdown callback fired on a rejected request")
			default:
			}
		})
	}
}

func TestIsLoopbackRequest(t *testing.T) {
	cases := map[string]bool{
		"127.0.0.1:8080": true,
		"[::1]:8080":     true,
		"127.0.0.1":      true, // no port → host is the whole string
		"203.0.113.7:9":  false,
		"10.0.0.5:9":     false,
	}
	for addr, want := range cases {
		req := httptest.NewRequest(http.MethodPost, "/shutdown", nil)
		req.RemoteAddr = addr
		if got := isLoopbackRequest(req); got != want {
			t.Errorf("isLoopbackRequest(%q) = %v, want %v", addr, got, want)
		}
	}
}
