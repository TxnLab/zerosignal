/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestShutdownRouteEndToEnd exercises the full wiring the daemon relies on: a
// server built with a shutdown token registers POST /shutdown, a real loopback
// POST with the token reaches the handler through the middleware chain, and the
// handler's trigger drives a graceful srv.Shutdown — mirroring app.Run, where
// the trigger is the run-context cancel.
func TestShutdownRouteEndToEnd(t *testing.T) {
	const token = "integration-tok"
	cfg := testConfig()

	stopped := make(chan struct{})
	var hs *http.Server
	s := testServer(cfg, Options{
		ShutdownToken: token,
		// Mirror app.Run: the control channel triggers a graceful drain. Run
		// async so the /shutdown request's own connection is freed for Shutdown.
		Shutdown: func() { go func() { _ = hs.Shutdown(context.Background()) }() },
	})
	hs = s.HTTPServer(ListenConfig{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		_ = hs.Serve(ln) // returns ErrServerClosed once Shutdown runs
		close(stopped)
	}()

	req, err := http.NewRequest(http.MethodPost, "http://"+ln.Addr().String()+"/shutdown", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Shutdown-Token", token)
	resp, err := (&http.Client{Timeout: 2 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("POST /shutdown: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	select {
	case <-stopped:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not shut down after POST /shutdown")
	}
}

// TestShutdownRouteUnregisteredWithoutToken confirms the route is conditional:
// a foreground / service-managed run (no token) does not expose POST /shutdown.
func TestShutdownRouteUnregisteredWithoutToken(t *testing.T) {
	s := testServer(testConfig(), Options{}) // no ShutdownToken

	req := httptest.NewRequest(http.MethodPost, "/shutdown", nil)
	req.RemoteAddr = "127.0.0.1:1"
	w := httptest.NewRecorder()
	s.mux.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 (route must be unregistered without a token)", w.Code)
	}
}
