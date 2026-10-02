/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"crypto/subtle"
	"net"
	"net/http"
)

// handleShutdown is the loopback-only graceful-stop control channel. It exists
// for Windows, which has no SIGTERM: `proxy stop` POSTs here with the token from
// daemon.json, and the handler triggers the same graceful drain a SIGTERM does
// on unix. Registered only when a shutdown token is configured (see routes()).
//
// Two guards: the request must originate on the loopback interface (it can't
// come from off-box even if the proxy binds a public address), and it must carry
// the matching X-Shutdown-Token. The token lives in daemon.json, readable only
// by the user who owns the process — consistent with the single-user-localhost
// model. This is a control-plane endpoint with no request/response content, so
// it does not touch the non-retention rule.
func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	if !isLoopbackRequest(r) {
		http.Error(w, "shutdown is loopback-only", http.StatusForbidden)
		return
	}
	got := r.Header.Get("X-Shutdown-Token")
	if s.shutdownToken == "" || subtle.ConstantTimeCompare([]byte(got), []byte(s.shutdownToken)) != 1 {
		http.Error(w, "invalid shutdown token", http.StatusForbidden)
		return
	}
	if s.shutdown == nil {
		http.Error(w, "shutdown not available", http.StatusServiceUnavailable)
		return
	}

	s.log.Info("graceful shutdown requested via control channel")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"stopping"}` + "\n"))
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	// Trigger the drain after the response is on the wire, and asynchronously so
	// this handler returns and frees its connection for srv.Shutdown to drain.
	go s.shutdown()
}

// isLoopbackRequest reports whether the request originated from the loopback
// interface (127.0.0.0/8 or ::1).
func isLoopbackRequest(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
