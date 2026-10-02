/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
)

// debugDumpRequestBody writes the plaintext request body the proxy is about to
// seal and send to the node to stderr, unescaped.
//
// This DELIBERATELY violates the non-retention rule documented in AGENTS.md
// ("never put request bodies ... into slog, traces, or any persistent sink").
// It exists solely as a local-debugging escape hatch and is gated behind the
// off-by-default Config.DebugLogBodies (the proxy's -debug-bodies flag, which
// logs a loud startup warning when on). Never enable it in production.
//
// Output goes straight to stderr via Fprintf rather than slog so the JSON is
// readable natively — a slog string attribute would escape quotes/newlines.
// The body is pretty-printed when it parses as JSON (chat/responses); for a
// non-JSON body (e.g. multipart image-edits) the raw bytes are written as-is.
func (s *Client) debugDumpRequestBody(endpoint string, operatorID uint64, ticketID string, body []byte) {
	if !s.debugLogBodies {
		return
	}
	out := body
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		out = pretty.Bytes()
	}
	fmt.Fprintf(os.Stderr,
		"\n=== hayai debug: POST %s -> operator %d (ticket %s) ===\n%s\n=== end request body ===\n",
		endpoint, operatorID, ticketID, out)
}

// debugDumpResponseBody writes the decrypted NON-STREAMING response body the
// proxy is about to return to the client to stderr. Same escape-hatch contract
// as debugDumpRequestBody — gated behind -debug-bodies, stderr only (not slog),
// off by default, never in production. Pretty-printed when it parses as JSON.
func (s *Client) debugDumpResponseBody(endpoint string, operatorID uint64, ticketID string, body []byte) {
	if !s.debugLogBodies {
		return
	}
	out := body
	var pretty bytes.Buffer
	if json.Indent(&pretty, body, "", "  ") == nil {
		out = pretty.Bytes()
	}
	fmt.Fprintf(os.Stderr,
		"\n=== hayai debug: RESPONSE %s <- operator %d (ticket %s) ===\n%s\n=== end response body ===\n",
		endpoint, operatorID, ticketID, out)
}

// debugDumpResponseFrame writes one decrypted STREAMING response frame to
// stderr as the proxy forwards it — a content delta, a tool-call fragment, a
// sealed mid-stream error, or a hayai status event. Frame-by-frame (one line
// each, tagged with ticket + frame index so interleaved parallel streams stay
// readable) so a stream cancelled before it completes still shows whatever the
// node managed to send. Same escape-hatch contract as the others.
func (s *Client) debugDumpResponseFrame(endpoint string, operatorID uint64, ticketID string, frameIndex uint64, plaintext []byte) {
	if !s.debugLogBodies {
		return
	}
	fmt.Fprintf(os.Stderr, "[zs debug] stream frame %d %s <- op %d (ticket %s): %s\n",
		frameIndex, endpoint, operatorID, ticketID, plaintext)
}
