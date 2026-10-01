/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package relay_test

import (
	"testing"

	"github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/wire"
)

func TestBuildRequest(t *testing.T) {
	r := relay.BuildRequest("https://relay.example/", 42, 7, "/v1/chat/completions", "POST")
	if want := "https://relay.example" + wire.RelayPath; r.URL != want {
		t.Errorf("URL = %q, want %q", r.URL, want)
	}
	if r.Target != "42" {
		t.Errorf("Target = %q, want 42", r.Target)
	}
	if r.TargetNode != "7" {
		t.Errorf("TargetNode = %q, want 7", r.TargetNode)
	}
	if r.Path != "/v1/chat/completions" || r.Method != "POST" {
		t.Errorf("Path/Method = %q/%q", r.Path, r.Method)
	}
}

func TestIsHopErrorCode(t *testing.T) {
	// Relay-generated codes that mean the relay (outer hop) failed.
	hop := []string{
		relay.CodeBadTarget,
		relay.CodeBadPath,
		relay.CodeBadMethod,
		relay.CodeBusy,
		relay.CodeUnknownTarget,
		relay.CodeBuildRequest,
	}
	for _, c := range hop {
		if !relay.IsHopErrorCode(c) {
			t.Errorf("IsHopErrorCode(%q) = false, want true", c)
		}
	}
	// Target-side: upstream-unreachable (relay reached, target down) and any
	// non-relay / unknown code (the target's own forwarded error).
	notHop := []string{
		relay.CodeUpstreamUnreachable,
		"ticket_required",
		"rate_limited",
		"",
		"relay_unknown_future_code",
	}
	for _, c := range notHop {
		if relay.IsHopErrorCode(c) {
			t.Errorf("IsHopErrorCode(%q) = true, want false", c)
		}
	}
}

func TestIsAllowedInnerPath(t *testing.T) {
	allowed := []string{
		"/v1/chat/completions",
		"/v1/responses",
		"/v1/images/generations",
		"/v1/images/edits",
		"/v1/models",
		"/v1/models/gpt-4.1-mini",
		"/v1/zs/reserve",
		"/v1/zs/details",
		"/v1/zs/attestation",
		// Per-model deep details probe (SPEC §3c): a query string scopes the
		// request; the allow-list gates the path, the relay forwards the query.
		"/v1/zs/details?model=alpha&expand=coordinates",
		"/v1/zs/details?expand=coordinates%2Cdigest&model=Qwen%2FQwen2.5-7B",
		"/v1/models/gpt-4.1-mini?x=y",
	}
	for _, p := range allowed {
		if !relay.IsAllowedInnerPath(p) {
			t.Errorf("IsAllowedInnerPath(%q) = false, want true", p)
		}
	}

	denied := []string{
		wire.RelayPath,                // no relay-to-relay chaining
		"/v1/zs/relay",                // same, explicit
		"/v1/zs/relay?x=y",            // ...even with a query
		"/v1/models/",                 // empty model id
		"/v1/models/a/b",              // multi-segment id
		"/v1/models/../hayai/reserve", // traversal
		"/v1/chat/completions/../admin",
		"/v1/chat/completions/../admin?q=1", // traversal survives a query suffix
		"/admin",
		"/admin?x=y", // a query can't launder a disallowed path
		"/healthz",
		"/metrics",
		"",
		"http://evil.example/",
	}
	for _, p := range denied {
		if relay.IsAllowedInnerPath(p) {
			t.Errorf("IsAllowedInnerPath(%q) = true, want false", p)
		}
	}
}
