/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package relay holds the transport-binding helpers for single-hop
// operator-as-relay routing (transport-privacy option A). It is pure: it
// builds the relay-indirection metadata a "user" endpoint (proxy / client)
// attaches to an outbound request, and defines the closed allow-list of inner
// paths a relaying node will forward. The header names and route constant live
// in proto/go/wire; this package shapes how they're used so the proxy and the
// client/ chat app relay identically. Mirrored in proto/ts/src/relay.
//
// The relay never decrypts: the request stays sealed to the target operator's
// age key. These helpers only move routing metadata (target id, inner path,
// inner method) that the relay needs to forward the bytes — and which it
// would observe anyway, since it must open a connection to the target.
package relay

import (
	"strconv"
	"strings"

	"github.com/TxnLab/zerosignal/go/wire"
)

// Request is the relay indirection for one inner request: the URL to send to
// (the relay's RelayPath endpoint) plus the values for the three relay
// headers. The caller sets wire.RelayTargetHeader / RelayPathHeader /
// RelayMethodHeader to Target / Path / Method respectively. Kept as plain
// strings so this package stays free of net/http.
type Request struct {
	URL        string // relay endpoint to send the inner request to
	Target     string // value for wire.RelayTargetHeader (target operator id)
	TargetNode string // value for wire.RelayTargetNodeHeader (target node id within the operator)
	Path       string // value for wire.RelayPathHeader (inner request path)
	Method     string // value for wire.RelayMethodHeader (inner request method)
}

// BuildRequest constructs the relay indirection for an inner request bound for
// the (targetOperatorID, targetNodeID) destination node. relayBaseURL is the
// chosen relay node's root; innerPath and innerMethod identify the inner
// request the relay reconstructs against the target. The body and content-type
// are unchanged from the direct case — the caller sends them as-is to
// Request.URL.
func BuildRequest(relayBaseURL string, targetOperatorID, targetNodeID uint64, innerPath, innerMethod string) Request {
	return Request{
		URL:        strings.TrimRight(relayBaseURL, "/") + wire.RelayPath,
		Target:     strconv.FormatUint(targetOperatorID, 10),
		TargetNode: strconv.FormatUint(targetNodeID, 10),
		Path:       innerPath,
		Method:     innerMethod,
	}
}

// exactAllowedInnerPaths is the closed set of fixed inner paths a relay will
// forward. RelayPath itself is deliberately absent — relaying is single-hop,
// so a relay must never forward to another relay (no chaining / loops).
var exactAllowedInnerPaths = map[string]struct{}{
	"/v1/chat/completions":   {},
	"/v1/responses":          {},
	"/v1/images/generations": {},
	"/v1/images/edits":       {},
	"/v1/models":             {},
	"/v1/zs/reserve":         {},
	"/v1/zs/details":         {},
	"/v1/zs/attestation":     {},
}

// modelsPrefix matches the per-model discovery route /v1/models/{id}.
const modelsPrefix = "/v1/models/"

// Relay error codes are the values a relaying node puts in the OpenAI-shaped
// error body's "code" field (see the node's writeOpenAIError calls on the
// /v1/zs/relay route). They identify failures that happened at the relay —
// the *outer hop* — as opposed to the target operator. A "user" endpoint
// (proxy / client) routing a request through a relay uses these to attribute a
// failure correctly: a relay-hop failure must NOT be mistaken for the target
// being down.
//
// CodeUpstreamUnreachable is the deliberate exception: the relay emits it
// precisely when it reached out but the *target* was unreachable, so it is a
// target-side signal, not a relay-side one — see IsHopErrorCode.
const (
	CodeBadTarget           = "relay_bad_target"           // 400: malformed/missing X-Zs-Relay-Target
	CodeBadPath             = "relay_bad_path"             // 400: inner path not relay-forwardable
	CodeBadMethod           = "relay_bad_method"           // 400: inner method not GET/POST
	CodeBusy                = "relay_busy"                 // 503: relay at its concurrent-circuit cap
	CodeUnknownTarget       = "relay_unknown_target"       // 404: target id not a known on-chain operator
	CodeBuildRequest        = "relay_build_request"        // 502: relay could not construct the inner request
	CodeUpstreamUnreachable = "relay_upstream_unreachable" // 502: relay reached out but the target was down
)

// IsHopErrorCode reports whether code names a relay-generated error that means
// the relay itself (the outer hop) failed — as opposed to the target. It
// returns false for CodeUpstreamUnreachable (relay reached, target down → a
// target-side signal) and for every non-relay code: a relay forwards the
// target's own error responses verbatim, and those never carry a relay_ code,
// so an unrecognized code is treated as a target-side failure.
func IsHopErrorCode(code string) bool {
	switch code {
	case CodeBadTarget, CodeBadPath, CodeBadMethod, CodeBusy, CodeUnknownTarget, CodeBuildRequest:
		return true
	default:
		return false
	}
}

// IsAllowedInnerPath reports whether p is a path a relay may forward. This is
// the SSRF boundary on the relay side: anything outside the allow-list (or any
// path attempting traversal) is rejected, so a relay can only be used to reach
// the well-known hayai endpoints on a known operator — never as a
// general-purpose open proxy.
func IsAllowedInnerPath(p string) bool {
	// The relay forwards any query string to the target verbatim (it is
	// appended to the fixed on-chain baseURL — see the node relay handler), so
	// the query can change neither the host nor the route. The allow-list (the
	// SSRF boundary) therefore gates the PATH only: split off the query before
	// matching. The per-model deep details probe rides
	// /v1/zs/details?model=…&expand=… (SPEC §3c "Deep model details").
	path := p
	if i := strings.IndexByte(p, '?'); i >= 0 {
		path = p[:i]
	}
	// Defense-in-depth: reject traversal and anything not rooted at /v1/.
	// Applied to the path portion so a traversal in a query value (not a route
	// traversal) doesn't false-reject an otherwise-allowed endpoint.
	if strings.Contains(path, "..") || !strings.HasPrefix(path, "/v1/") {
		return false
	}
	if _, ok := exactAllowedInnerPaths[path]; ok {
		return true
	}
	// /v1/models/{id}: a single non-empty path segment (no further slashes),
	// matching the node's own GET /v1/models/{id} route shape.
	if strings.HasPrefix(path, modelsPrefix) {
		id := path[len(modelsPrefix):]
		return id != "" && !strings.Contains(id, "/")
	}
	return false
}
