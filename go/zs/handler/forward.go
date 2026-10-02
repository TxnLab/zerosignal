/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
	hayai "github.com/TxnLab/zerosignal/go/zs"
)

// openAIErrorCode best-effort extracts the OpenAI-shaped error "code" from a
// (>=400) error body. Returns "" when the body isn't that shape — e.g. a sealed
// envelope or a non-JSON payload — in which case the caller treats it as a
// non-relay (target / success) outcome, since a relay forwards the target's own
// responses verbatim and those never carry a relay_ code.
func openAIErrorCode(body []byte) string {
	if len(body) == 0 {
		return ""
	}
	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal(body, &parsed) != nil {
		return ""
	}
	return parsed.Error.Code
}

// hopByHopHeaders are per-hop headers that MUST NOT be forwarded end-to-end.
var hopByHopHeaders = map[string]struct{}{
	"Connection":          {},
	"Keep-Alive":          {},
	"Proxy-Authenticate":  {},
	"Proxy-Authorization": {},
	"Te":                  {},
	"Trailers":            {},
	"Transfer-Encoding":   {},
	"Upgrade":             {},
}

// buildOperatorRequest creates an outbound HTTP request to the operator at
// baseURL. The proxy never injects bearer auth — admission is via the on-chain
// sealed envelope. The client's Authorization header is deliberately discarded.
// `contentType` sets the outbound Content-Type — use "application/json" for
// plaintext OpenAI and the hayai vendor type for encrypted envelopes.
//
// baseURL is the per-operator URL from the registry; it must be non-empty
// and is already scheme-validated at registry-load time.
func (s *Server) buildOperatorRequest(
	ctx context.Context,
	baseURL, method, endpoint string,
	body []byte,
	contentType string,
	extraHeaders http.Header,
) (*http.Request, error) {
	url := baseURL + endpoint

	var reader io.Reader
	if len(body) > 0 {
		reader = bytes.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, fmt.Errorf("build operator request: %w", err)
	}

	req.Header.Set("Content-Type", contentType)
	// Hayai envelopes may come back as application/vnd.zs+json; advertise
	// both so a strict node doing content negotiation won't 406.
	if contentType == wire.EncryptedContentType {
		req.Header.Set("Accept", wire.EncryptedContentType+", application/json")
	} else {
		req.Header.Set("Accept", "application/json")
	}

	for k, vs := range extraHeaders {
		if _, hop := hopByHopHeaders[http.CanonicalHeaderKey(k)]; hop {
			continue
		}
		// Never let the client or transformer override auth. The proxy
		// does not authenticate to operators with bearer tokens — the
		// sealed envelope is the admission credential.
		if strings.EqualFold(k, "Authorization") {
			continue
		}
		req.Header[http.CanonicalHeaderKey(k)] = append([]string(nil), vs...)
	}

	return req, nil
}

// nonStreamResponder handles an operator response after the raw forwarder
// has buffered it. The responder owns what the caller sees (em.reply or
// em.fail). Returning an error means it emitted nothing, and the forwarder
// reports it.
type nonStreamResponder func(em emitter, upstreamResp *http.Response, respBody []byte) error

// forwardRawNonStream is the low-level non-streaming forwarder used by the
// hayai dispatcher. It does not invoke the RequestTransformer — the caller
// is responsible for whatever request-side processing is appropriate, and
// supplies the final body, outbound Content-Type, and extra headers.
//
// baseURL is the per-operator URL from the registry; it must be non-empty.
func (s *Server) forwardRawNonStream(
	ctx context.Context,
	em emitter,
	baseURL, endpoint string,
	body []byte,
	outboundContentType string,
	extraHeaders http.Header,
	hop *hayai.RelayHop,
	respond nonStreamResponder,
) {
	upstreamReq, err := s.buildOperatorRequest(ctx, baseURL, http.MethodPost, endpoint, body, outboundContentType, extraHeaders)
	if err != nil {
		em.fail(newError("build_request", err.Error()))
		return
	}

	upstreamResp, err := s.httpClient.Do(upstreamReq)
	if err != nil {
		// In relayed mode the proxy connects to the relay, not the target, so a
		// transport error here is a relay-hop failure rather than the target's —
		// but only once the shared verdict has ruled out our OWN doing. ctx is
		// the payer's request context and Do blocks for the whole generation here, so
		// a payer hanging up mid-answer lands on this line; charging the relay
		// for a socket the proxy tore down itself is what this seam did while it
		// wrote to the reputation store directly.
		s.attributeRelayHop(ctx, hop, transient.TransportFailureStatus, nil, nil)
		s.log.Error("operator request failed", slog.String("endpoint", endpoint), relayAttr(hop), slog.Any("err", err))
		em.fail(newError("upstream_unreachable", err.Error()))
		return
	}
	defer upstreamResp.Body.Close()

	respBody, err := io.ReadAll(upstreamResp.Body)
	if err != nil {
		em.fail(newError("read_upstream", err.Error()))
		return
	}

	// Attribute the relay hop from the response: a relay-generated hop error
	// deprioritizes the relay; anything else (target error or success) credits it.
	s.attributeRelayHop(ctx, hop, upstreamResp.StatusCode, upstreamResp.Header, respBody)

	if err := respond(em, upstreamResp, respBody); err != nil {
		// Full detail goes to the log; client sees a generic proxy_error so
		// we don't leak transform/decrypt internals to callers.
		s.log.Error("response handling failed", slog.String("endpoint", endpoint), slog.Any("err", err))
		em.fail(newError("response_handler", "operator response could not be processed"))
	}
}

// stripHayaiHeaders deletes every X-Zs-* header. Run on the client-bound
// header set after every copyResponseHeaders in the hayai dispatch path —
// the sealed-response success path AND the pre-envelope error passthrough.
// SPEC.md §5.2 step 4: the client sees no X-Zs-Response-Key, no
// X-Zs-Receipt, no X-Zs-Settle-Group (the settle group carries the
// operator's pre-signed first half; nothing node-set should leak through).
// The proxy's own X-Zs-* usage headers are re-added afterwards by
// setHayaiUsageHeaders — proxy-owned metadata, not upstream passthrough.
func stripHayaiHeaders(h http.Header) {
	for k := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Zs-") {
			delete(h, k)
		}
	}
}

// snapshotHayaiHeaders copies the X-Zs-* headers already on the client-bound
// writer: the ones the PROXY set before the operator was ever called, such as
// the max_output clamp marker. copyResponseHeaders followed by
// stripHayaiHeaders clears every X-Zs-* on that writer — the node's and the
// proxy's alike — so anything set ahead of the response has to be re-asserted
// after the strip, which is what stripNodeHayaiHeaders does.
//
// Snapshot-and-restore rather than an allow-list inside the strip, because the
// strip is a security control and an allow-list would defeat it: the copy runs
// first, so a node answering with the same header name has already overwritten
// the proxy's value by the time the strip sees it, and exempting the name would
// hand the node's value straight to the client. A value captured before the
// operator was contacted can't be spoofed.
func snapshotHayaiHeaders(h http.Header) http.Header {
	var saved http.Header
	for k, vs := range h {
		if !strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Zs-") {
			continue
		}
		if saved == nil {
			saved = make(http.Header, 1)
		}
		saved[k] = slices.Clone(vs)
	}
	return saved
}

// stripNodeHayaiHeaders drops every node-set X-Zs-* from the client-bound
// header set (see stripHayaiHeaders) and puts the proxy's own back.
func stripNodeHayaiHeaders(h, saved http.Header) {
	stripHayaiHeaders(h)
	maps.Copy(h, saved)
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vs := range src {
		ck := http.CanonicalHeaderKey(k)
		if _, hop := hopByHopHeaders[ck]; hop {
			continue
		}
		// Access-Control-* headers describe the CORS contract between the
		// browser and whoever it's talking to directly — which is the proxy,
		// not the upstream node. The node sets its own CORS headers for
		// development setups that hit it directly, but those values would
		// overwrite the proxy's (set in writeCORSHeaders before the handler
		// ran) and the node's Expose-Headers omits the X-Zs-* cost
		// metadata the proxy attaches in setHayaiUsageHeaders — so the
		// browser ends up blocking JS access to the very headers the proxy
		// is trying to expose.
		if strings.HasPrefix(ck, "Access-Control-") {
			continue
		}
		dst[ck] = append([]string(nil), vs...)
	}
}
