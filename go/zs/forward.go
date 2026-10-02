/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
)

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
func (s *Client) buildOperatorRequest(
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
func (s *Client) forwardRawNonStream(
	ctx context.Context,
	em emitter,
	baseURL, endpoint string,
	body []byte,
	outboundContentType string,
	extraHeaders http.Header,
	hop *RelayHop,
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

// nodeHeader is the node's response header set as the caller sees it: a copy
// with every X-Zs-* field removed. SPEC.md §5.2 step 4: the caller gets no
// X-Zs-Response-Key, no X-Zs-Receipt, no X-Zs-Settle-Group (the settle group
// carries the operator's pre-signed first half), and nothing a future node
// adds under the prefix.
func nodeHeader(h http.Header) http.Header {
	out := make(http.Header, len(h))
	for k, vs := range h {
		if strings.HasPrefix(http.CanonicalHeaderKey(k), "X-Zs-") {
			continue
		}
		out[k] = slices.Clone(vs)
	}
	return out
}
