/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/inject"
)

// DefaultAttestationFetchTimeout bounds a single
// /v1/zs/attestation probe. Same default as DefaultDetailsFetchTimeout
// since the two probes share the per-operator deadline.
const DefaultAttestationFetchTimeout = 2 * time.Second

// maxOperatorResponseBytes caps how much we'll read from an
// operator-controlled HTTP response body. The cap exists to keep a
// hostile or buggy operator from streaming a multi-GB body and OOM-ing
// the proxy; the per-operator probe loop in fetcher.enrich runs
// concurrently, so one bad operator would otherwise amplify into
// N×size pressure.
//
// The headroom is narrower than it was. This used to say bundles are
// "well under 64 KB in practice", which stopped being true at proto
// 9.6: an evidence bundle now carries the app_compose PREIMAGE, which
// is ~22 KB on the 2026-08 capture and grows with the operator's own
// NODE_CONFIG_YAML, since that config is literal text inside the
// measured document. 256 KiB still holds with room to spare, and an
// over-cap body fails closed at json.Unmarshal rather than truncating
// into a plausible document — but the number to watch is now the
// config, which an operator controls, not the fixed fields.
const maxOperatorResponseBytes = 256 << 10 // 256 KiB

// AttestationClient fetches /v1/zs/attestation from a node. Mirrors
// the shape of DetailsClient (see details.go) so the per-operator
// probe layer doesn't need a second timeout / HTTP-pool model. The
// bundle it returns is checked by a tee.Verifier.
type AttestationClient struct {
	HTTP    *http.Client
	Timeout time.Duration
}

// NewAttestationClient constructs an AttestationClient. timeout falls
// back to DefaultAttestationFetchTimeout when non-positive. Pass an
// existing *http.Client to share connection pools across operators;
// per-fetch deadlines are enforced via context inside Fetch (we do not
// set http.Client.Timeout because the proxy's project-wide convention
// is to keep client timeouts at zero and rely on the request context).
func NewAttestationClient(client *http.Client, timeout time.Duration) *AttestationClient {
	if timeout <= 0 {
		timeout = DefaultAttestationFetchTimeout
	}
	if client == nil {
		// Timeout 0: the per-fetch deadline is enforced via context in Fetch.
		// The tuned transport gives a short dial timeout and a per-host idle
		// pool, matching DetailsClient (see details.go).
		client = httpx.Client(0, httpx.Options{})
	}
	return &AttestationClient{HTTP: client, Timeout: timeout}
}

// Fetch joins evidenceURL onto baseURL (so a node can advertise an
// absolute or relative path) and issues a GET. Any error (network,
// non-2xx, malformed JSON) is returned to the caller — Fetch does not
// silently swallow them; the fetcher logs each failure with the
// tee.FailureFetchFailed tag. A 404 is treated as a normal error here
// (operator advertised TEE but the endpoint is absent / misrouted) —
// the caller handles it the same as any other fetch failure.
// When hop is non-nil the probe is routed through that relay (transport-privacy
// mode). The relay forwards to the target's standard /v1/zs/attestation path
// (the only attestation path on the relay allow-list); an operator advertising
// a non-standard / absolute evidence URL cannot be relay-probed for attestation
// under privacy mode — a known limitation tracked for the privacy rollout.
func (c *AttestationClient) Fetch(ctx context.Context, baseURL, evidenceURL string, hop *RelayHop) (inject.TEEEvidenceBundle, error) {
	endpoint, err := joinAttestationURL(baseURL, evidenceURL)
	if err != nil {
		return inject.TEEEvidenceBundle{}, err
	}

	fetchCtx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	req, err := http.NewRequestWithContext(fetchCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", inject.AttestationContentType)
	if err := ApplyRelay(req, hop, "/v1/zs/attestation", http.MethodGet); err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("apply relay: %w", err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("attestation request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("attestation endpoint returned %d %s", resp.StatusCode, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOperatorResponseBytes))
	if err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("read attestation body: %w", err)
	}
	var bundle inject.TEEEvidenceBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return inject.TEEEvidenceBundle{}, fmt.Errorf("decode attestation: %w", err)
	}
	return bundle, nil
}

// joinAttestationURL resolves evidenceURL against baseURL. Handles
// three shapes the node may advertise:
//
//   - empty           → falls back to "/v1/zs/attestation"
//   - "/path/..."     → joined onto baseURL
//   - "http(s)://..." → used verbatim (the node has TLS-terminated the
//     attestation endpoint behind a different host than its base URL)
//
// Only http and https schemes are accepted on absolute URLs to
// prevent a malicious operator from steering the proxy at file:// or
// gopher:// targets via a crafted EvidenceURL.
func joinAttestationURL(baseURL, evidenceURL string) (string, error) {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return "", errors.New("empty operator base_url")
	}
	if evidenceURL == "" {
		return trimmed + "/v1/zs/attestation", nil
	}
	if strings.HasPrefix(evidenceURL, "http://") || strings.HasPrefix(evidenceURL, "https://") {
		return evidenceURL, nil
	}
	if !strings.HasPrefix(evidenceURL, "/") {
		evidenceURL = "/" + evidenceURL
	}
	return trimmed + evidenceURL, nil
}
