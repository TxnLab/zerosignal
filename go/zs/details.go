/*
 * Copyright (c) 2026. TxnLab Inc.
 * SPDX-License-Identifier: Apache-2.0
 */

package zs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TxnLab/zerosignal/go/httpx"
	"github.com/TxnLab/zerosignal/go/inject"
	protorelay "github.com/TxnLab/zerosignal/go/relay"
	"github.com/TxnLab/zerosignal/go/transient"
	"github.com/TxnLab/zerosignal/go/wire"
)

// RelayHopError marks a details probe that failed at the relay hop itself
// (transport-privacy mode) rather than at the target operator. Four shapes
// reach here:
//
//   - the proxy couldn't reach the relay at all (transport error, including
//     our own deadline expiring before the relay accepted a connection);
//   - the relay returned a relay-generated error (relay_busy,
//     relay_unknown_target, relay_bad_*) — see protorelay.IsHopErrorCode;
//   - the relay's own FRONT DOOR answered a code-less transient status while
//     the relay advertises wire.RelayHopHeaderMinVersion or newer and did not
//     stamp wire.RelayHopHeader. A relay that generation would have marked any
//     response its handler produced, so an unmarked one never reached it;
//   - our deadline or the caller's cancel ended the request after the relay
//     accepted the connection (CallerAborted).
//
// None of them shows the target down, so callers MUST NOT treat the target as
// unreachable on this error; they retry through a different relay, and
// deprioritize this one unless CallerAborted. The front-door shape is the one that
// used to be missing, and it was expensive: a code-less 504 from a relay's CDN
// fell through as a target-side failure, so probeOne benched a perfectly
// healthy node and advertisable() dropped it from /v1/models, while the relay
// that actually broke kept a spotless streak.
//
// RelayID / RelayNodeID / RelayURL identify the relay for logging and for
// excluding it from the retry. The (operator, node) pair is the key every
// downstream reliability store uses — a dead node must never tar a healthy
// sibling under the same operator.
type RelayHopError struct {
	RelayID     uint64
	RelayNodeID uint64
	RelayURL    string
	// CallerAborted is set when the caller's cancel ended the request, or the
	// probe's own deadline did after the relay accepted the connection. That
	// says nothing about either hop (SPEC § 10): a relay is byte-silent while
	// it waits on a slow target, so charging it would park a working relay for
	// the target's slowness. A deadline that expires before the connection is
	// a relay that never answered, and is charged like any connect failure.
	CallerAborted bool
	Err           error
}

func (e *RelayHopError) Error() string {
	return fmt.Sprintf("relay hop (operator %d, node %d, %s): %v", e.RelayID, e.RelayNodeID, e.RelayURL, e.Err)
}

func (e *RelayHopError) Unwrap() error { return e.Err }

// RelayUpstreamUnreachableError is a relay's claim (relay_upstream_unreachable)
// that it reached out and the target was down. The relay itself works, but one
// relay's view of the target proves little: the relay mesh can be partitioned,
// so another relay may reach the same node. A probe rotates past it, and only
// when a working relay said so on every rotation is the target down.
type RelayUpstreamUnreachableError struct {
	RelayID     uint64
	RelayNodeID uint64
	RelayURL    string
	Status      int
}

func (e *RelayUpstreamUnreachableError) Error() string {
	return fmt.Sprintf("relay (operator %d, node %d, %s) could not reach the target: %d %s",
		e.RelayID, e.RelayNodeID, e.RelayURL, e.Status, protorelay.CodeUpstreamUnreachable)
}

// DetailsBodyError is a 2xx details response whose body could not be read or
// decoded. The node answered, so a relay that carried it forwarded correctly.
type DetailsBodyError struct {
	Err error
}

func (e *DetailsBodyError) Error() string { return e.Err.Error() }

func (e *DetailsBodyError) Unwrap() error { return e.Err }

// relayErrorCode best-effort extracts the OpenAI-shaped error "code" from a
// relay's (>=400) error body. Returns "" when the body isn't that shape — in
// which case the caller treats it as a target-side failure, since a relay
// forwards the target's own error responses verbatim and those never carry a
// relay_ code.
func relayErrorCode(body io.Reader) string {
	var parsed struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	raw, err := io.ReadAll(io.LimitReader(body, 8*1024))
	if err != nil {
		return ""
	}
	if json.Unmarshal(raw, &parsed) != nil {
		return ""
	}
	return parsed.Error.Code
}

// DefaultDetailsFetchTimeout bounds a single /v1/zs/details probe.
// The fetch is best-effort: operators that don't respond in time keep
// their capability data empty and we move on. Keep this small so a
// slow operator doesn't delay startup materially.
const DefaultDetailsFetchTimeout = 2 * time.Second

// DefaultDetailsConcurrency caps concurrent per-operator details probes in
// one refresh cycle (see ChainOperatorSource.DetailsConcurrency). Sized to
// keep a large fleet's probe fan-out inside the refresh timeout without
// opening a socket per node at once; mirrors escrow's box-read fan-out cap.
const DefaultDetailsConcurrency = 24

// DetailsClient is a thin HTTP client for /v1/zs/details probes.
// Use NewDetailsClient to construct; the zero value is NOT ready for
// use because HTTP needs a client.
type DetailsClient struct {
	HTTP    *http.Client
	Timeout time.Duration
}

// NewDetailsClient returns a DetailsClient. timeout falls back to
// DefaultDetailsFetchTimeout when non-positive and is enforced via
// context inside Fetch (we do not set http.Client.Timeout because the
// proxy's project-wide convention is to keep client timeouts at zero
// and rely on the request context). Callers that want to share an HTTP
// connection pool across operators should pass an existing *http.Client.
func NewDetailsClient(client *http.Client, timeout time.Duration) *DetailsClient {
	if timeout <= 0 {
		timeout = DefaultDetailsFetchTimeout
	}
	if client == nil {
		// Timeout 0: the per-fetch deadline is enforced via context in Fetch.
		// The tuned transport gives a short dial timeout and a per-host idle
		// pool so the refresh loop's probes across operators reuse warm conns.
		client = httpx.Client(0, httpx.Options{})
	}
	return &DetailsClient{HTTP: client, Timeout: timeout}
}

// detailsQuery builds the optional "?model=…&expand=…" suffix for a deep
// per-model details probe (SPEC §3c "Deep model details"). Empty when
// neither is set — the lean bare-list probe. model is escaped (ids carry
// "/", e.g. "Qwen/Qwen2.5-7B"); expand tokens are comma-joined.
func detailsQuery(model string, expand []string) string {
	if model == "" && len(expand) == 0 {
		return ""
	}
	q := url.Values{}
	if model != "" {
		q.Set("model", model)
	}
	if len(expand) > 0 {
		q.Set("expand", strings.Join(expand, ","))
	}
	return "?" + q.Encode()
}

// Fetch issues a lean GET to baseURL + "/v1/zs/details" and returns the
// decoded advertisement. Any error (network, non-2xx, malformed JSON)
// is returned to the caller — Fetch does NOT silently swallow them so
// startup can log each failure. Callers decide whether to abort or
// proceed with empty capabilities.
// When hop is non-nil the probe is routed through that relay (transport-privacy
// mode); the relay forwards the inner GET to the target's details endpoint and
// returns the response verbatim, so the parsing below is unchanged. A nil hop
// probes the target directly.
func (c *DetailsClient) Fetch(ctx context.Context, baseURL string, hop *RelayHop) (inject.OperatorDetails, error) {
	return c.fetch(ctx, baseURL, "/v1/zs/details", hop)
}

// FetchModel issues the per-model deep details probe (SPEC §3c) — a GET to
// baseURL + "/v1/zs/details?model=<id>&expand=<tokens>". This is the
// proxy's drill-in primitive: the node scopes to the one model and assembles
// the requested verbose field groups (coordinates / digest), which the proxy
// returns verbatim rather than aggregating (they describe one node's served
// weights). The transport — direct or via a relay hop — is identical to
// Fetch; only the inner path carries the query. Unknown expand tokens are
// harmless (the node ignores them). The deep-path rail; the taxonomy /
// integrity enrichers populate the returned field groups. See SPEC §3c.
func (c *DetailsClient) FetchModel(ctx context.Context, baseURL, model string, expand []string, hop *RelayHop) (inject.OperatorDetails, error) {
	return c.fetch(ctx, baseURL, "/v1/zs/details"+detailsQuery(model, expand), hop)
}

// fetch is the shared probe core. innerPath is the target-relative path
// (with any "?model=…&expand=…" query); it doubles as the relay inner path
// so a relayed deep probe forwards the query verbatim.
func (c *DetailsClient) fetch(ctx context.Context, baseURL, innerPath string, hop *RelayHop) (inject.OperatorDetails, error) {
	trimmed := strings.TrimRight(baseURL, "/")
	if trimmed == "" {
		return inject.OperatorDetails{}, fmt.Errorf("empty operator base_url")
	}
	endpoint := trimmed + innerPath

	fetchCtx := ctx
	if c.Timeout > 0 {
		var cancel context.CancelFunc
		fetchCtx, cancel = context.WithTimeout(ctx, c.Timeout)
		defer cancel()
	}
	// The transport's dial and TLS timeouts outlast a probe's deadline, so a
	// relay that drops our SYNs would otherwise always end at our deadline and
	// read as "waiting on a slow target". Whether it ever accepted the
	// connection is what tells the two apart.
	var connected atomic.Bool
	traceCtx := httptrace.WithClientTrace(fetchCtx, &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { connected.Store(true) },
	})
	aborted := func() bool {
		return ctx.Err() != nil || (fetchCtx.Err() != nil && connected.Load())
	}
	callerAbortedHop := func(err error) error {
		return &RelayHopError{
			RelayID:       hop.RelayID,
			RelayNodeID:   hop.RelayNodeID,
			RelayURL:      hop.BaseURL,
			CallerAborted: true,
			Err:           err,
		}
	}
	req, err := http.NewRequestWithContext(traceCtx, http.MethodGet, endpoint, nil)
	if err != nil {
		return inject.OperatorDetails{}, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if err := ApplyRelay(req, hop, innerPath, http.MethodGet); err != nil {
		return inject.OperatorDetails{}, fmt.Errorf("apply relay: %w", err)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		// In relay mode the transport target IS the relay, so a dial/connect
		// failure here means the relay (not the target) was unreachable.
		if hop != nil {
			return inject.OperatorDetails{}, &RelayHopError{
				RelayID:       hop.RelayID,
				RelayNodeID:   hop.RelayNodeID,
				RelayURL:      hop.BaseURL,
				CallerAborted: aborted(),
				Err:           fmt.Errorf("details request: %w", err),
			}
		}
		return inject.OperatorDetails{}, fmt.Errorf("details request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		// In relay mode, a relay-generated error code means the relay (outer
		// hop) failed, not the target — classify it so the caller doesn't
		// blame the target. relay_upstream_unreachable is the relay's claim
		// about the target, returned as its own type; any non-relay code (the
		// target's own error, forwarded verbatim) falls through as a
		// target-side failure.
		if hop != nil {
			// One read: relayErrorCode CONSUMES the body, so it must not be
			// called twice.
			code := relayErrorCode(resp.Body)
			if code == "" && fetchCtx.Err() != nil {
				// Ended while reading the body: we can't tell a relay code
				// from the target's own error, so blame neither.
				return inject.OperatorDetails{}, callerAbortedHop(
					fmt.Errorf("read relay error body for %d %s: %w", resp.StatusCode, resp.Status, fetchCtx.Err()))
			}
			if protorelay.IsHopErrorCode(code) {
				return inject.OperatorDetails{}, &RelayHopError{
					RelayID:     hop.RelayID,
					RelayNodeID: hop.RelayNodeID,
					RelayURL:    hop.BaseURL,
					Err:         fmt.Errorf("relay returned %d %s (code %s)", resp.StatusCode, resp.Status, code),
				}
			}
			if code == protorelay.CodeUpstreamUnreachable {
				return inject.OperatorDetails{}, &RelayUpstreamUnreachableError{
					RelayID:     hop.RelayID,
					RelayNodeID: hop.RelayNodeID,
					RelayURL:    hop.BaseURL,
					Status:      resp.StatusCode,
				}
			}
			// The relay's own front door. A transient-shaped status from a relay
			// new enough to stamp wire.RelayHopHeader, arriving WITHOUT it,
			// means the relay's handler never ran — its CDN / ingress / LB
			// answered us and the target was never contacted. Attributing that
			// to the target is what let one broken relay evict healthy nodes
			// from discovery for hours.
			//
			// Marker-absence outranks the BODY here, unlike the dispatch path's
			// transient.NarrowRelayed. That divergence is deliberate: this
			// function only chooses an ERROR TYPE (rotate vs. blame the target),
			// so it can act on the stronger evidence, whereas NarrowRelayed
			// would have to flip retryability to do the same and must not. It
			// matters because a front door frequently emits its own coded JSON
			// — an Envoy `upstream_connect_error`, or the node's per-IP throttle
			// which runs AHEAD of the relay handler and answers a coded 429. All
			// of those previously benched the healthy target.
			//
			// Three gates remain load-bearing. A MARKED response falls through:
			// the relay did forward, so the status is the target's. A PRE-FLOOR
			// relay falls through: it owes no header, and charging it would
			// blame the entire un-upgraded fleet. And a status outside
			// transient.IsRelayFrontDoorStatus falls through — most notably a
			// gateway TIMEOUT, since the relay is byte-silent while forwarding
			// and may merely have been waiting on a slow target.
			//
			// The client's discovery probe (client/src/stream/operator-details.ts)
			// applies this same status-first gate over the same shared predicate.
			// Keep the two in lockstep — they are one decision made at two
			// vantage points, and they have drifted before.
			if transient.IsRelayFrontDoorStatus(resp.StatusCode) &&
				wire.SetsRelayHopHeader(hop.RelayProtoVersion) &&
				resp.Header.Get(wire.RelayHopHeader) == "" {
				return inject.OperatorDetails{}, &RelayHopError{
					RelayID:     hop.RelayID,
					RelayNodeID: hop.RelayNodeID,
					RelayURL:    hop.BaseURL,
					Err: fmt.Errorf("relay front door returned %d %s with no protocol code and no %s",
						resp.StatusCode, resp.Status, wire.RelayHopHeader),
				}
			}
		}
		return inject.OperatorDetails{}, fmt.Errorf("details endpoint returned %d %s", resp.StatusCode, resp.Status)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxOperatorResponseBytes))
	if err != nil {
		err = fmt.Errorf("read details body: %w", err)
		// A deadline or cancel mid-body is a slow or abandoned read, not a
		// body the target got wrong.
		if fetchCtx.Err() != nil {
			if hop != nil {
				return inject.OperatorDetails{}, callerAbortedHop(err)
			}
			return inject.OperatorDetails{}, err
		}
		return inject.OperatorDetails{}, &DetailsBodyError{Err: err}
	}
	var out inject.OperatorDetails
	if err := json.Unmarshal(raw, &out); err != nil {
		return inject.OperatorDetails{}, &DetailsBodyError{Err: fmt.Errorf("decode details: %w", err)}
	}
	return out, nil
}
